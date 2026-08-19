# Lesson 2.3.5 — Auditing OpenShell over gVisor

**This is the leaf where phase 2 stops being a nice idea.**

[Lesson 1.3.5](../../../phase1-attacks/chapter-3-kubernetes/lesson-05-compose-gvisor-openshell/)
stacked OpenShell's policy on gVisor and found that the filesystem clause **silently loses its
Landlock backing**, because gVisor answers `ENOSYS` to `landlock()`. Then it found the uncomfortable
part: **the loss is masked.** `fs_policy_write` stays BLOCKED anyway, because OpenShell's kubernetes
driver also backs those paths with a read-only **root filesystem**.

So the containment scorecard of this stack is *identical to the safe one*. Nothing on it moves. A team
scoring boundaries would ship this and never know a defense layer had disappeared.

## The finding

**One line of audit trail is the only thing in the entire run that distinguishes the broken stack from
the safe one.**

Measured here: **6 HIGH `landlock-unavailable` findings** in OpenShell's OCSF trail
("Landlock Filesystem Sandbox Unavailable"), while `fs_policy_write` reads **BLOCKED** — the same
verdict [2.3.4](../lesson-04-audit-k8s-openshell/) gives on plain runc and
[2.3.6](../lesson-06-audit-compose-kata-openshell/) gives on Kata.

That is the answer to *"why audit a boundary you already scored"*: **a scorecard compares outcomes,
and it cannot tell you about a control that stopped existing while the outcome stayed the same.**

The other half of the answer is in 1.3.5 Part 2: `hard_requirement` turns the same fact into a refusal
to start, rather than a line nobody read. Auditing tells you; failing closed protects you.

## Two sensors, and no host sensor between them

| sensor | covers |
| :-- | :-- |
| **the sentry's own trace** (`runsc --strace`) | the local attacks — ~120 000 syscalls captured |
| **OCSF** (OpenShell's L7 trail) | the network attacks, and the Landlock finding |

There is no host-sensor option on this rung *at all*: discovery gate **G2** established that no host
eBPF sensor can see through the sentry (Falco dropped its gVisor source in 0.41, Tetragon never had
one), so 2.3.4's Tetragon column has no equivalent here. See
[2.3.2](../lesson-02-audit-k8s-gvisor/) for that measured side by side.

The composition is **one flag from 2.3.4**: the same policy file, the same suite, the same OCSF
sensor, with `runtimeClassName: gvisor-trace` underneath instead of runc — selected per sandbox by
OpenShell's `--driver-config-json` overlay, exactly as 1.3.5 selects `gvisor`.

## Two things this leaf does differently from 1.3.5, and why

- **It runs the full suite** (`reach,abuse,kernel,policy,cost`) where 1.3.5 runs only
  `kernel,policy`. The audit question needs attacks the two sensors can *disagree* about; with only
  those two groups there is no network attack for OCSF to catch. The comparison that carries this
  lesson is therefore **2.3.4 → 2.3.5**, one field apart.
- **It names the row the suite does not survive.** On this rung the fork bomb regularly takes the
  whole sandbox down — gVisor's sentry and its per-task stub processes live *inside* the container's
  cgroup, so a 128-way fork that merely earns `EAGAIN` under runc exhausts the sandbox here, and the
  exec relay closes before `resource_exhaustion` reaches stdout. 2.2.2 lets that row simply vanish,
  leaving a card one row shorter than everyone else's with nothing saying why. This leaf records it
  explicitly, and scores it `contained = n/a` unless the pod object actually says `OOMKilled` — a
  sandbox that died for some other reason was not demonstrably capped.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.3.5     # provisions chapter-03-audit-k8s
uv run python -u main.py
```

Or the whole chapter on one box: `cd infra && ./chapter-03-audit.sh`.

OpenShell is **alpha** and this finding is version-specific — 1.3.5's headline had to be rewritten
once already when the prior art's predicted `fs_policy_write → ALLOWED` did not reproduce on 0.0.99.
The version is printed at the top of the run and recorded in the scorecard.
