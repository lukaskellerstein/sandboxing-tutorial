# Lesson 16 — Composition: OpenShell over gVisor

The tutorial has spent nine lessons showing that gVisor (lesson 7) and OpenShell
(lesson 9) are strong in **disjoint columns**: gVisor shrinks the host-kernel
attack surface, OpenShell adds per-binary and method-aware policy plus an audit
trail on ordinary runc. Stacking one under the other is the obvious move — keep
OpenShell's policy, and run it on gVisor's smaller kernel. This is the lesson that
runs it. The result is not a stronger boundary; it is a **failure mode**, and the
first one in the tutorial where composing two boundaries makes you *less* safe.

```bash
cd tutorial/chapter-3-kubernetes/lesson-16-compose-gvisor-openshell
./run.sh              # provisions the shared chapter-3 cluster, runs the lesson, destroys it
./run.sh --keep       # ...but leave the cluster up afterwards (you pay until infra/down.sh)
```

Lessons 6–9 and 16–17 all share one cluster (`chapter-03-k8s`), so the cheap way
through the chapter is `cd infra && ./chapter-03.sh`, which builds the box once
and runs every lesson on it. See [chapter 3's other lessons](../) for the shared-box
model.

## The one thing that changes from lesson 9

Lesson 9 created its sandbox on the cluster's default runtime (runc) and passed no
runtime class. This lesson passes exactly one thing more — OpenShell's per-sandbox
driver-config overlay, which lands as the pod's `spec.runtimeClassName`:

```python
DRIVER_CONFIG = {"kubernetes": {"pod": {"runtime_class_name": "gvisor"}}}
# openshell sandbox create … --driver-config-json '{"kubernetes":{"pod":{"runtime_class_name":"gvisor"}}}'
```

Everything else is lesson 9's: the same `policy.yaml`, the same probe suite, the
same gateway and collector Services. The runtime underneath is the only variable,
which is what makes the comparison honest — any row that moves, moved because of
gVisor.

**The boundary is asserted from inside, never from the flag.** The lesson reads
`spec.runtimeClassName` back from the pod *and* runs `uname -r` inside the sandbox
(gVisor answers `4.19.0-gvisor`); if either is wrong it refuses to report, because
a composition lesson that silently ran on runc measures nothing — this repo's
characteristic failure.

## What the run shows — and the subtlety measured on the box

> This is the tutorial's one combination that had **never actually been executed**
> upstream (the prior art was "Expected Output"). Run for real on OpenShell 0.0.99,
> the finding is subtler than the folklore, and this write-up follows the box, not
> the prediction.

Four clauses of the *same* policy, and how each fares under the runtime swap:

- **The kernel column closes.** Exactly as in lesson 7 — `bpf`, `io_uring_setup`
  and friends answer `EPERM`/`ENOSYS`, `sys_module_count` reads `0`, the kernel
  identifies as gVisor's own. This is the half of the composition that works as
  hoped.
- **The L7 policy is untouched.** The allowed `GET` still reaches the gateway, the
  same host's `POST` is still denied, the unlisted binary is still denied. These
  are enforced by OpenShell's HTTP proxy, which never reads the kernel.
- **Landlock silently vanishes.** OpenShell's filesystem policy leans on
  **Landlock**, and gVisor answers `ENOSYS` to `landlock()`. The sandbox starts
  anyway and reports healthy; the only signal is a HIGH line in the audit trail:
  *"Landlock Filesystem Sandbox Unavailable."* A defense layer is gone.
- **…but the write stays blocked, so nothing looks wrong.** `fs_policy_write` —
  the probe that writes `/etc/agent-probe-canary`, which lesson 9 refused — is
  **still refused here**. On this box every read-only path (`/etc`, `/app`,
  `/usr`, `/lib`, `/var/log`) stays blocked with Landlock gone, and none of them is
  a read-only bind mount: OpenShell's kubernetes driver backs the read-only paths
  with a **read-only root filesystem**, which needs no Landlock. So the lost layer
  is **masked** — the attack outcome is *identical* to the safe Kata stack
  (lesson 17), and the audit finding is the only thing that differs.

**That is the lesson, and it is sharper than "the write starts succeeding":** a
composed boundary can shed a whole enforcement layer with **no visible effect**.
If you judged this stack by "did the write fail?" you would call it as safe as
Kata — and you would be wrong, because it lost Landlock and only the audit trail
knew. Never infer *both layers are enforcing* from *the attack was blocked*.

Then Part 2 applies `policy-hard.yaml` — identical but for one line,
`compatibility: hard_requirement` — at sandbox **create** (never `policy set`, which
the live sandbox rejects because the Landlock section is locked at startup). On
gVisor the sandbox now **refuses to start** rather than run without a feature it
declared it needs. That is the setting you actually want for a composed stack:
fail closed, so a silently-missing layer becomes a startup error instead of a
false sense of safety.

### Measured on `chapter-03-k8s` (k3s, one node)

```text
  sandbox pod: default--sbx-l16-gvisor
  pod .spec.runtimeClassName: gvisor   (expected: gvisor)
  kernel from inside the sandbox: 4.19.0-gvisor   (expected: *-gvisor)

  [kernel]
    kernel_identity     4.19.0-gvisor              BLOCKED  node runs 6.8.0-106-generic
    sys_module_count    0                          BLOCKED
    bpf                 EPERM                      BLOCKED  refused — capability dropped
    io_uring_setup      EPERM                      BLOCKED
    perf_event_open     EPERM                      BLOCKED
  [policy]
    egress_gateway      200                        BLOCKED  should ALLOW
    egress_offpolicy    403                        BLOCKED  should DENY
    http_method_denied  403                        BLOCKED  POST should DENY
    binary_scoped       403                        BLOCKED  unlisted binary
    fs_policy_write     PermissionError            BLOCKED  <-- STILL blocked (read-only rootfs)

  Landlock under gVisor: UNAVAILABLE (5 HIGH 'landlock-unavailable' audit finding(s))
  the audit trail's independent witness:
    [sandbox] [OCSF] FINDING:CREATE [HIGH] "Landlock Filesystem Sandbox Unavailable"
              [type:landlock-unavailable confidence:high]

  Part 2 — hard_requirement:
    create REFUSED — the sandbox failed CLOSED rather than running without Landlock:
      × "The system is not in a state required for the operation's execution", "sandbox is not ready"
```

Contrast lesson 17 on the same box, where the audit trail reads
`Landlock filesystem sandbox available [abi:v7]` and `ruleset built [rules_applied:12 skipped:0]`,
and `hard_requirement` starts cleanly. The two stacks are identical on every scored
row and differ only there.

## Why this is the gVisor composition's only real home

This composition needs a `runtimeClassName: gvisor` to select, and that exists
only where `runsc` is installed at node level — a Kubernetes node, which is here.
Chapter 2 cannot run it (rootless podman cannot drive `runsc`;
[lesson 14](../../chapter-2-one-host/lesson-14-compose-gvisor-openshell/README.md)),
and chapter 4 cannot (gVisor is not a supported OpenShift runtime;
[lesson 18](../../chapter-4-openshift/lesson-18-compose-gvisor-openshell/README.md)).
Both document the reason and point back here.

The rule this rung establishes — and [lesson 17](../lesson-17-compose-kata-openshell/README.md)
completes by showing the same policy holding under Kata — is written up once in
[`docs/isolation-layers.md`](../../../docs/isolation-layers.md) § *The trap:
stacking two boundaries can make you less safe*:

> **Composition fails when the lower layer removes a kernel feature the upper
> layer depends on.** Stacking boundaries is not automatically additive — verify
> the upper layer is still enforcing, do not infer it from the fact that both are
> installed.
