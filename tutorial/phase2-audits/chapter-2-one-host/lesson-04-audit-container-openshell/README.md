# Lesson 2.2.4 — Auditing the OpenShell rung

**Two sensors, disjoint columns, and the honest gap between them.**
[Lesson 1.2.4](../../../phase1-attacks/chapter-2-one-host/lesson-04-container-openshell/) ran the agent
behind OpenShell's per-binary, L7 policy on **ordinary `runc`** — no VM (as [2.2.3](../lesson-03-audit-container-kata/)
had), no user-space kernel (as [2.2.2](../lesson-02-audit-container-gvisor/) had). So — unlike 2.2.3,
where the host sensor read **zero** behind Kata's guest kernel — the in-guest `auditd` **does** see the
workload's syscalls here (they reach the host kernel). Two sensors cover the attacks, in disjoint columns,
and **15 of the 19** probes are written down between them (measured, reproduced from scratch 2026-08-15).

## The two sensors

| Sensor | Catches (8 each) | How |
|:--|:--|:--|
| **auditd** (in-guest host) | `read_credentials`, `plant_backdoor`, `sys_module_count`, `kallsyms_readable`, `bpf`, `io_uring_setup`, `perf_event_open`, `malicious_package` | the workload-unique **path** each attack opens (`/sandbox/.ssh/id_rsa`, `/sandbox/.bashrc`, `/proc/kallsyms`, `agent_probe_evil`, …), or the **keyed syscall** for the kernel probes |
| **OCSF** (OpenShell L7) | `exfiltrate`, `cloud_metadata`, `egress_gateway`, `egress_offpolicy`, `http_method_denied`, `binary_scoped`, `reverse_shell`, `malicious_package` | the **binary + method + endpoint** of each network decision, allowed or denied |

`malicious_package` is the one attack **both** catch — the pip install writes `agent_probe_evil` (auditd
sees the file) *and* fetches from an index (OCSF sees the request). Everything else splits cleanly: the
local/kernel attacks are auditd's, the network attacks are OCSF's.

The **capability-denied kernel probes** (`bpf`, `io_uring_setup`, `perf_event_open`) are recorded even
though they fail: a syscall that returns `EPERM` still **exits**, and auditd's exit hook fires. That is
different from a `seccomp`-killed syscall — here the capability is dropped, the kernel refuses the call
and returns, and the refusal is on the record.

## Why this rung plants canaries

Unlike 1.2.4, this lesson sets `PLANT_FAKE_SECRETS=1` (with `HOME=/sandbox`) so the credential-theft
attack touches **real** files and leaves a **real** audit trail — that is what makes it auditable. The
consequence, on the scoreboard: `read_credentials` reads a canary here (**reached**), where 1.2.4 — with
nothing to steal — showed it **contained**. So containment reads 15/19 here against 1.2.4's 16/19; the
one-row difference is exactly the planted secret, and it is what turns a blocked-and-forgotten probe into
a recorded one.

## The honest gap

Only **`fs_policy_write`** is caught by neither sensor, and the reason is the finding: it is a write to
`/etc` **denied by the filesystem policy** before the open resolves to a record. A host syscall auditor
sees what the workload **did**, not what the boundary **denied** — so the one attack the policy *stopped*
at the filesystem is exactly the one the syscall trail cannot show. Only OpenShell's own policy engine
records that decision (and it is not a network decision, so it is not in the OCSF trail this lesson
parses either). `resource_exhaustion` is the other non-`LOGGED` row: a fork bomb looks exactly like
ordinary process spawning, so no keyed rule fingerprints it without flagging every subprocess.

That is the phase-2 finding at this rung: **observability is per-sensor-shaped** — auditd for the
syscalls that happen, OCSF for the L7 policy decisions — and full coverage is the two sensors *together*.

## The trap that made this hard (so it stays fixed)

The in-guest `auditd` needs two non-default `auditd.conf` settings, both baked into
`chapter-2-audit/auditd-guest.sh`, without which the trail is **intermittent** — a probe reads `LOGGED`
one run and blank the next:

- **`log_format = RAW`** (not Debian's `ENRICHED`), or the concatenated interpreted fields break the
  `grep type=PATH … name="…"` the mapping relies on.
- **`max_log_file = 500`** (not the 8 MB default), or the log **rotates mid-run** and the sensitive records
  land in a rotated segment the lesson's grep never reads.

## Why this box is its own, not the shared audit host

The other chapter-2 audit lessons share `chapter-02-audit-host`. This one cannot: OpenShell's
rootless-podman driver **refuses a public default-route address**, so `50-nat-vm` builds a Debian-13 NAT
guest and `up.sh` re-points the box **terminally** into it — the same constraint that keeps
[1.2.4](../../../phase1-attacks/chapter-2-one-host/lesson-04-container-openshell/) on its own box. The box
carries 1.2.4's two substrates plus `chapter-2-audit/auditd-guest`, which runs **after** the re-point and
so installs `auditd` inside the guest.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.2.4     # its own NAT-guest box (OpenShell in the guest + in-guest auditd)
uv run python -u main.py
```

> OpenShell is **alpha**. The run prints its version and records it in `results/2.2.4.json`, so drift
> shows up as a changed number rather than a mysterious failure.
