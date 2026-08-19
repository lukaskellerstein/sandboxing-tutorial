# Lesson 2.2.3 — Auditing the Kata rung

**The sharpest rung of the backwards-observability ladder.** [Lesson 1.2.3](../../../phase1-attacks/chapter-2-one-host/lesson-03-container-kata/)
put the workload in a per-container VM with its own guest kernel — the strongest kernel boundary on
the ladder. This lesson shows the consequence for auditing: **the host sensor goes fully blind, and
the sensor has to move into the guest with the workload.**

A container shares the host kernel, so in [2.2.1](../lesson-01-audit-container/) Tetragon saw straight
through it. A Kata guest does not: the attacks' syscalls are made against the **guest** kernel, inside
the VM, and never cross Tetragon's host-kernel probe. The same host sensor that recorded a whole container
in 2.2.1 records **zero** here.

Where [2.2.2](../lesson-02-audit-container-gvisor/) recovered coverage by switching to a gVisor-native
sensor (the sentry's own strace), a real VM hands the operator no such readout — the guest kernel is
opaque. Coverage returns only by putting a sensor **inside** the guest, and `main.py` measures both the
blindness and the recovery.

## The two things this rung teaches

- **The host sensor is blind behind a VM.** Part 1 runs the same hardened container as 1.2.3 under
  Kata with the host Tetragon watching; Part 2 reports how many attack fingerprints it caught: **none**.
- **The kernel-side sensor is fenced from the workload.** The BTF/`CONFIG_AUDITSYSCALL` debug kernel
  makes the guest's own audit trail real (with `audit=1`, records appear in the guest ring buffer), but
  a workload container cannot control it — `auditctl` returns `EPERM` inside the guest even as root with
  `CAP_AUDIT_CONTROL` and host namespaces. A kernel-side sensor (auditd/eBPF) needs the guest's init
  context, i.e. a **privileged pod sidecar** — which is the cluster's job, in lesson 2.3.3.
- **A ptrace tracer works from inside a single container.** `strace` traces the children it spawns, so
  it needs no audit netlink and no init-namespace privilege. Part 3 re-runs the same suite under an
  in-guest strace on the debug kernel and recovers a per-attack **RECORDED** verdict — the sensor that
  moved into the guest sees every syscall the host was blind to.

## The finding

Isolation reached its strongest kernel boundary on this ladder, and observability fell to **zero** at
the same step. Full coverage of a Kata workload is not a host sensor at all — it is a sensor deployed
into the guest, and even that is limited (a workload-container tracer, or a privileged sidecar the
platform injects). That is the backwards-observability ladder at its widest: the stronger the boundary,
the harder the workload is to watch.

## Why this box uses containerd + a debug kernel

Kata is a containerd shim-v2, so this rung runs under **nerdctl over containerd**, not podman (the same
reason [1.2.3](../../../phase1-attacks/chapter-2-one-host/lesson-03-container-kata/) does). The
`chapter-2-audit/kata-debug-kernel` substrate enables the `kernel` annotation on the shipped qemu
config so a run can opt into the BTF/`AUDITSYSCALL` debug kernel per-container; a run without the
annotation still boots the default guest, so Part 1's measured containment is exactly 1.2.3's.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.2.3     # chapter-02-audit-host (podman + runsc + kata + Tetragon)
uv run python -u main.py
```
