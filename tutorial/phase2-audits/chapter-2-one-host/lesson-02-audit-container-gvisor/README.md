# Lesson 2.2.2 — Auditing the gVisor rung

**The turning point of the backwards-observability ladder.** [Lesson 1.2.2](../../../phase1-attacks/chapter-2-one-host/lesson-02-container-gvisor/)
put the workload behind gVisor's user-space kernel. This lesson shows the consequence for auditing:
**a host sensor goes blind, and gVisor's own trace is the only sensor that still sees the app.**

Under runsc, every syscall the app makes is intercepted by the **sentry** and never reaches the host
kernel as the app made it. So [2.2.1](./../lesson-01-audit-container/)'s host Tetragon would see only
the sentry's own behaviour. The sensor here is gVisor-native: `runsc --strace` writes the app's syscalls
to the sentry's boot log, and `main.py` parses that log per attack.

> This is the reframe forced by **discovery gate G2**: modern Falco (0.44) dropped its gVisor event
> source and Tetragon never had one, so there is no host-sensor path at all. The blindness is a
> property of *where a host sensor sits*, not of which one you picked — the honest sensor is the
> sentry's own trace.

## The finding

Coverage **survives** the boundary, but only by **switching sensors** — from the host kernel to
gVisor's trace. That is what "only the sentry sees it under gVisor" means, measured. A host eBPF
sensor pointed at this box would record almost nothing of the attack, because the attack's syscalls
were serviced by the sentry in user space, not made against the host kernel.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.2.2     # chapter-02-audit-host (podman + runsc + Tetragon)
uv run python -u main.py
```
