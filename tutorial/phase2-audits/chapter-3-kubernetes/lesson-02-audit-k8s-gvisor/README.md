# Lesson 2.3.2 — Auditing the gVisor rung

**Phase 2 audits what phase 1 measured.**
[Lesson 1.3.2](../../../phase1-attacks/chapter-3-kubernetes/lesson-02-k8s-gvisor/) collapsed the
kernel column with one field. This lesson asks who was watching while it did.

## The finding

**The host sensor is attached to the wrong kernel, and it is not a tooling gap.**

Under gVisor the application's syscalls are serviced by the **sentry**, a kernel in user space. The
host kernel never sees the call the application made — it sees the calls the sentry and the gofer
make on its *behalf*, which are host processes doing host work. So a probe attached to the host
kernel cannot audit this workload, however good the probe is.

Measured here, side by side, rather than asserted:

| sensor | result |
| :-- | :-- |
| **the sentry's own trace** (`runsc --strace`) | ~97 000 syscalls captured; **10** of the scored probes matched |
| **Tetragon** (host CO-RE eBPF) | **0** events attributed to this sandbox — against **164** it attributed to *other* containers on the same node in the same seconds |

That second number is the guard that makes the zero mean something. A host sensor that never attached
and a host sensor that cannot see through gVisor produce the same empty column, so the lesson refuses
to report unless Tetragon is shown recording other containers meanwhile. (Only the **zero** is a
measurement of this boundary; the other-container count is a liveness figure and moves run to run with
whatever else the node is doing.)

Three rows are worth pointing at: `bpf`, `io_uring_setup` and `perf_event_open` read **LOGGED** here
and `NOT LOGGED` on every runc rung ([2.2.1](../../chapter-2-one-host/lesson-01-audit-container/),
2.3.1). On runc, seccomp refuses them at syscall *entry*, before any kernel-side sensor can fire. In
gVisor the kernel is in user space, so the sentry sees the call **before** anything refuses it. The
weaker isolation boundary is the one that forgets.

## Discovery gate G2 — this lesson exists because the plan failed

The design called for pointing a host eBPF sensor at gVisor. There is no such path:

- **Falco removed its gVisor event source in 0.41** (only `kmod` / `ebpf` / `modern_ebpf` engines
  remain; the gVisor source needs an EOL ~0.36).
- **Tetragon never had one.**

The blindness is a property of *where a host sensor sits*, not of which tool you pick — so the gate
was closed and the lesson reframed onto gVisor's own trace, exactly as
[2.2.2](../../chapter-2-one-host/lesson-02-audit-container-gvisor/) does one rung down.

## Why a second RuntimeClass

`gvisor-trace` selects the **same runsc binary** as 1.3.2's `gvisor`, with a different runsc config:
`--strace` on, debug log per sandbox. It is a separate class rather than a flag on the existing one
because **strace costs real time per syscall**, and 1.3.2's `syscall_ms` is a number on the ladder.

Read this lesson's cost row with that in mind: `syscall_ms` is ~1700 here against 1.3.2's ~209 on the
*identical boundary*. That is the instrument, not gVisor. 1.3.2 measures what the boundary costs;
this lesson measures what watching it costs. Merging the two onto one class would have quietly
blended them, which is exactly the kind of number this repo exists not to publish.

The substrate is
[`infra/substrates/chapter-3-audit/72-k8s-gvisor-trace.sh`](../../../../infra/substrates/chapter-3-audit/72-k8s-gvisor-trace.sh).
It must run **with** 70/75 and never after `80-k8s-kata`: it edits containerd's config template,
which only takes effect on a k3s restart, and a restart after 80 terminates the kata-deploy DaemonSet
— which reverts its own install on the way out.

Two details in it cost a run each to find:

- **`debug-log` must end in a slash.** runsc then treats it as a directory prefix and appends
  `<timestamp>.<command>.txt`, so `boot` (the only log carrying the application's syscalls) gets its
  own file. Given a plain path, every command's log lands in one file and boot is overwritten.
- **The containerd plugin name must be read as root.** The generated config is mode 0600; an
  unprivileged `grep` returns "permission denied", falls through to the containerd-1.x branch, and
  appends a correct-looking block to a template k3s never reads. The pod then sits in
  `ContainerCreating` forever, which reads like a broken runsc install.

## Containment is 1.3.2's, unchanged

Nothing is weakened for the audit: the sentry records the *attempt* whether or not it lands, so no
canary is needed. **16/19, zero rows different from 1.3.2.**

## Run it

```bash
cd ../../../../infra && ./up.sh 2.3.2     # provisions chapter-03-audit-k8s
uv run python -u main.py
```

Or the whole chapter on one box: `cd infra && ./chapter-03-audit.sh`.
