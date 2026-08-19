# Lesson 2.2.1 — Auditing the container rung

**Phase 2 audits what phase 1 measured.** [Lesson 1.2.1](../../../phase1-attacks/chapter-2-one-host/lesson-01-container/)
showed a container *blocks* more than the bare host (7/13 vs 3/13). This lesson asks whether it also
*hides* more.

It runs the **same** hardened rootless podman container, with **Tetragon** (a host-kernel sensor on a
CO-RE eBPF probe) watching, and reports — per attack — a **RECORDED** verdict.

## The finding

A container **blocks more but hides no more**. It shares the host kernel, so its syscalls cross
Tetragon's eBPF probe exactly as the bare host's crossed auditd in
[2.1.1](../../chapter-1-no-sandbox/lesson-01-audit-no-sandbox/) — the namespace/cgroup boundary that
*isolates* the workload is transparent to a sensor sitting in the kernel underneath it. Isolation
went up from 1.1.1; observability did not move.

**7 of 13 written down** (measured 2026-08-15). Three rows have no hook at all (`no sensor`, below).
The other three are the sharp edge, and they are worth the whole lesson:

### Blocked, and forgotten: the three `NOT LOGGED` rows

`bpf`, `io_uring_setup` and `perf_event_open` **are** hooked by the policy, and still leave no record.
podman's default seccomp profile allows `bpf` and `perf_event_open` only with `CAP_SYS_ADMIN`, and
does not list `io_uring_setup` at all — so under `--cap-drop ALL` all three fall to its
`defaultAction: SCMP_ACT_ERRNO`. **seccomp is evaluated before the `sys_enter` tracepoint**, and a
filter returning an errno never runs the syscall body, so the kprobe cannot fire — and neither can a
tracepoint, nor auditd's syscall-exit hook.

That it is seccomp and not the kernel is measured, not assumed: the node has `CONFIG_IO_URING=y`, the
identical call **succeeds** (`fd=3`) under `--security-opt seccomp=unconfined`, and
`perf_event_open`'s errno moves from `EPERM` (the filter) to `EACCES` (the kernel's own check).

So the boundary **blocked these three and left no evidence it had done so**. A syscall refused at
entry is invisible to every kernel-side sensor; the only witness available is the enforcing mechanism
itself (`SECCOMP_RET_LOG` → auditd `type=SECCOMP`). [2.2.2](./../lesson-02-audit-container-gvisor/) is
the instructive contrast — gVisor's kernel runs in user space, so the sentry records all three
*before* anything refuses them.

> This corrects an earlier reading of this rung, which scored 10/13 with these three as `LOGGED`.
> They cannot be: the mechanism above forbids it, whichever host sensor is watching.

> That trade only turns at gVisor (the workload talks to a user-space kernel the host sensor cannot
> see into) and Kata (a separate guest kernel entirely). The RECORDED band walks *backwards* down the
> isolation ladder from here.

## How the mapping works

The substrate [`infra/substrates/chapter-2-audit/tetragon.sh`](../../../../infra/substrates/chapter-2-audit/tetragon.sh)
installs Tetragon (pinned **v1.7.0**; CO-RE, no kernel-version pin needed — the host's 6.8 carries
BTF) and writes one `TracingPolicy` whose kprobes each carry a `tags: ["sbx_probe=…"]` fingerprint.
`main.py` starts Tetragon, runs the attack container while it watches, and marks a probe `LOGGED`
when that fingerprint appears in the JSON export. `/proc` reads and `uname` have no hook
(`no sensor`) — the shape of a targeted policy, against auditd's catch-all in 2.1.1.

Two details are load-bearing and easy to get wrong:

- **`read_credentials` hooks `sys_openat`, not `security_file_open`.** The LSM hook only fires once an
  inode has been resolved, so a read of a credential file that *does not exist* — exactly the
  hardened container's case, where the attack is contained — would never reach it, and the probe
  would read `NOT LOGGED` for a boundary that in fact blocked a **visible** attempt. The syscall
  entry fires either way.
- **Every event must come from the workload's own pid namespace** — *not* from a container id.
  `process.docker` is the obvious choice and it is **wrong on this rung**, measurably: Tetragon
  derives that id from the cgroup, and under **rootless** podman it lands on the host-side
  `podman`/`crun`/`conmon` while the container's own process gets none. Measured 2026-08-15: the
  container's `/bin/cat` had no docker id and `pid.inum=4026532425`, while the runtime processes on
  the host carried the id with `pid.inum=4026531836` (the init namespace). Gating on the id would
  have credited the workload with the runtime's execs and missed everything it actually did. The pid
  namespace is also stricter than a `container.id != host` rule clause, because the kernel's own view
  cannot be fooled by a runtime's bookkeeping — and without *some* such gate the box's own sshd
  connect would read as the workload's exfiltration. It needs `--enable-process-ns`, and `check.sh`
  asserts at provision time that the namespace actually populates.

  On the **cluster** rungs the opposite is true and 2.3.1 uses the container id instead: the kubelet's
  cgroups do carry it, and a pid-namespace test cannot separate the attack pod from the gateway pod
  beside it.

## Why Tetragon and not Falco

Both are host eBPF sensors and on this rung both see the same thing. The choice is about using **one**
sensor mechanism across the whole of phase 2: a reader comparing this rung to the k8s rung has to be
able to attribute a difference to the *boundary*, not to the instrument — the same argument phase 1
makes for running every rung against one fixed attack suite. Tetragon runs unmodified on both the
host and the cluster rungs, where Falco would have needed the k3s containerd socket wired by hand.

> One claim that used to sit here has been **withdrawn on measurement**: Tetragon's `--enable-k8s-api`
> "native pod enrichment" does *not* work on the k3s rung. It refuses to start (it also enables a
> TracingPolicy CRD watcher the release tarball ships no CRDs for), never resolves `process.pod` even
> with `--enable-cri` pointed at k3s's containerd socket, and delays every event up to 30 s in its
> EventCache while retrying — which manufactures false `NOT LOGGED` verdicts. The full measurement is
> in [`infra/substrates/chapter-3-audit/tetragon.sh`](../../../../infra/substrates/chapter-3-audit/tetragon.sh).
> The choice of Tetragon still stands on the not-mixing-instruments argument; the enrichment was
> never the reason.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.2.1     # provisions chapter-02-audit-host (podman + Tetragon)
uv run python -u main.py
```
