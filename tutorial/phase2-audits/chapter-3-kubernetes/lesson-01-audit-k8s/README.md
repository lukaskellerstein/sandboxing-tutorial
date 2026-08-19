# Lesson 2.3.1 — Auditing the Kubernetes rung

**Phase 2 audits what phase 1 measured.**
[Lesson 1.3.1](../../../phase1-attacks/chapter-3-kubernetes/lesson-01-k8s/) showed a hardened Pod
composes the container's boundary and adds a NetworkPolicy. This lesson asks whether anything would
have *written the attempts down*.

Two sensors watch the same seconds:

| sensor | what it can see |
| :-- | :-- |
| **Tetragon** (host CO-RE eBPF, pinned v1.7.0) | the syscalls the workload makes on the **node's** kernel |
| **the apiserver's audit log** | requests made to the **control plane** — a surface no syscall tracer has |

## The finding

**The host sensor's result does not move from the container rung, and the cluster adds one column it
could never have.**

Tetragon records **7** of the scored attacks here — the same 7 it recorded through a plain container
in [2.2.1](../../chapter-2-one-host/lesson-01-audit-container/), by the same policy, with the same
kprobes. That is the point: a Pod is namespaces and cgroups on the node's kernel, so a probe attached
to that kernel sees straight through it. **Kubernetes arranged the isolation; it did not move the
observability.**

The eighth is `k8s_sa_token`, and it is the interesting one. It makes no syscall worth hooking — to
Tetragon it is an `openat` on a path and a `tcp_connect`, indistinguishable from any other fetch.
That it was an *authenticated principal talking to the control plane* exists in exactly one place:
the apiserver's own record, as
`user.username = system:serviceaccount:sbx-2-3-1:default`. Most clusters ship the API audit log
**off**. Turn it off here and the attack that is unique to this rung is the one nothing anywhere
writes down.

The three kernel probes stay `NOT LOGGED` for 2.2.1's reason, unchanged by the cluster: the
`RuntimeDefault` seccomp profile refuses `bpf` / `io_uring_setup` / `perf_event_open` at **syscall
entry**, before any kprobe can fire. The boundary blocked them and left no evidence it had done so.

## This pod is 1.3.1's with exactly two controls off — and it says so

A sensor cannot record an attack the boundary stopped from ever being attempted. 1.3.1 sets
`automountServiceAccountToken: false` **and** denies egress to the apiserver, so the control-plane
attack never happens and there is nothing for any auditor to see — which is the right configuration
and the end of the measurement.

So this leaf leaves the pod as a cluster ships it by **default**: token mounted, apiserver reachable
(one extra NetworkPolicy clause, read from the cluster rather than hardcoded — both the Service
ClusterIP and the endpoint behind it, because kube-proxy DNATs one to the other and which address a
CNI's egress rules see depends on where in the chain they are evaluated).

Everything else is 1.3.1's, byte for byte. The result: **exactly one row differs** — `k8s_sa_token`
moves from contained to reached — and containment reads **13/19 against 1.3.1's 14/19**. This is the
same move [2.2.4](../../chapter-2-one-host/lesson-04-audit-container-openshell/) makes when it plants
canary credentials, and for the same reason.

## How the attribution works — and why it changed from 2.2.1

2.2.1 attributes an event to the workload by its **pid namespace**, because under rootless podman the
container id lands on the host-side runtime processes and not on the workload. On the cluster the
opposite holds, and the pid namespace is no longer good enough:

- `process.docker` **is** populated here — Tetragon derives it from the cgroup, and the kubelet's
  cgroups carry it. Measured on this box: every event bearing a container id was in a non-host pid
  namespace, and no host-side runtime process carried one at all.
- the stand-in **gateway is a second pod**, alive in this namespace for the whole capture window, and
  every k3s system pod is in a pid namespace of its own. "Not the host" would credit this workload
  with coredns's connects.

So the lesson reads the attack pod's own `containerID` **from the k8s API** after the run and matches
Tetragon's (truncated) id against it by prefix. The cluster is the authority on which container it
scheduled, which is stronger than trusting a sensor's self-reported enrichment.

> **`--enable-k8s-api` is deliberately NOT used.** Tetragon advertises stamping every event with its
> pod and namespace. On this box it refuses to start (the flag also enables a TracingPolicy CRD
> watcher the release tarball ships no CRDs for), never resolves `process.pod` even with
> `--enable-cri` pointed at k3s's containerd socket, and — worst — holds every event up to **30 s** in
> its EventCache while retrying, so a capture window that closes promptly reports `NOT LOGGED` for
> everything the workload did. The full measurement is in
> [`infra/substrates/chapter-3-audit/tetragon.sh`](../../../../infra/substrates/chapter-3-audit/tetragon.sh).

## Where this runs

On `chapter-03-audit-k8s` — a **separate** k3s box from phase 1's `chapter-03-k8s`, by the
co-residency rule: a host eBPF sensor taxes `syscall_ms`, so it must not share a machine with a
phase-1 lesson whose cost it would corrupt.

`check.sh` proves both sensors at provision time, from what they recorded rather than from the flags:
a kprobe must fire inside a pod whose container id the cluster confirms, and a service-account
request must appear in the audit log. An apiserver whose audit policy failed to parse starts the
cluster with auditing **off** — and every control-plane row would then read "not recorded" about a
cluster that was never recording.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.3.1     # provisions chapter-03-audit-k8s
uv run python -u main.py
```

Or run the whole chapter on one box, which is much cheaper:
`cd infra && ./chapter-03-audit.sh`.
