# Lesson 2.3.3 — Auditing the Kata rung

**Phase 2 audits what phase 1 measured.**
[Lesson 1.3.3](../../../phase1-attacks/chapter-3-kubernetes/lesson-03-k8s-kata/) put the workload in a
per-pod VM with its own guest kernel. [2.3.6](../lesson-06-audit-compose-kata-openshell/) showed what
that costs an auditor: the host eBPF sensor attributes **zero** events to the sandbox. This lesson is
where the coverage comes back — and where the *plan* for getting it back turns out to be wrong.

## The finding

**The sensor has to move into the guest, and only one kind of sensor can make the trip.**

| sensor | result |
| :-- | --: |
| **Tetragon**, on the node | **0** events attributed to the sandbox — against **123** it attributed to other containers on the same node in the same seconds |
| **the in-guest sidecar** | **12 of 19** attacks written down, from ~**3 900** traced syscalls |

The zero is guarded: the lesson refuses to report unless the same trail shows Tetragon recording
other containers meanwhile, because a probe that never attached and a probe that cannot see through a
guest kernel leave the same empty column. (Only the **zero** measures this boundary; the
other-container count is a liveness figure and moves run to run.)

## The prediction this lesson corrects

[2.2.3](../../chapter-2-one-host/lesson-03-audit-container-kata/) found that under **nerdctl** a
container inside the Kata guest cannot stand up a kernel-side sensor: `auditctl` returns `EPERM` even
as root with `CAP_AUDIT_CONTROL` and host namespaces, because the audit netlink is
initial-namespace-only. Discovery gate **G1** reframed that as *"the eBPF/auditd sidecar needs the
guest's init context, which is a **Kubernetes** construct — so it lands in 2.3.3."*

**Measured on a live cluster, that is false.** Every run of this lesson probes it and prints the
answer:

```text
audit netlink, from a privileged sidecar : Operation not permitted
eBPF program load, same sidecar          : loaded
BTF in the guest                         : present
```

The sidecar is `privileged: true`, `runAsUser: 0`, with a full `CapEff` of `000001ffffffffff` — and
the guest's audit subsystem still refuses it. Adding `hostPID: true` changes nothing, and the reason
is worth knowing: **under Kata, the kubelet's "host" is the sandbox, not the VM.** Kata's agent puts
the whole pod in a child pid namespace inside the guest, so the guest's real init is unreachable from
any container, and the kernel's `task_active_pid_ns(current) != &init_pid_ns` gate closes. No amount
of privilege opens it, because privilege is not what is being checked.

> Measured with `shareProcessNamespace: true` **and** with `hostPID: true`, as uid 1000 and as root,
> with explicit capabilities and with `privileged: true`. All four combinations: `EPERM`. The process
> list is identical under `hostPID` — `pause` is still PID 1 — which is the direct evidence that
> `hostPID` under Kata is not the VM's init namespace.

## What does work, and why

A **ptrace tracer**. It needs no netlink and no initial namespace — only the ability to trace a
process — and Kubernetes supplies exactly that with **`shareProcessNamespace: true`**, which puts
every container of the pod in one pid namespace *inside the guest*.

So the Kubernetes construct really does rescue this rung; just not the construct that was predicted,
and not a kernel-side sensor. It is also the thing nerdctl could not offer at all: there, one
container is one VM, and there is nothing to share.

The sidecar attaches **before** the workload starts. That handshake is deliberate and visible — the
two containers share an `emptyDir`, the workload blocks until `/coord/go` appears, and the sensor
creates it only after `strace` is attached. A tracer that attaches late misses everything already
done, which on a suite whose first act is reading credentials means missing the attack that matters
most.

## The eBPF line is the counterweight

The sidecar also **loads a real two-instruction eBPF program**, and it succeeds. Together with BTF
being present on the debug guest kernel, that says the obstacle was never the guest kernel's
capability: **audit is namespace-fenced and eBPF is not.** A CO-RE eBPF sensor could live in here —
it would just have to be shipped into the pod, which is the same cost the tracer pays.

The debug kernel is selected per-pod by annotation, enabled by
[`infra/substrates/chapter-3-audit/85-kata-debug-kernel.sh`](../../../../infra/substrates/chapter-3-audit/85-kata-debug-kernel.sh).
**BTF presence is the only discriminator** — both kernels report `6.18.35`, so a `uname` comparison
would pass on a guest that never got the annotation. `check.sh` asserts the contrast (`btf-absent`
default, `btf-present` annotated) rather than the flag.

> That substrate exists mostly to survive one trap. Under **kata-deploy** the qemu config is a
> **symlink**, and `sed -i` does not follow symlinks — it replaces the link, leaving the shim reading
> an unedited file. containerd still passes the annotation (kata-deploy sets
> `pod_annotations = ["io.katacontainers.*"]`), the shim rejects it as not enabled, and the pod sits
> in **ContainerCreating forever** — which reads like a broken Kata install rather than an edit that
> missed. The substrate resolves the path with `readlink -f` and reads it out of containerd's own
> `ConfigPath` where it can.

## Containment is 1.3.3's, unchanged

Nothing about the sandbox is weakened for the audit: the sidecar is a second container, not a hole in
the first. **14/19, with zero rows different from 1.3.3.**

## The cost worth carrying away

This coverage is **per-pod**. The sensor is not something the platform runs once on the node — it
ships in every workload's pod spec, doubles the container count, and a pod that forgets the sidecar
is exactly as dark as [2.3.6](../lesson-06-audit-compose-kata-openshell/). That is the real price of
the strongest isolation boundary on the ladder: you can have the VM and you can have the audit trail,
but the second one is now the workload author's responsibility rather than the cluster's.

## Run it

```bash
cd ../../../../infra && ./up.sh 2.3.3     # provisions chapter-03-audit-k8s
uv run python -u main.py
```

Or the whole chapter on one box: `cd infra && ./chapter-03-audit.sh`.
