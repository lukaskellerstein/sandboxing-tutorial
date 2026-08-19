# Lesson 2.4.3 — Auditing the Kata rung on OpenShift

**This is [2.4.1](../lesson-01-audit-openshift-pod/)'s pod with one field added** —
`runtimeClassName: kata` — so anything that moves, moved because the workload is now in a per-pod VM.

## The finding

**The node sensor's column collapses to nothing, and this platform will not let you fix it.**

| | 2.4.1 (no VM) | 2.4.3 (Kata) |
| :-- | --: | --: |
| file paths the node's auditd attributed to the pod | **739** | **0** |
| attacks written down | 4/13 | **0/14** |

The zero is guarded twice over. `lost = 0`, so nothing was dropped; and auditd recorded **17 992**
keyed records overall in the same window, so it was demonstrably running. The workload's syscalls
crossed a guest kernel and the node's never saw them — 2.2.3 and 2.3.6's finding on a third platform.

**There is also nothing to attribute by.** 2.4.1's key is the pod's SELinux MCS, assigned by the
node's policy to a process on the node's kernel. A Kata pod reports **no MCS at all** to the node: the
workload runs on a guest kernel, so the label does not exist. The sensor could not name this workload
even if it could see it.

*(A VM really did boot: DMI reports `KVM`, asserted from inside — never the kernel string, because Red
Hat builds the guest kernel from the same RHEL base as the node.)*

## Why you cannot do here what 2.3.3 did on k3s

[2.3.3](../../chapter-3-kubernetes/lesson-03-audit-k8s-kata/) rescues this rung with a sidecar in the
same pod running a **ptrace tracer**: `shareProcessNamespace: true` puts every container of the pod in
one namespace inside the guest, and a tracer needs nothing more than the ability to trace.

This pod sets that field. The sidecar reports on itself from inside the cluster, every run:

```text
uid               1000780000     ← the project's assigned range
caps              CapEff:0000000000000000
strace            ABSENT
dnf               AttributeError: 'ConfigMain' object has no attribute 'tempfiles'
workload_visible  18             ← it CAN see the workload
```

The namespace **is** shared — the sidecar sees the workload's process, exactly as on k3s. What it
cannot do is be a sensor:

* **no tracer in the image.** Chapter 4 cannot build images (RHCOS has no podman; the cluster has no
  `*.apps` route to push a registry through), so it uses a stock UBI image and `strace` is not in it.
* **no way to install one.** `dnf` fails twice over — on this hardened spec it dies on the read-only
  root filesystem, and in a pod without that (measured separately) it dies with *"This command has to
  be run with superuser privileges"*, because SCC assigns a non-root uid.
* **and the privilege that would lift both is exactly what 1.4.2 showed the cluster refusing.**

So the sidecar is not merely absent here, it is **structurally unavailable**. The same admission
control that makes [2.4.2](../lesson-02-audit-openshift-scc/) the one rung which records its own
refusals is what stops you deploying the sensor that would have seen this one.

That is the trade this chapter exists to state, and it is not a defect: a managed platform gives you a
strong boundary and a control-plane audit trail for free, and takes away the freedom to put your own
sensor where the workload went.

## Run it

```bash
../../../infra/openshift-sno/install.sh    # bring the shared cluster up (once, ~2 h, EUR 0.263/hr)
./run.sh
../../../infra/down.sh openshift-sno       # DESTROY it — nothing does this for you
```
