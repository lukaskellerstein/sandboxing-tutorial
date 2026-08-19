# Lesson 2.2.6 — Auditing OpenShell over Kata (documentation only)

> **This leaf is documentation, not a runnable lesson.** There is no `main.py`, no
> `run.sh`, and no entry in `infra/lessons.json` — nothing here provisions a box.
> Its phase-1 twin [1.2.6](../../../phase1-attacks/chapter-2-one-host/lesson-06-compose-kata-openshell/README.md)
> is a stub for the same reason: **on the chapter-2 host this composition has no mechanism to run**,
> so there is no boundary here to audit. The audit is done for real in
> [2.3.6](../../chapter-3-kubernetes/lesson-06-audit-compose-kata-openshell/README.md).

## Why there is nothing to audit here

Kata is a **containerd shim-v2** (`io.containerd.kata.v2`), and podman cannot drive a shim-v2 on any
OS — it is a different architecture, not a missing flag. OpenShell's chapter-2 driver *is* podman, so
there is no seam to place its sandbox onto Kata. 1.2.6 has the full argument.

No composition means no sensor question, and inventing one would be the false confidence this repo
exists to avoid.

## What the audit question *would* have been, and where it is answered

This pairing is the one that **works** on the containment side — a real guest kernel ships Landlock,
so OpenShell's filesystem policy keeps being enforced underneath it. The audit side is where it gets
expensive, and chapter 2 already has half the answer:

[2.2.3](../lesson-03-audit-container-kata/README.md) measured a host sensor behind Kata's guest kernel
at **zero** — fully blind, because the workload's syscalls cross the guest kernel and never touch the
host's. Coverage returned only by putting a sensor **inside** the guest.

[2.3.6](../../chapter-3-kubernetes/lesson-06-audit-compose-kata-openshell/README.md) runs the
composition on k3s and measures both halves at once, one field apart from
[2.3.4](../../chapter-3-kubernetes/lesson-04-audit-k8s-openshell/README.md):

| sensor | on runc (2.3.4) | over Kata (2.3.6) |
| :-- | --: | --: |
| host Tetragon | 7 attacks | **0** |
| OpenShell's OCSF trail | 8 attacks | **8** |

OCSF survives because it is **not a syscall sensor** — it is an L7 proxy in the gateway, sitting on
the network path, which a VM boundary does not cut. That makes it the one sensor that has seen every
rung of this ladder, and the price is printed in its column: it sees **network attacks only**.

Recovering the local column needs a sensor in the guest with the workload, which
[2.3.3](../../chapter-3-kubernetes/lesson-03-audit-k8s-kata/README.md) builds — and which
corrects the prediction 2.2.3 left behind. A privileged sidecar does **not** get the guest's init
context (`privileged` + `runAsUser: 0` + full `CapEff` + `hostPID: true` all still get `EPERM` from
the guest's audit netlink, because under Kata the kubelet's "host" is the sandbox, not the VM). The
sensor that works is a **ptrace** tracer, enabled by `shareProcessNamespace: true` — a Kubernetes
construct with no nerdctl equivalent, since here one container is one VM and there is nothing to
share. Which is a second, independent reason this leaf cannot be runnable on the chapter-2 host.

---

*If podman ever gains the ability to drive a containerd shim-v2, 1.2.6 becomes runnable and this leaf
should become its audit twin — though note the in-guest sensor would still be a ptrace tracer, for
the reason 2.3.3 measured.*
