# Lesson 1.2.6 — Composition: OpenShell over Kata (documentation only)

> **This leaf is documentation, not a runnable lesson.** There is no `main.py`, no
> `run.sh`, and no entry in `infra/lessons.json` — nothing here provisions a box,
> because on the chapter-2 host this composition **has no mechanism to run**. It is
> demonstrated for real in
> [chapter 3, lesson 1.3.6](../../chapter-3-kubernetes/lesson-06-compose-kata-openshell/README.md)
> and [chapter 4, lesson 1.4.6](../../chapter-4-openshift/lesson-06-compose-kata-openshell/README.md).

Kata (lesson 1.2.3) gives each workload its own guest kernel; OpenShell (lesson 1.2.4)
adds per-binary and method-aware policy. Unlike the gVisor stack, this pairing is
the one that *works* — a real guest kernel ships Landlock, so OpenShell's
filesystem policy keeps being enforced underneath it. But on this host there is
still no way to place OpenShell's sandbox onto Kata, for a reason that is
architectural, not a missing flag.

## Why there is no mechanism here

Kata is a **containerd shim-v2** (`io.containerd.kata.v2`). Podman cannot drive a
shim-v2 on **any** OS — it is not a version problem, it is a different
architecture, which is exactly why [lesson 1.2.3](../lesson-03-container-kata/README.md)
stands Kata up under containerd + `nerdctl` instead of podman. OpenShell's
chapter-2 driver **is** podman. So the driver that delivers OpenShell here has no
path to a shim-v2 runtime, and there is no seam to hand OpenShell's sandbox onto
Kata. The composition has no place to happen on this host.

## Where it does happen — and what it shows

The moment the engine underneath is containerd — a Kubernetes node — the runtime
becomes a `runtimeClassName`, and OpenShell's kubernetes driver can select it per
sandbox. That is
[chapter 3, lesson 1.3.6](../../chapter-3-kubernetes/lesson-06-compose-kata-openshell/README.md)
on k3s and
[chapter 4, lesson 1.4.6](../../chapter-4-openshift/lesson-06-compose-kata-openshell/README.md)
on OpenShift, where Kata is the shipped product. Both show OpenShell's filesystem
policy still enforcing — `fs_policy_write` stays **blocked** — because the guest
kernel is a real one and Landlock is present. That is the deliberate contrast with
the gVisor stack (lesson 1.3.5), and the pair together are the whole composition
finding; it is written up once in
[`docs/isolation-layers.md`](../../../../docs/isolation-layers.md) § *The trap:
stacking two boundaries can make you less safe*.

---

*If podman ever gains the ability to drive a containerd shim-v2, replace this
README with a runnable lesson.*
