# Lesson 18 — Composition: OpenShell over gVisor on OpenShift (documentation only)

> **This leaf is documentation, not a runnable lesson.** There is no `main.py`, no
> `run.sh`, and no entry in `infra/lessons.json` — nothing here provisions or
> touches the cluster, because on OpenShift this composition **has no runtime to
> select**. It is demonstrated for real in
> [chapter 3, lesson 16](../../chapter-3-kubernetes/lesson-16-compose-gvisor-openshell/README.md).

Chapter 4 runs OpenShell over Kata for real (lesson 19), because Kata is what
OpenShift ships. The obvious companion — OpenShell over gVisor — cannot be built
here, and the reason is the same one that keeps gVisor out of the rest of the
chapter.

## Why there is no runtime to select

gVisor is **not a supported OpenShift runtime**. There is no `RuntimeClass gvisor`
for OpenShell's kubernetes driver to name, because nothing installs `runsc` on the
node. Getting one would mean hand-installing `runsc` on RHCOS via a MachineConfig
— editing the immutable OS out from under the platform — which
[chapter 4 deliberately does not do](../../../syllabus.md). The chapter teaches
what OpenShift *ships*, and OpenShift ships one hypervisor-backed runtime: Kata,
via the sandboxed-containers operator (lesson 12). With no `runtimeClassName:
gvisor` to pass, OpenShell's per-sandbox runtime overlay has nothing to select,
and the composition has no place to happen on this cluster.

## Where it does happen — and what it shows

The gVisor stack has exactly one real home in this tutorial: k3s, where `runsc` is
installed at node level and OpenShell's kubernetes driver can set
`runtimeClassName: gvisor` per sandbox. That is
[chapter 3, lesson 16](../../chapter-3-kubernetes/lesson-16-compose-gvisor-openshell/README.md),
where the composition silently **loses Landlock** — gVisor answers `ENOSYS` to
Landlock, so OpenShell's filesystem clause drops its Landlock backing, visible only
as a HIGH audit finding (a read-only rootfs keeps the write blocked, masking the
loss). The rule and the fail-closed remedy (`landlock.compatibility:
hard_requirement`) are developed once in
[`docs/isolation-layers.md`](../../../docs/isolation-layers.md) § *The trap:
stacking two boundaries can make you less safe*, rather than repeated here.

---

*If OpenShift ever supports gVisor as a runtime (a `RuntimeClass gvisor` without
hand-patching RHCOS), replace this README with a runnable lesson.*
