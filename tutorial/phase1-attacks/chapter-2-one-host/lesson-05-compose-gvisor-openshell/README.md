# Lesson 1.2.5 — Composition: OpenShell over gVisor (documentation only)

> **This leaf is documentation, not a runnable lesson.** There is no `main.py`, no
> `run.sh`, and no entry in `infra/lessons.json` — nothing here provisions a box,
> because on the chapter-2 host this composition **has no mechanism to run**. The
> reason it has none is the lesson. It is demonstrated for real in
> [chapter 3, lesson 1.3.5](../../chapter-3-kubernetes/lesson-05-compose-gvisor-openshell/README.md).

Chapter 2 taught two boundaries that are strong in **disjoint columns**: gVisor
(lesson 1.2.2) shrinks the host-kernel attack surface, and OpenShell (lesson 1.2.4) adds
per-binary and method-aware policy on ordinary runc. Stacking one under the other
is the obvious next question — put OpenShell's policy engine on top of gVisor's
smaller kernel and get both. On this host you cannot even try, and that is worth
stating plainly rather than leaving as a gap.

## Why there is no mechanism here

OpenShell's chapter-2 delivery is its **rootless-podman** driver — the reason
lesson 1.2.4 runs inside a NAT'd guest at all. Composing it over gVisor would need
rootless podman to drive `runsc`, and it cannot:

```text
systemd cgroup manager  ->  runsc: creating container: systemd error:
                            Interactive authentication required
cgroupfs manager        ->  runsc: cannot set up cgroup for root: configuring cgroup:
                            open /sys/fs/cgroup/cgroup.subtree_control: permission denied
```

`runsc` insists on creating the container's cgroup, and an unprivileged user
cannot — which is exactly why [lesson 1.2.2](../lesson-02-container-gvisor/README.md)
runs **rootful**. OpenShell's podman driver is rootless by design. The two
requirements are contradictory on one host: the driver that delivers OpenShell
here refuses to run rootful, and the runtime it would stack onto refuses to run
rootless. There is no `--runtime runsc` seam to hand OpenShell's sandbox, so the
composition is not "hard here" — it has no place to happen.

## Where it does happen — and what it shows

Kubernetes is the layer where the two finally meet, because there the lower
runtime is selected declaratively with `runtimeClassName` and OpenShell's
kubernetes driver can set that field per sandbox. That is
[chapter 3, lesson 1.3.5](../../chapter-3-kubernetes/lesson-05-compose-gvisor-openshell/README.md),
and the result is a **failure mode**, not a stronger boundary: OpenShell's
filesystem policy leans on **Landlock**, gVisor answers `ENOSYS` to Landlock, and
the clause silently loses its Landlock backing — flagged only in the audit trail
(the read-only rootfs happens to keep the write blocked, so the loss is otherwise
invisible). The rule that generalizes — *composition fails when the lower layer
removes a kernel feature the upper layer depends on* — is developed once in
[`docs/isolation-layers.md`](../../../../docs/isolation-layers.md) § *The trap:
stacking two boundaries can make you less safe*, rather than re-argued here.

---

*If rootless podman ever gains the ability to drive `runsc` (or OpenShell ships a
rootful podman driver), replace this README with a runnable lesson.*
