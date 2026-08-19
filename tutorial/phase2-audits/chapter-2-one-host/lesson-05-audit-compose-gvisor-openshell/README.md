# Lesson 2.2.5 — Auditing OpenShell over gVisor (documentation only)

> **This leaf is documentation, not a runnable lesson.** There is no `main.py`, no
> `run.sh`, and no entry in `infra/lessons.json` — nothing here provisions a box.
> Its phase-1 twin [1.2.5](../../../phase1-attacks/chapter-2-one-host/lesson-05-compose-gvisor-openshell/README.md)
> is a stub for the same reason: **on the chapter-2 host this composition has no mechanism to run**,
> so there is no boundary here to audit. The audit is done for real in
> [2.3.5](../../chapter-3-kubernetes/lesson-05-audit-compose-gvisor-openshell/README.md).

Phase 2 asks *would you ever know the attempt was made?* — of the same boundary its phase-1 twin
measured. Where the twin has no boundary, the audit twin has nothing to watch. That is the whole of
this leaf, and it is worth one page rather than a silent gap in the numbering.

## Why there is nothing to audit here

OpenShell reaches this host through its **rootless-podman** driver, and `runsc` refuses to run
rootless (it must create the container's cgroup, which an unprivileged user cannot). The two
requirements are contradictory on one machine, so there is no `--runtime runsc` seam to hand
OpenShell's sandbox — the composition has no place to happen. 1.2.5 has the error messages.

No composition means no sensor question. Auditing a stack that cannot be built would mean inventing
its trail, which is precisely the false confidence this repo exists to avoid.

## What the audit question *would* have been, and where it is answered

Worth stating, because it is the sharpest one in phase 2 and this chapter cannot reach it.

Under gVisor a **host** sensor is attached to the wrong kernel: the workload's syscalls are serviced
by the sentry in user space, so the host kernel never sees the call the application made. That is
discovery gate **G2**, and it failed as specified — Falco removed its gVisor event source in 0.41 and
Tetragon never had one, so there is no host-sensor path whichever tool you pick. The sensors that
remain are gVisor's own trace and OpenShell's L7 trail.

[2.3.5](../../chapter-3-kubernetes/lesson-05-audit-compose-gvisor-openshell/README.md) runs exactly
that pair on k3s, and it is the leaf that justifies phase 2 existing at all. Measured there:
**6 HIGH `landlock-unavailable` findings** in OpenShell's OCSF trail while `fs_policy_write` reads
**BLOCKED** — the same verdict the safe stacks give. gVisor drops Landlock, the read-only rootfs masks
the loss, and **the containment scorecard is identical to a stack that is genuinely safe**. One line
of audit trail is the only thing in the entire run that tells them apart.

Two rungs of this chapter already carry the halves of that finding:

- [2.2.2](../lesson-02-audit-container-gvisor/README.md) — the host sensor goes blind under gVisor and
  the sentry's own `--strace` is what still sees (11/12).
- [2.2.4](../lesson-04-audit-container-openshell/README.md) — OpenShell's OCSF trail is the sensor
  that records what the boundary **denied**, which no syscall auditor can (15/19, two disjoint sensors).

---

*If rootless podman ever gains the ability to drive `runsc` (or OpenShell ships a rootful podman
driver), 1.2.5 becomes runnable and this leaf should become its audit twin.*
