# Lesson 2.4.5 — Auditing OpenShell over gVisor on OpenShift (documentation only)

> **This leaf is documentation, not a runnable lesson.** There is no `main.py`, no
> `run.sh`, and no entry in `infra/lessons.json` — nothing here provisions or touches the cluster.
> Its phase-1 twin [1.4.5](../../../phase1-attacks/chapter-4-openshift/lesson-05-compose-gvisor-openshell/README.md)
> is a stub for the same reason: **on OpenShift this composition has no runtime to select**, so there
> is no boundary here to audit. The audit is done for real in
> [2.3.5](../../chapter-3-kubernetes/lesson-05-audit-compose-gvisor-openshell/README.md).
>
> It is also the one chapter-4 audit leaf that needs **no cluster**, which is why it exists while
> 2.4.1–2.4.4 and 2.4.6 do not: those are blocked on the human-owned single-node OpenShift box.

## Why there is nothing to audit here

gVisor is **not a supported OpenShift runtime**. Nothing installs `runsc` on the node, so there is no
`RuntimeClass gvisor` for OpenShell's kubernetes driver to name, and its per-sandbox runtime overlay
has nothing to select. Getting one would mean hand-installing `runsc` on RHCOS through a
MachineConfig — editing the immutable OS out from under the platform — which chapter 4 deliberately
does not do: the chapter teaches what OpenShift *ships*, and what it ships is Kata, via the
sandboxed-containers operator.

No composition means no sensor question. There is no trail to read, and writing one up would be the
false confidence this repo exists to avoid.

## What the audit question *would* have been, and where it is answered

Under gVisor there is **no host-sensor path at all** — not a weak one, none. The workload's syscalls
are serviced by the sentry in user space, so a probe on the host kernel is attached to the wrong
kernel; Falco removed its gVisor event source in 0.41 and Tetragon never had one (discovery gate
**G2**). The sensors that remain are gVisor's own trace and OpenShell's L7 trail.

[2.3.5](../../chapter-3-kubernetes/lesson-05-audit-compose-gvisor-openshell/README.md) runs that pair
on k3s — the gVisor stack's one real home in this tutorial — and finds the sharpest result in phase 2:
**6 HIGH `landlock-unavailable` findings** in the OCSF trail while `fs_policy_write` reads **BLOCKED**,
the same verdict a genuinely safe stack gives. gVisor drops Landlock, a read-only rootfs masks the
loss, and the containment scorecard cannot tell the broken stack from the safe one. Only the audit
trail can — and `landlock.compatibility: hard_requirement` is what turns that line into a refusal to
start rather than something nobody read.

The rule it generalizes — *composition fails when the lower layer removes a kernel feature the upper
layer depends on* — is developed once in
[`docs/isolation-layers.md`](../../../../docs/isolation-layers.md) § *The trap: stacking two
boundaries can make you less safe*, rather than repeated here.

---

*If OpenShift ever supports gVisor as a runtime (a `RuntimeClass gvisor` without hand-patching RHCOS),
1.4.5 becomes runnable and this leaf should become its audit twin.*
