# Lesson 2.4.2 — Auditing SCC admission

**The only boundary in this tutorial that writes down what it refused.**

[Lesson 1.4.2](../../../phase1-attacks/chapter-4-openshift/lesson-02-openshift-scc/) showed OpenShift
refusing an over-privileged pod before it ever starts. This lesson makes the same two requests and
then goes looking for them in the **kube-apiserver audit log**.

**Containment is 1.4.2's exactly: 3/3, zero rows different. All 3 are also `LOGGED`.**

## The finding: this is the inversion phase 2 has been building to

Run back through the ladder and the same gap appears at every rung:

| rung | the boundary refused something | was the refusal recorded? |
| :-- | :-- | :-- |
| [2.2.1](../../chapter-2-one-host/lesson-01-audit-container/) | seccomp refuses `bpf` at syscall **entry** | **no** — the call never runs, so no kernel-side sensor can fire |
| [2.2.4](../../chapter-2-one-host/lesson-04-audit-container-openshell/) / [2.3.4](../../chapter-3-kubernetes/lesson-04-audit-k8s-openshell/) | Landlock denies the write to `/etc` | **no** — neither auditd nor OCSF sees it |
| [2.3.6](../../chapter-3-kubernetes/lesson-06-audit-compose-kata-openshell/) | a guest kernel hides the workload | **no** — the host sensor reads zero |
| **2.4.2** | SCC admission refuses the pod | **yes — in full** |

Measured here: a **403**, the identity that asked
(`system:serviceaccount:sbx-2-4-2:rogue`), and the entire SCC evaluation carried verbatim in the
record. The admitted pod is recorded too, with a 201. Nothing was installed, nothing was armed, and
nothing has to survive a reboot — unlike [2.4.1](../lesson-01-audit-openshift-pod/)'s node auditd.

## The rule that generalizes past OpenShift

> A boundary records what it refused **only when its decision is itself an event the platform already
> audits.**

Landlock, seccomp and a guest kernel all make their decisions in silence, in the kernel, with no
obligation to tell anyone. Admission control makes its decision by **answering an API call** — and the
API server audits every call it answers. The difference is not how strong the boundary is. It is where
the decision happens to live.

1.4.2 closes on *"no audit record to keep — because nothing ran"*. That is exactly half right, and
this lesson is the other half: **nothing ran, and the refusal was recorded anyway.**

## The trap this inherits from 1.4.2

The service account is granted `edit` RBAC **first**. Without it the refusal comes from RBAC, not SCC,
and the message says `cannot get resource pods` — you would conclude admission rejected the privileged
pod when in fact nothing ever evaluated it. Granting RBAC makes SCC the only thing left that can
refuse, which is the whole experiment. The lesson asserts the refusal actually mentions
`security context constraint` rather than trusting that it failed for the right reason.

## Run it

```bash
../../../infra/openshift-sno/install.sh    # bring the shared cluster up (once, ~2 h, EUR 0.263/hr)
./run.sh
../../../infra/down.sh openshift-sno       # DESTROY it — nothing does this for you
```
