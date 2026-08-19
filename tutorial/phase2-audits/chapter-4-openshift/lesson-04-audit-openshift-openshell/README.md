# Lesson 2.4.4 — Auditing the OpenShell rung on OpenShift

Audits [1.4.4](../../../phase1-attacks/chapter-4-openshift/lesson-04-openshift-openshell/) — the same
policy file, the same sandbox, the same suite — with every sensor this platform can offer pointed at
it at once.

**Containment is 1.4.4's exactly: 15/19, zero rows different.**

## The finding: full coverage is the union of sensors with disjoint blind spots

**12 of 19 written down**, by two sensors that see different things:

| sensor | catches | count |
| :-- | :-- | --: |
| **OCSF** — OpenShell's L7 decision trail | the network attacks, by binary/method/endpoint, and what the policy **denied** | 8 |
| **the node's `auditd`** — armed as 2.4.1 arms it | the local attacks; OpenShell is ordinary runc, so its syscalls reach the node's kernel | 4 (923 paths attributed) |
| **the kube-apiserver audit log** | the control plane — on by default | 0 of the workload's |

That is 2.2.4's two-sensor result and 2.3.4's three-column one, holding on a third platform.

## The gap all three share — and its exact opposite, one rung away

`fs_policy_write` is recorded by **nothing**, and it is the same structural gap 2.2.4 and 2.3.4 found:
the write is denied by **Landlock** before it resolves to a file an auditor could name, and Landlock is
a kernel verdict rather than an L7 one, so OpenShell's own trail never sees it either. *A host auditor
records what the workload did; only the enforcing layer knows what it refused.*

Now put that beside [2.4.2](../lesson-02-audit-openshift-scc/), on this same cluster and in the same
session. There, admission refuses a pod and the refusal is recorded **in full** — 403, the identity,
the entire SCC evaluation — because the decision *is* an API request. Two refusals, opposite outcomes.
The difference is not which boundary is stronger; it is whether the decision is an event something
already audits.

## The attribution problem this rung adds

2.4.1 scopes its audit rule by uid. That records **nothing** of an OpenShell sandbox, and the reason is
worth knowing: **OpenShell owns the sandbox pod spec and sets no `runAsUser`**, so the uid is neither
the stock image's 1001 nor the lesson namespace's assigned range — there is nothing for the lesson to
guess or read ahead of time. Measured: 0 paths attributed to a runc sandbox whose syscalls
demonstrably reach this kernel.

The fix is to scope the rule by **SELinux type** instead — `-F subj_type=container_t`, "any container
on this node" — and let the pod's MCS decide whose records they are at read time. That composes
exactly with how attribution already works here: *the rule decides what the kernel records, the MCS
decides whose it was.* It records more, which is why the read side spans **every** rotated segment
rather than three.

## Two operational traps worth knowing

* **The gateway goes flaky after repeated sandbox churn.** `openshell sandbox exec` starts timing out
  at 180 s. Restarting the `openshell-0` pod clears it.
* **The cluster runs out of storage for sandboxes.** Each sandbox binds one of the pre-provisioned
  hostPath PVs, and until 2026-08-15 those were created with `persistentVolumeReclaimPolicy: Delete` —
  which has no deleter for hostPath, so every released volume went to `Failed` and was gone for good.
  With four PVs and one held permanently by the gateway, the whole chapter got **three sandboxes,
  ever**; the fourth hung `Pending` on `unbound immediate PersistentVolumeClaims`, which reads like a
  broken gateway. `install.sh` now provisions 12 with `Retain` and frees released volumes on
  `--from storage`.

## Run it

```bash
../../../infra/openshift-sno/install.sh    # bring the shared cluster up (once, ~2 h, EUR 0.263/hr)
./run.sh                                   # starts and stops its own port-forward to the gateway
../../../infra/down.sh openshift-sno       # DESTROY it — nothing does this for you
```

OpenShell is **alpha** and pinned to 0.0.99 by this leaf's `pyproject.toml`; it must match the chart
`install.sh` deploys.
