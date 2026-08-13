# Lesson 11 — OpenShift SCC: the cluster refuses to run the agent

Every other rung in this tutorial **contains** an agent that is already running. This
one is a different kind of boundary: the cluster declines to start the workload at all —
the earliest and cheapest place to stop a bad one.

```bash
../../../infra/openshift-sno/install.sh    # the shared chapter-4 cluster, once
cd tutorial/chapter-4-openshift/lesson-11-openshift-scc
./run.sh
```

## What an SCC is, in one sentence

On plain Kubernetes you **ask** for privileges in your pod spec and the cluster generally
gives them to you. On OpenShift a gatekeeper checks that request against a policy bound
to your account and **rejects the pod before it ever starts**.

Lesson 6's hardening worked because we wrote a careful spec. Nothing stopped us writing a
careless one. Here, nothing *permits* a careless one.

## The teaching moment is a failure

The pod a careless engineer writes — `privileged: true`, `runAsUser: 0`, a `hostPath`
mount of `/` — never runs:

```text
Error from server (Forbidden): pods "rogue-privileged" is forbidden:
unable to validate against any security context constraint:
  [provider "anyuid": Forbidden: not usable by user or serviceaccount,
   provider restricted-v2: .containers[0].runAsUser: Invalid value: 0:
     must be in the ranges: [1000740000, 1000749999],
   provider restricted-v2: .containers[0].privileged: Invalid value: true:
     Privileged containers are not allowed,
   provider "privileged": Forbidden: not usable by user or serviceaccount, ...]
```

Read that carefully. It walked **every** SCC on the cluster and gave a reason for each.
Two matter; the rest simply are not bound to this account. **No container was created,
no image pulled, no syscall intercepted** — there was nothing to contain.

The same workload asking for nothing is admitted:

```text
compliant pod: ADMITTED
admitted under SCC: restricted-v2
```

**The fix was to DELETE `runAsUser`, not to add anything.** OpenShift assigns a UID from
the project's range; pinning one yourself is the commonest reason a manifest that works
on vanilla Kubernetes is refused here. That is also why lesson 10's pod omits it.

## Grant RBAC first, or you measure the wrong thing

> [!warning]
> **Trap #13.** A bare service account cannot create a pod at all, and the error is
> `cannot get resource pods` — that is **RBAC**, not SCC. You would conclude admission
> rejected your privileged pod when in fact nothing ever evaluated it.

So the lesson grants the test SA `edit` first. That makes SCC the *only* thing left that
can refuse, which is the entire point of the experiment. The assertion checks for the
string `security context constraint` in the refusal for exactly this reason — a refusal
is not evidence unless you know **who** refused.

## What you should see

Measured on single-node OpenShift 4.18.49 (2026-08-10):

```text
[policy]
  scc_privileged_refused    Forbidden                    BLOCKED
  scc_refused_by_admission  security-context-constraint  BLOCKED
  scc_compliant_admitted    restricted-v2                BLOCKED
  scc_count                 14                           n/a

[OK] the privileged pod was REFUSED
[OK] refused by SCC admission, not RBAC (Trap #13)
[OK] the compliant pod was ADMITTED
[OK] and OpenShift recorded which SCC allowed it
```

## Why there is no attack scorecard here

This is the one rung that **cannot** be measured with the nine attacks, and the reason is
the finding: the agent never executed a single instruction. A boundary that refuses to
start a workload has no runtime behaviour to probe. The rejection *is* the result, so
that is what the lesson records.

It is also the cheapest boundary on the ladder by a wide margin — no VM to boot, no
syscall table to intercept, no audit trail to write, because nothing ran.

## SCC and Pod Security Admission are not alternatives

OpenShift runs **both**. PSA is the upstream Kubernetes mechanism (`restricted`,
`baseline`, `privileged` at namespace level); SCC is OpenShift's older, finer-grained one
that also *mutates* — it is what assigns your UID from the project range. On a modern
OpenShift they run side by side, and a pod must satisfy both.

And an agent workload must never be granted `anyuid`. It is the SCC people reach for when
a container "needs" to be root, and it removes precisely the control this lesson
demonstrates.

## Next

- [`lesson-12-openshift-kata`](../lesson-12-openshift-kata/) — for the workloads that
  *are* admitted, a per-pod VM, as a supported product rather than a DIY install.
