# Lesson 6 — Kubernetes

The same attacks, now in a hardened Pod that a cluster scheduled. Kubernetes
**composes** the primitives lesson 2 already showed and invents no new boundary —
the pod still runs on the node's kernel, and Part 2 proves it rather than saying it.

What the cluster *does* add is a scheduler, a declarative way to ask, one new attack
surface, and one genuinely better network verdict.

```bash
cd tutorial/lesson-06-k8s
./run.sh              # provisions its box, runs the lesson there, destroys the box
./run.sh --keep       # ...but leave the box up afterwards, for poking around
```

One command, and the box is destroyed even if the lesson fails. It writes
`report.html` + `report.json` here beside the lesson.

## Where this actually runs

Single-node **k3s**, installed by [`infra/substrates/60-k8s.sh`](../../infra/substrates/60-k8s.sh)
onto the lesson's own disposable Scaleway VM. k3s is conformant Kubernetes: the
`RuntimeClass` field lessons 7 and 8 turn is the same field on any cluster, and it is
the same containerd underneath.

It runs on the box rather than against a managed cluster for a reason that matters
later: **every boundary in this chapter is installed at node level** — runsc's
binaries and a containerd runtime, kata-static plus `/dev/kvm`, the OpenShell
gateway. A managed node pool reconciles that away, and a nested cluster (minikube's
docker driver, kind) puts the node inside a container, which breaks Kata outright and
makes this lesson's "the pod runs on the *node's* kernel" claim untrue of the thing
you actually ran.

## The boundary this lesson teaches

Every control below has a lesson-2 twin. What changed is that you now **declare** it,
and a cluster could refuse you — which is lesson 11's subject, on OpenShift.

```yaml
spec:
  restartPolicy: Never                 # one throwaway pod per run
  automountServiceAccountToken: false  # untrusted code gets NO cluster credential
  securityContext:                     # pod level
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile: { type: RuntimeDefault }
  containers:
    - securityContext:                 # container level
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities: { drop: [ALL] }
      resources:
        limits: { memory: 256Mi, cpu: "1", ephemeral-storage: 256Mi }
```

Two of those are worth pausing on.

`ephemeral-storage` has no lesson-2 equivalent. It is how a cluster caps the *disk*
half of attack 7 — the pod is evicted at a known number instead of filling the node.

And one control is **missing** from the pod spec entirely: there is no pids limit.
Lesson 2 passed `--pids-limit 128` as a container flag; a Pod has no field for it.
Memory, CPU and ephemeral storage are the workload's to request, but the process
ceiling is the **cluster operator's** to impose — so `60-k8s.sh` sets it on the
kubelet (`--kubelet-arg=pod-max-pids=128`). Same number, different owner. That is a
real difference between the two rungs, and this lesson names it rather than hiding it
behind a matching result.

## The attack surface the cluster adds

Every pod gets a **service-account token** mounted at a fixed, guessable path unless
the spec opts out. It is a *cluster* credential: untrusted code that finds one stops
being merely a process on a node and becomes an authenticated principal talking to
the control plane. Nothing on a single host has an equivalent.

`automountServiceAccountToken: false` takes it away, and the scorecard's
`k8s_sa_token` row **measures** that rather than trusting it. The row is deliberately
three-valued, because three different things can be true:

| Reading | Means |
| :-- | :-- |
| `n/a-no-cluster` | not running in a pod at all — every chapter-1 and chapter-2 rung |
| `absent` → BLOCKED | in a pod, no token: the automount opt-out did its job |
| an HTTP status → SUCCEEDED | the token was there and the control plane **accepted it** |

The verdict is over **authentication, not authorisation**. A default service account
is permitted almost nothing by RBAC, so asking "could it list secrets?" would score a
perfectly working cluster credential as contained. Asking "did the control plane
accept it?" does not — and that is the honest question, because the token is a
foothold whatever RBAC allows today.

## The network verdict a container could not express

Lesson 2's container could say "network" or "no network" and nothing in between. With
the network an agent actually needs, attacks 2, 4, 5 and 6 all came back.

A NetworkPolicy can say *this destination, that port*:

```yaml
podSelector: { matchLabels: { app: agent-sandbox } }
policyTypes: [Egress]
egress:
  - to: [{ namespaceSelector: {}, podSelector: { matchLabels: { k8s-app: kube-dns } } }]
    ports: [{ protocol: UDP, port: 53 }, { protocol: TCP, port: 53 }]
  - to: [{ podSelector: { matchLabels: { app: sbx-gateway } } }]
    ports: [{ protocol: TCP, port: 8080 }]
```

**DNS is allowed deliberately**, and not as a convenience. With it denied, every
blocked request times out in the resolver instead of failing to route — so a working
policy looks like a hung agent, and you debug the image instead of reading the
boundary.

The `to:` rules select **pods**, and the lesson talks to the gateway's *pod IP*
rather than a Service ClusterIP. A ClusterIP is DNAT'd by kube-proxy on the way
through, so allowing "the Service" and then watching the packet arrive with a
rewritten destination is a well-known way to write a policy that looks right and
behaves differently across CNIs.

> [!warning]
> **flannel — k3s's default CNI — does not implement NetworkPolicy at all.**
> Enforcement comes from a network-policy controller k3s embeds alongside it. On a
> cluster where that controller is off, every NetworkPolicy object is still accepted,
> still listed by `kubectl get netpol`, and still completely ignored. This lesson's
> whole scoreboard would then be a lie, so [`infra/check.sh`](../../infra/check.sh)
> proves enforcement **with packets** before the lesson runs: reachable *without* the
> policy, unreachable *with* it. Either half alone proves nothing.

## The stand-in gateway answers 200 to everything

The lesson brings up a nine-line Python server as the model gateway the policy is
written around, and it answers **200 to every method**. That is the reason it is not
an off-the-shelf image: `python -m http.server` returns 501 to a POST, and the
`http_method_denied` probe would then read "the POST was denied" — crediting a
NetworkPolicy with a method-awareness it does not have and cannot have.

Make the stand-in indifferent to method, and any difference the probes see is
attributable to policy and to nothing else.

## Assert the boundary engaged

From the readings, never from the manifest that was posted — a manifest that was
*accepted* is not a boundary that *engaged*. The lesson exits without writing a
result unless all five hold:

1. host credentials unreachable (fresh filesystem)
2. no service-account token (the automount opt-out engaged)
3. off-policy egress denied (the NetworkPolicy engaged)
4. a resource cap bit (limits engaged)
5. **the allowed destination still works**

That last one points the opposite way from the other four and is the one worth
understanding. If the gateway were unreachable, every network row would read BLOCKED
and this lesson would announce that a NetworkPolicy stops exfiltration — when in
truth the pod simply had no working network at all. Indistinguishable from a real
result, and the exact false comfort this rung exists to remove.

## Part 3 re-runs lesson 2's container live

Not from `results/lesson-02.json` — that card was measured on a *different machine*,
so any difference could be the hardware. Part 3 runs the hardened container again,
here, minutes apart, and diffs the two.

One variable is held constant rather than copied: the container runs **rootful**,
because the kubelet running the pod is root too. Lesson 2's own headline rung is
rootless, so this is not a re-creation of lesson 2's card — it is lesson 2's
*boundary* at the pod's privilege level, which is what makes "container versus pod"
the only thing that moved.

## What you should see

Measured on a fresh `PLAY2-NANO` VM, k3s `v1.36.3+k3s1`, node kernel
`6.8.0-106-generic` (2026-08-08). **`boundaries that held: 14/19`**, with the network
**on**.

The comparison against lesson 2's hardened container, re-run live on the same box
minutes earlier:

```text
attack               container     pod           changed?
---------------------------------------------------------
read_credentials     BLOCKED       BLOCKED
exfiltrate           SUCCEEDED     BLOCKED       <-- closed
plant_backdoor       BLOCKED       BLOCKED
cloud_metadata       SUCCEEDED     BLOCKED       <-- closed
kernel_identity      SUCCEEDED     SUCCEEDED
sys_module_count     SUCCEEDED     SUCCEEDED
kallsyms_readable    BLOCKED       BLOCKED
bpf                  BLOCKED       BLOCKED
io_uring_setup       BLOCKED       BLOCKED
perf_event_open      BLOCKED       BLOCKED
malicious_package    SUCCEEDED     BLOCKED       <-- closed
reverse_shell        SUCCEEDED     BLOCKED       <-- closed
resource_exhaustion  BLOCKED       BLOCKED

probe            container           pod     ratio
------------------------------------------------
syscall_ms            79.8          77.7     0.97x
cpu_ms               127.2         133.4     1.05x
```

**Four attacks closed, and not one of them by the pod.** Exfiltration, cloud
metadata, the malicious package and the second-stage fetch all died against the
NetworkPolicy — a cluster can say *this destination, that port*, which a container's
on/off could not. This is the first rung in the tutorial to close those four **with
the network still on**. The cost rows are flat (0.97× / 1.05×): scheduling a
container is not a runtime tax.

The rows that make lesson 9 necessary:

```text
[policy]
  egress_gateway       200        BLOCKED   should ALLOW      <-- the allow rule works
  egress_offpolicy     000        BLOCKED   should DENY       <-- the deny rule works
  http_method_denied   200        SUCCEEDED POST should DENY  <-- no method awareness
  binary_scoped        200        SUCCEEDED unlisted binary   <-- no binary awareness
  fs_policy_write      ALLOWED    SUCCEEDED Landlock target   <-- no path policy at all
[reach]
  k8s_sa_token         absent     BLOCKED   automountServiceAccountToken: false
```

The first two rows are the cluster doing something a container cannot. The next three
are the ceiling: **a `POST` to the same allowed host succeeded**, and so did a `curl`
copied to a path nothing named.

And attack 7 behaved differently from lesson 2, at the same 256Mi limit:

```text
pod finished in phase Failed (terminated: OOMKilled)
resource_exhaustion  capped:pod-oomkilled  BLOCKED
```

Lesson 2's container **refuses** the allocation and keeps running. This pod is killed
outright, because cgroup v2 kills a container's cgroup as a group. Same cap, same
verdict, much larger blast radius — and the row proving the cap engaged is the one row
the pod never got to print, so it is merged back in from the kubelet's termination
reason. It is only credited when that reason is `OOMKilled`; anything else reports
`n/a` rather than inventing a boundary.

## What is still open

**Attack 8, untouched.** A pod is namespaces and cgroups on the node's kernel, so
`kernel_identity` still reports the node's and `/sys/module` still lists its modules.
Kubernetes scheduled the boundary; it did not strengthen it.
[`lesson-07-k8s-gvisor`](../lesson-07-k8s-gvisor/) changes one field and watches those
rows collapse.

**The L3/L4 ceiling.** Read the `[policy]` rows. The gateway `GET` was allowed and
the off-policy host denied — a container could express neither. But the `POST` to the
**same allowed host** also succeeded, and so did a `curl` copied to a path nothing
named. A NetworkPolicy judges an address and a port; never a method, never a binary.

**And it wrote nothing down.** A NetworkPolicy that drops a packet leaves no record
that anything was attempted. Attack 9 is exactly as open as it was in lesson 1.

Both of those are [`lesson-09-k8s-openshell`](../lesson-09-k8s-openshell/).

## Next

- [`lesson-07-k8s-gvisor`](../lesson-07-k8s-gvisor/) — `runtimeClassName: gvisor`,
  the shortest lesson in the tutorial, and the kernel rows collapse.
- [`lesson-08-k8s-kata`](../lesson-08-k8s-kata/) — the same one-line change, reaching
  a real guest kernel in a per-pod VM.
- [`lesson-09-k8s-openshell`](../lesson-09-k8s-openshell/) — per-binary and
  method-aware policy, plus the audit trail every rung so far has lacked.
