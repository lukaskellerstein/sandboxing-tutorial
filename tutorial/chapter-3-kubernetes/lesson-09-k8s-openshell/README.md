# Lesson 9 — OpenShell on the cluster: policy and audit at fan-out scale

Lesson 6 closed attacks 2, 4, 5 and 6 with a NetworkPolicy, then showed the ceiling: a
`POST` to the **same allowed host** succeeded, a `curl` copied to an unnamed path
succeeded, and nothing anywhere recorded that either was attempted. Lessons 7 and 8
changed the kernel underneath and moved **none** of those rows, because neither gVisor
nor Kata reads HTTP.

This rung closes them, with the network still on.

```bash
cd tutorial/chapter-3-kubernetes/lesson-09-k8s-openshell
./run.sh              # provisions its box, runs the lesson there, destroys the box
./run.sh --keep       # ...but leave the box up afterwards, for poking around
```

> [!warning]
> **OpenShell is alpha, and its Kubernetes path is the newest part of it.** Upstream
> says so plainly. The version is pinned in
> [`infra/substrates/chapter-3/90-k8s-openshell.sh`](../../../infra/substrates/chapter-3/90-k8s-openshell.sh)
> and recorded in this lesson's scorecard; unpinned alpha tooling rots silently.

## What actually changed from lesson 5

Almost nothing, and that is the point worth taking away. Lesson 5 ran the **podman**
driver on one machine. This is the **kubernetes** driver, where each sandbox is a Pod.

The policy file is lesson 5's, and the only line that had to move is the endpoint's
host — because the gateway is now a Service rather than a host alias:

```diff
-      - host: host.openshell.internal
-        port: 18410
+      - host: sbx-gateway.sbx-lesson-09.svc.cluster.local
+        port: 8080
```

Everything else — `filesystem_policy`, `landlock`, `process`, the `read-only` access
mode, the per-binary list — is unchanged. **The policy language does not know which
compute driver is underneath it**, which is the actual argument for a policy layer over
a per-deployment-target one.

## Two components, in order

```bash
# 1. the Agent Sandbox controller — the CRD OpenShell's kubernetes driver creates objects against
kubectl apply --server-side -f \
  https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.5.4/sandbox.yaml

# 2. the OpenShell gateway
helm upgrade --install openshell oci://ghcr.io/nvidia/openshell/helm-chart \
    --version 0.0.99 --namespace openshell --create-namespace \
    --set server.auth.allowUnauthenticatedUsers=true    # LOCAL DEV ONLY
```

Order matters: a gateway installed before the CRD comes up healthy and then fails
**every** sandbox create.

Component 1 is not OpenShell-specific. The **Agent Sandbox** controller is the
vendor-neutral, Kubernetes-native *orchestration* layer — the `Sandbox` API that
*selects* a runtime and runs the pod, but adds **no isolation of its own**. It is a
different axis from every boundary this tutorial scores;
[`docs/orchestration.md`](../../../docs/orchestration.md) explains where it fits and
why it has no scored lesson.

> [!note]
> The asset is `sandbox.yaml`. Guides written against agent-sandbox v0.5.3 and earlier
> say `manifests.yaml`, which no longer exists — a 404 that reads like a network
> problem rather than a renamed file.

`allowUnauthenticatedUsers` removes the gateway's identity-provider requirement so the
CLI can talk to it without one. Acceptable here for exactly one reason, stated rather
than assumed: **this box is destroyed minutes later.** Never on anything shared.

## The four traps, each of which produces a confusing failure

1. **One compute driver per gateway.** A gateway accepts a single driver. Lesson 5's is
   `podman`; this one is `kubernetes`, and they cannot share a configuration. Get it
   wrong and sandboxes simply refuse to create, with no message about drivers — so the
   lesson checks `OPENSHELL_DRIVERS` by name before doing anything else.

2. **`:latest` breaks a side-loaded image.** OpenShell owns the sandbox pod spec, so
   you cannot set `imagePullPolicy` yourself — and Kubernetes defaults a `:latest` tag
   to `Always`, sending the kubelet to Docker Hub for an image already on the node. Any
   other tag defaults to `IfNotPresent`, which is why the agent image is `:v1`
   everywhere in this chapter.

3. **Sandbox names cap at 19 characters**, and a longer one fails at create with a
   message that never mentions length.

4. **`create` returns before the sandbox accepts work.** An `exec` issued in that
   window does not fail — it *hangs*. `wait_ready()` polls `sandbox list` for `Ready`
   first. Lesson 5 hit this too; the cluster driver only widens the window, because a
   pod must be scheduled and pulled first.

There is a fifth that shapes the substrate: the gateway serves gRPC over **mTLS** and
`gateway add --local` **seeds** its `mtls/` directory from any gateway config already
present. So the client certificates must be copied *after* `gateway add`, never before,
or they are promptly overwritten and the failure surfaces later as a handshake error
that looks like a bad certificate rather than a clobbered one. Do not reach for
`--gateway-insecure`: it drops the client identity and the server answers
`CertificateRequired`.

## The experiment: two Services, one line of policy apart

The lesson stands up two identical stand-in servers behind Services:

| Service | In the policy? | Role |
| :-- | :-- | :-- |
| `sbx-gateway` | yes, `read-only` | the model gateway the agent legitimately needs |
| `sbx-collector` | **no** | the attacker's listener, the package index, the second stage |

Same image, same protocol, same port. **One line of policy separates them.** A
NetworkPolicy could draw that distinction too — lesson 6 did. The next two probes are
where it cannot follow:

- `http_method_denied` — a `POST` to the **same allowed host**, which lesson 6 let
  through because L3/L4 has no concept of a method.
- `binary_scoped` — the same `curl`, copied byte-for-byte to `/tmp`, making the
  identical request. The policy names a *path*, so the copy is denied. No kernel-level
  sandbox can see that difference, because at the syscall layer nothing about it
  differs.

## Assert the policy engaged

The distinguishing pair is the whole lesson: the allowed `GET` must **succeed** and the
same host's `POST` must **not**.

If both failed, egress is simply broken and every `BLOCKED` row is meaningless. If both
succeeded, no policy is being enforced. Only the split proves an L7 decision actually
happened — so the lesson refuses to write a result without it.

## Attack 9 dies here

Every rung before this one recorded **nothing** — not the exfiltration it blocked, not
the metadata request, not the typosquat install. `audit_records` is `0` on all of them.

OpenShell's L7 proxy writes an OCSF trail of every decision, *including the attempts
that failed*. That is the difference between "it was blocked" and an incident report.

The order matters: arm the OCSF writer **first**, then reload the policy — the reload
is what activates it. Enable it afterwards and the trail stays empty, which looks
exactly like a broken feature rather than a sequencing mistake.

## What you should see

Measured on a fresh `PLAY2-MICRO` VM, k3s `v1.36.3+k3s1`, agent-sandbox `v0.5.4`,
OpenShell `0.0.99` (CLI **and** chart), node kernel `6.8.0-106-generic` (2026-08-08).
**`boundaries that held: 17/19`**.

**The three rows lesson 6 could not close**, side by side with what a NetworkPolicy
managed on the identical probes:

| probe | lesson 6 (NetworkPolicy) | lesson 9 (OpenShell) |
| :-- | :-- | :-- |
| `egress_gateway` — should ALLOW | `200` BLOCKED | `200` BLOCKED |
| `egress_offpolicy` — should DENY | `000` BLOCKED | `403` BLOCKED |
| `http_method_denied` — POST to the **same allowed host** | `200` **SUCCEEDED** | `403` **BLOCKED** |
| `binary_scoped` — a copied `curl` at an unnamed path | `200` **SUCCEEDED** | `403` **BLOCKED** |
| `fs_policy_write` — a path policy | `ALLOWED` **SUCCEEDED** | `PermissionError` **BLOCKED** |

Note the `000` versus `403` in the second row. Both are denials, and they are not the
same event: `000` is *nothing answered*, `403` is *something refused you and wrote it
down*. That difference is the rest of this lesson.

**Attack 9 dies here.** 19 policy decisions recorded, naming the binary, the method and
the reason:

```text
HTTP:POST [MED]  DENIED  /usr/bin/curl(39) -> POST http://sbx-collector...:8080/collect
    [policy:- engine:opa] [reason:endpoint sbx-collector...:8080 is not allowed by any policy]
HTTP:GET  [MED]  DENIED  /usr/bin/curl(40) -> GET http://169.254.42.42/conf
    [policy:- engine:opa] [reason:endpoint 169.254.42.42:80 is not allowed by any policy]
HTTP:GET  [INFO] ALLOWED /usr/bin/curl(41) -> GET http://sbx-gateway...:8080/v1/models
    [policy:model_gateway engine:l7]
```

Every rung before this one recorded **nothing** — `audit_records` is absent or `0`
everywhere else. "It was blocked" is not an incident report; that is.

**Two rows stay open, and both are the point:**

```text
kernel_identity   6.8.0-106-generic   SUCCEEDED the SAME kernel as the node
plant_backdoor    3                   SUCCEEDED ~/.bashrc,~/.profile,~/.ssh/authorized_keys
```

`kernel_identity` is the headline — see below. `plant_backdoor` reads exactly as it
does on lesson 5 (`3`, SUCCEEDED): the policy grants `read_write: [/sandbox, /tmp,
/dev/null]` and `$HOME` **is** `/sandbox`, so a backdoor written there is permitted by
the policy as written. It is a fair reading of this policy rather than a failure of
OpenShell — tighten `read_write` and the row moves.

> [!note]
> **`k8s_sa_token` reads `n/a-no-cluster` here**, unlike lessons 6–8 where it is
> `absent`/BLOCKED. OpenShell's sandbox pod does not carry `KUBERNETES_SERVICE_HOST`,
> so the probe cannot tell whether a cluster is present and correctly declines to
> judge. A probe that never ran must never look like a boundary that held.

## What is still open — and why that is the finding

**The kernel rows are wide open.** This runs on ordinary runc, so attack 8 works
exactly as it did in lesson 6.

That is not a defect in OpenShell; it is the observation the whole tutorial has been
building toward. gVisor and Kata closed the kernel column and left the policy column
untouched. OpenShell does the reverse. **They are strong in disjoint columns.**

Which makes stacking them the obvious next move — and
[`lesson-16-compose-gvisor-openshell`](../lesson-16-compose-gvisor-openshell/) measures
what actually happens when you do (and [`lesson-17`](../lesson-17-compose-kata-openshell/)
the Kata case). This lesson is their clean **control**: nothing is stacked underneath,
and Landlock is genuinely available and genuinely enforced on this real kernel.

## Next

Chapter 4 moves the same four boundaries onto OpenShift, where the cluster starts
**refusing** workloads instead of merely containing them.
