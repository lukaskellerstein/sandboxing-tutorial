# Lesson 13 — OpenShell on OpenShift

The last rung of the ladder, and the only one where the boundary has to ask permission
before it can exist.

Lesson 12 closed the kernel column with a per-pod VM and left everything else exactly where
lesson 10 had it: a VM does not read HTTP, does not know which binary opened a socket, and
writes nothing down. This rung closes those three, with the network **on** — the same thing
[`lesson-09`](../lesson-09-k8s-openshell/) did on k3s.

What makes it a different lesson from lesson 9 is the collision with
[`lesson-11`](../lesson-11-openshift-scc/). OpenShell's supervisor builds a nested network
namespace with veth pairs to intercept the sandbox's traffic, and that needs privileges
`restricted-v2` refuses outright. So before the policy engine can enforce anything, it has
to be *let in*:

```bash
oc adm policy add-scc-to-user privileged -z openshell-sandbox -n openshell
```

That single line is the lesson. Every other rung's boundary was something you switched on.
This one you have to be **permitted** to switch on — and a control plane that refuses
privilege refuses it to your security tooling too.

> Verified 2026-08-10 against OpenShift **4.18.49** (single-node, bare metal), OpenShell
> chart and CLI **0.0.99**, agent-sandbox **v0.5.4**. OpenShell is alpha; the versions are
> pinned in `pyproject.toml` and `infra/openshift-sno/install.sh`, and they must match.

## Run it

Chapter 4 shares one cluster across lessons 10–13, so unlike chapters 1–3 **`run.sh` does
not provision or destroy anything**:

```bash
../../infra/openshift-sno/install.sh     # ~1.5-2 h, EUR 0.263/hr. ONCE, for lessons 10-13
cd tutorial/lesson-13-openshift-openshell
./run.sh
../../infra/down.sh openshift-sno        # DESTROY IT. Nothing else will.
```

The lesson runs on **your machine** and drives `oc` and the `openshell` CLI; the boundary
under test is on the OpenShift node, which is where it has to be. That is the opposite of
chapters 1–3, and it is forced: the node is RHCOS, an immutable image with no package
manager, no repo checkout and no uv.

## What the policy says

[`policy.yaml`](policy.yaml) is deliberately almost identical to lesson 9's, and that
similarity is the finding. The policy *language* does not know which control plane is
underneath it. One hole, three ways narrow:

```yaml
- host: sbx-gateway.sbx-lesson-13.svc.cluster.local
  port: 8080
  protocol: rest          # L7: OpenShell parses HTTP, so rules can name methods
  enforcement: enforce
  access: read-only       # GET/HEAD/OPTIONS allowed; POST/PUT/PATCH/DELETE denied
binaries:
  - { path: /usr/bin/curl }
```

Two stand-in Services run with the **same image, same protocol, same port**: `sbx-gateway`,
named in the policy, and `sbx-collector`, named nowhere. One line separates them.

The one thing that had to change from lesson 9 is the absence of a `process:` block. Lessons
5 and 9 pin `run_as_user: sandbox` because they run this repo's own agent image. There is no
registry to push to on a `platform: none` cluster, so this rung runs stock
`ubi9/python-312` — which has no `sandbox` user — and the suite is copied in with `oc cp`.
On OpenShift the uid is not really the policy's to choose anyway: the SCC assigns it.

## What was measured

All four policy assertions passed, read from inside the sandbox:

```text
[OK] the allowed GET reached the gateway (a policy, not a dead network)
[OK] the SAME host's POST was denied (method-aware, which L3/L4 cannot be)
[OK] an unlisted binary was denied (per-binary, which no kernel sandbox sees)
[OK] the off-policy host was denied
```

| Probe | Result | |
| :-- | :-- | :-- |
| `egress_gateway` | `200` | the allowed GET — a policy, not a dead network |
| `http_method_denied` | `403` | **same host, same port**, POST refused |
| `binary_scoped` | `403` | a byte-identical copy of `curl` at an unnamed path |
| `egress_offpolicy` | `403` | the collector, refused |
| `fs_policy_write` | `PermissionError` | Landlock, genuinely enforced on runc |
| `audit_records` | **21** | OCSF decisions, including the attempts that failed |

**15/19 boundaries held.** The audit trail is what kills attack 9 — the exfiltration attempt
is not merely blocked, it is *written down*:

```text
[ocsf] HTTP:POST [MED]  DENIED  /usr/bin/curl(162) -> POST http://sbx-collector…:8080/collect
[ocsf] HTTP:GET  [MED]  DENIED  /usr/bin/curl(163) -> GET  http://169.254.169.254/latest/meta-data/
[ocsf] HTTP:GET  [INFO] ALLOWED /usr/bin/curl(164) -> GET  http://sbx-gateway…:8080/v1/models
```

Note the process id beside the binary path. That is the whole difference from a
NetworkPolicy, which sees packets and cannot name a program.

## Where lesson 9 and lesson 13 disagree — and why

Same policy, same OpenShell version, **two rows differ**. Neither is a bug, and both say
more about the *host* than about OpenShell:

| Probe | k3s (lesson 9) | OpenShift SNO (lesson 13) |
| :-- | :-- | :-- |
| `resource_exhaustion` | `capped:pids` ✅ | `no-cap:pids>=200,mem>=512MB` ❌ |
| `sys_module_count` | `0` ✅ | `205` ❌ |

**The pid cap in lesson 9 was never OpenShell's.** It came from
`--kubelet-arg=pod-max-pids=128` in that chapter's k3s substrate. OpenShift's kubelet has no
such limit by default and OpenShell does not add one, so the sandbox forked past 200
processes and took 512 MB. If you read lesson 9 as "OpenShell caps resources", this is the
correction: it does not, and neither rung's policy file mentions resources at all.

**`sys_module_count` is the node's, not the sandbox's.** Both rungs are ordinary runc, so
`/proc/modules` is the host's list. A minimal Scaleway VM kernel loads almost nothing; a
bare-metal RHCOS node loads 205 modules. The number measures which machine you are on — and
that it is readable at all is precisely the kernel-surface column this rung leaves open.

## One result that is stronger than the card says

The card reports:

```text
k8s_sa_token   n/a-no-cluster   not running in a pod
```

which is literally false — it *is* running in a pod. The probe's discriminator is
`KUBERNETES_SERVICE_HOST`, and an OpenShell sandbox has none. Checked directly rather than
inferred:

```console
$ openshell sandbox exec -n sbx-probe -- sh -c 'env | grep -c KUBERNETES; ls /var/run/secrets/kubernetes.io/serviceaccount/'
0
ls: cannot access '/var/run/secrets/kubernetes.io/serviceaccount/': No such file or directory
```

So there is genuinely **nothing to steal** — no token, no API env vars — not merely nothing
found. That is a containment win the tally does not credit, and it holds on k3s too, which
is why lesson 9 reports the same `n/a`. Worth stating plainly, because "the probe returned
n/a" and "the credential is absent" look identical in a table and mean very different things.

## What is still open

```text
plant_backdoor       3                              ~/.bashrc, ~/.profile, ~/.ssh/authorized_keys
kernel_identity      5.14.0-427.138.1.el9_4.x86_64  the SAME kernel as the node
sys_module_count     205
resource_exhaustion  no-cap:pids>=200,mem>=512MB
```

The kernel rows are the node's. This runs on ordinary runc, so **lesson 12's column is wide
open again**. `/etc` is read-only and Landlock holds, but `$HOME` is not in the policy's
read-only list, so the backdoor lands.

That is the point the whole ladder has been building to:

> gVisor and Kata close the kernel column and leave policy untouched. OpenShell does the
> reverse. They are strong in **disjoint** columns.

Which is what makes stacking them tempting — and what lesson 14 measures.

## Traps

1. **`sandbox create` runs your command and waits for it to exit.** `-- sleep 3600` blocks
   the CLI for an hour while the pod sits Ready the whole time. Use `-- echo ready`; the
   pod's lifetime belongs to the Sandbox object, not to that command.
2. **Do not wrap the suite in `sh -c`.** The policy scopes egress *per binary*, so anything
   wrapping the command joins the execution path. The environment is passed with `--env` at
   create time and `exec` uses `--workdir`, keeping it to a single process.
3. **`sandbox delete` has no `--force`** in 0.0.99. Passing it makes the CLI exit on an
   unknown argument, and in a `finally` that ignores the return code the sandbox leaks in
   silence.
4. **The SCC grant creates a namespaced RoleBinding**, not a ClusterRoleBinding. Checking
   only the cluster-scoped object reports "not granted" about a cluster where the grant is
   present and working.
5. **The chart creates `openshell-sandbox` itself.** Pre-creating that service account hands
   Helm an object it does not own and the install dies on `invalid ownership metadata`.
6. **Pin the CLI to the chart.** They ship on separate cadences — 0.0.101 was already on
   PyPI while this chart was current.
