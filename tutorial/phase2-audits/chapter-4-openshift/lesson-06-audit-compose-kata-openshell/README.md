# Lesson 2.4.6 — Auditing OpenShell over Kata on OpenShift (BLOCKED, documentation only)

> **This leaf is a record, not a lesson.** There is no `main.py`, no `run.sh`, and no entry in
> `infra/lessons.json`. It exists because the audit twin cannot be built until its phase-1 twin
> [1.4.6](../../../phase1-attacks/chapter-4-openshift/lesson-06-compose-kata-openshell/README.md)
> works, and 1.4.6 **does not work on this platform today** — for a reason that is fully diagnosed,
> is not a flaw in the composition, and has a named fix scheduled by the vendor.
>
> Everything needed to pick this up later is on this page: what failed, why, why it cannot be worked
> around from our side, what Red Hat is shipping, when, and the five-minute probe that answers
> "is it fixed yet?" before any lesson work is attempted.

**Do not delete this leaf and do not build it speculatively.** Run the probe in
§ *Picking this up later* first. If the probe says no, stop — everything after it will crashloop.

---

## 1. What was measured, and on exactly what

Measured **2026-08-15** on a from-scratch single-node OpenShift cluster (since destroyed):

| component | version |
| :-- | :-- |
| OpenShift | **4.18.49** (single node, bare metal, `EM-B112X-SSD`) |
| OpenShift sandboxed containers | **1.12.1** — CSV `sandboxed-containers-operator.v1.12.1` |
| RuntimeClass | `kata` (the one the operator registers — not k3s's `kata-qemu`) |
| Node kernel **and** Kata guest kernel | `5.14.0-427.138.1.el9_4.x86_64` — **identical strings**, see §2 |
| NVIDIA OpenShell | **0.0.99** (alpha) |

Both admissions 1.4.6 depends on were satisfied — the `kata` RuntimeClass existed, and the
`openshell-sandbox` service account held the privileged SCC. The composition still never started.
**OpenShell's supervisor crashloops** while building its sandbox:

```text
Network namespace creation failed and proxy mode requires isolation.
/usr/sbin/ip link add veth-… type veth peer name veth-… failed: Error: Unknown device type.
```

The identical driver-config overlay works on k3s — that is
[1.3.6](../../../phase1-attacks/chapter-3-kubernetes/lesson-06-compose-kata-openshell/README.md),
audited green by [2.3.6](../../chapter-3-kubernetes/lesson-06-audit-compose-kata-openshell/README.md)
at 8/19. So this is a **platform difference, not a composition flaw**.

### Why veth is structural to OpenShell, not incidental

Not a detail that could be configured away: the veth pair **is** how OpenShell's L7 proxy intercepts.
From OpenShell's own `crates/openshell-driver-podman/NETWORKING.md`:

> Namespace 3: Inner sandbox netns, created by supervisor … veth pair, such as 10.200.0.1 <-> 10.200.0.2
> … The veth pair bridges namespace 2 and 3. The proxy at the boundary of namespace 2 and 3 enforces
> network policy.

And its VM driver's own guest-kernel config, `crates/openshell-driver-vm/runtime/kernel/openshell.kconfig`,
lists it as a requirement:

```text
# ── Virtual Ethernet (veth pairs for pod networking) ────────────────────
CONFIG_VETH=y
```

No veth, no inner namespace; no inner namespace, no L7 policy — and OpenShell correctly **fails
closed** rather than running the sandbox with its network policy silently absent. (Which is the same
fail-closed discipline `landlock.compatibility: hard_requirement` gives us in 1.3.5 / 2.3.5.)

---

## 2. The diagnosis — corrected on 2026-08-15 by evidence from Red Hat

**An earlier draft of this finding said "the OpenShift guest kernel has no veth module", implying a
different kernel config. That is imprecise and would send the next reader down the wrong path.**

The Kata guest kernel on OpenShift **is the node's RHEL kernel version** — `uname -r` returns the
same string inside the VM as on the node, which is why 1.4.3/1.4.6 must assert the VM by DMI rather
than by kernel string (Trap #12). All eight chapter-4 `report.json` files record
`5.14.0-427.138.1.el9_4.x86_64` for both.

What differs is the **module set shipped inside the Kata guest image**. Red Hat's own bug
[KATA-5628](https://issues.redhat.com/browse/KATA-5628) — *"NFSv4 mounts fail with 'protocol not
supported' inside Kata Containers due to missing 'nfsv4' and 'dns_resolver' kernel modules in guest
VM"*, closed **Done**, fixVersion **OSC 1.13.z** — is the same bug class, and its comments show the
shape exactly:

> The root cause has been identified as missing kernel modules (nfsv4 and dns_resolver) in the Kata
> guest VM kernel, even though they are present and loaded in the underlying RHCOS node kernel.

with `uname -r` identical on node and guest (`5.14.0-570.112.1.el9_6`) and `lsmod` in the guest
showing a **subset** of the node's modules. `veth` is `=m` in RHEL kernels, so with the `.ko` absent
from the guest image, `ip link add … type veth` cannot autoload it and the kernel answers
`Unknown device type`.

k3s works because kata-deploy ships the **upstream** Kata guest kernel, whose config fragment
`tools/packaging/kernel/configs/fragments/common/network.conf` compiles veth **in**:

```text
# Add VETH support (necessary for running Docker in the guest)
CONFIG_VETH=y
```

Red Hat's downstream fork carries that same fragment on `osc-release-v1.10` … `v1.13` — but the
*productized* guest kernel is a RHEL build, not that fragment's output, which is why its presence
there is no help.

> **Summary for the next agent:** the guest kernel is fine. The guest **image** omits `veth.ko`.
> Do not go looking for a kernel-config difference, and do not try to rebuild a kernel.

---

## 3. Why we cannot work around it — checked, not assumed

Red Hat's workaround for KATA-5628 was: **hostPath-mount the node's `/lib/modules` into the Kata pod
and load the module manually.** It is sound in principle here — the guest kernel version is identical
to the node's, so the node's `veth.ko` is ABI-compatible, and loading a module inside a Kata guest
touches only that VM's kernel, never the host's. It is also **unavailable to us**, for a reason in
OpenShell rather than in OpenShift.

OpenShell's Kubernetes driver **renders the sandbox pod itself**. The only thing a caller can
influence is the `driver_config` passthrough, and that is a closed allow-list — every struct in
`crates/openshell-driver-kubernetes/src/driver.rs` carries `#[serde(default, deny_unknown_fields)]`:

| block | fields accepted | what is *not* there |
| :-- | :-- | :-- |
| `pod` | `node_selector`, `runtime_class_name`, `tolerations`, `priority_class_name` | `initContainers`, `securityContext`, `annotations`, `hostPID` |
| `containers.agent` | `resources`, `volume_mounts` | `command`, `securityContext`, `env` |
| `volumes[]` | `name`, `persistent_volume_claim` | **every other volume source — including `hostPath`** |

Volume names are additionally rejected when they collide with OpenShell-managed ones. This is
deliberate; RFC 0006 (`rfc/0006-driver-config-passthrough/README.md`, state: *implemented*) states it
as a non-goal:

> Do not allow driver config to override gateway-computed `platform_config` or typed public fields.

Three consequences, each a dead end that has already been walked so nobody walks it twice:

1. **No hostPath, no initContainer** → nowhere to stage or load `veth.ko`. And because each Kata pod
   is **its own VM**, the module must be loaded inside *that* pod's guest — there is no earlier hook,
   no node-level `modprobe` that carries into it, and no sidecar we are allowed to add.
2. **`runtime_class_name` is the one open lever, and it does not help.** A custom RuntimeClass whose
   Kata `configuration.toml` sets `agent.kernel_modules=["veth"]` still ends in `modprobe`, which
   needs the `.ko` to be in the guest image already. Same dead end for the
   `io.katacontainers.config.agent.kernel_modules` pod annotation — which the overlay cannot set anyway.
3. **Patching OpenShell or rebuilding the RPM is out of scope for this repo, on purpose.** The claim
   a lesson makes is about a *shipped* boundary. A leaf that only passes against a locally patched
   sandbox teaches something false about the product, which is the exact failure mode this tutorial
   exists to prevent.

So the fix has to arrive in the guest image, and that is Red Hat's to ship.

---

## 4. What Red Hat is shipping, and when

Searched 2026-08-15 against Red Hat's public Jira (now `redhat.atlassian.net`; its REST API answers
anonymously) and their developer blog.

| item | what it says |
| :-- | :-- |
| **[KATA-5840](https://issues.redhat.com/browse/KATA-5840)** — *"[Docs] Agent Sandbox: OpenShell support (**additional kernel modules**)"* | Status **New**, fixVersion **OSC 1.14**, created **2026-08-13**, parent `KATA-5801 — OSC 1.14 Documentation`. Description still empty; no public engineering counterpart yet. **This is the ticket.** |
| **OSC 1.14 planned release** | **2026-10-01** (work started 2026-07-15), from the KATA project's version list |
| **[KATA-5858](https://issues.redhat.com/browse/KATA-5858)** — *"CI: Scale test environments to cover all supported deployments"* | Lists, under *Variants in operators*: `Agent Sandbox` → **`OpenShell`**. OpenShell-on-OSC is becoming a CI-covered supported deployment. |
| **[KATA-5628](https://issues.redhat.com/browse/KATA-5628)** | The precedent for *how* it gets fixed: *"Problem resolved with the customer by building a scratch RPM that includes the missing kernel modules … A proper fix will be released in an upcoming z-stream release."* A rebuilt `kata-containers` RPM in the RHCOS extension — nothing a user configures. |
| **[Layered sandboxing for AI agents: OpenShift and OpenShell](https://developers.redhat.com/articles/2026/07/16/layered-sandboxing-ai-agents-openshift-and-openshell)** (2026-07-16) | Red Hat publishing *this exact composition* as a recommended pattern — *"the agent process sits inside an OpenShell sandbox … that sandbox runs inside a Kata micro-VM"*. Names **OpenShift 4.21** as a test environment. No versions, no YAML, no prerequisites, and **no mention of the veth requirement**. |
| **[Red Hat build of Agent Sandbox](https://developers.redhat.com/articles/2026/07/15/red-hat-build-agent-sandbox-isolated-workload-management-kubernetes)** (2026-07-15) | The operator this hangs off — `KATA-4728`, Tech Preview in OSC 1.13. |

### Confidence that it will work, honestly stated

| what we'd run | confidence |
| :-- | :-- |
| OCP 4.21 + OSC **1.12.1** — the newest *installable* stack today | **~20%** |
| OCP 4.21 + OSC **1.13**, if/when it goes GA | ~30% |
| **OSC 1.14** (planned 2026-10-01) | **~85%** |

The reasoning, so a later reader can re-weigh it rather than inherit a number:

- The dominant evidence is that **KATA-5840 was filed a month *after* the article was published, and
  scoped to 1.14.** Somebody at Red Hat hit "OpenShell needs additional kernel modules" and scheduled
  the fix forward rather than pointing at a shipped release. That reads as "not in what ships now".
- **"Latest available" today is still OSC 1.12.1** — Jira has 1.13 as `released: false` (planned
  2026-07-07, overdue) and the operator's GitHub releases stop at `v1.12.1` (2026-06-18). Moving
  OpenShift 4.18 → 4.21 changes the RHCOS base but **not** the OSC RPM that builds the guest image,
  and the module set is a packaging decision in that RPM.
- The article is weak evidence about *today*: no versions, no reproduction, and silent on the veth
  requirement — equally consistent with "it worked" and with "this describes the intended
  architecture". It is strong evidence of direction, which is why the 1.14 figure is 85% and not 60%.
- The 15% shortfall on 1.14 is "slips again, or ships an incomplete module set" — 1.13 already
  slipped — not "Red Hat abandons it".

---

## 5. Picking this up later

### Step 1 — the five-minute probe, BEFORE any lesson work

Needs a cluster with the sandboxed-containers operator installed, and nothing else. **Do not stand up
a cluster just for this** — at ~20% it is not worth €0.263/hr plus a ~2 h install. Fold it into the
next chapter-4 run you are already paying for.

```bash
oc apply -f - <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: vethprobe
  namespace: default
spec:
  runtimeClassName: kata
  restartPolicy: Never
  containers:
    - name: p
      image: registry.access.redhat.com/ubi9/python-312:latest
      command: ["sh","-c","uname -r; ls /lib/modules/$(uname -r)/kernel/drivers/net/veth* 2>&1; modprobe veth 2>&1; ip link add v0 type veth peer name v1 2>&1 && echo VETH_OK || echo VETH_MISSING"]
      securityContext:
        privileged: true
EOF
oc wait --for=jsonpath='{.status.phase}'=Succeeded pod/vethprobe --timeout=300s
oc logs vethprobe
oc delete pod vethprobe
```

- `VETH_OK` → the guest image now ships the module. Go to step 2.
- `VETH_MISSING` / `Unknown device type` → **stop.** Record the OCP + OSC versions you probed on in
  this file, and check KATA-5840 again.

Also worth recording either way: `oc get csv -n openshift-sandboxed-containers-operator` (the OSC
version actually installed) and `oc get clusterversion` — the two numbers this whole page turns on.

### Step 2 — building the leaf, once the probe passes

1. **Fix 1.4.6 first.** It is written but has never had a green run; its README still asserts the
   composition holds on OpenShift, which is unproven. Run it, fill its `MEASURED-OUTPUT` marker, and
   only then build the twin.
2. **Copy [2.3.6](../../chapter-3-kubernetes/lesson-06-audit-compose-kata-openshell/README.md), not
   2.4.4.** 2.3.6 is the same composition, already audited, and its structure carries over. What
   changes for chapter 4 is only the sensor set and the attribution key.
3. **The sensor question here is 2.4.3's, not 2.4.4's.** Behind Kata the node's `auditd` measured
   **0 paths against 2.4.1's 739**, and a Kata pod reports **no SELinux MCS** to the node — so there
   is no attribution key either. The realistic trail is **OpenShell's OCSF decisions alone**
   (2.4.4 got 8 of its 12 that way), plus the apiserver audit log for the admission half.
4. **Expect the in-guest sidecar rescue to be unavailable**, as it was for 2.4.3: `strace` is absent
   from the stock UBI image, chapter 4 cannot build images, and `dnf` refuses (read-only rootfs, and
   a non-root uid behind it). Do not spend a cluster hour rediscovering that.
5. **Containment must equal 1.4.6's exactly, zero rows different** — that is the phase-2 contract
   every other built leaf holds to.

### If the probe never passes

This leaf stays as it is. That is a legitimate outcome and a genuine finding, which
[2.4.5](../lesson-05-audit-compose-gvisor-openshell/README.md) states in its own form: **a
composition can be blocked by what a platform's guest image omits, rather than by anything about the
boundaries being composed.** Both chapter-4 composition leaves are blocked, and for unrelated
reasons — 2.4.5 because OpenShift ships no gVisor runtime at all, 2.4.6 because the shipped Kata
guest image is missing one module. Neither is a statement about whether the composition is sound;
[2.3.5](../../chapter-3-kubernetes/lesson-05-audit-compose-gvisor-openshell/README.md) and
[2.3.6](../../chapter-3-kubernetes/lesson-06-audit-compose-kata-openshell/README.md) answer that on
k3s, where both run.

---

## Provenance

Measured on the cluster 2026-08-15; vendor evidence searched 2026-08-15 (Red Hat Jira via
`redhat.atlassian.net`'s anonymous REST API, `NVIDIA/openshell` and `kata-containers` on GitHub,
developers.redhat.com). The handoff doc for all of phase 2 is
[`docs/my-specs/05-phase-split-and-audit-coverage/current_status.md`](../../../../docs/my-specs/05-phase-split-and-audit-coverage/current_status.md).
