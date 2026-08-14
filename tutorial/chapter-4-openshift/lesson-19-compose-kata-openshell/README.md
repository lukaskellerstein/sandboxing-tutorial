# Lesson 19 — Composition: OpenShell over Kata, on OpenShift

The composition on the platform an enterprise actually buys it on. Lesson 17
proved OpenShell's policy holds on Kata on k3s; this rung runs the same stack on
OpenShift's **sandboxed-containers operator**, where Kata is the shipped product
and OpenShell's policy engine must itself clear **SCC admission**. Two boundaries
the control plane had to be talked into admitting, stacked, and both enforcing.

> **This lesson runs against the shared chapter-4 cluster and neither provisions
> nor destroys it.** Single-node OpenShift takes ~1.5–2 h to install and costs
> €0.263/hr; teardown is a step **you** own. There is no EXIT trap here that will
> save you.

```bash
../../../infra/openshift-sno/install.sh     # bring the cluster up — ONCE, shared by lessons 10-13, 19
cd tutorial/chapter-4-openshift/lesson-19-compose-kata-openshell
./run.sh                                     # runs this lesson against it
../../../infra/down.sh openshift-sno         # DESTROY it when the chapter is done
```

## What has to line up before the stack even exists

Two admissions, each earned in an earlier lesson, both required here at once:

- **The `kata` RuntimeClass** — the sandboxed-containers operator registers
  exactly one class, `kata` (lesson 12), not k3s's `kata-qemu`. OpenShell's
  driver-config overlay selects it per sandbox:

  ```python
  DRIVER_CONFIG = {"kubernetes": {"pod": {"runtime_class_name": "kata"}}}
  ```

- **The privileged SCC** — OpenShell's supervisor builds a nested network
  namespace, which `restricted-v2` refuses, so its service account must hold the
  privileged SCC or every sandbox dies at admission. That is lesson 11 acting on
  this lesson, exactly as it acts on lesson 13:

  ```bash
  oc adm policy add-scc-to-user privileged -z openshell-sandbox -n openshell
  ```

  `preflight()` verifies both before creating anything, and refuses with the fix
  attached rather than failing deep in a create.

## Assert the VM by DMI, never the kernel string

Red Hat builds the Kata guest kernel from the same RHEL base as the node's, so
`uname -r` inside the VM is **identical** to the node's. Lesson 8's k3s test —
"the kernel differs, therefore it is a VM" — returns *no VM* here, a false
negative on the strongest isolation on the ladder (Trap #12). This lesson asserts
the VM the way lesson 12 does: **DMI names a hypervisor (`KVM` / `Red Hat`),
virtio devices are present, and the guest's CPU/memory are far below the node's** —
all read from inside the sandbox, plus `spec.runtimeClassName` read back from the
pod. Never the flag.

## What the run shows

The expected reading is lesson 17's, on the enterprise platform:

- **`fs_policy_write` blocked** — the write to `/etc` that lesson 13 refused on
  runc is refused here too, because the operator's Kata guest ships Landlock and
  OpenShell's `landlock()` call succeeds inside the VM. The audit witness reports
  Landlock available and the ruleset built — the positive mirror of lesson 16's
  gVisor failure.
- **The L7 policy holds** — allowed `GET` through, same-host `POST` denied,
  unlisted binary denied.
- **`hard_requirement` starts** (Part 4) — satisfiable, because Landlock is really
  present. The same file that makes gVisor refuse to start (lesson 16) runs
  cleanly here.

<!-- MEASURED-OUTPUT: filled in from the run on the shared openshift-sno cluster -->

## Where this sits in the composition story

| Composition | Home | Landlock | Why |
| :-- | :-- | :-- | :-- |
| OpenShell + gVisor | [lesson 16](../../chapter-3-kubernetes/lesson-16-compose-gvisor-openshell/README.md) (k3s) | **silently lost** (audit-only; write still blocked by the rootfs) | gVisor drops Landlock |
| OpenShell + Kata | [lesson 17](../../chapter-3-kubernetes/lesson-17-compose-kata-openshell/README.md) (k3s) | present, enforced | real guest kernel ships Landlock |
| OpenShell + Kata | **lesson 19 (OpenShift)** | present, enforced | same, on the shipped product, through SCC admission |

The rule is developed once in
[`docs/isolation-layers.md`](../../../docs/isolation-layers.md) § *The trap:
stacking two boundaries can make you less safe*. Chapter 4 cannot host the gVisor
composition at all — gVisor is not a supported OpenShift runtime
([lesson 18](../lesson-18-compose-gvisor-openshell/README.md) documents why).
