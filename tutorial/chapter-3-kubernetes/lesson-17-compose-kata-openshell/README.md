# Lesson 17 — Composition: OpenShell over Kata

Lesson 16 stacked OpenShell's policy on gVisor and watched the filesystem clause
silently disappear. This rung stacks the **same policy** on Kata, and it holds.
The pair is one finding with two halves: composition fails when the lower layer
drops a kernel feature the upper layer needs, and it *succeeds* when the lower
layer keeps that feature. Kata keeps it, because it boots a real guest kernel and
a real Linux kernel ships Landlock.

```bash
cd tutorial/chapter-3-kubernetes/lesson-17-compose-kata-openshell
./run.sh              # provisions the shared chapter-3 cluster, runs the lesson, destroys it
./run.sh --keep       # ...but leave the cluster up afterwards (you pay until infra/down.sh)
```

As with the rest of chapter 3, the cheap way through is `cd infra && ./chapter-03.sh`,
which builds the shared box once and runs every lesson on it.

## The one thing that changes from lesson 9

The same single field lesson 16 changed — OpenShell's per-sandbox driver-config
overlay — pointed at Kata instead of gVisor:

```python
DRIVER_CONFIG = {"kubernetes": {"pod": {"runtime_class_name": "kata-qemu"}}}
# openshell sandbox create … --driver-config-json '{"kubernetes":{"pod":{"runtime_class_name":"kata-qemu"}}}'
```

Everything else — `policy.yaml`, the probe suite, the gateway and collector
Services — is lesson 9's, unchanged. The runtime underneath is the only variable.

**The boundary is asserted from inside, never from the flag.** The lesson reads
`spec.runtimeClassName` back from the pod *and* checks that the guest kernel
reported by `uname -r` inside the sandbox **differs** from the node's — on k3s the
Kata guest runs its own kernel, and that difference is the VM. (On OpenShift the
guest kernel matches the node, so [lesson 19](../../chapter-4-openshift/lesson-19-compose-kata-openshell/README.md)
asserts by DMI/virtio instead; here the kernel difference is the honest test.)

## What the run shows

The same three clauses as lesson 16, all three intact this time:

- **The kernel column closes** — the Kata guest is a full VM, so the node kernel
  is not reachable from inside at all.
- **The L7 policy holds** — allowed `GET` through, same-host `POST` denied,
  unlisted binary denied. Kernel-agnostic, as always.
- **The filesystem clause holds too.** `fs_policy_write` stays **blocked** — the
  write to `/etc` that lesson 9 refused is refused here as well, because
  OpenShell's `landlock()` call succeeds inside the guest and the ruleset is
  actually built. The audit trail's witness is the positive mirror of lesson 16's:
  Landlock *available*, ruleset *built*, nothing skipped.

Part 2 then applies `policy-hard.yaml` (`compatibility: hard_requirement`) at
sandbox create. On gVisor that refuses to start; here the sandbox **starts
normally**, because the hard requirement is genuinely satisfied. The same file
that makes gVisor fail closed runs cleanly on Kata.

### Measured on `chapter-03-k8s` (k3s, one node)

```text
  sandbox pod: default--sbx-l17-kata
  pod .spec.runtimeClassName: kata-qemu   (expected: kata-qemu)
  guest kernel from inside: 6.18.35   (node: 6.8.0-106-generic)

  [kernel]
    kernel_identity     6.18.35                    BLOCKED  node runs 6.8.0-106-generic
    sys_module_count    0                          BLOCKED
    bpf                 EPERM                      BLOCKED
  [policy]
    egress_gateway      200                        BLOCKED  should ALLOW
    http_method_denied  403                        BLOCKED  POST should DENY
    binary_scoped       403                        BLOCKED  unlisted binary
    fs_policy_write     PermissionError            BLOCKED  <-- Landlock present, clause enforced

  the audit trail's independent witness (Landlock available / ruleset built):
    CONFIG:PROBED   [INFO] Landlock filesystem sandbox available [abi:v7 compat:BestEffort ro:9 rw:3]
    CONFIG:BUILT    [INFO] Landlock ruleset built [rules_applied:12 skipped:0]

  Part 2 — hard_requirement:
    create SUCCEEDED — hard_requirement is satisfied, because Landlock is really there.
```

Every scored row is identical to lesson 16's gVisor run. The two diverge **only**
in the audit trail — here `Landlock ... available` and `ruleset built [skipped:0]`,
there `Landlock ... Unavailable [HIGH]`. That single difference is the entire
composition finding: the guest kernel is what carries Landlock, and gVisor does
not have one to carry it.

## The cost, and the rule

Kata is heavier than gVisor — a KVM VM per pod rather than a user-space kernel —
and that weight is not incidental to this result. It is *why* the composition
works: the VM carries a real kernel, and the real kernel carries the Landlock the
policy depends on. gVisor's lightness is exactly what dropped it.

The rule, developed once in
[`docs/isolation-layers.md`](../../../docs/isolation-layers.md) § *The trap:
stacking two boundaries can make you less safe*:

> **Composition fails when the lower layer removes a kernel feature the upper
> layer depends on** — and succeeds when it keeps it. Verify the upper layer is
> still enforcing; do not infer it from the fact that both are installed.

The commercially-relevant version of this composition — OpenShell over Kata on
OpenShift, where Kata is the shipped product — is
[chapter 4, lesson 19](../../chapter-4-openshift/lesson-19-compose-kata-openshell/README.md).
