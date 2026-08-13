# Lesson 12 — Kata on OpenShift: the same boundary, as a product

Lesson 8 assembled Kata on k3s: a Helm chart, a `k8sDistribution` value that had to be
right, a DaemonSet, a containerd drop-in, a devmapper thin-pool for the Firecracker
variant, and 35 RuntimeClasses to choose between. It worked, and it was visibly a thing
you *built*.

Here the same boundary arrives as an **operator**. `KataConfig` is a two-line custom
resource, the operator drives a MachineConfig, the node reboots once, and a RuntimeClass
called exactly `kata` appears. The workload manifest is then byte-identical to lesson 8's.

```bash
cd tutorial/lesson-12-openshift-kata && ./run.sh
```

## The install, for contrast with lesson 8

```bash
oc apply -f manifests/osc-operator.yaml   # ns + OperatorGroup + Subscription (channel: stable)
oc apply -f manifests/kataconfig.yaml     # -> MachineConfig -> ONE node reboot
oc get runtimeclass kata                  # appears when kataconfig is ready 1/1
```

Measured on this cluster: the CSV reached `Succeeded` in **~40 seconds**; `KataConfig`
took **~19 minutes**, almost all of it the node reboot. One RuntimeClass, not 25.

## The reading that matters — and why lesson 8's test fails here

> [!warning]
> **The Kata guest kernel is byte-identical to the node's.** Red Hat builds it from the
> same RHEL base. Lesson 8 proves its VM on k3s by the kernel **differing** — run that
> test here and it reports **no VM**, a false negative on the rung that isolates most
> thoroughly. This is Trap #12, and it is why the assertion is DMI, virtio and the
> resource gap instead.

```text
                  kata                            runc
KERNEL            5.14.0-427.138.1.el9_4.x86_64   5.14.0-427.138.1.el9_4.x86_64
DMI_PRODUCT       KVM                             PowerEdge R720    <-- differs
NPROC             2                               24                <-- differs
VIRTIO            6                               0                 <-- differs
MEM_KB            2204728                         198005264         <-- differs
```

The runc pod reports the actual **Dell motherboard**; the Kata pod reports **KVM**, six
virtio devices, 2 CPUs out of the node's 24, and 2.1 GB out of 198 GB. One field moved all
of that into a VM the node cannot be reached from — while the kernel string never moved
at all.

## Neither witness works everywhere

Worth carrying forward, because it is the reason lesson 8's assertion takes *either*
signal rather than both:

| | guest kernel | DMI |
| :-- | :-- | :-- |
| **k3s** (lesson 8) | **differs** (`6.18.35` vs `6.8.0`) | **absent** — minimal guest, no SMBIOS |
| **OpenShift** (here) | **identical** — same RHEL base | **present** (`KVM` / `Red Hat`) |

Exact mirror images. A test demanding both fails on both clusters; a test demanding
either passes on both, honestly.

## What you should see

Measured on single-node OpenShift 4.18.49, sandboxed-containers operator `v1.12.1`,
`EM-B112X-SSD` bare metal (2026-08-10):

```text
[kernel]
  kata_dmi_product      KVM                            BLOCKED
  kata_virtio_devices   6                              BLOCKED
  kata_guest_cpus       2                              BLOCKED   node has 24
  kata_guest_mem_kb     2204728                        BLOCKED   node has 198005264Ki
  kata_kernel_identity  5.14.0-427.138.1.el9_4.x86_64  n/a       identical by design (Trap #12)

[OK] DMI names a hypervisor: KVM / Red Hat
[OK] virtio devices present (6) — they exist only in a VM
[OK] CPU is the VM's, not the node's (2 vs 24)
[OK] memory is the VM's, not the node's (2204728 kB)
```

`kata_kernel_identity` is recorded as **INFO and never scored**. Scoring it would mark
this rung as failing the very thing it does best.

## One hypervisor, and no choice about it

Lessons [4](../lesson-04-container-kata/) and [8](../lesson-08-k8s-kata/) both run Kata on
**two** hypervisors — QEMU and Firecracker — and lesson 8 picks between them by changing
`runtimeClassName` from `kata-qemu` to `kata-fc`.

**That choice does not exist here.** OpenShift sandboxed containers ships **QEMU only**:
the operator (v1.12.1) registers a single RuntimeClass, `kata`, and the guest is a
QEMU/KVM VM (`REPRODUCE.md` §8 records it as *"real KVM VM (QEMU/`kata-monitor` on
node)"*). There is no `kata-fc` to name, and no supported way to add one — the same
reason gVisor is absent from this chapter, and the same principle: **chapter 4 teaches
what OpenShift actually ships**, not what upstream Kata can be made to do.

So the layer lesson 4 spends a whole Part on — a hypervisor being a component *below* the
runtime, swappable — is real, and on this platform it is the vendor's choice rather than
yours. Which is worth knowing before you plan a migration around it.

## Peer pods and Confidential Containers — named and scoped out

Two questions always follow this lesson:

- **Peer pods** create the VM through a *remote* hypervisor, so the Kata pod's VM lives
  outside the cluster node. That sidesteps the bare-metal requirement in clouds that will
  not sell you a metal node — which is most of them. Not demonstrated here because this
  box *is* metal, so the plain path is the honest one to show.
- **Confidential Containers** add attestation and memory encryption on top. A different
  threat model (protecting the workload *from the operator*), and a different lesson.

## Why this needs bare metal

Kata needs `/dev/kvm` on the node **and** cluster-admin to install the operator. That
rules out every cheap managed option: the free Red Hat Developer Sandbox has no
cluster-admin, and ROSA/ARO only run Kata on `*.metal` instances at roughly $5/hr.
Self-hosting single-node OpenShift on a €0.263/hr box is the cheapest path that exists —
see [`infra/openshift-sno/REPRODUCE.md`](../../infra/openshift-sno/REPRODUCE.md).

## Next

- [`lesson-13-openshift-openshell`](../lesson-13-openshift-openshell/) — the columns
  neither Kata nor gVisor touches: which binary, which HTTP method, and an audit trail.
