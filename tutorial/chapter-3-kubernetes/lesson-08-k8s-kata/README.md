# Lesson 8 — Kubernetes with Kata Containers

The same kernel result as lesson 7, by a completely different route: a **real Linux
kernel, in its own VM, per pod**. The workload manifest differs from lesson 6's by one
line — exactly as lesson 7's did — but everything underneath it is different, and the
scorecard shows where that matters.

```bash
cd tutorial/chapter-3-kubernetes/lesson-08-k8s-kata
./run.sh              # provisions its box, runs the lesson there, destroys the box
./run.sh --keep       # ...but leave the box up afterwards, for poking around
```

## This is where chapter 2's awkwardness pays off

Lesson 4 had to stand up a **whole second container stack** — containerd + nerdctl
beside podman — because Kata is a containerd shim-v2 and podman cannot drive it on any
OS. That was genuinely annoying, and it was the argument for this chapter.

On a cluster the cost vanishes. containerd is already what the kubelet talks to, so
Kata is a node install plus a RuntimeClass, and the workload change is one line.

## kata-deploy is a Helm chart now

As of Kata 4.0.0 the install is a Helm chart. The older
`kubectl apply -k .../overlays/k3s` kustomize overlays are **gone**, so any guide that
tells you to apply an overlay is describing a version you are not running.

```bash
helm upgrade --install kata-deploy \
    oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy \
    --version 4.0.0 --namespace kube-system \
    --set k8sDistribution=k3s
```

`k8sDistribution=k3s` is the load-bearing value. k3s does not keep containerd where a
stock cluster does — the config lives under `/var/lib/rancher/k3s/agent/etc/containerd`
and the socket is `/run/k3s/containerd/containerd.sock` — and the chart derives both
from this one setting. Left at its default (`k8s`), kata-deploy writes a drop-in into a
directory k3s never reads, **reports success**, and every Kata pod then fails to start
for a reason nothing in the DaemonSet's logs mentions.

> [!note]
> The chart's default DaemonSet model selects **all** nodes (`nodeSelector` and
> `tolerations` are both empty), which is what a single-node cluster needs. Its other
> model, `deploymentMode=job`, defaults its node selector to *not* control-plane — and
> on a single-node cluster that targets nothing at all.

## Read the RuntimeClass name; never guess it

kata-deploy registers **one class per enabled shim** — 35 of them here (`kata-qemu`,
`kata-clh`, `kata-fc`, `kata-qemu-runtime-rs`, the coco/snp/tdx/nvidia variants…) — and
which appear depends on the release and the node. The lesson asks the cluster:

```bash
kubectl get runtimeclass
```

A hardcoded guess fails as *"RuntimeClass not found"*, which reads like a broken
install rather than a stale assumption, and sends you debugging the substrate instead
of the name.

## Assert it engaged — two witnesses, because one can lie

The obvious check is that the guest kernel differs from the node's. It is **not
sufficient on its own**: on a RHEL-family host, Red Hat builds the guest kernel from
the same base as the node's, so the two legitimately match and a "different kernel"
test reports no VM where there is one.

DMI does not have that problem — a VM reports its hypervisor where metal reports a
motherboard — so the lesson requires both, read from *inside* the sandbox:

```text
uname -r                      != the node's
/sys/class/dmi/id/sys_vendor  names a hypervisor
```

## Expect rows to go the *wrong* way

Kata's guest kernel is a **stock** kernel. The node's is an Ubuntu kernel with
`unprivileged_bpf_disabled=2`, `perf_event_paranoid=4` and `kptr_restrict=1` already
set. So `bpf()` and `io_uring_setup` can start **succeeding** inside the VM after a
plain pod refused them — lesson 4 measured exactly this reversal.

That is not a bug and not a regression in Kata. It is the reason the syllabus says to
**read the matrix, never the count**: a strictly stronger isolation boundary does not
produce a uniformly better scorecard, because the two rungs are hardened by different
people for different threats.

## The VM boot tax is printed, not asserted

"Kata boots a VM per pod" is true and tells you nothing about what you actually wait
for. The lesson times a do-nothing pod under both runtimes, min of three, from `apply`
to a terminal phase — so scheduling, image handling and the kubelet's own loop are in
the figure too, which is what a user experiences.

The prior art's measurement is worth knowing before you see yours: the per-pod VM boot
**did not dominate** — scheduling swamped it.

## What you should see

Measured on a fresh `PLAY2-MICRO` VM, k3s `v1.36.3+k3s1`, kata-deploy `4.0.0`,
`runtimeClassName: kata-qemu`, node kernel `6.8.0-106-generic` (2026-08-08).

The same pod, with and without the one field:

```text
attack               pod (runc)    pod (kata)    changed?
---------------------------------------------------------
read_credentials     BLOCKED       BLOCKED
exfiltrate           BLOCKED       BLOCKED
plant_backdoor       BLOCKED       BLOCKED
cloud_metadata       BLOCKED       BLOCKED
k8s_sa_token         BLOCKED       BLOCKED
kernel_identity      SUCCEEDED     BLOCKED       <-- closed
sys_module_count     SUCCEEDED     BLOCKED       <-- closed
kallsyms_readable    BLOCKED       BLOCKED
bpf                  BLOCKED       SUCCEEDED     <-- OPENED
io_uring_setup       BLOCKED       SUCCEEDED     <-- OPENED
perf_event_open      BLOCKED       BLOCKED
egress_gateway       BLOCKED       BLOCKED
egress_offpolicy     BLOCKED       BLOCKED
http_method_denied   SUCCEEDED     SUCCEEDED
binary_scoped        SUCCEEDED     SUCCEEDED
fs_policy_write      SUCCEEDED     SUCCEEDED
malicious_package    BLOCKED       BLOCKED
reverse_shell        BLOCKED       BLOCKED
resource_exhaustion  BLOCKED       BLOCKED
```

**Two rows closed and two rows OPENED.** That is the headline, and it is why the
syllabus says to read the matrix and never the count: this rung and lesson 6 both
score 14/19, for completely different reasons.

```text
kernel_identity    6.18.35   BLOCKED   node runs 6.8.0-106-generic
sys_module_count   80        BLOCKED   the guest kernel's own modules, not the node's
bpf                fd=3      SUCCEEDED REACHED — the call succeeded
io_uring_setup     fd=3      SUCCEEDED REACHED — the call succeeded
```

`bpf()` and `io_uring_setup` **succeed inside the VM** after a plain pod refused them.
Kata's guest is a *stock* kernel; the node's is an Ubuntu kernel with
`unprivileged_bpf_disabled=2` already set. A strictly stronger isolation boundary, and
a scorecard that is not uniformly better — because the two kernels were hardened by
different people for different threats. Lesson 4 measured the same reversal on a host.

**The cost is the opposite of gVisor's:**

```text
probe           pod (runc)    pod (kata)     ratio
------------------------------------------------
syscall_ms            72.4          22.0     0.30x
cpu_ms               129.0         133.7     1.04x
```

Syscalls get **faster**, which surprises people who expect a VM to cost more. Kata
charges no interception toll — the guest kernel answers syscalls directly, and it is a
stock kernel without the node's mitigations. Compare lesson 7's 2.51×: same kernel
column closed, opposite cost profile.

`cpu_ms` sits on either side of 1.0 between runs (0.96× and 1.04× on two boxes), which
is the honest reading: **compute pays nothing measurable**, and any single sample of it
is noise.

**The per-pod VM boot tax, measured:**

```text
a do-nothing pod, min of 3, apply -> terminal phase:
  runc      :   2.80s
  kata-qemu :   6.73s   (2.40x of runc)
  kata-fc   :   6.80s   (2.43x of runc)
```

Real, and it is a *pod* figure rather than a hypervisor one — scheduling, image
handling and the kubelet's loop are all in it, which is what you actually wait for.

This lesson was run on two separate boxes, and that number moved the most of anything
here: **2.76× and 3.71×**, from ~2 s of runc against ~6 s of Kata. Every
BLOCKED/SUCCEEDED verdict in the matrix above was **identical** across both. Treat the
verdicts as reproducible and the timings as your cluster's, not the tutorial's — which
is exactly why the lesson prints the number instead of asserting a tax.

**And attack 7 behaves differently again.** The runc pod is `OOMKilled` and dies; the
Kata pod **survives** and reports `capped:mem` itself. The limit is enforced by the
**guest** kernel inside the VM, one kernel further in, so it refuses the allocation
before the node's cgroup ever sees pressure. Same cap, smaller blast radius.

> [!note]
> **This guest exposes no DMI.** Neither `kata-clh` nor `kata-qemu` provides
> `/sys/class/dmi/id/sys_vendor` here — a minimal guest need not build SMBIOS support
> in. The differing kernel is the proof, and it is decisive on its own; DMI is only
> needed on hosts where the guest kernel legitimately *matches* the node's, which is
> the OpenShift case chapter 4 hit.

## Part 3b — the same field, a different machine underneath

Change the field again, from `kata-qemu` to `kata-fc`, and the **hypervisor** under the
runtime changes from QEMU to Firecracker. That is the layer below the one this chapter
usually talks about — [`docs/isolation-layers.md`](../../../docs/isolation-layers.md) has the
picture, and this lesson does not repeat it.

**Lesson 4 taught the mechanism on a host; this rung teaches the selection.** There it
took a shim config file, a devmapper thin-pool and `--snapshotter devmapper` on the
command line. Here all of it is one word:

```yaml
spec:
  runtimeClassName: kata-fc     # instead of kata-qemu
```

### Registered is not working — the trap worth carrying away

`kata-fc` has been in `kubectl get runtimeclass` **since the day kata-deploy was
installed**, one of 35 classes. Naming it got you a pod that never started:

```text
failed to create containerd container: error unpacking image:
unable to initialize unpacker: snapshotter must be provided to unpack
```

Firecracker has no virtio-fs, so its rootfs must be a **block device**, and nothing on
the node provided one. `infra/substrates/chapter-3/75-k8s-devmapper.sh` adds the
devmapper snapshotter — and it must run *before* kata-deploy, because loading a
snapshotter needs containerd restarted and a restart after kata-deploy reverts it.

That gap is this repo's characteristic failure wearing a RuntimeClass: **the object
exists, the API accepts the pod, and the boundary is not there.** It is exactly why the
lesson runs a workload under the class instead of trusting the listing.

### The security matrix does not move

```text
kata-qemu 14/19    kata-fc 14/19      <- 19 rows, not one different
```

Both hypervisors sit on KVM and hand the workload the **same guest kernel**, so what an
attack can reach is unchanged. This is measured, not asserted — the whole suite runs a
second time under Firecracker and the two cards are diffed. Swapping the VMM is not a
boundary change.

### What does move, read from inside each guest

```text
reading                  kata-qemu                  kata-fc
----------------------------------------------------------------------------
guest kernel             6.18.35                    6.18.35
/sys/bus/pci/devices     11                         0
virtio sits on           pci0000:00/0000:00:01.0    virtio-mmio-cmdline/virtio-mmio.0
rootfs filesystem        virtiofs                   ext4
hotpluggable mem blocks  17                         17
```

The kernel row is identical, so `uname -r` — the proof this chapter has leaned on since
lesson 6 — **cannot tell these two apart**. The PCI bus can: Firecracker boots `pci=off`
and has none. The `rootfs` row is the devmapper requirement seen from the inside.

The hotplug row is worth keeping precisely because it came back **equal**: the guests are
the same by construction, and the differences are in the machine around them, not in what
the workload is handed.

### Speed and weight

```text
startup, min of 3          the VMM process on the node
  runc        2.80s          kata-qemu    269.7 MB RSS
  kata-qemu   6.73s          kata-fc      161.5 MB RSS
  kata-fc     6.80s
```

**The boot advantage did NOT survive the kubelet, and that is the honest result.** In
lesson 4, through `nerdctl run`, Firecracker started ~0.4 s ahead of QEMU every time.
Here it lands on top of it. Two runs on this same cluster measured `kata-fc` at **5.75 s
and 6.80 s** while `kata-qemu` sat at **6.66 s and 6.73 s** — the QEMU figure is steady
and the Firecracker one swings by a second, which means the difference is **inside the
run-to-run noise** of a pod round trip.

That is the prior art's finding reproduced rather than a disappointment: `time_pod_startup`
measures `apply` → terminal phase on purpose, so scheduling, image handling and the
kubelet's own loop are all in the figure, and together they swamp a VM boot. If you want
to see the hypervisor's own start cost, lesson 4 is where it is visible.

**The memory difference does survive, and it is the one to plan around:** ~108 MB per
sandbox, on every pod running at once. It reproduced within 2 MB across both runs, and it
is invisible from inside the guest — which is why `vmm_footprint()` is the only probe in
this chapter that looks out of the sandbox rather than into it.

## What is still open

The same rows lesson 7 left open, for the same reason. A VM per pod buys attack 8 and
buys **nothing** on attacks 2, 4, 5, 6 or 9: Kata does not read HTTP, does not know
which binary opened a socket, and writes nothing down.

One difference from lesson 7 matters later. This is a **real** kernel, so it ships
Landlock — which gVisor's user-space kernel answers `ENOSYS` to. Lesson 14 stacks a
policy engine on both and finds the same composition works here and *silently fails*
there.

## Next

- [`lesson-09-k8s-openshell`](../lesson-09-k8s-openshell/) — per-binary and
  method-aware policy plus an audit trail: the columns neither gVisor nor Kata touches.
