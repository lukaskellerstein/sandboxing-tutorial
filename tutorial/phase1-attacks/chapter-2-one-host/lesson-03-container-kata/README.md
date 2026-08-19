# Lesson 1.2.3 — Container + Kata Containers

The same kernel result as lesson 1.2.2, reached by the opposite route. gVisor
*reimplements* the kernel in user space; Kata boots a **real Linux kernel inside a
per-container virtual machine**. The scorecards look alike. What each one *keeps*
does not, and that is the whole reason both lessons exist.

```bash
cd tutorial/phase1-attacks/chapter-2-one-host/lesson-03-container-kata
./run.sh              # provisions its box, runs the lesson there, destroys the box
./run.sh --keep       # ...but leave the box up afterwards, for poking around
```

That is the whole workflow — one command, and the box is destroyed even if the lesson
fails. It writes `report.html` + `report.json` here beside the lesson.

## This lesson needs KVM, and will refuse without it

Kata needs `/dev/kvm` **and** `/dev/vhost-vsock`, and `main.py` checks for both
before it runs anything. Note what that check is *not*: it does not ask whether the
host is bare metal, because that is not the requirement. Plenty of VMs expose both,
and plenty of dedicated hardware does not. The refusals are specific because each
one is a different wrong lesson if papered over:

| Host | What happens | Why |
|:--|:--|:--|
| Scaleway `PLAY2-MICRO` **VM** | works | AMD EPYC 7543 with `svm` and `kvm_amd.nested=1`; `/dev/kvm` and `/dev/vhost-vsock` both present. Guest kernel `6.18.35` |
| Scaleway `EM-A116X-SSD` metal | works | `vmx`, `/dev/kvm`, vsock all real, and no hypervisor underneath |
| Apple Silicon Mac | **refuses** | a guest kernel genuinely boots, but host↔guest vsock times out — libkrun already owns the vsock domain (`ss --vsock` shows the machine listening on it, CID 3 returns `Address already in use`). Cloud Hypervisor fails identically. There is no workaround |
| Hetzner Cloud | **refuses** | `/dev/kvm` absent and the CPU flag masked entirely, on the *dedicated* family too |

Those are measurements, not guesses — see the syllabus § *Verified on this
hardware*. The lesson runs on the VM by default, which does mean the "per-container
VM" is nested inside the cloud's own hypervisor. The boundary Kata builds is real
either way; what nesting costs is a little speed, not isolation.

**It also needs disk.** The Kata stack — `nerdctl-full` plus `kata-static` —
measures 9.3 GB, and a Scaleway VM's default root volume is 8 GB usable, so the
install dies mid-`tar` with `No space left on device`. `infra/lessons.json` gives
this lesson **60 GB**: 9.3 GB of Kata, plus room for the 20 GB thin-pool the
second hypervisor needs (sparse and thin-provisioned, so that is a ceiling rather
than disk actually spent — see *A second hypervisor* below).

## Why this lesson uses nerdctl and not podman

Kata is a **containerd shim-v2**. Podman cannot drive a shim-v2 on any OS — it is
not a missing flag or a version problem, it is a different architecture. So
`infra/substrates/chapter-2/30-containerd-kata.sh` installs containerd + nerdctl +
`kata-static` **alongside** podman, which is left completely untouched: podman is
daemonless and never looks at containerd, so lessons 1.2.1 and 1.2.2 still behave
identically on a box that has both.

That second stack is the honest cost of this rung, and it is exactly what
[chapter 3](../../../../syllabus.md) deletes: a Kubernetes node already runs containerd,
so Kata there is one field in a pod spec.

> The image is built **into containerd's store**. Podman and containerd keep
> separate stores, so an image built in lesson 1.2.1 is invisible here.

## Proving a VM booted

Measured on the `PLAY2-MICRO` VM:

```text
node kernel   6.8.0-106-generic
guest kernel  6.18.35          <- a different kernel = a real guest VM
guest size    2 cpu, 2179 MB   <- not the node's 4 cpu / 8 GB
```

`uname -r` differing is strong evidence *here* and is **not proof in general**: on
RHEL-family hosts Red Hat builds the guest kernel from the same base and the
strings match. The textbook fallback is **DMI** — a VM reports its hypervisor in
`/sys/class/dmi/id/sys_vendor`, bare metal reports a motherboard vendor — but on
this stack the container's `/sys` does not expose DMI at all and the reading comes
back `no-dmi`. So the lesson checks three things and makes only the kernel check
fatal: DMI can be absent or masked, an identical kernel cannot be explained away.

## Four results worth the whole lesson

**1. The kernel rows close, exactly as they did under gVisor.** `kernel_identity`
and `sys_module_count` both flip to BLOCKED — the agent is enumerating the *guest's*
80 modules, which say nothing about the node's 201. (That node figure moves with the
box: 179, 193 and 201 across three provisions. The guest's 80 is the stable one,
because it is Kata's own image rather than whatever the host booted.)

**2. A `--memory` limit stops meaning what it meant one rung ago.**

```text
asked for            --memory 256m --cpus 1 --pids-limit 128
the guest received   2179MB, 2 cpu
```

Those flags sized a *host* cgroup around the VMM; the workload lives in a guest
sized by Kata's own `default_memory`. So the fork bomb never meets the ceiling the
flag names. To cap a Kata workload you configure the sandbox, not just the
container — and OOM is then handled by the **guest** kernel before the node ever
sees it, which is why an OOM here looks different in the node's logs.

**3. A guest kernel is a stronger boundary *and* a less-hardened kernel.**

| sysctl | node (Ubuntu 24.04) | Kata guest (6.18.35) |
|:--|--:|--:|
| `kernel.unprivileged_bpf_disabled` | **2** | **0** |
| `kernel.perf_event_paranoid` | **4** | **2** |

This is the surprise. With `CapEff: 0000000000000000` — every capability dropped —
a workload inside the guest **can still create a BPF map**, because the guest boots
upstream defaults and nothing there ever disabled unprivileged BPF. So `bpf` and
`io_uring_setup` show `<-- OPENED` against the plain-container rung on the same box.

That is not Kata failing. It is the honest shape of the trade: the isolation got
much stronger, and the distro hardening you were implicitly relying on did not come
with it. If you move a workload to Kata, its guest's sysctls are now yours to set.

**4. A VM per container buys attack 8, and nothing on the network axis.**

Like every rung of this ladder, the suite runs with the ordinary network — an
agent that cannot reach a model API is not an agent, and `--net none` would score
this rung 11/13 while describing a deployment nobody ships.

```text
attack               verdict     value
exfiltrate           SUCCEEDED   open
cloud_metadata       SUCCEEDED   200
malicious_package    SUCCEEDED   index-reached
reverse_shell        SUCCEEDED   stage=no-stage-url,egress=open,bind=ok

7/13
```

This is the sharpest version of the tutorial's whole argument. Kata is the
**strongest kernel boundary on this ladder** — a separate kernel in a separate VM,
with a per-container hypervisor — and it leaves *exactly* the four rows open that
a plain `podman run` leaves open. A VM boundary is not a network policy. Nothing
in a guest kernel can tell the model-API call the agent needs from the
exfiltration it does not, because that distinction lives in HTTP and a kernel does
not read HTTP.

The number makes it blunt: **Kata scores 7/13, and so does the plain container of
lesson 1.2.1.** They tie — for opposite reasons. Kata blocks `kernel_identity` and
`sys_module_count` and opens `bpf` and `io_uring_setup` (result 3 above); the
container does the exact reverse. Read the matrix, never the count — a scoreboard
that only shows the total would call these two rungs equivalent, and they are
strong in disjoint rows.

The lesson refuses to report unless the guest kernel is distinct from the node's
**and** egress was demonstrably open. A VM that quietly came up with no network
would show those four rows BLOCKED and credit a per-container hypervisor with
stopping exfiltration it never touched.

## Cost

The cost table prints the syscall and CPU taxes and deliberately does **not** fold
in the per-container VM boot: that is paid once at startup rather than per syscall,
so a syscall-tax comparison flatters Kata and a startup comparison does not. On
this box syscall-bound work measured *faster* inside the guest than in a plain
container on the node (`0.29x`) — a real effect of a quieter, less-instrumented
kernel, and a good reason to read the startup cost separately. The prior art's
cluster measurement is the other half: the famous VM boot **did not dominate**,
because scheduling swamped it.

## A second hypervisor under the same runtime — Part 3b

Kata is the **runtime**. The **hypervisor** is a component one layer *below* it,
and this box has two installed, so Part 3b is a real choice rather than a
description. Which kind of thing is which — and why "Kata + gVisor" is a category
error while "Kata + Firecracker" is not — is
[`docs/isolation-layers.md`](../../../../docs/isolation-layers.md); this lesson does not
repeat it.

**Start with the negative result, because it is the whole point:** swapping the VMM
does **not** change your isolation model. Both sit on KVM and boot the same guest
kernel — and rather than assert that, the lesson runs the **whole suite a second
time** under Firecracker and diffs the two cards:

```text
attack               kata-qemu     kata-fc       changed?
---------------------------------------------------------
read_credentials     BLOCKED       BLOCKED
exfiltrate           SUCCEEDED     SUCCEEDED
plant_backdoor       BLOCKED       BLOCKED
cloud_metadata       SUCCEEDED     SUCCEEDED
kernel_identity      BLOCKED       BLOCKED
sys_module_count     BLOCKED       BLOCKED
kallsyms_readable    BLOCKED       BLOCKED
bpf                  SUCCEEDED     SUCCEEDED
io_uring_setup       SUCCEEDED     SUCCEEDED
perf_event_open      BLOCKED       BLOCKED
malicious_package    SUCCEEDED     SUCCEEDED
reverse_shell        SUCCEEDED     SUCCEEDED
resource_exhaustion  BLOCKED       BLOCKED

kata-qemu 7/13    kata-fc 7/13      <- nothing moved
```

**Thirteen rows, not one of them different.** The score stays **7/13**, every row
Part 3b adds is INFO, and none of it is scored. What changes is the host-side
process the guest talks to.

### Selecting one, and the flag that is not decoration

```bash
--runtime io.containerd.kata.v2                              # QEMU
--runtime io.containerd.kata-fc.v2 --snapshotter devmapper   # Firecracker
```

Firecracker's device model has virtio-block and **no virtio-fs**, so a container
rootfs cannot be shared in from the host the way QEMU's is — it has to arrive as a
block device, which is what the devmapper snapshotter produces. Drop the second
flag and the container dies mounting its own rootfs with `ENOENT`, which reads like
a Kata bug and is a storage prerequisite. `infra/substrates/chapter-2/35-containerd-devmapper.sh`
builds the thin-pool.

### What each guest reports about the machine it is on

```text
reading                kata-qemu                  kata-fc
--------------------------------------------------------------------------
guest kernel           6.18.35                    6.18.35
/sys/bus/pci/devices   11                         0
virtio sits on         pci0000:00/0000:00:01.0    virtio-mmio-cmdline/virtio-mmio.0
rootfs filesystem      virtiofs                   ext4
```

**The kernel row is identical, and that is the finding rather than a gap in the
probe.** It also means the usual proof does not work here: `uname -r` cannot tell
these two apart, so *which VMM booted* has to be read from the machine itself. The
PCI bus answers it — Firecracker boots `pci=off` and has no PCI bus at all, putting
virtio on MMIO instead.

That matters more than it looks. The first version of this lesson's substrate
registered the Firecracker runtime as a plain `containerd-shim-kata-fc-v2` symlink;
every container it started reported a convincing guest kernel, and **every one of
them was QEMU**. The runtime name proved nothing. Both the lesson and `check.sh`
now refuse to report unless the guest has no PCI bus.

The `rootfs` row is the `--snapshotter` flag seen from the inside: the storage
requirement and the in-guest reading are the same fact from two sides.

### Speed and weight — where Firecracker is actually lighter

```text
a do-nothing container, min of 3:        the VMM process, while a sandbox is up:
  runc         0.34s                       qemu           262.1 MB RSS
  kata-qemu    3.18s                       firecracker    148.3 MB RSS
  kata-fc      2.79s   (0.88x)
```

```text
on disk:  firecracker   2.9 MB
          qemu         73.4 MB  +  320.7 MB of firmware (BIOS, EDK2, device ROMs)
```

The guests weigh the same **by construction** — same kernel, same rootfs, same
`default_memory` — so nothing read from inside a guest could show this. The
difference is entirely the host-side process, which is exactly where Firecracker's
design lives: five emulated devices (virtio-net, virtio-block, virtio-vsock,
serial, a minimal keyboard controller), no BIOS, no PCI, no ACPI.

**The boot advantage is real but modest — 0.88×, not a different order of
magnitude.** This is the shortest path either hypervisor has: `nerdctl run` with no
scheduler and no kubelet in the way, which is where a boot advantage should show
most clearly. It buys about 0.4 s. The **memory** difference is the one worth
planning around — a bit under half the VMM, on every sandbox you run at once.
[Lesson 1.3.3](../../chapter-3-kubernetes/lesson-03-k8s-kata/) times the same thing through Kubernetes, where
the prior art found the VM boot got swamped entirely, and prints whatever it gets.

## Scoped out, named on purpose

- **Confidential Containers** and **peer pods** are the attestation and cloud
  extensions of this path; lesson 1.4.3 names them.
- **Cloud Hypervisor** (`kata-clh`) is the third VMM in that slot. kata-static
  ships it and this lesson does not measure it: two hypervisors already make the
  point that the slot exists, and a third would be a longer table saying the same
  thing.

## Next

Kata and gVisor close the same column. Neither can tell you *which binary* made a
request, *which method* it used, or that it happened at all — and neither keeps the
four network attacks closed once the agent is online. That is
[lesson 1.2.4](../lesson-04-container-openshell/), which closes them on ordinary `runc`
with no kernel boundary whatsoever, and with the network still on.

And the difference that only surfaces in lesson 1.3.6: a real guest kernel **ships
Landlock**. gVisor answers `ENOSYS` to it, so a policy engine stacked on gVisor
silently stops enforcing filesystem rules while still reporting healthy (lesson 1.3.5).
