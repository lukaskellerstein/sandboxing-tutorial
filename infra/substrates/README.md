# Substrates — install scripts + verification results

Each script installs one boundary and asserts it engages **from inside** (kernel
identity), never from the flag.

They live in per-chapter directories, and the `substrates` arrays in `lessons.json` carry
that path (`chapter-3/60-k8s`). `up.sh` interpolates it straight into the path it runs, so
adding a chapter needs no code change; `check.sh` dispatches on the **basename**, so its
assertions stay named after the boundary rather than after the tree.

The directory names stay the short `chapter-N` on purpose: they are already
chapter-grouped, matching `tutorial/chapter-2-one-host/` and
`tutorial/chapter-3-kubernetes/` by number, and renaming them would touch every
`substrates` string in `lessons.json` for a purely cosmetic gain.
(`infra/openshift-sno/` is chapter 4's substrate in the same sense — kept apart
because its install replaces the box's OS and cannot run through `up.sh`.)

- **`chapter-2/`** — `10`–`50`, one host. `10`+`20`+`30`+`35` install onto the ONE host
  **lessons 2–4** share (`chapter-02-host`); `50`+`40` build lesson 5's own box, the one
  lesson pinned off the shared host by OpenShell's private-primary-address requirement.
- **`chapter-3/`** — `60`–`90`, Kubernetes. All five install onto the ONE cluster
  **lessons 6–9** share (`chapter-03-k8s`). Documented at the end of this file.

> [!warning]
> **Chapter 3's order is load-bearing, and it is about restarts rather than files.**
> `70-k8s-gvisor.sh` and `75-k8s-devmapper.sh` are the substrates that run `systemctl restart
> k3s`. A restart *after* `80` terminates the kata-deploy DaemonSet pod, which reverts its
> own installation on the way out. So: **60 → 70 → 75 → 80**, and each of `70` and `75`
> writes additively (neither owns containerd's config — kata-deploy writes into the same
> directory) and restarts only when its own file actually changed, so re-running `up.sh`
> against a live shared cluster does not bounce Kata.
>
> **`75` is numbered where it is for exactly that reason.** Loading a snapshotter needs
> containerd restarted, k3s *embeds* containerd, and there is no post-`80` seam — so the
> storage has to be in place before kata-deploy arrives, not added afterwards.

## gVisor and Kata DO coexist on one k3s node (2026-08-13)

The open question is answered, and it was answered empirically rather than by reasoning about
kata-deploy's internals — two plausible mechanisms disagreed about whether it appends to the same
`*.tmpl` or writes a `config-v3.toml.d/` drop-in, so `70` was simply made additive under both and
`check.sh` was left to settle it. On one `PLAY2-MICRO` running `60`+`70`+`80`:

```text
kubectl get runtimeclass   gvisor (83s)  kata-qemu + ~18 variants (75s)   <- both registered
node / plain pod           6.8.0-106-generic     <- Kata did NOT become the default runtime
runtimeClassName: gvisor   4.19.0-gvisor
runtimeClassName: kata-qemu 6.18.35              <- a real guest VM, same kernel metal recorded
```

All read from inside the sandbox. Lessons 6, 7 and 8 then reproduced their separate-box scores
exactly (14, 16, 14 of 19).

## …but `90-k8s-openshell` does not fit beside them on 8 GB

With `90` also installed, the OpenShell gateway and Agent Sandbox controller stay resident from
provisioning onward, and lesson 8's **Part 3b** — which boots Kata guests repeatedly to time the
per-pod VM tax — took the whole box down mid-run: ssh dropped (`Connection closed by remote host`),
and lesson 9 could not reach the machine at all afterwards. Lesson 8 had passed that same Part 3b
on an 8 GB box carrying `60`+`80` and no gateway, which is what points at memory rather than at a
substrate conflict.

The obvious fix — a bigger box — **is not available on this account**: `POP2-4C-16G`, `PRO2-XS`,
`BASIC3-X4C-16G` and `BASIC3-X6C-24G` all fail to create with `has reached its quota (0/0)`, and
`PLAY2-MICRO` is the largest `PLAY2`. So lesson 9 keeps its own box. It also loses the least by
being separate: OpenShell is the one chapter-3 boundary **not** selected with `runtimeClassName`
(its sandboxes take that from the gateway), so it was never part of the per-pod menu.

> [!warning]
> **SUPERSEDED (2026-08-13, same day): the quota was an identity gate, and it is lifted.** The
> `0/0` above was the account's *unverified identity*, not stock; with identity verified,
> `PRO2-XS` and `PRO2-S` create normally. All four chapter-3 lessons now share one `PRO2-S`
> (32 GB) node carrying `60`+`70`+`75`+`80`+`90`, and lesson 8's Part 3b runs beside the resident
> gateway without taking it down — measured, see `syllabus.md` § *Verified on this hardware*.
> `90` runs last and must not restart k3s (it does not: `systemctl --user` services only), so
> kata-deploy survives it — `check.sh` proves that by booting a Kata guest after all five
> substrates have run.

> [!important]
> **This file is a measurement log, and its early entries were superseded on
> 2026-08-06.** The substrates now run on Scaleway **VMs** (`PLAY2-NANO` /
> `PLAY2-MICRO`), not on `EM-A116X-SSD` bare metal, and every one of them was
> re-verified there. Two conclusions recorded below were re-tested and found wrong —
> each is marked **SUPERSEDED** in place rather than deleted, because the reasoning
> that produced them is the useful part:
>
> - *"lesson 5's guest must be L1, so its box is bare metal"* — the symptom behind
>   that was BIOS-vs-UEFI, not nesting. See the correction at the end.
> - *"a VM cannot carry Kata"* — a Scaleway VM exposes `/dev/kvm` **and**
>   `/dev/vhost-vsock`; Kata boots guest kernel `6.18.35` there, the same one metal
>   recorded.
>
> The original 2026-08-04 measurements below were taken on one fresh Ubuntu 24.04
> `EM-A116X-SSD` (€0.077/hr, `/dev/kvm` present, SELinux none).

| # | Substrate | Lesson | Result | Proof (from inside the box) |
| :-- | :-- | :-- | :-- | :-- |
| `10-podman.sh` | podman rootless container | 2 | ✅ **works** | plain container → `uname -r` = **6.8.0-88-generic** (host kernel — no kernel boundary, correct for lesson 2) |
| `20-runsc.sh` | gVisor (`runsc`) | 3 | ✅ **works** | container under `--runtime runsc` → `uname -r` = **4.19.0-gvisor**. **No `label=disable` needed** on Ubuntu (that trap was CoreOS-only) |
| `30-containerd-kata.sh` | Kata (containerd + nerdctl + kata-static) | 4 | ✅ **works** | `--runtime io.containerd.kata.v2` → `uname -r` = **6.18.35** (a real guest VM kernel, ≠ node's 6.8.0-88). Coexists with podman (daemonless) |
| `35-containerd-devmapper.sh` | Firecracker as a second hypervisor under Kata | 4 | ✅ **works** | `--snapshotter devmapper --runtime io.containerd.kata-fc.v2` → **0 PCI devices** and `rootfs=ext4`, against kata-qemu's 10 and `virtiofs`. Same guest kernel `6.18.35` under both. See below |
| `40-openshell.sh` | NVIDIA OpenShell | 5 | ⚠️ **installs; blocked on podman version** | see below |

**All three of 10/20/30 coexist on one box** — podman's default runtime stays
`crun`, containerd runs separately, runsc is opt-in. That was the coexistence
question, answered.

**Re-answered on the shared `chapter-02-host` (2026-08-13), now with `35` beside them.**
One `PRO2-XS` carrying `10`+`20`+`30`+`35` in that order: rootless podman still defaults
to `crun` (4.9.3) and a rootless container still reports the node kernel; `--runtime
runsc` reports `4.19.0-gvisor`; `io.containerd.kata.v2` boots guest `6.18.35` with 10 PCI
devices and a `virtiofs` rootfs; `io.containerd.kata-fc.v2 --snapshotter devmapper` boots
the same guest kernel with **0** PCI devices and an `ext4` rootfs. Order note: `20`'s
smoke test needs podman (`10` first), `35` restarts containerd (`30` first); nothing
host-side has chapter 3's revert-on-restart trap, because kata-static is files on disk
rather than a DaemonSet. With one kata-qemu guest resident the host used 774 MB of
16 GB (VMM RSS ~272 MB) and 11 of 54 GB of disk — `PRO2-XS` is ample.

## Firecracker under Kata (2026-08-13) — and two traps that look like success

`35-containerd-devmapper.sh` adds a **second hypervisor** under the runtime lesson 4
already installed. It is not a new rung: both boot the same guest kernel through KVM,
and lesson 4's score is unchanged at 7/13. What differs is the machine underneath.

```text
                 kernel     /sys/bus/pci/devices   rootfs
kata-qemu        6.18.35    10                     virtiofs
kata-fc          6.18.35     0                     ext4
```

**The kernel string cannot tell them apart** — that is the finding, not a gap in the
check. `/sys/bus/pci/devices` can: Firecracker boots with `pci=off` and puts virtio on
MMIO (`/sys/bus/virtio/devices/virtio0` → `virtio-mmio-cmdline/virtio-mmio.0`, where
QEMU's points at `pci0000:00/...`). The `rootfs` column is the devmapper requirement
seen from inside: Firecracker has virtio-block and **no virtio-fs**, so the container
rootfs cannot be shared in and arrives as a block device instead.

Two things cost a box each to find, and both exit 0 or read as an unrelated bug:

1. **A `containerd-shim-kata-fc-v2` symlink silently runs QEMU.** The shim does *not*
   key its config off its own binary name — it falls back to the default configuration
   and boots QEMU while answering to the Firecracker runtime name. Nothing in the output
   says so; only the PCI count does. Every guide that describes the symlink is describing
   a Kata older than 4.0.0.
2. **`KATA_CONF_FILE` is allow-listed as of Kata 4.0.0** — the shim symlink-resolves it
   and refuses anything that is not one of its **two** shipped config paths, with
   `only shipped Kata configuration files are accepted`. Kubernetes does not meet this:
   kata-deploy passes the path as a containerd runtime option (`ConfigPath`), which is
   CRI-only, and nerdctl is not a CRI client. So the substrate registers the Firecracker
   config *as* the second shipped path and pins QEMU into the first —
   `/etc/kata-containers/configuration.toml` → `configuration-qemu.toml`, which is
   searched first, so a shim invoked with no config named still gets QEMU. The failure
   mode of the arrangement is "the hypervisor you already had", never a silent swap, and
   `check.sh` asserts both halves.

**Without the thin-pool a Firecracker container dies as
`failed to mount /run/kata-containers/shared/containers/<id>/rootfs … ENOENT`** — which
reads like a Kata bug and is a missing storage prerequisite. That is the same symptom as
upstream [kata-containers#12558](https://github.com/kata-containers/kata-containers/issues/12558),
still open.

## OpenShell (lesson 5) — precise status

- ✅ OpenShell **0.0.97 installs** via the official `install.sh` (CLI **and** the
  `openshell-gateway` systemd daemon at `https://127.0.0.1:17670`). `uv tool
  install openshell` is **not enough** — it installs only the CLI, no gateway.
- ✅ The gateway **connects to podman** (rootless, netavark) once you set
  `OPENSHELL_DRIVERS=podman` and give it a reachable podman socket.
- ❌ **Blocked by podman 4.9.3** (what Ubuntu 24.04 ships). OpenShell's rootless
  podman driver requires **pasta** as podman's *default rootless network command*
  for the sandbox→gateway callback:
  `Podman rootless network helper '<missing>' does not support direct local
  gateway callbacks; configure pasta or use an explicitly remote grpc_endpoint`.
  Installing `passt` is not enough — pasta-as-default is **podman 5.0+** behaviour;
  4.9.3 still reports the helper missing.
- Running the gateway against **rootful** podman clears the rootless-helper block
  (`rootless=false`, bridge `10.89.0.1` ready) but then fails to bind the callback
  listener to the bridge IP — a per-network setup detail, not the intended path.

### podman-5 fix — VERIFIED (2026-08-04, Debian 13 box)

Re-ran on **Debian 13 (trixie), podman 5.4.2, pasta** as a non-root `agent` user
(rootless), OpenShell **0.0.98**:

- ✅ **The original podman-4.9.3 blocker is GONE.** Rootless podman 5.4.2 uses
  pasta by default; a rootless container gets pasta networking and
  `host.containers.internal` → `169.254.1.2` (the callback path). The gateway now
  progresses past driver connection with no "rootless network helper missing".
- ❌ **A different, deliberate constraint stops it on this host:**

  ```text
  configuration error: compute driver 'podman' requested the gateway
  default-route interface, but its resolved address 62.210.94.34 is not a
  private IPv4 address (Podman rootless pasta callback uses the host
  default-route interface)
  ```

  This is a **safety check, not a bug**: OpenShell refuses to expose the gateway
  callback on a **public** IP. A Scaleway Elastic Metal box has a single **public**
  IP as its default route, so the rootless-podman driver won't start. Setting
  `OPENSHELL_GRPC_ENDPOINT` / the `[openshell.drivers.podman] grpc_endpoint` config
  does **not** bypass it — the default-route-interface check runs regardless.

**So: podman 5 is necessary AND sufficient for the original problem; it is not
sufficient on a public-IP bare-metal host.** OpenShell's rootless-podman path
assumes a **private default-route IP** — true on a laptop's podman-machine VM
(what the prior art used), a NAT'd cloud VM, or a k8s node (lesson 9's k8s driver,
where the pod network is private), but NOT on bare metal with a public IP.

**Implication for the tutorial (design decision needed):** lesson 5 (local
container OpenShell) needs a host with a **private default-route IP**. Options,
cheapest first: (a) attach a **Scaleway Private Network** and make it the default
route; (b) run OpenShell on a NAT'd VM rather than bare metal; (c) fold OpenShell
into the k8s track only (lesson 9's kubernetes driver sidesteps this entirely).
This is a genuine tension with the "remote bare-metal, one public IP per box"
substrate choice — flag it before writing lesson 5.

**Status:** verified-installed = 0.0.98 · verified-driver-connects = yes (podman 5)
· verified-sandbox-runs = **no** (blocked by public-IP default route on bare metal;
not yet tested on a private-IP host).

### Option 1 (private IP on the bare-metal box) — attempted, does NOT fully work

Tried giving the box a private default-route address so OpenShell's check passes:

- Adding a **secondary** private IP to `eno1` → ignored (OpenShell reads the
  interface's *primary* address).
- Changing the **default-route `src`** to a private IP (`ip route change default
  … src 10.99.0.1`) → **the gateway check PASSES and the gateway starts** (client
  connects, mTLS, `openshell status` = Connected). The check only runs at startup,
  so you can even revert `src` to public afterwards to restore host egress.
- **But sandboxes still fail** (`ContainerExited: code 1`): the hack made OpenShell
  bind the callback listener on `10.99.0.1:17670`, while the sandbox actually
  reaches the gateway via `host.containers.internal` → `169.254.1.2` (pasta's
  fixed host alias). The two don't match, so the in-sandbox supervisor can't call
  back and exits.

**Root cause:** OpenShell's rootless-podman + pasta path needs the host's
default-route interface to have a **genuine private *primary* IP**, so the callback
binding and `host.containers.internal` resolve to the *same* private address. That
is a **NAT topology** — native on a laptop's podman-machine VM (what the prior art
used), a NAT'd cloud VM, or a k8s node — but not on public-IP bare metal. A
fully-working option 1 on Scaleway EM would require a **Private Network made the
real default route via a Public Gateway (NAT)** — a VPC + paid gateway + a
console-less routing change that risks SSH lockout. Not worth it for one lesson.

**Decision recommended:** run lesson-5 OpenShell on a **NAT'd host with a private
default-route IP**. Cleanest = the **k8s driver** (chapter 3 / lesson 9) — the pod
network is private and this entire class of problem disappears. Second choice = a
NAT'd cloud VM (a Scaleway *Instance*, which natively has a private default-route
IP), noting OpenShell does not need `/dev/kvm`, so it need not be on bare metal.

> [!warning]
> **CORRECTION (2026-08-05): a Scaleway Instance does NOT have a private
> default-route IP.** Measured on a `BASIC3-X2C-4G`, Ubuntu 24.04, fr-par-1:
>
> ```text
> RoutedIPEnabled  true          PRIVATE IP  -
> ip -4 addr       inet 163.172.152.10/32 metric 100 scope global dynamic ens2
> ip route         default via 62.210.0.1 dev ens2 proto dhcp src 163.172.152.10
> ```
>
> The public address sits **directly on the NIC**, which is what "routed IP" means.
> The private-default-route claim above describes Scaleway's retired **NAT** model
> and no longer holds for instances created today. So the OpenShell blocker applies
> to Elastic Metal **and** to plain Instances alike, and lesson 5's box has to build
> its own NAT topology (`50-nat-vm.sh`) rather than inherit one.
>
> Two other things that measurement settled, both useful elsewhere: a Scaleway
> Instance **does** expose nested virtualisation (`/dev/kvm`, `/dev/vhost-vsock`,
> `kvm_amd.nested=1`, `svm` in `/proc/cpuinfo`) — so a NAT'd KVM guest on one is
> viable; and Ubuntu 24.04 still ships **podman 4.9.3**, which is the version that
> fails the rootless-pasta requirement, so the NAT guest must be Debian 13.

**Verified end state:** podman-5 is the correct fix for the original blocker;
OpenShell installs and its gateway runs; **sandbox execution needs a private-IP
(NAT) host** and was not achieved on public-IP bare metal.

### Re-confirmed on OpenShell 0.0.99 (2026-08-05) — and resolved

The constraint is **current, not a fixed-in-a-later-release artefact**. On a
Scaleway Instance (Debian 13, podman 5.4.2, rootless, non-root `agent` user),
OpenShell 0.0.99's gateway connects its podman driver and then exits:

```text
INFO openshell_server::compute: Compute driver connected configured_driver=podman
Error:   × configuration error: compute driver 'podman' requested the gateway
  │ default-route interface, but its resolved address 163.172.152.10 is not a
  │ private IPv4 address (reason: Podman rootless pasta callback uses the host
  │ default-route interface)
```

**The resolution lesson 5 uses: build the NAT topology instead of looking for one.**
A libvirt guest on the default `virbr0` network has a genuinely private *primary*
address on its default-route interface (192.168.122.0/24), which is exactly what
the check wants — and it is the same shape that makes OpenShell work on a laptop,
where the private address is the home LAN's. `50-nat-vm.sh` builds it; the lesson
then runs *inside* the guest, reached through the box as a jump host.

> [!warning]
> **SUPERSEDED (2026-08-06).** The paragraph below concluded that nesting was the
> failure. It was not: the same symptom — grub loads, prints ``Booting `Debian
> GNU/Linux'``, kernel resets forever — was later reproduced **on bare metal**, and
> traced to Debian 13's genericcloud image being **UEFI-only** while libvirt was
> booting it on the default BIOS firmware. That is why `50-nat-vm.sh` passes
> `--boot uefi`, and the comment on that flag says so.
>
> Re-tested with the flag in place: the NAT guest boots on a Scaleway **VM**,
> `virsh domstate` = `running`, lease `192.168.122.53/24` on `virbr0` — a private
> primary address on the default-route interface, which is the whole requirement.
> So lesson 5 does **not** need metal.

**That guest must be L1, so lesson 5's box is bare metal.** Measured: on a Scaleway
Instance — itself a VM — the guest's grub loads, prints ``Booting `Debian
GNU/Linux'``, and the kernel then resets in a loop, forever, with `--machine pc`
and `--cpu qemu64` too. Nested KVM inside a cloud VM is the failure; on Elastic
Metal there is no L0, which is the same reason lesson 4's Kata VMs work there.
The host stays Ubuntu — only the **guest** needs Debian 13, for podman 5 + pasta.

Also worth recording: the installer is now a system **`.deb`** (`openshell_0.0.99-1_amd64.deb`)
and needs root to install, while the **gateway must run as an unprivileged user**
(its podman driver is rootless). So install as root, run the daemon as the user —
`up.sh` encodes that split with the `# runs-as: user` marker on the substrate.

## Notes that carry into `infra/` automation

- gVisor: `runsc` + `containerd-shim-runsc-v1` from the gVisor release bucket,
  registered as an **opt-in** podman runtime drop-in (default runtime unchanged).
- Kata: identical to the bare-metal proof — `nerdctl-full`, `kata-static 4.0.0`,
  a shim symlink, and the containerd service. Needs `/dev/kvm`. On x86 Xeon the
  Apple-Silicon `pmu=off` trap does not apply.
- OpenShell gateway is a **per-user systemd service**; on Linux the macOS
  `DOCKER_HOST` trap does not apply, but you must set `OPENSHELL_DRIVERS=podman`
  and provide a podman socket + pasta (podman 5).

## Re-verified on VMs, and three bugs found doing it (2026-08-06)

Every substrate re-run on Scaleway VMs, using these scripts unmodified. Results:

| Substrate | Box | Result |
| :-- | :-- | :-- |
| `10-podman.sh` | `PLAY2-NANO` | ✅ rootless podman 4.9.3, container `uname -r` = node's |
| `20-runsc.sh` | `PLAY2-NANO` | ✅ `4.19.0-gvisor` |
| `30-containerd-kata.sh` | `PLAY2-MICRO` | ✅ guest kernel `6.18.35` ≠ node `6.8.0-106-generic` |
| `50-nat-vm.sh` | `PLAY2-MICRO` | ✅ **after three fixes**, below |

**`30-containerd-kata.sh` needs a 40 GB root volume.** A Scaleway VM's default is
8 GB usable and the `kata-static` unpack dies with `No space left on device` at
9.3 GB. Elastic Metal's large local SSD is why this had never appeared. Sizing now
lives per lesson in `lessons.json`.

**`50-nat-vm.sh` could not provision its guest on any host.** Three separate bugs
in the cloud-config it generates, found by reading the guest's serial console:

1. **`packages:` was indented two spaces** at the document's top level. That is
   invalid YAML, and cloud-init discards the *entire* user-data as `empty cloud
   config` — no `agent` user, no podman, no hostname. The guest still boots and
   takes a DHCP lease, so the only visible symptom is `Permission denied
   (publickey)` on the next hop, which reads like a key problem. Host-independent
   and fatal; this is why lesson 5 never produced a scorecard.
2. **`authorized_keys` was copied unfiltered.** On a Scaleway VM that file is
   generated by `scw-fetch-ssh-keys` with a 16-line comment header, so prefixing
   every line with a `-` list marker fed cloud-init `- #` list items. On Elastic Metal the file
   is plain keys, which is why this one only appears on VMs.
3. **`runcmd` used `systemctl --machine=agent@.host`.** `--machine` needs
   `systemd-container`, which a cloud image does not ship, so the runcmd failed and
   took cloud-init's final stage with it (`cloud-init status` → `error`), leaving
   the rootless podman socket absent. `40-openshell.sh` enables that socket itself,
   so the runcmd is simply gone.

With 1 and 2 fixed the guest comes up correct: `podman 5.4.2`, `pasta`, `agent`
with sudo, lingering on, and `192.168.122.x/24` as its primary address.

A fourth, latent one worth not reintroducing: that heredoc is **unquoted** (it has
to interpolate the keys), so `$(...)` anywhere inside it — including in a comment —
runs on the host at generation time. One comment contained `$(openshell doctor
check)` and was being executed.

---

## Chapter 3 substrates — Kubernetes (lessons 6–9)

Single-node **k3s** on the lesson's own disposable VM. Why k3s rather than a managed
cluster (Kapsule) or a nested one (minikube, kind) is argued once, in
`lessons.json`; the short version is that every boundary in this chapter is
installed at **node** level, which managed node pools reconcile away and nested nodes
cannot host at all.

| # | Substrate | Lesson | Result | Proof (from inside the box) |
| :-- | :-- | :-- | :-- | :-- |
| `60-k8s.sh` | k3s `v1.36.3+k3s1`, containerd `2.3.2-k3s2` | 6 | ✅ **works** | plain pod → `uname -r` = **6.8.0-106-generic**, the node's. Correct: a pod is not a kernel boundary |
| `70-k8s-gvisor.sh` | gVisor `release-20260803.0` as a containerd runtime + RuntimeClass | 7 | ✅ **works** | pod under `runtimeClassName: gvisor` → **4.19.0-gvisor**, `/sys/module` 216 → **0** |
| `75-k8s-devmapper.sh` | devmapper snapshotter, so `kata-fc` stops being decorative | 8 | ✅ **works** | pod under `runtimeClassName: kata-fc` → **0 PCI devices** against `kata-qemu`'s 10, same guest kernel. See below |
| `80-k8s-kata.sh` | kata-deploy `4.0.0` Helm chart, `k8sDistribution=k3s` | 8 | see below | |
| `90-k8s-openshell.sh` | agent-sandbox `v0.5.4` + OpenShell chart `0.0.99` | 9 | see below | |

### Four things that cost a provisioned box each to find (2026-08-08)

1. **`kubectl wait --all` does not wait for a resource to EXIST.** With nothing
   matching it exits immediately with `error: no matching resources found`. For the
   first ~20 s after k3s starts the API server answers but the node has not registered,
   so the wait lands in exactly that window and fails the substrate. Poll for the
   object first, then wait on its condition.

2. **A NetworkPolicy is not in force when a pod starts.** It is rules a controller
   writes in *reaction* to the pod's creation, so a container that opens a socket on
   its first instruction beats it. Measured: a one-shot pod got the **same 301** with
   and without a deny-all policy. Two consequences, both load-bearing:
   - `check.sh` proves enforcement by `exec`ing into an **already-running** pod, and
     reports how long it took (**0 s** once the pod exists — so the whole effect is the
     pod-start race, not slow enforcement).
   - the lessons' agent pod waits `POLICY_SETTLE_S` before starting the suite. If that
     is ever too short the lesson **fails loudly** rather than reporting a weaker
     boundary, because `exfiltrate` would read SUCCEEDED and the assertion catches it.

3. **`kubectl run --rm -i` returns the output TWICE, intermittently.** With `-i`
   kubectl attaches, and when the container has already written and exited before the
   attach lands it *also* dumps the logs. One run reported a clean `6.8.0-106-generic`,
   the next `6.8.0-106-generic\n6.8.0-106-generic` — which then failed to equal the
   node's kernel and read as "something is already intercepting". `check.sh` now
   creates → polls for a terminal phase → reads `kubectl logs` → deletes.

4. **In a Pod, attack 7 kills the container instead of being refused.** Lesson 2's
   podman container survives the same 256Mi cap and reports `capped:pids,mem`; the pod
   is `OOMKilled`, because cgroup v2 kills a container's cgroup as a **group**. The row
   proving the cap engaged is therefore the one row the box never prints, so it is
   merged host-side from the kubelet's termination reason — and only credited as
   contained when that reason is literally `OOMKilled`.

### Notes that carry into `infra/` automation

- **k3s does not auto-detect `runsc` or Kata.** Its automatic alternative-runtime
  detection covers crun, the NVIDIA runtimes and the wasm shims only. gVisor needs a
  containerd config template beside the generated config (k3s **regenerates**
  `config.toml` on every start, so editing it directly is undone).
- **The CRI plugin was renamed in containerd 2.0**: `io.containerd.grpc.v1.cri` →
  `io.containerd.cri.v1.runtime`, config version 2 → 3. `70-k8s-gvisor.sh` reads the
  plugin name off the config k3s just generated rather than hardcoding it, so it works
  on either side of that change. Verified live: `io.containerd.cri.v1.runtime` →
  `config-v3.toml.tmpl`.
- **`k8sDistribution=k3s` is load-bearing for kata-deploy.** k3s keeps containerd under
  `/var/lib/rancher/k3s/agent/etc/containerd` with the socket at
  `/run/k3s/containerd/containerd.sock`, and the chart derives both from that one
  value. Left at its default the chart writes a drop-in into a directory k3s never
  reads, **reports success**, and every Kata pod then fails for a reason nothing in the
  DaemonSet logs mentions.
- **kata-deploy is a Helm chart as of Kata 4.0.0.** The kustomize `overlays/k3s` path
  is gone; any guide telling you to `kubectl apply -k` is describing an older version.
- **The agent image is tagged `:v1`, never `:latest`.** Kubernetes defaults a `:latest`
  tag to `imagePullPolicy: Always`, so a side-loaded image is ignored and the kubelet
  chases Docker Hub for something already on disk. Lessons 6–8 could set the policy
  themselves; **lesson 9 cannot**, because OpenShell owns that pod spec.
- **`~/.sandboxing-tutorial.env` must be APPENDED to, with a guard.** Lesson 9 runs
  `60-k8s.sh` *and* `90-k8s-openshell.sh`, and a substrate that truncates it would strip
  the `KUBECONFIG` the previous one exported.

### `kata-fc` was always registered here, and never worked (2026-08-13)

kata-deploy registers a RuntimeClass per shim — **35** of them on this cluster — and `kata-fc` has
been in that list since chapter 3 was built. Naming it got you a pod that never starts:

```text
failed to create containerd container: error unpacking image:
unable to initialize unpacker: snapshotter must be provided to unpack
```

**Registered is not working**, and the gap is storage rather than Kata. Firecracker has virtio-block
and **no virtio-fs**, so a container rootfs cannot be shared in and must arrive as a block device —
which is the devmapper snapshotter's job. `75-k8s-devmapper.sh` supplies it.

What it deliberately does **not** do is configure a per-runtime snapshotter, because kata-deploy
already has:

```toml
[plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata-fc]
snapshotter = "devmapper"
```

on `kata-fc` **and on nothing else** — `kata-qemu` carries no snapshotter line at all and so stays on
the cluster default. The qemu-on-overlayfs / fc-on-devmapper split therefore comes free and correct
from upstream, and a second copy of that decision here would be a second thing to keep in sync.

Two mechanics worth keeping:

- **The drop-in is the seam.** k3s generates
  `imports = [".../config-v3.toml.d/*.toml"]` into every config it writes, and kata-deploy uses that
  directory (`kata-deploy.toml`). `75` drops `devmapper.toml` beside it — two files, two distinct
  tables, nothing shared to clobber, and the gVisor template `70` writes is untouched.
- **An image is unpacked for ONE snapshotter.** `60-k8s.sh` side-loads the agent image into
  overlayfs, and the kubelet never pulls a `:v1` image the node already has — so nothing would put
  those layers into devmapper, and a kata-fc pod would fail at sandbox creation on a node where
  `crictl images` plainly lists the image. `images/agent/import-k3s.sh` now imports a second time
  with `--snapshotter devmapper` wherever that snapshotter is configured.

### Lesson 9 — OpenShell's kubernetes driver WORKS, and the NAT guest is not needed

The open question from chapter 2 is answered. Lesson 5's `50-nat-vm.sh` exists because
OpenShell's **rootless-podman** driver refuses to start when the host's default-route
address is public, and every Scaleway box has one. That constraint belongs to the podman
driver's sandbox callback. Under the **kubernetes** driver the gateway is a workload in
the cluster and the callback is an in-cluster Service on a private ClusterIP, so there is
nothing to work around: `openshell status` reports **Connected** on a plain public-IP VM,
and a policy-governed sandbox pod runs. This confirms, on hardware, the prediction made
in the OpenShell section above ("Cleanest = the k8s driver … this entire class of problem
disappears").

Two traps found here, both costing a box:

1. **The installer bootstraps its own LOCAL gateway and then fails.** After unpacking the
   `.deb`, `install.sh` registers a local gateway on `127.0.0.1:17670`, sets it active,
   and blocks waiting for it. On this box it cannot start —

   ```text
   configuration error: no compute driver configured and auto-detection found
   no suitable driver; set --drivers or OPENSHELL_DRIVERS to kubernetes, podman, docker, or vm
   ```

   — because the user service has no `OPENSHELL_DRIVERS` and there is no rootless podman
   socket to auto-detect. That failure is correct and irrelevant (lesson 9's gateway is
   the Helm release), but the installer **exits non-zero**, which under `set -e` threw
   away a working box. The substrate now tolerates that exit, asserts the binary landed,
   and disables the local service. It also runs `openshell gateway select k8s`, because
   the installer left *its* gateway marked active.

2. **The CLI and the chart version independently.** Pinning only the chart gave a gateway
   at `0.0.99` paired with a CLI that installed itself as **`0.0.101`**. `install.sh`
   honours `OPENSHELL_VERSION`, so both are now pinned to the same version — note the
   forms differ: the chart wants `0.0.99`, the git tag is `v0.0.99`.

Verified: `openshell 0.0.99`, gateway **Connected**, driver `kubernetes`, sandbox Ready,
policy applied, **19 OCSF decisions recorded**, and `http_method_denied` / `binary_scoped`
/ `fs_policy_write` all `403`/`PermissionError` where lesson 6's NetworkPolicy let every
one of them through.
