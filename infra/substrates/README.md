# Chapter 2 substrates — install scripts + verification results

Each script installs one boundary and asserts it engages **from inside** (kernel
identity), never from the flag.

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
| `40-openshell.sh` | NVIDIA OpenShell | 5 | ⚠️ **installs; blocked on podman version** | see below |

**All three of 10/20/30 coexist on one box** — podman's default runtime stays
`crun`, containerd runs separately, runsc is opt-in. That was the coexistence
question, answered.

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
lives per lesson in `terraform/lessons.json`.

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
