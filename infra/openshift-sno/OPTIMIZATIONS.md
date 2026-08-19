# Rebuilding this cluster faster — findings from the second run

> **Status: from a live rebuild on 2026-08-05.** [`REPRODUCE.md`](REPRODUCE.md)
> is the runbook and stays the source of truth for *what* to do. This file is
> what the second run learned about *how* to do it for less time and money, plus
> three traps the first run never hit because it took a different route.
>
> Every item below is marked **verified** (observed this run), **new trap**
> (cost time this run), or **candidate** (reasoned, not yet proven).

The cluster is deleted after every session, so "test the env" always means a
full rebuild. That makes the rebuild path itself worth optimising: it is not a
one-off, it is the unit of work for all of chapter 4.

---

## 1. Preflight before you spend — **verified**, biggest win

The meter starts at `server create`. Everything in this table can be checked
**before** that, costs nothing, and each one catches a failure that would
otherwise surface with the box already billing:

```bash
# 1. has the pinned release moved?  (stable-4.18 -> expect 4.18.49)
curl -fsSL https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-4.18/release.txt | grep -m1 Name:

# 2. do the pinned client artifacts still exist?
curl -fsS -o /dev/null -w '%{http_code}\n' \
  https://mirror.openshift.com/pub/openshift-v4/clients/ocp/4.18.49/openshift-install-mac-arm64.tar.gz

# 3. is the hardware orderable, and at what price?
scw baremetal offer list zone=fr-par-1 -o json \
  | jq -r '.[]|select(.name|test("B112X"))|"\(.name) stock=\(.stock) \(.price_per_hour)"'

# 4. credentials present (never print them)
ls -l ~/.secrets/rh-pull-secret.json && scw account project list -o json | jq -r '.[].name'

# 5. lesson 1.4.4's upstream deps — at the versions CHAPTER 3 pinned, not older ones
curl -fsS -o /dev/null -w 'agent-sandbox %{http_code}\n' -L \
  https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.5.4/sandbox.yaml
helm show chart oci://ghcr.io/nvidia/openshell/helm-chart --version 0.0.99 >/dev/null && echo "openshell chart ok"
```

> All five are now implemented as `./install.sh --preflight`, so there is nothing to
> copy-paste and nothing to forget. Run it before every session.

On 2026-08-05 all five passed and `stable-4.18` was still `4.18.49`, so the pin
had not drifted in a year of wall-clock. That is luck, not a guarantee — the
point of the check is that finding out costs €0 instead of €0.26/hr.

**On 2026-08-10 the pin HAD drifted: `stable-4.18` is now `4.18.50`.** The 4.18.49
artifacts are still served, so this repo stays on the version it actually proved and
the preflight reports the drift as information rather than as a failure. That is the
check earning its keep on the second outing.

Two version numbers in this file were also stale by then and are corrected above:
lesson 1.4.4's deps were listed at agent-sandbox `v0.5.3` and openshell `0.0.42`, while
chapter 3 shipped against `v0.5.4` and `0.0.99`. A preflight that checks the wrong
versions is worse than none — it returns green for artifacts nothing will fetch.

**Do the whole ignition build before ordering, too.** `openshift-install` is
**641 MB** and takes ~45 s to fetch; the only input that needs the real box is
`machineNetwork`, and Scaleway hands you a `/24` off the assigned IP. Render the
config with the presumed CIDR, generate the ignition, wrap it, and confirm the
CIDR on the node before you kexec (this run: assumed `62.210.89.0/24`, node
reported `62.210.89.205/24` — match, no regeneration).

---

## 2. Wrap the ignition on the Mac — **verified**, deletes Traps #3 and #4

`quay.io/coreos/coreos-installer:release` publishes **linux/arm64** as well as
amd64, so `pxe ignition wrap` runs natively on Apple Silicon:

```bash
podman run --rm --arch arm64 -v "$PWD":/data:z -w /data \
  quay.io/coreos/coreos-installer:release \
  pxe ignition wrap -i /data/bootstrap.ign -o /data/ign.img
# verify: XZ-compressed cpio containing exactly config.ign
gzip -dc ign.img 2>/dev/null | cpio -t     # -> config.ign
```

`ign.img` is ~109 KB, so it `scp`s instantly. That removes the *only* reason the
node ever needed a container runtime, and with it:

- **Trap #3** (rescue is Ubuntu 20.04, no podman) — no longer reachable.
- **Trap #4** (tmpfs can't hold overlay xattrs, needs ext4 on `/dev/sdb`) — no
  longer reachable.

`scripts/rescue-raid-teardown-and-docker.sh` exists to set up that Docker. With
the wrap moved to the workstation, its entire second half is dead code.

---

## 3. Scaleway rescue refused the IAM SSH key — **new trap**

Booting `boot-type=rescue` worked (`boot_type: rescue`, `server_start_rescue`
event, sshd answering, OpenSSH 8.2p1 = Ubuntu 20.04), but **every login was
rejected**, as `root` and as `ubuntu`, still failing 5 minutes after rescue
started:

```text
debug1: Offering public key: ~/.ssh/id_ed25519_mymac ED25519 SHA256:elG+Ayw...
debug1: Authentications that can continue: publickey,password
Permission denied (publickey,password).
```

The key was **provably correct** — its MD5 fingerprint matched the registered
IAM key byte for byte:

```bash
ssh-keygen -lf ~/.ssh/id_ed25519_mymac.pub -E md5
#   256 MD5:8a:fc:7e:...:33:79
scw iam ssh-key get 41075dd9-... -o json | jq -r .fingerprint
#   256 MD5:8a:fc:7e:...:33:79   (identical)
```

This matters because **`REPRODUCE.md` §3.4 method (A) starts in rescue.** Anyone
following the runbook literally hits this wall with the box already billing.

**The fix: don't use rescue.** Kexec from the *installed* OS instead — see §4.
Root cause of the refusal was not chased; at €0.26/hr the cheaper move was to
route around it. If you do want to debug it, `scw baremetal bmc start` (a paid
option) gives a real console, and Trap #15 already recommends enabling one.

---

## 4. Kexec from the installed Ubuntu, not from rescue — **verified**

Rescue exists in the runbook for exactly one reason: it runs from a ramdisk, so
both disks are free to wipe. But **kexec already gives you that** — the RHCOS
live system runs entirely in RAM, so whatever was mounted from disk is gone the
moment it jumps. Rescue is not load-bearing.

Kexec-ing from the installed Ubuntu 24.04 has two concrete advantages: the IAM
key works by construction (`install.ssh_key_ids`), and 24.04 is a modern
userspace instead of 20.04. The script is
[`scripts/ubuntu-kexec-live.sh`](scripts/ubuntu-kexec-live.sh).

The one thing it must handle that rescue did not: **Ubuntu's root is on md-RAID
across both disks** (`/dev/md0` = `/boot`, `/dev/md1` = `/`, RAID1 over
`sda3+sdb2` / `sda4+sdb3` — Trap #6, confirmed from the API's
`partitioning_schema`), and you cannot wipe a disk you are running from. So:

1. **Detach and wipe the second disk first.** RAID1 keeps running degraded on
   the remaining member, which is fine — the array is about to be destroyed:

   ```bash
   mdadm --manage /dev/md0 --fail /dev/sdb2; mdadm --manage /dev/md0 --remove /dev/sdb2
   mdadm --manage /dev/md1 --fail /dev/sdb3; mdadm --manage /dev/md1 --remove /dev/sdb3
   mdadm --zero-superblock /dev/sdb[123]; wipefs -a /dev/sdb; sgdisk --zap-all /dev/sdb
   ```

2. **Add `rd.md=0 rd.auto=0`** to the live kernel cmdline, intended to stop the
   live environment assembling the surviving array so `/dev/sda` has no holders.

> [!warning]
> **`rd.md=0` did not actually work** — see §5. The thing that saved this run was
> step 1, plus a device-naming coincidence. Do not rely on step 2 alone.

Timings this run: `install_done` → 11 min. Ubuntu reachable → 5 min after a
reboot (note `install_done` does **not** mean reachable; the box reboots).
Kexec jump → RHCOS live with `bootkube` running in **~75 seconds**.

---

## 5. Device names are not stable across kernels — **new trap**, nearly fatal

Under Ubuntu, the system disk was `/dev/sda` and the disk I wiped was
`/dev/sdb`. After the kexec, **RHCOS live enumerated them the other way round**:

| | Ubuntu 24.04 | RHCOS live (after kexec) |
| :-- | :-- | :-- |
| system disk (RAID members) | `sda` | **`sdb`** |
| wiped/clean disk | `sdb` | **`sda`** |

`install-config.yaml` says `bootstrapInPlace.installationDisk: /dev/sda`, and
that name is resolved by the **RHCOS live kernel**, not by the kernel you typed
it under. So the install went to the physical disk Ubuntu called `sdb`.

**This broke the run.** RHCOS installed perfectly — ostree deployment, `grub2`,
`ignition.firstboot`, loader entries, all verified by mounting the partitions —
but onto the disk **the BIOS does not boot**. After the pivot the box came back
up in *Ubuntu*, and the giveaway was the SSH banner:

```text
debug1: Remote protocol version 2.0, remote software version OpenSSH_9.6p1 Ubuntu-3ubuntu13.14
```

An installed-and-invisible cluster is a nasty failure mode: `bootkube` reports
success, `install-to-disk` exits 0, the disk really does contain a complete
node, and the only symptom is that the API never comes up. Nothing in the
install log says "wrong disk".

And `rd.md=0 rd.auto=0` did **not** prevent assembly — the live environment
still brought the array up, just renamed and read-only:

```text
md126 : active (auto-read-only) raid1 sdb4[0]
md127 : active (auto-read-only) raid1 sdb3[0]
```

So `rd.md=0` bought nothing. The array came up on the disk we were *not*
installing to, which is the only reason `install-to-disk` found its target free
and Trap #7 did not also fire. Two independent failures were in play and only
one of them landed.

**The fix — never name the install disk by kernel device name.** Capture the
WWN on the node *before* generating the ignition, and use the stable path, which
`bootstrapInPlace` accepts:

```bash
lsblk -o NAME,SIZE,WWN,SERIAL        # on the node, during fact capture
findmnt -no SOURCE /boot             # -> which disk the firmware actually boots
```

```yaml
bootstrapInPlace:
  installationDisk: /dev/disk/by-id/wwn-0x5001b448b798b45e
```

**And it must be the disk the firmware boots**, not merely a clean one. On this
box:

| Disk | WWN | Role |
| :-- | :-- | :-- |
| Ubuntu's `sda` | `0x5001b448b798b45e` | **the BIOS boot disk** — install here |
| Ubuntu's `sdb` | `0x5001b448b798b45a` | second disk — a perfect install here is invisible |

There is a second-order problem the WWN fix alone does not solve: on a 2-disk
Scaleway box, Ubuntu's root is md-RAID across **both** disks, so the BIOS boot
disk always carries an array that the live environment re-assembles — making it
busy for `install-to-disk` (Trap #7, for real). Wiping it from the running
system is impossible, since that is the disk you are running from. Options, in
order of preference:

1. **Two-stage kexec** — boot the live env with a minimal ssh-only ignition,
   `mdadm --stop --scan` and wipe *both* disks from RAM, then kexec again with
   the bootstrap ignition. Deterministic; costs one extra ~90 s jump.
2. **Custom Scaleway partitioning** — install the base OS to one disk only
   (`partitioning_schema`), leaving the boot disk untouched and RAID-free.
3. **Recover after the fact** — if RHCOS has already landed on the non-boot
   disk, zeroing the boot disk's protective MBR + primary GPT (34 sectors) makes
   the firmware fall through to the good disk. This is what the 2026-08-05 run
   did, and it is a repair, not a plan.

---

## 6. Take the RHCOS live URLs from the installer, never from the mirror index

**Verified.** The mirror has a `dependencies/rhcos/4.18/latest/` directory. It
is **not** the build your installer wants:

| Source | Build |
| :-- | :-- |
| `mirror.../dependencies/rhcos/4.18/latest/` | **4.18.27** |
| `openshift-install 4.18.49 coreos print-stream-json` | **418.94.202602022246-0**, on a *different* host (`rhcos.mirror.openshift.com/art/storage/...`) |

Guessing the path under `dependencies/` returns 404s that read like the artifacts
are gone; taking `latest/` instead silently gives you a live image mismatched
with your installer. Always:

```bash
./openshift-install coreos print-stream-json \
  | jq -r '.architectures.x86_64.artifacts.metal.formats.pxe
           | .kernel.location, .initramfs.location, .rootfs.location'
```

The three URLs hard-coded in `scripts/node-kexec-live.sh` are correct **for
4.18.49 only** — they are a cache of that command, and they rot the moment the
pin moves. Re-derive rather than trust them.

---

## 7. Timings and cost from this run

| Phase | Wall-clock |
| :-- | :-- |
| `server create` → `install_done` (Ubuntu) | 11 min |
| reboot → Ubuntu reachable | 5 min |
| rescue detour (dead end, §3) | ~6 min |
| ignition generate + wrap + scp | < 2 min (all pre-staged) |
| kexec → RHCOS live with bootkube running | ~1.5 min |
| bootkube → pivot → cluster | *(see below)* |

---

## 8. Candidates — reasoned, not yet verified

- **Skip the OS install entirely.** Nothing from Ubuntu survives; it exists only
  to give a shell that accepts the IAM key. If a freshly-delivered box can boot
  rescue *with working keys*, ~11 min disappears. Blocked on §3.
- **Drive `oc` from the Mac** via `tls-server-name`, instead of pushing a 185 MB
  `oc` to the node (Trap #11):

  ```bash
  oc config set-cluster sno --server=https://<IP>:6443 --tls-server-name=api.sno.spike.lab
  ```

  The cert's SAN is `api.sno.spike.lab`; `tls-server-name` makes verification use
  that name while connecting to the IP, so no `/etc/hosts` edit and no 185 MB
  push. **Verified below if the result section says so.**
- **`scripts/rescue-raid-teardown-and-docker.sh` should be retired** in favour of
  `ubuntu-kexec-live.sh`. Keeping both invites following the rescue path into §3.

---

## 9. Outcome of the 2026-08-05 run — **no cluster**

Stated plainly so nobody reads this file as a success report: **the rebuild did
not produce a working cluster, and lessons 1.4.1–1.4.4 were not verified against
anything live.**

How far it got:

| Stage | Result |
| :-- | :-- |
| Provision `EM-B112X-SSD` | ✅ 11 min |
| Ignition generated + wrapped on the Mac | ✅ |
| kexec Ubuntu → RHCOS live | ✅ ~90 s |
| `bootkube` (temporary control plane) | ✅ completed, `.bootkube.done` written |
| `install-to-disk` | ✅ wrote a complete RHCOS node… **to the wrong disk** (§5) |
| Node boots into the cluster | ❌ came back up in **Ubuntu** |
| MBR-wipe repair → BIOS fall-through | ❌ inconclusive — three short ping windows (boot, network up, reset) but never SSH or API |
| Lessons 1.4.1, 1.4.2, 1.4.3, 1.4.4 | ❌ **not run** |

The box was deleted at `00:14:50Z`, ~1h26m after `billing_start` — **~€0.38**.

**The single lesson worth carrying forward:** an install can succeed completely
and still be invisible. `bootkube` finished, `install-to-disk` exited 0, and the
target disk held a valid ostree deployment with a working bootloader — yet the
machine had no cluster on it, because the firmware boots a *different* disk than
the one the live kernel calls `/dev/sda`. Pin `installationDisk` to a WWN and
confirm it is the disk the firmware boots; everything else here is secondary.

**Still unproven, and must not be assumed:**

- the WWN fix (§5) — reasoned, never executed
- the two-stage kexec (§5) — designed, never executed
- `tls-server-name` for driving `oc` from the Mac (§8) — configured, never
  reached a live API
- every claim in `REPRODUCE.md` §3.6–3.8 (operator, KataConfig, Kata VM, SCC),
  which this run never got close enough to re-test

---

## 10. The disk fix, built and validated on the ground — 2026-08-10

§5 diagnosed the failure and proposed a fix but never executed it. It is now
implemented in [`install.sh`](install.sh), and **every part of it that can be proven
without hardware has been**, for €0 — which is the point of §1 taken to its
conclusion. Nothing below has yet met a real box; what is claimed is only that the
artifacts are correct.

### What the fix actually is

Two independent causes had to be closed, and the §5 proposal only named one:

1. **The wrong disk.** `installationDisk` is resolved by the RHCOS-live kernel, which
   enumerated the disks the other way round from Ubuntu. Now pinned by **WWN**, read
   off the box during fact capture:
   `installationDisk: /dev/disk/by-id/wwn-0x...`.
2. **A second bootable disk.** Even a perfect install is invisible if the firmware has
   a leftover Ubuntu to boot instead — that is precisely what run 2 produced. §5
   proposed a **two-stage kexec** to wipe both disks from RAM. That was dropped: it
   assumes `kexec` exists inside RHCOS-live, which is not guaranteed, and it needs an
   operator to remember a manual step on a blind box.

   Instead the generated ignition is patched with `jq` to carry a unit:

   ```ini
   [Unit]
   Description=Wipe every disk before bootstrap-in-place installs
   DefaultDependencies=false
   After=basic.target
   Before=install-to-disk.service
   ```

   which runs `mdadm --stop --scan`, then `wipefs`/`sgdisk`/`dd` over every whole
   disk, in RAM, before anything is written. One kexec, no live-env tooling assumed,
   and the guarantee travels **inside the artifact** rather than in a runbook step.

### Verified without spending anything

| Claim | How it was checked |
| :-- | :-- |
| install-config renders with the real CIDR + WWN | rendered from faked facts, `installationDisk:` line inspected |
| the ignition builds | `openshift-install create single-node-ignition-config` → 293 KB + `auth/` |
| the wipe unit lands | `jq` assertion in the script, then extracted from the wrapped image |
| the wrap works on Apple Silicon | `podman --arch arm64 coreos-installer pxe ignition wrap` → **109,916 B**, XZ cpio containing exactly `config.ign` |
| **the WWN reaches the installer** | decoded the gzip+base64 file contents inside the ignition: `/usr/local/bin/install-to-disk.sh` runs `coreos-installer install -n -i /opt/openshift/master.ign /dev/disk/by-id/wwn-0x...` |

That last one is the one worth doing. A plain `grep` of the ignition JSON for the WWN
finds **nothing** — every file payload is gzip+base64 — so "I checked and the disk
isn't in there" is a false alarm waiting to happen, in both directions.

### The near-miss that matters most — a fix that caused the next bug

Bug 1 below (`facts.env` not shell-sourceable) was fixed by **quoting** the `DISK=` lines.
That fix silently broke the WWN extraction: `awk '{print $3}'` now returned the value
*with its closing quote*, and it went all the way through to

```yaml
installationDisk: /dev/disk/by-id/wwn-0x5001b448b798588b"
```

— a path no device will ever match. On a live box this wipes both disks, fails to
install, and leaves you debugging a machine with no console: **the exact shape of the
2026-08-05 failure.** It was caught only because the script echoes the value it is about
to use and someone read it; the kexec had not yet fired, so the box was salvaged and no
re-provision was needed.

The fix is `tr -d '"'`, but the *lesson* is the validation that is now there:

```bash
case "${INSTALL_WWN}" in
  0x[0-9a-f]*) : ;;
  *) die "WWN '${INSTALL_WWN}' is not of the form 0x<hex> — refusing to pin installationDisk" ;;
esac
```

A value whose entire job is to resolve to a real device **in a different kernel, an hour
later, with no console** deserves a shape check at capture time. "Non-empty" is not
validation. Note also that both disks on this box have WWNs of the same shape but
different vendors (`0x5001b448...` Seagate, `0x5002538d...` Samsung) — so "it looks like
a WWN" is necessary, not sufficient; it must also be the disk the firmware boots.

### Three bugs the dry run caught before the meter started

1. **`facts.env` was not shell-sourceable.** `DISK=sda 894.3G 0x...` → `894.3G:
   command not found`. The file is a human-readable log *and* was being `source`d;
   it now quotes multi-word values, and `install.sh` extracts the two values it needs
   with `awk` instead of sourcing at all.
2. **The preflight aborted on its first failure.** A transient `curl` exit 56 on the
   release notes killed the run under `set -e`, reporting one problem instead of
   twelve. Preflight now runs with errexit off — a diagnostic that stops at the first
   symptom is not a diagnostic.
3. **The podman machine was down**, so the wrap failed. Now surfaced as a real
   non-zero exit rather than a message scrolling past.

### The device-name swap, REPRODUCED on hardware — 2026-08-10

§5 inferred the swap from a post-mortem. It has now been observed directly, on
`sbx-openshift-sno`, by reading the disks under both kernels in the same session:

| | Ubuntu 24.04 | RHCOS live (after kexec) |
| :-- | :-- | :-- |
| `sda` | 953.9G `0x5001b448b798588b` | 931.5G `0x5002538d428fd895` |
| `sdb` | 931.5G `0x5002538d428fd895` | **953.9G `0x5001b448b798588b`** |

**They swap.** `installationDisk: /dev/sda` — what the template shipped with, and what
`ubuntu-kexec-live.sh` still hardcodes — resolves under the live kernel to the *other*
physical disk. That is not a theory about what went wrong in 2026-08-05; it is the same
machine doing the same thing again, with the WWN pin now making it harmless.

Note the two disks are different models (Seagate `0x5001b448…` 953.9G, Samsung
`0x5002538d…` 931.5G), so the sizes give the swap away at a glance. Do not rely on that
— pin the WWN and check it against the disk the firmware boots.

The wipe unit also ran, first time:

```text
● sbx-wipe-disks.service - Wipe every disk before bootstrap-in-place installs
     Active: active (exited) ... (code=exited, status=0/SUCCESS)
     + dd if=/dev/zero of=/dev/sdb bs=1M count=16 oflag=direct
```

and both disks came out with an empty `FSTYPE` — no filesystem, no RAID superblock, and
therefore nothing else on the machine for the firmware to boot.

### Still unproven, and must not be assumed

- that `Before=install-to-disk.service` orders early enough in the live env
- everything in `REPRODUCE.md` §3.6–3.8 (operator, KataConfig, Kata VM, SCC), which
  has not been re-tested since 2026-08-04
