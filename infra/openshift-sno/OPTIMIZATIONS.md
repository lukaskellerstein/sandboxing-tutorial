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

# 5. lesson 13's upstream deps
curl -fsS -o /dev/null -w 'agent-sandbox %{http_code}\n' -L \
  https://github.com/kubernetes-sigs/agent-sandbox/releases/download/v0.5.3/sandbox.yaml
helm show chart oci://ghcr.io/nvidia/openshell/helm-chart --version 0.0.42 >/dev/null && echo "openshell chart ok"
```

On 2026-08-05 all five passed and `stable-4.18` was still `4.18.49`, so the pin
had not drifted in a year of wall-clock. That is luck, not a guarantee — the
point of the check is that finding out costs €0 instead of €0.26/hr.

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
not produce a working cluster, and lessons 10–13 were not verified against
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
| Lessons 10, 11, 12, 13 | ❌ **not run** |

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
