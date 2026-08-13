# Reproducing Kata-on-OpenShift on cheap bare metal (Single-Node OpenShift)

> **Status: PROVEN end-to-end on 2026-08-04.** A Single-Node OpenShift (SNO)
> cluster was installed on a Scaleway Elastic Metal box for **~€0.6 total**, the
> OpenShift sandboxed-containers operator was installed, and a pod under
> `runtimeClassName: kata` was confirmed to run inside a **real KVM VM** (not a
> runc fallback). SCC admission was also demonstrated. This document is the
> runbook to do it again, plus every wrong turn so you don't repeat them.

This exists because **there is no cheap *managed* Kata-on-OpenShift.** Kata needs
bare-metal worker nodes **and** cluster-admin. That rules out every cheap option:
the free Red Hat Developer Sandbox has no cluster-admin (can't install the
operator); ROSA/ARO only run Kata on AWS/Azure `*.metal` instances (~$5/hr);
MicroShift's community CentOS-Stream-9 repo is dead (stuck at 4.8.0 / 2022,
missing `cri-o`). Self-hosting SNO on cheap bare metal is the cheapest path that
exists, and this is how.

---

## 0. Outcome to reproduce (what "done" looks like)

Two assertions, both made **from inside the sandbox / cluster**, never from the
flag you passed:

**Kata is a real VM** — a pod with `runtimeClassName: kata` reports:

```text
DMI_PRODUCT=KVM          # <- running inside a KVM virtual machine
DMI_VENDOR=Red Hat
NPROC=1                  # node has 24 -> isolated VM CPU allocation
MEM_TOTAL_KB=1942568     # ~1.9 GB; node has 198 GB -> separate VM memory
VIRTIO_DEVS=6            # virtio devices only exist in a VM
KERNEL=5.14.0-427...     # NOTE: matches the node version — see Trap #12
```

**SCC admission rejects an over-privileged pod:**

```text
A) privileged pod  -> Forbidden: unable to validate against any security context
   constraint: [ ... restricted-v2: privileged: Invalid value: true: Privileged
   containers are not allowed ... ]   (all 15 SCCs checked, none allow it)
B) compliant pod   -> admitted, assigned SCC "restricted-v2"
```

---

## 1. Prerequisites

| Need | Detail |
| :-- | :-- |
| **Scaleway account** + `scw` CLI | context configured; project can create Elastic Metal. Your SSH **public** key registered as an IAM SSH key (used for rescue + base OS). |
| **Red Hat pull secret** | free (Red Hat Developer account) → <https://console.redhat.com/openshift/install/pull-secret>. Kept **outside the repo**, e.g. `~/.secrets/rh-pull-secret.json`, mode 600. This is the only credential SNO needs (no `subscription-manager`). |
| `openshift-install` + `oc` | pinned to a version, see §3. macOS build for generating ignition; **linux `oc`** to drive the cluster from the node. |
| **Client network** | see **Trap #1 (MTU)** — SSH to Scaleway may need `sudo ifconfig <if> mtu 1400`. |

**Never commit** the pull secret, the generated `auth/kubeconfig`, `auth/kubeadmin-password`,
or any SSH private key. See `.gitignore` in this directory.

---

## 2. Hardware choice

**`EM-B112X-SSD`** (fr-par-1): 12c/24t, 192 GB, 2× 954 GB SATA SSD, **BIOS** boot,
Xeon E5-2620 (has `vmx` → `/dev/kvm` present, required for Kata). **€0.263/hr.**

Why this one: SNO minimum is **8 vCPU / 16 GB / 120 GB**. EM-B112X clears it with
room and is *cheaper* than the 8-core NVMe offers. Two disks matter — the base
Ubuntu install puts them in md-RAID (Trap #6), and we use `/dev/sdb` as scratch
(Trap #4).

---

## 3. The procedure (that works)

All commands below assume `WORK` is a scratch dir holding the tools + config, and
`$IP` is the box's public IP. The actual working scripts are in `scripts/`.

### 3.1 Tools + pinned version (on your workstation)

```bash
BASE=https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable-4.18   # -> 4.18.49
curl -fsSL "$BASE/openshift-install-mac-arm64.tar.gz"  | tar -xz openshift-install
curl -fsSL "$BASE/openshift-client-mac-arm64.tar.gz"   | tar -xz oc
curl -fsSL "$BASE/openshift-client-linux.tar.gz"       | tar -xz -O oc > oc-linux   # for the node
# RHCOS images that match the installer:
./openshift-install coreos print-stream-json | jq -r '.architectures.x86_64.artifacts.metal.formats.pxe | .kernel.location, .initramfs.location, .rootfs.location'
```

Verified versions: **OCP 4.18.49**, **RHCOS 418.94.202602022246-0**,
sandboxed-containers-operator **v1.12.1**, coreos-installer container
**quay.io/coreos/coreos-installer:release** (v0.26.0).

### 3.2 Provision the box (Ubuntu base, then we replace it)

```bash
scw baremetal server create name=sno type=EM-B112X-SSD zone=fr-par-1 \
  install.os-id=<ubuntu-24.04-os-id> install.hostname=sno \
  install.ssh-key-ids.0=<your-iam-ssh-key-id>
# WAIT on install.status == "completed" (NOT server status == "ready" — Trap #8)
```

Capture the node's **network CIDR** and **disks** once SSH is up (`ubuntu@$IP`):
`ip -4 -o addr show scope global` (→ e.g. `62.210.88.0/24`), `lsblk` (→ `sda`,`sdb`),
`[ -d /sys/firmware/efi ] && echo UEFI || echo BIOS`.

### 3.3 Generate the SNO ignition (on your workstation)

`install-config.yaml` (fill `machineNetwork` with the real CIDR from 3.2; embed the
pull secret as a single line; `sshKey` = a throwaway pubkey for the RHCOS `core`
user):

```yaml
apiVersion: v1
baseDomain: spike.lab
metadata: { name: sno }
compute:      [{ name: worker, replicas: 0 }]
controlPlane: { name: master, replicas: 1 }
networking:
  networkType: OVNKubernetes
  clusterNetwork: [{ cidr: 10.128.0.0/14, hostPrefix: 23 }]
  serviceNetwork: [172.30.0.0/16]
  machineNetwork: [{ cidr: 62.210.88.0/24 }]     # <- the node's real subnet
platform: { none: {} }
bootstrapInPlace: { installationDisk: /dev/sda }
pullSecret: '<one-line pull secret JSON>'
sshKey: '<core pubkey>'
```

```bash
openshift-install --dir=cfg create single-node-ignition-config
# -> cfg/bootstrap-in-place-for-live-iso.ign, cfg/auth/kubeconfig, cfg/auth/kubeadmin-password
```

### 3.4 Write RHCOS to disk — **the critical step, do it via kexec**

> ⚠️ **Do NOT** `coreos-installer install /dev/sda -i bootstrap...ign` with the
> **metal raw image**. It "works" (disk gets RHCOS) but then bootstrap-in-place's
> `install-to-disk.service` loops forever with *"found busy partitions"* because
> the running system occupies `/dev/sda`. This wasted the most time. See Trap #7.

The correct method boots RHCOS **live in RAM** so both disks are free. Two ways —
we used (B):

**(A) if starting from rescue:** boot rescue (`scw baremetal server reboot <id>
boot-type=rescue`), install `docker.io` (rescue is Ubuntu 20.04, no podman —
Trap #3), back it with ext4 on `/dev/sdb` (tmpfs can't do overlay xattrs —
Trap #4), and `kexec` into the RHCOS live kernel with the ignition wrapped in.

**(B) if a broken metal install is already looping (what happened):** `kexec`
straight from the stuck RHCOS node — it has podman + kexec. This is
`scripts/node-kexec-live.sh`, run on the node:

```bash
# on the RHCOS node (ssh core@$IP), with /var/tmp/bootstrap.ign present:
curl -fsSL <LIVE_KERNEL_URL>    -o kernel
curl -fsSL <LIVE_INITRAMFS_URL> -o initramfs.img
sudo podman run --rm -v /var/tmp:/data:z -w /data quay.io/coreos/coreos-installer:release \
     pxe ignition wrap -i /data/bootstrap.ign -o /data/ign.img      # embed ignition
cat initramfs.img ign.img > boot.img                                # append ignition cpio
sudo kexec -l kernel --initrd=boot.img \
     --append="coreos.live.rootfs_url=<LIVE_ROOTFS_URL> ignition.firstboot ignition.platform.id=metal rd.neednet=1 ip=dhcp"
sudo bash -c 'nohup kexec -e >/dev/null 2>&1 &'     # jumps into RHCOS live in RAM
```

Then RHCOS live (RAM) runs `install-to-disk` → writes the permanent system to the
now-free `/dev/sda` → reboots → the real SNO forms.

### 3.5 Wait for the cluster, and drive it from the node

The API comes up on the **node IP**, not localhost. `platform: none` provides no
DNS, so you must map the names yourself (**Trap #10**). Drive `oc` from the node
(it resolves the cluster's internal names); pushing a 185 MB `oc` binary is slow,
push it **once** after the cluster stabilises (Trap #11):

```bash
# on the node (ssh core@$IP), once reachable:
echo "$IP api.sno.spike.lab api-int.sno.spike.lab" | sudo tee -a /etc/hosts
export KUBECONFIG=/home/core/kc          # scp cfg/auth/kubeconfig here
./oc get clusterversion                  # watch "Working towards 4.18.49: N of 906"
```

**Accept 32/34 operators.** `authentication`, `console`, `ingress` stay Degraded
because the `*.apps.<domain>` **wildcard** DNS isn't set (Trap #10). That blocks
only the web console / browser oauth — **not** the API, operators, Kata, or SCC.
Proceed.

### 3.6 Install the sandboxed-containers operator + Kata

```bash
oc apply -f manifests/osc-operator.yaml      # ns + OperatorGroup + Subscription (channel: stable)
# wait: oc get csv -n openshift-sandboxed-containers-operator  -> ...v1.12.1 Succeeded  (~1 min)
oc apply -f manifests/kataconfig.yaml        # triggers a MachineConfig -> ONE node reboot (~10-15 min)
# wait: oc get runtimeclass kata             -> appears when kataconfig ready=1/1
```

### 3.7 Verify Kata is a real VM (assert from inside — Trap #12)

```bash
oc apply -f manifests/kata-verify-pod.yaml   # runtimeClassName: kata, prints DMI/virtio/nproc/mem
oc logs kata-verify -n default               # expect DMI_PRODUCT=KVM, VIRTIO_DEVS>0, NPROC/MEM << node
oc get node -o jsonpath='{.items[0].status.nodeInfo.kernelVersion}'   # for contrast
```

### 3.8 Demonstrate SCC admission (Trap #13)

```bash
oc create ns scctest; oc -n scctest create sa rogue
oc -n scctest adm policy add-role-to-user edit system:serviceaccount:scctest:rogue   # RBAC so ONLY SCC can block
oc -n scctest --as=system:serviceaccount:scctest:rogue create -f manifests/priv-pod.yaml   # -> REJECTED by SCC
oc -n scctest --as=system:serviceaccount:scctest:rogue create -f manifests/compliant-pod.yaml # -> admitted, restricted-v2
```

### 3.9 Tear down

```bash
scw baremetal server delete <id> zone=fr-par-1      # stops billing. ~€0.26/hr while up.
```

---

## 3b. Watching progress — **poll the actual state, never just wait**

Every phase below has a *direct* way to see where it is. Nothing here needs a
"notification" — if you're wondering whether something finished, run the check.
The principle: **start long jobs detached, then poll their log or the live
state on a cadence matched to the operation.** Run a long command with
`nohup … >/tmp/x.log 2>&1 &` (survives SSH drops), then `tail`/`grep` the log or
query the system. A useful poll loop logs *only on state change* so it stays
readable:

```bash
last=""; for i in $(seq 1 N); do s=$(<check>); [ "$s" != "$last" ] && { echo "[$(date +%H:%M:%S)] $s"; last=$s; }; <break-on-done>; sleep <secs>; done
```

| Phase | How to check it (run this — don't wait) | "Done" looks like |
| :-- | :-- | :-- |
| **Scaleway provision / OS install** | `scw baremetal server get <id> -o json \| jq '{status,install:.install.status}'` · `scw baremetal server list-events server-id=<id>` (power/install timeline) | `.install.status == "completed"` (server `status: ready` alone is NOT enough — Trap #8) |
| **Blind boot (no console)** | `ping -c1 <ip>` (kernel up) · `nc -z <ip> 22` (sshd up) · `scw baremetal server list-events …` · for a real console: `scw baremetal bmc start server-id=<id> ip=<your-ip>` (Serial Console/Remote Access option) | port 22 answers *and* an ssh command returns (sshd flaps during boot — poll for 2 consecutive opens) |
| **RHCOS write (rescue)** | run it detached; `sudo tail -f /tmp/rhcos.log` · `lsblk /dev/sda` | log shows `coreos rc=0`; `sda` gains a partition table |
| **Bootstrap-in-place** (from `ssh core@<ip>`) | `sudo journalctl -u bootkube -u install-to-disk --no-pager \| tail` · `ls /opt/openshift/.bootkube.done` · `systemctl is-active kubelet` · `sudo crictl pods` · `pgrep -a coreos-installer` | `.bootkube.done` exists; `install-to-disk` **not** restart-looping (if it is → Trap #7); a self-reboot happens (uptime resets) |
| **API reachable** | from anywhere: `curl -k -s -o /dev/null -w '%{http_code}' https://<ip>:6443/healthz` | `200` |
| **Operator rollout** (`oc`, admin kubeconfig) | `oc get clusterversion` (→ `Working towards 4.18.49: N of 906 done (Y%)`) · `oc get co` · not-ready + why: `oc get co \| awk '$3!="True"\|\|$5=="True"'` | `clusterversion Available=True`, or accept 32/34 (auth/console/ingress degraded on `*.apps` — fine for Kata+SCC) |
| **OLM operator install** | `oc get csv -n openshift-sandboxed-containers-operator` · `oc get sub,installplan -n …` | CSV `…v1.12.1  Succeeded` (~1 min) |
| **KataConfig / Kata install** | `oc get kataconfig cluster-kataconfig -o jsonpath='{.status.conditions[?(@.type=="InProgress")].status} ready={.status.kataNodes.readyNodeCount}/{.status.kataNodes.nodeCount}'` · `oc get runtimeclass kata` · the node **reboots once** here | `runtimeclass kata` exists; `InProgress=False ready=1/1` |
| **Kata pod / VM proof** | `oc get pod`, `oc logs <pod>` · on node: `sudo pgrep -a 'qemu\|cloud-hyper\|kata'` (`kata-monitor` present) | pod `Running`; logs show `DMI_PRODUCT=KVM` |

Practical notes learned the hard way:

- **A quiet monitor is not a stalled process.** If a state-change-only loop hasn't
  logged in a while, `ssh` in and read `journalctl` / `oc get clusterversion`
  directly — don't assume. (During bootstrap the API goes down for the pivot
  reboot; that's expected, not a hang — confirm with `install-to-disk` status.)
- **Match the poll interval to the thing.** Boot: ~10–20 s. Operator rollout /
  Kata install: ~30–45 s. Provisioning: ~20 s.
- **Push the 185 MB `oc` once** (Trap #11); after that every `oc` check is instant.
- The node's host key changes on reinstall/pivot/MCO-reboot — `ssh-keygen -R <ip>`
  and `StrictHostKeyChecking=accept-new`, then checks keep working.

---

## 4. Traps & fixes — the full catalogue

Every one of these cost real time. They are the reason this document exists.

| # | Trap | Symptom | Fix |
| :-- | :-- | :-- | :-- |
| 1 | **Client MTU blackhole** | SSH to Scaleway hangs / "banner exchange timeout" while `ping` is perfect. Large packets dropped. Came and went mid-session. | `sudo ifconfig <default-if> mtu 1400` on the workstation (revert with `1500`). Fixed SSH from 0/10 to 10/10 instantly. **This blocked everything for ~30 min.** |
| 2 | **Flaky individual box** | One box had SSH timeouts in *both* rescue and normal boot even with MTU fixed. | Not worth debugging — `delete` it and provision a fresh one (different IP/path). |
| 3 | **Rescue has no podman** | Scaleway rescue = **Ubuntu 20.04**; `apt install podman` → "Unable to locate package". | Use `docker.io` from `universe` (present on 20.04). |
| 4 | **tmpfs can't hold container layers** | `docker run` → `failed to register layer: lsetxattr user.overlay.impure /etc: operation not supported`. Rescue ramdisk is tmpfs. | Back Docker with real disk: `mkfs.ext4 /dev/sdb; mount /mnt/docker; dockerd --data-root=/mnt/docker --storage-driver=overlay2`. |
| 5 | **coreos-installer has no binary** | GitHub releases ship only a `-vendor.tar.gz` (source). | Run the container: `quay.io/coreos/coreos-installer:release`. |
| 6 | **Scaleway Ubuntu uses md-RAID** | `/dev/sda`,`sdb` are RAID members (`md126`,`md127`); coreos-installer needs a clean disk. | Tear down first: `mdadm --stop --scan; mdadm --zero-superblock ...; wipefs -a /dev/sda /dev/sdb; sgdisk --zap-all ...`. |
| 7 | **Metal image ≠ bootstrap-in-place** | `install-to-disk.service` restart-loops (135×) with *"checking for exclusive access to /dev/sda: found busy partitions"*. It also tries to download **Fedora** CoreOS. | Bootstrap-in-place must run from a **live env in RAM**. Use the **kexec-into-RHCOS-live** method (§3.4), which frees `/dev/sda`. **This was the single biggest wrong turn.** |
| 8 | **`status: ready` ≠ installed** | Provisioned box shows `status: ready` but SSH refuses; OS install is separate. | Poll `install.status == "completed"`, not server status. Login user is **`ubuntu`** (sudo), not root. |
| 9 | **Host key churn** | SSH MITM warnings after every reinstall/pivot/MCO-reboot. | `ssh-keygen -R <ip>` + `StrictHostKeyChecking=accept-new`. Benign here (we cause the reinstalls). |
| 10 | **SNO `platform: none` DNS** | `oc` can't resolve `api.sno.spike.lab`; `authentication`/`console`/`ingress` Degraded on `*.apps`. | Add `api`+`api-int` → node IP in the node's `/etc/hosts`. The `*.apps` **wildcard** can't go in `/etc/hosts`; for a *complete* cluster you'd run dnsmasq/CoreDNS with a wildcard, but Kata+SCC don't need it. |
| 11 | **185 MB `oc` push is slow** | `scp oc` times out; `Text file busy` if you exec mid-copy. | Push `oc`+kubeconfig **once** after the node stops rebooting; then all checks are fast. (Reboots wipe `/home/core` transient state during install — re-push after the MCO reboot.) |
| 12 | **Kata guest kernel == node kernel** | `uname -r` inside the kata pod matches the node → looks like a runc fallback. | **Not** a fallback: Red Hat builds the Kata guest kernel from the same RHEL 5.14 base. Assert the VM via **`DMI_PRODUCT=KVM`**, virtio devices, and CPU/mem far below the node — never the kernel string. |
| 13 | **SCC test hits RBAC first** | Privileged pod as a bare SA → "cannot get resource pods" — that's **RBAC**, not SCC. | Grant the SA `edit` (RBAC to create pods) so the **only** thing that can block it is SCC; use `oc create` (not `apply`, which does a GET). |
| 14 | **Managed OpenShift dead-ends** | Chased "cheap managed one-node OpenShift with Kata". | Doesn't exist: free Sandbox = no cluster-admin; ROSA/ARO Kata = `*.metal` ~$5/hr; MicroShift-on-CS9 community repo dead (4.8/2022). Self-host SNO. |
| 15 | **No console by default** | Elastic Metal has no KVM-over-IP on this tier → all installs are "blind". | `scw baremetal server list-events` gives a power/install timeline. **`Serial Console`/`Remote Access` are purchasable options** (`scw baremetal bmc start`) — enable one as the fallback when a blind boot goes dark. `get-metrics` is "Not implemented". |

---

## 5. Final setup — versions & the config that worked

- **Substrate:** Scaleway `EM-B112X-SSD`, fr-par-1, €0.263/hr, BIOS, 2× SSD, `/dev/kvm` present.
- **OCP:** 4.18.49 (`stable-4.18`). **RHCOS:** 418.94.202602022246-0.
- **Install method:** `single-node-ignition-config` (bootstrap-in-place) delivered via **kexec into RHCOS-live-in-RAM** from an Ubuntu rescue / the stuck node.
- **Cluster:** SNO, `platform: none`, `baseDomain: spike.lab`, name `sno`, machineNetwork = the box's public /24; `api`/`api-int` in node `/etc/hosts`; `*.apps` wildcard intentionally skipped (32/34 operators, enough for Kata+SCC).
- **Kata:** OpenShift sandboxed-containers operator **v1.12.1**, channel `stable`, `KataConfig` name `cluster-kataconfig`, RuntimeClass **`kata`**. Guest = real KVM VM (QEMU/`kata-monitor` on node), 1 vCPU / ~1.9 GB, RHEL-5.14-based guest kernel.
- **SCC:** default `restricted-v2` rejects privileged pods; 15 SCCs total.
- **Cost/time:** ~**€0.6** total; ~**2 h** wall-clock (≈45 min of it was the metal-image wrong turn + MTU debugging).

Config files and the exact scripts live next to this doc: `manifests/` (operator,
KataConfig, verify/priv/compliant pods) and `scripts/` (provision, RHCOS-write,
kexec, verify). Secrets and generated auth are gitignored.

---

## 6. TODO to turn this into `infra/` automation

This runbook is manual/agent-followable. To make it one-command (`infra/up.sh --openshift`):

1. A `"kind": "baremetal"` row in `lessons.json` for EM-B112X — the
   `lesson-box` module already builds Elastic Metal and waits on the install, so
   this is a table entry rather than a new script. Capture CIDR/disks after apply.
2. `openshift-sno/install.sh` — generate ignition from a template + the real CIDR; boot rescue; docker-on-sdb; kexec-into-live; poll for API; add `/etc/hosts`; push `oc`. (Earlier drafts of this note called it `substrates/90-openshift-sno.sh`; no such substrate was ever written, and it could not be one — the install replaces the box's OS mid-flight, so there is no `agent` user, no repo checkout and no `uv` left for `up.sh`'s substrate model to use.)
3. Decide the `*.apps` DNS story (on-node dnsmasq wildcard) if the web console is ever wanted.
4. Idempotency + a `--teardown` that `scw baremetal server delete`s and reverts the client MTU.
5. Assert-from-inside checks baked into `check.sh` (DMI=KVM for Kata; SCC reject for admission).

---

## 7. Third run — 2026-08-10: the install path is now scripted and it worked

**Status: cluster up, Kata + SCC both re-proven.** The 2026-08-05 failure (no cluster) is
fixed and the fix is verified on hardware. The whole path is now one command,
[`install.sh`](install.sh), replacing §3's manual sequence.

```bash
./install.sh --preflight     # free; catches everything that can fail for €0
./install.sh                 # preflight -> provision -> facts -> ignition -> kexec -> cluster
./install.sh --from api      # resume after a hiccup (idempotent; skips the pivot wait)
../down.sh openshift-sno     # DESTROY. Nothing does this for you.
```

**Watch it from a second terminal.** Two hours with no answer to "which stage is it in" is how a
stalled step gets mistaken for a slow one — §8 below cost 37 minutes to exactly that. Every run,
including one typed by hand, writes its stage stream to `../.state/openshift-sno/`, so:

```bash
python3 ../ctl.py status openshift-sno   # stages done, the one running, elapsed vs measured
../tui/sbx-tui openshift-sno             # the same thing, live, with the log beside it
```

The stage ids below are `../stages.json`'s, which is also where `install.sh` reads them from — so
`--from <id>` takes any of them, and after an interrupted run `ctl.py` names the one to resume at
rather than leaving you to work it out (`next: up --from api`).

### Timeline of the working run

| Time (UTC) | Event |
| :-- | :-- |
| 08:43:41 | `billing_start` |
| 08:54:30 | `install_done` (Ubuntu) — 11 min |
| 08:59:22 | ssh answers — 5 min after install_done, box reboots in between |
| 09:01 | ignition generated + wrapped, kexec into RHCOS live |
| 09:02:06 | **wipe unit ran**, both disks cleared, `status=0/SUCCESS` |
| 09:08:58 | `.bootkube.done` — bootkube finished in ~7 min |
| 09:23 | pivot reboot; the real cluster starts answering |
| 09:46 | **node registers** (after the `/etc/hosts` fix below) |
| 10:04 | 32/34 operators Available |
| 10:18 | sandboxed-containers operator `v1.12.1 Succeeded` (~40 s) |
| 10:37:28 | `runtimeclass=kata ready=1/1` |

≈ 1 h 54 m and ~€0.50, including two stalls that are now fixed in the script.

### Where the hour in `api` goes

That one stage is 62 of the 114 minutes, so it reports the three phases it can observe — the
boundaries below are state changes the wait loop already reads, and they are what the panel nests
under `api`:

| Substage | From the timeline | What is happening |
| :-- | --: | :-- |
| `bootkube` | 09:02 → 09:09, **7 min** | a *throwaway* control plane runs from RAM: etcd, kube-apiserver, the initial cluster state |
| `install-to-disk` | 09:09 → 09:46, **37 min** | the permanent system is written to the WWN-pinned disk, the box pivot-reboots into it, the kubelet registers the node |
| `operators` | 09:46 → 10:04, **18 min** | the trimmed operator set reconciles, all of it on one node |

The structural reason it is slow is that **SNO serialises what a normal install parallelises**: a
multi-node install uses a separate bootstrap *machine*, and bootstrap-in-place folds that into the
same box — two system bring-ups back to back, then every operator that would normally spread over
three control-plane nodes reconciling on this one.

The middle figure is inflated: that run hit the api-int deadlock of §8, which `node_dns` now
repairs, so expect roughly a third of it once a clean run recalibrates the number.

### The two fixes that made it work

**1. Pin `installationDisk` by WWN.** The device-name swap from §5 was reproduced live —
under Ubuntu the target was `sda`, under RHCOS-live the same physical disk is `sdb`. The
result: root landed on `/dev/sdb4`, WWN `0x5001b448b798588b`, exactly the disk pinned, and
the firmware booted it. A `sbx-wipe-disks.service` injected into the ignition
(`Before=install-to-disk.service`) cleared both disks from RAM first, so nothing else on
the machine was bootable — which is what actually went wrong in 2026-08-05.

**2. The node needs `/etc/hosts` even when the client does not.** §8's `tls-server-name`
trick removes the need for a hosts entry *for `oc`*, and it is tempting to conclude the
step is obsolete. It is not: the **kubelet** resolves `api-int.sno.spike.lab` to register
the node, and `platform: none` provides no DNS.

```text
Unable to register node with API server:
  Post "https://api-int.sno.spike.lab:6443/api/v1/nodes": ... no such host
```

The symptom is a cluster that *looks* alive — API answering, `clusterversion` present —
while `oc get nodes` is empty and the rollout sits at the same percentage. It sat at
**541/906 for 37 minutes**. One line into the node's `/etc/hosts` plus a kubelet restart,
and the node registered in 45 s. It **survives the KataConfig MachineConfig reboot**
(verified), so no MachineConfig is needed.

### Trap #12, demonstrated rather than described

The Kata guest kernel is **byte-identical** to the node's:

```text
in the sandbox   KERNEL=5.14.0-427.138.1.el9_4.x86_64   DMI_PRODUCT=KVM  DMI_VENDOR=Red Hat
                 NPROC=1   VIRTIO_DEVS=6   MEM_TOTAL_KB=1942580
the node         KERNEL=5.14.0-427.138.1.el9_4.x86_64   24 cpu   198 GB
```

A "different kernel ⇒ it is a VM" test — which is exactly what chapter 3's lesson 8 uses on
k3s — returns **no VM** here. It is a false negative on the rung that isolates most
thoroughly. Assert by DMI, virtio and the CPU/memory gap.

Worth noting the mirror image: on k3s (chapter 3) the Kata guest exposes **no DMI at all**
while its kernel *does* differ. Neither witness works on both clusters, which is why
lesson 8's assertion takes either one.

### SCC admission, re-proven

```text
A) privileged pod as a restricted SA
   -> Forbidden: unable to validate against any security context constraint
      [all 15 SCCs listed, each with why it refused]
B) compliant pod, same SA
   -> created, scc=restricted-v2
```

Grant the SA `edit` first (Trap #13) or RBAC refuses before SCC ever runs.

### Accept 32/34 — and encode it

`clusterversion` never reports `Available=True` on this cluster and **never will**:
`console` cannot resolve `…apps.sno.spike.lab` without the wildcard DNS this setup
deliberately skips, and `authentication` follows it down. Waiting for `Available=True`
times out after an hour on a perfectly good cluster. `install.sh` waits for a Ready node
plus every operator *except a named set* — "any two missing" would pass a cluster whose
etcd was the broken one.

### Trap #2 revisited — try a reboot before you delete the box (2026-08-10)

Trap #2 says a flaky box is "not worth debugging — delete it and provision a fresh one".
That is more expensive than it needs to be. On the second build of this cluster the box
reported `install_done` and then **never came back on the network at all**:

```text
install_done - Ubuntu 24.04 LTS (Noble Numbat)   13:57:08Z
...30 minutes later
ping  -> 100% packet loss        port 22 -> closed
```

Note the discriminator: **100% packet loss is NOT Trap #1.** The MTU blackhole shows ping
working perfectly while SSH hangs; nothing answering at all is a different fault.

`scw baremetal server reboot <id>` recovered it in ~6 minutes:

```text
14:28  reboot requested (status=stopping)
14:31  PING OK        (then quiet again — the box boots, drops, and comes back)
14:34  PORT 22 OPEN
```

Reboot first, delete second. A reinstall costs ~11 min of OS install plus ~5 of reboot and
starts the billing clock on a new machine; a reboot costs ~6 min and keeps the one you have.
Only if the reboot fails is the box genuinely a dud.

Also worth knowing: on this box **both disks were the same size** (953.9G,
`0x5001b448b798bac1` and `0x5001b448b798a1ff`). The previous build had a 953.9G/931.5G
pair, which made the RHCOS device-name swap obvious at a glance. Here it would not have
been. Do not lean on size to identify the disk — that is exactly why it is pinned by WWN.

---

## 8. `--from api` — three bugs that all looked like a broken cluster

The 2026-08-10 build was interrupted mid-bootstrap and resumed with `./install.sh --from api`.
That resume path had never actually been exercised, and it failed three times in a row **on a
perfectly healthy cluster**. All three are fixed; they are recorded because each one presents
as an infrastructure fault and is not one.

### 8.1 `set -e` + `pipefail` kill the wait loops on their own success condition

Two loops died silently with exit 1 and no message:

```bash
s="$(node_ssh '...')"                                        # ssh is DOWN during the pivot
node=$(oc get nodes --no-headers 2>/dev/null | awk … | head -1)   # NO nodes yet, by definition
```

`ssh` returns 255 when the box is rebooting, and `oc get nodes` exits non-zero when the cluster
is empty. `set -o pipefail` promotes that over `head`'s 0, and **a failed command substitution
in a plain assignment trips `set -e`**. So each loop aborted on precisely the state it existed
to wait for.

The tell is the shape of the failure: the step header prints, then nothing — not even the
loop's own first status line — and `$?` is 1 with an empty stderr. `bash -x` is unnecessary;
if a wait loop dies before its first heartbeat, suspect the assignment, not the cluster.

Fixed by `|| true` on every probe substitution. Note an `if` condition is *not* protection —
errexit is suspended for the condition itself, but `s=$(...)` on the next line is a bare
assignment again.

### 8.2 `/run/ostree-booted` is not "bootstrap finished"

Added as a cheap short-circuit so `--from api` would not wait for a marker that had already
been and gone. It is wrong: the file exists from the moment the machine boots off the disk,
which is the **start** of the bootstrap-in-place phase. Measured — it declared "bootstrap is
done" over a cluster four minutes into bootstrap, and the operator loop then hunted for
operators that could not exist yet.

### 8.3 `.bootkube.done` exists, then stops existing

The marker's real lifecycle, both halves measured on the same box:

| Time (UTC) | State | `/opt/openshift/.bootkube.done` |
| :-- | :-- | :-- |
| 12:44 | bootstrap control plane running from disk | **present** |
| 14:52 | after the pivot reboot | **gone** — `/opt/openshift` is cleaned out |

So waiting only for the marker hangs 45 minutes on an already-pivoted cluster, and waiting
only for its absence never starts. `wait_api` now breaks on **either** the marker **or** a
registered node, which between them cover the whole timeline.

### 8.4 What a healthy post-pivot boot actually looks like

Worth knowing so it is not mistaken for a loop. After the pivot, `bootkube.service` goes
`activating` **again** — it is running `bootstrap-in-place-post-reboot.sh`, which releases the
bootstrap leases, restores the CVO overrides, and then sits in:

```text
Waiting for node to report ready status
Approving csrs ...
```

That is the node registering, not a stall. And the machine reboots **twice**, not once — the
pivot, then the MCO applying the final rendered MachineConfig — so any message promising
"expected once" is wrong.

### 8.5 Trap #10 comes back, and `node_dns()` running once is not enough

The most expensive fault of the day, and it presents as a stalled install with no error at
all. The convergence loop sat at `api-nodes=0` while the cluster looked fine from outside —
API answering, node booted, kubelet active. The kubelet's journal had the answer:

```text
Failed to contact API server when waiting for CSINode publishing:
  dial tcp: lookup api-int.sno.spike.lab on 51.159.69.156:53: no such host
```

**`/etc/hosts` does not survive the reboots.** `node_dns()` had written the `api`/`api-int`
entries at 16:43 and they were gone by 17:03 — the pivot and the MCO's final MachineConfig
apply both replace the file. Without the name the kubelet cannot reach `api-int`, so it
never submits a CSR, so the node never registers, so the wait can never end. It is a
deadlock, and both halves look healthy in isolation.

The causal chain, measured:

```text
17:03:37  entry restored in /etc/hosts, kubelet restarted
17:03:41  csr-2bpvk  Pending          <- four seconds later
17:03:58  node registered (NotReady)
17:05:42  node Ready
```

So `node_dns()` must be re-applied **after the last reboot**, not once before them. Calling
it once between the bootstrap wait and the operator wait — which is where it sits — is only
correct if no further reboot happens, and one always does. Until it is moved inside the
convergence loop, a resumed install needs this run alongside it:

```bash
while true; do
  ssh core@<ip> 'grep -q api-int /etc/hosts || { sudo sh -c "echo \"<ip> api.sno.spike.lab api-int.sno.spike.lab\" >> /etc/hosts"; sudo systemctl restart kubelet; }'
  sleep 30
done
```

The discriminator that saves the time: if the node is up and the API answers but
`oc get nodes` is empty **and `oc get csr` is empty too**, it is never a slow rollout. No CSR
means the kubelet is not talking to the API at all, and DNS is the first thing to check.
