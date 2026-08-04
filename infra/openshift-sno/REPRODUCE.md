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

1. `provision/openshift-box.sh` — create EM-B112X, wait `install.status`, capture CIDR/disks.
2. `substrates/90-openshift-sno.sh` — generate ignition from a template + the real CIDR; boot rescue; docker-on-sdb; kexec-into-live; poll for API; add `/etc/hosts`; push `oc`.
3. Decide the `*.apps` DNS story (on-node dnsmasq wildcard) if the web console is ever wanted.
4. Idempotency + a `--teardown` that `scw baremetal server delete`s and reverts the client MTU.
5. Assert-from-inside checks baked into `check.sh` (DMI=KVM for Kata; SCC reject for admission).
