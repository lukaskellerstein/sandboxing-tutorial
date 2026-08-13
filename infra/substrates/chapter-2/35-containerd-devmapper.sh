#!/usr/bin/env bash
# Chapter 2 substrate — a SECOND hypervisor under Kata (lesson 4). Runs AFTER 30-containerd-kata.sh.
#
# Kata is the runtime; the hypervisor is a component *underneath* it. 30-containerd-kata.sh installed
# the runtime and got QEMU by default. This adds Firecracker beside it, so lesson 4 can run the same
# workload on both and compare capabilities, speed and weight. It is NOT a new rung on the ladder:
# both boot the same guest kernel through KVM, and the security matrix is expected to be identical.
#
# Two things have to be true before a Firecracker sandbox can start, and each is a real design fact
# rather than a setting:
#
# 1. A BLOCK-DEVICE ROOTFS. Firecracker's device model has virtio-block and no virtio-fs, so the
#    container rootfs cannot be shared in from the host the way QEMU's is — it has to be handed over
#    as a block device. That is what the devmapper snapshotter produces, and it is why this substrate
#    exists at all. Without it a Firecracker container dies with
#    `failed to mount /run/kata-containers/shared/containers/<id>/rootfs ... ENOENT`, which reads like
#    a Kata bug and is a storage prerequisite. Read from inside, the same fact shows up as the
#    rootfs filesystem: `virtiofs` under QEMU, `ext4` under Firecracker.
#
# 2. THE SHIM HAS TO BE TOLD WHICH CONFIG TO LOAD. One shim binary serves every hypervisor; which
#    one it boots is decided by the configuration file it reads. On Kubernetes kata-deploy passes
#    that path as a containerd runtime option (`ConfigPath`) — a CRI-only mechanism, and nerdctl is
#    not a CRI client. The other channel is `KATA_CONF_FILE`, and as of Kata 4.0.0 it is
#    ALLOW-LISTED: the shim resolves symlinks and refuses anything that is not one of its two
#    shipped config paths, with `only shipped Kata configuration files are accepted`. So a plain
#    `containerd-shim-kata-fc-v2` symlink does not work — measured: it silently booted QEMU, because
#    the shim ignores its own binary name and fell back to the default config.
#
# The layout below satisfies that allow-list without lying about anything:
#
#   /etc/kata-containers/configuration.toml            -> configuration-qemu.toml   (slot 1)
#   /opt/kata/.../configuration.toml                   -> configuration-fc.toml     (slot 2)
#
# Slot 1 is searched FIRST, so a shim invoked with no KATA_CONF_FILE at all still gets QEMU — which
# keeps `io.containerd.kata.v2` exactly what lesson 4 already measured, and makes the failure mode of
# this whole arrangement "you get the hypervisor you had before" rather than a silent swap. Slot 2
# is what makes the Firecracker config a *shipped* path, so the wrapper below is accepted.
set -euo pipefail

POOL=devpool
DATA_DIR=/var/lib/containerd-devmapper
DATA_GB=20
META_GB=2
KDIR=/opt/kata/share/defaults/kata-containers
CONTAINERD_CONF=/etc/containerd/config.toml

[ -x /opt/kata/bin/containerd-shim-kata-v2 ] || {
  echo "FATAL: Kata is absent — 30-containerd-kata.sh must run before this substrate."
  exit 1
}
[ -x /opt/kata/bin/firecracker ] || {
  echo "FATAL: /opt/kata/bin/firecracker is absent — this kata-static build ships no Firecracker."
  exit 1
}
echo "firecracker: $(/opt/kata/bin/firecracker --version 2>&1 | head -1)"

# --- the thin-pool ------------------------------------------------------------
#
# Sparse files on loop devices: the pool is thin-provisioned, so `DATA_GB` is a ceiling rather than
# disk that gets spent. Idempotent in the way that actually matters — `losetup --find` would happily
# attach a SECOND loop device to a file that already has one, so ask `losetup -j` first. (A loop
# device does not survive a reboot; neither does this box, which exists for minutes.)
loop_for() {
  local file="$1" dev
  dev=$(losetup -j "${file}" | head -1 | cut -d: -f1)
  [ -n "${dev}" ] || dev=$(losetup --find --show "${file}")
  echo "${dev}"
}

if dmsetup info "${POOL}" >/dev/null 2>&1; then
  echo "thin-pool ${POOL} already exists"
else
  mkdir -p "${DATA_DIR}"
  [ -f "${DATA_DIR}/data" ] || truncate -s "${DATA_GB}G" "${DATA_DIR}/data"
  [ -f "${DATA_DIR}/meta" ] || truncate -s "${META_GB}G" "${DATA_DIR}/meta"
  DATA_DEV=$(loop_for "${DATA_DIR}/data")
  META_DEV=$(loop_for "${DATA_DIR}/meta")
  # 128 sectors (64 KB) of allocation granularity, and a low-water mark in blocks — the values from
  # the upstream how-to. The length is the DATA device in 512-byte sectors.
  dmsetup create "${POOL}" \
    --table "0 $(($(blockdev --getsize64 -q "${DATA_DEV}") / 512)) thin-pool ${META_DEV} ${DATA_DEV} 128 32768"
  echo "thin-pool ${POOL} created on ${DATA_DEV} (data) + ${META_DEV} (metadata)"
fi

# --- teach containerd about the snapshotter -----------------------------------
#
# 30-containerd-kata.sh leaves containerd on its compiled-in defaults with no config file at all, so
# an unspecified plugin here still gets its default: this file adds the devmapper snapshotter and
# changes NOTHING else. overlayfs stays the default snapshotter, which is what keeps QEMU (and every
# ordinary container on this box) exactly where lesson 4 already measured them.
#
# CREATE-IF-ABSENT, APPEND-IF-MISSING rather than `cat >`, matching 70-k8s-gvisor.sh: a truncating
# write is how a substrate erases something another one put here.
CHANGED=0
mkdir -p "$(dirname "${CONTAINERD_CONF}")"
if [ ! -f "${CONTAINERD_CONF}" ]; then
  printf 'version = 3\n' >"${CONTAINERD_CONF}"
  CHANGED=1
fi
if ! grep -q 'snapshotter.v1.devmapper' "${CONTAINERD_CONF}"; then
  cat >>"${CONTAINERD_CONF}" <<EOF

[plugins.'io.containerd.snapshotter.v1.devmapper']
  pool_name = '${POOL}'
  root_path = '${DATA_DIR}'
  base_image_size = '10GB'
  discard_blocks = true
EOF
  CHANGED=1
fi

# --- register the Firecracker config, and the shim that asks for it -----------
mkdir -p /etc/kata-containers
ln -sf "${KDIR}/configuration-qemu.toml" /etc/kata-containers/configuration.toml
ln -sf "${KDIR}/configuration-fc.toml" "${KDIR}/configuration.toml"

cat >/usr/local/bin/containerd-shim-kata-fc-v2 <<EOF
#!/usr/bin/env bash
# containerd resolves io.containerd.kata-fc.v2 to this name. One shim binary serves every
# hypervisor; the config file is what picks one. See 35-containerd-devmapper.sh.
KATA_CONF_FILE=${KDIR}/configuration-fc.toml exec /opt/kata/bin/containerd-shim-kata-v2 "\$@"
EOF
chmod 0755 /usr/local/bin/containerd-shim-kata-fc-v2

if [ "${CHANGED}" -eq 1 ]; then
  systemctl restart containerd
  sleep 3
else
  echo "devmapper already registered in ${CONTAINERD_CONF} — leaving containerd alone"
fi

# The plugin reports `ok` only once it has found its pool. `skip` means "configured badly or not at
# all", and containerd says so here rather than at the first container, several confusing minutes on.
echo -n "containerd devmapper plugin: "
ctr plugins ls | awk '$2 == "devmapper" {print $4}'
ctr plugins ls | awk '$2 == "devmapper" && $4 == "ok" {found=1} END {exit !found}' || {
  echo "FATAL: containerd did not initialise the devmapper snapshotter"
  ctr plugins ls | grep -i devmapper
  exit 1
}

# --- smoke: a DIFFERENT VMM, proven from inside the guest ---------------------
#
# `pci=off` is on Firecracker's kernel command line and it has no PCI bus at all, so an empty
# /sys/bus/pci/devices is the reading that separates the two hypervisors from inside. The runtime
# name proves nothing: this substrate's first draft ran QEMU under the Firecracker runtime name and
# printed a perfectly convincing guest kernel while doing it.
# shellcheck disable=SC2016  # must expand inside the guest, not here
probe='echo "kernel=$(uname -r) pci=$(ls /sys/bus/pci/devices 2>/dev/null | wc -l) rootfs=$(awk "\$2 == \"/\" {print \$3}" /proc/mounts)"'
echo "node           : kernel=$(uname -r)"
echo -n "kata-qemu      : "
nerdctl run --rm --net none --runtime io.containerd.kata.v2 \
  --entrypoint sh docker.io/library/alpine:3.22 -c "${probe}"
echo -n "kata-fc        : "
nerdctl run --rm --net none --snapshotter devmapper --runtime io.containerd.kata-fc.v2 \
  --entrypoint sh docker.io/library/alpine:3.22 -c "${probe}"
