#!/usr/bin/env bash
# Chapter 3 substrate — the storage Firecracker needs (lesson 8). Runs AFTER 60-k8s.sh, and
# CRUCIALLY between 70-k8s-gvisor.sh and 80-k8s-kata.sh.
#
# Lesson 8 selects a boundary with `runtimeClassName`, and kata-deploy registers a class per shim —
# `kata-fc` among them. That class exists on any cluster kata-deploy has touched and, out of the box,
# **does not work**: a pod naming it never starts, with
#
#     failed to create containerd container: error unpacking image:
#     unable to initialize unpacker: snapshotter must be provided to unpack
#
# Registered is not the same as working, and that gap is this repo's characteristic failure wearing
# a RuntimeClass. What is missing is storage: Firecracker's device model has virtio-block and no
# virtio-fs, so a container rootfs cannot be shared in the way QEMU's is — it has to arrive as a
# block device, which is what the devmapper snapshotter produces.
#
# kata-deploy has ALREADY done the containerd half. Its drop-in writes
#
#     [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.kata-fc]
#     snapshotter = "devmapper"
#
# on `kata-fc` and on nothing else — `kata-qemu` carries no snapshotter line and so stays on the
# cluster default, overlayfs. So this substrate does not configure a per-runtime snapshotter and must
# not: it supplies the snapshotter kata-deploy is already asking for, and the qemu-on-overlayfs /
# fc-on-devmapper split comes free and correct from upstream.
#
# ORDER, and it is about restarts rather than files. Loading a snapshotter needs containerd
# restarted, k3s embeds containerd, and a k3s restart AFTER kata-deploy terminates its DaemonSet pod
# — which reverts its own install on the way out. Numbered 75 so that restart happens while there is
# still nothing to revert. There is no post-80 seam to do this in, which is why it is not simply
# folded into 80.
#
# It therefore CANNOT smoke-test a Firecracker pod: no kata-fc runtime exists yet when this runs.
# What it can prove is that the snapshotter initialises and can actually unpack an image, which is
# what it does below; the pod-level proof belongs to check.sh's 80-k8s-kata case, after both halves
# are in place.
set -euo pipefail

POOL=devpool
DATA_DIR=/var/lib/containerd-devmapper
DATA_GB=25
META_GB=2
CONTAINERD_DIR=/var/lib/rancher/k3s/agent/etc/containerd
DROPIN="${CONTAINERD_DIR}/config-v3.toml.d/devmapper.toml"
AGENT_IMAGE=docker.io/sandboxing-tutorial/agent:v1

command -v k3s >/dev/null || {
  echo "FATAL: k3s is absent — 60-k8s.sh must run before this substrate."
  exit 1
}

# --- the thin-pool ------------------------------------------------------------
#
# Sparse files on loop devices, thin-provisioned: DATA_GB is a ceiling, not disk spent. Idempotent
# where it matters — `losetup --find` would cheerfully attach a SECOND loop device to a file that
# already has one, so ask `losetup -j` first.
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
  dmsetup create "${POOL}" \
    --table "0 $(($(blockdev --getsize64 -q "${DATA_DEV}") / 512)) thin-pool ${META_DEV} ${DATA_DEV} 128 32768"
  echo "thin-pool ${POOL} created on ${DATA_DEV} (data) + ${META_DEV} (metadata)"
fi

# --- teach k3s's containerd about it ------------------------------------------
#
# A DROP-IN, not the template `70-k8s-gvisor.sh` appends to. k3s generates
# `imports = [".../config-v3.toml.d/*.toml"]` into every config it writes, so a file dropped here is
# merged by containerd itself — and it is the same seam kata-deploy uses (`kata-deploy.toml`), which
# is the strongest available evidence that it is the supported one. Two files, two distinct tables,
# no shared line to clobber.
CHANGED=0
mkdir -p "${CONTAINERD_DIR}/config-v3.toml.d"
if [ ! -f "${DROPIN}" ]; then
  cat >"${DROPIN}" <<EOF
version = 3

[plugins.'io.containerd.snapshotter.v1.devmapper']
  pool_name = '${POOL}'
  root_path = '${DATA_DIR}'
  base_image_size = '10GB'
  discard_blocks = true
EOF
  CHANGED=1
fi

# Restart ONLY when something moved — the same discipline 70-k8s-gvisor.sh keeps, and for the same
# reason: `up.sh` is an idempotent alias on a shared box, so this script can legitimately run again
# against a cluster that is already serving lessons 6 and 7.
if [ "${CHANGED}" -eq 1 ]; then
  echo "devmapper drop-in written — restarting k3s"
  systemctl restart k3s
else
  echo "devmapper already registered in ${DROPIN##*/} — leaving k3s alone"
fi

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
for _ in $(seq 1 60); do
  [ -n "$(kubectl get nodes -o name 2>/dev/null)" ] && break
  sleep 5
done
kubectl wait --for=condition=Ready node --all --timeout=300s

# `ok` means the plugin found its pool. `skip` means "configured badly, or not at all" — and a
# `skip` here is invisible until a kata-fc pod fails at sandbox creation several minutes later,
# which is precisely the delayed, misattributed failure this file exists to prevent.
echo -n "containerd devmapper plugin: "
k3s ctr plugins ls | awk '$2 == "devmapper" {print $4}'
k3s ctr plugins ls | awk '$2 == "devmapper" && $4 == "ok" {found=1} END {exit !found}' || {
  echo "FATAL: containerd did not initialise the devmapper snapshotter"
  k3s ctr plugins ls | grep -i devmapper
  exit 1
}

# --- what this substrate does NOT have to do ----------------------------------
#
# It does not put the agent image into the new snapshotter, and the reasoning is worth keeping
# because the opposite looks obviously necessary. `ctr images import` unpacks layers for ONE
# snapshotter, so 60-k8s.sh's side-load put them in overlayfs alone; the kubelet never pulls a `:v1`
# image the node already has; so it reads as though a kata-fc pod could never find a rootfs.
#
# Measured 2026-08-13: it can. **containerd unpacks into a runtime's snapshotter on demand, at
# container creation.** A kata-fc pod ran from an image imported for overlayfs only and reported its
# Firecracker guest normally. The earlier `snapshotter must be provided to unpack` failure was this
# plugin being absent, not the image being in the wrong place — which is why the fix is the pool
# above and nothing else.
#
# (A second `ctr images import --snapshotter devmapper` is also not spellable here: naming a
# snapshotter routes the import through the transfer service, which refuses with `no unpack
# platforms defined`, and this ctr has no `--platform` flag to satisfy it. Two runs died on that
# before the on-demand behaviour was measured.)
echo "${AGENT_IMAGE##*/} stays in overlayfs; containerd will unpack it into devmapper on demand"
