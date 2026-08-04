#!/usr/bin/env bash
# Runs in Scaleway RESCUE mode (Ubuntu 20.04). Prepares the box for a RHCOS
# install: tears down Scaleway's md-RAID and stands up a disk-backed Docker so
# the coreos-installer *container* can run (Traps #3, #4, #6 in REPRODUCE.md).
#
# NOTE: the final `docker run ... coreos-installer install <metal-image>` shown
# at the bottom is the WRONG path — writing the metal image to disk makes
# bootstrap-in-place loop forever on a busy /dev/sda (Trap #7). Use it only to
# prove the container runs; for the real install, kexec into RHCOS-live-in-RAM
# (scripts/node-kexec-live.sh). The RAID + Docker setup above IS reused there
# (Docker is needed to `coreos-installer pxe ignition wrap`).
set -uo pipefail

echo "=== 1. tear down software RAID + wipe both disks"
swapoff -a 2>/dev/null || true
mdadm --stop --scan 2>/dev/null || true
mdadm --zero-superblock /dev/sda* /dev/sdb* 2>/dev/null || true
wipefs -a /dev/sda /dev/sdb 2>/dev/null || true
sgdisk --zap-all /dev/sda 2>/dev/null || true
sgdisk --zap-all /dev/sdb 2>/dev/null || true

echo "=== 2. Docker from focal universe (rescue has no podman), backed by ext4 on sdb"
export DEBIAN_FRONTEND=noninteractive
apt-get -qq update && apt-get -qq install -y docker.io
pkill -9 dockerd 2>/dev/null || true
sleep 2
mkfs.ext4 -F -q /dev/sdb # tmpfs ramdisk can't hold overlay xattrs -> real disk
mkdir -p /mnt/docker && mount /dev/sdb /mnt/docker
nohup dockerd --data-root=/mnt/docker --storage-driver=overlay2 >/tmp/dockerd.log 2>&1 &
for _ in $(seq 1 40); do
  docker info >/dev/null 2>&1 && break
  sleep 2
done
if docker info >/dev/null 2>&1; then
  echo "docker up ($(docker info --format '{{.Driver}}'))"
else
  echo "docker FAILED"
  tail -15 /tmp/dockerd.log
  exit 1
fi

echo "=== ready. Next: scripts/node-kexec-live.sh (kexec into RHCOS live in RAM)."
