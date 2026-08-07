#!/usr/bin/env bash
# Runs on the INSTALLED Ubuntu 24.04 (user `ubuntu`, sudo). kexecs into
# RHCOS-live-in-RAM so bootstrap-in-place can write to a free /dev/sda.
#
# Why not rescue (what REPRODUCE.md §3.4 method A does): Scaleway rescue did
# not accept the project's IAM SSH key, and debugging that costs paid time.
# The installed OS accepts it (install.ssh_key_ids), and kexec frees the disks
# either way because the live system runs entirely in RAM.
#
# The catch this path introduces: Ubuntu's root is on md-RAID across BOTH
# disks, so they cannot be wiped while running. Two mitigations:
#   1. rd.md=0 on the live kernel cmdline -> the live env never assembles md,
#      so /dev/sda has no holders and install-to-disk can claim it (Trap #7).
#   2. detach + wipe /dev/sdb first (it can be removed from a RAID1 while the
#      array keeps running on /dev/sda), so no stale superblock survives to
#      auto-assemble a degraded array on the installed system.
set -uo pipefail

B=https://rhcos.mirror.openshift.com/art/storage/prod/streams/4.18-9.4/builds/418.94.202602022246-0/x86_64
K="$B/rhcos-418.94.202602022246-0-live-kernel-x86_64"
I="$B/rhcos-418.94.202602022246-0-live-initramfs.x86_64.img"
R="$B/rhcos-418.94.202602022246-0-live-rootfs.x86_64.img"

cd /var/tmp || exit 1

echo "=== 0. sanity: ign.img present (scp'd from the workstation)"
[ -s ign.img ] || {
  echo "ign.img missing/empty"
  exit 1
}
echo "ign.img=$(stat -c%s ign.img) bytes"

echo "=== 0b. node facts"
ip -4 -o addr show scope global | awk '{print "ADDR", $2, $4}'
[ -d /sys/firmware/efi ] && echo "FIRMWARE UEFI" || echo "FIRMWARE BIOS"
echo "KVM=$(ls /dev/kvm 2>/dev/null || echo absent) VMX=$(grep -c vmx /proc/cpuinfo) CPU=$(nproc) MEM=$(awk '/MemTotal/{print int($2/1048576)"GB"}' /proc/meminfo)"
cat /proc/mdstat

echo "=== 0c. tools"
command -v kexec >/dev/null || {
  sudo DEBIAN_FRONTEND=noninteractive apt-get -qq update
  sudo DEBIAN_FRONTEND=noninteractive apt-get -qq install -y kexec-tools
}
command -v kexec >/dev/null || {
  echo "kexec missing"
  exit 1
}

echo "=== 1. detach /dev/sdb from the RAID1 arrays and wipe it"
sudo swapoff -a 2>/dev/null || true
for pair in "md0:/dev/sdb2" "md1:/dev/sdb3"; do
  arr="${pair%%:*}"
  dev="${pair##*:}"
  sudo mdadm --manage "/dev/$arr" --fail "$dev" 2>/dev/null || true
  sudo mdadm --manage "/dev/$arr" --remove "$dev" 2>/dev/null || true
done
sudo mdadm --zero-superblock /dev/sdb1 /dev/sdb2 /dev/sdb3 2>/dev/null || true
sudo wipefs -a /dev/sdb 2>/dev/null || true
sudo sgdisk --zap-all /dev/sdb 2>/dev/null || true
cat /proc/mdstat

echo "=== 2. download RHCOS live kernel + initramfs"
curl -fsSL "$K" -o kernel || exit 1
curl -fsSL "$I" -o initramfs.img || exit 1
echo "kernel=$(stat -c%s kernel) initramfs=$(stat -c%s initramfs.img)"

echo "=== 3. append the ignition cpio to the initramfs"
cat initramfs.img ign.img >boot.img
echo "boot.img=$(stat -c%s boot.img)"

echo "=== 4. kexec load (rd.md=0 keeps the live env off the RAID)"
sudo kexec -l kernel --initrd=boot.img \
  --append="coreos.live.rootfs_url=$R ignition.firstboot ignition.platform.id=metal rd.neednet=1 ip=dhcp rd.md=0 rd.auto=0" || exit 1

echo "=== 5. JUMP (ssh will drop now)"
sudo bash -c 'nohup sh -c "sleep 2; kexec -e" >/dev/null 2>&1 &'
echo "kexec -e scheduled"
