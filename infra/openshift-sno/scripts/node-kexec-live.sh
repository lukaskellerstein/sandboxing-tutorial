#!/usr/bin/env bash
# Runs on the STUCK RHCOS node. kexec into RHCOS-live-in-RAM so install-to-disk
# can write the permanent system to /dev/sda (freed by kexec).
set -uo pipefail
K=https://rhcos.mirror.openshift.com/art/storage/prod/streams/4.18-9.4/builds/418.94.202602022246-0/x86_64/rhcos-418.94.202602022246-0-live-kernel-x86_64
I=https://rhcos.mirror.openshift.com/art/storage/prod/streams/4.18-9.4/builds/418.94.202602022246-0/x86_64/rhcos-418.94.202602022246-0-live-initramfs.x86_64.img
R=https://rhcos.mirror.openshift.com/art/storage/prod/streams/4.18-9.4/builds/418.94.202602022246-0/x86_64/rhcos-418.94.202602022246-0-live-rootfs.x86_64.img
cd /var/tmp || exit 1
echo "=== stop the failing install loop"
sudo systemctl stop install-to-disk.service 2>/dev/null || true
echo "=== download live kernel + initramfs"
curl -fsSL "$K" -o kernel
curl -fsSL "$I" -o initramfs.img
echo "kernel=$(stat -c%s kernel) initramfs=$(stat -c%s initramfs.img)"
echo "=== wrap bootstrap ignition into an initramfs cpio (via podman)"
sudo podman run --rm -v /var/tmp:/data:z -w /data quay.io/coreos/coreos-installer:release \
  pxe ignition wrap -i /data/bootstrap.ign -o /data/ign.img
echo "ign.img=$(stat -c%s ign.img)"
echo "=== combine initramfs + ignition"
cat initramfs.img ign.img >boot.img
echo "=== kexec load"
sudo kexec -l kernel --initrd=boot.img \
  --append="coreos.live.rootfs_url=$R ignition.firstboot ignition.platform.id=metal rd.neednet=1 ip=dhcp"
echo "=== JUMP (ssh will drop now)"
sudo bash -c 'nohup kexec -e >/dev/null 2>&1 &'
