#!/usr/bin/env bash
# Chapter 2 audit substrate — make Kata's BTF/AUDITSYSCALL DEBUG kernel selectable per run. Runs
# AFTER chapter-2/30-containerd-kata.sh (which installs kata-static and containerd).
#
# The finding lesson 2.2.3 turns on: under Kata the workload runs in a per-container VM with its OWN
# guest kernel, so the host eBPF sensor (2.2.1's Tetragon) is FULLY blind — it never sees the
# attacks, because their syscalls cross the guest kernel and never touch the host's. Coverage returns
# only by putting a sensor INSIDE the guest. That needs a guest kernel that carries the sensor's
# prerequisites, and the DEFAULT Kata guest kernel does not: it ships without CONFIG_AUDITSYSCALL and
# without BTF, so neither auditd nor a CO-RE eBPF probe can attach inside it.
#
# The pinned kata-static 4.0.0 tarball ALSO ships a debug kernel built with them on
# (`vmlinuz-*-debug`: CONFIG_AUDITSYSCALL=y, CONFIG_DEBUG_INFO_BTF=y, CONFIG_BPF_SYSCALL=y — verified
# by discovery gate G1). This substrate does NOT build a kernel and does NOT add a second runtime
# (Kata 4.0.0 allow-lists KATA_CONF_FILE to its own shipped config files, so a third config is
# refused). It instead ENABLES the `kernel` annotation on the shipped qemu config, so a single run can
# opt into the debug kernel with:
#
#   nerdctl run --runtime io.containerd.kata.v2 \
#     --annotation io.katacontainers.config.hypervisor.kernel=<debug vmlinuz> ...
#
# A run WITHOUT the annotation still boots the default kernel — so `io.containerd.kata.v2` stays
# exactly what lesson 1.2.3 measured, and 2.2.3's Part 1 (host sensor blind) runs on the same default
# guest 1.2.3 did. Only 2.2.3's Part 3 (the in-guest sensor) opts into the debug kernel.
set -euo pipefail

KDIR=/opt/kata/share/defaults/kata-containers
QEMU_CONF="${KDIR}/configuration-qemu.toml"
ANNOTATION_KEY=io.katacontainers.config.hypervisor.kernel

[ -x /opt/kata/bin/containerd-shim-kata-v2 ] || {
  echo "FATAL: Kata is absent — chapter-2/30-containerd-kata.sh must run before this substrate."
  exit 1
}
[ -f "${QEMU_CONF}" ] || {
  echo "FATAL: shipped qemu config not found at ${QEMU_CONF}"
  ls -la "${KDIR}" || true
  exit 1
}

# --- find the debug kernel the tarball shipped ---------------------------------
#
# Globbed, not hardcoded: the exact version (6.18.35-200 today) rides on the kata-static release, so
# resolve it from disk. The debug kernel is the one this whole substrate exists to reach.
DEBUG_KERNEL=$(find "${KDIR%/share/defaults/kata-containers}"/share/kata-containers -maxdepth 1 -name 'vmlinuz-*-debug' 2>/dev/null | head -1 || true)
if [ -z "${DEBUG_KERNEL}" ]; then
  # kata-static may lay the kernels beside the tarball root rather than under share/defaults.
  DEBUG_KERNEL=$(find /opt/kata -maxdepth 4 -name 'vmlinuz-*-debug' 2>/dev/null | head -1 || true)
fi
[ -n "${DEBUG_KERNEL}" ] || {
  echo "FATAL: no vmlinuz-*-debug found under /opt/kata — this kata-static build ships no debug kernel"
  find /opt/kata -maxdepth 4 -name 'vmlinuz*' 2>/dev/null | sed 's/^/  /' || true
  exit 1
}
# Resolve the symlink: the debug image is usually a symlink to a versioned file, and the annotation
# path allow-list matches on the resolved path.
DEBUG_KERNEL=$(readlink -f "${DEBUG_KERNEL}")
echo "debug kernel   : ${DEBUG_KERNEL}"

# --- enable the kernel annotation on the shipped qemu config --------------------
#
# Two gates guard a path annotation in Kata: it must be listed in `enable_annotations`, and — where
# the config carries a `valid_kernel_paths` allow-list — the path must match one of its globs. Add
# both, idempotently. `enable_annotations` is a single array line under [hypervisor.qemu]; splice
# "kernel" into it if absent.
if ! grep -Eq '^\s*enable_annotations\s*=.*"kernel"' "${QEMU_CONF}"; then
  sed -i -E 's/^(\s*enable_annotations\s*=\s*\[)/\1"kernel", /' "${QEMU_CONF}"
  echo "enable_annotations: added \"kernel\""
else
  echo "enable_annotations: \"kernel\" already present"
fi

# valid_kernel_paths: only touch it if the config already declares one — adding an unknown key to a
# strict TOML parser is how a substrate breaks the runtime it is trying to extend. If present, append
# the debug kernel's directory glob so the annotation's path is accepted.
if grep -Eq '^\s*valid_kernel_paths\s*=' "${QEMU_CONF}"; then
  if ! grep -Eq "^\s*valid_kernel_paths\s*=.*$(dirname "${DEBUG_KERNEL}")" "${QEMU_CONF}"; then
    sed -i -E "s#^(\s*valid_kernel_paths\s*=\s*\[)#\1\"$(dirname "${DEBUG_KERNEL}")/*\", #" "${QEMU_CONF}"
    echo "valid_kernel_paths: added $(dirname "${DEBUG_KERNEL}")/*"
  else
    echo "valid_kernel_paths: debug kernel dir already allowed"
  fi
else
  echo "valid_kernel_paths: not declared in config — annotation path gated by enable_annotations only"
fi

# Record the resolved debug-kernel path where the lesson (and check.sh) can read it without re-globbing.
echo "${DEBUG_KERNEL}" >/etc/kata-containers-debug-kernel

# --- smoke: the debug kernel boots and carries the sensor prerequisites --------
#
# Asserted from INSIDE the guest, never from the flag: the whole point is what the guest kernel
# actually carries. A guest booted with the annotation must report the debug kernel string AND expose
# /sys/kernel/btf/vmlinux (BTF) — the default guest exposes neither.
echo "node uname -r  : $(uname -r)"
DBG_UNAME=$(basename "${DEBUG_KERNEL}" | sed 's/^vmlinuz-//')
echo -n "kata DEBUG kernel (via annotation): "
# shellcheck disable=SC2016  # the $(...) must expand inside the guest, not on the host
if nerdctl run --rm --net none --runtime io.containerd.kata.v2 \
  --annotation "${ANNOTATION_KEY}=${DEBUG_KERNEL}" \
  docker.io/library/alpine:3.22 sh -c 'echo "uname=$(uname -r) btf=$(test -e /sys/kernel/btf/vmlinux && echo present || echo absent)"'; then
  echo "  (default guest, for contrast):"
  echo -n "kata default kernel                : "
  # shellcheck disable=SC2016  # the $(...) must expand inside the guest, not on the host
  nerdctl run --rm --net none --runtime io.containerd.kata.v2 \
    docker.io/library/alpine:3.22 sh -c 'echo "uname=$(uname -r) btf=$(test -e /sys/kernel/btf/vmlinux && echo present || echo absent)"' || true
else
  echo "WARN: the debug-kernel annotation did not boot a guest — check.sh's kata-debug-kernel arm will fail."
  echo "      (enable_annotations was edited; inspect the annotation channel / path allow-list in ${QEMU_CONF})"
fi
echo "expected debug uname contains: ${DBG_UNAME}"
