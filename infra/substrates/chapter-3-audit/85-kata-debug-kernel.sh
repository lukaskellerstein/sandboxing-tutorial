#!/usr/bin/env bash
# Chapter 3 audit substrate — make Kata's BTF/AUDITSYSCALL DEBUG kernel selectable per POD. Runs
# AFTER chapter-3/80-k8s-kata.sh, which is what installs /opt/kata and kata-deploy's containerd
# drop-in.
#
# Lesson 2.3.3 needs a guest kernel that could host an in-guest sensor, and the DEFAULT Kata guest
# kernel cannot: it ships without BTF, so no CO-RE eBPF probe can attach inside it. The pinned Kata
# build also ships `vmlinuz-*-debug` with BTF and CONFIG_AUDITSYSCALL on, selectable per run through
# the `io.katacontainers.config.hypervisor.kernel` annotation — which is what this substrate enables.
#
# It restarts NOTHING (it edits a config file the shim reads per container), so it is safe anywhere
# after 80. It must not run BEFORE 80: kata-deploy lays down /opt/kata when its DaemonSet starts, and
# would overwrite an earlier edit.
#
# ---------------------------------------------------------------------------------------------
# THE TRAP THIS SUBSTRATE EXISTS TO AVOID, measured 2026-08-15.
#
# Chapter 2's twin (`chapter-2-audit/kata-debug-kernel.sh`) edits
# `/opt/kata/share/defaults/kata-containers/configuration-qemu.toml` directly, because kata-static
# lays that down as a REGULAR FILE. Under **kata-deploy** the same path is a SYMLINK into
# `runtimes/qemu/`, and `sed -i` does not follow symlinks — it writes a temp file and renames it over
# the link, so the edit lands on a NEW regular file and the config the shim actually reads is
# untouched. The symptom is not a warning: containerd passes the annotation (kata-deploy sets
# `pod_annotations = ["io.katacontainers.*"]`), the shim finds it is not in `enable_annotations`,
# rejects it, and the pod sits in **ContainerCreating forever** — which reads like a broken Kata
# install rather than an edit that missed.
#
# So the path is resolved with `readlink -f` first, and the assertion at the bottom reads BTF from
# INSIDE a guest booted with the annotation rather than trusting the file.
# ---------------------------------------------------------------------------------------------
set -euo pipefail

KDIR=/opt/kata/share/defaults/kata-containers
ANNOTATION_KEY=io.katacontainers.config.hypervisor.kernel
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
AGENT_IMAGE="${AGENT_IMAGE_TAG:-docker.io/sandboxing-tutorial/agent:v1}"

[ -d /opt/kata ] || {
  echo "FATAL: /opt/kata is absent — chapter-3/80-k8s-kata.sh must run before this substrate."
  exit 1
}

# --- find the debug kernel kata-deploy shipped --------------------------------
#
# Globbed, never hardcoded: the version (6.18.35-200 today) rides on the Kata release.
DEBUG_KERNEL=$(find /opt/kata/share/kata-containers -maxdepth 1 -name 'vmlinuz-*-debug' 2>/dev/null | head -1 || true)
[ -n "${DEBUG_KERNEL}" ] || {
  echo "FATAL: no vmlinuz-*-debug under /opt/kata/share/kata-containers — this Kata build ships none"
  find /opt/kata -maxdepth 4 -name 'vmlinuz*' 2>/dev/null | sed 's/^/  /' || true
  exit 1
}
DEBUG_KERNEL=$(readlink -f "${DEBUG_KERNEL}")
echo "debug kernel: ${DEBUG_KERNEL}"

# --- the config the SHIM reads, not the one that is convenient to name --------
#
# Read the path out of kata-deploy's containerd drop-in where possible: that file's `ConfigPath` is
# by definition the config the kata-qemu shim loads, so it cannot drift from what is running. Fall
# back to resolving the well-known symlink.
CONF=$(grep -h -A3 'runtimes\.kata-qemu\.options\]' /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/*.toml 2>/dev/null \
  | sed -n 's/.*ConfigPath *= *"\([^"]*\)".*/\1/p' | head -1 || true)
[ -n "${CONF}" ] || CONF="${KDIR}/configuration-qemu.toml"
CONF=$(readlink -f "${CONF}")
[ -f "${CONF}" ] || {
  echo "FATAL: kata-qemu config not found (resolved to '${CONF}')"
  ls -la "${KDIR}" || true
  exit 1
}
echo "shim config : ${CONF}"

# --- enable the kernel annotation, idempotently -------------------------------
if grep -Eq '^\s*enable_annotations\s*=.*"kernel"' "${CONF}"; then
  echo "enable_annotations: \"kernel\" already present"
else
  sed -i -E 's/^(\s*enable_annotations\s*=\s*\[)/\1"kernel", /' "${CONF}"
  echo "enable_annotations: added \"kernel\""
fi

# valid_kernel_paths: only touched when the config already declares one. Adding an unknown key to a
# strict TOML parser is how a substrate breaks the runtime it is trying to extend.
if grep -Eq '^\s*valid_kernel_paths\s*=' "${CONF}"; then
  if ! grep -Eq "^\s*valid_kernel_paths\s*=.*$(dirname "${DEBUG_KERNEL}")" "${CONF}"; then
    sed -i -E "s#^(\s*valid_kernel_paths\s*=\s*\[)#\1\"$(dirname "${DEBUG_KERNEL}")/*\", #" "${CONF}"
    echo "valid_kernel_paths: added $(dirname "${DEBUG_KERNEL}")/*"
  fi
else
  echo "valid_kernel_paths: not declared — the annotation is gated by enable_annotations only"
fi

# Where the lesson and check.sh read the resolved path from, so neither re-globs.
echo "${DEBUG_KERNEL}" >/etc/kata-containers-debug-kernel

# --- smoke: BTF is the discriminator, not the kernel string --------------------
#
# BOTH kernels report the same `uname -r` (6.18.35) — the debug build carries the same version — so a
# uname comparison cannot tell them apart and would pass on a guest that never got the annotation.
# BTF can: the default guest has none. Asserted from INSIDE both guests.
btf_of() { # $1 = pod name, $2 = annotation block (may be empty)
  kubectl delete pod "$1" --ignore-not-found --now >/dev/null 2>&1
  cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $1
${2}
spec:
  runtimeClassName: kata-qemu
  restartPolicy: Never
  containers:
    - name: probe
      image: ${AGENT_IMAGE}
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh","-c","echo \$(uname -r) \$(test -e /sys/kernel/btf/vmlinux && echo btf-present || echo btf-absent)"]
YAML
  for _ in $(seq 1 60); do
    case "$(kubectl get pod "$1" -o jsonpath='{.status.phase}' 2>/dev/null)" in
      Succeeded | Failed) break ;;
    esac
    sleep 3
  done
  kubectl logs "$1" 2>/dev/null | tail -1
  kubectl delete pod "$1" --ignore-not-found --now --wait=false >/dev/null 2>&1
}

DEFAULT_GUEST=$(btf_of sbx-kdk-default "")
DEBUG_GUEST=$(btf_of sbx-kdk-debug "  annotations:
    ${ANNOTATION_KEY}: \"${DEBUG_KERNEL}\"")
echo "kata default guest : ${DEFAULT_GUEST:-<no output>}"
echo "kata DEBUG guest   : ${DEBUG_GUEST:-<no output>}"
case "${DEBUG_GUEST}" in
  *btf-present*) echo "OK: the annotation swapped the kernel — an in-guest sensor has BTF to attach against" ;;
  *)
    echo "FATAL: the debug-kernel annotation did NOT take effect (no BTF in-guest)."
    echo "       Usually the edit landed on a symlink rather than ${CONF} — see the header."
    exit 1
    ;;
esac
