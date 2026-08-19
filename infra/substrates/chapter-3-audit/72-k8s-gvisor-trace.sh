#!/usr/bin/env bash
# Chapter 3 audit substrate — gVisor's OWN sensor, as a second RuntimeClass. Runs AFTER
# chapter-3/70-k8s-gvisor.sh and BEFORE chapter-3/80-k8s-kata.sh.
#
# WHY A SENSOR HAS TO COME FROM gVISOR ITSELF (discovery gate G2, and it failed as originally
# specified). A host eBPF sensor cannot watch a gVisor sandbox at all — not Tetragon, which never had
# a gVisor event source, and not Falco, which REMOVED its one in 0.41 (it needs an EOL ~0.36 to work
# at all). That is not a gap in either tool: under gVisor the workload's syscalls are serviced by the
# SENTRY, a user-space kernel, and the host kernel never sees the calls the application made. A probe
# attached to the host kernel is watching the wrong kernel.
#
# What can see them is gVisor's own trace. `runsc --strace` writes every syscall the sandboxed
# application makes into the sentry's boot log, which is what lesson 2.3.2 reads — the same sensor
# 2.2.2 used one rung down, so the two are comparable.
#
# WHY A SECOND RuntimeClass RATHER THAN TURNING TRACING ON FOR `gvisor`. Two reasons, and the first
# is the measurement. Chapter 3's phase-1 lesson 1.3.2 runs under `gvisor`, and strace costs real
# time per syscall — turning it on for that class would tax `syscall_ms` on a rung whose cost number
# is part of the ladder. The second is that a reader can then see both classes in `kubectl get
# runtimeclass` and pick: the boundary and the boundary-with-a-sensor are separate choices, which is
# exactly the point phase 2 is making.
#
# ORDER IS LOAD-BEARING. This edits containerd's config template, which only takes effect on a k3s
# RESTART — and a k3s restart after 80-k8s-kata terminates the kata-deploy DaemonSet pod, which
# reverts its own install on the way out. So it must sit with 70/75, never after 80.
set -euo pipefail

CONTAINERD_DIR=/var/lib/rancher/k3s/agent/etc/containerd
GENERATED="${CONTAINERD_DIR}/config.toml"
RUNSC_CONFIG=/etc/containerd/runsc-trace.toml
TRACE_DIR=/var/log/runsc-trace

command -v runsc >/dev/null || {
  echo "FATAL: runsc is absent — chapter-3/70-k8s-gvisor.sh must run before this substrate."
  exit 1
}
[ -f "${GENERATED}" ] || {
  echo "FATAL: ${GENERATED} does not exist — has k3s ever started?"
  exit 1
}

# Where the sentry writes. World-writable because the sentry drops privilege for parts of its own
# startup and the LESSON reads these files back with sudo; this box exists for minutes and is
# destroyed, which is the only reason that is acceptable — do not copy it to anything long-lived.
mkdir -p "${TRACE_DIR}"
chmod 777 "${TRACE_DIR}"

# /etc/containerd does NOT exist on a k3s node — k3s keeps its containerd config under
# /var/lib/rancher/k3s/agent/etc/containerd and never creates the distro path. The runsc shim reads
# ConfigPath as an absolute path, so the directory has to be made here. Without it the write below
# fails with "No such file or directory" and takes the whole provision down; found on a from-scratch
# run, after an incremental one had passed because a hand-run probe happened to create the directory.
mkdir -p "$(dirname "${RUNSC_CONFIG}")"

# The runsc flags, as a config file the containerd shim points at. `debug-log` ending in a SLASH is
# required: runsc treats it as a directory prefix and appends its own `<timestamp>.<command>.txt`
# suffix, so each of boot/create/gofer/start lands in its own file. Given a plain path it writes
# every command's log into one file and the boot log — the only one carrying the application's
# syscalls — is overwritten by whatever ran last.
cat >"${RUNSC_CONFIG}" <<TOML
log_path = "${TRACE_DIR}/shim-%ID%.log"
log_level = "debug"

[runsc_config]
  debug = "true"
  strace = "true"
  debug-log = "${TRACE_DIR}/"
TOML

# The CRI plugin was SPLIT in containerd 2.0 (`io.containerd.grpc.v1.cri` became
# `io.containerd.cri.v1.runtime`) and the config version went from 2 to 3. Read the plugin name and
# the template filename OFF the config k3s just generated rather than hardcoding today's answer —
# the same discipline 70-k8s-gvisor.sh uses, and it must be done as ROOT: the generated config is
# mode 0600, so an unprivileged `grep` returns "permission denied", falls through to the v2 branch,
# and appends a correct-looking block to a template k3s never reads. Measured 2026-08-15: the pod
# then sits in ContainerCreating forever, which reads like a broken runsc install.
if grep -q 'io.containerd.cri.v1.runtime' "${GENERATED}"; then
  CRI_PLUGIN="io.containerd.cri.v1.runtime"
  TEMPLATE="${CONTAINERD_DIR}/config-v3.toml.tmpl"
else
  CRI_PLUGIN="io.containerd.grpc.v1.cri"
  TEMPLATE="${CONTAINERD_DIR}/config.toml.tmpl"
fi
echo "containerd CRI plugin: ${CRI_PLUGIN}  ->  ${TEMPLATE##*/}"

# APPEND-IF-MISSING, never `cat >`: this file is shared with 70-k8s-gvisor.sh and kata-deploy, and a
# truncating write here erases whatever already landed. The symptom is the nastiest kind — the
# RuntimeClass objects still exist, so pods are ADMITTED and only fail minutes later at sandbox
# creation, which reads like a broken Kata install rather than a substrate that deleted it.
[ -f "${TEMPLATE}" ] || printf '{{ template "base" . }}\n' >"${TEMPLATE}"
CHANGED=0
if ! grep -q 'containerd.runtimes.runsc-trace' "${TEMPLATE}"; then
  cat >>"${TEMPLATE}" <<EOF

[plugins.'${CRI_PLUGIN}'.containerd.runtimes.runsc-trace]
  runtime_type = "io.containerd.runsc.v1"
  [plugins.'${CRI_PLUGIN}'.containerd.runtimes.runsc-trace.options]
    TypeUrl = "io.containerd.runsc.v1.options"
    ConfigPath = "${RUNSC_CONFIG}"
EOF
  CHANGED=1
fi

if [ "${CHANGED}" -eq 1 ]; then
  echo "runsc-trace registered in ${TEMPLATE##*/} — restarting k3s"
  systemctl restart k3s
else
  echo "runsc-trace already registered — leaving k3s alone"
fi
# The API server answers again well before the node is schedulable, and `kubectl wait --all` does NOT
# wait for a resource to come into existence. Poll for the object, THEN wait on its condition.
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
for _ in $(seq 1 60); do
  [ -n "$(kubectl get nodes -o name 2>/dev/null)" ] && break
  sleep 5
done
kubectl wait --for=condition=Ready node --all --timeout=300s

# `handler` must equal the containerd runtime name EXACTLY — it is the string that selects the block
# written above. A mismatch is not a validation error: the object is accepted and every pod naming it
# fails at sandbox creation, several confusing minutes later.
kubectl apply -f - <<'YAML'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor-trace
handler: runsc-trace
YAML

echo "runsc: $(runsc --version | head -1)"
echo "trace config: ${RUNSC_CONFIG} (strace on, debug-log ${TRACE_DIR}/)"
# `grep` with no match exits 1, and this script runs under `set -e` — so the pipeline gets a `|| true`
# rather than being allowed to end a successful provision on a cosmetic summary line.
echo "gvisor RuntimeClasses: $(kubectl get runtimeclass -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep gvisor | tr '\n' ' ' || true)"
