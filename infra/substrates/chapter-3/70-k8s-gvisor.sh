#!/usr/bin/env bash
# Chapter 3 substrate — gVisor on the cluster (lesson 7). Runs AFTER 60-k8s.sh.
#
# Lesson 3 registered runsc as an opt-in podman runtime. Here the same binary becomes a containerd
# runtime and then a Kubernetes RuntimeClass, which is the whole point of the chapter: the boundary
# stops being a flag you remember to pass and becomes a field the workload asks for by name.
#
# k3s does NOT auto-detect runsc. Its automatic alternative-runtime detection covers crun, the NVIDIA
# runtimes and the wasm shims — not gVisor and not Kata. So the runtime has to be added to
# containerd's config, and k3s owns that file: it REGENERATES config.toml on every start, so editing
# it directly is undone by the next restart. The supported seam is a template beside it.
#
# ORDER: after 60-k8s.sh, and BEFORE 80-k8s-kata.sh. This is the only substrate in the chapter that
# restarts k3s, and a restart after Kata is installed terminates the kata-deploy DaemonSet pod, which
# reverts its own install on the way out. It shares the containerd config directory with kata-deploy,
# so every write below is additive — see the template block.
set -euo pipefail

ARCH=$(uname -m)
URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
CONTAINERD_DIR=/var/lib/rancher/k3s/agent/etc/containerd
GENERATED="${CONTAINERD_DIR}/config.toml"

command -v k3s >/dev/null || {
  echo "FATAL: k3s is absent — 60-k8s.sh must run before this substrate."
  exit 1
}

# --- runsc + the containerd shim ---------------------------------------------
#
# Same release channel and the same checksum discipline as lesson 3's 20-runsc.sh. The extra binary
# over lesson 3 is nothing new — 20-runsc.sh already installs containerd-shim-runsc-v1 — it is only
# that here it is the half that actually gets used.
if ! command -v runsc >/dev/null 2>&1; then
  cd /tmp
  for f in runsc containerd-shim-runsc-v1; do
    curl -fsSL "${URL}/${f}" -o "$f"
    curl -fsSL "${URL}/${f}.sha512" -o "${f}.sha512"
    sha512sum -c "${f}.sha512"
    chmod +x "$f"
    mv "$f" /usr/local/bin/
  done
fi
echo "runsc: $(runsc --version | head -1)"

# --- teach k3s's containerd about it -----------------------------------------
#
# The CRI plugin was SPLIT in containerd 2.0: `io.containerd.grpc.v1.cri` became
# `io.containerd.cri.v1.runtime` (+ `.images`), and the config file version went from 2 to 3. k3s
# ships containerd 2.x as of the Feb-2025 releases, but this repo should not rot the first time that
# changes in either direction — so the plugin name and the template filename are READ OFF the config
# k3s just generated rather than hardcoded from whatever was true the day this was written.
[ -f "${GENERATED}" ] || {
  echo "FATAL: ${GENERATED} does not exist — has k3s ever started?"
  exit 1
}
if grep -q 'io.containerd.cri.v1.runtime' "${GENERATED}"; then
  CRI_PLUGIN="io.containerd.cri.v1.runtime"
  TEMPLATE="${CONTAINERD_DIR}/config-v3.toml.tmpl"
else
  CRI_PLUGIN="io.containerd.grpc.v1.cri"
  TEMPLATE="${CONTAINERD_DIR}/config.toml.tmpl"
fi
echo "containerd CRI plugin: ${CRI_PLUGIN}  ->  ${TEMPLATE##*/}"

# `{{ template "base" . }}` extends k3s's own defaults instead of replacing them. Copy-pasting k3s's
# generated config into a template is the documented wrong answer: it freezes today's defaults, and
# the next k3s upgrade silently keeps running the old ones.
#
# CREATE-IF-ABSENT, APPEND-IF-MISSING — never `cat >`. This substrate no longer owns this file: on
# chapter 3's shared cluster it runs beside 80-k8s-kata.sh, and kata-deploy writes its own runtime
# registration into this same directory. A truncating write here would erase whatever else had
# already landed, and the symptom is the nastiest kind this repo has: the RuntimeClass objects still
# exist, so pods are ADMITTED and only fail later at sandbox creation, which reads like a broken
# Kata install rather than a substrate that deleted it.
#
# It also has to be idempotent for a second reason — `up.sh` is an idempotent alias on a shared box,
# so this script can legitimately run again against a cluster that is already serving.
CHANGED=0
if [ ! -f "${TEMPLATE}" ]; then
  printf '{{ template "base" . }}\n' >"${TEMPLATE}"
  CHANGED=1
fi
if ! grep -q 'containerd.runtimes.runsc' "${TEMPLATE}"; then
  cat >>"${TEMPLATE}" <<EOF

[plugins.'${CRI_PLUGIN}'.containerd.runtimes.runsc]
  runtime_type = "io.containerd.runsc.v1"
EOF
  CHANGED=1
fi

# Restart ONLY when the template actually moved. An unconditional restart is not free once this box
# is shared: it bounces every pod on the node, which terminates the kata-deploy DaemonSet pod — and
# that pod reverts its own installation on termination — and it drops the OpenShell gateway's
# port-forward that check.sh asserts is Connected. Neither is recoverable within this script.
if [ "${CHANGED}" -eq 1 ]; then
  echo "containerd template updated — restarting k3s"
  systemctl restart k3s
else
  echo "runsc already registered in ${TEMPLATE##*/} — leaving k3s alone"
fi
# The API server answers again well before the node is schedulable, and a RuntimeClass applied into
# that window succeeds while the pod that wants it sits Pending. Wait for the real condition — and
# poll for the node OBJECT first, because `kubectl wait --all` does not wait for a resource to come
# into existence: with nothing matching it exits at once with "no matching resources found".
for _ in $(seq 1 60); do
  [ -n "$(kubectl get nodes -o name 2>/dev/null)" ] && break
  sleep 5
done
kubectl wait --for=condition=Ready node --all --timeout=300s

# --- the RuntimeClass ---------------------------------------------------------
#
# `handler` must equal the containerd runtime name EXACTLY — it is the string that selects the block
# written above. A mismatch is not a validation error: the object is accepted and every pod that
# names it fails at sandbox creation, several confusing minutes later.
kubectl apply -f - <<'YAML'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: gvisor
handler: runsc
YAML
kubectl get runtimeclass

# --- smoke: whose kernel answers inside a gvisor pod? -------------------------
#
# Asked from INSIDE, because the silent failure this whole repo is built around is a pod that named
# a RuntimeClass, quietly ran on runc anyway, and exited 0.
echo "node uname -r  : $(uname -r)"
echo -n "gvisor pod     : "
kubectl run gvisor-smoke --rm -i --quiet --restart=Never \
  --image=docker.io/sandboxing-tutorial/agent:v1 --image-pull-policy=IfNotPresent \
  --overrides='{"spec":{"runtimeClassName":"gvisor"}}' --command -- uname -r
