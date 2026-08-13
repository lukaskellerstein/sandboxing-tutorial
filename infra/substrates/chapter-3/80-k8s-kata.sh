#!/usr/bin/env bash
# Chapter 3 substrate — Kata Containers on the cluster (lesson 8). Runs AFTER 60-k8s.sh.
#
# This is the substrate that pays off chapter 2's awkwardness. Lesson 4 had to stand up a WHOLE
# SECOND container stack — containerd + nerdctl beside podman — because Kata is a containerd shim-v2
# and podman cannot drive it. On a cluster that cost disappears: containerd is already what the
# kubelet talks to, so Kata becomes an install onto the node plus a RuntimeClass, and the workload
# change is one line.
#
# kata-deploy is the upstream install path: a DaemonSet that drops the binaries onto each node,
# writes a containerd drop-in, and registers the RuntimeClasses. As of Kata 4.0.0 it ships as a HELM
# CHART — the older `kubectl apply -k .../overlays/k3s` kustomize overlays are gone, so any guide
# that tells you to apply an overlay is describing a version you are not running.
set -euo pipefail

KATA_VERSION=4.0.0
HELM_VERSION=v3.19.0

command -v k3s >/dev/null || {
  echo "FATAL: k3s is absent — 60-k8s.sh must run before this substrate."
  exit 1
}
# Fail here, loudly, rather than letting the shim fall back and letting the lesson report a "VM"
# that is an ordinary container. Lesson 4 measured that this VM type does expose both devices.
test -e /dev/kvm || {
  echo "FATAL: /dev/kvm absent — Kata needs hardware virtualisation"
  exit 1
}
echo "/dev/kvm present; /dev/vhost-vsock: $([ -e /dev/vhost-vsock ] && echo present || echo ABSENT)"

# --- helm ---------------------------------------------------------------------
if ! command -v helm >/dev/null 2>&1; then
  curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" -o /tmp/helm.tgz
  tar -C /tmp -xzf /tmp/helm.tgz
  install -m 0755 /tmp/linux-amd64/helm /usr/local/bin/helm
fi
echo "helm: $(helm version --short)"

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

# --- kata-deploy --------------------------------------------------------------
#
# k8sDistribution=k3s is the load-bearing value. k3s does not keep containerd where a stock cluster
# does — the config lives under /var/lib/rancher/k3s/agent/etc/containerd and the socket is
# /run/k3s/containerd/containerd.sock — and the chart derives both from this one setting. Left at its
# default ("k8s") kata-deploy writes a drop-in into a directory k3s never reads, reports success, and
# every Kata pod then fails to start for a reason nothing in the DaemonSet's logs mentions.
#
# The DaemonSet deployment model (the chart's default) selects ALL nodes: `nodeSelector` and
# `tolerations` are both empty by default. That matters on a single-node cluster, where the only
# node is also the control plane — and it is worth knowing that the chart's OTHER model,
# deploymentMode=job, defaults its node selector to "not control-plane" and would therefore install
# onto nothing at all here.
helm upgrade --install kata-deploy \
  "oci://ghcr.io/kata-containers/kata-deploy-charts/kata-deploy" \
  --version "${KATA_VERSION}" \
  --namespace kube-system \
  --set k8sDistribution=k3s \
  --wait --timeout 15m

# The DaemonSet being Ready is NOT the same as Kata being installed: the pod comes up, then does its
# work. kata-deploy signals completion by labelling the node, so that label is the real condition.
echo "waiting for kata-deploy to finish installing onto the node..."
for _ in $(seq 1 90); do
  [ -n "$(kubectl get nodes -l katacontainers.io/kata-runtime=true -o name 2>/dev/null)" ] && break
  sleep 10
done
kubectl get nodes -l katacontainers.io/kata-runtime=true -o name \
  | grep -q node/ || {
  echo "FATAL: kata-deploy never labelled the node katacontainers.io/kata-runtime=true"
  kubectl -n kube-system logs -l name=kata-deploy --tail=40 || true
  exit 1
}

# --- which RuntimeClasses actually exist? -------------------------------------
#
# READ them, never guess. kata-deploy registers one class per enabled shim (kata-qemu, kata-clh,
# kata-qemu-runtime-rs, ...) and the set moves between releases — the syllabus's note that "the
# obvious guess is wrong" came from exactly this. The lesson and check.sh both read this list.
kubectl get runtimeclass
KATA_CLASS=$(kubectl get runtimeclass -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep '^kata-qemu$' || true)
[ -n "${KATA_CLASS}" ] || KATA_CLASS=$(kubectl get runtimeclass -o jsonpath='{.items[*].metadata.name}' | tr ' ' '\n' | grep '^kata' | head -1)
[ -n "${KATA_CLASS}" ] || {
  echo "FATAL: kata-deploy registered no kata* RuntimeClass"
  exit 1
}
echo "kata RuntimeClass: ${KATA_CLASS}"

# --- smoke: a DIFFERENT kernel means a real VM booted -------------------------
echo "node uname -r  : $(uname -r)"
echo -n "kata pod       : "
kubectl run kata-smoke --rm -i --quiet --restart=Never \
  --image=docker.io/sandboxing-tutorial/agent:v1 --image-pull-policy=IfNotPresent \
  --overrides="{\"spec\":{\"runtimeClassName\":\"${KATA_CLASS}\"}}" --command -- uname -r
