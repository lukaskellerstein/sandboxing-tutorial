#!/usr/bin/env bash
# runs-as: user
#
# Chapter 3 substrate — NVIDIA OpenShell on the cluster (lesson 9). Runs AFTER 60-k8s.sh.
#
# Lesson 5 ran OpenShell's **podman** driver on one machine. This is the **kubernetes** driver: the
# gateway becomes a workload in the cluster and each policy-governed sandbox becomes a pod.
#
# THIS RUNS AS THE UNPRIVILEGED USER, and up.sh honours the `runs-as: user` marker above. The
# openshell CLI keeps its gateway registry and mTLS material under ~/.config/openshell, so installing
# it as root puts the credentials in root's home and the lesson — which runs as this user — then
# cannot see the gateway it just registered.
#
# Note what this substrate does NOT need, and why. Lesson 5 required 50-nat-vm.sh because OpenShell's
# rootless-podman driver refuses to start when the host's default-route address is public, and every
# Scaleway box has one. That constraint belongs to the podman driver's sandbox callback. Under the
# kubernetes driver the callback address is an in-cluster Service on a private ClusterIP, so there is
# nothing to work around and no NAT'd guest.
set -euo pipefail

AGENT_SANDBOX_VERSION=v0.5.4
OPENSHELL_VERSION=0.0.99
HELM_VERSION=v3.19.0
GW_NAMESPACE=openshell
GW_LOCAL_PORT=18080

[ "$(id -u)" -ne 0 ] || {
  echo "FATAL: run this as an unprivileged user — the openshell CLI keeps per-user gateway config."
  exit 1
}
command -v kubectl >/dev/null || {
  echo "FATAL: kubectl is absent — 60-k8s.sh must run before this substrate."
  exit 1
}
export PATH="${HOME}/.local/bin:${PATH}"
export KUBECONFIG="${HOME}/.kube/config"

# --- helm ---------------------------------------------------------------------
if ! command -v helm >/dev/null 2>&1; then
  curl -fsSL "https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz" -o /tmp/helm.tgz
  tar -C /tmp -xzf /tmp/helm.tgz
  sudo install -m 0755 /tmp/linux-amd64/helm /usr/local/bin/helm
fi
echo "helm: $(helm version --short)"

# --- 1. the Agent Sandbox controller -----------------------------------------
#
# Two components, and the ORDER matters: this CRD is what OpenShell's kubernetes driver creates
# objects against, so a gateway installed first comes up healthy and then fails every sandbox create.
#
# The asset is `sandbox.yaml`. Guides written against v0.5.3 and earlier say `manifests.yaml`, which
# no longer exists — a 404 that reads like a network problem rather than a renamed file.
kubectl apply --server-side -f \
  "https://github.com/kubernetes-sigs/agent-sandbox/releases/download/${AGENT_SANDBOX_VERSION}/sandbox.yaml"
kubectl wait --for=condition=Established crd/sandboxes.agents.x-k8s.io --timeout=180s
kubectl -n agent-sandbox-system rollout status deploy --timeout=300s 2>/dev/null || true

# --- 2. the OpenShell gateway -------------------------------------------------
#
# allowUnauthenticatedUsers removes the gateway's identity-provider requirement so the CLI can talk
# to it without one. LOCAL DEV ONLY, and acceptable here for exactly one reason worth stating rather
# than assuming: this box is destroyed minutes from now. Never on anything shared.
helm upgrade --install openshell \
  "oci://ghcr.io/nvidia/openshell/helm-chart" \
  --version "${OPENSHELL_VERSION}" \
  --namespace "${GW_NAMESPACE}" --create-namespace \
  --set server.auth.allowUnauthenticatedUsers=true \
  --wait --timeout 15m
kubectl -n "${GW_NAMESPACE}" get pods

# --- 3. the openshell CLI -----------------------------------------------------
#
# `uv tool install openshell` is NOT enough — it omits the gateway daemon. Here we only need the
# client half (the daemon is the Helm release above), but the installer ships both as a system .deb,
# so it wants root to place them while the CONFIG it writes must belong to this user.
if ! command -v openshell >/dev/null 2>&1; then
  curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh -o /tmp/openshell-install.sh
  # PIN THE CLI to the same version as the chart above. Left unset the installer resolves "latest",
  # which is not the same thing: measured on this box, the chart pinned at 0.0.99 was paired with a
  # CLI that installed itself as 0.0.101, because the two are released on their own cadences. A
  # client and a server drifting apart on alpha software is how a lesson starts failing for reasons
  # that have nothing to do with what it teaches — and this repo's rule is to pin alpha tooling and
  # record the version it was verified against.
  #
  # `|| true` is load-bearing, and this is the trap that cost a box to find. After unpacking the
  # .deb the installer ALSO bootstraps a LOCAL gateway (a user systemd service on 127.0.0.1:17670),
  # registers it as the active gateway, and then blocks waiting for it to answer. On this box it
  # cannot start:
  #
  #     configuration error: no compute driver configured and auto-detection found
  #     no suitable driver; set --drivers or OPENSHELL_DRIVERS to kubernetes, podman, docker, or vm
  #
  # — the service has no OPENSHELL_DRIVERS in its environment and there is no rootless podman
  # socket for auto-detection to find. That failure is CORRECT and irrelevant: lesson 9's gateway is
  # the Helm release running in the cluster, not a local daemon. But the installer exits non-zero,
  # and under `set -e` that threw away an otherwise perfectly good box. So: tolerate the exit, then
  # assert the thing we actually came for — the binary.
  sudo env "OPENSHELL_VERSION=v${OPENSHELL_VERSION}" sh /tmp/openshell-install.sh || true
fi
command -v openshell >/dev/null || {
  echo "FATAL: the openshell CLI is not on PATH after install."
  exit 1
}
echo "openshell: $(openshell --version 2>&1 | head -1)"

# Stop the local gateway the installer just enabled. It cannot run here, it is not what this lesson
# drives, and leaving it restarting forever fills the journal and confuses `openshell status`.
systemctl --user disable --now openshell-gateway >/dev/null 2>&1 || true

# --- 4. reach the gateway ------------------------------------------------------
#
# Over a port-forward to 127.0.0.1 rather than straight to the Service's ClusterIP, which the node
# can route to perfectly well. The reason is TLS, not routing: the chart's server certificate lists
# 127.0.0.1 among its SANs, and a ClusterIP is not in there — so the direct route fails verification.
# Reaching for --gateway-insecure to make that go away is the wrong fix twice over: it drops the
# CLIENT identity too, and the server answers CertificateRequired.
#
# A systemd USER unit, not a backgrounded process: `up.sh` and `run.sh` open separate ssh sessions,
# and a nohup'd child of the first one dies with it. Restart=always covers the gateway resetting
# connections it rejects, which kills the forward.
SVC=$(kubectl -n "${GW_NAMESPACE}" get svc -o jsonpath='{.items[?(@.spec.ports[0].port==8080)].metadata.name}' | awk '{print $1}')
[ -n "${SVC}" ] || SVC=openshell
echo "gateway service: ${SVC}"

mkdir -p "${HOME}/.config/systemd/user"
cat >"${HOME}/.config/systemd/user/openshell-portforward.service" <<EOF
[Unit]
Description=port-forward to the in-cluster OpenShell gateway
[Service]
Environment=KUBECONFIG=${HOME}/.kube/config
ExecStart=/usr/local/bin/kubectl -n ${GW_NAMESPACE} port-forward svc/${SVC} ${GW_LOCAL_PORT}:8080
Restart=always
RestartSec=2
[Install]
WantedBy=default.target
EOF
sudo loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || true
systemctl --user daemon-reload
systemctl --user enable --now openshell-portforward >/dev/null 2>&1 || true
systemctl --user restart openshell-portforward >/dev/null 2>&1 || true

for _ in $(seq 1 30); do
  (echo >/dev/tcp/127.0.0.1/${GW_LOCAL_PORT}) >/dev/null 2>&1 && break
  sleep 2
done

# --- 5. register it, THEN install the client certificates ---------------------
#
# This order is not cosmetic. `gateway add --local` SEEDS the new gateway's mtls/ directory from any
# gateway config already on the box, so certificates copied in first are promptly overwritten by
# whatever it decides to seed — and the failure surfaces later as a TLS handshake error that looks
# like a bad certificate rather than a clobbered one.
openshell gateway add "https://127.0.0.1:${GW_LOCAL_PORT}" --name k8s --local 2>&1 | tail -3 || true
# The installer registered ITS gateway as the active one a few steps ago. Say explicitly which one
# this lesson drives rather than relying on whichever was added last.
openshell gateway select k8s >/dev/null 2>&1 || true

CERT_DIR="${HOME}/.config/openshell/gateways/k8s/mtls"
mkdir -p "${CERT_DIR}"
for f in ca.crt tls.crt tls.key; do
  kubectl -n "${GW_NAMESPACE}" get secret openshell-client-tls \
    -o jsonpath="{.data.${f/./\\.}}" | base64 -d >"${CERT_DIR}/${f}"
done
chmod 600 "${CERT_DIR}"/tls.key

# --- 6. the env every later shell needs ---------------------------------------
#
# APPEND with a guard. 60-k8s.sh already wrote KUBECONFIG into this file, and truncating it here
# would leave the lesson unable to reach the cluster it is about to drive.
#
# OPENSHELL_DRIVERS=kubernetes is the one that produces the most confusing failure if forgotten:
# a gateway accepts a SINGLE compute driver, so this cannot share a configuration with lesson 5's
# podman driver. Get it wrong and sandboxes simply refuse to create, with no mention of drivers.
ENV_FILE="${HOME}/.sandboxing-tutorial.env"
touch "${ENV_FILE}"
if ! grep -q 'OPENSHELL_DRIVERS' "${ENV_FILE}"; then
  cat >>"${ENV_FILE}" <<'EOF'
export OPENSHELL_DRIVERS=kubernetes
export OPENSHELL_GATEWAY=k8s
EOF
fi
export OPENSHELL_DRIVERS=kubernetes
export OPENSHELL_GATEWAY=k8s

echo "--- gateway status ---"
openshell status 2>&1 | tail -6
