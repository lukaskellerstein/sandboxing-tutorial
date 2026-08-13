#!/usr/bin/env bash
# Chapter 3 substrate — THE CLUSTER (lessons 6-9). Single-node k3s, on this box's own kernel.
#
# Why k3s on the lesson's own disposable VM rather than a managed cluster: every boundary chapter 3
# teaches is installed at NODE level — runsc's binaries and a containerd runtime (lesson 7),
# kata-static plus /dev/kvm (lesson 8), the OpenShell gateway (lesson 9). A managed node pool
# reconciles that away, and a nested cluster (minikube's docker driver, kind) puts the node inside a
# container, which breaks Kata outright and makes lesson 6's "the pod runs on the NODE's kernel"
# claim untrue of the thing the reader actually ran. The full reasoning is in lessons.json.
#
# k3s is conformant Kubernetes, not a toy: the RuntimeClass field lessons 7 and 8 turn is the same
# field on any cluster, and it is the same containerd underneath.
set -euo pipefail

K3S_VERSION="v1.36.3+k3s1"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# THREE levels up: chapter-3 -> substrates -> infra -> the repo root. Count them against this file's
# own path rather than trusting the shape — substrates moved into per-chapter directories on
# 2026-08-13 and this line, still climbing two, resolved REPO_ROOT to `infra/` and sent the
# import below to `infra/infra/images/...`. It fails as bash exit 127 mid-provision, which reads
# like a missing tool rather than a wrong path.
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"

# The unprivileged user the LESSON runs as. up.sh invokes this script with sudo from an ssh session
# as that user, so SUDO_USER is it; the fallback matches what cloud-init creates.
USER_NAME="${SUDO_USER:-agent}"
USER_HOME="$(getent passwd "${USER_NAME}" | cut -d: -f6)"
[ -n "${USER_HOME}" ] || {
  echo "FATAL: cannot resolve the home directory of '${USER_NAME}'"
  exit 1
}

# --- k3s ---------------------------------------------------------------------
#
# The three --disable flags are not tuning. traefik, servicelb and metrics-server are ~300 MB of
# components no lesson in this chapter uses, and traefik in particular takes a while to settle —
# which on lesson 6's 4 GB box is memory and startup time spent on nothing.
#
# --write-kubeconfig-mode 0644 is what lets the unprivileged lesson user read the kubeconfig at all.
# It is a deliberate loosening, acceptable here for one reason and stated so a reader does not copy
# it: this box exists for minutes, runs a rogue-agent suite, and is then destroyed. On anything that
# outlives an afternoon, hand the user a scoped kubeconfig instead.
#
# pod-max-pids=128 matches lesson 2's `--pids-limit 128` so attack 7 meets a comparable cap — but
# note WHERE it had to go. A container flag became a KUBELET flag, because a Pod spec has no field
# for a pids limit: memory, cpu and ephemeral-storage are the workload's to request, the process
# ceiling is the cluster operator's to impose. That is a real difference between the two rungs and
# lesson 6 teaches it rather than hiding it behind a matching number.
if ! command -v k3s >/dev/null 2>&1; then
  curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION="${K3S_VERSION}" sh -s - \
    --write-kubeconfig-mode 0644 \
    --kubelet-arg=pod-max-pids=128 \
    --disable traefik \
    --disable servicelb \
    --disable metrics-server
fi

# `k3s` dispatches on argv[0], so this is a real kubectl and not a wrapper script.
ln -sf /usr/local/bin/k3s /usr/local/bin/kubectl
ln -sf /usr/local/bin/k3s /usr/local/bin/crictl

systemctl is-active --quiet k3s || systemctl start k3s
echo "k3s: $(k3s --version | head -1)"

# Two waits, and BOTH are needed — the first one is not obvious and cost a provision to find.
#
# `kubectl wait --all` does not wait for a resource to come into existence: with zero matching
# objects it exits immediately with "error: no matching resources found". For the first ~20 seconds
# after k3s starts, the API server is answering but the node has not registered itself yet, so the
# wait lands in exactly that window and fails the whole substrate. Poll for the object first, THEN
# wait on its condition.
for _ in $(seq 1 60); do
  [ -n "$(kubectl get nodes -o name 2>/dev/null)" ] && break
  sleep 5
done
kubectl wait --for=condition=Ready node --all --timeout=300s
kubectl get nodes -o wide

# --- the kubeconfig the lesson user needs ------------------------------------

install -d -o "${USER_NAME}" -g "${USER_NAME}" -m 0700 "${USER_HOME}/.kube"
install -o "${USER_NAME}" -g "${USER_NAME}" -m 0600 /etc/rancher/k3s/k3s.yaml "${USER_HOME}/.kube/config"

# A dedicated env file, NOT ~/.bashrc — Debian/Ubuntu .bashrc opens with an interactive-shell guard,
# so anything appended there is silently skipped by the non-interactive ssh that run.sh uses.
# infra/run.sh and infra/check.sh both source this path already.
#
# APPEND with a guard, never `cat >`. Lesson 9 runs this substrate AND 90-k8s-openshell, and a
# substrate that truncates this file would strip the KUBECONFIG the one before it just exported —
# producing a lesson that cannot reach its own cluster, for a reason nothing in the output names.
ENV_FILE="${USER_HOME}/.sandboxing-tutorial.env"
touch "${ENV_FILE}"
if ! grep -q 'KUBECONFIG' "${ENV_FILE}"; then
  cat >>"${ENV_FILE}" <<EOF
export KUBECONFIG="${USER_HOME}/.kube/config"
export PATH="\${HOME}/.local/bin:\${PATH}"
EOF
fi
chown "${USER_NAME}:${USER_NAME}" "${ENV_FILE}"

# --- podman, to build the agent image ----------------------------------------
#
# The kubelet pulls from the NODE's image store, not from anywhere the lesson can reach, so the
# image has to be built here and handed to k3s's containerd. See images/agent/import-k3s.sh.
export DEBIAN_FRONTEND=noninteractive
if ! command -v podman >/dev/null 2>&1; then
  apt-get -qq update
  apt-get -qq install -y podman
fi
echo "podman: $(podman --version)"

bash "${REPO_ROOT}/infra/images/agent/import-k3s.sh"

# --- NetworkPolicy: is anything actually enforcing it? -----------------------
#
# ADVISORY here, behavioural in check.sh. flannel — k3s's default CNI — does not implement
# NetworkPolicy at all; what enforces it is a network-policy controller k3s embeds (kube-router's),
# and it can be turned off with --disable-network-policy. A cluster where it is off still ACCEPTS
# every NetworkPolicy object and reports them with `kubectl get netpol`, then routes the traffic
# anyway. That is this repo's characteristic failure wearing a cluster's clothes, and lesson 6's
# entire scoreboard would be a lie on such a box — so check.sh proves it with packets, not with this.
if grep -q 'disable-network-policy' /etc/systemd/system/k3s.service 2>/dev/null; then
  echo "FATAL: k3s was started with --disable-network-policy; lesson 6 has nothing to enforce its policy"
  exit 1
fi
echo -n "kube-router netpol chains: "
iptables-save 2>/dev/null | grep -c 'KUBE-ROUTER' || echo 0

# --- smoke: a pod runs, and it runs on the NODE's kernel ---------------------
#
# The expected result is that these are the SAME. A pod is not a kernel boundary, and lesson 6 is
# built on saying so out loud; lessons 7 and 8 are where that stops being true.
echo "node uname -r : $(uname -r)"
