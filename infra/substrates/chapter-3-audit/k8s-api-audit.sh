#!/usr/bin/env bash
# Chapter 3 audit substrate — the Kubernetes API server's own audit log.
#
# THE SECOND SENSOR, and the one the cluster adds that no syscall tracer can be. Every rung before
# chapter 3 had exactly one column to watch: what the workload asked the KERNEL for. A cluster gives
# untrusted code a second way to act — it can present a service-account token and talk to the CONTROL
# PLANE — and that attack never touches a syscall a sensor could hook. `k8s_sa_token` reads a file and
# makes one HTTPS request; from Tetragon's side of the world that is `openat` on a path plus a
# `tcp_connect`, indistinguishable from any other fetch. What it *was* — an authenticated principal
# asking the apiserver for something — exists only in the apiserver's own record.
#
# So this is not "more logging". It is a sensor watching a DIFFERENT surface, and the pairing is the
# chapter's whole point: Tetragon's blind spot here is the control plane, the API audit log's blind
# spot is everything below the kubelet, and the union is the coverage.
#
# WHERE THIS MUST SIT IN THE SUBSTRATE ORDER: at or with 60-k8s, and BEFORE 80-k8s-kata. Enabling
# audit is an apiserver FLAG, so it needs k3s restarted — and a k3s restart after 80 terminates the
# kata-deploy DaemonSet pod, which reverts its own install on the way out. Same constraint 70 and 75
# already live under.
set -euo pipefail

POLICY=/var/lib/rancher/k3s/server/audit-policy.yaml
LOG=/var/lib/rancher/k3s/server/logs/audit.log
CONFIG=/etc/rancher/k3s/config.yaml

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

mkdir -p "$(dirname "${POLICY}")" "$(dirname "${LOG}")"

# --- the policy ---------------------------------------------------------------
#
# FIRST MATCHING RULE WINS, so the order below is the design and not a listing. The drops come first
# because a catch-all placed above them would swallow everything; the named attacks come next so they
# are recorded even when a later, broader rule would have logged them differently.
#
# `level: Metadata` throughout, deliberately, and it is the security decision in this file. Metadata
# records WHO, WHAT verb, WHICH resource and the response code — everything the per-attack mapping
# needs — and records no request or response BODY. `RequestResponse` on `secrets` would write the
# secret's VALUE into a plaintext file on disk, which turns the audit trail itself into the most
# valuable thing on the box. A tutorial that showed that pattern would be teaching a real mistake.
#
# `omitStages: [RequestReceived]` halves the log: every request would otherwise appear twice, once on
# arrival and once on completion, and only the completed event carries the response code the mapping
# reads.
cat >"${POLICY}" <<'YAML'
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - RequestReceived
rules:
  # --- 1. drop the cluster's own chatter ---------------------------------------
  #
  # Not tuning. On an idle k3s the control plane's internal traffic is ~99% of the events, and a trail
  # a human cannot read is one nobody reads. Everything dropped here is the cluster talking to itself:
  # if any of it were the attack, the attack would already own the control plane.
  - level: None
    users:
      - system:apiserver
      - system:kube-scheduler
      - system:kube-controller-manager
      - system:kube-proxy
  - level: None
    userGroups:
      - system:nodes
      # Every service account in kube-system is a member of this group. Dropped by GROUP rather than
      # by name because k3s's own set moves between releases, and a name list that went stale would
      # quietly re-admit the noise rather than fail.
      - system:serviceaccounts:kube-system
  - level: None
    nonResourceURLs:
      - /healthz*
      - /readyz*
      - /livez*
      - /version
      - /metrics
      - /openapi/*

  # --- 2. the attacks this chapter measures ------------------------------------
  #
  # pods/exec is the control-plane attack with no kernel fingerprint AT ALL on the node the auditor
  # watches: the exec is created through the API and the syscalls happen wherever the pod is, so on a
  # multi-node cluster a syscall sensor on THIS node sees nothing whatsoever. Named first so it is
  # recorded even for a principal a later rule drops.
  - level: Metadata
    resources:
      - group: ""
        resources: ["pods/exec", "pods/attach", "pods/portforward"]

  # Secrets, at Metadata and never above — see the note on levels above.
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets"]

  # ANY request presented with a service-account token. This is the `k8s_sa_token` fingerprint: the
  # username is `system:serviceaccount:<namespace>:<name>`, which names the POD's identity rather than
  # a process, and is the one field that ties a control-plane request back to the workload.
  - level: Metadata
    userGroups:
      - system:serviceaccounts

  # --- 3. everything else ------------------------------------------------------
  #
  # Including the lesson's own kubectl (`system:admin`), on purpose: an audit log that recorded only
  # the workload would be flattering rather than honest. What the operator did is in the trail too.
  - level: Metadata
YAML

# --- the apiserver flags ------------------------------------------------------
#
# Via /etc/rancher/k3s/config.yaml rather than by editing the systemd unit. k3s merges the two, and
# the unit is INSTALL-time output owned by get.k3s.io — a sed into it is undone by any reinstall and
# is invisible to `k3s server --help`. config.yaml is the supported seam and it is additive: 60-k8s.sh
# passes its flags on the command line and sets no kube-apiserver-arg, so nothing here overrides it.
#
# max_log_file's k8s twin is audit-log-maxsize (MB). Chapter 2 learned this the expensive way with
# auditd: an 8 MB default rotated MID-RUN under the suite's volume and dropped the records the
# mapping reads, which read LOGGED one run and blank the next. 512 MB is far more than a lesson
# produces, so a whole run is always in one file.
cat >"${CONFIG}" <<EOF
kube-apiserver-arg:
  - "audit-policy-file=${POLICY}"
  - "audit-log-path=${LOG}"
  - "audit-log-maxage=1"
  - "audit-log-maxbackup=1"
  - "audit-log-maxsize=512"
EOF

systemctl restart k3s

# The API server answers again well before the node is schedulable, and `kubectl wait --all` does NOT
# wait for a resource to come into existence — with nothing matching it exits at once with "no
# matching resources found". Poll for the object, THEN wait on its condition. (Same shape as 70/75.)
for _ in $(seq 1 60); do
  [ -n "$(kubectl get nodes -o name 2>/dev/null)" ] && break
  sleep 5
done
kubectl wait --for=condition=Ready node --all --timeout=300s

# --- prove it from the LOG, never from the flag -------------------------------
#
# A policy file the apiserver rejected does not stop k3s: it logs a parse error and starts with
# auditing OFF, and every lesson downstream then reports "the control plane recorded nothing" about a
# cluster that was never recording. So make one request whose exact shape we know, and read it back
# out of the file. The service-account arm is the one that matters — it is the field `k8s_sa_token`
# is mapped by, and it is the half a plain `kubectl get` would never exercise.
TOKEN=$(kubectl create token default 2>/dev/null || echo "")
if [ -n "${TOKEN}" ]; then
  curl -sk -o /dev/null -H "Authorization: Bearer ${TOKEN}" https://127.0.0.1:6443/api || true
fi
kubectl get --raw '/api/v1/namespaces/default/secrets?limit=1' >/dev/null 2>&1 || true
sleep 3

echo "k8s API audit: policy ${POLICY} ($(grep -c '^  - level:' "${POLICY}") rules)"
if [ -s "${LOG}" ]; then
  echo "audit log: ${LOG} ($(wc -l <"${LOG}") events)"
  echo "  service-account events: $(grep -c 'system:serviceaccount:default:default' "${LOG}" || true)"
  echo "  secrets events:         $(grep -c '"resource":"secrets"' "${LOG}" || true)"
else
  echo "FATAL: ${LOG} is empty or absent — the apiserver is NOT auditing."
  echo "       Every 2.3.x control-plane row would read 'nothing recorded' about a cluster that never watched."
  journalctl -u k3s --no-pager -n 40 | grep -i audit || true
  exit 1
fi
