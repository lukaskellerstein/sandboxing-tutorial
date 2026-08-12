#!/usr/bin/env bash
# The localhost port-forward to the in-cluster OpenShell gateway.
#
#   ./openshell-forward.sh start    # idempotent — a live forward is left alone
#   ./openshell-forward.sh stop
#
# Extracted into its own script because two things need it and neither should own it: openshell.sh
# needs one while it registers the gateway, and lesson 13's run.sh needs one for the whole lesson.
# Two ad-hoc `oc port-forward &` invocations is how you end up with an orphan holding the port after
# a failed run, and the next run then talks to a forward pointing at a cluster that no longer exists.
#
# `oc port-forward` dies when the gateway resets a connection — which it does routinely, on any
# request it rejects — so the process is wrapped in a restart loop rather than run bare.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091  # path is computed from BASH_SOURCE; it exists at run time
source "${HERE}/../lib.sh"

CLUSTER=openshift-sno
API_SAN="api.sno.spike.lab"
GW_NAMESPACE=openshell
GW_LOCAL_PORT=18080

OC="${HERE}/oc"
KC="${HERE}/cfg/gen/auth/kubeconfig"
PIDFILE="${HERE}/cfg/forward.pid"
LOGFILE="${HERE}/cfg/forward.log"

port_open() { (echo >"/dev/tcp/127.0.0.1/${GW_LOCAL_PORT}") >/dev/null 2>&1; }

# Kill the supervisor loop FIRST, then the `oc` child it is supervising. The order matters: kill the
# child first and the loop cheerfully starts a replacement.
#
# The child is matched by command line rather than by a recorded PID, because it is replaced every
# time the gateway resets a connection — any PID written at start time is stale within minutes. The
# pattern is narrow enough to be safe (this namespace, this port pair). `setsid` would have been
# tidier, but it does not exist on macOS and this script runs on the workstation.
stop() {
  if [ -f "${PIDFILE}" ]; then
    kill "$(cat "${PIDFILE}")" 2>/dev/null || true
    rm -f "${PIDFILE}"
  fi
  pkill -f "port-forward svc/.* ${GW_LOCAL_PORT}:8080" 2>/dev/null || true
  for _ in $(seq 1 20); do
    port_open || return 0
    sleep 0.5
  done
}

start() {
  if port_open; then
    echo "    port-forward already up on 127.0.0.1:${GW_LOCAL_PORT}"
    return 0
  fi
  [ -s "${KC}" ] || die "no kubeconfig at ${KC} — run ./install.sh first"
  state_load "${CLUSTER}"
  export KUBECONFIG="${KC}"
  "${OC}" config set-cluster sno --server="https://${BOX_IP}:6443" --tls-server-name="${API_SAN}" >/dev/null

  local svc
  svc=$("${OC}" -n "${GW_NAMESPACE}" get svc \
    -o jsonpath='{.items[?(@.spec.ports[0].port==8080)].metadata.name}' 2>/dev/null | awk '{print $1}' || true)
  [ -n "${svc}" ] || svc=openshell

  nohup bash -c "
    while true; do
      KUBECONFIG='${KC}' '${OC}' -n '${GW_NAMESPACE}' port-forward 'svc/${svc}' '${GW_LOCAL_PORT}:8080'
      sleep 1
    done
  " >"${LOGFILE}" 2>&1 &
  echo $! >"${PIDFILE}"

  for _ in $(seq 1 60); do
    port_open && {
      echo "    port-forward up: 127.0.0.1:${GW_LOCAL_PORT} -> svc/${svc}:8080"
      return 0
    }
    sleep 1
  done
  die "the port-forward never came up. Last output:
$(tail -5 "${LOGFILE}" 2>/dev/null)"
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  *) die "usage: ./openshell-forward.sh [start|stop]" ;;
esac
