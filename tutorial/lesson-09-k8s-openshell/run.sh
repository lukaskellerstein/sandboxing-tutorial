#!/usr/bin/env bash
# One command for this lesson: provision its box, run the lesson on it, destroy the box.
#
#   ./run.sh            provision -> run -> destroy
#   ./run.sh --keep     leave the box up afterwards (debugging; you pay until ../../infra/down.sh)
#
# THIS IS THE ONE CHAPTER-3 LESSON WITH ITS OWN BOX, and the reason is capacity rather than design.
# Lessons 6-8 share `chapter-03-k8s`, which carries the three boundaries a workload picks with
# `runtimeClassName`. OpenShell is not one of them — its sandbox pods take their runtime class from
# the GATEWAY, not per sandbox — so it was never part of the per-pod menu that cluster demonstrates.
# It is also the heaviest: the gateway StatefulSet and the Agent Sandbox controller stay resident,
# and on one 8 GB node beside Kata's repeated guest boots the machine went down. infra/lessons.json
# records the measurement and the quota ceiling that stopped us simply buying a bigger box.
#
# The box is destroyed by an EXIT trap, which means it goes away even when the lesson fails, when a
# substrate fails, or when you Ctrl-C. That is the point: every box here runs a rogue-agent suite,
# and the thing that turns this into a cheap tutorial rather than a surprise invoice is that
# teardown is not a step someone can forget.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LESSON="$(basename "${HERE}")"
INFRA="$(cd "${HERE}/../../infra" && pwd)"

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

teardown() {
  local rc=$?
  if [ "${KEEP}" -eq 1 ]; then
    echo
    echo "==> --keep: leaving the box up. Destroy it with:  ${INFRA}/down.sh ${LESSON}"
    return 0
  fi
  echo
  echo "==> destroying ${LESSON}'s box (exit ${rc})"
  "${INFRA}/down.sh" "${LESSON}" || echo "!! teardown failed — check: scw instance server list"
}
trap teardown EXIT

"${INFRA}/up.sh" "${LESSON}"
"${INFRA}/run.sh" "${LESSON}"
