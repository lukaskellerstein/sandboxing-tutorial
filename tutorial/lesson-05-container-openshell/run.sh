#!/usr/bin/env bash
# One command for this lesson: provision its box, run the lesson on it, destroy the box.
#
#   ./run.sh            provision -> run -> destroy
#   ./run.sh --keep     leave the box up afterwards (debugging; you pay until ./../../infra/down.sh)
#
# The lesson name is this directory's name, so there is nothing to pass and nothing to keep in sync.
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
