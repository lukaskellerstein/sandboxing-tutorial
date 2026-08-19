#!/usr/bin/env bash
# One command for this lesson: bring up the cluster it runs on, run the lesson there, destroy it.
#
#   ./run.sh            up -> run -> destroy
#   ./run.sh --keep     leave the cluster up afterwards (debugging; you pay until ../../../infra/down.sh)
#
# Lessons 6-9 SHARE one cluster — `chapter-03-k8s`, named by this lesson's `box` field in
# infra/lessons.json — because the boundary each of them selects is only a real choice when the
# others are installed beside it. On a box carrying gVisor alone, `runtimeClassName: gvisor` is a
# menu of one. (Lesson 9's OpenShell is the one boundary not selected that way — its sandboxes take
# their runtime class from the gateway — but its policy/audit axis is measured on the same node the
# menu lives on. All four fit since the identity-verified quota bought a 32 GB node; lessons.json
# records the measurement.) Two consequences worth knowing before you run this:
#
#   * `up` installs all FIVE of the cluster's substrates, so one lesson on its own costs ~30
#     minutes rather than ~8. To pay that once for the chapter, use ../../../infra/chapter-03.sh.
#   * teardown destroys the CLUSTER. Running one lesson alone is still self-cleaning, because
#     nothing else is on it — but working through the chapter, let infra/chapter-03.sh own this.
#
# The EXIT trap is unchanged and is still the point: the box goes away even when the lesson fails,
# when a substrate fails, or when you Ctrl-C. Every box here runs a rogue-agent suite, and what turns
# that into a cheap tutorial rather than a surprise invoice is that teardown is not forgettable.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# This lesson's dotted id, read from the three folder names (phaseP-*/chapter-C-*/lesson-LL-*) —
# the same derivation lib.sh's lesson_id_of_dir does, inlined so this leaf stays standalone.
_p=$(basename "$(dirname "$(dirname "${HERE}")")")
_p="${_p#phase}"
_p="${_p%%-*}"
_c=$(basename "$(dirname "${HERE}")")
_c="${_c#chapter-}"
_c="${_c%%-*}"
_l=$(basename "${HERE}")
_l="${_l#lesson-}"
_l="${_l%%-*}"
LESSON="${_p}.${_c}.$((10#${_l}))"
INFRA="$(cd "${HERE}/../../../../infra" && pwd)"
# The MACHINE, which is no longer this lesson's name. Same expression lib.sh's lesson_box() uses, so
# there is one rule about where a lesson runs and no second copy of it to drift.
BOX=$(jq -r --arg l "${LESSON}" '.[$l].box // $l' "${INFRA}/lessons.json")

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

teardown() {
  local rc=$?
  if [ "${KEEP}" -eq 1 ]; then
    echo
    echo "==> --keep: leaving ${BOX} up. Destroy it with:  ${INFRA}/down.sh ${BOX}"
    return 0
  fi
  echo
  echo "==> destroying ${BOX}, the cluster ${LESSON} ran on (exit ${rc})"
  "${INFRA}/down.sh" "${BOX}" || echo "!! teardown failed — check: scw instance server list"
}
trap teardown EXIT

# up.sh is idempotent: it exits 0 when the box already exists, which is what lets infra/chapter-03.sh
# bring the cluster up once and then run every lesson against it.
"${INFRA}/up.sh" "${BOX}"
"${INFRA}/run.sh" "${LESSON}"
