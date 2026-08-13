#!/usr/bin/env bash
# One command for this lesson: bring up the cluster it runs on, run the lesson there, destroy it.
#
#   ./run.sh            up -> run -> destroy
#   ./run.sh --keep     leave the cluster up afterwards (debugging; you pay until ../../../infra/down.sh)
#
# Lessons 6, 7 and 8 SHARE one cluster — `chapter-03-k8s`, named by this lesson's `box` field in
# infra/lessons.json — because the boundary each of them selects is only a real choice when the
# others are installed beside it. On a box carrying gVisor alone, `runtimeClassName: gvisor` is a
# menu of one. (Lesson 9 is not on it: OpenShell is not runtime-class-selected, and its resident
# gateway does not fit beside Kata on 8 GB. lessons.json records that measurement.) Two consequences
# worth knowing before you run this:
#
#   * `up` installs all THREE of the cluster's substrates, so one lesson on its own costs ~25
#     minutes rather than ~8. To pay that once for the chapter, use ../../../infra/chapter-03.sh.
#   * teardown destroys the CLUSTER. Running one lesson alone is still self-cleaning, because
#     nothing else is on it — but working through the chapter, let infra/chapter-03.sh own this.
#
# The EXIT trap is unchanged and is still the point: the box goes away even when the lesson fails,
# when a substrate fails, or when you Ctrl-C. Every box here runs a rogue-agent suite, and what turns
# that into a cheap tutorial rather than a surprise invoice is that teardown is not forgettable.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LESSON="$(basename "${HERE}")"
INFRA="$(cd "${HERE}/../../../infra" && pwd)"
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

# up.sh is idempotent: it exits 0 when the box already exists, which is what lets run-all.sh bring
# the cluster up once and then call each lesson's runner against it.
"${INFRA}/up.sh" "${BOX}"
"${INFRA}/run.sh" "${LESSON}"
