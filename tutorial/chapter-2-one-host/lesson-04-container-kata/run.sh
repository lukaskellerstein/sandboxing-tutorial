#!/usr/bin/env bash
# One command for this lesson: bring up the host it runs on, run the lesson there, destroy it.
#
#   ./run.sh            up -> run -> destroy
#   ./run.sh --keep     leave the host up afterwards (debugging; you pay until ../../../infra/down.sh)
#
# Lessons 2, 3 and 4 SHARE one host — `chapter-02-host`, named by this lesson's `box` field in
# infra/lessons.json — because the boundary each of them selects is only a real choice when the
# others are installed beside it. On a box carrying crun alone, `--runtime runsc` is a menu of one.
# (Lesson 5 is not on it: its OpenShell gateway needs a private primary address on the
# default-route interface, so its box builds a NAT'd guest and is re-pointed inside it, which
# cannot co-host host-level lessons. chapter-02-host's `why` records the constraint.) Two
# consequences worth knowing before you run this:
#
#   * `up` installs all FOUR of the host's substrates, so one lesson on its own pays the whole
#     build rather than its slice. To pay it once for the chapter, use ../../../infra/chapter-02.sh.
#   * teardown destroys the HOST. Running one lesson alone is still self-cleaning, because
#     nothing else is on it — but working through the chapter, let infra/chapter-02.sh own this.
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
  echo "==> destroying ${BOX}, the host ${LESSON} ran on (exit ${rc})"
  "${INFRA}/down.sh" "${BOX}" || echo "!! teardown failed — check: scw instance server list"
}
trap teardown EXIT

# up.sh is idempotent: it exits 0 when the box already exists, which is what lets infra/chapter-02.sh
# bring the host up once and then run every lesson against it.
"${INFRA}/up.sh" "${BOX}"
"${INFRA}/run.sh" "${LESSON}"
