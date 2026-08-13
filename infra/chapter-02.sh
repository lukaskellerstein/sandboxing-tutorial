#!/usr/bin/env bash
# Chapter 2, end to end: lessons 2-5, on the fewest boxes they fit on.
#
#   ./chapter-02.sh            up -> lessons 2,3,4,5 -> destroy every box it used
#   ./chapter-02.sh --keep     leave them up afterwards (you pay until ./down.sh)
#
# It lives in infra/ beside up.sh / run.sh / down.sh because that is all it is: those three verbs in
# the right order over a set of lessons. The lessons themselves live under
# tutorial/chapter-2-one-host/ — one folder per chapter, the same grouping syllabus.md, the
# shared boxes in lessons.json and these chapter runners already use.
#
# The reason it exists is arithmetic. Lessons 2-4 share `chapter-02-host`, which carries four
# substrates (podman, runsc, containerd+kata, devmapper); running them separately pays that build
# three times. Here it is paid once, and lesson 5's own box is brought up only when the loop
# reaches it — its OpenShell gateway needs a private primary address on the default-route
# interface, which no Scaleway box has, so a NAT'd Debian-13 guest gets built there and the whole
# box is re-pointed inside it. That relocation is why lesson 5 cannot ride the shared host; the
# full story is in chapter-02-host's `why` in lessons.json.
#
# It is also the honest way to see the chapter's claim. Lessons 2, 3 and 4 run against the SAME
# host in the same hour with crun, runsc and Kata all installed — so when lesson 3 asks for
# `--runtime runsc` it is choosing from a menu rather than naming the only thing present, and the
# scorecards are comparable without report/overall.py warning that they came from different
# hardware.
#
# Teardown is an EXIT trap rather than a step you own. Chapter 4 gave that up because single-node
# OpenShift takes two hours to install; a few minutes of substrates does not buy the same excuse,
# and a standing "remember to destroy it" is the most expensive habit this repo could teach.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA="${HERE}"
SHARED=chapter-02-host

LESSONS=(
  lesson-02-container
  lesson-03-container-gvisor
  lesson-04-container-kata
  lesson-05-container-openshell
)

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

# Every DISTINCT box the lessons above resolve to. Lesson 5 owns its own (the OpenShell NAT guest
# re-points its whole box, which cannot co-host the host-level lessons — see lessons.json), so this
# is a set, not one name, and the trap has to destroy all of it. Derived from lessons.json rather
# than hardcoded: a list here that drifted from that table is a box nothing tears down.
boxes() {
  local l
  for l in "${LESSONS[@]}"; do
    jq -r --arg l "${l}" '.[$l].box // $l' "${INFRA}/lessons.json"
  done | sort -u
}

teardown() {
  local rc=$? b
  if [ "${KEEP}" -eq 1 ]; then
    echo
    echo "==> --keep: leaving these up. Destroy them with:"
    for b in $(boxes); do echo "      ${INFRA}/down.sh ${b}"; done
    return 0
  fi
  echo
  echo "==> destroying chapter 2's boxes (exit ${rc})"
  # Every box gets its own attempt, and one failure must not skip the next — an un-destroyed box
  # bills silently, which is the one outcome this whole trap exists to prevent.
  for b in $(boxes); do
    "${INFRA}/down.sh" "${b}" || echo "!! teardown of ${b} FAILED — check: scw instance server list"
  done
}
trap teardown EXIT

# The shared host once, up front. Lesson 5's own box is brought up by the loop when it reaches it.
# up.sh is idempotent, so a later call against the running host costs a state-file check.
"${INFRA}/up.sh" "${SHARED}"

echo
echo "==> the runtime menu lessons 2-4 choose from, on ONE host:"
"${INFRA}/ssh.sh" "${SHARED}" 'echo "podman default : $(podman info --format "{{.Host.OCIRuntime.Name}}" 2>/dev/null)"
  echo "podman opt-in  : $(runsc --version 2>/dev/null | head -1)"
  echo "containerd     : $(sudo nerdctl --version 2>/dev/null), kata $(/opt/kata/bin/kata-runtime --version 2>/dev/null | head -1 | awk "{print \$NF}") (qemu + fc)"' || true

FAILED=()
for lesson in "${LESSONS[@]}"; do
  echo
  echo "================================================================="
  echo "  ${lesson}"
  echo "================================================================="
  # up.sh per lesson, then run.sh. For 2-4 the `up` is a no-op state-file check against the host
  # already running; for lesson 5 it is what brings its own box into existence. Going through
  # infra/ directly rather than the leaf runners keeps ONE owner of the teardown — this script's
  # trap — instead of four traps each destroying a box out from under the next lesson.
  #
  # A failing lesson does NOT abort the chapter: the remaining rungs are still worth measuring, and
  # the boxes are already paid for. Collect and report at the end instead.
  if ! "${INFRA}/up.sh" "$(jq -r --arg l "${lesson}" '.[$l].box // $l' "${INFRA}/lessons.json")" \
    || ! "${INFRA}/run.sh" "${lesson}"; then
    echo "!! ${lesson} FAILED — continuing with the rest of the chapter"
    FAILED+=("${lesson}")
  fi
done

echo
echo "================================================================="
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "  chapter 2: all ${#LESSONS[@]} lessons green on $(boxes | tr '\n' ' ')"
else
  echo "  chapter 2: ${#FAILED[@]} of ${#LESSONS[@]} FAILED — ${FAILED[*]}"
fi
echo "================================================================="
echo
echo "  cross-lesson view:  python3 ${INFRA}/report/overall.py"

# Fail the script when any lesson failed, so a supervisor and a human see the same verdict. The EXIT
# trap still destroys the boxes either way — that is the whole point of it being a trap.
[ ${#FAILED[@]} -eq 0 ]
