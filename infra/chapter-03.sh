#!/usr/bin/env bash
# Chapter 3, end to end: lessons 6-9, on the fewest boxes they fit on.
#
#   ./chapter-03.sh            up -> lessons 6,7,8,9 -> destroy every box it used
#   ./chapter-03.sh --keep     leave them up afterwards (you pay until ./down.sh)
#
# It lives in infra/ beside up.sh / run.sh / down.sh because that is all it is: those three verbs in
# the right order over a set of lessons. The lessons themselves live under
# tutorial/chapter-3-kubernetes/ — one folder per chapter, the same grouping syllabus.md, the
# shared boxes in lessons.json and these chapter runners already use.
#
# The reason it exists is arithmetic. All four lessons share `chapter-03-k8s` — one node carrying
# five substrates that take ~30 minutes to build; running the lessons separately pays that four
# times. Here it is paid once. (Lesson 9 used to own a separate box because its resident gateway
# did not fit beside Kata's guest boots on 8 GB; the identity-verified quota bought the PRO2-S that
# holds all four — lessons.json records the measurement.)
#
# It is also the honest way to see the chapter's claim. Lessons 6, 7 and 8 run against the SAME node
# in the same hour with gVisor and Kata both installed — so when lesson 7 asks for
# `runtimeClassName: gvisor` it is choosing from a menu rather than naming the only thing present,
# and the scorecards are comparable without report/overall.py warning that they came from different
# hardware.
#
# Teardown is an EXIT trap rather than a step you own. Chapter 4 gave that up because single-node
# OpenShift takes two hours to install; twenty-five minutes does not buy the same excuse, and a
# standing "remember to destroy it" is the most expensive habit this repo could teach.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA="${HERE}"
SHARED=chapter-03-k8s

LESSONS=(
  lesson-06-k8s
  lesson-07-k8s-gvisor
  lesson-08-k8s-kata
  lesson-09-k8s-openshell
)

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

# Every DISTINCT box the lessons above resolve to. All four share one node now (the
# identity-verified quota bought a box big enough — see lessons.json), so today this collapses to
# a single name — but it stays a derived set, never hardcoded: it self-corrects if the topology
# moves again, and a list here that drifted from that table is a box nothing tears down.
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
  echo "==> destroying chapter 3's boxes (exit ${rc})"
  # Every box gets its own attempt, and one failure must not skip the next — an un-destroyed box
  # bills silently, which is the one outcome this whole trap exists to prevent.
  for b in $(boxes); do
    "${INFRA}/down.sh" "${b}" || echo "!! teardown of ${b} FAILED — check: scw instance server list"
  done
}
trap teardown EXIT

# The shared cluster once, up front — the one box every lesson below resolves to. up.sh is
# idempotent, so the per-lesson calls in the loop cost a state-file check each.
"${INFRA}/up.sh" "${SHARED}"

echo
echo "==> the runtime menu lessons 6-8 choose from, on ONE node:"
"${INFRA}/ssh.sh" "${SHARED}" 'kubectl get runtimeclass' || true

FAILED=()
for lesson in "${LESSONS[@]}"; do
  echo
  echo "================================================================="
  echo "  ${lesson}"
  echo "================================================================="
  # up.sh per lesson, then run.sh. Every `up` here is a no-op state-file check against the cluster
  # already running — kept in the loop so this script still works if a lesson ever gets its own
  # box back. Going through infra/ directly rather than the leaf runners keeps ONE owner of the
  # teardown — this script's trap — instead of four traps each destroying a box out from under the
  # next lesson.
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
  echo "  chapter 3: all ${#LESSONS[@]} lessons green on $(boxes | tr '\n' ' ')"
else
  echo "  chapter 3: ${#FAILED[@]} of ${#LESSONS[@]} FAILED — ${FAILED[*]}"
fi
echo "================================================================="
echo
echo "  cross-lesson view:  python3 ${INFRA}/report/overall.py"

# Fail the script when any lesson failed, so a supervisor and a human see the same verdict. The EXIT
# trap still destroys the cluster either way — that is the whole point of it being a trap.
[ ${#FAILED[@]} -eq 0 ]
