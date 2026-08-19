#!/usr/bin/env bash
# Chapter 3's AUDIT twins, end to end: the phase-2 leaves 2.3.x, on the one cluster they share.
#
#   ./chapter-03-audit.sh            up -> the built 2.3.x leaves -> destroy every box it used
#   ./chapter-03-audit.sh --keep     leave them up afterwards (you pay until ./down.sh)
#
# The sibling of chapter-03.sh, and it exists for the same arithmetic. `chapter-03-audit-k8s` carries
# SEVEN substrates — the whole chapter-3 boundary stack (k3s, gVisor, devmapper, Kata, OpenShell)
# plus both audit sensors (the apiserver audit log, Tetragon) — and running one leaf on its own pays
# that build in full. Here it is paid once.
#
# It is a separate box from chapter-03.sh's by the CO-RESIDENCY RULE: a host eBPF sensor taxes
# `syscall_ms`, so it must not share a machine with a phase-1 lesson whose cost it would corrupt.
# Running both chapter runners at once is fine — each box is independent, created and destroyed by
# its own id, with no shared state to race.
#
# All six chapter-3 audit leaves are built, so all six run here.
#
# ORDER MATTERS, and only in one place: 2.3.6 boots a Kata guest, so it must not follow anything that
# restarts k3s (a restart terminates the kata-deploy DaemonSet, which reverts its own install on the
# way out). No leaf restarts k3s — every substrate that does runs at provision time, before 80 — so
# this order is really about reading: each lesson sits next to the rung it is compared against.
#
# Teardown is an EXIT trap rather than a step you own — a standing "remember to destroy it" is the
# most expensive habit this repo could teach.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INFRA="${HERE}"
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "${HERE}/lib.sh" # for lesson_box — one implementation of the lesson->box rule, not a copy
SHARED=chapter-03-audit-k8s

LESSONS=(
  2.3.1
  2.3.2
  2.3.3
  2.3.4
  2.3.5
  2.3.6
)

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

# Every DISTINCT box the lessons above resolve to. Derived from lessons.json rather than hardcoded:
# a list here that drifted from that table is a box nothing tears down.
boxes() {
  local l
  for l in "${LESSONS[@]}"; do
    lesson_box "${l}"
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
  echo "==> destroying chapter 3's audit boxes (exit ${rc})"
  # Every box gets its own attempt, and one failure must not skip the next — an un-destroyed box
  # bills silently, which is the one outcome this whole trap exists to prevent.
  for b in $(boxes); do
    "${INFRA}/down.sh" "${b}" || echo "!! teardown of ${b} FAILED — check: scw instance server list"
  done
}
trap teardown EXIT

"${INFRA}/up.sh" "${SHARED}"

echo
echo "==> the two sensors the 2.3.x leaves read, on ONE cluster:"
# shellcheck disable=SC2016  # must expand on the box, not here
"${INFRA}/ssh.sh" "${SHARED}" 'echo "tetragon      : $(command -v tetragon || echo MISSING) (policy $(sudo grep -c "^    - call:" /etc/tetragon/sbx-sandboxing.yaml 2>/dev/null || echo 0) kprobes, k8s-api=$(cat /etc/tetragon/tetragon.conf.d/enable-k8s-api 2>/dev/null || echo off))"
  echo "apiserver audit: $(sudo wc -l </var/lib/rancher/k3s/server/logs/audit.log 2>/dev/null || echo 0) events so far"' || true

FAILED=()
for lesson in "${LESSONS[@]}"; do
  echo
  echo "================================================================="
  echo "  ${lesson}"
  echo "================================================================="
  # Going through infra/ directly rather than the leaf runners keeps ONE owner of the teardown —
  # this script's trap — instead of three traps each destroying a box out from under the next lesson.
  #
  # A failing lesson does NOT abort the chapter: the remaining rungs are still worth measuring, and
  # the box is already paid for. Collect and report at the end instead.
  if ! "${INFRA}/up.sh" "$(lesson_box "${lesson}")" \
    || ! "${INFRA}/run.sh" "${lesson}"; then
    echo "!! ${lesson} FAILED — continuing with the rest of the chapter"
    FAILED+=("${lesson}")
  fi
done

echo
echo "================================================================="
if [ ${#FAILED[@]} -eq 0 ]; then
  echo "  chapter 3 audit: all ${#LESSONS[@]} built leaves green on $(boxes | tr '\n' ' ')"
else
  echo "  chapter 3 audit: ${#FAILED[@]} of ${#LESSONS[@]} FAILED — ${FAILED[*]}"
fi
echo "================================================================="
echo
echo "  cross-lesson view:  python3 ${INFRA}/report/overall.py"

# Fail the script when any lesson failed, so a supervisor and a human see the same verdict. The EXIT
# trap still destroys the boxes either way — that is the whole point of it being a trap.
[ ${#FAILED[@]} -eq 0 ]
