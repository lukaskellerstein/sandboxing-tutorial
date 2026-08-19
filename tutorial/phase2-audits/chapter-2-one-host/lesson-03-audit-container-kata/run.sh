#!/usr/bin/env bash
# One command for this lesson: bring up the host it runs on, run the lesson there, destroy it.
#
#   ./run.sh            up -> run -> destroy
#   ./run.sh --keep     leave the host up afterwards (debugging; you pay until ../../../../infra/down.sh)
#
# The phase-2 chapter-2 audit lessons SHARE one host — `chapter-02-audit-host`, named by this lesson's
# `box` field in infra/lessons.json — separate from the phase-1 `chapter-02-host` by the co-residency
# rule: a host eBPF sensor (Tetragon) taxes syscall_ms, so it must not share a machine with a phase-1
# lesson whose cost it would corrupt. The box carries podman, gVisor's runsc, containerd + kata-static,
# Tetragon (the host sensor), and the kata-debug-kernel enablement this lesson's in-guest sensor needs.
# Two consequences worth knowing before you run this:
#
#   * `up` installs ALL of the host's substrates, so one lesson on its own pays the whole build rather
#     than its slice. To pay it once for the chapter, use ../../../../infra/chapter-02-audit.sh.
#   * teardown destroys the HOST. Running one lesson alone is still self-cleaning, because nothing else
#     is on it — but working through the chapter, let the chapter runner own this.
#
# The EXIT trap is the point: the box goes away even when the lesson fails, when a substrate fails, or
# when you Ctrl-C. Every box here runs a rogue-agent suite, and what turns that into a cheap tutorial
# rather than a surprise invoice is that teardown is not forgettable.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# This lesson's dotted id, read from the three folder names (phaseP-*/chapter-C-*/lesson-LL-*) — the
# same derivation lib.sh's lesson_id_of_dir does, inlined so this leaf stays standalone.
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
# The MACHINE, which is not this lesson's name. Same expression lib.sh's lesson_box() uses, so there
# is one rule about where a lesson runs and no second copy of it to drift.
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

# up.sh is idempotent: it exits 0 when the box already exists, which is what lets a chapter runner
# bring the host up once and then run every lesson against it.
"${INFRA}/up.sh" "${BOX}"
"${INFRA}/run.sh" "${LESSON}"
