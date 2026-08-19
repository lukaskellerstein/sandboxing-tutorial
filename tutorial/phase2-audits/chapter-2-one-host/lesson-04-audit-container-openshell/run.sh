#!/usr/bin/env bash
# One command for this lesson: provision its box, run the lesson on it, destroy the box.
#
#   ./run.sh            provision -> run -> destroy
#   ./run.sh --keep     leave the box up afterwards (debugging; you pay until ../../../../infra/down.sh)
#
# 2.2.4 keeps its OWN box, NOT the chapter-02-audit-host the other chapter-2 audit lessons share — for
# the same hard reason 1.2.4 does: OpenShell's rootless-podman driver refuses a public default route, so
# 50-nat-vm builds a Debian-13 NAT guest and up.sh re-points the box terminally into it, a relocation the
# Tetragon/Kata audit host cannot ride along on. The box carries OpenShell in the guest plus in-guest auditd
# (chapter-2-audit/auditd-guest), and the lesson runs INSIDE the guest, reached through the box.
#
# The box is destroyed by an EXIT trap, so it goes away even when the lesson fails, when a substrate
# fails, or when you Ctrl-C — every box here runs a rogue-agent suite, and teardown must not be
# forgettable.
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
