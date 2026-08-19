#!/usr/bin/env bash
# Destroy a lesson's box. This is not housekeeping — it is what keeps this a EUR 1 tutorial.
#
#   ./down.sh 1.2.2
#   ./down.sh --all
#
# It also destroys evidence, deliberately. Every one of these boxes has had a rogue-agent suite run
# on it: a backdoor written, a package installed that executed code at install time, a fork bomb.
# Nothing is left running afterwards, which is the other half of why the attacks can be real.
#
# Isolation is now structural, not a keep-list. A single teardown terminates EXACTLY its own box by
# id (lib.sh's box_destroy) and never touches another — there is no whole-set apply and no prefix
# sweep that could reach a neighbour. Only `--all` sweeps the prefix, to catch anything untracked.
# On 2026-08-10 a single `./down.sh 1.1.1` destroyed lesson 1.2.1's live box because the old sweep
# terminated every sbx-* it saw; that class of bug cannot happen when a single down never sweeps.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "${HERE}/lib.sh"

# Everything this repo creates is named sbx-*. Anything else in the account is somebody's real work
# and is only ever REPORTED here, never touched.
PREFIX=sbx-

# Detached volumes and unattached flexible IPs each keep billing on their own after a server is gone,
# and the server list reading empty looks exactly like "all clear". A `terminate with-block with-ip`
# should leave none, so this only WARNS — it never deletes, because a volume could belong to work
# outside this repo. Foreign (non-sbx-) boxes are reported and left alone.
#
# TWO volume APIs, and asking only the first is a silent all-clear. `scw instance volume list`
# returns l_ssd/b_ssd volumes ONLY; an `sbs` volume — which lib.sh's box_create_vm makes for EVERY
# current lesson — lives in the Block API and is invisible to it. On 2026-08-13 a 20 GB sbs root
# volume detached since 2026-08-08 sat in fr-par-1 billing ~EUR 0.06/day while `instance volume
# list` reported 0. A block volume carries no sbx- prefix to attribute it by (its name comes from
# the image: "Ubuntu 24.04 Noble Numbat_sbs_volume_0"), so the ids are printed for a human to judge.
report_leftovers() {
  local vols ips blk blkids
  vols=$(scw instance volume list zone="${ZONE}" -o json 2>/dev/null | jq '[.[] | select(.server == null)] | length')
  ips=$(scw instance ip list zone="${ZONE}" -o json 2>/dev/null | jq '[.[] | select(.server == null)] | length')
  blkids=$(scw block volume list zone="${ZONE}" -o json 2>/dev/null | jq -r '.[] | select(((.references // []) | length) == 0) | .id')
  blk=$(printf '%s' "${blkids}" | grep -c . || true)
  [ "${vols:-0}" -gt 0 ] && echo "    WARNING: ${vols} detached volume(s) still exist — 'scw instance volume list zone=${ZONE}'"
  [ "${ips:-0}" -gt 0 ] && echo "    WARNING: ${ips} unattached flexible IP(s) still exist — 'scw instance ip list zone=${ZONE}'"
  if [ "${blk:-0}" -gt 0 ]; then
    echo "    WARNING: ${blk} detached BLOCK volume(s) still billing — 'scw block volume list zone=${ZONE}'"
    while read -r id; do
      [ -z "${id}" ] || echo "               scw block volume delete ${id} zone=${ZONE}"
    done <<<"${blkids}"
  fi
  scw instance server list zone="${ZONE}" -o json \
    | jq -r --arg p "${PREFIX}" '.[] | select(.name | startswith($p) | not) | "    (not ours, left alone) vm        \(.name)"'
  scw baremetal server list zone="${ZONE}" -o json \
    | jq -r --arg p "${PREFIX}" '.[] | select(.name | startswith($p) | not) | "    (not ours, left alone) baremetal \(.name)"'
  return 0
}

# --all ONLY: terminate every sbx-* server still in the account, tracked or not. Never called by a
# single-lesson teardown — that already destroyed exactly its own box by id.
sweep_orphans() {
  local found=0 id name
  say "sweeping ${ZONE} for anything still billable"
  while read -r id name; do
    [ -z "${id}" ] && continue
    found=1
    echo "    ORPHAN vm        ${name} (${id}) — terminating"
    scw instance server terminate "${id}" zone="${ZONE}" with-ip=true with-block=true >/dev/null || true
  done < <(scw instance server list zone="${ZONE}" -o json \
    | jq -r --arg p "${PREFIX}" '.[] | select(.name | startswith($p)) | "\(.id) \(.name)"')
  while read -r id name; do
    [ -z "${id}" ] && continue
    found=1
    echo "    ORPHAN baremetal ${name} (${id}) — deleting"
    scw baremetal server delete "${id}" zone="${ZONE}" >/dev/null || true
  done < <(scw baremetal server list zone="${ZONE}" -o json \
    | jq -r --arg p "${PREFIX}" '.[] | select(.name | startswith($p)) | "\(.id) \(.name)"')
  [ "${found}" -eq 0 ] && say "nothing with the ${PREFIX} prefix was left running"
  report_leftovers
}

# A lesson that SHARES a box must never be destroyed by its own name, and this guard is the reason
# the sharing is safe at all. Without it the failure is silent and expensive: a shared lesson has no
# .state file of its own, so box_destroy falls through to its by-name branch, looks for a console
# name that was never created, matches nothing, exits 0 — and this script then prints
# `destroyed, billing stopped` over a cluster that is still running and still billing. That is a
# FALSE ALL-CLEAR, the same class of bug as the 2026-08-10 incident in the header, and the only
# difference is that this one bills quietly instead of destroying a neighbour.
if [ -n "${1:-}" ] && [ "${1}" != "--all" ]; then
  _down_box=$(lesson_box "${1}")
  [ "${_down_box}" = "${1}" ] || die "${1} does not own a box — it shares '${_down_box}' with the rest of its chapter.
       Destroying it means destroying the cluster every one of those lessons runs on:
         ./down.sh ${_down_box}"
fi

# One target is a target; `--all` is not, and there is no per-target run directory to record it in.
[ "${1:-}" = "--all" ] || run_track down "${1:?usage: ./down.sh <lesson>   (or --all)}"

stage_begin destroy "destroying"
if [ "${1:-}" = "--all" ]; then
  say "destroying every lesson box"
  # Each tracked box, terminated by its own id. Independent boxes, so this is just a loop — no set to
  # recompute, no lock.
  shopt -s nullglob
  for f in "${STATE_DIR}"/*.env; do
    box_destroy "$(basename "${f}" .env)"
  done
  ALL_SWEEP=1
else
  LESSON="${1:?usage: ./down.sh <lesson>   (or --all)}"
  # Terminate EXACTLY this lesson's box — by id from .state, or by name if the create died before it
  # recorded anything. There is no set and no broad sweep, so a single teardown cannot touch another
  # lesson's box. That isolation is the whole reason this repo moved off Terraform's whole-set apply.
  box_destroy "${LESSON}"
  say "${LESSON}: destroyed, billing stopped"
  ALL_SWEEP=0
fi
stage_end ok

# NEVER the finish line. `destroyed, billing stopped` prints when the terminate call returns; a
# volume or a flexible IP can outlive the server, each billing on its own. Ask the ACCOUNT. `--all`
# terminates every remaining sbx-* box; a single teardown already destroyed exactly its own box by
# id, so it only REPORTS leftovers — it must never terminate another lesson's box.
stage_begin sweep "sweeping the account"
if [ "${ALL_SWEEP}" -eq 1 ]; then
  sweep_orphans
else
  report_leftovers
fi
stage_end ok
