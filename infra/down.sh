#!/usr/bin/env bash
# Destroy a lesson's box. This is not housekeeping — it is what keeps this a EUR 1 tutorial.
#
#   ./down.sh lesson-03-container-gvisor
#   ./down.sh --all
#
# It also destroys evidence, deliberately. Every one of these boxes has had a rogue-agent suite run
# on it: a backdoor written, a package installed that executed code at install time, a fork bomb.
# Nothing is left running afterwards, which is the other half of why the attacks can be real.
#
# Isolation is now structural, not a keep-list. A single teardown terminates EXACTLY its own box by
# id (lib.sh's box_destroy) and never touches another — there is no whole-set apply and no prefix
# sweep that could reach a neighbour. Only `--all` sweeps the prefix, to catch anything untracked.
# On 2026-08-10 a single `./down.sh lesson-01` destroyed lesson 2's live box because the old sweep
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
report_leftovers() {
  local vols ips
  vols=$(scw instance volume list zone="${ZONE}" -o json 2>/dev/null | jq '[.[] | select(.server == null)] | length')
  ips=$(scw instance ip list zone="${ZONE}" -o json 2>/dev/null | jq '[.[] | select(.server == null)] | length')
  [ "${vols:-0}" -gt 0 ] && echo "    WARNING: ${vols} detached volume(s) still exist — 'scw instance volume list zone=${ZONE}'"
  [ "${ips:-0}" -gt 0 ] && echo "    WARNING: ${ips} unattached flexible IP(s) still exist — 'scw instance ip list zone=${ZONE}'"
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
