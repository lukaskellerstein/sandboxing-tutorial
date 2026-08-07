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
# Two mechanisms, on purpose. Terraform owns what it created and `up=[]` is a real assertion that
# nothing remains. The prefix sweep afterwards catches what Terraform cannot know about: a box
# created outside it, or one whose state entry was lost. That is not paranoia — it happened while
# this repo was being written, and the sweep is what found the untracked box.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "${HERE}/lib.sh"

# Everything this repo creates is named sbx-*. Anything else in the account is somebody's real work
# and is only ever REPORTED here, never touched.
PREFIX=sbx-

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

  # A terminated server can leave these behind, and both keep billing on their own. They are the
  # orphans nobody looks for, because the server list is empty and that reads like "all clear".
  local vols ips
  vols=$(scw instance volume list zone="${ZONE}" -o json 2>/dev/null | jq '[.[] | select(.server == null)] | length')
  ips=$(scw instance ip list zone="${ZONE}" -o json 2>/dev/null | jq '[.[] | select(.server == null)] | length')
  [ "${vols:-0}" -gt 0 ] && echo "    WARNING: ${vols} detached volume(s) still exist — 'scw instance volume list zone=${ZONE}'"
  [ "${ips:-0}" -gt 0 ] && echo "    WARNING: ${ips} unattached flexible IP(s) still exist — 'scw instance ip list zone=${ZONE}'"

  [ "${found}" -eq 0 ] && say "nothing with the ${PREFIX} prefix was left running"

  # Report, never touch. A box that is not ours is somebody's real work.
  scw instance server list zone="${ZONE}" -o json \
    | jq -r --arg p "${PREFIX}" '.[] | select(.name | startswith($p) | not) | "    (not ours, left alone) vm        \(.name)"'
  scw baremetal server list zone="${ZONE}" -o json \
    | jq -r --arg p "${PREFIX}" '.[] | select(.name | startswith($p) | not) | "    (not ours, left alone) baremetal \(.name)"'
  return 0
}

if [ "${1:-}" = "--all" ]; then
  say "destroying every lesson box"
  tf_init_once
  tf apply -input=false -auto-approve -no-color -var 'up=[]' >/dev/null
  rm -f "${STATE_DIR}"/*.env "${STATE_DIR}"/*.sshcfg 2>/dev/null || true
else
  LESSON="${1:?usage: ./down.sh <lesson>   (or --all)}"
  if [ -f "$(state_file "${LESSON}")" ]; then
    state_load "${LESSON}"
    say "destroying ${LESSON}: ${BOX_KIND} ${BOX_ID} (${BOX_IP})"
  else
    say "${LESSON}: no box recorded — asking Terraform to make sure anyway"
  fi
  # Re-apply with this lesson SUBTRACTED, so every other lesson's box survives untouched. The
  # subtraction has to be explicit: current_up_json unions in Terraform's own view, which still
  # lists this lesson, so deleting the state file alone would leave the box running.
  rm -f "$(state_file "${LESSON}")" "$(ssh_config_file "${LESSON}")"
  tf_apply "$(current_up_json | jq -c --arg l "${LESSON}" 'map(select(. != $l))')"
  say "${LESSON}: destroyed, billing stopped"
fi

sweep_orphans
