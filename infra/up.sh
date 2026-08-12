#!/usr/bin/env bash
# Bring up ONE lesson's box: provision it with the scw CLI, copy the repo onto it, install the
# substrates that lesson needs, and assert each boundary FROM INSIDE.
#
#   ./up.sh lesson-03-container-gvisor
#   ./up.sh --list
#
# The assertion at the end is not ceremony. This repo's characteristic failure is a lesson that
# *intends* to run under gVisor, silently falls back to runc, and exits 0 printing everything the
# lesson expects. Failing at setup time is the only place that costs nothing to fix.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "${HERE}/lib.sh"

if [ "${1:-}" = "--list" ]; then
  printf '%-32s %-10s %-14s %s\n' LESSON KIND TYPE SUBSTRATES
  while read -r l; do
    printf '%-32s %-10s %-14s %s\n' "${l}" "$(lesson_kind "${l}")" "$(lesson_type "${l}")" \
      "$(lesson_substrates "${l}" | tr '\n' ' ')"
  done < <(lesson_names)
  exit 0
fi

LESSON="${1:?usage: ./up.sh <lesson>   (./up.sh --list)}"
lesson_kind "${LESSON}" >/dev/null # validates the name against lessons.json
KIND=$(lesson_kind "${LESSON}")
TYPE=$(lesson_type "${LESSON}")

require_key

# --- cancel safety ------------------------------------------------------------
#
# Turn a cancel signal into a normal exit so the shell tears down cleanly. There is nothing to undo
# here beyond that: box_create writes the .state file the instant it has an id, so a box that exists
# is always tracked and tearable, and destroying-on-cancel is the supervisor's job (ctl.py runs
# down.sh, which finds the box by id or, if the create died before recording, by name). No lock to
# release, because there is no lock — each box is independent.
trap 'exit 130' INT TERM

if [ -f "$(state_file "${LESSON}")" ]; then
  state_load "${LESSON}"
  say "${LESSON} already has a box: ${BOX_ID} (${BOX_IP}). ./down.sh ${LESSON} to destroy it."
  exit 0
fi

# Below the early exit above on purpose: "already has a box" does no work, and recording it as a run
# would replace this lesson's last real provision with an empty one in every watcher's history.
run_track up "${LESSON}"

stage_begin provision "provisioning ${KIND} ${TYPE}"
say "provisioning ${LESSON}: ${KIND} ${TYPE} in ${ZONE} — EUR $(hourly_price "${TYPE}" "${KIND}")/hr"
# One independent box, created by the scw CLI. No shared state, no lock, no "maintain the whole set"
# apply — so starting several `up`s at once just works: each creates its own box concurrently and
# nothing any of them does can drop another's box.
box_create "${LESSON}"
state_load "${LESSON}"
say "${LESSON} → ${BOX_USER}@${BOX_IP}  (${BOX_ID})"
emit box "box allocated" "id=${BOX_ID}" "ip=${BOX_IP}" "type=${BOX_TYPE}" "kind=${BOX_KIND}"
stage_end ok

stage_begin ssh "waiting for sshd"
box_wait_ssh "${LESSON}"
stage_end ok

# cloud-init is what creates the unprivileged `agent` user and enables lingering, and sshd answers
# before it has finished. Touching the box first produces failures that look like permissions bugs.
stage_begin cloud-init "waiting for cloud-init"
box_wait_cloud_init "${LESSON}"
stage_end ok

# rsync has to exist on the box BEFORE the first rsync, and a minimal cloud image does not ship it.
# This is the one step that must go over plain ssh.
stage_begin sync "copying the repo"
say "bootstrapping rsync on the box"
# shellcheck disable=SC2016  # expands on the box
box_ssh "${LESSON}" 'command -v rsync >/dev/null && exit 0
  if sudo -n true 2>/dev/null; then SUDO=sudo; else SUDO=""; fi
  export DEBIAN_FRONTEND=noninteractive
  $SUDO apt-get update -qq && $SUDO apt-get install -y -qq rsync >/dev/null'

say "copying the repo to ${BOX_USER}@${BOX_IP}:~/sandboxing-tutorial"
# --delete keeps the box a mirror of the tree, so a stale lesson file can never be what ran.
# results/ is excluded in BOTH directions: it is the box's output, and shipping ours up would let a
# laptop-recorded number masquerade as this box's measurement.
rsync -az --delete -e "$(box_rsync_shell "${LESSON}")" \
  --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude 'results' \
  --exclude '.state' --exclude '.ruff_cache' --exclude '.terraform' \
  "${REPO_ROOT}/" "box:sandboxing-tutorial/"
stage_end ok

stage_begin tooling "installing uv"
say "installing base tooling (uv)"
# Single-quoted on purpose: every expansion below must happen on the BOX, not here.
# shellcheck disable=SC2016
box_ssh "${LESSON}" 'set -e
  if sudo -n true 2>/dev/null; then SUDO=sudo; else SUDO=""; fi
  export DEBIAN_FRONTEND=noninteractive
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq curl ca-certificates jq >/dev/null
  if ! command -v uv >/dev/null; then curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1; fi
  echo "uv: $("$HOME"/.local/bin/uv --version 2>/dev/null || echo MISSING)"'
stage_end ok

for sub in $(lesson_substrates "${LESSON}"); do
  # One stage per substrate rather than one "substrates" stage, because they are the slowest and
  # most variable part of a lesson box — the Kata stack is 9.3 GB and the NAT guest builds a VM —
  # and "installing substrates, 11 minutes elapsed" tells you nothing about which one is slow.
  stage_begin "substrate:${sub}" "substrate ${sub}"
  say "substrate: ${sub}"
  # A substrate marked `# runs-as: user` must NOT be sudo'd. OpenShell's podman driver is rootless by
  # design, and installing its gateway as root produces a daemon that starts and then cannot reach
  # the user's podman socket — a failure that looks like a driver bug and is a privilege mistake.
  if head -8 "${HERE}/substrates/${sub}.sh" | grep -q '^# runs-as: user'; then
    box_ssh "${LESSON}" "bash sandboxing-tutorial/infra/substrates/${sub}.sh"
  else
    box_ssh "${LESSON}" "sudo bash sandboxing-tutorial/infra/substrates/${sub}.sh"
  fi

  # The NAT-guest substrate MOVES the lesson: everything after it runs inside the guest, reached
  # through the box we just provisioned. Re-point the state and re-sync the repo one hop further in.
  if [ "${sub}" = "50-nat-vm" ]; then
    GUEST_IP=$(box_ssh "${LESSON}" 'sudo sed -n "s/^GUEST_IP=//p" /etc/sandboxing-tutorial-guest.env')
    [ -n "${GUEST_IP}" ] || die "50-nat-vm did not report a guest IP"
    say "re-pointing ${LESSON} at the NAT'd guest ${GUEST_IP} (via ${BOX_IP})"
    state_save "${LESSON}" \
      "BOX_ID=${BOX_ID}" "BOX_IP=${GUEST_IP}" "BOX_USER=agent" \
      "BOX_KIND=${BOX_KIND}" "BOX_TYPE=${BOX_TYPE}" \
      "BOX_JUMP_IP=${BOX_IP}" "BOX_JUMP_USER=${BOX_USER}"
    state_load "${LESSON}"
    write_ssh_config "${LESSON}"
    box_wait_ssh "${LESSON}"
    rsync -az --delete -e "$(box_rsync_shell "${LESSON}")" \
      --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude 'results' \
      --exclude '.state' --exclude '.ruff_cache' --exclude '.terraform' \
      "${REPO_ROOT}/" "box:sandboxing-tutorial/"
    box_ssh "${LESSON}" 'command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1'
    emit box "lesson re-pointed at the NAT guest" "ip=${GUEST_IP}" "jump=${BOX_JUMP_IP}"
  fi
  stage_end ok
done

stage_begin check "asserting the boundary"
say "asserting the boundary from inside"
"${HERE}/check.sh" "${LESSON}"
stage_end ok

# Only a COMPLETE provision blesses the box. run.sh gates on this marker (its wait-box stage): a
# run started mid-up used to mirror the same tree concurrently with the sync stage above, and the
# two rsync --delete passes destroyed each other's temp files — the provision died as rsync rc 23,
# on a box that then looked broken and was merely half-built.
echo "BOX_READY=1" >>"$(state_file "${LESSON}")"

cat <<EOF

  ${LESSON} is up:  ${BOX_USER}@${BOX_IP}   (${BOX_TYPE}, EUR $(hourly_price "${TYPE}" "${KIND}")/hr, running now)

    ./run.sh  ${LESSON}      run the lesson on the box and fetch its scorecard
    ./ssh.sh  ${LESSON}      a shell on the box
    ./down.sh ${LESSON}      destroy it — this is what keeps the tutorial a EUR 1 tutorial

EOF
