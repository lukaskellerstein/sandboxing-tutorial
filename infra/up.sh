#!/usr/bin/env bash
# Bring up ONE lesson's box: provision it with the scw CLI, copy the repo onto it, install the
# substrates that lesson needs, and assert each boundary FROM INSIDE.
#
#   ./up.sh 1.2.2
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
  # BOX is its own column because it is the one thing this table cannot leave implicit: four rows
  # showing identical hardware are not four machines. `(own)` is the normal case — one disposable
  # box per lesson — and a name there means the row shares that machine with its whole chapter.
  printf '%-30s %-16s %-10s %-14s %s\n' LESSON BOX KIND TYPE SUBSTRATES
  while read -r l; do
    b=$(lesson_box "${l}")
    [ "${b}" = "${l}" ] && b="(own)"
    printf '%-30s %-16s %-10s %-14s %s\n' "${l}" "${b}" "$(lesson_kind "${l}")" "$(lesson_type "${l}")" \
      "$(lesson_substrates "${l}" | tr '\n' ' ')"
  done < <(lesson_names)
  exit 0
fi

LESSON="${1:?usage: ./up.sh <lesson>   (./up.sh --list)}"
lesson_kind "${LESSON}" >/dev/null # validates the name against lessons.json

# Everything below this line provisions a MACHINE, and the machine is not always named after the
# lesson: chapter 3's four lessons all resolve to `chapter-03-k8s`, one cluster carrying every
# boundary in the chapter. Resolve once, here, so that every box_* call, every state file and every
# message below names the thing that actually exists in the Scaleway account — and so that
# `./up.sh 1.3.2` is simply an alias for bringing that cluster up, idempotently.
BOX=$(lesson_box "${LESSON}")
[ "${BOX}" = "${LESSON}" ] || say "${LESSON} shares its cluster with the rest of its chapter — provisioning ${BOX}"

KIND=$(lesson_kind "${BOX}")
TYPE=$(lesson_type "${BOX}")

require_key

# --- cancel safety ------------------------------------------------------------
#
# Turn a cancel signal into a normal exit so the shell tears down cleanly. There is nothing to undo
# here beyond that: box_create writes the .state file the instant it has an id, so a box that exists
# is always tracked and tearable, and destroying-on-cancel is the supervisor's job (ctl.py runs
# down.sh, which finds the box by id or, if the create died before recording, by name). No lock to
# release, because there is no lock — each box is independent.
trap 'exit 130' INT TERM

if [ -f "$(state_file "${BOX}")" ]; then
  state_load "${BOX}"
  say "${BOX} already has a box: ${BOX_ID} (${BOX_IP}). ./down.sh ${BOX} to destroy it."
  exit 0
fi

# Below the early exit above on purpose: "already has a box" does no work, and recording it as a run
# would replace this lesson's last real provision with an empty one in every watcher's history.
run_track up "${BOX}"

stage_begin provision "provisioning ${KIND} ${TYPE}"
say "provisioning ${BOX}: ${KIND} ${TYPE} in ${ZONE} — EUR $(hourly_price "${TYPE}" "${KIND}")/hr"
# One independent box, created by the scw CLI. No shared state, no lock, no "maintain the whole set"
# apply — so starting several `up`s at once just works: each creates its own box concurrently and
# nothing any of them does can drop another's box.
box_create "${BOX}"
state_load "${BOX}"
say "${BOX} → ${BOX_USER}@${BOX_IP}  (${BOX_ID})"
emit box "box allocated" "id=${BOX_ID}" "ip=${BOX_IP}" "type=${BOX_TYPE}" "kind=${BOX_KIND}"
stage_end ok

stage_begin ssh "waiting for sshd"
box_wait_ssh "${BOX}"
stage_end ok

# cloud-init is what creates the unprivileged `agent` user and enables lingering, and sshd answers
# before it has finished. Touching the box first produces failures that look like permissions bugs.
stage_begin cloud-init "waiting for cloud-init"
box_wait_cloud_init "${BOX}"
stage_end ok

# rsync has to exist on the box BEFORE the first rsync, and a minimal cloud image does not ship it.
# This is the one step that must go over plain ssh.
stage_begin sync "copying the repo"
say "bootstrapping rsync on the box"
# shellcheck disable=SC2016  # expands on the box
box_ssh "${BOX}" 'command -v rsync >/dev/null && exit 0
  if sudo -n true 2>/dev/null; then SUDO=sudo; else SUDO=""; fi
  export DEBIAN_FRONTEND=noninteractive
  $SUDO apt-get update -qq && $SUDO apt-get install -y -qq rsync >/dev/null'

say "copying the repo to ${BOX_USER}@${BOX_IP}:~/sandboxing-tutorial"
# --delete keeps the box a mirror of the tree, so a stale lesson file can never be what ran.
# results/ is excluded in BOTH directions: it is the box's output, and shipping ours up would let a
# laptop-recorded number masquerade as this box's measurement.
rsync -az --delete -e "$(box_rsync_shell "${BOX}")" \
  --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude 'results' \
  --exclude '.state' --exclude '.ruff_cache' --exclude '.terraform' \
  "${REPO_ROOT}/" "box:sandboxing-tutorial/"
stage_end ok

stage_begin tooling "installing uv"
say "installing base tooling (uv)"
# Single-quoted on purpose: every expansion below must happen on the BOX, not here.
# shellcheck disable=SC2016
box_ssh "${BOX}" 'set -e
  if sudo -n true 2>/dev/null; then SUDO=sudo; else SUDO=""; fi
  export DEBIAN_FRONTEND=noninteractive
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq curl ca-certificates jq >/dev/null
  if ! command -v uv >/dev/null; then curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1; fi
  echo "uv: $("$HOME"/.local/bin/uv --version 2>/dev/null || echo MISSING)"'
stage_end ok

for sub in $(lesson_substrates "${BOX}"); do
  # One stage per substrate rather than one "substrates" stage, because they are the slowest and
  # most variable part of a lesson box — the Kata stack is 9.3 GB and the NAT guest builds a VM —
  # and "installing substrates, 11 minutes elapsed" tells you nothing about which one is slow.
  stage_begin "substrate:${sub}" "substrate ${sub}"
  say "substrate: ${sub}"
  # A substrate marked `# runs-as: user` must NOT be sudo'd. OpenShell's podman driver is rootless by
  # design, and installing its gateway as root produces a daemon that starts and then cannot reach
  # the user's podman socket — a failure that looks like a driver bug and is a privilege mistake.
  if head -8 "${HERE}/substrates/${sub}.sh" | grep -q '^# runs-as: user'; then
    box_ssh "${BOX}" "bash sandboxing-tutorial/infra/substrates/${sub}.sh"
  else
    box_ssh "${BOX}" "sudo bash sandboxing-tutorial/infra/substrates/${sub}.sh"
  fi

  # The NAT-guest substrate MOVES the lesson: everything after it runs inside the guest, reached
  # through the box we just provisioned. Re-point the state and re-sync the repo one hop further in.
  # Basename, because substrates are named by chapter now (`chapter-2/50-nat-vm`). Comparing the
  # full path here would silently never match, and the symptom would be lesson 1.2.4 running on the BOX
  # instead of inside its NAT'd guest — which is exactly the lesson's whole point, failing quietly.
  if [ "${sub##*/}" = "50-nat-vm" ]; then
    GUEST_IP=$(box_ssh "${BOX}" 'sudo sed -n "s/^GUEST_IP=//p" /etc/sandboxing-tutorial-guest.env')
    [ -n "${GUEST_IP}" ] || die "50-nat-vm did not report a guest IP"
    say "re-pointing ${BOX} at the NAT'd guest ${GUEST_IP} (via ${BOX_IP})"
    state_save "${BOX}" \
      "BOX_ID=${BOX_ID}" "BOX_IP=${GUEST_IP}" "BOX_USER=agent" \
      "BOX_KIND=${BOX_KIND}" "BOX_TYPE=${BOX_TYPE}" \
      "BOX_JUMP_IP=${BOX_IP}" "BOX_JUMP_USER=${BOX_USER}"
    state_load "${BOX}"
    write_ssh_config "${BOX}"
    box_wait_ssh "${BOX}"
    rsync -az --delete -e "$(box_rsync_shell "${BOX}")" \
      --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude 'results' \
      --exclude '.state' --exclude '.ruff_cache' --exclude '.terraform' \
      "${REPO_ROOT}/" "box:sandboxing-tutorial/"
    box_ssh "${BOX}" 'command -v uv >/dev/null || curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null 2>&1'
    emit box "lesson re-pointed at the NAT guest" "ip=${GUEST_IP}" "jump=${BOX_JUMP_IP}"
  fi
  stage_end ok
done

stage_begin check "asserting the boundary"
say "asserting the boundary from inside"
"${HERE}/check.sh" "${BOX}"
stage_end ok

# Only a COMPLETE provision blesses the box. run.sh gates on this marker (its wait-box stage): a
# run started mid-up used to mirror the same tree concurrently with the sync stage above, and the
# two rsync --delete passes destroyed each other's temp files — the provision died as rsync rc 23,
# on a box that then looked broken and was merely half-built.
echo "BOX_READY=1" >>"$(state_file "${BOX}")"

cat <<EOF

  ${BOX} is up:  ${BOX_USER}@${BOX_IP}   (${BOX_TYPE}, EUR $(hourly_price "${TYPE}" "${KIND}")/hr, running now)

EOF

# `run` takes a LESSON, never a box — there is no tutorial/phase1-attacks/chapter-03-k8s to cd into. On a shared
# cluster the two names have come apart, so print the ones that actually work rather than a
# copy-pasteable command that dies with "no such directory".
if [ "${BOX}" = "${LESSON}" ]; then
  cat <<EOF
    ./run.sh  ${LESSON}      run the lesson on the box and fetch its scorecard
    ./ssh.sh  ${LESSON}      a shell on the box
    ./down.sh ${LESSON}      destroy it — this is what keeps the tutorial a EUR 1 tutorial

EOF
else
  cat <<EOF
    ./run.sh  <lesson>       run any of $(lesson_names | while read -r l; do [ "$(lesson_box "${l}")" = "${BOX}" ] && printf '%s ' "${l}"; done)
    ./ssh.sh  ${BOX}   a shell on the cluster
    ./down.sh ${BOX}   destroy it — every lesson above runs on this ONE box

EOF
fi
