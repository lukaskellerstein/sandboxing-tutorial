#!/usr/bin/env bash
# Shared helpers for the infra scripts. Sourced, never executed.
#
# The per-lesson hardware table lives in terraform/lessons.json and NOWHERE else. Terraform reads it
# with jsondecode(); this file reads the same bytes with jq. That is the whole reason it is JSON
# rather than .tfvars — a second, generated copy is how the two drift apart, and a drifted table
# means provisioning one box while the lesson believes it got another.

set -euo pipefail

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${INFRA_DIR}/.state"
TF_DIR="${INFRA_DIR}/terraform"
LESSONS_JSON="${TF_DIR}/lessons.json"

# Consumed by the scripts that source this file, which is invisible to shellcheck from in here.
# shellcheck disable=SC2034
REPO_ROOT="$(cd "${INFRA_DIR}/.." && pwd)"

# The throwaway keypair these boxes trust. Deliberately NOT your personal key: every box here runs a
# rogue-agent suite and is destroyed within the hour, so the credential that reaches it should be
# disposable too. Lives outside the repo, and no private key ever enters the tree.
SSH_KEY="${SANDBOXING_TUTORIAL_SSH_KEY:-${HOME}/.config/sandboxing-tutorial/id_ed25519}"
SSH_KEY_NAME="${SANDBOXING_TUTORIAL_SSH_KEY_NAME:-sandboxing-tutorial}"

ZONE="${SCW_DEFAULT_ZONE:-fr-par-1}"

die() {
  echo "FATAL: $*" >&2
  exit 1
}
say() { echo "==> $*"; }

# --- the lessons table -------------------------------------------------------

lesson_names() { jq -r 'keys[] | select(startswith("_") | not)' "${LESSONS_JSON}"; }

lesson_field() {
  local v
  v=$(jq -r --arg l "$1" --arg f "$2" '.[$l][$f] // empty' "${LESSONS_JSON}")
  [ -n "${v}" ] || die "lessons.json has no '$2' for '$1'. Known lessons: $(lesson_names | tr '\n' ' ')"
  echo "${v}"
}

lesson_kind() { lesson_field "$1" kind; }
lesson_type() { lesson_field "$1" type; }

# Substrate scripts, in order. An empty list is meaningful: lesson 1 IS the bare box.
lesson_substrates() {
  jq -r --arg l "$1" '.[$l].substrates[]?' "${LESSONS_JSON}"
}

# --- terraform ---------------------------------------------------------------
#
# `up` is the list of lessons Terraform should be maintaining. Every entry point recomputes it from
# the .state files rather than passing a single name, so an apply can never quietly destroy a box
# some other lesson is still using.

tf() { terraform -chdir="${TF_DIR}" "$@"; }

tf_init_once() {
  [ -d "${TF_DIR}/.terraform" ] || tf init -input=false -no-color >/dev/null
}

# Terraform maintains ONE set of boxes, and every apply names the whole set. Two infra commands
# running at once would each compute that set from its own stale snapshot, and the second would
# destroy what the first had just created — silently, because destroying an unwanted box is exactly
# what the second apply is for. `mkdir` is atomic on every filesystem this runs on, so it is the lock.
tf_lock() {
  local waited=0
  mkdir -p "${STATE_DIR}"
  until mkdir "${STATE_DIR}/.tf.lock" 2>/dev/null; do
    [ "${waited}" -eq 0 ] && say "another infra command holds the lock — waiting"
    sleep 2
    waited=$((waited + 2))
    [ "${waited}" -gt 1800 ] && die "timed out on ${STATE_DIR}/.tf.lock — delete it if nothing else is running"
  done
  # shellcheck disable=SC2064  # expand STATE_DIR now: the trap must not depend on later scope
  trap "rmdir '${STATE_DIR}/.tf.lock' 2>/dev/null || true" EXIT
}

# The lessons currently claimed: the union of what Terraform itself believes and what the .state
# cache says. Terraform's view is the authoritative half — a .state file can be deleted by hand,
# and rebuilding the set from the cache alone would then quietly destroy a live box.
current_up_json() {
  shopt -s nullglob
  local f names=() from_tf
  for f in "${STATE_DIR}"/*.env; do names+=("$(basename "${f}" .env)"); done
  from_tf=$(tf output -json up 2>/dev/null || echo '[]')
  printf '%s\n' "${names[@]+"${names[@]}"}" \
    | jq -R . \
    | jq -sc --argjson tf "${from_tf:-[]}" 'map(select(length > 0)) + $tf | unique'
}

# Apply with an explicit lesson set. Terraform is the authority on what exists; the .state files are
# only a convenience cache for the ssh helpers.
tf_apply() {
  local up_json="$1"
  tf_init_once
  tf_lock
  tf apply -input=false -auto-approve -no-color -var "up=${up_json}" >/dev/null
}

# Refresh one lesson's .state file from Terraform's outputs.
tf_state_sync() {
  local lesson="$1" box
  box=$(tf output -json boxes | jq -c --arg l "${lesson}" '.[$l] // empty')
  [ -n "${box}" ] || die "terraform has no box for '${lesson}'"
  mkdir -p "${STATE_DIR}"
  {
    echo "BOX_ID=$(jq -r .id <<<"${box}")"
    echo "BOX_IP=$(jq -r .ip <<<"${box}")"
    echo "BOX_USER=$(jq -r .user <<<"${box}")"
    echo "BOX_KIND=$(jq -r .kind <<<"${box}")"
    echo "BOX_TYPE=$(jq -r .type <<<"${box}")"
  } >"$(state_file "${lesson}")"
}

# --- state -------------------------------------------------------------------
#
# One file per lesson, holding the server id and IP. Gitignored: it names live, billable resources,
# and a stale one committed to a repo is how someone else's box gets destroyed.

state_file() { echo "${STATE_DIR}/$1.env"; }

state_save() {
  local lesson="$1"
  mkdir -p "${STATE_DIR}"
  shift
  printf '%s\n' "$@" >"$(state_file "${lesson}")"
}

state_load() {
  local f
  f="$(state_file "$1")"
  [ -f "${f}" ] || die "no box recorded for '$1' — run ./up.sh $1 first."
  # shellcheck disable=SC1090  # path is computed; there is nothing to follow at lint time
  source "${f}"
}

# --- ssh ---------------------------------------------------------------------
#
# Every hop goes through a GENERATED ssh config rather than a pile of -o flags. One lesson (5) does
# not run on the box we provisioned at all: it runs inside a NAT'd guest VM on that box, reached
# through it. Expressing that as a ProxyJump in a config file keeps `ssh`, `rsync` and `scp` all
# working with the same one-word host alias, where hand-built flag arrays would need three different
# quoting rules for the same two hops.

ssh_config_file() { echo "${STATE_DIR}/$1.sshcfg"; }

write_ssh_config() {
  local lesson="$1" cfg
  state_load "${lesson}"
  cfg="$(ssh_config_file "${lesson}")"
  {
    echo "Host box"
    echo "  HostName ${BOX_IP}"
    echo "  User ${BOX_USER}"
    [ -n "${BOX_JUMP_IP:-}" ] && echo "  ProxyJump jump"
    if [ -n "${BOX_JUMP_IP:-}" ]; then
      echo
      echo "Host jump"
      echo "  HostName ${BOX_JUMP_IP}"
      echo "  User ${BOX_JUMP_USER}"
    fi
    echo
    echo "Host box jump"
    echo "  IdentityFile ${SSH_KEY}"
    echo "  IdentitiesOnly yes"
    # Host keys legitimately change every time a box is reinstalled, and we cause every reinstall —
    # so a known-hosts entry here is pure friction that presents as a MITM warning.
    echo "  StrictHostKeyChecking no"
    echo "  UserKnownHostsFile /dev/null"
    echo "  LogLevel ERROR"
    echo "  ConnectTimeout 10"
    echo "  ServerAliveInterval 15"
    echo "  ServerAliveCountMax 8"
  } >"${cfg}"
}

# Both entry points regenerate the config from the state file first. It is a few lines of I/O, and
# it removes a whole class of ordering bug: any script that reaches a box works whether or not some
# earlier step happened to have written the config, and the config can never describe a stale IP.
box_ssh() {
  local lesson="$1"
  shift
  write_ssh_config "${lesson}"
  ssh -F "$(ssh_config_file "${lesson}")" box "$@"
}

# The box we PROVISIONED, as opposed to wherever the lesson ended up running. For lesson 5 those are
# different machines: the lesson runs inside a NAT'd guest, but questions about the hypervisor —
# "is the guest domain running?" — can only be answered by the host underneath it. Asking the guest
# gets `virsh: command not found`, which reads as a failed boundary rather than a wrong addressee.
box_ssh_host() {
  local lesson="$1"
  shift
  write_ssh_config "${lesson}"
  state_load "${lesson}"
  if [ -n "${BOX_JUMP_IP:-}" ]; then
    ssh -F "$(ssh_config_file "${lesson}")" jump "$@"
  else
    ssh -F "$(ssh_config_file "${lesson}")" box "$@"
  fi
}

# The `-e` value rsync needs, so it takes the same hops as box_ssh.
box_rsync_shell() {
  write_ssh_config "$1"
  echo "ssh -F $(ssh_config_file "$1")"
}

# Wait for sshd to answer as the login user. A box reports "ready" long before it is reachable, and
# sshd flaps during first boot — so require two consecutive successes, not one.
box_wait_ssh() {
  local lesson="$1" tries="${2:-60}" ok=0 i
  state_load "${lesson}"
  write_ssh_config "${lesson}"
  for ((i = 1; i <= tries; i++)); do
    if box_ssh "${lesson}" true 2>/dev/null; then
      ok=$((ok + 1))
      if [ "${ok}" -ge 2 ]; then
        say "ssh is up (${BOX_USER}@${BOX_IP})"
        return 0
      fi
    else
      ok=0
    fi
    sleep 10
  done
  die "ssh to ${BOX_IP} never came up. If ping works but ssh hangs, this is the MTU trap:
       run 'sudo ifconfig \$(route -n get default | awk \"/interface/{print \\\$2}\") mtu 1400' and retry."
}

# Cloud-init has to finish before a lesson may touch the box: it is what creates the unprivileged
# `agent` user and enables lingering. sshd answers before that is done.
box_wait_cloud_init() {
  # shellcheck disable=SC2016  # single-quoted on purpose: this must expand on the box, not here
  box_ssh "$1" 'command -v cloud-init >/dev/null || exit 0
    sudo cloud-init status --wait >/dev/null 2>&1 || true
    printf "    cloud-init: %s\n" "$(cloud-init status 2>/dev/null | head -1)"'
}

# --- misc --------------------------------------------------------------------

require_key() {
  [ -f "${SSH_KEY}" ] || die "no ssh key at ${SSH_KEY}.
       Generate one and register it:  ssh-keygen -t ed25519 -N '' -f ${SSH_KEY}
                                      scw iam ssh-key create name=${SSH_KEY_NAME} public-key=\"\$(cat ${SSH_KEY}.pub)\""
  scw iam ssh-key list -o json \
    | jq -e --arg n "${SSH_KEY_NAME}" 'any(.[]; .name == $n)' >/dev/null \
    || die "ssh key '${SSH_KEY_NAME}' is not registered with Scaleway IAM."
}

# Live price from the Scaleway catalogue, never a hardcoded table. A cost warning that has silently
# gone stale is worse than none, and the old two-entry lookup returned "?" for every type it did not
# know — which is exactly what happens the moment lessons.json changes.
hourly_price() {
  local type="$1" kind="$2" p
  if [ "${kind}" = "baremetal" ]; then
    p=$(scw baremetal offer list zone="${ZONE}" -o json 2>/dev/null \
      | jq -r --arg t "${type}" 'first(.[] | select(.name == $t)) | ((.price_per_hour.units // 0) + ((.price_per_hour.nanos // 0) / 1e9))')
  else
    p=$(scw instance server-type list zone="${ZONE}" -o json 2>/dev/null \
      | jq -r --arg t "${type}" 'first(.[] | select(.name == $t)) | ((.hourly_price.units // 0) + ((.hourly_price.nanos // 0) / 1e9))')
  fi
  [ -n "${p}" ] && [ "${p}" != "null" ] && printf '%.4f' "${p}" || echo "?"
}
