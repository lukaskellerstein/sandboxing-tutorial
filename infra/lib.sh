#!/usr/bin/env bash
# Shared helpers for the infra scripts. Sourced, never executed.
#
# Boxes are provisioned with the `scw` CLI directly — no Terraform, no shared state file, no lock.
# Each box is INDEPENDENT: created and destroyed by its own id, tracked in .state/<lesson>.env. That
# independence is the whole reason up / down / parallel-provision / cancel are simple here — there is
# no "maintain the whole set" apply that a second command can race, and destroying one box is a
# single terminate by id that cannot touch another. The account is the source of truth; .state is a
# cache; `down.sh --all` sweeps anything untracked.
#
# The per-lesson hardware table lives in lessons.json and NOWHERE else, read here with jq.

set -euo pipefail

INFRA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR="${INFRA_DIR}/.state"
LESSONS_JSON="${INFRA_DIR}/lessons.json"
CLOUD_INIT_TMPL="${INFRA_DIR}/cloud-init.yaml.tmpl"
STAGES_JSON="${INFRA_DIR}/stages.json"

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
  emit stage_fail "$*"
  exit 1
}
say() {
  echo "==> $*"
  hb_reset
}

# --- events ------------------------------------------------------------------
#
# One structured line per interesting moment, for whatever is watching. Appended to the file named
# by SBX_EVENT_FILE, which ctl.py sets and tails; with nothing set, every function here is a no-op
# and the scripts print exactly what they always printed.
#
# That no-op is the load-bearing part. `./up.sh 1.2.3` typed by hand must never become dependent
# on a supervisor existing — the scripts are the tutorial's real interface, and ctl.py is a client
# of them rather than the other way round.
#
# A FILE and not a file descriptor, deliberately: `>&"${fd}"` needs a bash new enough that relying
# on it would make these scripts fail on macOS's system bash, and for a handful of lines per stage
# an O_APPEND write is every bit as good and works in any shell.

SBX_STAGE=""
SBX_STAGE_T0=0
SBX_HB_LAST=0
#: The open stage and the open substage inside it, kept apart because SBX_STAGE holds the COMPOSED
#: id (`api/bootkube`) that goes on the wire, and closing a substage has to restore the parent's.
SBX_PARENT=""
SBX_SUB=""
SBX_SUB_T0=0
# Set by run_track below. Read by the drivers that source this file, which shellcheck cannot see.
# shellcheck disable=SC2034
SBX_RUN_LOG=""
SBX_RUN_T0=0

# Seconds as `7m12s` / `48s`. Durations here are read by a human deciding whether to keep waiting.
fmt_dur() {
  local s="${1:-0}"
  if [ "${s}" -ge 3600 ]; then
    printf '%dh%02dm' $((s / 3600)) $(((s % 3600) / 60))
  elif [ "${s}" -ge 60 ]; then
    printf '%dm%02ds' $((s / 60)) $((s % 60))
  else
    printf '%ds' "${s}"
  fi
}

# emit <event> <msg> [key=value ...]
emit() {
  [ -n "${SBX_EVENT_FILE:-}" ] || return 0
  local event="${1:-log}" msg="${2:-}"
  # Drop the two positional args we have already read, so what remains is exactly the key=value
  # tail. `set --` rather than `shift 2` when there is no tail: shifting more than $# is an error,
  # and this runs inside `die`, where a spurious failure would replace the real exit status.
  if [ "$#" -gt 2 ]; then shift 2; else set --; fi
  local data='{}'
  [ "$#" -gt 0 ] && data=$(printf '%s\n' "$@" \
    | jq -Rn '[inputs | select(length > 0) | split("=") | {(.[0]): (.[1:] | join("="))}] | add // {}' 2>/dev/null || echo '{}')
  jq -cn \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg stage "${SBX_STAGE}" \
    --arg event "${event}" \
    --arg msg "${msg}" \
    --argjson data "${data}" \
    '{ts: $ts, stage: $stage, event: $event, msg: $msg, data: $data}' >>"${SBX_EVENT_FILE}" 2>/dev/null || true
}

# The measured duration of a stage, from stages.json. Zero when unknown, which the callers render as
# "no estimate" rather than as "instant".
stage_expect() {
  jq -r --arg p "$1" --arg s "$2" \
    'first(.[$p].stages[]? | select(.id == $s) | .expect_s) // 0' "${STAGES_JSON}" 2>/dev/null || echo 0
}

stage_begin() {
  SBX_STAGE="$1"
  SBX_PARENT="$1"
  SBX_SUB=""
  SBX_STAGE_T0=$(date +%s)
  SBX_HB_LAST="${SBX_STAGE_T0}"
  emit stage_start "${2:-$1}"
}

# stage_end ok|fail [msg]
stage_end() {
  # Close an open substage with the parent's own verdict first, or it stays "running" in every
  # watcher for the rest of time — the same failure the parent-level bracketing already guards.
  [ -z "${SBX_SUB}" ] || substage_end "$1" "${2:-}"
  emit "stage_$1" "${2:-}" "elapsed_s=$(($(date +%s) - SBX_STAGE_T0))"
  SBX_STAGE=""
  SBX_PARENT=""
}

# --- substages ----------------------------------------------------------------
#
# `substage_begin <id> [title]` — a step INSIDE the stage that is currently open, for the few stages
# long enough that "still in `api`, 41 minutes" is not an answer. It is emitted as an ORDINARY
# stage_start whose id is `parent/child`, deliberately: no new event type, no new field, readers that
# know nothing about substages skip an id they cannot find in their table, and `die` attributes a
# failure to the substage it happened in for free (SBX_STAGE is the composed id while one is open).
#
# A substage must be DECLARED in stages.json under its parent, for the same reason the parents are:
# a watcher can only show a step as pending, or attribute a duration to it, if it knew about it
# beforehand. Emitting one the manifest does not list makes it invisible rather than wrong.
substage_begin() {
  # No open stage means nothing to nest under, and a `parent/child` id with an empty parent would be
  # a top-level stage no table has. Silently doing nothing is right: substages are an annotation.
  [ -n "${SBX_PARENT}" ] || return 0
  [ -z "${SBX_SUB}" ] || substage_end ok
  SBX_SUB="$1"
  SBX_SUB_T0=$(date +%s)
  SBX_STAGE="${SBX_PARENT}/${SBX_SUB}"
  emit stage_start "${2:-$1}"
}

# substage_end ok|fail [msg]
substage_end() {
  [ -n "${SBX_SUB}" ] || return 0
  emit "stage_$1" "${2:-}" "elapsed_s=$(($(date +%s) - SBX_SUB_T0))"
  SBX_SUB=""
  SBX_STAGE="${SBX_PARENT}"
}

# A life sign for poll loops that can legitimately go quiet for minutes. `hb <expected_seconds>`,
# called every iteration; it prints at most once every 90 s and resets whenever anything else does.
#
# This exists because a stage that prints nothing is indistinguishable from one that has hung, and
# on this repo's most expensive box the difference is 37 minutes of a stalled rollout that looked
# exactly like a slow one (install.sh's node_dns comment). REPRODUCE.md section 3b already warns
# "a quiet monitor is not a stalled process" — in prose, which no terminal ever displays.
hb() {
  local expect="${1:-0}" now el
  now=$(date +%s)
  [ $((now - SBX_HB_LAST)) -ge 90 ] || return 0
  SBX_HB_LAST="${now}"
  el=$((now - SBX_STAGE_T0))
  if [ "${expect}" -gt 0 ]; then
    printf '    [%s]     ... %s in this stage (measured ~%s)\n' \
      "$(date +%H:%M:%S)" "$(fmt_dur "${el}")" "$(fmt_dur "${expect}")"
  else
    printf '    [%s]     ... %s in this stage\n' "$(date +%H:%M:%S)" "$(fmt_dur "${el}")"
  fi
  emit progress "still working" "elapsed_s=${el}" "expect_s=${expect}"
}

hb_reset() { SBX_HB_LAST=$(date +%s); }

# --- run tracking -------------------------------------------------------------
#
# `run_track <op> <target> [logfile]`, called once at the top of a driver, so a run started BY HAND
# leaves exactly the trail a supervised one does: the structured event stream, a durable log, and the
# `current.json` that ctl.py and the panel read to find both.
#
# It exists because visibility used to be a property of HOW a script was started rather than of the
# script. `./ctl.py up openshift-sno` was watchable stage by stage; `./openshift-sno/install.sh` —
# the form the runbook actually prints, and the one people type — emitted nothing at all, so two
# hours of cluster install had no answer to "which stage is it in". The stage table already existed;
# only the event file was missing.
#
# Under ctl.py this returns immediately: the supervisor made all three files before it started us and
# already set SBX_EVENT_FILE. Forking the stream in two is how a watcher comes to render half a run.
run_track() {
  local op="$1" target="$2" log="${3:-}" dir stamp
  [ -z "${SBX_EVENT_FILE:-}" ] || return 0
  dir="${STATE_DIR}/${target}"
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  SBX_EVENT_FILE="${dir}/run-${stamp}.ndjson"
  SBX_RUN_LOG="${log:-${dir}/run-${stamp}.log}"
  SBX_OP="${op}:${target}"
  SBX_RUN_T0=$(date +%s)
  export SBX_EVENT_FILE SBX_OP
  mkdir -p "${dir}" "$(dirname "${SBX_RUN_LOG}")"
  # `external: true` is the one thing ctl.py cannot work out for itself: this run has no supervisor,
  # so cancelling it cannot be followed by an automatic teardown, and `stop` has to say so rather
  # than imply the box is being cleaned up.
  jq -n \
    --arg op "${op}" --arg target "${target}" --arg argv "$0" \
    --arg events "${SBX_EVENT_FILE}" --arg log "${SBX_RUN_LOG}" \
    --arg started "${stamp}" --argjson pid "$$" --argjson t0 "${SBX_RUN_T0}" \
    '{op: $op, target: $target, pid: $pid, external: true, argv: [$argv],
      events: $events, log: $log, started_epoch: $t0, started: $started}' >"${dir}/current.json"
  # Turn a cancel into a normal exit, so the EXIT trap below still runs: bash does NOT run an EXIT
  # trap when it dies of an untrapped signal, and a run that ends with no `op_end` leaves every
  # watcher showing a stage as running forever. up.sh sets the same trap for its own reasons and
  # must keep doing so — under ctl.py this function returns before ever reaching here.
  trap 'exit 130' INT TERM
  trap 'run_track_end "$?"' EXIT
  emit op_start "${op} ${target}" "argv=$0"
  # Every byte the run printed, on disk. This box has no console when it goes dark, and the panel's
  # log pane tails exactly this file.
  exec > >(tee -a "${SBX_RUN_LOG}") 2>&1
}

# The EXIT half. It closes an open stage first: a run killed mid-stage otherwise leaves that stage
# looking like it is still going, to every watcher, forever.
run_track_end() {
  local rc="${1:-0}" status
  case "${rc}" in
    0) status=ok ;;
    130 | 143) status=cancelled ;;
    *) status=fail ;;
  esac
  [ -z "${SBX_STAGE}" ] || stage_end fail "${status}"
  emit op_end "${SBX_OP:-run} finished" \
    "status=${status}" "rc=${rc}" "elapsed_s=$(($(date +%s) - ${SBX_RUN_T0:-0}))"
}

# --- the lessons table -------------------------------------------------------

lesson_names() { jq -r 'keys[] | select(startswith("_") | not)' "${LESSONS_JSON}"; }

lesson_field() {
  local v
  v=$(jq -r --arg l "$1" --arg f "$2" '.[$l][$f] // empty' "${LESSONS_JSON}")
  [ -n "${v}" ] || die "lessons.json has no '$2' for '$1'. Known lessons: $(lesson_names | tr '\n' ' ')"
  echo "${v}"
}

# The box a lesson RUNS ON — usually itself, because one disposable box per lesson is the model.
# Chapter 3's four lessons instead carry `"box": "chapter-03-k8s"` and share one cluster, so that the
# runtime each of them selects is a real choice from a menu where the other three are installed and
# working beside it. A shared lesson keeps its own identity everywhere else: its directory, its
# report, its run history. Only the machine is shared.
#
# `// $l` means every other lesson resolves to itself, so callers never branch on whether sharing is
# in play. It is also why an unknown name survives this and dies with a useful message downstream,
# in lesson_field, rather than here with a jq error.
lesson_box() { jq -r --arg l "$1" '.[$l].box // $l' "${LESSONS_JSON}"; }

# --- the id <-> leaf-path resolver -------------------------------------------
#
# A lesson's id is `P.C.L`, DERIVED from where its leaf sits in the tree — phase number from
# `phaseP-*`, chapter number from `chapter-C-*`, leaf number from `lesson-LL-*`. The tree is the one
# place that mapping lives; the id is computed, never stored a second time. These two functions are
# the only implementation of that computation in bash, and render.py/overall.py's ids.py is its twin.

# id (P.C.L) -> repo-relative leaf path. Exactly one match; zero or many is a broken tree, the same
# "no silent first-wins" contract run.sh's old name-glob carried.
lesson_relpath() {
  local id="$1" p c l pad match="" d
  IFS=. read -r p c l <<<"${id}"
  [ -n "${p}" ] && [ -n "${c}" ] && [ -n "${l}" ] || die "not a dotted lesson id: '${id}' (want P.C.L)"
  pad=$(printf '%02d' "$((10#${l}))" 2>/dev/null) || die "lesson id '${id}' has a non-numeric leaf part"
  for d in "${REPO_ROOT}"/tutorial/phase"${p}"-*/chapter-"${c}"-*/lesson-"${pad}"-*; do
    [ -d "${d}" ] || continue
    [ -z "${match}" ] || die "lesson id ${id} matches more than one leaf directory"
    match="${d#"${REPO_ROOT}"/}"
  done
  [ -n "${match}" ] || die "no leaf directory for lesson id ${id} (tutorial/phase${p}-*/chapter-${c}-*/lesson-${pad}-*)"
  echo "${match}"
}

# leaf directory -> its dotted id, read from the three folder number prefixes. The inverse of
# lesson_relpath; each leaf run.sh reads the same three basenames inline so it stays standalone.
lesson_id_of_dir() {
  local dir="$1" p c l
  p=$(basename "$(dirname "$(dirname "${dir}")")")
  p=${p#phase}
  p=${p%%-*}
  c=$(basename "$(dirname "${dir}")")
  c=${c#chapter-}
  c=${c%%-*}
  l=$(basename "${dir}")
  l=${l#lesson-}
  l=${l%%-*}
  echo "${p}.${c}.$((10#${l}))"
}

# Hardware belongs to the BOX, never to the lesson, so these resolve through lesson_box first. That
# is what lets a shared lesson carry no kind/type/image of its own — duplicating those onto all four
# would be the "generated second copy" lessons.json's own header warns drifts.
lesson_kind() { lesson_field "$(lesson_box "$1")" kind; }
lesson_type() { lesson_field "$(lesson_box "$1")" type; }

# Substrate scripts, in order. An empty list is meaningful: lesson 1.1.1 IS the bare box.
# Read from the BOX: the substrates are what is installed on the machine, and on a shared cluster all
# four lessons see the same set.
lesson_substrates() {
  jq -r --arg l "$(lesson_box "$1")" '.[$l].substrates[]?' "${LESSONS_JSON}"
}

# --- provisioning (scw, one independent box per lesson) ----------------------
#
# No Terraform and no lock: each box is created and destroyed by its own id. box_create writes the
# .state file the instant it has an id — BEFORE the IP wait — so a process killed mid-create still
# leaves a tracked, tearable box rather than an invisible orphan. Anything the account holds that has
# no .state file is caught by down.sh's prefix sweep.

# The Scaleway console name for a lesson's box: `sbx-<key>`. The one place that mapping lives
# (down.sh's sweep and by-name teardown reuse it). A Scaleway name cannot carry dots, so a dotted
# lesson id (`1.1.1`, for a lesson on its own box) is slugged to `sbx-1-1-1`; a descriptive box name
# (`chapter-02-host`) is unchanged. The legacy `lesson-` strip is kept so an old-style name still maps.
box_slug() { echo "${1//./-}"; }
box_name() { echo "sbx-$(box_slug "${1#lesson-}")"; }

# The first IPv4 address in an instance's JSON, tolerating both the `public_ips[]` array and the
# older singular `public_ip`. Empty when none is assigned yet.
box_json_ipv4() {
  jq -r 'first((.public_ips // [])[] | select(.family == "inet") | .address) // (.public_ip.address // "")'
}

# Render cloud-init for one lesson: substitute the two placeholders the template carries. sed is
# safe here — the ssh key is a single line of base64 (no `|`, `&` or newlines) and the hostname is a
# lesson name. Prints the path of a temp file the caller is responsible for removing.
render_cloud_init() {
  local lesson="$1" pub out host
  pub=$(cat "${SSH_KEY}.pub")
  # A dotted lesson id would become a dotted hostname (read as host.domain); slug it like box_name.
  host=$(box_slug "${lesson}")
  out=$(mktemp "${TMPDIR:-/tmp}/sbx-cloud-init.XXXXXX")
  sed -e "s|\${hostname}|${host}|g" -e "s|\${ssh_public_key}|${pub}|g" "${CLOUD_INIT_TMPL}" >"${out}"
  echo "${out}"
}

# Create this lesson's box and write .state/<lesson>.env. The caller (up.sh) guards against an
# existing box first. Dispatches on kind; baremetal is the shared OpenShift cluster only.
box_create() {
  local lesson="$1" kind
  kind=$(lesson_kind "${lesson}")
  if [ "${kind}" = "baremetal" ]; then
    box_create_baremetal "${lesson}"
  else
    box_create_vm "${lesson}"
  fi
}

box_create_vm() {
  local lesson="$1" type image gb voltype name ci out id ip tries
  type=$(lesson_type "${lesson}")
  image=$(lesson_field "${lesson}" image)
  gb=$(jq -r --arg l "${lesson}" '.[$l].root_volume_gb // 20' "${LESSONS_JSON}")
  # PLAY2 (every current lesson) has NO local storage — its root volume is Block SSD (sbs), and
  # `root-volume=local:` fails with "couldn't find a local image for this commercial type". sbs is
  # the default; a future lesson on a local-volume family (DEV1/GP1) sets root_volume_type: "local".
  voltype=$(jq -r --arg l "${lesson}" '.[$l].root_volume_type // "sbs"' "${LESSONS_JSON}")
  name=$(box_name "${lesson}")
  ci=$(render_cloud_init "${lesson}")

  # dynamic-ip-required: a dynamic IPv4 that dies with the box — never a flexible IP, which keeps
  # billing after the server is gone (the orphan this repo exists not to leave). -w waits until the
  # server is running, by which point the dynamic IP is assigned.
  out=$(scw instance server create \
    name="${name}" type="${type}" image="${image}" zone="${ZONE}" \
    root-volume="${voltype}:${gb}GB" dynamic-ip-required=true \
    cloud-init=@"${ci}" \
    tags.0=sandboxing-tutorial tags.1="${lesson}" tags.2=disposable \
    -w -o json) || {
    rm -f "${ci}"
    die "scw instance server create failed for ${lesson}"
  }
  rm -f "${ci}"

  id=$(jq -r '.id // empty' <<<"${out}")
  [ -n "${id}" ] || die "${lesson}: scw create returned no server id"
  # Record the box the instant we have its id — before the IP wait — so it is never untracked.
  state_save "${lesson}" \
    "BOX_ID=${ZONE}/${id}" "BOX_IP=" "BOX_USER=agent" "BOX_KIND=vm" "BOX_TYPE=${type}"

  ip=$(box_json_ipv4 <<<"${out}")
  tries=0
  while [ -z "${ip}" ] && [ "${tries}" -lt 30 ]; do
    sleep 4
    ip=$(scw instance server get "${id}" zone="${ZONE}" -o json 2>/dev/null | box_json_ipv4)
    tries=$((tries + 1))
  done
  [ -n "${ip}" ] || die "${lesson}: box ${id} created but no public IPv4 appeared (still tracked — ./down.sh ${lesson})"
  state_save "${lesson}" \
    "BOX_ID=${ZONE}/${id}" "BOX_IP=${ip}" "BOX_USER=agent" "BOX_KIND=vm" "BOX_TYPE=${type}"
}

# Elastic Metal, for the shared OpenShift cluster ONLY. NOTE: migrated from Terraform but NOT
# live-verified — a metal box is EUR 0.263/hr and its OS install is ~10-15 min, so it is not
# provisioned casually. The flags mirror the old Terraform module (offer, Ubuntu 24.04 OS id, the
# throwaway IAM key, `ubuntu` login). Verify on the next real cluster build.
box_create_baremetal() {
  local lesson="$1" type osid keyid out id ip tries
  type=$(lesson_type "${lesson}")
  osid=$(scw baremetal os list zone="${ZONE}" -o json 2>/dev/null \
    | jq -r 'first(.[] | select(.name == "Ubuntu" and (.version | startswith("24.04"))) | .id) // empty')
  [ -n "${osid}" ] || die "no Ubuntu 24.04 baremetal OS offered in ${ZONE}"
  keyid=$(scw iam ssh-key list -o json | jq -r --arg n "${SSH_KEY_NAME}" 'first(.[] | select(.name == $n) | .id) // empty')
  [ -n "${keyid}" ] || die "ssh key '${SSH_KEY_NAME}' is not registered with Scaleway IAM"

  out=$(scw baremetal server create \
    name="$(box_name "${lesson}")" type="${type}" zone="${ZONE}" \
    install.os-id="${osid}" install.hostname="${lesson}" \
    install.ssh-key-ids.0="${keyid}" install.user=ubuntu \
    tags.0=sandboxing-tutorial tags.1="${lesson}" tags.2=disposable \
    -o json) || die "scw baremetal server create failed for ${lesson}"
  id=$(jq -r '.id // empty' <<<"${out}")
  [ -n "${id}" ] || die "${lesson}: scw baremetal create returned no server id"
  state_save "${lesson}" \
    "BOX_ID=${ZONE}/${id}" "BOX_IP=" "BOX_USER=ubuntu" "BOX_KIND=baremetal" "BOX_TYPE=${type}"

  # Metal installs the OS after create; wait for the IPv4 to appear (install.status == completed is
  # what the SNO install script itself gates on — see REPRODUCE.md trap #8).
  tries=0
  ip=""
  while [ -z "${ip}" ] && [ "${tries}" -lt 120 ]; do
    sleep 15
    ip=$(scw baremetal server get "${id}" zone="${ZONE}" -o json 2>/dev/null \
      | jq -r 'first(.ips[]? | select(.version == "IPv4") | .address) // empty')
    hb "$(stage_expect openshift-sno provision)"
    tries=$((tries + 1))
  done
  [ -n "${ip}" ] || die "${lesson}: baremetal ${id} created but no IPv4 appeared (still tracked — ./down.sh ${lesson})"
  state_save "${lesson}" \
    "BOX_ID=${ZONE}/${id}" "BOX_IP=${ip}" "BOX_USER=ubuntu" "BOX_KIND=baremetal" "BOX_TYPE=${type}"
}

# Destroy exactly this lesson's box — by id from .state, or, if there is no .state (a create killed
# before it recorded anything), by the box's console name. Either way it touches ONLY this lesson's
# box: there is no set to recompute and no sweep of everything, which is what makes a single teardown
# unable to harm another lesson.
box_destroy() {
  local lesson="$1" kind id name
  name=$(box_name "${lesson}")
  if [ -f "$(state_file "${lesson}")" ]; then
    state_load "${lesson}"
    kind="${BOX_KIND:-vm}"
    id="${BOX_ID##*/}" # strip the "<zone>/" prefix
    say "destroying ${lesson}: ${kind} ${id} (${BOX_IP:-no ip})"
    _terminate "${kind}" "${id}"
  else
    # No record — find it by name so a box created but never tracked is still torn down.
    say "${lesson}: no state file — looking for ${name} in the account"
    while read -r id; do
      [ -z "${id}" ] && continue
      echo "    terminating untracked ${name} (${id})"
      _terminate vm "${id}"
    done < <(scw instance server list zone="${ZONE}" name="${name}" -o json 2>/dev/null | jq -r '.[].id')
    while read -r id; do
      [ -z "${id}" ] && continue
      echo "    deleting untracked baremetal ${name} (${id})"
      _terminate baremetal "${id}"
    done < <(scw baremetal server list zone="${ZONE}" -o json 2>/dev/null \
      | jq -r --arg n "${name}" '.[] | select(.name == $n) | .id')
  fi
  rm -f "$(state_file "${lesson}")" "$(ssh_config_file "${lesson}")"
}

# Terminate one server by id. VMs use `terminate` (which also removes the dynamic IP and any block
# volumes); metal uses `delete`. Never fails the caller — a box already gone is success.
_terminate() {
  local kind="$1" id="$2"
  if [ "${kind}" = "baremetal" ]; then
    scw baremetal server delete "${id}" zone="${ZONE}" >/dev/null 2>&1 || true
  else
    scw instance server terminate "${id}" zone="${ZONE}" with-ip=true with-block=true >/dev/null 2>&1 || true
  fi
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

# --- box readiness -----------------------------------------------------------
#
# up.sh appends `BOX_READY=1` to the state file as its LAST act, so the marker means every stage —
# sync, tooling, substrates, check — finished. A state file WITHOUT it is a box mid-provision (the
# file is written the instant an id exists, long before the box is usable) or one whose provision
# died. run.sh gates on the marker: running early is not merely premature, its rsync and up.sh's
# sync stage mirror the same tree concurrently and their --delete passes destroy each other's temp
# files, which kills the provision with rsync rc 23.

# The most recent `up` event stream ctl.py recorded for this lesson, if any. Empty for a box built
# by a hand-run ./up.sh — no supervisor, no events — and the caller must read "no stream" as
# "unknown", never as "failed".
_up_events_file() {
  local f found=""
  for f in "${STATE_DIR}/$1"/run-*.ndjson; do
    [ -e "${f}" ] || continue # an unmatched glob stays literal
    if jq -e -R 'fromjson? | select(.event == "op_start" and (.msg | startswith("up ")))' \
      "${f}" >/dev/null 2>&1; then
      found="${f}"
    fi
  done
  echo "${found}"
}

# What the most recent supervised `up` of this lesson is doing: running | ok | fail | cancelled |
# unknown. "unknown" is the hand-run case; callers fall back to a plain timeout there.
box_up_status() {
  local f s
  f=$(_up_events_file "$1")
  if [ -z "${f}" ]; then
    echo unknown
    return 0
  fi
  s=$(jq -rR 'fromjson? | select(.event == "op_end") | .data.status // empty' "${f}" 2>/dev/null | tail -1)
  echo "${s:-running}"
}

# Block until up.sh declares this lesson's box ready, with a visible timer. Polls every second; on
# a terminal the timer updates in place, in a captured log it prints a line every 10 s. Fails FAST
# when the provision is known dead — a failed up never produces the marker, and discovering that by
# timeout would cost half an hour of "provisioning ..." against a box nothing is building.
box_wait_ready() {
  local lesson="$1" timeout="${SBX_BOX_READY_TIMEOUT:-1800}" waited=0 f status
  f="$(state_file "${lesson}")"
  while :; do
    if [ -f "${f}" ] && grep -q '^BOX_READY=1$' "${f}"; then
      if [ "${waited}" -gt 0 ]; then
        [ -t 1 ] && printf '\n'
        say "box is ready — provisioning finished (waited $(fmt_dur "${waited}"))"
      fi
      return 0
    fi
    status=$(box_up_status "${lesson}")
    case "${status}" in
      fail | cancelled)
        [ -t 1 ] && [ "${waited}" -gt 0 ] && printf '\n'
        die "${lesson}: the provisioning ${status} before finishing — the box is not runnable.
       Rebuild it:  ./down.sh ${lesson} && ./up.sh ${lesson}"
        ;;
      unknown)
        # Nothing supervised is building this box. If there is no state file either, nothing at all
        # is coming; with one, a hand-run ./up.sh may still be working — wait out the timeout.
        [ -f "${f}" ] || die "no box recorded for '${lesson}' and no provisioning in flight — run ./up.sh ${lesson} first."
        ;;
    esac
    if [ "${waited}" -ge "${timeout}" ]; then
      [ -t 1 ] && printf '\n'
      die "${lesson}: box not ready after $(fmt_dur "${timeout}") — the provision looks stuck.
       Watch it: ./ctl.py logs ${lesson} -f   Rebuild:  ./down.sh ${lesson} && ./up.sh ${lesson}"
    fi
    if [ -t 1 ]; then
      printf '\r    box is being provisioned ... (%s) ' "$(fmt_dur "${waited}")"
    elif [ $((waited % 10)) -eq 0 ]; then
      say "box is being provisioned ... ($(fmt_dur "${waited}") elapsed)"
    fi
    sleep 1
    waited=$((waited + 1))
  done
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

# The box we PROVISIONED, as opposed to wherever the lesson ended up running. For lesson 1.2.4 those are
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
  local lesson="$1" tries="${2:-60}" ok=0 i expect
  state_load "${lesson}"
  write_ssh_config "${lesson}"
  expect=$(stage_expect lesson ssh)
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
    hb "${expect}"
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
