#!/usr/bin/env bash
# Run one lesson ON ITS BOX and bring the scorecard home.
#
#   ./run.sh lesson-03-container-gvisor
#   ./run.sh lesson-01-no-sandbox -- --part 2      # args after -- go to the lesson
#
# The lesson runs on the box because that is where the boundary is. Nothing about it is remote-aware:
# it is the same `cd <lesson> && uv sync && uv run python -u main.py` a reader types by hand, which is
# the point — if it only worked through this script, this script would be the tutorial.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "${HERE}/lib.sh"

LESSON="${1:?usage: ./run.sh <lesson> [-- <args for main.py>]}"
shift
[ "${1:-}" = "--" ] && shift
ARGS="$*"

state_load "${LESSON}"

say "syncing the lesson tree to the box"
rsync -az --delete -e "$(box_rsync_shell "${LESSON}")" \
  --exclude '.git' --exclude '.venv' --exclude '__pycache__' --exclude 'results' \
  --exclude '.state' --exclude '.ruff_cache' \
  "${REPO_ROOT}/" "box:sandboxing-tutorial/"

say "running ${LESSON} on ${BOX_IP}"
# SANDBOXING_TUTORIAL_DISPOSABLE=1 is the box telling the lesson it is allowed to do real damage.
# Only ever set here, and only on a machine `down.sh` is about to destroy.
# `source ~/.bashrc` is not decoration: a substrate may have exported what the lesson needs there
# (lesson 5's DOCKER_HOST and OPENSHELL_DRIVERS), and a non-interactive ssh reads no profile at all.
# Attack 4 probes a cloud-metadata endpoint, and WHICH address matters. The suite defaults to AWS's
# 169.254.169.254, which does not answer on Scaleway — so the row read BLOCKED everywhere and the
# baseline lost the SSRF finding it exists to show, for a reason that had nothing to do with any
# boundary. Measured on a Scaleway VM 2026-08-06: 169.254.169.254 -> 000, 169.254.42.42 -> 200.
METADATA_URL="${PROBE_METADATA_URL:-http://169.254.42.42/conf}"

box_ssh "${LESSON}" "source ~/.sandboxing-tutorial.env 2>/dev/null; cd sandboxing-tutorial/tutorial/${LESSON} \
  && export PATH=\$HOME/.local/bin:\$PATH \
  && export SANDBOXING_TUTORIAL_DISPOSABLE=1 \
  && export PROBE_METADATA_URL=${METADATA_URL} \
  && uv sync --quiet \
  && uv run python -u main.py ${ARGS}"

say "fetching results/"
mkdir -p "${REPO_ROOT}/results"
rsync -az -e "$(box_rsync_shell "${LESSON}")" \
  "box:sandboxing-tutorial/results/" "${REPO_ROOT}/results/" 2>/dev/null \
  || say "(no results/ on the box — the lesson did not write one)"

find "${REPO_ROOT}/results" -maxdepth 1 -name '*.json' -exec basename {} \; 2>/dev/null | sed 's|^|    results/|'

# Re-render THIS lesson's report (report.html + report.json, in its own folder). The lesson's own
# main.py already does this when it runs; repeating it here covers the case where the lesson ran on
# a box whose report never came back. It reads only the JSON, so a failed render can never affect a
# lesson's result — hence `|| true`.
say "rendering ${LESSON}'s report"
python3 "${HERE}/report/render.py" "${LESSON}" || true
