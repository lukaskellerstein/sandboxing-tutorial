#!/usr/bin/env bash
# Run this lesson against the SHARED chapter-4 cluster.
#
#   ../../../infra/openshift-sno/install.sh     bring the cluster up — ONCE, for lessons 10-13
#   ./run.sh                                 run this lesson against it
#   ../../../infra/down.sh openshift-sno        DESTROY it. EUR 0.263/hr for as long as it lives.
#
# THIS IS THE ONE CHAPTER WHERE run.sh DOES NOT PROVISION OR DESTROY, and the difference is
# deliberate rather than an oversight. Chapters 1-3 give every lesson its own disposable box and tear
# it down in an EXIT trap, which is what makes them safe to run casually. Installing single-node
# OpenShift takes far longer than a lesson does, so all four chapter-4 lessons share one cluster —
# and that means the teardown is a step YOU own. There is no trap here that will save you.
#
# The lesson itself runs on your workstation and drives `oc`; the BOUNDARY under test is on the
# OpenShift node, which is where it has to be. That is the opposite arrangement from chapters 1-3,
# where the lesson ran on the box — and it is forced: the node is RHCOS, an immutable image with no
# package manager, no repo checkout and no uv.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# This lesson's dotted id, read from the three folder names (phaseP-*/chapter-C-*/lesson-LL-*) —
# the same derivation lib.sh's lesson_id_of_dir does, inlined so this leaf stays standalone.
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
CLUSTER_STATE="${INFRA}/.state/openshift-sno.env"

if [ ! -f "${CLUSTER_STATE}" ]; then
  cat >&2 <<EOF
No chapter-4 cluster is running, so ${LESSON} has nothing to run against.

  ${INFRA}/openshift-sno/install.sh --preflight   # free checks first
  ${INFRA}/openshift-sno/install.sh               # ~1.5-2h, EUR 0.263/hr

It is deliberately not started for you: it is the most expensive thing in this repo, it is
shared by lessons 10-13, and nothing here will destroy it on your behalf.
EOF
  exit 1
fi

# shellcheck disable=SC1090  # path is computed; nothing to follow at lint time
source "${CLUSTER_STATE}"
echo "==> cluster ${BOX_ID} at ${BOX_IP}"

cd "${HERE}"
uv sync --quiet

# The openshell CLI reaches the in-cluster gateway over a localhost port-forward, so one has to be
# running for the whole lesson. THIS trap is the one piece of chapter-1-style hygiene that does
# survive into chapter 4 — it costs nothing and an orphaned forward is genuinely confusing: the port
# stays open, the CLI connects happily, and it is talking to a cluster that may no longer exist.
#
# Note what the trap does NOT do: destroy the cluster. See the header.
FORWARD="${INFRA}/openshift-sno/openshell-forward.sh"
"${FORWARD}" start
trap '"${FORWARD}" stop >/dev/null 2>&1 || true' EXIT

uv run python -u main.py "$@"
