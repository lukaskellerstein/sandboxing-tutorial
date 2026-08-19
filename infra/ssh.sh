#!/usr/bin/env bash
# A shell on a lesson's box, or one command on it.
#
#   ./ssh.sh 1.2.2
#   ./ssh.sh 1.2.2 'podman ps -a'
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "${HERE}/lib.sh"

LESSON="${1:?usage: ./ssh.sh <lesson> [command]}"
shift
# A shell is a shell on a MACHINE, so either name gets you there: chapter 3's four lessons all
# resolve to the one cluster they share, and `./ssh.sh 1.3.3` lands on the same node as
# `./ssh.sh chapter-03-k8s`. Anything else would be a trap while investigating a failed run.
BOX=$(lesson_box "${LESSON}")
write_ssh_config "${BOX}"
exec ssh -F "$(ssh_config_file "${BOX}")" -t box "$@"
