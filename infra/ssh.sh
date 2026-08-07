#!/usr/bin/env bash
# A shell on a lesson's box, or one command on it.
#
#   ./ssh.sh lesson-03-container-gvisor
#   ./ssh.sh lesson-03-container-gvisor 'podman ps -a'
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source-path=SCRIPTDIR source=lib.sh
source "${HERE}/lib.sh"

LESSON="${1:?usage: ./ssh.sh <lesson> [command]}"
shift
write_ssh_config "${LESSON}"
exec ssh -F "$(ssh_config_file "${LESSON}")" -t box "$@"
