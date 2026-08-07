#!/usr/bin/env bash
# Build the one shared agent image. Every lesson runs this image under a different boundary; the
# image itself is boundary-agnostic. On the real boxes this builds x86_64 natively; on a Mac podman
# machine it builds arm64 natively — both fine, the attack suite is arch-aware.
#
#   ./build.sh                 build with the default engine (podman)
#   CONTAINER_ENGINE=docker ./build.sh
#   ./build.sh --tag myrepo/agent:dev
set -euo pipefail

ENGINE="${CONTAINER_ENGINE:-podman}"
TAG="sandboxing-tutorial/agent:latest"
if [[ "${1:-}" == "--tag" ]]; then
  TAG="${2:?--tag needs a value}"
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v "${ENGINE}" >/dev/null || {
  echo "Container engine '${ENGINE}' is not on PATH. Install podman, or set CONTAINER_ENGINE=docker." >&2
  exit 1
}

echo "=== building ${TAG}  (engine: ${ENGINE})"
"${ENGINE}" build -t "${TAG}" "${HERE}"

echo
echo "Done. Smoke-test the script driver in a throwaway container:"
echo "  ${ENGINE} run --rm -e PROBE_GROUPS=kernel,cost ${TAG}"
