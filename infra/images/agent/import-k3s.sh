#!/usr/bin/env bash
# Build the shared agent image and hand it to k3s's containerd. Chapter 3's counterpart to build.sh.
#
#   sudo ./import-k3s.sh
#
# Two things make this its own script rather than a line in a substrate.
#
# 1. THE TAG IS NOT `:latest`, and that is load-bearing rather than taste. Kubernetes defaults
#    imagePullPolicy to `Always` for a `:latest` tag and to `IfNotPresent` for every other tag. An
#    image side-loaded onto the node under `:latest` is therefore ignored, and the kubelet goes to
#    Docker Hub for something already sitting on the disk — `ErrImagePull` for an image you can see
#    in `crictl images`. Lessons 6-8 could set the policy explicitly in their own pod specs, but
#    lesson 9 CANNOT: OpenShell owns that pod spec. One non-latest tag removes the trap everywhere.
#
# 2. A lesson re-runs it every time, exactly as chapter 2 re-runs build.sh. Layer caching makes that
#    nearly free, and skipping it is how a lesson measures a stale suite — which on this ladder means
#    silently comparing two different attack suites and calling the difference a boundary.
set -euo pipefail

TAG="${AGENT_IMAGE_TAG:-docker.io/sandboxing-tutorial/agent:v1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARCHIVE="/tmp/sandboxing-tutorial-agent.tar"

[ "$(id -u)" -eq 0 ] || {
  echo "FATAL: run this as root — it writes into k3s's containerd image store." >&2
  exit 1
}
command -v k3s >/dev/null || {
  echo "FATAL: k3s is not installed; run substrate 60-k8s.sh first." >&2
  exit 1
}

echo "=== building ${TAG}"
podman build -q -t "${TAG}" "${HERE}"

# `rm -f` before the save is not tidiness. `--format docker-archive` REFUSES to write into an
# existing tar ("docker-archive doesn't support modifying existing images"), and ignoring that error
# re-imports the previous build — so you debug a fix that was never shipped. Prior art paid for this.
rm -f "${ARCHIVE}"
podman save --format docker-archive -o "${ARCHIVE}" "${TAG}"

echo "=== importing into k3s containerd"
k3s ctr images import "${ARCHIVE}"
rm -f "${ARCHIVE}"

# Verify it landed under the name the pod specs actually reference. Importing under a name nothing
# asks for fails later as ImagePullBackOff, several minutes and one confusing pod event away.
if ! k3s crictl images | awk '{print $1":"$2}' | grep -q "^${TAG}$"; then
  echo "FATAL: ${TAG} is not in k3s's image store after import. What IS there:" >&2
  k3s crictl images >&2
  exit 1
fi
echo "agent image on the node: ${TAG}"
