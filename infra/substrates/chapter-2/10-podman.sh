#!/usr/bin/env bash
# Chapter 2 substrate — the plain container engine (lesson 2).
# Runs on a fresh Ubuntu bare-metal host. Idempotent.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
if ! command -v podman >/dev/null 2>&1; then
  apt-get -qq update
  apt-get -qq install -y podman
fi
echo "podman: $(podman --version)"
echo "default runtime: $(podman info --format '{{.Host.OCIRuntime.Name}}')"

# smoke: a plain container reports the HOST kernel (no kernel boundary — that is lesson 3+).
echo -n "container uname -r: "
podman run --rm --network none docker.io/library/alpine:3.22 uname -r
