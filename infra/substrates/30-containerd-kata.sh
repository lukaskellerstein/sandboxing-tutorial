#!/usr/bin/env bash
# Chapter 2 substrate — Kata Containers (lesson 4). Kata is a containerd shim-v2,
# so Podman cannot drive it: this stands up containerd + nerdctl alongside podman
# (they coexist — podman is daemonless and never touches containerd). Proven on
# Scaleway bare metal (guest kernel 6.18.35). Needs /dev/kvm on the host.
set -euo pipefail

NERDCTL_VER=2.3.5
KATA_VER=4.0.0
ARCH=$(uname -m)
[ "$ARCH" = "x86_64" ] && GO=amd64 || GO=arm64

test -e /dev/kvm || {
  echo "FATAL: /dev/kvm absent — Kata needs hardware virt"
  exit 1
}

if ! command -v nerdctl >/dev/null 2>&1; then
  curl -fsSL "https://github.com/containerd/nerdctl/releases/download/v${NERDCTL_VER}/nerdctl-full-${NERDCTL_VER}-linux-${GO}.tar.gz" -o /tmp/nerdctl.tgz
  tar -C /usr/local -xzf /tmp/nerdctl.tgz
fi
if [ ! -x /opt/kata/bin/kata-runtime ]; then
  curl -fsSL "https://github.com/kata-containers/kata-containers/releases/download/${KATA_VER}/kata-static-${KATA_VER}-${GO}.tar.zst" -o /tmp/kata.tar.zst
  tar -C / -xf /tmp/kata.tar.zst # unpacks ./opt/kata
fi
ln -sf /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
cp -n /usr/local/lib/systemd/system/containerd.service /etc/systemd/system/ 2>/dev/null || true
# buildkit too: `nerdctl build` is a BuildKit client, not a builder. Without buildkitd running it
# fails with "failed to get buildkit host", which reads like a nerdctl problem and is not one.
# nerdctl-full ships the unit; it just is not enabled.
cp -n /usr/local/lib/systemd/system/buildkit.service /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload
systemctl enable --now containerd >/dev/null 2>&1
systemctl enable --now buildkit >/dev/null 2>&1 || true
sleep 3
echo "containerd: $(systemctl is-active containerd)   buildkit: $(systemctl is-active buildkit)"
/opt/kata/bin/kata-runtime check 2>&1 | tail -2

# smoke: a Kata container reports a DIFFERENT (guest) kernel than the node.
echo "node uname -r  : $(uname -r)"
echo -n "kata uname -r  : "
nerdctl run --rm --net none --runtime io.containerd.kata.v2 docker.io/library/alpine:3.22 uname -r
