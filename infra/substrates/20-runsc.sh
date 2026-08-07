#!/usr/bin/env bash
# Chapter 2 substrate — gVisor (lesson 3). Installs runsc and registers it as a
# podman OCI runtime. On Ubuntu (SELinux not enforcing) no label=disable is
# needed — that trap was CoreOS/podman-machine specific.
set -euo pipefail

ARCH=$(uname -m)
URL="https://storage.googleapis.com/gvisor/releases/release/latest/${ARCH}"
if ! command -v runsc >/dev/null 2>&1; then
  cd /tmp
  for f in runsc containerd-shim-runsc-v1; do
    curl -fsSL "${URL}/${f}" -o "$f"
    curl -fsSL "${URL}/${f}.sha512" -o "${f}.sha512"
    sha512sum -c "${f}.sha512"
    chmod +x "$f"
    mv "$f" /usr/local/bin/
  done
fi
# register runsc as an opt-in podman runtime (does NOT change the default)
mkdir -p /etc/containers/containers.conf.d
cat >/etc/containers/containers.conf.d/50-runsc.conf <<'EOF'
[engine.runtimes]
runsc = ["/usr/local/bin/runsc"]
EOF
echo "runsc: $(runsc --version | head -1)"

# smoke: a container under runsc reports gVisor's OWN kernel, not the host's.
echo -n "gVisor container uname -r: "
podman run --rm --network none --runtime runsc docker.io/library/alpine:3.22 uname -r
