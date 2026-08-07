#!/usr/bin/env bash
# runs-as: user
#
# Chapter 2 substrate — NVIDIA OpenShell (lesson 5). Per-binary + L7 network policy and an OCSF audit
# trail, on ordinary runc/crun. Alpha.
#
# THIS RUNS AS AN UNPRIVILEGED USER, and `up.sh` honours the `runs-as: user` marker above. That is a
# requirement, not tidiness: OpenShell's podman driver is **rootless**. Installed as root, the gateway
# starts and then cannot reach the user's podman socket — a failure that reads like a driver bug and
# is a privilege mistake.
#
# It also expects to be running INSIDE the NAT'd guest that `50-nat-vm.sh` builds, for the reason
# spelled out at the top of that file: the gateway refuses to expose its sandbox callback on a public
# default-route address, and every Scaleway box has one. In the guest the default route is private
# (192.168.122.0/24), which is the topology OpenShell is written for.
#
# Two things `uv tool install openshell` does NOT give you, both fatal:
#   * the `openshell-gateway` DAEMON — the CLI on its own talks to nothing;
#   * podman 5 with pasta as the default rootless network helper. Podman 4.9.3 (what Ubuntu 24.04
#     ships) reports the helper missing and the driver refuses to start, which is why the guest is
#     Debian 13 (podman 5.4.2) rather than the Ubuntu every other lesson uses.
set -euo pipefail

[ "$(id -u)" -ne 0 ] || {
  echo "FATAL: run this as an unprivileged user — OpenShell's podman driver is rootless."
  exit 1
}

echo "podman: $(podman --version)"
echo "default route: $(ip route show default)"

# The gateway's podman driver talks to the ROOTLESS podman API socket, and the user session has to
# survive our ssh logout or the socket dies with it.
sudo loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || true
systemctl --user enable --now podman.socket >/dev/null 2>&1 || true
SOCK="/run/user/$(id -u)/podman/podman.sock"
[ -S "${SOCK}" ] || {
  echo "FATAL: rootless podman socket ${SOCK} is absent"
  exit 1
}

# The installer ships a system .deb now and needs root to place it, while the DAEMON has to run as
# this unprivileged user. So: install with sudo, run without. Getting that backwards produces a
# gateway that starts and then cannot see the user's podman socket.
# Pin the cgroup manager. Rootless podman detects "no systemd user session" and falls back to
# cgroupfs for itself, but buildah still hands crun --systemd-cgroup, and crun then dies with
# "sd-bus call: Interactive authentication required" on the first RUN step of a build. Saying it
# once, here, makes every tool in the chain agree.
mkdir -p "${HOME}/.config/containers"
grep -q cgroup_manager "${HOME}/.config/containers/containers.conf" 2>/dev/null || cat >>"${HOME}/.config/containers/containers.conf" <<'EOF'
[engine]
cgroup_manager = "cgroupfs"
EOF

if ! command -v openshell-gateway >/dev/null 2>&1; then
  curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh -o /tmp/openshell-install.sh
  sudo sh /tmp/openshell-install.sh
fi
export PATH="${HOME}/.local/bin:${PATH}"
echo "openshell: $(openshell --version 2>&1 | head -1)"

# The user service inherits nothing from this shell, so the driver settings go in a drop-in.
mkdir -p "${HOME}/.config/systemd/user/openshell-gateway.service.d"
cat >"${HOME}/.config/systemd/user/openshell-gateway.service.d/env.conf" <<EOF
[Service]
Environment=OPENSHELL_DRIVERS=podman
Environment=DOCKER_HOST=unix://${SOCK}
EOF
systemctl --user daemon-reload

# Both variables are needed by every later CLI call and by the daemon, so they go in the shell
# profile rather than only this script's environment — `run.sh` opens a fresh non-interactive shell.
# XDG_RUNTIME_DIR matters as much as the driver settings. A non-interactive ssh gets no session, so
# without it rootless podman cannot find its runtime dir and crun dies with "sd-bus call: Interactive
# authentication required" the moment it builds or runs a container — which reads like a permissions
# bug and is a missing variable. Lingering (above) keeps /run/user/<uid> alive; this points at it.
# A dedicated env file, NOT ~/.bashrc. Debian's .bashrc opens with an interactive-shell guard
# (`case $- in *i*) ;; *) return;; esac`), so everything appended to it is silently skipped by the
# non-interactive ssh that `run.sh` uses — the exports look present and have no effect.
cat >"${HOME}/.sandboxing-tutorial.env" <<EOF
export PATH="\${HOME}/.local/bin:\${PATH}"
export XDG_RUNTIME_DIR=/run/user/$(id -u)
export DOCKER_HOST=unix://${SOCK}
export OPENSHELL_DRIVERS=podman
EOF
export DOCKER_HOST="unix://${SOCK}"
export OPENSHELL_DRIVERS=podman

systemctl --user enable --now openshell-gateway >/dev/null 2>&1 || true
systemctl --user restart openshell-gateway >/dev/null 2>&1 || true
sleep 10

# If the gateway refused to start, say WHY here rather than letting the lesson discover it later.
if ! systemctl --user is-active --quiet openshell-gateway; then
  echo "--- openshell-gateway failed to start ---"
  journalctl --user -u openshell-gateway -n 15 --no-pager | tail -15
  exit 1
fi

# ADVISORY, and it must not gate the install — `|| true` is load-bearing.
#
# `doctor check` shells out to a docker-compatible CLI, and under podman-docker emulation its Docker
# item fails on a template field podman's `docker info` does not implement:
#
#     docker info failed: template: info:1:2: executing "info" at <.ServerVersion>:
#     can't evaluate field ServerVersion in type system.infoReport
#
# The compute driver is perfectly healthy at that point — the gateway has already reported
# `connected` a few lines above. Under `set -euo pipefail` a non-zero exit here aborts the whole
# substrate and `up.sh` reports the lesson unprovisionable, which is how a working box gets thrown
# away. The lesson's own main.py reaches the same conclusion and says so; this keeps the two in
# agreement. The load-bearing check is the next one: the gateway is Connected or it is not.
openshell doctor check 2>&1 | tail -8 || true
echo "--- gateway status ---"
openshell status 2>&1 | tail -6
