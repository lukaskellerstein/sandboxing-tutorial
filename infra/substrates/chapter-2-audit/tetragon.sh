#!/usr/bin/env bash
# Chapter 2 audit substrate — Tetragon (Cilium's eBPF sensor). A host kernel sensor that watches every
# container on the box through a CO-RE eBPF probe. The finding lesson 2.2.1 turns on: a container does
# NOT hide its syscalls from a host kernel sensor — it shares the host kernel, and Tetragon sees
# straight through the namespace/cgroup boundary that isolates it. Isolation improved over no-sandbox;
# observability did not change.
#
# WHY TETRAGON AND NOT FALCO. Both are host eBPF sensors and on this rung both see the same thing —
# the choice is about using ONE sensor mechanism across the whole of phase 2 rather than a different
# one per chapter. A reader comparing the container rung to the k8s rung must be able to attribute a
# difference to the BOUNDARY, not to the instrument; that is the same argument the phase-1 chapters
# make for running every rung against one fixed attack suite. Tetragon covers the three positions
# phase 2 needs — host (2.2.1), Kubernetes with native pod enrichment (2.3.x), and a candidate
# in-guest sidecar under Kata (2.3.3) — where Falco would have needed the k3s containerd socket wired
# by hand and would still not be the in-guest story.
#
# CO-RE needs the HOST kernel to carry BTF (CONFIG_DEBUG_INFO_BTF) — Ubuntu Noble's 6.8 does, so no
# driver is compiled and nothing is pinned to a kernel version. The TETRAGON VERSION is pinned,
# because a sensor whose event schema moved under a lesson rots that lesson silently.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

TETRAGON_VERSION=v1.7.0
POLICY=/etc/tetragon/sbx-sandboxing.yaml

if ! command -v tetragon >/dev/null 2>&1; then
  arch=$(dpkg --print-architecture)
  tmp=$(mktemp -d)
  curl -fsSL -o "${tmp}/tetragon.tar.gz" \
    "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-${arch}.tar.gz"
  tar -xzf "${tmp}/tetragon.tar.gz" -C "${tmp}"
  (cd "${tmp}/tetragon-${TETRAGON_VERSION}-${arch}" && ./install.sh)
  rm -rf "${tmp}"
fi

# install.sh enables AND starts the systemd unit. The LESSON starts its own tetragon for the capture
# window (start sensor -> run only the attack container -> stop sensor), and two instances fight over
# the same pinned BPF maps in /sys/fs/bpf/tetragon — the second one fails to attach. So the service is
# stopped and disabled here: the sensor is installed and provably loadable, and the lesson owns when
# it runs. This is also what keeps the probe off the box between lessons.
systemctl disable --now tetragon >/dev/null 2>&1 || true

# One kprobe per attack fingerprint, each tagging its probe so the mapping is by FIELD, not by
# guesswork — the same contract Falco's `output:` string carried, now in Tetragon's `tags:`, which the
# JSON export emits as a real array rather than a substring to scrape.
#
# read_credentials hooks the OPEN SYSCALLS rather than security_file_open on purpose. The LSM hook only fires
# once an inode has been resolved, so a read of a credential file that DOES NOT EXIST — which is
# exactly the hardened container's case, where the attack is contained — would never reach it, and the
# probe would read NOT_LOGGED for a boundary that in fact blocked a visible attempt. The syscall
# entry fires either way, which is the honest measurement: the sensor saw the attempt.
#
# Postfix matching keeps this independent of $HOME: the suite reads $HOME/.ssh/id_rsa and friends, and
# HOME is /sandbox in the shared agent image but /root on the bare host in 2.1.1.
mkdir -p /etc/tetragon
cat >"${POLICY}" <<'YAML'
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "sbx-sandboxing"
spec:
  kprobes:
    # BOTH sys_open and sys_openat, and that is not belt-and-braces — it is a measured requirement.
    # glibc routes open() to the openat syscall; musl on x86_64 uses SYS_open directly. So a
    # glibc image (the shared agent image, python:3.12-slim) is invisible to a sys_open-only hook and
    # an alpine/musl image is invisible to a sys_openat-only one. Measured 2026-08-15: alpine's
    # /bin/cat fired __x64_sys_open and nothing else. A sensor that silently misses one libc is the
    # false blank this repo exists to avoid.
    - call: "sys_open"
      syscall: true
      message: "sbx_probe=read_credentials"
      tags: ["sbx_probe=read_credentials"]
      args:
        - index: 0
          type: "string"
      selectors:
        - matchArgs:
            - index: 0
              operator: "Postfix"
              values:
                - "/.ssh/id_rsa"
                - "/.aws/credentials"
                - "/.config/gh/hosts.yml"
                - "/.netrc"
                - "/.env"

    - call: "sys_openat"
      syscall: true
      message: "sbx_probe=read_credentials"
      tags: ["sbx_probe=read_credentials"]
      args:
        - index: 0
          type: "int"
        - index: 1
          type: "string"
      selectors:
        - matchArgs:
            - index: 1
              operator: "Postfix"
              values:
                - "/.ssh/id_rsa"
                - "/.aws/credentials"
                - "/.config/gh/hosts.yml"
                - "/.netrc"
                - "/.env"

    - call: "tcp_connect"
      syscall: false
      message: "sbx_probe=network"
      tags: ["sbx_probe=network"]
      args:
        - index: 0
          type: "sock"

    - call: "sys_bpf"
      syscall: true
      message: "sbx_probe=bpf"
      tags: ["sbx_probe=bpf"]

    - call: "sys_io_uring_setup"
      syscall: true
      message: "sbx_probe=io_uring_setup"
      tags: ["sbx_probe=io_uring_setup"]

    - call: "sys_perf_event_open"
      syscall: true
      message: "sbx_probe=perf_event_open"
      tags: ["sbx_probe=perf_event_open"]
YAML

# No policy is written for the exec-based attacks: Tetragon exports process_exec for every execve as a
# BASE event, with no kprobe to declare. That is the one place its default is wider than Falco's, and
# the lesson reads those events directly.
# The tetragon binary has NO --version flag (measured on v1.7.0: "Error: unknown flag"), so the
# pin is the only version statement, and the binary path proves the install landed.
echo "tetragon: ${TETRAGON_VERSION} (pinned) at $(command -v tetragon)"
echo "policy: ${POLICY} ($(grep -c '^    - call:' "${POLICY}") kprobes)"
echo "note: the lesson runs tetragon with --enable-process-ns; the pid namespace is how an event"
echo "      is attributed to the workload, because rootless podman does not give it a container id"
echo "service: $(systemctl is-enabled tetragon 2>/dev/null || echo disabled) (the lesson starts its own)"
