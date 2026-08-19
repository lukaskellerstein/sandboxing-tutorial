#!/usr/bin/env bash
# Chapter 3 audit substrate — Tetragon (Cilium's eBPF sensor), on the k3s node.
#
# The same host kernel sensor chapter 2 uses (2.2.1), pointed at a cluster, and deliberately the SAME
# sensor with the SAME configuration: a reader comparing the container rung to the k8s rung has to be
# able to attribute a difference to the BOUNDARY rather than to the instrument. The finding it turns
# on for k8s is 2.2.1's, composed: a Pod is namespaces + cgroups on the NODE kernel, so Tetragon sees
# straight through it exactly as it saw the plain container — isolation was arranged by the cluster,
# observability did not move. What the cluster adds is a SECOND sensor no syscall tracer can be (the
# API audit log, chapter-3-audit/k8s-api-audit), for the control-plane attacks that never touch the
# kernel.
#
# ---------------------------------------------------------------------------------------------
# WHY THERE IS NO `--enable-k8s-api` HERE, MEASURED 2026-08-15 ON THIS BOX.
#
# This substrate used to set it, on the reasoning that Tetragon is Kubernetes-aware natively and would
# stamp every event with its pod and namespace — so a lesson could map an event to its workload BY
# NAME, and the k8s rung would be cheaper to instrument than the container rung was. On a real k3s box
# none of that holds, and the flag is actively harmful. Five rounds on a live cluster:
#
#   1. Tetragon REFUSES TO START with it: `--enable-k8s-api` also switches on the TracingPolicy CRD
#      watcher (`enable-tracing-policy-crd` defaults true), and the release TARBALL ships no CRDs —
#      only the Helm chart installs them. It exits with
#          Failed to execute tetragon  error="no matches for kind \"TracingPolicy\" in version
#          \"cilium.io/v1alpha1\""
#      which check.sh reported as `hits=0`, i.e. exactly like a sensor that saw nothing.
#   2. With the CRD watcher turned off it runs — and still resolves NO pod. `process.pod` is null on
#      every event, with and without `NODE_NAME` set to the node's real name.
#   3. Tetragon itself names the missing half: `cgidmap is enabled but cri is not. This means that pod
#      association will not work for existing pods.` So pod association needs `--enable-cri` pointed
#      at k3s's NON-STANDARD containerd socket (/run/k3s/containerd/containerd.sock) — the very
#      hand-wiring the old comment here claimed was Falco's problem and that Tetragon avoided. That
#      comment was wrong.
#   4. Even with `--enable-cgidmap --enable-cri --cri-endpoint=unix:///run/k3s/containerd/containerd.sock`
#      the CRI client initialises cleanly and `process.pod` is STILL null.
#   5. And the flag makes the trail LATE. Waiting on pod info it will never get, Tetragon holds events
#      in its EventCache (`event-cache-retries:15` x `event-cache-retry-delay:2` = up to 30 s) before
#      exporting them without it. Measured: with the flag on and a 5 s drain the workload's events are
#      ABSENT and reappear only after ~45 s. A lesson that stops its sensor when the workload finishes
#      would report NOT LOGGED for every attack — a false blank, which is the one failure this whole
#      repo is built to prevent.
#
# So the sensor is configured exactly as chapter 2 configures it, and the lesson attributes events to
# the workload by CONTAINER ID instead: `process.docker` IS populated on this rung (it is derived from
# the cgroup, and unlike chapter 2's rootless podman the cluster's cgroups carry it), and the attack
# pod's own container id is read from the k8s API with kubectl. That is stronger than trusting the
# sensor's enrichment — it is per-POD, it is verifiable against the cluster, and it keeps the
# instrument byte-identical to the rung below. Measured with this configuration: a pod's exec and
# kprobe events are matched to it by container id within a 4 s drain.
# ---------------------------------------------------------------------------------------------
#
# CO-RE needs the NODE kernel to carry BTF (CONFIG_DEBUG_INFO_BTF) — Ubuntu Noble's 6.8 does, so no
# driver is compiled and nothing is pinned to a kernel version. The TETRAGON VERSION is pinned.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

TETRAGON_VERSION=v1.7.0
POLICY=/etc/tetragon/sbx-sandboxing.yaml
CONF_D=/etc/tetragon/tetragon.conf.d

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
# window, and two instances fight over the same pinned BPF maps in /sys/fs/bpf/tetragon — the second
# fails to attach. Stopped and disabled here: installed and provably loadable, run when the lesson
# says so. This substrate therefore restarts NOTHING, which is what lets it run last on this box —
# a k3s restart after chapter-3/80-k8s-kata terminates the kata-deploy DaemonSet, and that pod
# reverts its own install on the way out.
systemctl disable --now tetragon >/dev/null 2>&1 || true

# The one configuration that is NOT chapter 2's, and it is about where bytes land rather than what the
# sensor sees. install.sh's own drop-ins set `export-file-max-size-mb: 10` with compression on, so the
# JSON export ROTATES to a .gz mid-run once the trail passes 10 MB — and a lesson that reads the
# current segment then silently loses everything before the rotation. That is the auditd
# `max_log_file` trap of 2.2.4 wearing a different hat, and a k8s trail is the bigger one: an idle
# node's own kubelet/iptables churn already produced ~1 MB per minute here before any attack ran.
# Raising the ceiling changes no capture and no fingerprint; it only keeps one run in one file.
mkdir -p "${CONF_D}"
echo 512 >"${CONF_D}/export-file-max-size-mb"
echo false >"${CONF_D}/export-file-compress"
# Removed rather than left to rot: an earlier revision of this substrate wrote these, and a box built
# from a mixed checkout would otherwise keep a flag the block at the top of this file explains at
# length must not be set.
rm -f "${CONF_D}/enable-k8s-api" "${CONF_D}/k8s-kubeconfig-path"

# The SAME kprobes chapter 2 writes, byte for byte. Duplicated rather than shared on purpose: the two
# chapters' boxes are provisioned independently and a substrate that sourced a common file would make
# the chapters' sensors silently coupled — change one rung's fingerprint and every other rung's
# measurement moves with it. See chapter-2-audit/tetragon.sh for why read_credentials hooks the
# syscall rather than the LSM hook, and why Postfix matching keeps it independent of $HOME.
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

# The tetragon binary has NO --version flag (measured on v1.7.0: "Error: unknown flag"), so the
# pin is the only version statement, and the binary path proves the install landed.
echo "tetragon: ${TETRAGON_VERSION} (pinned) at $(command -v tetragon)"
echo "policy: ${POLICY} ($(grep -c '^    - call:' "${POLICY}") kprobes)"
echo "attribution: by CONTAINER ID (process.docker), matched against the pod's own containerID from"
echo "             the k8s API — NOT --enable-k8s-api, which does not resolve pods here and delays"
echo "             every event up to 30s in the EventCache. See the block at the top of this file."
echo "export rotation: $(cat "${CONF_D}/export-file-max-size-mb") MB, compress=$(cat "${CONF_D}/export-file-compress")"
echo "service: $(systemctl is-enabled tetragon 2>/dev/null || echo disabled) (the lesson starts its own)"
