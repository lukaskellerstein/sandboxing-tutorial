#!/usr/bin/env bash
# Chapter 1 audit substrate — host auditd (lesson 2.1.1). The kernel audit subsystem records the
# syscalls the attack suite makes on the bare host, so the lesson can ask "was any of it written
# down?" against a REAL record rather than a claim.
#
# This is the counterpoint the phase-2 finding turns on: on the NO-SANDBOX rung — the one where every
# attack lands — the host sensor sees essentially everything, because there is no boundary between the
# attack's syscall and the kernel that audits it. Full observability, zero isolation. Every later rung
# trades one for the other, in opposite directions.
#
# Rules are KEYED so the lesson maps each probe to its own audit key with `ausearch -k`, rather than
# grepping raw text. auid>=1000 restricts syscall rules to the unprivileged `agent` user (uid 1000+),
# keeping the system's own boot/systemd noise out of the trail.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq auditd audispd-plugins >/dev/null

cat >/etc/audit/rules.d/sandboxing.rules <<'RULES'
## sandboxing-tutorial phase-2 audit rules — one key per attack fingerprint.
-D
# A large backlog, and WAIT rather than drop: the openat rule below is high-volume (the suite opens
# thousands of files), and with a small backlog + wait_time 0 the kernel drops the rarer records —
# the bpf/io_uring/perf attempts vanish and read as "not logged" when they were merely lost. Waiting
# taxes syscall time, which does not matter on an audit box.
-b 65536
--backlog_wait_time 60000
# execve — malicious_package (pip runs code at install), reverse_shell (curl a payload), plant_backdoor
# (drops a unit and reloads systemd), resource_exhaustion (the fork bomb).
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k sbx_exec
# connect — exfiltrate (the collector), cloud_metadata (169.254.x), reverse_shell (the second stage).
-a always,exit -F arch=b64 -S connect -F auid>=1000 -F auid!=unset -k sbx_net
# openat — read_credentials reads the planted canaries; the lesson filters the path from the record.
-a always,exit -F arch=b64 -S openat -F auid>=1000 -F auid!=unset -F success=1 -k sbx_open
# kernel-surface syscalls the suite exercises directly.
-a always,exit -F arch=b64 -S bpf -k sbx_bpf
-a always,exit -F arch=b64 -S io_uring_setup -k sbx_iouring
-a always,exit -F arch=b64 -S perf_event_open -k sbx_perf
# NOTE: a `-w /proc/kallsyms -p r` watch does NOT fire — auditd's inode watches do not work on
# procfs. The open of /proc/kallsyms is instead caught by the sbx_open (openat) rule above, and the
# lesson matches it by path. /proc/modules is not opened at all — the suite reads /sys/module by
# directory listing (getdents), which nothing here records: an honest gap, and its own small finding.
RULES

# Load the rules. augenrules compiles rules.d into the running set; fall back to auditctl if the
# service model on this image differs.
systemctl enable --now auditd >/dev/null 2>&1 || service auditd start || true
augenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/sandboxing.rules >/dev/null 2>&1 || true

echo "auditd: $(systemctl is-active auditd 2>/dev/null || echo running)"
echo "loaded $(auditctl -l 2>/dev/null | grep -c sbx_ || echo 0) sandboxing rules:"
auditctl -l 2>/dev/null | grep sbx_ || true
