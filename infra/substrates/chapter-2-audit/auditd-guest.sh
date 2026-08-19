#!/usr/bin/env bash
# Chapter 2 audit substrate — auditd INSIDE the NAT guest (lesson 2.2.4).
#
# 2.2.4 audits 1.2.4 (OpenShell on ordinary runc). OpenShell has NO kernel boundary — it is runc with the
# host kernel fully exposed — so unlike Kata (2.2.3), the workload's syscalls DO reach the host kernel this
# auditd watches. Here "the host" is the NAT guest 50-nat-vm built and 40-openshell runs OpenShell inside:
# this substrate runs AFTER both, so up.sh has already re-pointed the box at the guest and this auditd lands
# in the guest, watching the same kernel the sandbox shares.
#
# The workload runs as a ROOTLESS podman container whose processes land at a subuid on the host
# (container `sandbox`/uid 1000 -> host 100999, from /etc/subuid). uid>=1000 captures them along with the
# gateway; the lesson maps a probe to a record by the WORKLOAD-UNIQUE PATH it touches (its planted
# credentials under /sandbox, its backdoor writes to /sandbox/.bashrc, the pip-installed agent_probe_evil),
# so the runtime/gateway noise at uid 1000 does not produce false positives. The gap is honest and
# teachable: the attacks that FAIL before touching a real file — the seccomp-refused bpf/io_uring/perf
# (blocked at syscall entry, before the audit exit hook) and the Landlock-denied /etc write — leave no
# matchable record, so a host syscall auditor sees what the workload DID, not what the boundary denied.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y -qq auditd audispd-plugins >/dev/null

# Two auditd.conf changes, and BOTH were needed for the lesson to read a stable trail (measured on the
# box 2026-08-14; without them the mapping was intermittent — a probe read LOGGED one run and blank the
# next, for reasons that had nothing to do with the sandbox):
#   * log_format RAW, not the Debian-default ENRICHED. ENRICHED appends interpreted fields with no
#     separators (`key="sbx_open"ARCH=x86_64 SYSCALL=openat...`) and prefixes `node=`, which breaks the
#     simple `grep type=PATH ... name="..."` the lesson uses to map a probe to the file it touched.
#   * max_log_file 500 MB (from the 8 MB default) so the log does NOT rotate mid-run. The suite makes
#     thousands of openat records; at 8 MB the log rotated to audit.log.1 during the run and the sensitive
#     records the lesson greps for landed in a ROTATED segment — read as a false blank. 500 MB holds a
#     whole run in one file; the box is disposable, so the disk cost does not matter.
sed -i 's/^log_format = ENRICHED/log_format = RAW/I' /etc/audit/auditd.conf
sed -i 's/^max_log_file = .*/max_log_file = 500/' /etc/audit/auditd.conf

cat >/etc/audit/rules.d/sandboxing.rules <<'RULES'
## sandboxing-tutorial phase-2 audit rules (guest) — the attack-shaped syscalls, watched at uid>=1000.
-D
# A large backlog rather than dropping records: the runtime is high-volume (podman/crun open thousands of
# files), and a small backlog would drop records and muddy the count the lesson reports. Waiting taxes
# syscall time, which does not matter on an audit box.
-b 131072
--backlog_wait_time 60000
# execve / connect / openat+openat2 / bpf / io_uring / perf — the syscalls the rogue-agent suite makes.
# The rules ARE correct and DO fire; the finding is WHOSE syscalls they catch (the runtime's, never the
# rootless workload's). openat2 is a separate rule from openat because a combined `-S openat -S openat2`
# never arms openat2 on Debian 13; both are kept so the trail reflects modern glibc's open path too.
-a always,exit -F arch=b64 -S execve -F uid>=1000 -k sbx_exec
-a always,exit -F arch=b64 -S connect -F uid>=1000 -k sbx_net
-a always,exit -F arch=b64 -S openat -F uid>=1000 -k sbx_open
-a always,exit -F arch=b64 -S openat2 -F uid>=1000 -k sbx_open
-a always,exit -F arch=b64 -S bpf -F uid>=1000 -k sbx_bpf
-a always,exit -F arch=b64 -S io_uring_setup -F uid>=1000 -k sbx_iouring
-a always,exit -F arch=b64 -S perf_event_open -F uid>=1000 -k sbx_perf
RULES

# RESTART, not `enable --now`. apt started auditd with the DEFAULT auditd.conf, so the log_format/
# max_log_file edits above are on disk but NOT in the running daemon — `enable --now` is a no-op on an
# already-running service and would leave it on ENRICHED + 8 MB, which is precisely the intermittency
# these edits fix. Restart makes the daemon re-read auditd.conf and re-load rules.d. (measured 2026-08-15)
systemctl enable auditd >/dev/null 2>&1 || true
systemctl restart auditd >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1 || true
sleep 1
augenrules --load >/dev/null 2>&1 || auditctl -R /etc/audit/rules.d/sandboxing.rules >/dev/null 2>&1 || true

echo "auditd: $(systemctl is-active auditd 2>/dev/null || echo running)  (inside NAT guest $(hostname))"
echo "config: $(grep -i '^log_format' /etc/audit/auditd.conf), $(grep '^max_log_file' /etc/audit/auditd.conf)"
echo "loaded $(auditctl -l 2>/dev/null | grep -c sbx_ || echo 0) sandboxing rules:"
auditctl -l 2>/dev/null | grep sbx_ || true
