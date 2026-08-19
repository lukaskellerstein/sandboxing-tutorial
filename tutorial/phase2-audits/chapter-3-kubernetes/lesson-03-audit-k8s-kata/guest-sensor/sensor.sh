#!/bin/sh
# The in-guest sensor for lesson 2.3.3, running as the pod's privileged SIDECAR.
#
# It is a ptrace tracer, and that is the lesson's finding rather than a shortcut — see the README and
# kernel_probe.py. What makes it possible on Kubernetes and impossible under nerdctl (2.2.3) is
# `shareProcessNamespace: true`: every container in a pod then lives in ONE pid namespace inside the
# guest, so this container can see and trace the workload's processes. Under nerdctl each container
# is its own VM and there is nothing to share.
#
# THE ORDERING PROBLEM, and why the workload waits for us. A tracer that attaches after the workload
# has started misses everything it already did — which on a suite whose first act is reading
# credentials means missing the attack the lesson cares most about. So the two containers hand off
# through a shared emptyDir: the workload blocks until /coord/go exists, we attach first, then create
# it. That handshake is a real property of sidecar sensors and worth seeing rather than hiding.
set -u

COORD=/coord
TRACE="${COORD}/trace.log"
GO="${COORD}/go"
#: The workload's command carries this marker so we can find it in the shared pid namespace without
#: guessing at process names — `sh` and `python` are both ambiguous here, since this container runs
#: them too.
MARKER=SBX_WORKLOAD_2_3_3

echo "sensor: uid=$(id -u) kernel=$(uname -r)"
python /app/kernel_probe.py || echo "SBX_AUDIT_NETLINK probe-failed"

# --- find the workload in the shared pid namespace ----------------------------
PID=""
i=0
while [ "${i}" -lt 180 ]; do
  for c in /proc/[0-9]*/cmdline; do
    p=$(echo "${c}" | cut -d/ -f3)
    [ "${p}" = "$$" ] && continue
    if grep -qa "${MARKER}" "${c}" 2>/dev/null; then
      PID="${p}"
      break
    fi
  done
  [ -n "${PID}" ] && break
  i=$((i + 1))
  sleep 1
done

if [ -z "${PID}" ]; then
  echo "SBX_SENSOR_STATUS no-workload-visible"
  echo "  the pid namespace is NOT shared — shareProcessNamespace must be true, or this sidecar"
  echo "  cannot see the workload at all."
  touch "${GO}" 2>/dev/null
  exit 0
fi
echo "sensor: workload pid ${PID} ($(tr '\0' ' ' <"/proc/${PID}/cmdline" | cut -c1-60))"

# --- attach BEFORE releasing the workload -------------------------------------
#
# -f follows the children the suite spawns, and it survives the `exec` the workload's shell does, so
# the trace covers the suite from its first syscall. The syscall set is the same one 2.2.2 and 2.2.3
# grep for, so the three in-guest/sentry rungs are mapped identically.
: >"${TRACE}"
strace -f -qq -y \
  -e trace=execve,connect,openat,openat2,open,bpf,io_uring_setup,perf_event_open \
  -o "${TRACE}" -p "${PID}" &
STRACE_PID=$!
sleep 3
if ! kill -0 "${STRACE_PID}" 2>/dev/null; then
  echo "SBX_SENSOR_STATUS strace-failed-to-attach"
  touch "${GO}"
  exit 0
fi
echo "SBX_SENSOR_STATUS attached"
touch "${GO}"

# --- wait for the workload to finish ------------------------------------------
while [ -d "/proc/${PID}" ]; do sleep 2; done
sleep 4
kill "${STRACE_PID}" 2>/dev/null
sleep 1

# --- map the trace to the suite's probes --------------------------------------
#
# Grepped HERE, in the guest, and never shipped out: the fork bomb floods this file to tens of MB of
# part-binary text. Only the verdicts cross the boundary, as SBX_FP lines main.py parses.
say_if() { # $1 = probe name, $2 = ERE
  if grep -qaE "$2" "${TRACE}" 2>/dev/null; then echo "SBX_FP $1"; fi
}

say_if read_credentials 'open(at)?\(.*(id_rsa|id_ed25519|\.aws/credentials|hosts\.yml|/\.netrc|/\.env)'
say_if kallsyms_readable 'open(at)?\(.*/proc/kallsyms'
say_if sys_module_count 'open(at)?\(.*(/proc/modules|/sys/module)'
say_if bpf '\bbpf\('
say_if io_uring_setup '\bio_uring_setup\('
say_if perf_event_open '\bperf_event_open\('
# Any exec at all IS the fingerprint for the four exec-driven attacks, exactly as 2.2.1/2.3.1 treat
# Tetragon's process_exec: the suite's only execs are the ones those attacks make.
if grep -qaE '\bexecve\(' "${TRACE}"; then
  for p in plant_backdoor malicious_package reverse_shell resource_exhaustion; do echo "SBX_FP ${p}"; done
fi
# The two network attacks separate on the destination, as they do in 2.2.2's sentry mapping: the
# metadata service is a fixed link-local address, everything else is the exfiltration target.
if grep -qaE 'connect\(.*169\.254' "${TRACE}"; then echo "SBX_FP cloud_metadata"; fi
# Filter to connect lines FIRST, then ask whether any of them went somewhere other than the metadata
# service. The tempting one-liner — `grep -qa 'connect(' && grep -qav '169.254'` — is wrong and
# always true: `grep -v` succeeds as soon as ANY line in the file fails to match, and the file is
# mostly openat.
if grep -aE 'connect\(' "${TRACE}" 2>/dev/null | grep -qavE '169\.254'; then
  echo "SBX_FP exfiltrate"
fi

echo "SBX_TRACE_LINES $(wc -l <"${TRACE}" 2>/dev/null || echo 0)"
echo "SBX_TRACE_BYTES $(wc -c <"${TRACE}" 2>/dev/null || echo 0)"
echo "SBX_SENSOR_STATUS done"
