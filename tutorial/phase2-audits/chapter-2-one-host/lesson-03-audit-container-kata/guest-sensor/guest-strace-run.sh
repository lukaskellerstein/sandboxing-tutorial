#!/bin/sh
# In-guest sensor for lesson 2.2.3. Trace the SAME entrypoint the measured run uses, under strace.
#
# strace traces its own children (the default ptrace_scope permits tracing a descendant), so it needs
# NO audit netlink and NO initial-namespace privilege. That is exactly why it is the sensor that works
# from inside a single Kata guest container: the guest kernel's audit subsystem is fenced off from a
# workload container (auditctl returns EPERM even as root with CAP_AUDIT_CONTROL and host namespaces),
# but a process may always trace the children it spawns.
#
# The trace is written to a bind-mounted directory so it survives the container's --rm and is grepped
# on the box. It is never read whole into the lesson: the suite makes tens of thousands of openat
# calls, so the host maps each probe to a syscall by grepping the file, not by parsing it.
set -e
LOG=/trace/kata-strace.log
: >"${LOG}"
strace -f -qq -y \
  -e trace=execve,connect,openat,openat2,bpf,io_uring_setup,perf_event_open \
  -o "${LOG}" \
  /app/entrypoint.sh
