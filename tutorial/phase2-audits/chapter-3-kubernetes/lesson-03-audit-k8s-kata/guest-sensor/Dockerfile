# The in-guest sensor image for lesson 2.3.3 — the sidecar that rides INSIDE the Kata guest with the
# workload, because no sensor on the node can see through the guest kernel (2.3.6 measured the host
# eBPF probe at exactly 0 events).
#
# It mirrors infra/images/agent (the one shared attack image) and adds `strace`. Two reasons it is a
# ptrace tracer rather than the kernel-side sensor the plan called for, both MEASURED on a live
# cluster 2026-08-15 and written up in the lesson README:
#
#   * the guest's audit subsystem is unreachable from any pod container — `privileged: true`,
#     `runAsUser: 0`, `hostPID: true` and a full CapEff still get EPERM on the audit netlink, because
#     the kernel gates it on the INITIAL pid namespace and Kata's agent puts the whole pod in a child
#     one. `hostPID` under Kata means "the sandbox", not "the VM's init".
#   * a process may always trace a process it can ptrace in a shared pid namespace, and
#     `shareProcessNamespace: true` gives the sidecar exactly that.
#
# The attack code (attacks/, entrypoint.sh) is COPY'd from the SAME source as the shared image —
# main.py assembles the build context from infra/images/agent and drops these files in — so the suite
# is byte-identical. It is restated FROM a registry base rather than `FROM sandboxing-tutorial/agent`
# because BuildKit cannot resolve a local-only containerd image as a base.
FROM python:3.12-slim-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates procps iproute2 strace \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir setuptools wheel
RUN groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /sandbox --shell /bin/bash sandbox
WORKDIR /app
COPY attacks/ /app/attacks/
COPY entrypoint.sh /app/entrypoint.sh
COPY sensor.sh /app/sensor.sh
COPY kernel_probe.py /app/kernel_probe.py
RUN chmod +x /app/entrypoint.sh /app/sensor.sh
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/sandbox \
    DRIVER=script
# NO `USER sandbox`: this image is the SIDECAR and must start as root to ptrace the workload, which
# runs as uid 1000. The workload container uses the ordinary agent image and its own securityContext.
ENTRYPOINT ["/app/sensor.sh"]
