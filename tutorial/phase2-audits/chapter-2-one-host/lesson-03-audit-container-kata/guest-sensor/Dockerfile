# The in-guest-sensor image for lesson 2.2.3. It mirrors infra/images/agent (the one shared attack
# image) and adds `strace` — the ptrace tracer that stands in for a sensor deployed INSIDE the Kata
# guest. Why a separate image at all: under Kata the workload runs in a guest VM whose kernel a HOST
# sensor cannot see, so the sensor has to move into the guest with the workload; and a kernel-side
# sensor (auditd/eBPF) is fenced off from a workload container by the guest's audit-netlink namespace
# rules, so the sensor that actually works from inside a single container is a ptrace tracer.
#
# The attack code (attacks/, entrypoint.sh) is COPY'd from the SAME source as the shared image — main.py
# assembles the build context from infra/images/agent and drops this Dockerfile + wrapper in — so the
# suite behaves identically; only the base preamble is restated. It is restated rather than reused via
# `FROM sandboxing-tutorial/agent` because nerdctl's BuildKit cannot resolve a local-only containerd
# image as a base (it tries to pull it from a registry), so this derives from the registry base.
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
COPY guest-strace-run.sh /app/guest-strace-run.sh
RUN chmod +x /app/entrypoint.sh /app/guest-strace-run.sh
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/sandbox \
    DRIVER=script
USER sandbox
ENTRYPOINT ["/app/guest-strace-run.sh"]
