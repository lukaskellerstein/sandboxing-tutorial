# The one image every lesson shares. It carries the attack suite and, later, the agent driver;
# a lesson only supplies the boundary it runs this under. Built natively on the box (x86_64 on the
# Scaleway hosts, arm64 on a Mac podman machine for local smoke tests) — no cross-building, no qemu.
#
# The preamble (a real non-root `sandbox` user + group, HOME=/sandbox, iproute2, a writable /tmp)
# is what lets the SAME image also run under OpenShell later without a rebuild — two image variants
# would mean the ladder compares images instead of comparing isolation.
FROM python:3.12-slim-bookworm

# curl: attacks 2/4/5/6 and the policy probes shell out to the real binary, because OpenShell's
#   policy is per-binary and only sees what an agent's tools would actually run.
# procps/iproute2: process and network inspection the probes and a human debugging the box use.
# ca-certificates: so egress to https targets is a policy decision, not a TLS failure.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates procps iproute2 \
    && rm -rf /var/lib/apt/lists/*

# setuptools + wheel are needed at runtime by attack 5's offline sdist build (--no-build-isolation).
RUN pip install --no-cache-dir setuptools wheel

# A real unprivileged user with a real home — not just USER 1000. HOME=/sandbox matches the path
# OpenShell expects and keeps $HOME writable when a lesson mounts the rootfs read-only + a tmpfs.
RUN groupadd --gid 1000 sandbox \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /sandbox --shell /bin/bash sandbox

WORKDIR /app
COPY attacks/ /app/attacks/
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Unbuffered: a buffered stdout makes a working run that is mid-probe look hung — a trap the prior
# art hit repeatedly. The scorecard line must appear the instant it is printed.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/sandbox \
    DRIVER=script

USER sandbox
ENTRYPOINT ["/app/entrypoint.sh"]
