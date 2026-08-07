#!/usr/bin/env bash
# The image's one entrypoint. It dispatches on DRIVER so the SAME image serves both the
# deterministic script front-end (what proves the environments) and, later, the real agent.
#
#   DRIVER=script   run the nine attacks from a fixed script — deterministic, no model. (default)
#   DRIVER=agent    steer a real agent into running them via prompt injection.        (phase 2)
#
# Everything human goes to stderr; stdout carries the one SCORECARD_JSON line (and, under the agent
# driver, one AGENT_JSON line). Args after the driver are passed through, e.g. --groups kernel,cost.
set -euo pipefail

DRIVER="${DRIVER:-script}"

case "${DRIVER}" in
  script)
    exec python -m attacks.run "$@"
    ;;
  agent)
    echo "[entrypoint] DRIVER=agent is not built yet — this is phase 2 (the four frameworks)." >&2
    echo "[entrypoint] The environments are proven with DRIVER=script first, by design." >&2
    exit 3
    ;;
  *)
    echo "[entrypoint] unknown DRIVER='${DRIVER}' — choose 'script' or 'agent'." >&2
    exit 2
    ;;
esac
