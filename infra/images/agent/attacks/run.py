"""The script driver — run the nine attacks inside the box and print the scorecard.

This is the deterministic front-end: it runs the *same* attacks an agent would be steered into
running, but from a fixed script instead of a model. That determinism is the point — it lets a
lesson prove the boundary engaged without a language model in the loop, so a cell flipping
REACHED → BLOCKED between two rungs is unambiguously the boundary and never the model phrasing an
attack differently. The agent driver (``DRIVER=agent``) reuses this exact suite; only who *calls*
the attacks changes.

Contract, identical on every rung:

* every human-readable word goes to **stderr**;
* **stdout** carries one ``FINDING_JSON {...}`` line per attack as it completes, then a final
  ``SCORECARD_JSON {...}`` line with the whole card.

so a lesson can run this behind any boundary and parse the result the same way. The streaming half
exists because a *sandbox can die mid-suite*: attack 7's fork bomb OOM-kills a gVisor sandbox
outright, and a card printed only at the end would take the kernel evidence down with it. Stream,
and the host keeps everything up to the attack that killed the box — then reads that last attack's
verdict off the exit status, which is the only place it is still legible.

Exit status is 0 whenever the suite ran to completion — the findings are data, not a failure. A
non-zero exit means the suite itself could not run, or the box did not survive it: either way the
host must say so rather than report a short card as a complete one.
"""

from __future__ import annotations

import getpass
import os
import platform
import socket
import sys

from .report import DEFAULT_GROUPS, FINDING_SENTINEL, IN_BOX_GROUPS, Finding
from .suite import plant_fake_secrets, run_groups


def log(message: str = "") -> None:
    """Human output → stderr. stdout is reserved for the machine lines."""
    print(message, file=sys.stderr, flush=True)


def emit(finding: Finding) -> None:
    """One finding → stdout, immediately. Flushed, because the next attack may end the sandbox."""
    print(f"{FINDING_SENTINEL} {finding.to_json()}", flush=True)


def resolve_groups(argv: list[str]) -> list[str]:
    """Groups from ``--groups a,b`` or ``PROBE_GROUPS``; default is every in-box group."""
    raw = ""
    if "--groups" in argv:
        idx = argv.index("--groups")
        raw = argv[idx + 1] if idx + 1 < len(argv) else ""
    raw = raw or os.environ.get("PROBE_GROUPS", "")
    groups = [g.strip() for g in raw.split(",") if g.strip()] if raw else list(DEFAULT_GROUPS)
    unknown = [g for g in groups if g not in IN_BOX_GROUPS]
    if unknown:
        log(f"[driver] ignoring unknown group(s): {unknown} (choose from {list(IN_BOX_GROUPS)})")
    return [g for g in groups if g in IN_BOX_GROUPS]


def identity() -> str:
    """Who and where this ran — printed to stderr so a human can confirm the box is the box."""
    try:
        user = getpass.getuser()
    except Exception:
        user = str(os.getuid()) if hasattr(os, "getuid") else "?"
    return f"host={socket.gethostname()} user={user} kernel={platform.system()} {platform.release()} arch={platform.machine()}"


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    groups = resolve_groups(argv)

    log("=" * 72)
    log("  DRIVER=script — the rogue agent's nine attacks, run deterministically")
    log(f"  {identity()}")
    log(f"  groups: {groups}")
    log("=" * 72)

    if "--plant" in argv or os.environ.get("PLANT_FAKE_SECRETS") == "1":
        planted = plant_fake_secrets()
        log(f"[driver] planted {planted} fake canary credential(s) into $HOME (lesson 1 baseline)")

    card = run_groups(groups, on_finding=emit)

    log("")
    log(card.table())
    blocked, applicable = card.tally()
    log("")
    log(f"  boundaries that held: {blocked}/{applicable}")
    log("  (evidence/audit is measured by the lesson from the runtime's logs, not from in here)")

    # The whole card, as one line. The per-finding lines above already carry the same data; this is
    # the host's fast path and its proof that the suite reached the end.
    print(f"SCORECARD_JSON {card.to_json()}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
