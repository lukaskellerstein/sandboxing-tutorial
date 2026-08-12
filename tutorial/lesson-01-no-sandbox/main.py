"""Lesson 1 — the rogue agent with nothing in its way. The baseline everything else is measured against.

There is no boundary here. The same nine attacks that every later lesson runs are run once, as a
bare process, and every single one lands: it reads planted credentials, tries to exfiltrate them,
plants a backdoor, reaches for the cloud-metadata endpoint, installs a package that runs code at
install time, fetches a second stage, exhausts resources (bounded), and enumerates the host kernel
including ``bpf()`` — and nothing anywhere records that any of it happened.

**Where this really runs — and ONLY where.** On a fresh, disposable Scaleway box, as a native host
process. That is the honest "no sandbox", and running the destructive attacks as a bare process on a
machine you care about is exactly what you must not do — so this lesson runs on the box and NOWHERE
ELSE. But ``uv run main.py`` is still the one command you type: start the box, then run it.

    # 1. start the box (once):
    cd ../../infra && ./up.sh lesson-01-no-sandbox     # or press 'u' in the sbx-tui panel
    # 2. run the lesson — from this directory, as many times as you like:
    uv run python -u main.py

``main.py`` is aware of the box. On the box (``infra/run.sh`` sets ``SANDBOXING_TUTORIAL_DISPOSABLE=1``)
it runs the attacks natively. On your machine it sees the box is up and runs the lesson ON it — sync,
execute, fetch the scorecard. With no box up it runs nothing and tells you to start one.

Everything the box does is bounded and cleaned up, the credentials are obvious fakes, and no attack
is ever aimed at anything but this box itself. Then the box is destroyed.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[2]
LESSON = "lesson-01-no-sandbox"
#: What infra records about this lesson's box. Read only to make the refusal ACTIONABLE — "no box at
#: all" and "the box is up, you are just not on it" need different next steps. Missing means missing:
#: the leaf still runs from a clone that has never touched infra/, nothing is imported from it, and
#: nothing breaks if the file never appears.
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
SUITE_DIR = REPO_ROOT / "infra" / "images" / "agent"  # PYTHONPATH for the native run
RESULTS = REPO_ROOT / "results" / "lesson-01.json"
GROUPS = "reach,abuse,kernel,cost"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def run_native() -> Card:
    """The real 'no boundary': the suite as a bare host process on the disposable box.

    The one and only way this lesson runs. There is no laptop stand-in: the whole point is a native
    process on a machine that is about to be destroyed, and nothing else measures the same thing.
    """
    print("  mode: NATIVE host process (no container, no boundary) — the honest baseline")
    print(f"  $ PYTHONPATH={SUITE_DIR} PLANT_FAKE_SECRETS=1 python -m attacks.run --groups {GROUPS}\n")
    env = {
        **os.environ,
        "PYTHONPATH": str(SUITE_DIR),
        "PLANT_FAKE_SECRETS": "1",
        # The node's kernel IS this process's kernel here — which is exactly the finding.
        "PROBE_NODE_KERNEL": platform.release(),
    }
    done = subprocess.run(
        [sys.executable, "-m", "attacks.run", "--groups", GROUPS],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    _echo_box_stderr(done.stderr)
    return Card.parse(done.stdout)


def _echo_box_stderr(stderr: str) -> None:
    if stderr:
        print("  --- box stderr (human view) ---")
        print("\n".join("  " + ln for ln in stderr.strip().splitlines()))
        print()


def box_ip_if_any() -> str | None:
    """The IP of this lesson's box, from infra's state file — or None if there is no box.

    A refusal decision only, never imported logic: the leaf stays runnable from a clone that has
    never touched ``infra/`` (the file is simply absent → None → "start a box first"). Nothing here
    talks to Scaleway; "state file present" is a good enough proxy for "a box is up" to tell someone
    what to do next, and being wrong only means the message points at ``run.sh`` instead of ``up.sh``.
    """
    try:
        for line in STATE_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("BOX_IP="):
                return line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        return None
    return None


def run_on_box(ip: str) -> int:
    """A box is up but this is not it — run the lesson ON the box, exactly as ./run.sh does.

    This is what makes ``uv run main.py`` the only command a reader needs: start the box, then run
    it from here as often as you like. It delegates to infra/run.sh so there is a single
    implementation of "run this lesson on its box" — that run sets SANDBOXING_TUTORIAL_DISPOSABLE=1,
    so the copy of main.py which executes ON the box takes the native path below rather than
    delegating again (no loop).
    """
    runner = REPO_ROOT / "infra" / "run.sh"
    print(f"Box for {LESSON} is up ({ip}). Running the lesson ON it via infra/run.sh …\n")
    return subprocess.run([str(runner), LESSON]).returncode


def refuse_no_box() -> None:
    """No box is up — say how to start one, and exit having run NOTHING.

    A native rogue-agent run is only acceptable on a machine that is about to be destroyed, so with
    no box there is nothing safe to do here but tell you to start one. This is the "the VM is DOWN"
    message rather than a full run against your laptop.
    """
    print(f"No box for {LESSON} is up — nothing to run.")
    print("This lesson only runs on its own disposable Scaleway box (a native rogue-agent run is only")
    print("acceptable on a machine about to be destroyed). Start one, then run it from here:\n")
    print(f"    cd ../../infra && ./up.sh {LESSON}      # or press 'u' in the sbx-tui panel")
    print("    uv run python -u main.py                # runs it on the box and brings the card home")
    raise SystemExit(2)


def main() -> None:
    # `uv run main.py` is the one command. On the disposable box it runs the attacks for real (infra
    # sets SANDBOXING_TUTORIAL_DISPOSABLE=1 there). On your machine it runs the lesson ON the box when
    # one is up, and tells you to start one when none is.
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        ip = box_ip_if_any()
        if not ip:
            refuse_no_box()
            return  # unreachable — refuse_no_box exits — but narrows ip to str for the type checker
        raise SystemExit(run_on_box(ip))

    banner("Part 1 — The simplest thing that works: nothing at all")
    print("  The agent runs as a normal process with your privileges, your files, your network.")
    print("  This is how most agent code ships, and it is the row every later lesson improves on.")

    banner("Part 2 — Turn the rogue agent loose (the same nine attacks)")
    card = run_native()
    print(card.render())
    blocked, applicable = card.tally()
    print(f"\n  boundaries that held: {blocked}/{applicable}")

    banner("Part 4 — What is still open (for lesson 1, that is everything)")
    reached = card.reached()
    print(f"  {len(reached)} of the attacks landed with nothing to stop them:")
    for f in reached:
        print(f"    {f['name']:<20} {f['value']}")
    print("\n  Lesson 1 has no Part 3 — there is no rung below it to compare against. Every row above")
    print("  is a promise the rest of the tutorial keeps: lesson 2 (a container) closes most of them")
    print("  at once, and the few it leaves open are why gVisor, Kata and OpenShell exist.")
    if card.contained("cloud_metadata") is True:
        print("\n  Note: cloud_metadata shows BLOCKED only because this box has no metadata endpoint")
        print("  (a laptop VM does not). On a real cloud box it is REACHED — the classic SSRF target.")

    # We only reach here on the disposable box (main() refuses everywhere else), so this run IS the
    # measurement and always records. The kernel is recorded on every lesson so the overall report
    # can tell when two rungs were measured on different machines — without it the guard has nothing
    # to compare and silently passes.
    kernel = card.get("kernel_identity")
    card.save(
        RESULTS,
        lesson="lesson-01-no-sandbox",
        # There is no second mode here, and that is the point rather than an omission: turning
        # egress off requires a boundary, and this rung is the absence of one. The baseline is
        # network-on by construction, which is also why it is the honest thing to compare the
        # other rungs' network-on cards against.
        mode="network-on",
        node_kernel=str(kernel["value"]) if kernel else platform.release(),
        boundary="native host process",
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)} — lesson 2 reads it for its Part 3.")
    report = Path(__file__).parent / "report.html"
    if render_report(REPO_ROOT):
        print(f"  report written to  {report.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
