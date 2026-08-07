"""Lesson 1 — the rogue agent with nothing in its way. The baseline everything else is measured against.

There is no boundary here. The same nine attacks that every later lesson runs are run once, as a
bare process, and every single one lands: it reads planted credentials, tries to exfiltrate them,
plants a backdoor, reaches for the cloud-metadata endpoint, installs a package that runs code at
install time, fetches a second stage, exhausts resources (bounded), and enumerates the host kernel
including ``bpf()`` — and nothing anywhere records that any of it happened.

**Where this really runs.** On a fresh, disposable bare-metal box, as a native host process — that
is the honest "no sandbox", and it is what ``infra/`` provisions. Running the destructive attacks as
a bare process on a machine you care about is exactly what you must not do, so this lesson refuses to
run natively unless it is told the box is disposable (``SANDBOXING_TUTORIAL_DISPOSABLE=1``, set by
infra). Anywhere else it falls back to ``--standin``: the same suite in a fully-unconfined, throwaway
container — enough of a boundary to keep your laptop safe, little enough to still show the baseline.

    uv run python -u main.py               # native on a disposable box, else safe standin
    uv run python -u main.py --standin     # force the unconfined-container stand-in

Everything the box does is bounded and cleaned up, the credentials are obvious fakes, and no attack
is ever aimed at anything but this box itself. Then, on a real run, the box is destroyed.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sandboxing-tutorial/agent:latest"
SUITE_DIR = REPO_ROOT / "infra" / "images" / "agent"  # PYTHONPATH for the native run
RESULTS = REPO_ROOT / "results" / "lesson-01.json"
GROUPS = "reach,abuse,kernel,cost"
# Attack 4's target, inherited from the environment rather than hardcoded, and forwarded into every
# sandbox below. `infra/run.sh` points it at the cloud this box actually runs on: Scaleway answers on
# 169.254.42.42, AWS on 169.254.169.254, and a probe aimed at the wrong one reads BLOCKED for a
# reason that has nothing to do with the boundary under test. Empty means "use the suite's default".
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["-e", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def engine() -> str:
    for eng in ("podman", "docker"):
        if shutil.which(eng):
            return eng
    sys.exit("No container engine found. Install podman (preferred) or docker.")


def node_kernel(eng: str) -> str:
    """The Linux kernel the container's host runs — read from a plain container, not the host.

    In the stand-in the box shares the podman VM's kernel, and on macOS that is NOT the host's Darwin
    (which ``platform.release()`` would return). A plain container under the default runtime shares
    the host kernel, so its ``uname -r`` is the node's, on macOS and on a Linux box alike.
    """
    out = subprocess.run(
        [eng, "run", "--rm", "--entrypoint", "uname", IMAGE, "-r"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return out.stdout.strip() or platform.release()


def ensure_image(eng: str) -> None:
    exists = subprocess.run([eng, "image", "exists", IMAGE], capture_output=True).returncode == 0
    if not exists and eng == "docker":
        exists = subprocess.run([eng, "image", "inspect", IMAGE], capture_output=True).returncode == 0
    if not exists:
        print(f"  image {IMAGE} not found — building it once via infra/images/agent/build.sh")
        subprocess.run(["bash", str(SUITE_DIR / "build.sh")], check=True)


def run_native() -> Card:
    """The real 'no boundary': the suite as a bare host process on a disposable box."""
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


def run_standin(eng: str) -> Card:
    """A stand-in for a bare host process: the same suite in a fully-unconfined throwaway container.

    Every namespace shared with the host that podman will allow, every capability added, seccomp and
    label confinement off. It is not literally 'no boundary' — the mount namespace still gives it its
    own root filesystem — but it is as close as is safe on a machine you are not about to destroy.
    """
    ensure_image(eng)
    print("  mode: STAND-IN (fully-unconfined throwaway container) — safe on a non-disposable machine")
    argv = [
        eng,
        "run",
        "--rm",
        "--user",
        "0",
        "--security-opt",
        "seccomp=unconfined",
        "--security-opt",
        "label=disable",
        "--cap-add",
        "ALL",
        "--network",
        "host",
        "--pid",
        "host",
        "-e",
        "PLANT_FAKE_SECRETS=1",
        "-e",
        f"PROBE_GROUPS={GROUPS}",
        "-e",
        f"PROBE_NODE_KERNEL={node_kernel(eng)}",
        *METADATA_ENV,
        IMAGE,
    ]
    print(f"  $ {' '.join(argv)}\n")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    _echo_box_stderr(done.stderr)
    return Card.parse(done.stdout)


def _echo_box_stderr(stderr: str) -> None:
    if stderr:
        print("  --- box stderr (human view) ---")
        print("\n".join("  " + ln for ln in stderr.strip().splitlines()))
        print()


def main() -> None:
    force_standin = "--standin" in sys.argv[1:]
    disposable = os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") == "1"

    banner("Part 1 — The simplest thing that works: nothing at all")
    print("  The agent runs as a normal process with your privileges, your files, your network.")
    print("  This is how most agent code ships, and it is the row every later lesson improves on.")

    banner("Part 2 — Turn the rogue agent loose (the same nine attacks)")
    if force_standin:
        card = run_standin(engine())
    elif disposable:
        card = run_native()
    else:
        print("  This is not a disposable box (SANDBOXING_TUTORIAL_DISPOSABLE is unset), so running")
        print("  the destructive attacks natively here is refused. Falling back to the safe stand-in.\n")
        card = run_standin(engine())
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

    # The kernel this rung ran on. Recorded on every lesson so the overall report can tell when two
    # rungs were measured on different machines — without it the guard has nothing to compare and
    # silently passes. Taken from the suite's own reading rather than platform.release(), because in
    # the stand-in on macOS the host is Darwin while the box's kernel is the podman VM's Linux.
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
        boundary=("native host process" if (disposable and not force_standin) else "unconfined container (stand-in)"),
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)} — lesson 2 reads it for its Part 3.")
    report = Path(__file__).parent / "report.html"
    if render_report(REPO_ROOT):
        print(f"  report written to  {report.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
