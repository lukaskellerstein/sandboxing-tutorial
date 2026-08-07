"""Lesson 2 — the same nine attacks, now inside a hardened rootless container.

Lesson 1 ran the rogue agent with no boundary and every attack landed. This lesson changes exactly
one thing — it puts the *same image* behind a container with every everyday control turned on — and
re-runs the identical suite. Most attacks die here. Three do not, and those three are the whole rest
of the tutorial:

  * attack 8 (kernel) is untouched — a container shares the host kernel, so ``/sys/module`` is still
    full and the kernel identifies as the host's. That is lesson 3 (gVisor) and lesson 4 (Kata).
  * attacks 5–6 die ONLY because egress is fully off (``--network none``). A real agent needs *some*
    network, and the moment you allow any, blanket on/off cannot tell a typosquat install from a
    legitimate GET. That is lesson 5 (OpenShell).
  * nothing here recorded that any attempt was made (evidence = 0). Also lesson 5.

Part 4 stops *asserting* that second point and measures it. The same container runs the suite twice:

  ``egress-off``   ``--network none`` — the scoreboard everyone quotes
  ``network-on``   the engine's ordinary network — what an agent that must call an LLM API has

Both are the same container with the same hardening; only the network differs. The egress-off column
is the one that flatters a container, and it describes a deployment that cannot run an agent.

The boundary lives in the podman machine on macOS, or on the host kernel on a real Linux box — this
lesson runs the same either way. What it does NOT claim is a kernel boundary; see Part 4.

    cd tutorial/lesson-02-container && uv sync && uv run python -u main.py
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
# Attack 4's target, inherited from the environment rather than hardcoded, and forwarded into the
# sandbox below. `infra/run.sh` points it at the cloud this box actually runs on: Scaleway answers on
# 169.254.42.42, AWS on 169.254.169.254, and a probe aimed at the wrong one reads BLOCKED for a
# reason that has nothing to do with the boundary under test. Empty means "use the suite's default".
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["-e", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []

RESULTS = REPO_ROOT / "results" / "lesson-02.json"
#: The same rung measured with the network an agent actually needs. A separate card rather than a
#: second findings list, so every consumer keeps reading one card shape and can simply ask which
#: mode it holds.
RESULTS_NET_ON = REPO_ROOT / "results" / "lesson-02-network-on.json"
PREVIOUS = REPO_ROOT / "results" / "lesson-01.json"
SUITE_DIR = REPO_ROOT / "infra" / "images" / "agent"  # PYTHONPATH for the live no-sandbox re-run

# The boundary this lesson teaches: every everyday control, one throwaway container per run.
# HOME stays on the read-only rootfs (only /tmp is a small writable tmpfs), which is what makes the
# backdoor writes fail rather than land in an ephemeral home.
HARDENING = [
    "--cap-drop",
    "ALL",  # drop every Linux capability
    "--security-opt",
    "no-new-privileges",  # a child can never regain privilege
    "--read-only",  # immutable root filesystem...
    "--tmpfs",
    "/tmp:rw,exec,size=64m",  # ...with one small writable scratch space
    "--memory",
    "256m",
    "--memory-swap",
    "256m",  # cgroup memory cap (anti-exhaustion)
    "--pids-limit",
    "128",  # cgroup pids cap (anti-fork-bomb)
    "--cpus",
    "1",  # cgroup cpu cap
]

#: The only difference between the two runs in Part 4. Everything above stays identical, which is
#: what makes the comparison a measurement of the network model rather than of two containers.
NET_OFF = ["--network", "none"]  # deny all egress
#: No flag at all: the engine's default network, which is what you get when you do not think about
#: it — and what an agent that must reach an LLM API is given. Naming a specific mode here
#: (slirp4netns, pasta) would pin a podman implementation detail the lesson does not teach.
NET_ON: list[str] = []


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
    """The kernel the sandbox's host actually runs — read from a plain container, not the host.

    A plain container under the default runtime shares the host kernel, so its ``uname -r`` IS the
    node's. Sourcing it this way (rather than ``platform.release()``) is what keeps the kernel verdict
    correct when the engine runs inside a VM — as podman does on macOS, where the host is Darwin but
    the container's kernel is the Linux guest's. On a real Linux box the two are identical.
    """
    out = subprocess.run(
        [eng, "run", "--rm", "--entrypoint", "uname", IMAGE, "-r"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    return out.stdout.strip() or platform.release()


def ensure_image(eng: str) -> None:
    """Build every run. Layer caching makes that nearly free; skipping it can measure a stale suite."""
    build = REPO_ROOT / "infra" / "images" / "agent" / "build.sh"
    subprocess.run(["bash", str(build)], check=True, capture_output=True, env={**os.environ, "CONTAINER_ENGINE": eng})


def run_in_container(eng: str, net: list[str]) -> Card:
    argv = [
        eng, "run", "--rm", "--user", "1000:1000", *HARDENING, *net,
        "-e", "PROBE_GROUPS=reach,abuse,kernel,cost",
        "-e", f"PROBE_NODE_KERNEL={node_kernel(eng)}",
        *METADATA_ENV,
        IMAGE,
    ]  # fmt: skip
    print(f"  $ {' '.join(argv)}\n")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    if done.stderr:
        print("  --- box stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()))
        print()
    return Card.parse(done.stdout)


def previous_rung() -> tuple[Card | None, str]:
    """Get lesson 1's rung to compare against — re-run live where that is possible.

    Re-running beats reading a file, and not by a little: with one disposable box per lesson, a
    recorded lesson-01 card was measured on a *different machine*, so any difference could be the
    hardware rather than the boundary. On the box this lesson provisions we can simply run the suite
    as a bare host process — which is exactly what "no sandbox" means — and compare two numbers taken
    minutes apart on the same silicon.

    Running the destructive attacks as a native process is only acceptable on a machine that is about
    to be destroyed, so it is gated on infra's disposable flag and falls back to the recorded file.
    """
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") == "1":
        print("  re-running the no-sandbox rung natively on this box (it is disposable, and about")
        print("  to be destroyed) so the comparison is two boundaries, not two machines.\n")
        env = {
            **os.environ,
            "PYTHONPATH": str(SUITE_DIR),
            "PLANT_FAKE_SECRETS": "1",
            "PROBE_NODE_KERNEL": platform.release(),
        }
        done = subprocess.run(
            [sys.executable, "-m", "attacks.run", "--groups", "reach,abuse,kernel,cost"],
            capture_output=True,
            text=True,
            env=env,
            timeout=600,
        )
        return Card.parse(done.stdout, allow_partial=True), "measured live, just now, on this box"
    return Card.load(PREVIOUS), f"recorded earlier in {PREVIOUS.name} — a DIFFERENT box"


def assert_boundary_engaged(card: Card) -> None:
    """Prove the container actually did what the lesson claims — from the readings, not the flags.

    This repo's characteristic silent failure is a boundary that did not engage yet still exits 0.
    Lesson 2's boundary is 'a fresh, capped, egress-less filesystem', so we assert exactly that: the
    host's credentials were unreachable, egress was denied, and a resource cap bit. If any of these
    did not hold, the container was not the container we asked for and the scorecard is a lie.
    """
    checks = {
        "fresh filesystem (host creds unreachable)": card.contained("read_credentials") is True,
        "egress denied (--network none engaged)": card.contained("exfiltrate") is True,
        "resource cap bit (cgroups engaged)": card.contained("resource_exhaustion") is True,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  boundary assertion FAILED — the container did not engage as configured; not reporting a result.")


def assert_network_on(card: Card) -> None:
    """Prove the network-on run really had a network — the mode must be asserted, not assumed.

    This is the same class of failure the whole repo is built to catch, pointing the other way. If
    the second container came up with no egress after all — a broken rootless network stack, a
    missing pasta/slirp4netns binary — every network row would read BLOCKED and the page would
    announce that a container stops exfiltration when an agent is online. That is precisely the
    false comfort Part 4 exists to remove, and it would be indistinguishable from a real result.

    So: the network-on run is only allowed to report if egress demonstrably worked. The hardening
    half must still hold too, or the two runs differ by more than the network and the comparison is
    not about the network at all.
    """
    checks = {
        "egress genuinely OPEN (the mode under test actually engaged)": card.contained("exfiltrate") is False,
        "same hardening still on (fresh filesystem)": card.contained("read_credentials") is True,
        "same hardening still on (resource cap)": card.contained("resource_exhaustion") is True,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  network-on assertion FAILED — this run did not differ from egress-off only by the network.")


def main() -> None:
    eng = engine()
    ensure_image(eng)

    banner("Part 1 — The simplest thing that works: one hardened container")
    print("  Same image as lesson 1. The only change is the boundary it runs behind:")
    print("    " + " ".join(HARDENING))

    banner("Part 2 — Turn the rogue agent loose (the same nine attacks)")
    print("  Mode: egress-off (--network none)\n")
    card = run_in_container(eng, NET_OFF)
    print(card.render())
    blocked, applicable = card.tally()
    print(f"\n  boundaries that held: {blocked}/{applicable}")

    banner("Assert the boundary engaged (from inside, never from the flags passed)")
    assert_boundary_engaged(card)

    banner("Part 3 — What just changed (the previous rung, re-run live on this same box)")
    prev, source = previous_rung()
    if prev is None:
        print("  Nothing to compare against: this is not a disposable box, and there is no recorded")
        print("  results/lesson-01.json either. Run lesson 1 first, or run this on its own box.")
    else:
        print(f"  ({source})\n")
        print(card.diff_against(prev, "no-sandbox", "container"))

    banner("Part 4 — The same container, with the network a real agent needs")
    print("  Everything above was measured with --network none. An agent that cannot reach an LLM")
    print("  API is not an agent, so that column describes a deployment nobody ships. Here is the")
    print("  identical container with the engine's ordinary network, and nothing else changed.\n")
    net_card = run_in_container(eng, NET_ON)
    print(net_card.render())
    net_blocked, net_applicable = net_card.tally()
    print(f"\n  boundaries that held: {net_blocked}/{net_applicable}   (egress-off scored {blocked}/{applicable})")

    banner("Assert the network-on run really had a network")
    assert_network_on(net_card)

    print("\n  What the network bought the attacker:\n")
    print(net_card.diff_against(card, "egress-off", "network-on"))
    print("  Those rows did not reopen because the container got weaker — it is byte-for-byte the")
    print("  same hardening. They reopened because a container's only network verdict is on/off, and")
    print("  an agent needs 'on'. Nothing here can tell a typosquat fetch from a legitimate GET, and")
    print("  no gVisor or Kata rung will help: neither reads HTTP. That is lesson 5's whole argument.")

    banner("Part 5 — What is still open (the next lesson's reason to exist)")
    still_open = card.reached()
    for f in still_open:
        print(f"    {f['name']:<20} {f['value']}")
    print("\n  The kernel rows above are the big one: a container SHARES the host kernel, so attack 8")
    print("  is exactly as open as it was in lesson 1. Lesson 3 swaps one word (--runtime runsc) and")
    print("  watches it collapse. And every row Part 4 reopened stays open through lessons 3 and 4 —")
    print("  only lesson 5 closes them, which is why it exists.")

    # node_kernel: what the sandbox reported as the node's kernel. See lesson 1 for why it is here.
    kernel = node_kernel(eng)
    card.save(
        RESULTS,
        lesson="lesson-02-container",
        mode="egress-off",
        engine=eng,
        node_kernel=kernel,
        boundary="hardened rootless container, --network none",
    )
    net_card.save(
        RESULTS_NET_ON,
        lesson="lesson-02-container",
        mode="network-on",
        engine=eng,
        node_kernel=kernel,
        boundary="hardened rootless container, ordinary network",
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
    print(f"                   and {RESULTS_NET_ON.relative_to(REPO_ROOT)}")
    report = Path(__file__).parent / "report.html"
    if render_report(REPO_ROOT):
        print(f"  report written to  {report.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
