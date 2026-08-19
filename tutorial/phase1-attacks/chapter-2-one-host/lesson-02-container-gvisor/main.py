"""Lesson 1.2.2 — the same hardened container, one word different: ``--runtime runsc``.

Lesson 1.2.1 closed most of the list and left attack 8 completely untouched, because a container shares
the host kernel: ``/sys/module`` was still full, and the kernel still identified as the node's. This
lesson changes *the runtime and nothing else* and re-runs the identical suite. The kernel rows
collapse — not because a rule was added, but because the syscalls now go to **gVisor's own kernel**,
a user-space one written in Go, instead of to Linux.

To keep the comparison honest the lesson runs the suite **twice, live, in the same minute**: once
under the default runtime (``crun``/``runc``) and once under ``runsc``, with byte-identical flags on
both. Reading lesson 1.2.1's recorded numbers instead would compare two machines as well as two
runtimes, and this is a tutorial about not doing that.

Like every rung of this ladder it runs with the engine's **ordinary network**, because an agent that
cannot reach a model API is not an agent. That matters more here than it looks: gVisor's boundary is
the syscall interface, so it collapses the kernel rows and leaves the network ones exactly where a
plain container left them. A stronger *kernel* boundary does not buy a network policy, and measuring
this rung online is what makes that visible instead of assertable.

Two things this lesson measures that are easy to get wrong:

* **The syscall tax is real and the CPU tax is not.** Every syscall now traverses a user-space
  kernel; arithmetic does not. Printing one number for "the cost of gVisor" would be false either
  way, so both are printed side by side.
* **Attack 7 kills the sandbox instead of being capped by it.** gVisor's sentry and its per-task
  stub processes live inside the *container's own* cgroup, so a fork bomb that merely earns
  ``EAGAIN`` under runc spends the workload's whole memory budget under runsc, and the box is
  OOM-killed. The suite streams its findings for exactly this reason; the verdict for that one row
  is then read from the exit status, which is the only place it is still legible.

    # 1. start the box (once):
    cd ../../../../infra && ./up.sh 1.2.2     # or press 'u' in the sbx-tui panel
    # 2. then, as often as you like (on your machine this runs the lesson ON the box):
    cd tutorial/phase1-attacks/chapter-2-one-host/lesson-02-container-gvisor && uv sync && uv run python -u main.py
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from scorecard import Card, Finding, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "1.2.2"
#: What infra records about this lesson's box. Read only to make the refusal ACTIONABLE — "no box at
#: all" and "the box is up, you are just not on it" need different next steps. Missing means missing:
#: the leaf still runs from a clone that has never touched infra/, nothing is imported from it, and
#: nothing breaks if the file never appears.
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
IMAGE = "sandboxing-tutorial/agent:latest"
RESULTS = REPO_ROOT / "results" / "1.2.2.json"
GROUPS = "reach,abuse,kernel,cost"
# Attack 4's target, inherited from the environment rather than hardcoded, and forwarded into every
# sandbox below. `infra/run.sh` points it at the cloud this box actually runs on: Scaleway answers on
# 169.254.42.42, AWS on 169.254.169.254, and a probe aimed at the wrong one reads BLOCKED for a
# reason that has nothing to do with the boundary under test. Empty means "use the suite's default".
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["-e", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []


# Byte-identical to lesson 1.2.1. That is the entire experimental design: if any of these differed, a row
# that changed could be the flag rather than the runtime, and the lesson would prove nothing.
HARDENING = [
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/tmp:rw,exec,size=64m",
    "--memory", "256m",
    "--memory-swap", "256m",
    "--pids-limit", "128",
    "--cpus", "1",
]  # fmt: skip


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def engine_argv() -> list[str]:
    """The podman invocation this lesson uses — **rootful**, and that is not a shortcut.

    Rootless podman cannot drive ``runsc`` on an ordinary Linux host, measured on this box:

        systemd cgroup manager  ->  runsc: creating container: systemd error:
                                    Interactive authentication required
        cgroupfs manager        ->  runsc: cannot set up cgroup for root: configuring cgroup:
                                    open /sys/fs/cgroup/cgroup.subtree_control: permission denied

    runsc wants to create the container's cgroup itself and, rootless, it can do so through neither
    path — the system D-Bus refuses an unprivileged caller, and the root cgroup is not writable. The
    tempting fix is runsc's ``--ignore-cgroups``, and it is a trap: the sandbox then starts happily
    while the memory and pids caps are silently not applied, so attack 7 flips to ``no-cap`` and the
    lesson reports a boundary difference that is really a configuration difference.

    So the whole lesson — including Part 3's baseline — runs rootful, which keeps the one-variable
    claim intact. The caps are verified to still bite: ``memory.max`` reads 268435456 and
    ``pids.max`` 128 in the container's cgroup on the host side.
    """
    if platform.system() != "Linux":
        sys.exit(
            f"  This lesson runs on Linux; this is {platform.system()}.\n"
            "  gVisor is a Linux-kernel-facing runtime, and on a Mac it would run inside the podman\n"
            "  machine rather than on your host — a boundary in a different place than the lesson\n"
            "  claims. Run it on its own box instead:\n"
            "    cd infra && ./up.sh 1.2.2 && ./run.sh 1.2.2"
        )
    if shutil.which("podman") is None:
        sys.exit("  podman not found — run infra/substrates/chapter-2/10-podman.sh")
    return ["podman"] if os.geteuid() == 0 else ["sudo", "podman"]


def ensure_image(eng: list[str]) -> None:
    """Build the image every run, into the same (rootful) store the run uses.

    Deliberately not "build only if missing". Layer caching makes a no-op build nearly free, while a
    skipped one silently measures whatever the box happened to have — and when the attack suite is the
    thing that changed, that is a scorecard describing code you are no longer running.
    """
    build_dir = REPO_ROOT / "infra" / "images" / "agent"
    subprocess.run([*eng, "build", "-q", "-t", IMAGE, str(build_dir)], check=True, capture_output=True)


def selinux_enforcing() -> bool:
    """Is SELinux enforcing here? runsc cannot parse an SELinux-labelled spec and refuses outright.

    The symptom is ``FetchSpec failed: reading spec: SELinux is not supported`` and it reads like a
    gVisor bug rather than a host policy, which is why this is detected rather than hard-coded: it is
    true on Fedora CoreOS (a Mac's podman machine) and false on the Ubuntu box this lesson targets.
    """
    try:
        return Path("/sys/fs/selinux/enforce").read_text().strip() == "1"
    except OSError:
        return False


def run_suite(eng: list[str], runtime: str | None) -> tuple[Card, int]:
    """Run the suite once. Returns the card and the container's exit status.

    The exit status is not decoration. It is the only evidence left when the sandbox dies mid-suite,
    and under gVisor at these limits it does.

    No network flag is passed, deliberately: the engine's default is what an agent that must reach a
    model API is given, and it is what both sides of Part 3's comparison get, so a row that moves
    there moved because of the runtime.
    """
    argv = [*eng, "run", "--rm", "--user", "1000:1000", *HARDENING]
    if runtime:
        argv += ["--runtime", runtime]
        if selinux_enforcing():
            argv += ["--security-opt", "label=disable"]
    argv += ["-e", f"PROBE_GROUPS={GROUPS}", "-e", f"PROBE_NODE_KERNEL={platform.release()}", *METADATA_ENV, IMAGE]

    print(f"  $ {' '.join(argv)}\n")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=600)
    if done.stderr:
        print("  --- box stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-14:]))
        print()
    return Card.parse(done.stdout, allow_partial=True), done.returncode


def merge_sandbox_death(card: Card, rc: int, runtime: str) -> Card:
    """Fill in the one row a dead box could not report, from the only place the answer survives.

    A sandbox killed by its own cgroup while running the fork bomb *was* contained — violently, and
    by the memory cap rather than the pids cap, but contained. Recording that as "not measured" would
    understate the boundary; recording it as an ordinary ``capped:`` would hide that the workload
    died with it. So it gets its own value, and the exit code is kept in the detail.
    """
    if card.complete or card.get("resource_exhaustion") is not None:
        return card
    print(f"  ! the sandbox did not survive the suite (exit {rc}) — {len(card.findings)} findings streamed out")
    print("    Under runsc this is expected and is itself the result: gVisor's sentry and its")
    print("    per-task stubs are charged to the container's cgroup, so the fork bomb exhausts the")
    print("    256 MB budget and the whole sandbox is killed rather than the fork being refused.")
    return card.add(
        Finding(
            name="resource_exhaustion",
            value="capped:sandbox-killed",
            contained=True,
            group="abuse",
            detail=f"{runtime} sandbox exited {rc} mid-attack (host-observed)",
        )
    )


def assert_gvisor_engaged(card: Card) -> None:
    """Prove runsc actually engaged — from what the sandbox reported, never from the flag we passed.

    This is the assertion the whole repo exists to make. A container that silently fell back to runc
    exits 0 and prints a perfectly plausible scorecard; the *only* thing that distinguishes it is the
    sandbox's own answer to "whose kernel are you".

    Egress is asserted here too, pointing the other way. If this sandbox came up with no network —
    a broken rootless stack, a missing pasta/slirp4netns — every network row would read BLOCKED and
    the page would credit gVisor with stopping exfiltration it never touched. gVisor does not read
    HTTP, so those rows staying open is the *expected* result and must not be faked by an accident.
    """
    identity = str(card.get("kernel_identity") or {}).lower()
    modules = card.get("sys_module_count")
    checks = {
        "the kernel identifies as gVisor's own": "gvisor" in identity,
        "/sys/module is empty (no host modules to enumerate)": (modules or {}).get("value") == 0,
        "/proc/kallsyms is unreadable": card.contained("kallsyms_readable") is True,
        "egress genuinely OPEN (the network this rung claims to measure)": card.contained("exfiltrate") is False,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  gVisor assertion FAILED — the sandbox ran on the host kernel. Not reporting a result.")


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
    so the copy of main.py which executes ON the box takes the real path rather than delegating
    again (no loop).
    """
    runner = REPO_ROOT / "infra" / "run.sh"
    print(f"Box for {LESSON} is up ({ip}). Running the lesson ON it via infra/run.sh …\n")
    return subprocess.run([str(runner), LESSON]).returncode


def refuse_no_box() -> None:
    """No box is up — say how to start one, and exit having run NOTHING.

    The boundary this lesson measures exists only on its disposable box, so the first thing a local
    run hits is a failure that has nothing to do with the lesson. Refusing here, with the next step
    attached, is the honest version of that failure.
    """
    print(f"No box for {LESSON} is up — nothing to run.")
    print("This lesson only runs on its own disposable Scaleway box:")
    print("the rung is podman --runtime runsc on the box's Linux kernel. runsc is a Linux binary the")
    print("substrates install there; nothing on this machine runs it natively.")
    print("Start the box, then run it from here:\n")
    print(f"    cd ../../../../infra && ./up.sh {LESSON}      # or press 'u' in the sbx-tui panel")
    print("    uv run python -u main.py                # runs it on the box and brings the card home")
    raise SystemExit(2)


def main() -> None:
    # `uv run main.py` is the one command. On the disposable box it runs for real (infra sets
    # SANDBOXING_TUTORIAL_DISPOSABLE=1 there). On your machine it runs the lesson ON the box when
    # one is up, and tells you to start one when none is.
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        ip = box_ip_if_any()
        if not ip:
            refuse_no_box()
            return  # unreachable — refuse_no_box exits — but narrows ip to str for the type checker
        raise SystemExit(run_on_box(ip))

    eng = engine_argv()
    ensure_image(eng)

    banner("Part 1 — The simplest thing that works: add --runtime runsc")
    print("  Same image, same nine attacks, and the same container flags as lesson 1.2.1:")
    print("    " + " ".join(HARDENING))
    print("\n  The only difference is which program answers the syscalls. gVisor's `runsc` puts a")
    print("  kernel written in Go between the workload and Linux, and intercepts with seccomp-bpf —")
    print("  its default `systrap` platform needs no KVM, contrary to a widely repeated claim.")

    banner("Part 2 — Turn the rogue agent loose, under gVisor")
    gvisor, gv_rc = run_suite(eng, "runsc")
    gvisor = merge_sandbox_death(gvisor, gv_rc, "runsc")
    print(gvisor.render())
    blocked, applicable = gvisor.tally()
    print(f"\n  boundaries that held: {blocked}/{applicable}")

    banner("Assert gVisor engaged (from inside the sandbox, never from the flag)")
    assert_gvisor_engaged(gvisor)

    banner("Part 3 — What just changed (the previous rung, re-run live on this same box)")
    print("  Re-running the identical suite under the DEFAULT runtime now, so the comparison is two")
    print("  runtimes rather than two machines.\n")
    plain, plain_rc = run_suite(eng, None)
    plain = merge_sandbox_death(plain, plain_rc, "runc")
    print(gvisor.diff_against(plain, "container", "+ gVisor"))
    print("\n  The price of the boundary:\n")
    print(gvisor.cost_delta(plain, "container", "+ gVisor"))
    print("\n  Read those two rows together. Syscall-bound work pays a real multiple; arithmetic pays")
    print("  essentially nothing. An agent waiting on a model is nearly all of the latter.")
    print("\n  Note WHICH rows moved: the kernel ones, and not one network row. Both sides ran with")
    print("  the same ordinary network, so the network rows sit identical on each and drop out of")
    print("  the diff entirely — which is the finding, not a gap. gVisor's boundary is the syscall")
    print("  interface; it never had an opinion about HTTP.")

    banner("Part 4 — What is still open (the next lessons' reason to exist)")
    for f in gvisor.reached():
        print(f"    {f['name']:<20} {f['value']}")
    print("\n  gVisor closed attack 8 and nothing else. Every network row a plain container left")
    print("  open is still open here, because a stronger KERNEL boundary does not buy a network")
    print("  policy: runsc has no idea WHICH binary made a request, WHICH HTTP method it used, and")
    print("  it keeps no record that anything was attempted. Those are lesson 1.2.4 (OpenShell), and")
    print("  they are a different axis, not a weaker version of this one.")
    print("\n  Lesson 1.2.3 reaches the same kernel result by a completely different route — a real guest")
    print("  kernel in a VM — and that difference matters later: Kata keeps Landlock, gVisor drops it.")

    gvisor.save(
        RESULTS,
        lesson="1.2.2",
        mode="network-on",
        engine=" ".join(eng),
        # The kernel this rung ran on. Recorded on every lesson so the overall report can
        # tell when two rungs were measured on different machines — without it the guard has
        # nothing to compare and silently passes.
        node_kernel=platform.release(),
        boundary="hardened rootless container + gVisor (runsc), ordinary network",
        runtime_exit_code=gv_rc,
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
    report = Path(__file__).parent / "report.html"
    if render_report(REPO_ROOT):
        print(f"  report written to  {report.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
