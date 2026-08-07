"""Lesson 3 — the same hardened container, one word different: ``--runtime runsc``.

Lesson 2 closed most of the list and left attack 8 completely untouched, because a container shares
the host kernel: ``/sys/module`` was still full, and the kernel still identified as the node's. This
lesson changes *the runtime and nothing else* and re-runs the identical suite. The kernel rows
collapse — not because a rule was added, but because the syscalls now go to **gVisor's own kernel**,
a user-space one written in Go, instead of to Linux.

To keep the comparison honest the lesson runs the suite **twice, live, in the same minute**: once
under the default runtime (``crun``/``runc``) and once under ``runsc``, with byte-identical flags on
both. Reading lesson 2's recorded numbers instead would compare two machines as well as two
runtimes, and this is a tutorial about not doing that.

Two things this lesson measures that are easy to get wrong:

* **The syscall tax is real and the CPU tax is not.** Every syscall now traverses a user-space
  kernel; arithmetic does not. Printing one number for "the cost of gVisor" would be false either
  way, so both are printed side by side.
* **Attack 7 kills the sandbox instead of being capped by it.** gVisor's sentry and its per-task
  stub processes live inside the *container's own* cgroup, so a fork bomb that merely earns
  ``EAGAIN`` under runc spends the workload's whole memory budget under runsc, and the box is
  OOM-killed. The suite streams its findings for exactly this reason; the verdict for that one row
  is then read from the exit status, which is the only place it is still legible.

    cd tutorial/lesson-03-container-gvisor && uv sync && uv run python -u main.py
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from scorecard import Card, Finding, render_report

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sandboxing-tutorial/agent:latest"
RESULTS = REPO_ROOT / "results" / "lesson-03.json"
#: The same rung with the network an agent actually needs — see lesson 2 for why this is a separate
#: card rather than a second findings list.
RESULTS_NET_ON = REPO_ROOT / "results" / "lesson-03-network-on.json"
GROUPS = "reach,abuse,kernel,cost"
# Attack 4's target, inherited from the environment rather than hardcoded, and forwarded into every
# sandbox below. `infra/run.sh` points it at the cloud this box actually runs on: Scaleway answers on
# 169.254.42.42, AWS on 169.254.169.254, and a probe aimed at the wrong one reads BLOCKED for a
# reason that has nothing to do with the boundary under test. Empty means "use the suite's default".
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["-e", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []


# Byte-identical to lesson 2. That is the entire experimental design: if any of these differed, a row
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

#: Byte-identical to lesson 2's split, for the same reason: the network model is a variable this
#: ladder measures, not a constant it assumes. gVisor is a *kernel* boundary — it reads syscalls,
#: not HTTP — so the network-on run is expected to reopen exactly what it reopened for a plain
#: container, and demonstrating that is the point rather than a disappointment.
NET_OFF = ["--network", "none"]
NET_ON: list[str] = []


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
            "    cd infra && ./up.sh lesson-03-container-gvisor && ./run.sh lesson-03-container-gvisor"
        )
    if shutil.which("podman") is None:
        sys.exit("  podman not found — run infra/substrates/10-podman.sh")
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


def run_suite(eng: list[str], runtime: str | None, net: list[str] = NET_OFF) -> tuple[Card, int]:
    """Run the suite once. Returns the card and the container's exit status.

    The exit status is not decoration. It is the only evidence left when the sandbox dies mid-suite,
    and under gVisor at these limits it does.
    """
    argv = [*eng, "run", "--rm", "--user", "1000:1000", *HARDENING, *net]
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
    """
    identity = str(card.get("kernel_identity") or {}).lower()
    modules = card.get("sys_module_count")
    checks = {
        "the kernel identifies as gVisor's own": "gvisor" in identity,
        "/sys/module is empty (no host modules to enumerate)": (modules or {}).get("value") == 0,
        "/proc/kallsyms is unreadable": card.contained("kallsyms_readable") is True,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  gVisor assertion FAILED — the sandbox ran on the host kernel. Not reporting a result.")


def main() -> None:
    eng = engine_argv()
    ensure_image(eng)

    banner("Part 1 — The simplest thing that works: add --runtime runsc")
    print("  Same image, same nine attacks, and the same container flags as lesson 2:")
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

    banner("Part 4 — The same gVisor sandbox, with the network a real agent needs")
    print("  Everything above ran with --network none. Re-running under runsc with the engine's")
    print("  ordinary network — same runtime, same hardening, only the network differs.\n")
    gv_net, gv_net_rc = run_suite(eng, "runsc", NET_ON)
    gv_net = merge_sandbox_death(gv_net, gv_net_rc, "runsc")
    print(gv_net.render())
    net_blocked, net_applicable = gv_net.tally()
    print(f"\n  boundaries that held: {net_blocked}/{net_applicable}   (egress-off scored {blocked}/{applicable})")

    banner("Assert gVisor engaged in the network-on run too")
    assert_gvisor_engaged(gv_net)
    if gv_net.contained("exfiltrate") is not False:
        sys.exit("  network-on assertion FAILED — egress was not actually open; this run proves nothing.")
    print("    [OK] egress genuinely OPEN (the mode under test actually engaged)")

    print("\n  What the network bought the attacker:\n")
    print(gv_net.diff_against(gvisor, "egress-off", "network-on"))
    print("  Note WHICH rows moved: the network ones, and not one kernel row. gVisor's boundary is")
    print("  the syscall interface, so it holds attack 8 exactly as before — and it never had an")
    print("  opinion about HTTP, so it reopens the same rows a plain container does. A stronger")
    print("  kernel boundary does not buy a network policy. That is lesson 5, on a different axis.")

    banner("Part 5 — What is still open (the next lessons' reason to exist)")
    for f in gvisor.reached():
        print(f"    {f['name']:<20} {f['value']}")
    print("\n  gVisor closed attack 8 and nothing else — it has no idea WHICH binary made a request,")
    print("  WHICH HTTP method it used, and it keeps no record that anything was attempted. Those are")
    print("  lesson 5 (OpenShell), and they are a different axis, not a weaker version of this one.")
    print("  Lesson 4 reaches the same kernel result by a completely different route — a real guest")
    print("  kernel in a VM — and that difference matters later: Kata keeps Landlock, gVisor drops it.")

    gv_net.save(
        RESULTS_NET_ON,
        lesson="lesson-03-container-gvisor",
        mode="network-on",
        engine=" ".join(eng),
        node_kernel=platform.release(),
        boundary="hardened rootless container + gVisor (runsc), ordinary network",
        runtime_exit_code=gv_net_rc,
    )
    gvisor.save(
        RESULTS,
        lesson="lesson-03-container-gvisor",
        mode="egress-off",
        engine=" ".join(eng),
        # The kernel this rung ran on. Recorded on every lesson so the overall report can
        # tell when two rungs were measured on different machines — without it the guard has
        # nothing to compare and silently passes.
        node_kernel=platform.release(),
        boundary="hardened rootless container + gVisor (runsc)",
        runtime_exit_code=gv_rc,
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
    print(f"                   and {RESULTS_NET_ON.relative_to(REPO_ROOT)}")
    report = Path(__file__).parent / "report.html"
    if render_report(REPO_ROOT):
        print(f"  report written to  {report.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
