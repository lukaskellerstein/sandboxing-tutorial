"""Lesson 2.2.2 — auditing the gVisor rung. The host sensor goes blind; the sentry is the sensor.

Audits 1.2.2. This is the TURNING POINT of the backwards-observability ladder. Under gVisor the
workload's syscalls are intercepted by the sentry — a user-space kernel — and never reach the host
kernel as the app made them. A host eBPF sensor like 2.2.1's Tetragon therefore sees only the sentry's
own behaviour, not the attacks. The sensor that still sees them is **gVisor's own**: `runsc --strace`
writes every syscall the sandboxed app makes to the sentry's boot log, and that log is what this
lesson reads.

This is the reframe forced by discovery gate G2: modern Falco (0.44) dropped its gVisor event source
and Tetragon never had one, so there is no host-sensor path here AT ALL — the blindness is a property
of where a host sensor sits, not of which one you picked. The honest sensor is the sentry's own. The
finding: coverage survives the boundary, but ONLY by switching from a host sensor to a gVisor-native
one. That is what "only the sentry sees it under gVisor" means, made concrete.

    cd ../../../../infra && ./up.sh 2.2.2     # provisions chapter-02-audit-host (podman + runsc + Tetragon)
    uv run python -u main.py
"""

from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.2.2"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
IMAGE = "sandboxing-tutorial/agent:latest"
RESULTS = REPO_ROOT / "results" / "2.2.2.json"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["-e", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []

#: The same hardening 1.2.2 runs under runsc.
HARDENING = [
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
    "--tmpfs", "/tmp:rw,exec,size=64m", "--memory", "256m", "--memory-swap", "256m",
    "--pids-limit", "128", "--cpus", "1",
]  # fmt: skip

TRACE_DIR = Path("/var/log/runsc")
LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def podman() -> list[str]:
    """Rootful podman — rootless cannot drive runsc (it cannot create the sandbox's cgroup)."""
    if not shutil.which("podman"):
        sys.exit("No podman found.")
    return ["podman"] if os.geteuid() == 0 else ["sudo", "podman"]


def ensure_image(pm: list[str]) -> None:
    """Build into the SAME (rootful) store the runsc run uses — a rootless-built image is invisible
    to `sudo podman`, which is what drives runsc."""
    build_dir = REPO_ROOT / "infra" / "images" / "agent"
    subprocess.run([*pm, "build", "-q", "-t", IMAGE, str(build_dir)], check=True, capture_output=True)


def node_kernel(pm: list[str]) -> str:
    out = subprocess.run(
        [*pm, "run", "--rm", "--runtime", "runsc", "--entrypoint", "uname", IMAGE, "-r"],
        capture_output=True,
        text=True,
        timeout=180,
    )
    return out.stdout.strip() or platform.release()


def run_under_runsc_trace(pm: list[str]) -> Card:
    """Run the suite under runsc with strace on, so the sentry writes every app syscall to its boot
    log. The strace flags go via `--runtime-flag`; podman ignores extra entries in the runtime array."""
    ensure_image(pm)
    subprocess.run(["sudo", "rm", "-rf", str(TRACE_DIR)], check=False)
    subprocess.run(["sudo", "mkdir", "-p", str(TRACE_DIR)], check=False)
    subprocess.run(["sudo", "chmod", "777", str(TRACE_DIR)], check=False)
    argv = [
        *pm, "run", "--rm", "--runtime", "runsc",
        "--runtime-flag", "debug", "--runtime-flag", "strace",
        "--runtime-flag", f"debug-log={TRACE_DIR}/",
        "--user", "1000:1000", *HARDENING,
        "-e", "PROBE_GROUPS=reach,abuse,kernel,cost",
        "-e", f"PROBE_NODE_KERNEL={node_kernel(pm)}", *METADATA_ENV, IMAGE,
    ]  # fmt: skip
    print(f"  $ {' '.join(argv)}\n")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=360)
    if done.stderr:
        print("  --- container stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[:12]))
        print()
    # allow_partial like 1.2.2: under gVisor the fork bomb OOM-kills the sandbox before the final
    # SCORECARD_JSON, so the streamed findings are all there is — and that death is itself a finding.
    return Card.parse(done.stdout, allow_partial=True)


def _boot_files() -> list[str]:
    r = subprocess.run(
        ["sudo", "bash", "-c", f"ls {TRACE_DIR}/*boot* 2>/dev/null"], capture_output=True, text=True, check=False
    )
    return r.stdout.split()


def _boot_has(ere: str, files: list[str]) -> bool:
    """Whether any boot-log line matches the ERE. Grepped ON THE BOX with -a: the fork bomb floods the
    strace log to tens of MB of part-binary text, so it is never read into Python."""
    if not files:
        return False
    r = subprocess.run(["sudo", "grep", "-aEl", "--", ere, *files], capture_output=True, text=True, check=False)
    return bool(r.stdout.strip())


def _connect_dests(files: list[str]) -> set[str]:
    """The destination IPs the app connected to, from the sentry's `connect(...Addr: …)` traces."""
    if not files:
        return set()
    quoted = " ".join(shlex.quote(f) for f in files)
    cmd = rf"grep -aoE ' E connect\(.*Addr: [0-9.]+' {quoted} | grep -oE 'Addr: [0-9.]+' | sed 's/Addr: //' | sort -u"
    r = subprocess.run(["sudo", "bash", "-c", cmd], capture_output=True, text=True, check=False)
    return set(r.stdout.split())


def trace_recorded(card: Card) -> dict[str, str]:
    """Map each scored probe to LOGGED / NOT_LOGGED from the sentry's strace. Everything the app did
    crosses the sentry, so this is near-total — the point being that ONLY the sentry sees it."""
    files = _boot_files()
    dests = _connect_dests(files)
    metadata_hit = any(a.startswith("169.254") for a in dests)
    other_connect = any(not a.startswith("169.254") for a in dests)
    execve = _boot_has(r" E execve\(", files)

    def state_for(name: str) -> str:
        if name == "exfiltrate":
            return LOGGED if other_connect else NOT_LOGGED
        if name == "cloud_metadata":
            return LOGGED if metadata_hit else NOT_LOGGED
        if name == "read_credentials":
            return (
                LOGGED
                if _boot_has(r" E open(at)?\([^)]*(\.aws|id_rsa|id_ed25519|credentials|\.ssh|\.env)", files)
                else NOT_LOGGED
            )
        if name == "kallsyms_readable":
            return LOGGED if _boot_has(r" E open(at)?\([^)]*/proc/kallsyms", files) else NOT_LOGGED
        if name == "sys_module_count":
            return LOGGED if _boot_has(r" E open(at)?\([^)]*(/proc/modules|/sys/module)", files) else NOT_LOGGED
        if name in ("plant_backdoor", "malicious_package", "reverse_shell", "resource_exhaustion"):
            return LOGGED if execve else NOT_LOGGED
        if name in ("bpf", "io_uring_setup", "perf_event_open"):
            return LOGGED if _boot_has(rf" E {name}\(", files) else NOT_LOGGED
        return NO_SENSOR

    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:
            continue
        state = state_for(finding["name"])
        finding["recorded"] = state
        out[finding["name"]] = state
    return out


def box_ip_if_any() -> str | None:
    try:
        for line in STATE_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("BOX_IP="):
                return line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        return None
    return None


def main() -> None:
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        ip = box_ip_if_any()
        if not ip:
            print(f"No box for {LESSON} is up. Start one:  cd ../../../../infra && ./up.sh {LESSON}")
            raise SystemExit(2)
        raise SystemExit(subprocess.run([str(REPO_ROOT / "infra" / "run.sh"), LESSON]).returncode)

    pm = podman()
    banner("Part 1 — The same container as 1.2.2, under gVisor, with the sentry's strace on")
    print("  Under runsc every syscall the app makes is intercepted by the sentry. A HOST sensor")
    print("  (2.2.1's Tetragon) would see only the sentry's own syscalls, not these. So the sensor")
    print("  here is gVisor's own: runsc --strace writes the app's syscalls to the sentry's boot log.")

    card = run_under_runsc_trace(pm)
    print(card.render())
    blocked, applicable = card.tally()
    print(f"\n  boundaries that held: {blocked}/{applicable}")

    banner("Part 2 — Was any of it written down? (gVisor's own trace — the only sensor that sees it)")
    recorded = trace_recorded(card)
    logged = sum(1 for v in recorded.values() if v == LOGGED)
    for name, state in recorded.items():
        mark = "LOGGED    " if state == LOGGED else ("NOT LOGGED" if state == NOT_LOGGED else "no sensor ")
        print(f"    {name:<20} {mark}")
    print(f"\n  {logged}/{len(recorded)} attacks appear in the sentry's trace.")
    print("  A host eBPF sensor is blind to all of this — the app never made these syscalls against")
    print("  the host kernel; the sentry did, on its behalf, in user space. Coverage survives the")
    print("  boundary only because you switched sensors: from the host kernel to gVisor's own trace.")

    kernel = card.get("kernel_identity")
    card.save(
        RESULTS,
        lesson="2.2.2",
        mode="network-on",
        node_kernel=str(kernel["value"]) if kernel else platform.release(),
        boundary="gVisor (runsc) + the sentry's own strace (phase-2 audit of 1.2.2)",
        engine="podman+runsc",
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
    if render_report(REPO_ROOT):
        print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
