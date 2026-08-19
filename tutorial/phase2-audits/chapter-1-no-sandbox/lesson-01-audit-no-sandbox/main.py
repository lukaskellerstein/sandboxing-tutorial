"""Lesson 2.1.1 — auditing the no-sandbox baseline. Would you ever know the attacks were tried?

The mirror of 1.1.1 on the other axis. Phase 1 asked *did the boundary hold?* — and at this rung the
answer was "there is no boundary", so every attack landed. Phase 2 asks *would you ever know?* It
runs the SAME nine attacks as a bare host process, then reads the host's ``auditd`` trail and reports,
per attack, whether it was **written down**.

The finding is the phase-2 thesis at rung 1: near-everything is **LOGGED**. The rung with zero
isolation has almost total observability, because there is no boundary between the attack's syscall
and the kernel that audits it. Every stronger boundary up the ladder trades that away — a host sensor
sees only the sentry's readout under gVisor, and nothing at all inside a Kata guest. That inversion
is the whole point of phase 2, and it starts here, where the trail is a wall of LOGGED against
phase 1's wall of *no sensor*.

**Where this runs — and ONLY where.** On a fresh, disposable Scaleway box (``chapter-01-audit``),
as a native host process, with ``auditd`` watching. Same rule as 1.1.1: a native rogue-agent run is
only acceptable on a machine about to be destroyed.

    cd ../../../../infra && ./up.sh 2.1.1     # provisions the box, installs auditd, asserts it is watching
    uv run python -u main.py                  # runs it on the box and brings the card home
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.1.1"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
SUITE_DIR = REPO_ROOT / "infra" / "images" / "agent"
RESULTS = REPO_ROOT / "results" / "2.1.1.json"
GROUPS = "reach,abuse,kernel,cost"

#: The raw audit log, grep'd directly. `ausearch -k` returns "<no matches>" on this box's
#: enriched-format log even when the key IS present, so the robust read is grep for the `key="..."`
#: field. read_credentials is separated from the torrent of ordinary opens by matching the planted
#: credential filenames under $HOME (not, say, python's own `token.cpython-312.pyc`).
AUDIT_LOG = "/var/log/audit/audit.log"
SECRET_PATH_RE = r'name="/home/[^"]*(credentials|id_rsa|id_ed25519|/\.env)[^"]*"'

#: Probes recorded by a distinctive SYSCALL — the presence of the audit key means the attack was
#: written down. Kept beside the substrate's rules (infra/substrates/chapter-1-audit/10-auditd.sh):
#: change the two together or the map lies. A probe in neither this nor PROBE_PATHS is one this sensor
#: cannot see at all (NO_SENSOR).
PROBE_KEYS = {
    "exfiltrate": ["sbx_net"],
    "cloud_metadata": ["sbx_net"],
    "plant_backdoor": ["sbx_exec"],
    "malicious_package": ["sbx_exec"],
    "reverse_shell": ["sbx_exec", "sbx_net"],
    "resource_exhaustion": ["sbx_exec"],
    "bpf": ["sbx_bpf"],
    "io_uring_setup": ["sbx_iouring"],
    "perf_event_open": ["sbx_perf"],
}
#: Probes recorded by the FILE they open, matched by path in the openat (`sbx_open`) trail. Path,
#: not key, because auditd's `-w` watch does NOT fire on procfs, and the credential files do not
#: exist when the rules load. sys_module_count reads /sys/module by directory listing (getdents),
#: which no rule here catches — an honest NOT_LOGGED, and itself a finding: a readdir-based
#: enumeration slips past rules built around open().
PROBE_PATHS = {
    "read_credentials": SECRET_PATH_RE,
    "kallsyms_readable": r'name="/proc/kallsyms"',
    "sys_module_count": r'name="/proc/modules"',
}

LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def run_native() -> Card:
    """The SAME native run 1.1.1 does — the suite as a bare host process, every attack landing."""
    print("  mode: NATIVE host process, with auditd watching the host kernel")
    print(f"  $ PYTHONPATH={SUITE_DIR} PLANT_FAKE_SECRETS=1 python -m attacks.run --groups {GROUPS}\n")
    env = {
        **os.environ,
        "PYTHONPATH": str(SUITE_DIR),
        "PLANT_FAKE_SECRETS": "1",
        "PROBE_NODE_KERNEL": platform.release(),
    }
    done = subprocess.run(
        [sys.executable, "-m", "attacks.run", "--groups", GROUPS],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    if done.stderr:
        print("  --- box stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()))
        print()
    return Card.parse(done.stdout)


def _key_logged(key: str) -> bool:
    """Whether auditd wrote at least one record for this key — grep of the raw log (needs sudo)."""
    r = subprocess.run(
        ["sudo", "grep", "-c", f'key="{key}"', AUDIT_LOG],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return int(r.stdout.strip() or "0") > 0
    except ValueError:
        return False


def _path_logged(regex: str) -> bool:
    """Whether the openat trail recorded a file whose path matches — grep of the raw log (needs sudo)."""
    r = subprocess.run(
        ["sudo", "grep", "-oE", regex, AUDIT_LOG],
        capture_output=True,
        text=True,
        check=False,
    )
    return bool(r.stdout.strip())


def audit_recorded(card: Card) -> dict[str, str]:
    """Read auditd's trail once and resolve every scored probe to LOGGED / NOT_LOGGED / NO_SENSOR.

    Host-side by necessity: a process cannot see the record kept *about* it. The verdict (blocked or
    not) is already on the card from the attack run; this adds the orthogonal 'was it written down?'.
    """
    subprocess.run(["sync"], check=False)
    logged = {key: _key_logged(key) for key in sorted({k for ks in PROBE_KEYS.values() for k in ks})}
    paths = {name: _path_logged(rx) for name, rx in PROBE_PATHS.items()}

    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:  # INFO rows are not scored, so not audited
            continue
        name = finding["name"]
        if name in PROBE_PATHS:
            state = LOGGED if paths[name] else NOT_LOGGED
        elif name in PROBE_KEYS:
            state = LOGGED if any(logged.get(k) for k in PROBE_KEYS[name]) else NOT_LOGGED
        else:
            state = NO_SENSOR
        finding["recorded"] = state  # rides through Card.save into results/2.1.1.json and the band
        out[name] = state
    return out


def box_ip_if_any() -> str | None:
    try:
        for line in STATE_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("BOX_IP="):
                return line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        return None
    return None


def run_on_box(ip: str) -> int:
    runner = REPO_ROOT / "infra" / "run.sh"
    print(f"Box for {LESSON} is up ({ip}). Running the lesson ON it via infra/run.sh …\n")
    return subprocess.run([str(runner), LESSON]).returncode


def refuse_no_box() -> None:
    print(f"No box for {LESSON} is up — nothing to run.")
    print("This lesson only runs on its own disposable Scaleway box (a native rogue-agent run is only")
    print("acceptable on a machine about to be destroyed). Start one, then run it from here:\n")
    print(f"    cd ../../../../infra && ./up.sh {LESSON}      # or press 'u' in the sbx-tui panel")
    print("    uv run python -u main.py                # runs it on the box and brings the card home")
    raise SystemExit(2)


def main() -> None:
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        ip = box_ip_if_any()
        if not ip:
            refuse_no_box()
            return
        raise SystemExit(run_on_box(ip))

    banner("Part 1 — The same nine attacks, on the same bare host — but auditd is watching")
    print("  Nothing changed about the boundary: there is none. What changed is that the host kernel's")
    print("  audit subsystem is recording the syscalls each attack makes. 1.1.1 measured what got")
    print("  through; 2.1.1 measures what got written down.")

    card = run_native()
    print(card.render())
    blocked, applicable = card.tally()
    print(f"\n  boundaries that held: {blocked}/{applicable}  (unchanged from 1.1.1 — this is the same rung)")

    banner("Part 2 — Was any of it written down? (the RECORDED axis)")
    recorded = audit_recorded(card)
    logged = sum(1 for v in recorded.values() if v == LOGGED)
    for name, state in recorded.items():
        mark = "LOGGED    " if state == LOGGED else ("NOT LOGGED" if state == NOT_LOGGED else "no sensor ")
        print(f"    {name:<20} {mark}")
    print(f"\n  {logged}/{len(recorded)} attacks left a record in auditd's trail.")
    print("  This is the phase-2 finding at rung 1: the boundary held nothing, and the sensor caught")
    print("  almost everything. Zero isolation, near-total observability — and every stronger boundary")
    print("  above trades that away. Compare the RECORDED band here against the 'no sensor' wall on")
    print("  every phase-1 report.")

    kernel = card.get("kernel_identity")
    card.save(
        RESULTS,
        lesson="2.1.1",
        mode="network-on",
        node_kernel=str(kernel["value"]) if kernel else platform.release(),
        boundary="native host process + host auditd (phase-2 audit of 1.1.1)",
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
    report = Path(__file__).parent / "report.html"
    if render_report(REPO_ROOT):
        print(f"  report written to  {report.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
