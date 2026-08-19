"""Lesson 2.2.4 — auditing the OpenShell rung. Two sensors, disjoint columns, and the honest gap between them.

Audits 1.2.4. On the isolation ladder this rung is the WEAKEST boundary — OpenShell is ordinary runc with
the host kernel fully exposed, no VM (as Kata had), no user-space kernel (as gVisor had). So — unlike
2.2.3, where the host sensor read ZERO behind Kata's guest kernel — the in-guest auditd DOES see the
workload's syscalls here (they reach the host kernel). Two sensors cover the attacks, in disjoint columns:

  * **auditd** (in-guest host sensor): the 8 local/kernel attacks — the credentials the agent reads, the
    backdoor it writes to ~/.bashrc, the module/kallsyms it probes, the bpf/io_uring/perf syscalls it
    attempts, the malicious package it pip-installs. Matched by the workload-unique PATH each opens (or,
    for the kernel probes, the keyed syscall). This rung PLANTS canary credentials (unlike 1.2.4) so the
    theft is real and leaves a real trail — which is why read_credentials reads a canary here (reached)
    where 1.2.4, with nothing to steal, showed it contained.
  * **OCSF** (OpenShell's L7 trail): the 8 network attacks — which binary, which method, which endpoint,
    allowed or denied. The per-binary/L7 column a raw syscall has no words for.

Between them, 15 of the 19 probes are written down. Note the capability-denied kernel probes
(bpf/io_uring/perf) ARE recorded — a syscall that returns EPERM still exits, and the audit exit hook
fires. What leaves no trail is the write DENIED by the filesystem policy: fs_policy_write's open of /etc is
refused before it resolves to a record, so a host syscall auditor sees what the workload DID, not what the
boundary DENIED — the one decision only OpenShell's policy engine writes down. That is the phase-2 finding
at this rung: observability is per-sensor-shaped, and full coverage is the two sensors together.

    cd ../../../../infra && ./up.sh 2.2.4   # provisions its OWN NAT-guest box (OpenShell + in-guest auditd)
    uv run python -u main.py                # runs it inside the guest and brings the card home

Verified against the OpenShell version printed at the top of the run. OpenShell is ALPHA; the version is
recorded in the scorecard so drift is visible rather than mysterious.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scorecard import Card, Finding, render_report

#: A parsed OpenShell decision: action / method / binary / target / raw, all strings.
Decision = dict[str, str]

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.2.4"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
IMAGE = "localhost/sandboxing-tutorial/agent:latest"
RESULTS = REPO_ROOT / "results" / "2.2.4.json"
POLICY = Path(__file__).parent / "policy.yaml"
SANDBOX = "sbx-tutorial-l5"
#: Same suite and same groups as 1.2.4 (its twin), so the containment card is 1.2.4's, not a variant.
GROUPS = "reach,abuse,kernel,policy,cost"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["--env", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []

HOST_ALIAS = "host.openshell.internal"
GATEWAY_PORT = 18410  # the model gateway the agent legitimately needs — ALLOWED by the policy
COLLECTOR_PORT = 18411  # the attacker's collector — never named by the policy, therefore DENIED

AUDIT_LOG = "/var/log/audit/audit.log"
LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"

# --- sensor 1: auditd (in-guest host sensor) — the workload's local attacks, by the file they touch ---
#
# The workload runs as a rootless container at a subuid (100999). auditd captures its syscalls, and the
# robust fingerprint is a `type=PATH name="..."` match on a WORKLOAD-UNIQUE path (RAW log format, set by
# the substrate, keeps those lines cleanly greppable). This rung PLANTS canary credentials (create_sandbox
# below sets PLANT_FAKE_SECRETS=1 + HOME=/sandbox), unlike 1.2.4, so the credential-theft and backdoor
# attacks touch REAL files and leave a REAL audit trail — which is what makes them auditable, and is why
# `read_credentials` reads canaries here (reached) where 1.2.4, with nothing planted, showed it contained.
# Measured on the box (2026-08-14): id_rsa / .bashrc / .profile / agent_probe_evil all surface.
#: Local/filesystem attacks, fingerprinted by the sensitive PATH the workload opened.
AUDITD_PATHS = {
    "read_credentials": r'name="[^"]*(\.ssh/id_rsa|\.aws/credentials|hosts\.yml|/\.netrc|/sandbox/\.env)"',
    "plant_backdoor": r'name="[^"]*(/sandbox/\.bashrc|/sandbox/\.profile|/sandbox/\.ssh/authorized_keys|/etc/cron\.d/agent-probe)"',
    "malicious_package": r'name="[^"]*agent_probe_evil[^"]*"',
    "kallsyms_readable": r'name="/proc/kallsyms"',
    "sys_module_count": r'name="/sys/module"',
    "fs_policy_write": r'name="/etc/agent-probe-canary"',
}
#: Kernel-surface attacks auditd RULES on but does not record: OpenShell's seccomp profile refuses
#: bpf/io_uring/perf at syscall ENTRY, before the audit exit hook fires. Checked (expected empty) so the
#: honest gap is measured, not assumed — the capability drop that blocks the attack also hides it.
AUDITD_SYSCALL_KEYS = {"bpf": "sbx_bpf", "io_uring_setup": "sbx_iouring", "perf_event_open": "sbx_perf"}

# --- sensor 2: OCSF (OpenShell's L7 decision trail) — the workload's network attacks ---
#: Network attacks, fingerprinted in OpenShell's per-binary/method/endpoint decision trail. This trail
#: sits at the POLICY boundary inside the sandbox, so it also records the DENIALS a syscall auditor never
#: sees — but it is L7-shaped, so it sees network attacks only.
OCSF_MATCH: dict[str, Callable[[Decision], bool]] = {
    "exfiltrate": lambda d: "/collect" in d["target"],
    "cloud_metadata": lambda d: "169.254" in d["target"],
    "reverse_shell": lambda d: "/stage" in d["target"],
    "malicious_package": lambda d: "pypi" in d["target"] or "/simple" in d["target"],
    "egress_gateway": lambda d: d["action"] == "ALLOWED" and f":{GATEWAY_PORT}" in d["target"],
    "egress_offpolicy": lambda d: (
        d["action"] == "DENIED"
        and f":{COLLECTOR_PORT}" in d["target"]
        and "/collect" not in d["target"]
        and "/stage" not in d["target"]
    ),
    "http_method_denied": lambda d: (
        d["action"] == "DENIED" and d["method"] == "POST" and f":{GATEWAY_PORT}" in d["target"]
    ),
    "binary_scoped": lambda d: "/tmp/" in d["binary"],
}


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


# --- the two listeners (identical to 1.2.4; the whole point is that they are indistinguishable) ------

HITS: list[str] = []


class _Listener(BaseHTTPRequestHandler):
    label = "?"

    def _record(self) -> None:
        HITS.append(f"{self.command} {self.label}{self.path}")
        body = json.dumps({"object": "list", "data": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record
    do_POST = _record

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - base class names it `format`
        """Silence the default stderr access log — the lesson prints what matters itself."""


def serve(port: int, label: str) -> ThreadingHTTPServer:
    handler = type(f"Listener{port}", (_Listener,), {"label": label})
    srv = ThreadingHTTPServer(("0.0.0.0", port), handler)  # noqa: S104 - throwaway box, destroyed by down.sh
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --- the openshell CLI (from 1.2.4) ------------------------------------------


def osh(*args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openshell", *args], capture_output=True, text=True, timeout=timeout, check=False)


def preflight() -> str:
    if shutil.which("openshell") is None:
        sys.exit("  OpenShell is not installed — run infra/substrates/chapter-2/40-openshell.sh in the NAT guest")
    version = osh("--version", timeout=30).stdout.strip() or "unknown"
    status = osh("status", timeout=60)
    if "Connected" not in status.stdout:
        sys.exit(
            f"  The OpenShell gateway is not reachable:\n{status.stdout}{status.stderr}\n"
            "  The gateway is a DAEMON, separate from the CLI. A PUBLIC default-route IP is the usual\n"
            "  cause — OpenShell's rootless-podman driver refuses a public address, which is why this\n"
            "  lesson runs inside the NAT guest 50-nat-vm builds."
        )
    return version


def cleanup() -> None:
    """Delete the sandbox and WAIT for it to be gone — `delete` returns before the removal completes."""
    osh("sandbox", "delete", SANDBOX, timeout=180)
    for _ in range(60):
        if SANDBOX not in osh("sandbox", "list", timeout=30).stdout:
            return
        time.sleep(2)
    print(f"  warning: {SANDBOX} is still listed after delete — the next create may fail")


def ensure_image() -> None:
    """Build the SHARED agent image into the local podman store OpenShell pulls from — same attack code."""
    print(f"  building {IMAGE} into the local podman store")
    build_dir = REPO_ROOT / "infra" / "images" / "agent"
    done = subprocess.run(
        ["podman", "build", "-q", "-t", IMAGE, str(build_dir)], capture_output=True, text=True, timeout=1800
    )
    if done.returncode != 0:
        sys.exit(f"  image build failed:\n{done.stdout}\n{done.stderr}")


def create_sandbox(policy: Path | None) -> None:
    """Create the sandbox from our image with the probe URLs injected. Two envs differ from 1.2.4, and
    both are what make the local attacks AUDITABLE: PLANT_FAKE_SECRETS plants canary credentials so
    read_credentials touches real files (leaving a real audit trail), and HOME=/sandbox points the plant
    and the backdoor writes at the writable home whose opens the host auditd records."""
    argv = [
        "sandbox", "create", "--name", SANDBOX,
        "--no-tty", "--no-auto-providers",
        "--from", IMAGE,
        "--env", f"PROBE_GATEWAY_URL=http://{HOST_ALIAS}:{GATEWAY_PORT}",
        "--env", f"PROBE_EXFIL_URL=http://{HOST_ALIAS}:{COLLECTOR_PORT}/collect",
        "--env", f"PROBE_OFFPOLICY_URL=http://{HOST_ALIAS}:{COLLECTOR_PORT}/",
        "--env", f"PROBE_STAGE_URL=http://{HOST_ALIAS}:{COLLECTOR_PORT}/stage.sh",
        "--env", f"PROBE_GROUPS={GROUPS}",
        "--env", f"PROBE_NODE_KERNEL={platform.release()}",
        "--env", "PYTHONPATH=/app",
        "--env", "PLANT_FAKE_SECRETS=1",
        "--env", "HOME=/sandbox",
        *METADATA_ENV,
    ]  # fmt: skip
    if policy:
        argv += ["--policy", str(policy)]
    argv += ["--", "echo", "ready"]
    done = osh(*argv, timeout=600)
    if done.returncode != 0:
        sys.exit(f"  sandbox create failed:\n{done.stdout}\n{done.stderr}")


def wait_ready(timeout_s: int = 120) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        listing = osh("sandbox", "list", timeout=60).stdout
        for line in listing.splitlines():
            if SANDBOX in line and "Ready" in line:
                return
        time.sleep(3)
    print(f"  warning: {SANDBOX} never reported Ready within {timeout_s}s; continuing anyway")


def apply_policy() -> None:
    """Arm the OCSF writer FIRST, then reload the policy — the reload activates it (order is load-bearing)."""
    osh("settings", "set", SANDBOX, "--key", "ocsf_json_enabled", "--value", "true", timeout=120)
    done = osh("policy", "set", SANDBOX, "--policy", str(POLICY), "--wait", timeout=300)
    if done.returncode != 0:
        sys.exit(f"  policy reload failed:\n{done.stdout}\n{done.stderr}")


def run_suite() -> Card:
    done = osh(
        "sandbox", "exec", "-n", SANDBOX, "--",
        "python", "-m", "attacks.run", "--groups", GROUPS,
        timeout=900,
    )  # fmt: skip
    if done.stderr:
        print("  --- box stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-16:]))
        print()
    return Card.parse(done.stdout, allow_partial=True)


# --- sensor 1: OCSF (OpenShell's L7 decision trail) --------------------------


_DECISION = re.compile(
    r"(?P<klass>NET|HTTP|SSH|PROC|FINDING):(?P<activity>\S+)\s+\[(?P<sev>[A-Z]+)\s*\]\s+(?P<action>ALLOWED|DENIED)\b(?P<detail>.*)"
)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BINARY = re.compile(r"(?P<binary>/\S+?)\((?P<pid>\d+)\)")
_HTTP = re.compile(r"\b(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+(?P<url>https?://\S+)")
_ENDPOINT = re.compile(r"->\s*(?P<endpoint>\S+)")


def ocsf_decisions() -> list[Decision]:
    """Read and parse OpenShell's decision trail — a compact form of the shared `parse_decisions`.

    Each decision dict carries `action`, `method` (HTTP), `binary`, and `target` (the URL or endpoint),
    which is all the OCSF_MATCH predicates need. Read host-side and a few seconds late: the L7 proxy
    flushes its log lazily, so this waits before reading.
    """
    time.sleep(4)
    done = osh("logs", SANDBOX, "--since", "15m", "-n", "800", "--source", "sandbox", timeout=120)
    decisions: list[Decision] = []
    for raw in _ANSI.sub("", done.stdout).splitlines():
        m = _DECISION.search(raw)
        if not m:
            continue
        detail = m.group("detail")
        head = detail.split("[policy:", 1)[0]
        binary = _BINARY.search(head)
        http = _HTTP.search(head)
        endpoint = _ENDPOINT.search(head)
        decisions.append(
            {
                "klass": m.group("klass"),
                "action": m.group("action"),
                "method": http.group("method") if http else "",
                "binary": binary.group("binary") if binary else "",
                "target": (http.group("url") if http else (endpoint.group("endpoint") if endpoint else head.strip())),
                "raw": raw.strip(),
            }
        )
    return decisions


def ocsf_recorded(decisions: list[Decision]) -> dict[str, str]:
    """Which network/policy probes OpenShell's L7 trail wrote down — the OCSF column."""
    return {name: (LOGGED if any(match(d) for d in decisions) else NOT_LOGGED) for name, match in OCSF_MATCH.items()}


# --- the auditd sensor's reads (all grep'd on the box, never read into Python) ------


def _grep_matches(pattern: str) -> bool:
    """Whether a workload record matches — grep of type=PATH lines only, so an EXECVE whose ARG happens
    to contain the pattern (e.g. this lesson's own `grep id_rsa`) cannot masquerade as an open."""
    r = subprocess.run(
        ["sudo", "grep", "-aE", f"type=PATH .*{pattern}", AUDIT_LOG], capture_output=True, text=True, check=False
    )
    return bool(r.stdout.strip())


def _key_logged(key: str) -> bool:
    r = subprocess.run(["sudo", "grep", "-ac", f'key="{key}"', AUDIT_LOG], capture_output=True, text=True, check=False)
    try:
        return int(r.stdout.strip() or "0") > 0
    except ValueError:
        return False


def _workload_syscalls() -> int:
    """How many syscalls the trail attributes to the rootless workload (subuid range) — the number that
    shows the host sensor is NOT blind at this rung, unlike Kata's zero. RAW format, grep'd on the box."""
    r = subprocess.run(
        ["sudo", "bash", "-c", f"grep 'type=SYSCALL' {AUDIT_LOG} | grep -cE ' uid=1[0-9]{{5}} '"],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return int(r.stdout.strip() or "0")
    except ValueError:
        return 0


def auditd_recorded() -> dict[str, str]:
    """Which local/kernel probes the in-guest auditd wrote down — the auditd column. Path probes match a
    workload-unique PATH; the seccomp-refused syscalls check their (expected-empty) key. Read once, host-side."""
    subprocess.run(["sync"], check=False)
    out = {name: (LOGGED if _grep_matches(rx) else NOT_LOGGED) for name, rx in AUDITD_PATHS.items()}
    out.update({name: (LOGGED if _key_logged(key) else NOT_LOGGED) for name, key in AUDITD_SYSCALL_KEYS.items()})
    return out


# --- combine the two sensors into the per-probe RECORDED band ----------------


def _mark(state: str | None) -> str:
    if state == LOGGED:
        return "LOGGED"
    if state == NOT_LOGGED:
        return "not logged"
    return "— (blind)"


def combine(card: Card, auditd: dict[str, str], ocsf: dict[str, str]) -> dict[str, str]:
    """Resolve every scored probe to LOGGED / NOT_LOGGED / NO_SENSOR from the UNION of the two sensors,
    and write it onto the finding so it rides into results/2.2.4.json and the RECORDED band. A probe no
    sensor is applicable to (kernel_identity, the audit_records meta-row) is NO_SENSOR, never blank."""
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:  # INFO rows are not scored, so not audited
            continue
        name = finding["name"]
        states = [s for s in (auditd.get(name), ocsf.get(name)) if s is not None]
        if not states:
            state = NO_SENSOR
        elif LOGGED in states:
            state = LOGGED
        else:
            state = NOT_LOGGED
        finding["recorded"] = state
        out[name] = state
    return out


def assert_no_kernel_boundary(card: Card, guest_kernel: str) -> None:
    """OpenShell is runc: the sandbox shares the guest kernel, so its syscalls DO reach the host kernel
    auditd watches (the mirror of 2.2.3's assert_vm_engaged, which demanded the kernels DIFFER). The twist
    this rung then measures: reaching the host kernel is not the same as being attributed by a host sensor."""
    inside = card.get("kernel_identity")
    inside_kernel = str(inside["value"]) if inside else "?"
    same = inside_kernel == guest_kernel
    print(f"    sandbox kernel {inside_kernel}   guest (host) kernel {guest_kernel}")
    print(
        f"    [{'OK' if same else '..'}] the sandbox shares the guest kernel — no VM boundary, its syscalls reach the host"
    )
    if not same:
        print("    note: kernel_identity differs from the guest — a boundary is present the lesson did not expect")


# --- box plumbing (from 1.2.4) -----------------------------------------------


def box_ip_if_any() -> str | None:
    try:
        for line in STATE_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("BOX_IP="):
                return line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        return None
    return None


def refuse_no_box() -> None:
    print(f"No box for {LESSON} is up — nothing to run.")
    print("This lesson runs INSIDE a libvirt NAT guest on its own disposable box (OpenShell's rootless")
    print("driver refuses a public default route). Start the box, then run it from here:\n")
    print(f"    cd ../../../../infra && ./up.sh {LESSON}      # or press 'u' in the sbx-tui panel")
    print("    uv run python -u main.py                # runs it on the box and brings the card home")
    raise SystemExit(2)


def main() -> None:
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        ip = box_ip_if_any()
        if not ip:
            refuse_no_box()
            return  # unreachable — refuse_no_box exits — but narrows ip to str for the type checker
        print(f"Box for {LESSON} is up ({ip}). Running the lesson ON it via infra/run.sh …\n")
        raise SystemExit(subprocess.run([str(REPO_ROOT / "infra" / "run.sh"), LESSON]).returncode)

    version = preflight()
    ensure_image()
    guest_kernel = platform.release()

    banner("Part 1 — The same suite as 1.2.4 (plus planted canaries), under OpenShell, with auditd watching")
    print(f"  OpenShell {version} — ALPHA. Ordinary runc, host kernel fully exposed: no VM boundary, so the")
    print("  workload's syscalls reach the in-guest auditd — the opposite of Kata (2.2.3). 1.2.4 measured")
    print("  what the policy blocked; 2.2.4 measures what got written down, by auditd and by OpenShell's OCSF.")
    print("\n  Two listeners on the guest, one port apart:")
    print(f"    :{GATEWAY_PORT}  the model gateway the agent legitimately needs   -> policy ALLOWS GET")
    print(f"    :{COLLECTOR_PORT}  the attacker's collector                         -> never named, DENIED")
    gateway = serve(GATEWAY_PORT, "gateway")
    collector = serve(COLLECTOR_PORT, "collector")

    try:
        banner("Part 2a — Default-deny, before any policy exists")
        cleanup()
        create_sandbox(None)
        wait_ready()
        status = probe_default_deny()
        print(f"    agent tool -> GET gateway/v1/models : {status}  ", end="")
        print("(denied — a sandbox with no policy permits nothing)" if not status.startswith("2") else "(REACHED)")

        banner("Part 2b — Recreate WITH the policy, arm the audit trail, then reload")
        cleanup()  # a fresh sandbox: the static half of a policy can only be set at startup
        create_sandbox(POLICY)
        wait_ready()
        apply_policy()
        print(f"    ocsf_json_enabled=true, then policy set --wait  ({POLICY.name})")
        print("    (that order is load-bearing: the writer activates on the policy reload)")

        banner("Part 2c — Turn the rogue agent loose, with egress ON but scoped")
        card = run_suite()
        decisions = ocsf_decisions()
        card.add(
            Finding(
                name="audit_records",
                value=len(decisions),
                contained=len(decisions) > 0,
                group="evidence",
                detail="policy decisions recorded by OpenShell's OCSF trail",
            )
        )
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}  (read_credentials reads a planted canary here,")
        print("  so it shows reached where 1.2.4 — with nothing to steal — showed it contained)")

        banner("No VM boundary here — the workload's syscalls DO reach the host kernel")
        assert_no_kernel_boundary(card, guest_kernel)

        banner("Part 3 — Two sensors, disjoint columns: auditd (host syscalls) and OCSF (L7 network)")
        auditd = auditd_recorded()
        ocsf = ocsf_recorded(decisions)
        workload_syscalls = _workload_syscalls()
        recorded = combine(card, auditd, ocsf)
        print(f"    {'probe':<20} {'auditd (host)':<16} {'OCSF (L7)':<12}")
        print(f"    {'-' * 20} {'-' * 16} {'-' * 12}")
        for name in recorded:
            print(f"    {name:<20} {_mark(auditd.get(name)):<16} {_mark(ocsf.get(name)):<12}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down — by the union of the two sensors.")
        print(f"  Unlike Kata (2.2.3, where the host sensor read ZERO), auditd recorded {workload_syscalls}")
        print("  syscalls from the rootless workload here: OpenShell is runc, so the syscalls reach the host")
        print("  kernel. auditd catches the attacks that touch a real file — the planted credentials it reads,")
        print("  the backdoor it writes, the malicious package it installs. OCSF catches the network attacks,")
        print("  naming each by binary, method and endpoint — the column a raw syscall has no words for.")

        banner("Part 4 — What each sensor saw, and the honest gap between them")
        for d in [d for d in decisions if d["action"] in ("ALLOWED", "DENIED")][:6]:
            print(f"      {d['raw'][:112]}")
        gaps = [n for n, v in recorded.items() if v == NOT_LOGGED]
        print(f"\n  Not written down: {', '.join(gaps) or '(none)'}.")
        print("  The capability-denied kernel probes (bpf/io_uring/perf) ARE recorded — a syscall that")
        print("  returns EPERM still exits, and the audit exit hook fires. What leaves no trail is a")
        print("  write DENIED by the filesystem policy: fs_policy_write's open of /etc is refused before")
        print("  it resolves to a record, so a host syscall auditor sees what the workload DID, not what")
        print("  the boundary DENIED — the one decision only OpenShell's policy engine writes down. That")
        print("  is the phase-2 finding: observability is per-sensor-shaped, and full coverage is the two")
        print("  sensors together — auditd for the syscalls that happen, OCSF for the L7 policy decisions.")

        card.save(
            RESULTS,
            lesson="2.2.4",
            mode="network-on",
            node_kernel=guest_kernel,
            boundary="ordinary runc + OpenShell policy; in-guest auditd (local attacks) + OCSF trail (network attacks) (phase-2 audit of 1.2.4)",
            engine="openshell",
            openshell_version=version,
            auditd_workload_syscalls=workload_syscalls,
            host_sensor_logged=sum(1 for v in auditd.values() if v == LOGGED),
            ocsf_logged=sum(1 for v in ocsf.values() if v == LOGGED),
            listener_hits=HITS,
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        gateway.shutdown()
        collector.shutdown()
        cleanup()


def probe_default_deny() -> str:
    try:
        done = osh(
            "sandbox", "exec", "-n", SANDBOX, "--",
            "/usr/bin/curl", "-sS", "-m", "8", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://{HOST_ALIAS}:{GATEWAY_PORT}/v1/models",
            timeout=60,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        return "timeout"
    return (done.stdout or "000").strip().splitlines()[-1] if done.stdout.strip() else "000"


if __name__ == "__main__":
    main()
