"""Lesson 2.3.5 — auditing OpenShell over gVisor. The run where the audit trail is the only witness.

Audits 1.3.5, and it is the leaf where phase 2's whole argument stops being a nice idea and becomes
load-bearing.

1.3.5 measured this: stacking OpenShell's policy on gVisor makes the filesystem clause **silently
lose its Landlock backing**, because gVisor answers `ENOSYS` to `landlock()`. And then it measured
the uncomfortable part — the loss is **masked**. `fs_policy_write` stays BLOCKED anyway, because
OpenShell's kubernetes driver also backs the read-only paths with a read-only ROOT FILESYSTEM. So the
containment scorecard of this stack is **identical to the safe one**. Nothing on it moves. A team
scoring boundaries would ship this and never know a defense layer had disappeared.

The one thing that does move is a line in the audit trail: OpenShell emits a HIGH
`landlock-unavailable` finding and carries on. This lesson reads it, and that is the answer to "why
audit a boundary you already scored" — because a scorecard cannot tell you about a control that
stopped existing while the outcome stayed the same.

Two sensors, and deliberately no host one between them:

  * **OCSF** — OpenShell's L7 decision trail, for the network attacks AND for the Landlock finding.
  * **the sentry's own trace** — gVisor's user-space kernel, for the local attacks, exactly as 2.3.2
    reads it. There is no host-sensor option here at all: discovery gate G2 established that no host
    eBPF sensor can see through the sentry (Falco dropped its gVisor source in 0.41; Tetragon never
    had one), so 2.3.4's Tetragon column has no equivalent on this rung.

The composition is one flag from 2.3.4: the same policy file, the same suite, the same OCSF sensor,
with `runtimeClassName: gvisor-trace` underneath instead of runc.

    cd ../../../../infra && ./up.sh 2.3.5     # provisions chapter-03-audit-k8s
    uv run python -u main.py

Verified against the OpenShell version printed at the top of the run. OpenShell is ALPHA; the version
is recorded in the scorecard so drift is visible rather than mysterious.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import k8s
from scorecard import Card, Finding, render_report

Decision = dict[str, str]

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.3.5"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
NAMESPACE = "sbx-2-3-5"
RESULTS = REPO_ROOT / "results" / "2.3.5.json"
POLICY_SRC = Path(__file__).parent / "policy.yaml"
POLICY_OUT = Path("/tmp/lesson-2-3-5-policy.yaml")

#: The TRACED gVisor class, not 1.3.5's plain `gvisor`. Same runsc binary, same boundary; the only
#: difference is that this one writes the sandbox's syscalls to the sentry's boot log, which is the
#: sole sensor that can see inside it (substrate chapter-3-audit/72-k8s-gvisor-trace).
RUNTIME_CLASS = "gvisor-trace"
DRIVER_CONFIG = {"kubernetes": {"pod": {"runtime_class_name": RUNTIME_CLASS}}}
GW_NS = "openshell"
#: OpenShell caps sandbox names at 19 characters. Counted, not estimated.
SANDBOX = "sbx-235-gvis-osh"
#: The FULL suite, where 1.3.5 runs only `kernel,policy`. The audit question needs attacks the two
#: sensors can disagree about; with only those two groups there is no network attack for OCSF to
#: catch. The comparison this leaf turns on is 2.3.4 -> 2.3.5, one field apart.
GROUPS = "reach,abuse,kernel,policy,cost"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")

TRACE_DIR = Path("/var/log/runsc-trace")

#: Which probes the sentry's trace can fingerprint. Same map 2.3.2 uses.
SENTRY_PROBES = (
    "read_credentials",
    "exfiltrate",
    "cloud_metadata",
    "plant_backdoor",
    "malicious_package",
    "reverse_shell",
    "resource_exhaustion",
    "bpf",
    "io_uring_setup",
    "perf_event_open",
    "sys_module_count",
    "kallsyms_readable",
)

#: 2.3.4's OCSF predicates, unchanged — the composition must not move the L7 sensor's mapping, or a
#: difference between the two lessons could be the mapping rather than the runtime.
OCSF_MATCH: dict[str, Callable[[Decision], bool]] = {
    "exfiltrate": lambda d: "/collect" in d["target"],
    "cloud_metadata": lambda d: "169.254" in d["target"],
    "reverse_shell": lambda d: "/stage" in d["target"],
    "malicious_package": lambda d: "pypi" in d["target"] or "/simple" in d["target"],
    "egress_gateway": lambda d: d["action"] == "ALLOWED" and "sbx-gateway" in d["target"],
    "egress_offpolicy": lambda d: (
        d["action"] == "DENIED"
        and "sbx-collector" in d["target"]
        and "/collect" not in d["target"]
        and "/stage" not in d["target"]
    ),
    "http_method_denied": lambda d: d["action"] == "DENIED" and d["method"] == "POST" and "sbx-gateway" in d["target"],
    "binary_scoped": lambda d: "/tmp/" in d["binary"],
}

LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def osh(*args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openshell", *args], capture_output=True, text=True, timeout=timeout, check=False)


def preflight() -> str:
    if os.environ.get("OPENSHELL_DRIVERS") != "kubernetes":
        sys.exit(
            "  OPENSHELL_DRIVERS is not 'kubernetes'. A gateway takes ONE compute driver, and this\n"
            "  lesson needs the cluster one. `source ~/.sandboxing-tutorial.env` (substrate 90 wrote it)."
        )
    status = osh("status", timeout=120).stdout
    if "Connected" not in status:
        sys.exit(f"  the OpenShell gateway is not Connected:\n{status}")
    raw = osh("--version", timeout=60).stdout.strip()
    version = raw.splitlines()[0] if raw else "unknown"
    print(f"  openshell {version}, gateway Connected, driver=kubernetes")
    return version


def render_policy(gateway_host: str) -> Path:
    text = POLICY_SRC.read_text(encoding="utf-8").replace("__GATEWAY_HOST__", gateway_host)
    POLICY_OUT.write_text(text, encoding="utf-8")
    return POLICY_OUT


def create_sandbox(policy: Path, gateway: str, collector: str) -> None:
    argv = [
        "sandbox", "create", "--name", SANDBOX,
        "--no-tty", "--no-auto-providers",
        "--from", k8s.IMAGE,
        "--driver-config-json", json.dumps(DRIVER_CONFIG),
        "--env", f"PROBE_GATEWAY_URL=http://{gateway}:{k8s.GATEWAY_PORT}",
        "--env", f"PROBE_EXFIL_URL=http://{collector}:{k8s.GATEWAY_PORT}/collect",
        "--env", f"PROBE_OFFPOLICY_URL=http://{collector}:{k8s.GATEWAY_PORT}/",
        "--env", f"PROBE_STAGE_URL=http://{collector}:{k8s.GATEWAY_PORT}/stage.sh",
        "--env", f"PROBE_GROUPS={GROUPS}",
        "--env", f"PROBE_NODE_KERNEL={platform.release()}",
        "--env", "PYTHONPATH=/app",
        "--policy", str(policy),
    ]  # fmt: skip
    if METADATA_URL:
        argv += ["--env", f"PROBE_METADATA_URL={METADATA_URL}"]
    argv += ["--", "echo", "ready"]
    done = osh(*argv, timeout=900)
    if done.returncode != 0:
        sys.exit(f"  sandbox create failed:\n{done.stdout}\n{done.stderr}")


def wait_ready(timeout_s: int = 300) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for line in osh("sandbox", "list", timeout=60).stdout.splitlines():
            if SANDBOX in line and "Ready" in line:
                return
        time.sleep(3)
    print(f"  warning: {SANDBOX} never reported Ready within {timeout_s}s; continuing anyway")


def apply_policy(policy: Path) -> None:
    osh("settings", "set", SANDBOX, "--key", "ocsf_json_enabled", "--value", "true", timeout=120)
    done = osh("policy", "set", SANDBOX, "--policy", str(policy), "--wait", timeout=300)
    if done.returncode != 0:
        sys.exit(f"  policy reload failed:\n{done.stdout}\n{done.stderr}")


def sandbox_pod() -> str:
    out = k8s.kubectl(
        "-n", GW_NS, "get", "pods", "-o", "jsonpath={range .items[*]}{.metadata.name}{'\\n'}{end}", check=False
    )  # fmt: skip
    return next((n for n in out.splitlines() if SANDBOX in n), "")


def run_suite() -> Card:
    done = osh(
        "sandbox", "exec", "-n", SANDBOX, "--",
        "python", "-m", "attacks.run", "--groups", GROUPS,
        timeout=1200,
    )  # fmt: skip
    if done.stderr:
        print("  --- sandbox stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-16:]))
        print()
    return merge_sandbox_death(Card.parse(done.stdout, allow_partial=True), done.stderr)


def merge_sandbox_death(card: Card, stderr: str) -> Card:
    """Record the row the suite did not survive to print, instead of letting it vanish.

    On this rung the fork bomb regularly takes the whole sandbox with it, and that is a property of
    gVisor rather than a flake: the sentry and its per-task stub processes live INSIDE the container's
    cgroup, so a 128-way fork that merely earns EAGAIN under runc exhausts the sandbox itself here.
    The exec relay then closes before the command reports an exit status and `resource_exhaustion`
    never reaches stdout.

    2.2.2 lets that row simply disappear, which leaves an 18-row card next to everyone else's 19 with
    nothing saying why. Naming it costs one row and removes a silent hole.

    `contained` stays **None** unless the pod object actually says OOMKilled. A sandbox that died for
    some other reason was not demonstrably capped, and scoring it as contained would invent a
    boundary — the same rule 1.3.1's merge_pod_death follows.
    """
    if card.get("resource_exhaustion") is not None:
        return card
    pod = sandbox_pod()
    reason = ""
    if pod:
        reason = k8s.kubectl(
            "-n", GW_NS, "get", "pod", pod,
            "-o", "jsonpath={.status.containerStatuses[0].state.terminated.reason}",
            check=False,
        )  # fmt: skip
    oom = reason == "OOMKilled"
    print(f"  ! the suite did not survive attack 7 (pod terminated: {reason or 'still running'})")
    print("    Expected on this rung: gVisor's sentry and stubs share the container's cgroup, so the")
    print("    fork bomb exhausts the sandbox rather than merely earning EAGAIN.")
    # The FIRST line of stderr is the suite's own banner rule, not the failure — quoting it verbatim
    # put a row of `=` in the scorecard's detail where the diagnosis should be. Find the line that
    # actually mentions an error, and say nothing rather than something misleading if there is none.
    complaint = next((ln.strip() for ln in stderr.splitlines() if "error" in ln.lower()), "")
    return card.add(
        Finding(
            name="resource_exhaustion",
            value="capped:sandbox-oomkilled" if oom else "sandbox-died:exec-relay-closed",
            contained=True if oom else None,
            group="abuse",
            detail=(
                "the fork bomb took the gVisor sandbox down mid-attack; "
                + ("the kubelet recorded OOMKilled" if oom else "no OOMKilled evidence, so not scored as contained")
            )
            + (f" ({complaint[:70]})" if complaint else ""),
        )
    )


# --- sensor 1: the sentry's own trace (from 2.3.2) ---------------------------


def clear_trace() -> None:
    """Empty the trace directory before the run — several sandboxes run on this node, and a boot log
    left from one of them would put another workload's syscalls in this lesson's trail."""
    subprocess.run(["sudo", "bash", "-c", f"rm -f {TRACE_DIR}/* 2>/dev/null"], check=False)


def _boot_files() -> list[str]:
    r = subprocess.run(
        ["sudo", "bash", "-c", f"ls {TRACE_DIR}/*boot* 2>/dev/null"], capture_output=True, text=True, check=False
    )
    return r.stdout.split()


def _boot_has(ere: str, files: list[str]) -> bool:
    if not files:
        return False
    r = subprocess.run(["sudo", "grep", "-aEl", "--", ere, *files], capture_output=True, text=True, check=False)
    return bool(r.stdout.strip())


def _connect_dests(files: list[str]) -> set[str]:
    if not files:
        return set()
    quoted = " ".join(shlex.quote(f) for f in files)
    cmd = rf"grep -aoE ' E connect\(.*Addr: [0-9.]+' {quoted} | grep -oE 'Addr: [0-9.]+' | sed 's/Addr: //' | sort -u"
    r = subprocess.run(["sudo", "bash", "-c", cmd], capture_output=True, text=True, check=False)
    return set(r.stdout.split())


def sentry_recorded() -> tuple[dict[str, str], int]:
    files = _boot_files()
    total = 0
    if files:
        quoted = " ".join(shlex.quote(f) for f in files)
        r = subprocess.run(
            ["sudo", "bash", "-c", rf"grep -ahcE ' E [a-z_]+\(' {quoted} | awk '{{n += $1}} END {{print n + 0}}'"],
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            total = int(r.stdout.strip() or "0")
        except ValueError:
            total = 0
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

    return {name: state_for(name) for name in SENTRY_PROBES}, total


# --- sensor 2: OCSF ----------------------------------------------------------

_DECISION = re.compile(
    r"(?P<klass>NET|HTTP|SSH|PROC|FINDING):(?P<activity>\S+)\s+\[(?P<sev>[A-Z]+)\s*\]\s+(?P<action>ALLOWED|DENIED)\b(?P<detail>.*)"
)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BINARY = re.compile(r"(?P<binary>/\S+?)\((?P<pid>\d+)\)")
_HTTP = re.compile(r"\b(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+(?P<url>https?://\S+)")
_ENDPOINT = re.compile(r"->\s*(?P<endpoint>\S+)")


def sandbox_log() -> str:
    """OpenShell's trail for this sandbox, read once and reused.

    Read once because the two things this lesson takes from it — the policy decisions and the
    Landlock finding — are in the same stream, and reading it twice would let them come from
    different windows.
    """
    time.sleep(4)
    return osh("logs", SANDBOX, "--since", "20m", "-n", "800", "--source", "sandbox", timeout=120).stdout


def ocsf_decisions(raw_log: str) -> list[Decision]:
    decisions: list[Decision] = []
    for raw in _ANSI.sub("", raw_log).splitlines():
        m = _DECISION.search(raw)
        if not m:
            continue
        head = m.group("detail").split("[policy:", 1)[0]
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
    return {name: (LOGGED if any(match(d) for d in decisions) else NOT_LOGGED) for name, match in OCSF_MATCH.items()}


def landlock_witness(raw_log: str) -> tuple[int, list[str]]:
    """The audit trail's word on Landlock — the ONLY signal that a defense layer silently vanished.

    Under gVisor `landlock()` answers ENOSYS, and OpenShell 0.0.99 emits a HIGH finding
    (`landlock-unavailable`, "Landlock Filesystem Sandbox Unavailable") and CONTINUES. Its presence
    is what tells you the filesystem clause lost its Landlock backing — the attack outcome cannot,
    because the read-only rootfs still blocks the write. Matched on the wording this CLI version
    actually prints, verified on the box, not the prior art's phrasing.
    """
    high = [ln for ln in raw_log.splitlines() if "landlock" in ln.lower() and "unavailable" in ln.lower()]
    return len(high), high[:4]


# --- combine and assert ------------------------------------------------------


def _mark(state: str | None) -> str:
    if state == LOGGED:
        return "LOGGED"
    if state == NOT_LOGGED:
        return "not logged"
    return "— (blind)"


def combine(card: Card, sentry: dict[str, str], ocsf: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:
            continue
        name = finding["name"]
        states = [s for s in (sentry.get(name), ocsf.get(name)) if s is not None]
        if not states:
            state = NO_SENSOR
        elif LOGGED in states:
            state = LOGGED
        else:
            state = NOT_LOGGED
        finding["recorded"] = state
        out[name] = state
    return out


def assert_stack_engaged(card: Card, pod: str, sentry_syscalls: int, decisions: list[Decision]) -> None:
    """Prove BOTH layers of the composition are real, and both sensors were live.

    The gVisor half is asserted from the pod spec AND from inside the sandbox: a `runtimeClassName`
    that was accepted while runc ran anyway exits 0 and prints everything this lesson expects, and
    the whole finding below would then be about a stack that was never built.
    """
    rtclass = k8s.kubectl("-n", GW_NS, "get", "pod", pod, "-o", "jsonpath={.spec.runtimeClassName}", check=False)
    inside = card.get("kernel_identity")
    kernel = str(inside["value"]) if inside else "?"
    print(f"    pod .spec.runtimeClassName: {rtclass or '(none)'}   (expected: {RUNTIME_CLASS})")
    print(f"    kernel inside the sandbox : {kernel}")
    checks = {
        "the overlay landed (the sandbox pod asked for the traced gVisor class)": rtclass == RUNTIME_CLASS,
        "gVisor engaged — the sandbox reports its OWN kernel, not the node's": "gvisor" in kernel.lower(),
        "the sentry's trace holds the application's syscalls": sentry_syscalls > 0,
        "OpenShell's L7 policy is live above it (the same host's POST was denied)": (
            card.contained("http_method_denied") is True
        ),
        "OpenShell's OCSF trail recorded decisions": len(decisions) > 0,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  assertion FAILED — the stack or a sensor did not engage; not reporting a result.")


def cleanup() -> None:
    osh("sandbox", "delete", SANDBOX, "--force", timeout=300)
    k8s.delete_namespace(NAMESPACE)


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
    print("This lesson only runs on its own disposable Scaleway box: it needs k3s with the traced")
    print("gVisor RuntimeClass and the OpenShell gateway. Start the box, then run it from here:\n")
    print(f"    cd ../../../../infra && ./up.sh {LESSON}")
    print("    uv run python -u main.py")
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
    subprocess.run(
        ["sudo", "bash", str(REPO_ROOT / "infra" / "images" / "agent" / "import-k3s.sh")],
        check=True, capture_output=True, timeout=900,
    )  # fmt: skip
    k8s.ensure_namespace(NAMESPACE)
    try:
        banner("Part 1 — 2.3.4's stack with gVisor underneath it, and a sensor that can see inside")
        gateway = k8s.start_service(NAMESPACE, "sbx-gateway")
        collector = k8s.start_service(NAMESPACE, "sbx-collector")
        print(f"  gateway   (allowed by policy): {gateway}:{k8s.GATEWAY_PORT}")
        print(f"  collector (named nowhere)    : {collector}:{k8s.GATEWAY_PORT}")
        print(f"  driver-config overlay: {json.dumps(DRIVER_CONFIG)}")
        print("  There is NO host sensor on this rung and there cannot be — gate G2. The two sensors")
        print("  are OpenShell's own L7 trail and gVisor's own sentry trace.\n")

        clear_trace()
        policy = render_policy(gateway)
        create_sandbox(policy, gateway, collector)
        wait_ready()
        apply_policy(policy)
        pod = sandbox_pod()
        print(f"  sandbox {SANDBOX} Ready as pod {pod or '?'}, OCSF armed, policy applied")

        banner("Part 2 — Turn the rogue agent loose on the composed stack")
        card = run_suite()
        raw_log = sandbox_log()
        decisions = ocsf_decisions(raw_log)
        n_high, sample = landlock_witness(raw_log)
        sentry, sentry_syscalls = sentry_recorded()
        card.add(
            Finding(
                name="audit_records",
                value=len(decisions),
                contained=len(decisions) > 0,
                group="evidence",
                detail="policy decisions recorded by OpenShell's OCSF trail",
            )
        )
        card.add(
            Finding(
                name="landlock_available",
                value="unavailable" if n_high else "available",
                contained=None,
                group="evidence",
                detail=f"{n_high} HIGH landlock-unavailable finding(s); the read-only rootfs masks the loss",
            )
        )
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        banner("Assert the composed stack and both sensors engaged")
        assert_stack_engaged(card, pod, sentry_syscalls, decisions)

        banner("Part 3 — Two sensors, no host one, and the row that did NOT move")
        ocsf = ocsf_recorded(decisions)
        recorded = combine(card, sentry, ocsf)
        print(f"    {'probe':<20} {'sentry trace':<16} {'OCSF (L7)':<14}")
        print(f"    {'-' * 20} {'-' * 16} {'-' * 14}")
        for name in recorded:
            print(f"    {name:<20} {_mark(sentry.get(name)):<16} {_mark(ocsf.get(name)):<14}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down, by two sensors with no host")
        print(f"  sensor available between them. The sentry saw {sentry_syscalls} syscalls from this")
        print("  sandbox; a host eBPF probe would have seen none of them, whichever tool you picked.")

        banner("Part 4 — The finding that only the audit trail can carry")
        if n_high:
            print(f"  {n_high} HIGH `landlock-unavailable` finding(s) in OpenShell's trail:\n")
            for line in sample:
                print(f"      {line.strip()[:112]}")
            print()
            print("  Now look at `fs_policy_write` on the card above. It is BLOCKED — the same verdict")
            print("  the safe Kata stack gives (2.3.6), and the same verdict plain runc gives (2.3.4).")
            print("  gVisor answered ENOSYS to landlock(), the filesystem clause lost its Landlock")
            print("  backing, and the outcome did not move a millimetre, because this driver ALSO")
            print("  backs those paths with a read-only root filesystem. The lost layer is MASKED.")
            print()
            print("  That is the sharpest argument phase 2 has. A containment scorecard compares")
            print("  outcomes, and here the outcome is identical to the stack that is genuinely safe.")
            print("  The only thing in this entire run that distinguishes them is one line of audit")
            print("  trail — and `hard_requirement` (1.3.5 Part 2), which turns the same fact into a")
            print("  refusal to start rather than a line nobody read.")
        else:
            print("  NO landlock-unavailable finding was recorded, which contradicts 1.3.5's measurement")
            print("  on OpenShell 0.0.99. Either the version moved or the sandbox did not run on gVisor.")
            print("  Investigate before trusting this run — the assertion above checked the runtime, so")
            print("  the likelier cause is that this OpenShell version changed how it reports the loss.")

        card.save(
            RESULTS,
            lesson="2.3.5",
            mode="compose-gvisor",
            engine="k3s",
            node_kernel=platform.release(),
            openshell_version=version,
            runtime_class=RUNTIME_CLASS,
            boundary="OpenShell kubernetes driver stacked on gVisor (runtimeClassName: gvisor-trace); sentry trace + OCSF, no host sensor possible (phase-2 audit of 1.3.5)",
            landlock_findings=n_high,
            sentry_syscalls=sentry_syscalls,
            sentry_logged=sum(1 for v in sentry.values() if v == LOGGED),
            ocsf_logged=sum(1 for v in ocsf.values() if v == LOGGED),
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
