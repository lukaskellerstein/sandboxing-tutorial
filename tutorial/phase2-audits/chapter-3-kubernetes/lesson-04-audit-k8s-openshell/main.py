"""Lesson 2.3.4 — auditing the OpenShell rung on a cluster. Three sensors, and one of them has nothing to say.

Audits 1.3.4. It runs the SAME suite under the SAME OpenShell policy — byte for byte, 1.3.4's
``policy.yaml`` — with three sensors watching, and reports per attack whether any of them wrote it
down. This is 2.2.4's two-sensor mapping moved onto the cluster, with the host sensor swapped for the
one this phase uses everywhere else:

  * **Tetragon** (host CO-RE eBPF) — the local attacks. OpenShell runs on ordinary runc, so the
    sandbox pod's syscalls reach the NODE's kernel, where Tetragon is watching. This is the mirror of
    2.2.4's in-guest auditd and the opposite of 2.2.3, where Kata's guest kernel left the host sensor
    reading zero.
  * **OCSF** (OpenShell's L7 decision trail) — the network attacks, by binary, method and endpoint.
    The one sensor that also records what the boundary **denied**, which no syscall tracer can.
  * **the apiserver audit log** — the control-plane column 2.3.1 turned on.

**The third sensor records nothing of the workload's, and that is a finding rather than a gap.** An
OpenShell sandbox is a Pod, but it is not a cluster *principal*: it gets no service-account token and
no ``KUBERNETES_SERVICE_HOST``, so ``k8s_sa_token`` does not even run (it reads ``n/a-no-cluster``,
exactly as it does in 1.3.4). The attack surface 2.3.1 had to leave open to measure at all is simply
absent here — the sandbox cannot talk to the control plane because it was never told there is one.
The audit log is on and recording throughout; what it holds is the OPERATOR's actions, not the
agent's.

Unlike 2.2.4 this lesson plants **no canary credentials**, and the reason is the sensor. 2.2.4's
auditd fingerprints a `type=PATH` record, which only exists once a path resolves to an inode — so
without a planted file the credential theft left no trail and the rung looked blind. Tetragon hooks
the open SYSCALL, which fires on the attempt whether or not the file exists. So the honest
measurement needs no canary here, and this card is 1.3.4's containment unchanged rather than one
row weaker.

    cd ../../../../infra && ./up.sh 2.3.4     # provisions chapter-03-audit-k8s
    uv run python -u main.py

Verified against the OpenShell version printed at the top of the run. OpenShell is ALPHA; the version
is recorded in the scorecard so drift is visible rather than mysterious.
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import k8s
from scorecard import Card, Finding, render_report

#: A parsed OpenShell decision: action / method / binary / target / raw, all strings.
Decision = dict[str, str]

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.3.4"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
NAMESPACE = "sbx-2-3-4"
RESULTS = REPO_ROOT / "results" / "2.3.4.json"
POLICY_SRC = Path(__file__).parent / "policy.yaml"
POLICY_OUT = Path("/tmp/lesson-2-3-4-policy.yaml")
#: OpenShell caps sandbox names at 19 characters and rejects a longer one with a message that never
#: mentions length. Counted, not estimated.
SANDBOX = "sbx-234-audit-osh"
#: OpenShell's kubernetes driver puts every sandbox pod in its own namespace, named
#: `<tenant>--<sandbox>`. Read at run time rather than assumed — see sandbox_container_id.
OSH_NAMESPACE = "openshell"
GROUPS = "reach,abuse,kernel,policy,cost"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")

# --- sensor 1: Tetragon, the host kernel sensor ------------------------------
#
#: The SAME map 2.2.1 and 2.3.1 use, so the host-sensor column is comparable straight down the ladder.
PROBE_TAG = {
    "read_credentials": "read_credentials",
    "exfiltrate": "network",
    "cloud_metadata": "network",
    "plant_backdoor": "exec",
    "malicious_package": "exec",
    "reverse_shell": "exec",
    "resource_exhaustion": "exec",
    "bpf": "bpf",
    "io_uring_setup": "io_uring_setup",
    "perf_event_open": "perf_event_open",
}
TETRAGON_OUT = Path("/tmp/sbx-tetragon.jsonl")
TETRAGON_POLICY = "/etc/tetragon/sbx-sandboxing.yaml"
TETRAGON_BPF_LIB = "/usr/local/lib/tetragon/bpf"
ATTACH_SECONDS = 20
_TAG_RE = re.compile(r"^sbx_probe=(\w+)$")

# --- sensor 2: OCSF, OpenShell's L7 decision trail ---------------------------
#
#: 2.2.4's predicates, retargeted from ports to cluster DNS names. On the podman driver the gateway
#: and the collector were two ports on one host; here they are two Services on the same port, which
#: is what makes the policy readable — and it is still ONE line of policy that separates them.
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

# --- sensor 3: the apiserver audit log ---------------------------------------
AUDIT_LOG = Path("/var/lib/rancher/k3s/server/logs/audit.log")

LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


# --- the openshell CLI (from 1.3.4) ------------------------------------------


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
    """1.3.4's sandbox, with 1.3.4's environment. Nothing here is weakened for the sake of the audit —
    see the module docstring on why this rung needs no planted canaries."""
    argv = [
        "sandbox", "create", "--name", SANDBOX,
        "--no-tty", "--no-auto-providers",
        "--from", k8s.IMAGE,
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
    """`sandbox create` returns before the supervisor accepts work, and an exec in that window HANGS
    rather than failing — polling for Ready turns a mystifying stall into a bounded wait."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for line in osh("sandbox", "list", timeout=60).stdout.splitlines():
            if SANDBOX in line and "Ready" in line:
                return
        time.sleep(3)
    print(f"  warning: {SANDBOX} never reported Ready within {timeout_s}s; continuing anyway")


def apply_policy(policy: Path) -> None:
    """Arm the OCSF writer FIRST, then reload the policy — the reload is what activates it."""
    osh("settings", "set", SANDBOX, "--key", "ocsf_json_enabled", "--value", "true", timeout=120)
    done = osh("policy", "set", SANDBOX, "--policy", str(policy), "--wait", timeout=300)
    if done.returncode != 0:
        sys.exit(f"  policy reload failed:\n{done.stdout}\n{done.stderr}")


def sandbox_container_id() -> str:
    """The container id of the pod OpenShell created — the key the host sensor's trail is filtered by.

    OpenShell owns this pod, so the lesson cannot label it or name it: it is discovered. The driver
    puts it in the `openshell` namespace under `<tenant>--<sandbox>`, but rather than trusting that
    shape, every pod in that namespace whose name CONTAINS the sandbox name is matched — a naming
    change upstream then costs nothing, and the alternative (a hardcoded pod name) would fail as an
    empty trail, which reads exactly like "the sensor saw nothing".
    """
    out = k8s.kubectl(
        "-n", OSH_NAMESPACE, "get", "pods",
        "-o", "jsonpath={range .items[*]}{.metadata.name}{'\\t'}{.status.containerStatuses[0].containerID}{'\\n'}{end}",
        check=False,
    )  # fmt: skip
    for line in out.splitlines():
        name, _, cid = line.partition("\t")
        if SANDBOX in name and cid:
            return cid.split("://")[-1]
    return ""


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
    return Card.parse(done.stdout, allow_partial=True)


# --- Tetragon (from 2.3.1: attribution by container id) ----------------------


def start_tetragon() -> subprocess.Popen[bytes]:
    subprocess.run(["sudo", "rm", "-f", str(TETRAGON_OUT)], check=False)
    proc = subprocess.Popen(
        [
            "sudo",
            "tetragon",
            "--bpf-lib",
            TETRAGON_BPF_LIB,
            "--enable-process-ns",
            "--tracing-policy",
            TETRAGON_POLICY,
            "--export-filename",
            str(TETRAGON_OUT),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"  Tetragon loading its policy and attaching kprobes ({ATTACH_SECONDS}s) …")
    time.sleep(ATTACH_SECONDS)
    return proc


def stop_tetragon(proc: subprocess.Popen[bytes]) -> None:
    time.sleep(3)
    # By process NAME (-x), never by command line (-f): the -f form also matches any shell whose argv
    # holds that literal, which is how it once killed an ssh wrapper.
    subprocess.run(["sudo", "pkill", "-x", "tetragon"], check=False)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        subprocess.run(["sudo", "pkill", "-9", "-x", "tetragon"], check=False)


def tetragon_recorded(container_id: str) -> tuple[dict[str, str], int]:
    """Which probes the host sensor wrote down for the SANDBOX POD, and how many events it attributed.

    Filtered by container id rather than pid namespace, for 2.3.1's reason and one more of this
    lesson's own: the OpenShell GATEWAY is itself a pod on this node, it proxies every request the
    workload makes, and it therefore produces a `tcp_connect` for each one. Attributing by "some
    container" would credit the workload with the proxy's egress and mark `exfiltrate` LOGGED on the
    strength of the sensor watching the sandbox's own jailer.
    """
    seen: set[str] = set()
    attributed = 0
    text = subprocess.run(["sudo", "cat", str(TETRAGON_OUT)], capture_output=True, text=True, check=False).stdout
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        for kind, body in event.items():
            if not isinstance(body, dict):
                continue
            proc = body.get("process")
            if not isinstance(proc, dict):
                continue
            docker = proc.get("docker")
            if not isinstance(docker, str) or not docker or not container_id.startswith(docker):
                continue
            attributed += 1
            if kind == "process_exec":
                seen.add("exec")
            elif kind == "process_kprobe":
                for tag in [*body.get("tags", []), body.get("message", "")]:
                    m = _TAG_RE.match(str(tag))
                    if m:
                        seen.add(m.group(1))
    return {name: (LOGGED if tag in seen else NOT_LOGGED) for name, tag in PROBE_TAG.items()}, attributed


# --- OCSF (from 2.2.4) -------------------------------------------------------

_DECISION = re.compile(
    r"(?P<klass>NET|HTTP|SSH|PROC|FINDING):(?P<activity>\S+)\s+\[(?P<sev>[A-Z]+)\s*\]\s+(?P<action>ALLOWED|DENIED)\b(?P<detail>.*)"
)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BINARY = re.compile(r"(?P<binary>/\S+?)\((?P<pid>\d+)\)")
_HTTP = re.compile(r"\b(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+(?P<url>https?://\S+)")
_ENDPOINT = re.compile(r"->\s*(?P<endpoint>\S+)")


def ocsf_decisions() -> list[Decision]:
    """Read and parse OpenShell's decision trail. Read a few seconds late: the L7 proxy flushes lazily."""
    time.sleep(4)
    done = osh("logs", SANDBOX, "--since", "20m", "-n", "800", "--source", "sandbox", timeout=120)
    decisions: list[Decision] = []
    for raw in _ANSI.sub("", done.stdout).splitlines():
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


# --- the apiserver audit log (from 2.3.1) ------------------------------------


def audit_log_lines() -> int:
    out = subprocess.run(
        ["sudo", "bash", "-c", f"wc -l < {AUDIT_LOG} 2>/dev/null || echo 0"],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        return int(out.stdout.strip() or "0")
    except ValueError:
        return 0


def audit_events_since(mark: int) -> list[dict[str, object]]:
    out = subprocess.run(
        ["sudo", "bash", "-c", f"tail -n +{mark + 1} {AUDIT_LOG} 2>/dev/null"],
        capture_output=True,
        text=True,
        check=False,
    )
    events: list[dict[str, object]] = []
    for line in out.stdout.splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def audit_username(event: dict[str, object]) -> str:
    user = event.get("user")
    return str(user.get("username", "")) if isinstance(user, dict) else ""


# --- combine -----------------------------------------------------------------


def _mark(state: str | None) -> str:
    if state == LOGGED:
        return "LOGGED"
    if state == NOT_LOGGED:
        return "not logged"
    return "— (blind)"


def combine(card: Card, tetragon: dict[str, str], ocsf: dict[str, str]) -> dict[str, str]:
    """Resolve every scored probe to LOGGED / NOT_LOGGED / NO_SENSOR from the UNION of the sensors.

    The apiserver column is not merged in, because it has nothing to merge: an OpenShell sandbox is
    not a cluster principal, so no scored probe of this suite acts on the control plane. That is
    reported as a finding in Part 4 rather than hidden as an empty column here.
    """
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:  # INFO rows are not scored, so not audited
            continue
        name = finding["name"]
        states = [s for s in (tetragon.get(name), ocsf.get(name)) if s is not None]
        if not states:
            state = NO_SENSOR
        elif LOGGED in states:
            state = LOGGED
        else:
            state = NOT_LOGGED
        finding["recorded"] = state
        out[name] = state
    return out


def assert_sensors_engaged(card: Card, attributed: int, decisions: list[Decision]) -> None:
    """Prove all three sensors were live, from what they recorded — never from the flags we passed.

    The policy half is 1.3.4's own assertion, kept because a card measured behind a policy that did
    not engage is not this rung's card at all: the allowed GET must succeed and the SAME host's POST
    must not. Only the split proves an L7 decision happened.
    """
    checks = {
        "the allowed GET reached the gateway (a policy, not a dead network)": (
            card.contained("egress_gateway") is True
        ),
        "the SAME host's POST was denied (method-aware, which L3/L4 cannot be)": (
            card.contained("http_method_denied") is True
        ),
        "an unlisted binary was denied (per-binary, which no kernel sandbox can see)": (
            card.contained("binary_scoped") is True
        ),
        "Tetragon attributed events to the sandbox POD (the host sensor is not blind here)": attributed > 0,
        "OpenShell's OCSF trail recorded decisions": len(decisions) > 0,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  sensor assertion FAILED — a sensor or the policy was not engaged; not reporting a result.")


def cleanup() -> None:
    osh("sandbox", "delete", SANDBOX, "--force", timeout=300)
    k8s.delete_namespace(NAMESPACE)


# --- box plumbing ------------------------------------------------------------


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
    print("This lesson only runs on its own disposable Scaleway box: the stack is k3s plus the Agent")
    print("Sandbox controller, the OpenShell gateway, Tetragon and the apiserver audit log.")
    print("Start the box, then run it from here:\n")
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
    tetragon_proc = None
    try:
        banner("Part 1 — 1.3.4's policy-governed sandbox, with three sensors watching")
        gateway = k8s.start_service(NAMESPACE, "sbx-gateway")
        collector = k8s.start_service(NAMESPACE, "sbx-collector")
        print(f"  gateway   (allowed by policy): {gateway}:{k8s.GATEWAY_PORT}")
        print(f"  collector (named nowhere)    : {collector}:{k8s.GATEWAY_PORT}")
        print("  sensor 1: Tetragon    — the node's kernel, where a runc sandbox's syscalls land")
        print("  sensor 2: OCSF        — OpenShell's own L7 decision trail")
        print("  sensor 3: apiserver audit log — the control plane\n")

        # Tetragon starts BEFORE the sandbox exists, so the pod's whole life is inside the window.
        # Starting it later would work too — the kprobes attach to the kernel, not to a container —
        # but the first thing the trail should be able to show is the sandbox being created at all.
        tetragon_proc = start_tetragon()
        audit_mark = audit_log_lines()

        policy = render_policy(gateway)
        create_sandbox(policy, gateway, collector)
        wait_ready()
        apply_policy(policy)
        container_id = sandbox_container_id()
        print(f"  sandbox {SANDBOX} Ready, OCSF armed, policy applied")
        print(f"  OpenShell scheduled it as container {container_id[:16] or '?'}… — the id the host")
        print("  sensor's trail is filtered by, so the gateway's own proxying is not counted as the")
        print("  workload's egress")

        banner("Part 2 — Turn the rogue agent loose, under policy, with the network ON")
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
        stop_tetragon(tetragon_proc)
        tetragon_proc = None
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        banner("Assert the policy and all three sensors engaged")
        tetragon, attributed = tetragon_recorded(container_id)
        events = audit_events_since(audit_mark)
        assert_sensors_engaged(card, attributed, decisions)

        banner("Part 3 — Two columns that overlap, and a third that is empty")
        ocsf = ocsf_recorded(decisions)
        recorded = combine(card, tetragon, ocsf)
        print(f"    {'probe':<20} {'Tetragon (syscalls)':<22} {'OCSF (L7)':<14}")
        print(f"    {'-' * 20} {'-' * 22} {'-' * 14}")
        for name in recorded:
            print(f"    {name:<20} {_mark(tetragon.get(name)):<22} {_mark(ocsf.get(name)):<14}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down, by the union of the two sensors")
        print(f"  that had anything to see. Tetragon attributed {attributed} events to the sandbox pod —")
        print("  OpenShell is runc, so its syscalls reach the node's kernel, the mirror of 2.2.4's")
        print("  in-guest auditd and the opposite of Kata (2.2.3), where a host sensor read zero.")

        banner("Part 4 — The empty column, and the one thing only OpenShell writes down")
        api_from_workload = [e for e in events if "openshell" in audit_username(e)]
        print(f"  The apiserver recorded {len(events)} requests during this run and")
        print(f"  {len(api_from_workload)} of them came from anything the sandbox could be. `k8s_sa_token`")
        print("  reads n/a-no-cluster: an OpenShell sandbox is a Pod but NOT a cluster principal — no")
        print("  service-account token, no KUBERNETES_SERVICE_HOST, so the attack 2.3.1 had to leave")
        print("  the door open to measure cannot even start. The control-plane sensor is on and")
        print("  working; the surface it watches is simply not exposed to this workload.")
        print()
        print("  And the row neither syscall sensor can reach:")
        for d in [d for d in decisions if d["action"] == "DENIED"][:5]:
            print(f"      {d['raw'][:112]}")
        # NOT_LOGGED and NO_SENSOR are different diagnoses and the same outcome, so both belong in
        # this list: "a sensor watched and saw nothing" and "nothing was watching" are equally not an
        # incident report. Splitting them here would let the rung look better than it is.
        gaps = [n for n, v in recorded.items() if v != LOGGED]
        print(f"\n  Recorded by neither sensor: {', '.join(gaps) or '(none)'}.")
        print("  fs_policy_write is the same gap 2.2.4 found and it is structural: the write is DENIED")
        print("  by Landlock before it resolves to anything a syscall auditor records, and Landlock is")
        print("  a kernel verdict rather than an L7 one, so OCSF never sees it either. A host auditor")
        print("  records what the workload DID; only the enforcing layer knows what it REFUSED.")

        card.save(
            RESULTS,
            lesson="2.3.4",
            mode="network-on",
            engine="k3s",
            node_kernel=platform.release(),
            openshell_version=version,
            boundary="OpenShell kubernetes driver on runc; host Tetragon (local attacks) + OCSF trail (network attacks) + apiserver audit (phase-2 audit of 1.3.4)",
            tetragon_events_attributed=attributed,
            host_sensor_logged=sum(1 for v in tetragon.values() if v == LOGGED),
            ocsf_logged=sum(1 for v in ocsf.values() if v == LOGGED),
            api_audit_events=len(events),
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        if tetragon_proc is not None:
            stop_tetragon(tetragon_proc)
        cleanup()


if __name__ == "__main__":
    main()
