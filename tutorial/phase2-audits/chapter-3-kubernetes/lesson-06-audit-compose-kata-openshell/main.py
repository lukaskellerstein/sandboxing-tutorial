"""Lesson 2.3.6 — auditing OpenShell over Kata. One sensor survives every rung, and it only sees the network.

Audits 1.3.6, and it is **2.3.4 with one field changed**: `runtimeClassName: kata-qemu`, selected
through OpenShell's driver-config overlay exactly as 1.3.6 selects it. Same policy file, same suite,
same two sensors, same cluster, minutes apart — so anything that moves, moved because of Kata.

What moves is the whole host-sensor column. Tetragon watched the runc sandbox in 2.3.4 and recorded 7
attacks; here it records **none of them**, because under Kata the workload's syscalls cross a guest
kernel inside a VM and never reach the node kernel Tetragon's probe is attached to. That is 2.2.3's
finding, composed onto the cluster: a stronger isolation boundary hides more.

What does **not** move is OCSF. OpenShell's decision trail is written by an **L7 proxy in the
gateway**, not by a syscall sensor — it sits on the network path, which the guest boundary does not
cut. So it records exactly what it recorded in 2.3.4. That makes it the one sensor that survives
every rung of this ladder, and the price of surviving is written on its face: it sees **network
attacks only**. Everything local — the credentials read, the backdoor written, the kernel probed —
is dark at this rung to every sensor available on the host.

Recovering that column needs a sensor INSIDE the guest, which is a privileged pod with the guest's
init context (the sidecar 2.2.3's G1 reframe pushes into 2.3.3). This leaf names that as its disjoint
blind spot rather than standing the sidecar up a second time.

**On the suite this runs.** 1.3.6 runs only `kernel,policy` — enough to show Landlock surviving the
guest boundary, which is its whole claim. This leaf runs the FULL suite, because the audit question
needs attacks the two sensors can disagree about: with only `kernel,policy` there would be no network
attack for OCSF to catch and the collapse of the host column would have nothing to be measured
against. The comparison that carries this lesson is therefore **2.3.4 → 2.3.6**, one field apart.

    cd ../../../../infra && ./up.sh 2.3.6     # provisions chapter-03-audit-k8s
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

Decision = dict[str, str]

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.3.6"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
NAMESPACE = "sbx-2-3-6"
RESULTS = REPO_ROOT / "results" / "2.3.6.json"
POLICY_SRC = Path(__file__).parent / "policy.yaml"
POLICY_OUT = Path("/tmp/lesson-2-3-6-policy.yaml")

#: The lower runtime this lesson stacks OpenShell onto — the ONE field that differs from 2.3.4.
RUNTIME_CLASS = "kata-qemu"
DRIVER_CONFIG = {"kubernetes": {"pod": {"runtime_class_name": RUNTIME_CLASS}}}
#: OpenShell's kubernetes driver places each sandbox pod in the gateway's namespace (substrate 90).
GW_NS = "openshell"
#: OpenShell caps sandbox names at 19 characters. Counted, not estimated.
SANDBOX = "sbx-236-kata-osh"
GROUPS = "reach,abuse,kernel,policy,cost"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")

# --- sensor 1: Tetragon (expected blind) -------------------------------------
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

# --- sensor 2: OCSF (expected unchanged from 2.3.4) --------------------------
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
    """2.3.4's create, plus `--driver-config-json`. That flag IS the composition."""
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


def wait_ready(timeout_s: int = 420) -> None:
    """Longer than 2.3.4's wait, and not padding: a Kata sandbox has a VM to boot before the
    supervisor accepts work, and an exec issued into that window HANGS rather than failing."""
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


def sandbox_pod() -> tuple[str, str]:
    """The sandbox pod's NAME and container id — discovered, because OpenShell owns the pod."""
    out = k8s.kubectl(
        "-n", GW_NS, "get", "pods",
        "-o", "jsonpath={range .items[*]}{.metadata.name}{'\\t'}{.status.containerStatuses[0].containerID}{'\\n'}{end}",
        check=False,
    )  # fmt: skip
    for line in out.splitlines():
        name, _, cid = line.partition("\t")
        if SANDBOX in name:
            return name, cid.split("://")[-1]
    return "", ""


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


# --- Tetragon ----------------------------------------------------------------


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
    subprocess.run(["sudo", "pkill", "-x", "tetragon"], check=False)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        subprocess.run(["sudo", "pkill", "-9", "-x", "tetragon"], check=False)


def tetragon_recorded(container_id: str) -> tuple[dict[str, str], int, int]:
    """The host sensor's column, plus the two numbers that keep a zero honest.

    Returns ``(per-probe verdicts, events attributed to the SANDBOX, events attributed to ANY
    container on the node)``. The second number is what separates the two readings that look
    identical in a trail: "Kata hid the workload" and "the sensor never attached". A zero for the
    sandbox is only a finding while the same trail shows the sensor recording other containers on the
    same node in the same seconds — which is what the assertion below demands.
    """
    seen: set[str] = set()
    attributed = 0
    any_container = 0
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
            if not isinstance(docker, str) or not docker:
                continue
            any_container += 1
            if not container_id or not container_id.startswith(docker):
                continue
            attributed += 1
            if kind == "process_exec":
                seen.add("exec")
            elif kind == "process_kprobe":
                for tag in [*body.get("tags", []), body.get("message", "")]:
                    m = _TAG_RE.match(str(tag))
                    if m:
                        seen.add(m.group(1))
    return {name: (LOGGED if tag in seen else NOT_LOGGED) for name, tag in PROBE_TAG.items()}, attributed, any_container


# --- OCSF --------------------------------------------------------------------

_DECISION = re.compile(
    r"(?P<klass>NET|HTTP|SSH|PROC|FINDING):(?P<activity>\S+)\s+\[(?P<sev>[A-Z]+)\s*\]\s+(?P<action>ALLOWED|DENIED)\b(?P<detail>.*)"
)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BINARY = re.compile(r"(?P<binary>/\S+?)\((?P<pid>\d+)\)")
_HTTP = re.compile(r"\b(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+(?P<url>https?://\S+)")
_ENDPOINT = re.compile(r"->\s*(?P<endpoint>\S+)")


def ocsf_decisions() -> list[Decision]:
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


# --- combine and assert ------------------------------------------------------


def _mark(state: str | None) -> str:
    if state == LOGGED:
        return "LOGGED"
    if state == NOT_LOGGED:
        return "not logged"
    return "— (blind)"


def combine(card: Card, tetragon: dict[str, str], ocsf: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:
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


def assert_kata_engaged(card: Card, pod: str, node_kernel: str) -> None:
    """Prove the VM is real, from the pod spec AND from inside — never from the flag we passed.

    Both halves are needed. `runtimeClassName` proves the driver-config overlay landed; the kernel
    read from INSIDE proves the shim did not silently fall back to runc, which is this repo's
    characteristic failure and which exits 0 printing everything the lesson expects. On k3s the guest
    kernel differs from the node's, so the string comparison settles it (chapter 4's OpenShift rung
    cannot use it — Red Hat builds the guest kernel from the same base — and reads DMI instead).
    """
    rtclass = k8s.kubectl("-n", GW_NS, "get", "pod", pod, "-o", "jsonpath={.spec.runtimeClassName}", check=False)
    inside = card.get("kernel_identity")
    guest_kernel = str(inside["value"]) if inside else "?"
    print(f"    pod .spec.runtimeClassName: {rtclass or '(none)'}   (expected: {RUNTIME_CLASS})")
    print(f"    kernel inside the sandbox : {guest_kernel}   node: {node_kernel}")
    if rtclass != RUNTIME_CLASS or guest_kernel == node_kernel or guest_kernel == "?":
        sys.exit(
            "  the sandbox is NOT in a Kata VM — the overlay did not land or the shim fell back to\n"
            "  runc. Every reading below would be 2.3.4's wearing this lesson's name; not reporting."
        )
    print("    [OK] a real guest kernel answered — the workload's syscalls do not reach the node's")


def assert_sensors_engaged(card: Card, any_container: int, decisions: list[Decision]) -> None:
    """Prove both sensors were LIVE — which for the blind one is the whole difficulty.

    A host sensor that recorded nothing and a host sensor that was never running produce the same
    empty column, and reporting the first when it was the second would invent this lesson's headline.
    So Tetragon is required to have attributed events to SOME container on this node during the
    window (the gateway pod, the coredns pod, the collector) — it was watching, and the sandbox is
    simply not among the things it can see.
    """
    checks = {
        "the allowed GET reached the gateway (a policy, not a dead network)": (
            card.contained("egress_gateway") is True
        ),
        "the SAME host's POST was denied (the L7 policy is live behind the VM)": (
            card.contained("http_method_denied") is True
        ),
        "Tetragon was WATCHING (it recorded other containers on this node meanwhile)": any_container > 0,
        "OpenShell's OCSF trail recorded decisions": len(decisions) > 0,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  sensor assertion FAILED — a sensor or the policy was not engaged; not reporting a result.")


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
    print("This lesson only runs on its own disposable Scaleway box: it needs k3s with Kata installed,")
    print("the OpenShell gateway, and Tetragon on the node. Start the box, then run it from here:\n")
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
    node_kernel = platform.release()
    subprocess.run(
        ["sudo", "bash", str(REPO_ROOT / "infra" / "images" / "agent" / "import-k3s.sh")],
        check=True, capture_output=True, timeout=900,
    )  # fmt: skip
    k8s.ensure_namespace(NAMESPACE)
    tetragon_proc = None
    try:
        banner("Part 1 — 2.3.4's sandbox, one field different: runtimeClassName: kata-qemu")
        gateway = k8s.start_service(NAMESPACE, "sbx-gateway")
        collector = k8s.start_service(NAMESPACE, "sbx-collector")
        print(f"  gateway   (allowed by policy): {gateway}:{k8s.GATEWAY_PORT}")
        print(f"  collector (named nowhere)    : {collector}:{k8s.GATEWAY_PORT}")
        print(f"  driver-config overlay: {json.dumps(DRIVER_CONFIG)}")
        print("  Same policy file, same suite, same sensors as 2.3.4. Only the runtime moved.\n")

        tetragon_proc = start_tetragon()
        policy = render_policy(gateway)
        create_sandbox(policy, gateway, collector)
        wait_ready()
        apply_policy(policy)
        pod, container_id = sandbox_pod()
        print(f"  sandbox {SANDBOX} Ready as pod {pod or '?'}, OCSF armed, policy applied")

        banner("Part 2 — Turn the rogue agent loose, inside the VM")
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

        banner("Assert Kata engaged (from the pod spec AND from inside the sandbox)")
        assert_kata_engaged(card, pod, node_kernel)

        tetragon, attributed, any_container = tetragon_recorded(container_id)
        banner("Assert both sensors engaged — including the one that is about to report nothing")
        assert_sensors_engaged(card, any_container, decisions)

        banner("Part 3 — The host sensor's column collapses; the L7 trail does not move")
        ocsf = ocsf_recorded(decisions)
        recorded = combine(card, tetragon, ocsf)
        print(f"    {'probe':<20} {'Tetragon (syscalls)':<22} {'OCSF (L7)':<14}")
        print(f"    {'-' * 20} {'-' * 22} {'-' * 14}")
        for name in recorded:
            print(f"    {name:<20} {_mark(tetragon.get(name)):<22} {_mark(ocsf.get(name)):<14}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down — all of them by OCSF.")
        print(f"  Tetragon attributed {attributed} events to this sandbox, against {any_container} it")
        print("  attributed to other containers on the same node in the same seconds. The sensor was")
        print("  watching; the workload was on the far side of a guest kernel. In 2.3.4, one field ago,")
        print("  the same sensor recorded 7 of these attacks.")

        banner("Part 4 — What survives, what it costs, and what is now dark")
        print("  OCSF survives because it is not a syscall sensor. It is an L7 proxy in the GATEWAY,")
        print("  on the network path — and a VM boundary does not cut the network path. That makes it")
        print("  the one sensor that has seen every rung of this ladder: runc (2.2.4, 2.3.4), gVisor")
        print("  (2.3.5's stack), and now a guest kernel. The price is printed in its column: it sees")
        print("  network attacks and nothing else.")
        print()
        dark = [n for n, v in recorded.items() if v != LOGGED]
        print(f"  Dark to every sensor on this host: {', '.join(dark) or '(none)'}.")
        print("  Those are the local attacks — the credentials read, the backdoor written, the kernel")
        print("  probed. Nothing on the NODE can see them, and that is not a configuration mistake to")
        print("  fix: it is what a per-pod VM is for. Recovering the column needs a sensor inside the")
        print("  guest, which under Kubernetes means a privileged pod holding the guest's init context")
        print("  — the sidecar 2.2.3 could not stand up under nerdctl and 2.3.3 exists to build.")
        print()
        print("  The composition finding, stated as a rule: a boundary strong enough to hide the")
        print("  workload from the host hides it from the host's AUDITOR too, so every layer you add")
        print("  below the policy engine has to be paid for with a sensor above or inside it.")

        card.save(
            RESULTS,
            lesson="2.3.6",
            mode="compose-kata",
            engine="k3s",
            node_kernel=node_kernel,
            openshell_version=version,
            runtime_class=RUNTIME_CLASS,
            boundary="OpenShell kubernetes driver stacked on Kata (runtimeClassName: kata-qemu); host Tetragon (blind) + OCSF trail (phase-2 audit of 1.3.6)",
            tetragon_events_attributed=attributed,
            tetragon_events_other_containers=any_container,
            host_sensor_logged=sum(1 for v in tetragon.values() if v == LOGGED),
            ocsf_logged=sum(1 for v in ocsf.values() if v == LOGGED),
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
