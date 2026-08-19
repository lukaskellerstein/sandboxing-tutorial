"""Lesson 2.3.2 — auditing the gVisor rung. The host sensor is attached to the wrong kernel.

Audits 1.3.2. Same pod, same suite, same securityContext — and one field changed:
``runtimeClassName: gvisor-trace`` instead of ``gvisor``. That class selects the SAME runsc binary,
configured with ``--strace``, so gVisor writes down every syscall the application makes. Two sensors
watch, and the comparison between them is the lesson:

  * **the sentry's own trace** — gVisor's user-space kernel is the thing that services these
    syscalls, so it is the only place they exist in full. It sees essentially everything.
  * **Tetragon** — the host CO-RE eBPF sensor that recorded 7 attacks on the plain Pod (2.3.1). It is
    still running here, and its column is MEASURED rather than asserted.

**This is the reframe forced by discovery gate G2, which failed as originally specified.** The plan
was to point a host eBPF sensor at gVisor. There is no such path: Falco removed its gVisor event
source in 0.41 (it needs an EOL ~0.36) and Tetragon never had one. That is not a gap in either tool —
it is a property of *where a host sensor sits*. Under gVisor the application's syscalls are serviced
by the sentry in user space; the host kernel never sees the call the application made, so a probe
attached to the host kernel is attached to the wrong kernel.

Read Tetragon's column with that in mind. Whatever it records here is the SENTRY's or the GOFER's
own behaviour on the application's behalf — a host process doing host work — and not the
application's calls. Those are different things wearing similar names, and conflating them is how a
boundary gets credited with an audit trail it does not have.

**Why a second RuntimeClass** rather than turning strace on for the `gvisor` class 1.3.2 uses:
strace costs real time per syscall, and 1.3.2's `syscall_ms` is a number on the ladder. The
boundary and the boundary-with-a-sensor are separate choices, and on this cluster you can see both
in ``kubectl get runtimeclass``.

    cd ../../../../infra && ./up.sh 2.3.2     # provisions chapter-03-audit-k8s
    uv run python -u main.py
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
from pathlib import Path

import k8s
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.3.2"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
NAMESPACE = "sbx-2-3-2"
RESULTS = REPO_ROOT / "results" / "2.3.2.json"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")

#: The traced gVisor class, registered by infra/substrates/chapter-3-audit/72-k8s-gvisor-trace.sh.
#: The SAME runsc binary 1.3.2's `gvisor` class selects — only the runsc config differs.
RUNTIME_CLASS = "gvisor-trace"

#: 1.3.2's pod, byte for byte. Nothing is weakened for the audit: the sentry's trace records the
#: attempt whether or not it lands, so this card is 1.3.2's containment unchanged.
POD_SECURITY = {
    "runAsNonRoot": True,
    "runAsUser": 1000,
    "runAsGroup": 1000,
    "fsGroup": 1000,
    "seccompProfile": {"type": "RuntimeDefault"},
}
CONTAINER_SECURITY = {
    "allowPrivilegeEscalation": False,
    "readOnlyRootFilesystem": True,
    "capabilities": {"drop": ["ALL"]},
}
RESOURCES = {
    "limits": {"memory": "256Mi", "cpu": "1", "ephemeral-storage": "256Mi"},
    "requests": {"memory": "128Mi", "cpu": "100m", "ephemeral-storage": "64Mi"},
}
GROUPS = "reach,abuse,kernel,policy,cost"
POLICY_SETTLE_S = 20

# --- sensor 1: the sentry's own trace ----------------------------------------
#
#: Where substrate 72 told runsc to write. One directory per box, several files per sandbox; only the
#: `*boot*` ones carry the application's syscalls (create/gofer/start are the shim's own bookkeeping).
TRACE_DIR = Path("/var/log/runsc-trace")

# --- sensor 2: Tetragon, measured rather than assumed ------------------------
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

LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def probe_env(gateway_ip: str) -> dict[str, str]:
    env = {
        "PROBE_GROUPS": GROUPS,
        "PROBE_NODE_KERNEL": platform.release(),
        "PROBE_READONLY_PATH": "/tmp/agent-probe-canary",
        "PROBE_GATEWAY_URL": f"http://{gateway_ip}:{k8s.GATEWAY_PORT}",
    }
    if METADATA_URL:
        env["PROBE_METADATA_URL"] = METADATA_URL
    return env


def agent_pod(gateway_ip: str) -> dict[str, object]:
    env = probe_env(gateway_ip)
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "agent-sandbox", "labels": {"app": "agent-sandbox"}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "runtimeClassName": RUNTIME_CLASS,  # <-- the only field that differs from 1.3.1's pod
            "securityContext": POD_SECURITY,
            "containers": [
                {
                    "name": "agent",
                    "image": k8s.IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["/bin/sh", "-c", f"sleep {POLICY_SETTLE_S}; exec /app/entrypoint.sh"],
                    "securityContext": CONTAINER_SECURITY,
                    "resources": RESOURCES,
                    "env": [{"name": k, "value": v} for k, v in env.items()],
                    "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                }
            ],
            "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
        },
    }


def network_policy() -> dict[str, object]:
    """1.3.1's policy, unchanged — deny all egress, allow DNS and the gateway."""
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "agent-sandbox-egress"},
        "spec": {
            "podSelector": {"matchLabels": {"app": "agent-sandbox"}},
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "to": [{"namespaceSelector": {}, "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                    "ports": [{"protocol": "UDP", "port": 53}, {"protocol": "TCP", "port": 53}],
                },
                {
                    "to": [{"podSelector": {"matchLabels": {"app": k8s.GATEWAY_LABEL}}}],
                    "ports": [{"protocol": "TCP", "port": k8s.GATEWAY_PORT}],
                },
            ],
        },
    }


def ensure_image() -> None:
    script = REPO_ROOT / "infra" / "images" / "agent" / "import-k3s.sh"
    subprocess.run(["sudo", "bash", str(script)], check=True, capture_output=True, timeout=900)


# --- the sentry's trace ------------------------------------------------------


def clear_trace() -> None:
    """Empty the trace directory before the run.

    Not tidiness: several sandboxes have run on this node (the gateway pod, check.sh's own probe),
    and a boot log left from one of them would put another workload's syscalls in this lesson's
    trail — which on the sentry rung is exactly the false LOGGED the whole exercise exists to avoid.
    """
    subprocess.run(["sudo", "bash", "-c", f"rm -f {TRACE_DIR}/* 2>/dev/null"], check=False)


def _boot_files() -> list[str]:
    r = subprocess.run(
        ["sudo", "bash", "-c", f"ls {TRACE_DIR}/*boot* 2>/dev/null"], capture_output=True, text=True, check=False
    )
    return r.stdout.split()


def _boot_has(ere: str, files: list[str]) -> bool:
    """Whether any boot-log line matches the ERE. Grepped ON THE BOX with -a: the fork bomb floods
    the strace log to tens of MB of part-binary text, so it is never read into Python."""
    if not files:
        return False
    r = subprocess.run(["sudo", "grep", "-aEl", "--", ere, *files], capture_output=True, text=True, check=False)
    return bool(r.stdout.strip())


def _connect_dests(files: list[str]) -> set[str]:
    """The destinations the app connected to, from the sentry's `connect(...Addr: …)` traces."""
    if not files:
        return set()
    quoted = " ".join(shlex.quote(f) for f in files)
    cmd = rf"grep -aoE ' E connect\(.*Addr: [0-9.]+' {quoted} | grep -oE 'Addr: [0-9.]+' | sed 's/Addr: //' | sort -u"
    r = subprocess.run(["sudo", "bash", "-c", cmd], capture_output=True, text=True, check=False)
    return set(r.stdout.split())


def sentry_recorded() -> tuple[dict[str, str], int]:
    """Map each probe to LOGGED / NOT_LOGGED from the sentry's strace, and count the syscalls seen.

    Everything the application did crossed the sentry, so this is near-total — the point being that
    ONLY the sentry sees it. Identical mapping to 2.2.2, one rung down, so the two are comparable.
    """
    files = _boot_files()
    total = 0
    if files:
        quoted = " ".join(shlex.quote(f) for f in files)
        # awk rather than `paste | bc`: bc is not installed on a minimal Ubuntu cloud image, and the
        # failure would be an empty count that reads as "the sentry recorded nothing".
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

    return {name: state_for(name) for name in PROBE_TAG}, total


# --- Tetragon (attribution by container id, as 2.3.1) ------------------------


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
    """The host sensor's column, plus (events attributed to this sandbox, events attributed to ANY
    container). The second number is the liveness guard: an empty column is only a finding while the
    same trail shows the sensor recording other containers in the same seconds."""
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


# --- combine -----------------------------------------------------------------


def _mark(state: str | None) -> str:
    if state == LOGGED:
        return "LOGGED"
    if state == NOT_LOGGED:
        return "not logged"
    return "— (blind)"


def combine(card: Card, sentry: dict[str, str], tetragon: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:
            continue
        name = finding["name"]
        states = [s for s in (sentry.get(name), tetragon.get(name)) if s is not None]
        if not states:
            state = NO_SENSOR
        elif LOGGED in states:
            state = LOGGED
        else:
            state = NOT_LOGGED
        finding["recorded"] = state
        out[name] = state
    return out


def merge_pod_death(card: Card, reason: str) -> Card:
    """Fill in the row a dead pod could not report — 1.3.1's logic.

    Under gVisor this is not an edge case: the sentry and its per-task stub processes live INSIDE the
    container's cgroup, so a fork bomb that merely earns EAGAIN under runc gets the whole sandbox
    OOM-killed here. The kubelet is then the only witness that the cap engaged.
    """
    if card.complete or card.get("resource_exhaustion") is not None:
        return card
    oom = reason == "OOMKilled"
    print(f"  ! the pod did not survive the suite (terminated: {reason or 'unknown'})")
    return card.add(
        {
            "name": "resource_exhaustion",
            "value": "capped:pod-oomkilled" if oom else f"pod-died:{reason or 'unknown'}",
            "contained": True if oom else None,
            "group": "abuse",
            "detail": "the memory limit killed the pod mid-attack (host-observed, from the kubelet)",
        }
    )


def assert_sensors_engaged(card: Card, sentry_syscalls: int, any_container: int) -> None:
    """Prove gVisor engaged AND that both sensors were live — from readings, never from the manifest.

    The gVisor half is this repo's characteristic failure: a RuntimeClass that was accepted while
    runc ran anyway exits 0 and prints everything the lesson expects. The kernel read from INSIDE the
    sandbox is the only thing that catches it.

    The Tetragon half is the audit-side twin: a host sensor that never attached and a host sensor
    that cannot see through gVisor produce the same empty column, so Tetragon must be shown recording
    OTHER containers on this node during the same window before its silence about this one means
    anything.
    """
    inside = card.get("kernel_identity")
    kernel = str(inside["value"]) if inside else "?"
    checks = {
        f"gVisor engaged — the sandbox reports its OWN kernel ({kernel})": "gvisor" in kernel,
        "the sentry's trace holds the application's syscalls": sentry_syscalls > 0,
        "Tetragon was WATCHING (it recorded other containers on this node meanwhile)": any_container > 0,
        "the boundary is still 1.3.2's (off-policy egress denied)": card.contained("exfiltrate") is True,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  assertion FAILED — the boundary or a sensor did not engage; not reporting a result.")


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
    print("This lesson only runs on its own disposable Scaleway box: it needs k3s with runsc registered")
    print("twice — once plain, once with --strace — and Tetragon on the node.")
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

    ensure_image()
    k8s.ensure_namespace(NAMESPACE)
    tetragon_proc = None
    try:
        banner("Part 1 — 1.3.2's pod, under a gVisor that is writing its syscalls down")
        print(f"  namespace {NAMESPACE}, runtimeClassName: {RUNTIME_CLASS}")
        print("  sensor 1: the SENTRY's own trace — gVisor services these syscalls, so it is the only")
        print("            place they exist in full")
        print("  sensor 2: Tetragon (host eBPF) — running, and reported as measured")
        gateway_ip = k8s.start_gateway(NAMESPACE)
        print(f"  gateway pod at {gateway_ip}:{k8s.GATEWAY_PORT} — the one destination egress will allow")
        k8s.apply(network_policy(), NAMESPACE)
        print("  NetworkPolicy applied: deny all, allow DNS + the gateway\n")

        banner("Part 2 — Turn the rogue agent loose, inside the sandbox")
        clear_trace()
        tetragon_proc = start_tetragon()
        phase, logs, reason, container_id = k8s.run_pod(agent_pod(gateway_ip), NAMESPACE)
        stop_tetragon(tetragon_proc)
        tetragon_proc = None
        print(f"  pod finished in phase {phase} (terminated: {reason or 'n/a'})\n")
        card = merge_pod_death(Card.parse(logs, allow_partial=True), reason)
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        sentry, sentry_syscalls = sentry_recorded()
        tetragon, attributed, any_container = tetragon_recorded(container_id)

        banner("Assert gVisor engaged and both sensors were live")
        assert_sensors_engaged(card, sentry_syscalls, any_container)

        banner("Part 3 — Two sensors, and only one of them is looking at the right kernel")
        recorded = combine(card, sentry, tetragon)
        print(f"    {'probe':<20} {'sentry trace':<16} {'Tetragon (host)':<18}")
        print(f"    {'-' * 20} {'-' * 16} {'-' * 18}")
        for name in recorded:
            print(f"    {name:<20} {_mark(sentry.get(name)):<16} {_mark(tetragon.get(name)):<18}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        s_logged = sum(1 for v in sentry.values() if v == LOGGED)
        t_logged = sum(1 for v in tetragon.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down.")
        print(f"  The sentry recorded {sentry_syscalls} syscalls from this sandbox and matched {s_logged} probes.")
        print(f"  Tetragon matched {t_logged}, from {attributed} events it attributed to the sandbox's")
        print(f"  container — against {any_container} it attributed to other containers on the same node")
        print("  in the same seconds. It was watching. It was watching the host kernel.")
        print()
        cost = card.get("syscall_ms")
        print(
            f"  READ THE COST ROW AS AN INSTRUMENT COST, NOT A BOUNDARY COST: syscall_ms is "
            f"{cost['value'] if cost else '?'} here"
        )
        print("  against 1.3.2's ~209 on the identical boundary. That is `--strace` writing a line per")
        print("  syscall, not gVisor being slow — and it is exactly why the traced class is a SEPARATE")
        print("  RuntimeClass. 1.3.2 measures what gVisor costs; this lesson measures what watching it")
        print("  costs, and putting both on one class would have quietly merged the two numbers.")

        banner("Part 4 — What Tetragon's column actually means")
        print("  Under gVisor the application's syscalls are serviced by the SENTRY, a kernel in user")
        print("  space. The host kernel never sees the call the application made — it sees the calls")
        print("  the sentry and the gofer make on its behalf, which are host processes doing host")
        print("  work. So anything in Tetragon's column here is evidence about gVisor's plumbing, not")
        print("  about the agent, and reading it as an audit trail of the workload would credit this")
        print("  boundary with something it does not have.")
        print()
        print("  There is no host-sensor path to fix this, whichever tool you pick: Falco removed its")
        print("  gVisor event source in 0.41 and Tetragon never had one. That was discovery gate G2,")
        print("  and it failed — which is why this lesson reads gVisor's own trace instead.")
        print()
        print("  Coverage survives the boundary. It survives only because the SENSOR moved with it,")
        print("  from the host kernel to the one actually running the workload. Two rungs on, 2.3.6")
        print("  shows what happens when the sensor cannot follow at all.")

        card.save(
            RESULTS,
            lesson="2.3.2",
            mode="network-on",
            engine="k3s",
            node_kernel=platform.release(),
            runtime_class=RUNTIME_CLASS,
            boundary="gVisor Pod (runtimeClassName: gvisor-trace) + the sentry's own strace; host Tetragon measured alongside (phase-2 audit of 1.3.2)",
            sentry_syscalls=sentry_syscalls,
            sentry_logged=s_logged,
            #: So the cross-lesson view cannot read this rung's syscall_ms as gVisor's cost. It is
            #: strace's: the same boundary measured without tracing is 1.3.2's row.
            cost_note="syscall_ms includes --strace overhead; 1.3.2 is the untraced cost of this boundary",
            host_sensor_logged=t_logged,
            tetragon_events_attributed=attributed,
            tetragon_events_other_containers=any_container,
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        if tetragon_proc is not None:
            stop_tetragon(tetragon_proc)
        k8s.delete_namespace(NAMESPACE)


if __name__ == "__main__":
    main()
