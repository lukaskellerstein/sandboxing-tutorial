"""Lesson 2.3.3 — auditing the Kata rung. The sensor has to move into the guest, and only one kind can.

Audits 1.3.3. The same hardened Pod under `runtimeClassName: kata-qemu`, with the host sensor
watching from the node and a **sidecar riding inside the guest** beside the workload.

2.3.6 already measured the host half of this: behind a per-pod VM, Tetragon attributes **zero** events
to the sandbox. This leaf is where the coverage comes back — and where the plan for getting it back
turns out to be wrong.

**What the syllabus predicted (discovery gate G1).** 2.2.3 found that under *nerdctl* a workload
container cannot stand up a kernel-side sensor inside the Kata guest: `auditctl` returns `EPERM` even
as root with `CAP_AUDIT_CONTROL` and host namespaces, because the audit netlink is
initial-namespace-only. The reframe said the fix was a **Kubernetes** construct — a privileged
sidecar holding *the guest's init context* — and pushed it to this lesson.

**What is actually true, measured on a live cluster.** It does not work, and no amount of privilege
makes it work. A sidecar with `privileged: true`, `runAsUser: 0`, a full `CapEff` of
`000001ffffffffff` **and** `hostPID: true` still gets `EPERM` from the audit netlink. The reason is
that `hostPID` under Kata does not mean what it means on a node: the kubelet's "host" here is the
*sandbox*, and Kata's agent puts the whole pod in a child pid namespace inside the VM. The guest's
real init is not reachable from any container, so the kernel's `task_active_pid_ns(current) !=
&init_pid_ns` gate closes. The lesson probes this live, every run, rather than asserting it.

**What does work** is what worked in 2.2.3, for the same reason: a **ptrace tracer**. It needs no
netlink and no initial namespace — only the ability to trace a process — and Kubernetes supplies
exactly that with `shareProcessNamespace: true`, which puts every container of the pod in ONE pid
namespace inside the guest. That is the thing nerdctl could not offer (one VM per container, nothing
to share), so the Kubernetes construct *does* rescue the rung — just not the construct that was
predicted, and not a kernel-side sensor.

And the guest kernel is not the obstacle: the sidecar also loads a real two-instruction eBPF program
to show that `bpf()` is reachable and BTF is present on the debug kernel. An eBPF sensor could live
here. An *audit* one cannot.

    cd ../../../../infra && ./up.sh 2.3.3     # provisions chapter-03-audit-k8s
    uv run python -u main.py
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import k8s
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.3.3"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
NAMESPACE = "sbx-2-3-3"
RESULTS = REPO_ROOT / "results" / "2.3.3.json"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")

RUNTIME_CLASS = "kata-qemu"
#: NOT `:latest` — Kubernetes defaults a `:latest` tag to `imagePullPolicy: Always`, which sends the
#: kubelet to Docker Hub for an image that is already on the node's disk.
SENSOR_IMAGE = "docker.io/sandboxing-tutorial/guest-sensor:v1"
#: Written by infra/substrates/chapter-3-audit/85-kata-debug-kernel.sh. The DEFAULT Kata guest kernel
#: carries no BTF, so an eBPF sensor could not attach inside it; the debug kernel does, and the
#: annotation is how one pod opts in without changing what 1.3.3 measured.
DEBUG_KERNEL_FILE = Path("/etc/kata-containers-debug-kernel")
KATA_KERNEL_ANNOTATION = "io.katacontainers.config.hypervisor.kernel"
#: The workload's command carries this so the sidecar can find it in the shared pid namespace without
#: guessing at process names — both containers run `sh` and `python`.
MARKER = "SBX_WORKLOAD_2_3_3"

#: 1.3.3's securityContexts, unchanged — nothing about the sandbox is weakened for the audit.
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

# --- sensor 1: Tetragon on the node (expected blind) -------------------------
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

#: Which probes the in-guest tracer can fingerprint. `kernel_identity` has no syscall to hook, and the
#: `policy` rows are L7 decisions no syscall tracer reads — both stay honest NO_SENSOR.
GUEST_PROBES = (
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

LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def debug_kernel() -> str:
    try:
        return DEBUG_KERNEL_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        sys.exit(
            "  /etc/kata-containers-debug-kernel is missing — substrate\n"
            "  chapter-3-audit/85-kata-debug-kernel.sh has not run on this box."
        )


def ensure_images() -> None:
    """The shared agent image for the workload, and the sidecar image for the sensor.

    The sidecar's build context is assembled from `infra/images/agent` so `attacks/` is byte-identical
    to the measured image, then the leaf's `guest-sensor/` files are dropped in. BuildKit cannot use a
    local-only containerd image as a base, so the Dockerfile derives from the registry base instead of
    `FROM sandboxing-tutorial/agent`.
    """
    subprocess.run(
        ["sudo", "bash", str(REPO_ROOT / "infra" / "images" / "agent" / "import-k3s.sh")],
        check=True, capture_output=True, timeout=900,
    )  # fmt: skip
    agent_dir = REPO_ROOT / "infra" / "images" / "agent"
    sensor_dir = Path(__file__).parent / "guest-sensor"
    with tempfile.TemporaryDirectory() as tmp:
        ctx = Path(tmp)
        shutil.copytree(agent_dir, ctx, dirs_exist_ok=True)
        for name in ("sensor.sh", "kernel_probe.py", "Dockerfile"):
            shutil.copy(sensor_dir / name, ctx / name)
        archive = "/tmp/sandboxing-tutorial-guest-sensor.tar"
        subprocess.run(["podman", "build", "-q", "-t", SENSOR_IMAGE, str(ctx)], check=True, capture_output=True)
        # `podman save` REFUSES to write into an existing tar, and ignoring that error re-imports the
        # previous build — so you debug a fix that was never shipped. import-k3s.sh pays for this too.
        subprocess.run(["rm", "-f", archive], check=False)
        subprocess.run(
            ["podman", "save", "--format", "docker-archive", "-o", archive, SENSOR_IMAGE],
            check=True, capture_output=True,
        )  # fmt: skip
        subprocess.run(["sudo", "k3s", "ctr", "images", "import", archive], check=True, capture_output=True)
        subprocess.run(["rm", "-f", archive], check=False)


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


def agent_pod(gateway_ip: str, kernel: str) -> dict[str, object]:
    """1.3.3's pod, plus a sidecar in the same guest and the handshake that lets it attach first."""
    env = probe_env(gateway_ip)
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": "agent-sandbox",
            "labels": {"app": "agent-sandbox"},
            # The one annotation, and it changes only the guest KERNEL — not the boundary. The default
            # guest has no BTF, so without it the lesson could not honestly ask whether an eBPF sensor
            # would run in the guest.
            "annotations": {KATA_KERNEL_ANNOTATION: kernel},
        },
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "runtimeClassName": RUNTIME_CLASS,
            # THE FIELD THAT MAKES THIS RUNG AUDITABLE AT ALL. One pid namespace for every container
            # in the pod, inside the guest — so the sidecar can see and trace the workload. nerdctl
            # (2.2.3) has no equivalent, because there each container is its own VM.
            "shareProcessNamespace": True,
            "securityContext": POD_SECURITY,
            "containers": [
                {
                    "name": "agent",
                    "image": k8s.IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    # Waits for the sidecar's go-ahead, THEN hands over to the image's normal
                    # entrypoint. `exec` so the suite keeps this pid — which is the pid the tracer
                    # attached to — and its exit status is the container's.
                    "command": [
                        "/bin/sh",
                        "-c",
                        f": {MARKER}; sleep {POLICY_SETTLE_S}; "
                        f"i=0; while [ ! -f /coord/go ] && [ $i -lt 180 ]; do sleep 1; i=$((i+1)); done; "
                        f"exec /app/entrypoint.sh",
                    ],
                    "securityContext": CONTAINER_SECURITY,
                    "resources": RESOURCES,
                    "env": [{"name": k, "value": v} for k, v in env.items()],
                    "volumeMounts": [
                        {"name": "tmp", "mountPath": "/tmp"},
                        {"name": "coord", "mountPath": "/coord"},
                    ],
                },
                {
                    "name": "sensor",
                    "image": SENSOR_IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    # Root and privileged, and the lesson's point is that this is STILL not enough for
                    # a kernel-side sensor. It is enough to ptrace, which is the sensor that works.
                    "securityContext": {"privileged": True, "runAsUser": 0, "runAsNonRoot": False},
                    "resources": {"limits": {"memory": "256Mi", "cpu": "1"}},
                    "volumeMounts": [{"name": "coord", "mountPath": "/coord"}],
                },
            ],
            "volumes": [
                {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
                {"name": "coord", "emptyDir": {"sizeLimit": "256Mi"}},
            ],
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


# --- running the pod with both sensors ---------------------------------------


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
    container). The second number is the liveness guard that makes a zero a finding: a probe that
    never attached and one that cannot see through a guest kernel leave the same empty column."""
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


def sensor_logs() -> str:
    return k8s.kubectl("-n", NAMESPACE, "logs", "agent-sandbox", "-c", "sensor", check=False, timeout=120)


def guest_recorded(sensor_out: str) -> tuple[dict[str, str], dict[str, str]]:
    """Parse the sidecar's verdicts. Returns (per-probe states, the kernel-capability facts).

    The sidecar greps its own trace in the guest and emits one `SBX_FP <probe>` line per fingerprint —
    the trace itself never leaves, because the fork bomb floods it to tens of MB of part-binary text.
    """
    found = {line.split()[1] for line in sensor_out.splitlines() if line.startswith("SBX_FP ")}
    facts: dict[str, str] = {}
    for line in sensor_out.splitlines():
        for key in ("SBX_AUDIT_NETLINK", "SBX_BPF_LOAD", "SBX_BTF", "SBX_SENSOR_STATUS", "SBX_TRACE_LINES"):
            if line.startswith(key + " "):
                facts[key] = line.split(" ", 1)[1].strip()
    return {name: (LOGGED if name in found else NOT_LOGGED) for name in GUEST_PROBES}, facts


def _mark(state: str | None) -> str:
    if state == LOGGED:
        return "LOGGED"
    if state == NOT_LOGGED:
        return "not logged"
    return "— (blind)"


def combine(card: Card, host: dict[str, str], guest: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:
            continue
        name = finding["name"]
        states = [s for s in (host.get(name), guest.get(name)) if s is not None]
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
    """Fill in the row a dead pod could not report — 1.3.1's logic, for the same cgroup-v2 reason."""
    if card.complete or card.get("resource_exhaustion") is not None:
        return card
    oom = reason == "OOMKilled"
    print(f"  ! the agent container did not survive the suite (terminated: {reason or 'unknown'})")
    return card.add(
        {
            "name": "resource_exhaustion",
            "value": "capped:pod-oomkilled" if oom else f"pod-died:{reason or 'unknown'}",
            "contained": True if oom else None,
            "group": "abuse",
            "detail": "the memory limit killed the container mid-attack (host-observed, from the kubelet)",
        }
    )


def assert_engaged(card: Card, facts: dict[str, str], attributed: int, any_container: int, node_kernel: str) -> None:
    """Prove the VM is real, the sidecar attached, and the blind sensor was actually watching.

    The Kata half is asserted from INSIDE — a guest kernel that differs from the node's — because a
    RuntimeClass that was accepted while runc ran anyway exits 0 and prints everything this lesson
    expects. The blind-sensor half needs its own guard: Tetragon must be shown recording OTHER
    containers on this node in the same seconds, or "0 events" would be a broken probe rather than a
    boundary.
    """
    inside = card.get("kernel_identity")
    guest_kernel = str(inside["value"]) if inside else "?"
    print(f"    guest kernel {guest_kernel}   node kernel {node_kernel}")
    checks = {
        "Kata engaged — the sandbox reports its OWN kernel, not the node's": (guest_kernel not in ("?", node_kernel)),
        "the debug kernel booted (BTF in-guest, which the default guest has not)": (facts.get("SBX_BTF") == "present"),
        "the in-guest sidecar attached before the workload started": (facts.get("SBX_SENSOR_STATUS") == "done"),
        "Tetragon was WATCHING (it recorded other containers meanwhile)": any_container > 0,
        "the boundary is still 1.3.3's (off-policy egress denied)": card.contained("exfiltrate") is True,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  assertion FAILED — the boundary or a sensor did not engage; not reporting a result.")
    if attributed:
        print(f"    note: Tetragon attributed {attributed} events to the sandbox — expected 0 behind a VM")


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
    print("This lesson only runs on its own disposable Scaleway box: it needs k3s with Kata, the")
    print("BTF debug guest kernel enabled by annotation, and Tetragon on the node.")
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

    node_kernel = platform.release()
    kernel = debug_kernel()
    ensure_images()
    k8s.ensure_namespace(NAMESPACE)
    tetragon_proc = None
    try:
        banner("Part 1 — 1.3.3's Kata pod, with a sensor riding INSIDE the guest")
        print(f"  runtimeClassName: {RUNTIME_CLASS}, guest kernel by annotation:")
        print(f"    {kernel}")
        print("  sensor 1: Tetragon on the NODE — 2.3.6 measured it at 0 events behind this boundary")
        print("  sensor 2: a privileged SIDECAR in the same guest, sharing the pod's pid namespace")
        gateway_ip = k8s.start_gateway(NAMESPACE)
        print(f"  gateway pod at {gateway_ip}:{k8s.GATEWAY_PORT} — the one destination egress will allow")
        k8s.apply(network_policy(), NAMESPACE)
        print("  NetworkPolicy applied: deny all, allow DNS + the gateway\n")

        banner("Part 2 — Turn the rogue agent loose, watched from inside and from outside")
        tetragon_proc = start_tetragon()
        phase, logs, reason, container_id = k8s.run_pod(
            agent_pod(gateway_ip, kernel), NAMESPACE, timeout=1500, container="agent", delete=False
        )
        # Read the sidecar BEFORE the pod goes away — its verdicts exist nowhere else.
        sensor_out = sensor_logs()
        k8s.kubectl(
            "-n",
            NAMESPACE,
            "delete",
            "pod",
            "agent-sandbox",
            "--ignore-not-found",
            "--now",
            "--wait=false",
            check=False,
        )
        stop_tetragon(tetragon_proc)
        tetragon_proc = None
        print(f"  pod finished in phase {phase} (terminated: {reason or 'n/a'})\n")
        card = merge_pod_death(Card.parse(logs, allow_partial=True), reason)
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        host, attributed, any_container = tetragon_recorded(container_id)
        guest, facts = guest_recorded(sensor_out)

        banner("Assert the VM is real and both sensors engaged")
        assert_engaged(card, facts, attributed, any_container, node_kernel)

        banner("Part 3 — The node sees nothing; the sidecar sees almost everything")
        recorded = combine(card, host, guest)
        print(f"    {'probe':<20} {'Tetragon (node)':<18} {'sidecar (in-guest)':<20}")
        print(f"    {'-' * 20} {'-' * 18} {'-' * 20}")
        for name in recorded:
            print(f"    {name:<20} {_mark(host.get(name)):<18} {_mark(guest.get(name)):<20}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down — all of them by the sidecar.")
        print(f"  Tetragon attributed {attributed} events to this sandbox, against {any_container} it")
        print("  attributed to other containers on the same node in the same seconds. The workload was")
        print(f"  on the far side of a guest kernel. The sidecar traced {facts.get('SBX_TRACE_LINES', '?')} syscalls.")

        banner("Part 4 — Why the sensor is a ptrace tracer and not the one the plan called for")
        print(f"  audit netlink, from a privileged sidecar : {facts.get('SBX_AUDIT_NETLINK', '?')}")
        print(f"  eBPF program load, same sidecar          : {facts.get('SBX_BPF_LOAD', '?')}")
        print(f"  BTF in the guest                         : {facts.get('SBX_BTF', '?')}")
        print()
        print("  Read those three lines together. The sidecar is `privileged: true`, `runAsUser: 0`,")
        print("  with a full capability set — and the guest's audit subsystem still refuses it. That is")
        print("  not a missing capability: the kernel gates the audit netlink on the INITIAL pid")
        print("  namespace, and Kata's agent puts the whole pod in a child one. `hostPID: true` does")
        print("  not help, because under Kata the kubelet's 'host' is the sandbox, not the VM's init.")
        print("  2.2.3 hit the same wall under nerdctl and predicted Kubernetes would lift it. It does")
        print("  not — that prediction is corrected here, on the measurement above.")
        print()
        print("  What Kubernetes DOES supply is shareProcessNamespace: one pid namespace for the whole")
        print("  pod inside the guest. A tracer needs nothing more than the ability to trace, so the")
        print("  sidecar attaches to the workload and follows it through exec and every child. nerdctl")
        print("  could never do this — there, one container is one VM, and there is nothing to share.")
        print()
        print("  The eBPF line is the counterweight: the program LOADS, and BTF is present, so this")
        print("  guest kernel would host a real kernel-side sensor. The obstacle was never the kernel's")
        print("  capability — it is that the audit subsystem is namespace-fenced and eBPF is not.")
        print()
        print("  The cost is the part to carry away: this coverage is per-pod. The sensor is not")
        print("  something the platform runs once on the node — it ships in every workload's pod spec,")
        print("  and a pod that forgets the sidecar is as dark as 2.3.6.")

        card.save(
            RESULTS,
            lesson="2.3.3",
            mode="network-on",
            engine="k3s",
            node_kernel=node_kernel,
            runtime_class=RUNTIME_CLASS,
            boundary="hardened Pod under kata-qemu (per-pod VM); host Tetragon (blind) + an in-guest ptrace sidecar (phase-2 audit of 1.3.3)",
            guest_kernel=str((card.get("kernel_identity") or {}).get("value", "")),
            tetragon_events_attributed=attributed,
            tetragon_events_other_containers=any_container,
            host_sensor_logged=sum(1 for v in host.values() if v == LOGGED),
            guest_sensor_logged=sum(1 for v in guest.values() if v == LOGGED),
            guest_audit_netlink=facts.get("SBX_AUDIT_NETLINK", "?"),
            guest_bpf_load=facts.get("SBX_BPF_LOAD", "?"),
            guest_trace_lines=facts.get("SBX_TRACE_LINES", "?"),
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
