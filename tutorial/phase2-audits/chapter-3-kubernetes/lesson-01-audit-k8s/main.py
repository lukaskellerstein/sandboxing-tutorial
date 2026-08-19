"""Lesson 2.3.1 — auditing the Kubernetes rung. The same blindness, plus one sensor no tracer can be.

Audits 1.3.1. It runs the SAME suite in the SAME hardened Pod, with **two** sensors watching:

  * **Tetragon** — the host CO-RE eBPF sensor 2.2.1 used, with the same policy and the same
    configuration, deliberately. A reader comparing the container rung to this one has to be able to
    attribute a difference to the BOUNDARY rather than to the instrument.
  * **the apiserver's own audit log** — the sensor a cluster adds and a syscall tracer can never be.

What DID change is how an event is tied to the workload. 2.2.1 had to infer it from the pid
namespace, because rootless podman leaves the container id on the host-side runtime processes rather
than on the workload. Here the id is populated, so this lesson matches each event against the
container id **the cluster says it scheduled** — per-pod, and checkable against the API rather than
inferred. That precision is not a luxury: the stand-in gateway is a second pod alive in this same
namespace for the whole capture window, and "in some pid namespace" would credit this workload with
its traffic. (Tetragon's own ``--enable-k8s-api`` pod enrichment is NOT used and must not be — on a
k3s box it fails to resolve pods and delays every event up to 30 s, which manufactures false NOT
LOGGED verdicts. The measurement is in ``infra/substrates/chapter-3-audit/tetragon.sh``.)

The syscall half is 2.2.1's finding composed rather than changed: a Pod is namespaces and cgroups on
the NODE's kernel, so Tetragon sees straight through it exactly as it saw the plain container. The
cluster arranged the isolation; it did not move the observability.

What the cluster DOES add is a second surface. Untrusted code in a pod can stop being a process and
become an *authenticated principal* — it reads a service-account token and talks to the control
plane. That attack makes no syscall worth hooking: to Tetragon it is an ``openat`` on a path and a
``tcp_connect``, indistinguishable from any other fetch. What it *was* exists only in the apiserver's
record. Two sensors, two columns, disjoint blind spots — the same shape as 2.2.4's auditd+OCSF pair,
one rung up.

**This pod is 1.3.1's with two controls deliberately removed**, and for the reason 2.2.4 plants
canary credentials: a sensor cannot record an attack the boundary stopped from ever being attempted.
1.3.1 sets ``automountServiceAccountToken: false`` and denies egress to the apiserver, so the
control-plane attack never happens and there is nothing for any auditor to see. Here the pod is left
as a cluster ships it by DEFAULT — token mounted, apiserver reachable — which is precisely why 1.3.1
recommends turning both off. Containment therefore reads one lower than 1.3.1's, and this lesson says
so rather than quietly comparing two different pods.

    cd ../../../../infra && ./up.sh 2.3.1     # provisions chapter-03-audit-k8s (k3s + Tetragon + API audit)
    uv run python -u main.py
"""

from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path

import k8s
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.3.1"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
NAMESPACE = "sbx-2-3-1"
RESULTS = REPO_ROOT / "results" / "2.3.1.json"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")

#: 1.3.1's securityContexts, byte for byte. Nothing about the sandbox is weakened — the two changes
#: this lesson makes are to the CREDENTIAL and the egress rule, both named below.
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
#: 1.3.1's number, and the reason is the same: a NetworkPolicy is rules a controller writes when it
#: NOTICES a pod, so a container that opens a socket on its first instruction beats it there.
POLICY_SETTLE_S = 20

# --- sensor 1: Tetragon, the host kernel sensor ------------------------------
#
#: probe -> the `sbx_probe` fingerprint its kprobe tags. Identical to 2.2.1's map, which is the
#: comparison: the SAME sensor with the SAME policy against the SAME suite, one rung up the ladder.
#: `k8s_sa_token` is deliberately absent — it is the control-plane column, sensor 2's alone.
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
#: Tetragon must load its policy and attach every kprobe BEFORE the pod starts, or the first attacks
#: run unwatched and this lesson reports a false NOT_LOGGED. Same figure check.sh waits at provision.
ATTACH_SECONDS = 20
_TAG_RE = re.compile(r"^sbx_probe=(\w+)$")

# --- sensor 2: the apiserver audit log ---------------------------------------
#
#: Written by the k3s apiserver under the policy `infra/substrates/chapter-3-audit/k8s-api-audit.sh`
#: installs. Read with sudo and only the lines this run appended — an append-only log read whole would
#: credit this run with the previous one's events.
AUDIT_LOG = Path("/var/lib/rancher/k3s/server/logs/audit.log")
#: The one field that ties a control-plane request back to a POD rather than to a process: a
#: service-account token authenticates as `system:serviceaccount:<namespace>:<name>`.
SA_USER = f"system:serviceaccount:{NAMESPACE}:default"

LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def probe_env(gateway_ip: str) -> dict[str, str]:
    """1.3.1's environment, unchanged — so the only things that moved are the two named controls."""
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
            # THE FIRST OF THE TWO DELIBERATE CHANGES FROM 1.3.1, and the reason this leaf exists.
            # 1.3.1 sets this false and scores `k8s_sa_token` contained. A boundary that removes the
            # credential is the right answer and it is also the end of the measurement: with nothing
            # to steal there is no control-plane request, so no auditor anywhere can say whether one
            # would have been recorded. Left at the cluster's DEFAULT here, the attack is real.
            "automountServiceAccountToken": True,
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
                    # /tmp is the only writable path, and $HOME deliberately is not one — matching
                    # 1.3.1 so the containment diff is about the credential and nothing else.
                    "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                }
            ],
            "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
        },
    }


def network_policy(api_targets: list[dict[str, object]]) -> dict[str, object]:
    """1.3.1's policy plus ONE clause: the apiserver.

    THE SECOND DELIBERATE CHANGE. 1.3.1's deny-all leaves the control plane unreachable, so even a
    mounted token cannot be used — the attack dies at L3 and, again, there is nothing to audit. The
    clause is added explicitly rather than by dropping the policy, so `exfiltrate` and
    `egress_offpolicy` stay BLOCKED and every other row on this card is still 1.3.1's.
    """
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
                *api_targets,
            ],
        },
    }


def apiserver_egress() -> list[dict[str, object]]:
    """The apiserver, as ipBlocks — read from the cluster, never hardcoded.

    BOTH the Service ClusterIP and the endpoint behind it, on purpose. A pod reaches the API through
    ``KUBERNETES_SERVICE_HOST`` (the ClusterIP), and kube-proxy DNATs that to the node's own
    ``:6443`` on the way out — so which address a CNI's egress rules see depends on where in the
    chain they are evaluated. Naming one and guessing right is how a policy comes to work on one
    cluster and silently deny on the next.
    """
    cluster_ip = k8s.kubectl("get", "svc", "kubernetes", "-n", "default", "-o", "jsonpath={.spec.clusterIP}")
    endpoint = k8s.kubectl(
        "get", "endpoints", "kubernetes", "-n", "default", "-o", "jsonpath={.subsets[0].addresses[0].ip}", check=False
    )
    port = k8s.kubectl(
        "get", "endpoints", "kubernetes", "-n", "default", "-o", "jsonpath={.subsets[0].ports[0].port}", check=False
    )
    rules: list[dict[str, object]] = [
        {"to": [{"ipBlock": {"cidr": f"{cluster_ip}/32"}}], "ports": [{"protocol": "TCP", "port": 443}]}
    ]
    if endpoint and port:
        rules.append(
            {"to": [{"ipBlock": {"cidr": f"{endpoint}/32"}}], "ports": [{"protocol": "TCP", "port": int(port)}]}
        )
    print(f"  apiserver egress allowed: {cluster_ip}:443 and {endpoint or '?'}:{port or '?'}")
    return rules


# --- running the pod with both sensors armed ---------------------------------


def ensure_image() -> None:
    script = REPO_ROOT / "infra" / "images" / "agent" / "import-k3s.sh"
    subprocess.run(["sudo", "bash", str(script)], check=True, capture_output=True, timeout=900)


def audit_log_lines() -> int:
    """How many lines the apiserver's audit log holds right now — the mark this run reads forward from."""
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
    """The audit events this run appended, parsed. Read with sudo — the log is root-owned."""
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


def start_tetragon() -> subprocess.Popen[bytes]:
    """Start our own Tetragon for the capture window.

    The substrate leaves the shipped systemd unit DISABLED precisely so this instance owns the pinned
    BPF maps in /sys/fs/bpf/tetragon — two instances fight over them and the second fails to attach.
    The k8s enrichment flags come from the substrate's `/etc/tetragon/tetragon.conf.d/` drop-ins, so
    this invocation and any future service start pick up identically.
    """
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
    time.sleep(3)  # let it flush the last events
    # Kill by process NAME (-x), never by full command line (-f): `pkill -f 'tetragon --bpf-lib'`
    # also matches any shell whose argv contains that literal, which is how it once killed an ssh
    # wrapper. The probe must be gone before the next lesson on this shared box starts its own.
    subprocess.run(["sudo", "pkill", "-x", "tetragon"], check=False)
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        subprocess.run(["sudo", "pkill", "-9", "-x", "tetragon"], check=False)


def _is_workload(proc: dict[str, object], container_id: str) -> bool:
    """True when this event came from the ATTACK POD, and from nothing else on the node.

    THE ATTRIBUTION IS BY CONTAINER ID, and on this rung that is both possible and necessary.

    Possible, because ``process.docker`` is populated here: Tetragon derives it from the cgroup, and
    the kubelet's cgroups carry it. 2.2.1 could not use it — under ROOTLESS podman that id lands on
    the host-side ``podman``/``crun``/``conmon`` and not on the workload's own process — so that
    lesson had to fall back on the pid namespace.

    Necessary, because the pid namespace is no longer specific enough. The stand-in gateway is a
    second pod, alive in this same namespace for the whole capture window, and every k3s system pod
    is in a pid namespace of its own too. "Not the host" would credit this workload with coredns's
    connects. The container id names ONE pod, and the id is read from the k8s API rather than
    inferred — the cluster is the authority on which container it scheduled.

    Tetragon exports a TRUNCATED id, so the test is a prefix match against the full id kubectl gives.
    """
    docker = proc.get("docker")
    if not isinstance(docker, str) or not docker:
        return False
    return container_id.startswith(docker)


def tetragon_tags_seen(container_id: str) -> tuple[set[str], int]:
    """The `sbx_probe` fingerprints Tetragon recorded for the attack pod, and how many events it saw.

    A `process_kprobe` carries the policy's own `tags` array — a real field, not a substring of a
    rendered message. A `process_exec` carries no tag at all (it is a base event, not a policy hit),
    so an exec inside the attack pod IS the `exec` fingerprint.
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
            if not isinstance(proc, dict) or not _is_workload(proc, container_id):
                continue
            attributed += 1
            if kind == "process_exec":
                seen.add("exec")
            elif kind == "process_kprobe":
                for tag in [*body.get("tags", []), body.get("message", "")]:
                    m = _TAG_RE.match(str(tag))
                    if m:
                        seen.add(m.group(1))
    return seen, attributed


def audit_username(event: dict[str, object]) -> str:
    """The authenticated principal an audit event names, or "" — the field the mapping turns on."""
    user = event.get("user")
    if not isinstance(user, dict):
        return ""
    return str(user.get("username", ""))


def api_recorded(events: list[dict[str, object]]) -> dict[str, str]:
    """The control-plane column: which attacks the apiserver wrote down.

    Exactly one probe in the suite acts on the control plane, and that is the finding rather than a
    thin mapping — the surface is narrow and no other sensor covers it at all.
    """
    from_pod = [e for e in events if audit_username(e) == SA_USER]
    return {"k8s_sa_token": LOGGED if from_pod else NOT_LOGGED}


def combine(card: Card, tetragon: set[str], api: dict[str, str]) -> dict[str, str]:
    """Resolve every scored probe to LOGGED / NOT_LOGGED / NO_SENSOR from the UNION of both sensors."""
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:  # INFO rows are not scored, so not audited
            continue
        name = finding["name"]
        states: list[str] = []
        tag = PROBE_TAG.get(name)
        if tag is not None:
            states.append(LOGGED if tag in tetragon else NOT_LOGGED)
        if name in api:
            states.append(api[name])
        if not states:
            state = NO_SENSOR
        elif LOGGED in states:
            state = LOGGED
        else:
            state = NOT_LOGGED
        finding["recorded"] = state
        out[name] = state
    return out


def _mark(state: str | None) -> str:
    if state == LOGGED:
        return "LOGGED"
    if state == NOT_LOGGED:
        return "not logged"
    return "— (blind)"


def merge_pod_death(card: Card, reason: str) -> Card:
    """Fill in the row a dead pod could not report — 1.3.1's logic, for the same reason.

    Attack 7 allocates against a 256Mi limit. Under cgroup v2 a container's memory cgroup kills as a
    GROUP, so the pod dies rather than the allocation merely being refused, and the row proving the
    cap engaged is the one row the pod never got to print. The kubelet is the only witness.
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


def assert_sensors_engaged(card: Card, tetragon: set[str], api: dict[str, str]) -> None:
    """Prove BOTH sensors were live, from what they recorded — never from the flags we passed.

    The failure this exists to catch is the audit-side twin of this repo's silent fallback: a sensor
    that never attached produces an empty trail, and an empty trail reads exactly like "the boundary
    hid everything". Each check below is a thing that could only be true if the sensor really ran.

    The control-plane half is checked against the ATTACK, not against the log's mere existence: an
    apiserver whose audit policy failed to parse starts the cluster with auditing OFF, and every
    control-plane row would then read `not logged` about a cluster that was never recording.
    """
    checks = {
        "the boundary is still 1.3.1's (off-policy egress denied)": card.contained("exfiltrate") is True,
        "the allowed destination still works (a policy, not a dead network)": (
            card.contained("egress_gateway") is True
        ),
        "Tetragon attached and attributed events to the pod": len(tetragon) > 0,
        "the control-plane attack actually happened (token mounted AND usable)": (
            card.contained("k8s_sa_token") is False
        ),
        "the apiserver recorded it": api.get("k8s_sa_token") == LOGGED,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  sensor assertion FAILED — one of the two sensors was not watching; not reporting a result.")


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
    print("This lesson only runs on its own disposable Scaleway box: the boundary is a Pod on single-node")
    print("k3s, and both sensors (Tetragon's eBPF probe, the apiserver's audit log) live on that node.")
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
        banner("Part 1 — 1.3.1's Pod, with two sensors watching it")
        print(f"  namespace {NAMESPACE}, image {k8s.IMAGE}")
        print("  sensor 1: Tetragon (host CO-RE eBPF, k8s-enriched) — the same sensor 2.2.1 used")
        print("  sensor 2: the apiserver's audit log — the column no syscall tracer has")
        gateway_ip = k8s.start_gateway(NAMESPACE)
        print(f"  gateway pod at {gateway_ip}:{k8s.GATEWAY_PORT} — the one destination egress will allow")
        k8s.apply(network_policy(apiserver_egress()), NAMESPACE)
        print("  NetworkPolicy applied: deny all, allow DNS + the gateway + the apiserver\n")
        print("  Two controls of 1.3.1's are deliberately OFF, and only these two:")
        print("    automountServiceAccountToken: TRUE   (1.3.1 sets it false)")
        print("    the apiserver is reachable            (1.3.1's deny-all leaves it unreachable)")
        print("  Without them the control-plane attack never happens, and an auditor cannot record")
        print("  an attempt that was never made — the same reason 2.2.4 plants canary credentials.")

        banner("Part 2 — Turn the rogue agent loose, with both sensors armed")
        # The gateway pod is started BEFORE the sensor on purpose: it is a python process and it
        # execs, so an exec of its inside the capture window would satisfy the `exec` fingerprint on
        # its own and mark four attacks LOGGED that the workload might never have made. Pod-name
        # enrichment separates them too, but the window should not depend on the enrichment working.
        tetragon_proc = start_tetragon()
        audit_mark = audit_log_lines()
        phase, logs, reason, container_id = k8s.run_pod(agent_pod(gateway_ip), NAMESPACE)
        stop_tetragon(tetragon_proc)
        tetragon_proc = None
        print(f"  pod finished in phase {phase} (terminated: {reason or 'n/a'})")
        print(f"  the cluster scheduled it as container {container_id[:16] or '?'}… — the id every")
        print("  Tetragon event below is matched against, so the trail is THIS pod's and not the gateway's\n")
        card = merge_pod_death(Card.parse(logs, allow_partial=True), reason)
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}  (one lower than 1.3.1: the token is")
        print("  mounted here, so `k8s_sa_token` is reached rather than absent)")

        banner("Part 3 — Was any of it written down? Two sensors, two columns")
        tags, attributed = tetragon_tags_seen(container_id)
        events = audit_events_since(audit_mark)
        api = api_recorded(events)
        recorded = combine(card, tags, api)
        print(f"    {'probe':<20} {'Tetragon (syscalls)':<22} {'apiserver (control plane)':<26}")
        print(f"    {'-' * 20} {'-' * 22} {'-' * 26}")
        for name, _state in recorded.items():
            tag = PROBE_TAG.get(name)
            tcol = _mark(LOGGED if tag and tag in tags else (NOT_LOGGED if tag else None))
            print(f"    {name:<20} {tcol:<22} {_mark(api.get(name)):<26}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down, by the union of the two sensors.")
        print(f"  Tetragon attributed {attributed} events to this pod's container id.")
        from_pod = sum(1 for e in events if audit_username(e) == SA_USER)
        print(f"  The apiserver recorded {len(events)} requests during the window, {from_pod} of them")
        print(f"  authenticated as {SA_USER} — the pod itself.")

        banner("Assert both sensors engaged (from what they recorded, never from the flags)")
        assert_sensors_engaged(card, tags, api)

        banner("Part 4 — What each sensor cannot see")
        print("  Tetragon is 2.2.1's result composed, not changed: a Pod is namespaces and cgroups on")
        print("  the NODE's kernel, so the host sensor sees straight through it exactly as it saw the")
        print("  plain container. Kubernetes arranged the isolation; it did not move the observability.")
        print("  The three kernel probes stay NOT LOGGED for 2.2.1's reason — the RuntimeDefault seccomp")
        print("  profile refuses bpf/io_uring/perf at syscall ENTRY, before any kprobe can fire. The")
        print("  boundary blocked them and left no evidence it had done so.")
        print()
        print("  The apiserver's column is one row wide, and that IS the finding rather than a thin")
        print("  mapping. `k8s_sa_token` never made a syscall worth hooking: to Tetragon it was an")
        print("  openat on a path and a tcp_connect, indistinguishable from any other fetch. That it")
        print("  was an AUTHENTICATED PRINCIPAL talking to the control plane exists in exactly one")
        print("  place. Turn the API audit log off — most clusters ship it off — and the attack that")
        print("  matters most on this rung is the one nothing anywhere writes down.")
        for e in events[:4]:
            print(f"      {audit_username(e) or '?'}  {e.get('verb', '?')}  {str(e.get('requestURI', ''))[:52]}")

        card.save(
            RESULTS,
            lesson="2.3.1",
            mode="network-on",
            engine="k3s",
            node_kernel=platform.release(),
            boundary="hardened Pod + host Tetragon (syscalls) + apiserver audit log (control plane) (phase-2 audit of 1.3.1)",
            tetragon_events_attributed=attributed,
            api_audit_events=len(events),
            host_sensor_logged=sum(1 for n, t in PROBE_TAG.items() if t in tags and n in recorded),
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        if tetragon_proc is not None:
            stop_tetragon(tetragon_proc)
        # The namespace owns every object this lesson made, so one delete is the whole teardown — and
        # it runs even when the lesson fails, because a rogue agent's pod must never outlive it.
        k8s.delete_namespace(NAMESPACE)


if __name__ == "__main__":
    main()
