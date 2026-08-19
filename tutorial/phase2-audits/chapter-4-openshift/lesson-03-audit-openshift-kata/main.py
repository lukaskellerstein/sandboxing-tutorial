"""Lesson 2.4.3 — auditing the Kata rung on OpenShift. The node sensor goes blind, and this platform will not let you fix it.

Audits 1.4.3. It runs **2.4.1's pod with one field added** — `runtimeClassName: kata` — so anything
that moves, moved because the workload is now in a per-pod VM.

What moves is the entire node-sensor column. 2.4.1's `auditd` attributed **hundreds** of file paths to
the pod by its SELinux MCS; here it attributes **none**, because the workload's syscalls cross a guest
kernel and never reach the node's. That is 2.2.3 and 2.3.6's finding on a third platform.

**What is different here is the recovery, and it is a negative result.** 2.3.3 rescued this rung on
k3s with a privileged sidecar in the same pod running a ptrace tracer — `shareProcessNamespace: true`
puts every container of the pod in one namespace inside the guest, and a tracer needs nothing more
than the ability to trace. Every piece of that is blocked on OpenShift, and the lesson measures each
one rather than asserting it:

  * **no tracer in the image.** Chapter 4 cannot build images — RHCOS has no podman and the cluster
    has no `*.apps` route to push to a registry — so it uses a stock UBI image, and `strace` is not
    in it.
  * **no way to install one.** `dnf install strace` fails inside the pod, and it fails twice over:
    on this hardened spec it dies on the read-only root filesystem before it gets anywhere, and in a
    pod without that (measured separately during discovery) it dies with *"This command has to be run
    with superuser privileges"* because SCC assigns a non-root uid. The exact message the run prints
    is whichever refusal comes first.
  * **and the privilege that would fix both is exactly what 1.4.2 showed the cluster refusing.**

So the sidecar is not merely absent here, it is **structurally unavailable**: the same admission
control that makes 2.4.2 the one rung that records its refusals is what stops you deploying the
sensor that would have seen this one. That is not a flaw in the platform. It is the trade, stated
honestly — and it is the sharpest form of the chapter's thesis.

    ../../../infra/openshift-sno/install.sh    # bring the shared cluster up (once, ~2 h)
    ./run.sh
"""

from __future__ import annotations

import sys
from pathlib import Path

import nodeaudit
import openshift as oc
from scorecard import Card, Finding, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
RESULTS = REPO_ROOT / "results" / "2.4.3.json"
NS = "sbx-2-4-3"
GROUPS = "reach,abuse,kernel,cost"
#: kata-deploy on OpenShift registers exactly one class, unlike k3s's twenty-odd. Read, never guessed.
PREFERRED = "kata"

POD_SECURITY = {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}}
CONTAINER_SECURITY = {
    "allowPrivilegeEscalation": False,
    "readOnlyRootFilesystem": True,
    "capabilities": {"drop": ["ALL"]},
}
RESOURCES = {
    "limits": {"memory": "512Mi", "cpu": "1", "ephemeral-storage": "512Mi"},
    "requests": {"memory": "128Mi", "cpu": "100m", "ephemeral-storage": "64Mi"},
}
#: 2.4.1's map, unchanged — the point is that the SAME sensor with the SAME fingerprints finds nothing.
AUDIT_PATHS = {
    "read_credentials": ("id_rsa", "id_ed25519", "credentials", "hosts.yml", ".netrc", ".env"),
    "plant_backdoor": (".bashrc", ".profile", "authorized_keys", "agent-probe"),
    "malicious_package": ("agent_probe_evil",),
    "kallsyms_readable": ("kallsyms",),
    "sys_module_count": ("/sys/module", "/proc/modules"),
}
#: What the sidecar reports about its own ability to be a sensor. Printed by the container itself, so
#: every claim in Part 4 is a measurement from inside this cluster rather than a citation.
SENSOR_PROBE = (
    'echo "SBX_SENSOR uid=$(id -u)"; '
    'echo "SBX_SENSOR caps=$(grep CapEff /proc/self/status | tr -d \\"\\\\t\\" )"; '
    'echo "SBX_SENSOR strace=$(command -v strace || echo ABSENT)"; '
    # NO redirect to a file: this container has `readOnlyRootFilesystem: true` and no writable
    # mount, so `>/tmp/...` fails silently and the field comes back empty — which would leave a
    # load-bearing claim in Part 4 unmeasured. Pipe instead.
    'echo "SBX_SENSOR dnf=$(dnf install -y strace 2>&1 | tail -1 | cut -c1-70)"; '
    'echo "SBX_SENSOR workload_visible=$(grep -l SBX_AGENT_MARK /proc/[0-9]*/cmdline 2>/dev/null | head -1 | cut -d/ -f3)"; '
    "sleep 300"
)
LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def runtime_class() -> str:
    classes = oc.oc("get", "runtimeclass", "-o", "jsonpath={.items[*].metadata.name}", check=False).split()
    if PREFERRED in classes:
        return PREFERRED
    kata = [c for c in classes if c.startswith("kata")]
    if not kata:
        sys.exit("  no kata* RuntimeClass — the sandboxed-containers operator and KataConfig must be installed.")
    return kata[0]


def agent_pod(node_kernel: str, rtclass: str) -> dict[str, object]:
    """2.4.1's pod plus `runtimeClassName`, and a sidecar that reports whether it could ever be a sensor.

    `shareProcessNamespace` is on for the same reason 2.3.3 sets it: it is what would let a sidecar
    see the workload at all inside the guest. Here it is switched on and the sidecar STILL cannot be a
    sensor — which is the point, and is measured rather than argued.
    """
    env = {
        "PROBE_GROUPS": GROUPS,
        "PROBE_NODE_KERNEL": node_kernel,
        "PROBE_READONLY_PATH": "/tmp/agent-probe-canary",
        "PYTHONPATH": oc.SUITE_MOUNT,
        "HOME": "/tmp",
    }
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "agent-sandbox", "labels": {"app": "agent-sandbox"}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "runtimeClassName": rtclass,
            "shareProcessNamespace": True,
            "securityContext": POD_SECURITY,
            "containers": [
                {
                    "name": "agent",
                    "image": oc.IMAGE,
                    "command": [
                        "/bin/sh",
                        "-c",
                        ': SBX_AGENT_MARK; echo "SBX_MCS=$(cat /proc/self/attr/current 2>/dev/null)"; '
                        'echo "SBX_DMI=$(cat /sys/class/dmi/id/product_name 2>/dev/null)"; '
                        f"exec python3 -m attacks.run --groups {GROUPS}",
                    ],
                    "securityContext": CONTAINER_SECURITY,
                    "resources": RESOURCES,
                    "env": [{"name": k, "value": v} for k, v in env.items()],
                    "volumeMounts": [
                        {"name": "suite", "mountPath": f"{oc.SUITE_MOUNT}/attacks"},
                        {"name": "tmp", "mountPath": "/tmp"},
                    ],
                },
                {
                    "name": "sensor",
                    "image": oc.IMAGE,
                    "command": ["/bin/sh", "-c", SENSOR_PROBE],
                    "securityContext": CONTAINER_SECURITY,
                    "resources": {"limits": {"memory": "256Mi", "cpu": "500m"}},
                },
            ],
            "volumes": [
                {"name": "suite", "configMap": {"name": "attack-suite"}},
                {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
            ],
        },
    }


def node_recorded(paths: set[str]) -> dict[str, str]:
    return {
        probe: (LOGGED if any(any(f in p for p in paths) for f in frags) else NOT_LOGGED)
        for probe, frags in AUDIT_PATHS.items()
    }


def sensor_facts(logs: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in logs.splitlines():
        if line.startswith("SBX_SENSOR "):
            k, _, v = line[len("SBX_SENSOR ") :].partition("=")
            out[k.strip()] = v.strip()
    return out


def _mark(state: str | None) -> str:
    return "LOGGED" if state == LOGGED else ("not logged" if state == NOT_LOGGED else "— (blind)")


def main() -> None:
    node_kernel = oc.node_kernel()
    rtclass = runtime_class()
    banner("Part 1 — 2.4.1's pod with ONE field added")
    print(f"  runtimeClassName: {rtclass}    (node kernel: {node_kernel})")
    print("  Everything else — the securityContext, the limits, the ConfigMap-mounted suite, the")
    print("  auditd rules — is 2.4.1's. So whatever moves, moved because of the VM.")

    oc.ensure_namespace(NS)
    try:
        oc.apply(oc.suite_configmap(), NS)
        print("\n  Arming the node's auditd exactly as 2.4.1 does:")
        for line in nodeaudit.arm(NS).strip().splitlines():
            print(f"    {line}")

        banner("Part 2 — Turn the rogue agent loose, inside the VM")
        phase, logs, reason = oc.run_pod(agent_pod(node_kernel, rtclass), NS, container="agent", delete=False)
        sensor_logs = oc.oc("-n", NS, "logs", "agent-sandbox", "-c", "sensor", check=False)
        oc.oc("-n", NS, "delete", "pod", "agent-sandbox", "--ignore-not-found", "--now", "--wait=false", check=False)
        mcs = nodeaudit.mcs_of(logs)
        dmi = next((ln.split("=", 1)[1] for ln in logs.splitlines() if ln.startswith("SBX_DMI=")), "")
        print(f"  pod finished in phase {phase} (terminated: {reason or 'n/a'})")
        print(f"  DMI product inside the sandbox: {dmi or '?'}   SELinux level: {mcs or '?'}\n")
        card = Card.parse(logs, allow_partial=True)
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        raw, segments = nodeaudit.trail()
        paths = nodeaudit.paths_seen(raw, mcs)
        lost = nodeaudit.lost_count()
        facts = sensor_facts(sensor_logs)
        keyed = nodeaudit.keyed_records(raw)

        banner("Assert the VM is real, and that the sensor was genuinely watching")
        checks = {
            "the suite ran (a ConfigMap-mounted package imported)": len(card.findings) > 3,
            f"a VM booted — DMI reports a hypervisor, not metal ({dmi})": dmi.upper() == "KVM",
            # NOT "the pod has an MCS": under Kata it has none, and that is this rung's first
            # finding rather than a broken run — see Part 3.
            "the node's auditd was ARMED and lost nothing": lost == 0,
            "auditd was RECORDING in this window (the zero below is the boundary, not a dead sensor)": (keyed > 0),
            "the sidecar started and could report on itself": bool(facts),
        }
        for label, okv in checks.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(checks.values()):
            sys.exit("  assertion FAILED — the VM or the sensor did not engage; not reporting.")

        banner("Part 3 — The same sensor, the same fingerprints, and nothing to show")
        node = node_recorded(paths)
        recorded: dict[str, str] = {}
        for finding in card.findings:
            if finding["contained"] is None:
                continue
            state = node.get(finding["name"], NO_SENSOR)
            finding["recorded"] = state
            recorded[finding["name"]] = state
        if not mcs:
            print("  The pod has NO SELinux MCS the node can see, and that is the first half of the")
            print("  finding. 2.4.1's attribution key is assigned by the node's SELinux policy to a")
            print("  process on the node's kernel. This workload runs on a GUEST kernel, so there is")
            print("  no node-side label to attribute anything by — the sensor could not name it even")
            print("  if it could see it.\n")
        print(f"    {'probe':<20} {'node auditd':<14}")
        print(f"    {'-' * 20} {'-' * 14}")
        for name in recorded:
            print(f"    {name:<20} {_mark(node.get(name)):<14}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down.")
        print(f"  The node's auditd attributed {len(paths)} file paths to this pod (2.4.1, same sensor,")
        print(f"  same rules, no VM: 739). It recorded {keyed} keyed records overall in the same")
        print(f"  window, so it was demonstrably running. Read across {len(segments)} segment(s), lost={lost}.")
        print("  The workload's syscalls crossed a guest kernel; the node's never saw them.")

        banner("Part 4 — Why you cannot do here what 2.3.3 did on k3s")
        print("  On k3s, this rung is rescued by a sidecar in the same pod: shareProcessNamespace puts")
        print("  every container in one namespace INSIDE the guest, and a ptrace tracer needs nothing")
        print("  more than the ability to trace. This pod has that field set. Here is what the sidecar")
        print("  reported about itself, from inside this cluster:\n")
        for key in ("uid", "caps", "strace", "dnf", "workload_visible"):
            print(f"    {key:<17} {facts.get(key, '(not reported)')}")
        print()
        print("  It CAN see the workload — the namespace is shared, exactly as on k3s. What it cannot")
        print("  do is be a sensor: there is no tracer in the image, and it cannot install one — the")
        print("  dnf line above is that refusal, hitting the read-only rootfs first and the non-root")
        print("  uid behind it. Chapter 4 uses a stock UBI image because RHCOS has no podman to build")
        print("  with and this cluster has no *.apps route to push a registry through, so 'just bake")
        print("  strace in' is not available either.")
        print()
        print("  And the privilege that would lift both restrictions is precisely what 1.4.2 showed")
        print("  the cluster refusing. So the sidecar is not missing here, it is STRUCTURALLY")
        print("  unavailable: the same admission control that makes 2.4.2 the one rung which records")
        print("  its own refusals is what stops you deploying the sensor that would have seen this one.")
        print()
        print("  That is the trade this chapter exists to state. A managed platform gives you a strong")
        print("  boundary and a control-plane audit trail for free, and takes away the freedom to put")
        print("  your own sensor where the workload went.")

        card.add(
            Finding(
                name="in_guest_sensor_available",
                value="no" if facts.get("strace", "ABSENT") == "ABSENT" else "yes",
                contained=None,
                group="evidence",
                detail=f"strace={facts.get('strace', '?')}, dnf={facts.get('dnf', '?')[:40]}, "
                f"workload visible to the sidecar={'yes' if facts.get('workload_visible') else 'no'}",
            )
        )
        card.save(
            RESULTS,
            lesson="2.4.3",
            mode="network-on",
            engine="openshift",
            node_kernel=node_kernel,
            runtime_class=rtclass,
            boundary=f"Pod under runtimeClassName: {rtclass} (per-pod KVM VM); node auditd blind, in-guest sidecar unavailable (phase-2 audit of 1.4.3)",
            pod_mcs=mcs,
            guest_dmi=dmi,
            node_paths_attributed=len(paths),
            node_sensor_logged=logged,
            audit_records_lost=lost,
            audit_segments_read=len(segments),
            audit_keyed_records_total=keyed,
            sidecar_strace=facts.get("strace", "?"),
            sidecar_dnf=facts.get("dnf", "?")[:80],
            sidecar_sees_workload=bool(facts.get("workload_visible")),
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        nodeaudit.disarm()
        oc.delete_namespace(NS)


if __name__ == "__main__":
    main()
