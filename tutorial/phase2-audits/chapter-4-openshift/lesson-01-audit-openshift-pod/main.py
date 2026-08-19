"""Lesson 2.4.1 — auditing the OpenShift rung. The platform audits the control plane, not the kernel.

Audits 1.4.1. The same hardened Pod, the same suite mounted from the same ConfigMap, with the two
sensors an OpenShift cluster actually has:

  * **the kube-apiserver audit log** — on by default, no configuration, served straight out of
    `oc adm node-logs --role=master`. This is what the platform gives you.
  * **the node's `auditd`** — RUNNING on RHCOS, and watching nothing that matters. It ships with two
    `exclude` rules and no syscall rules at all, so out of the box it cannot see a workload.

**The finding is the shape of that pair.** Every rung before this one had a sensor you installed
(auditd in 2.1.1, Tetragon in 2.2.1/2.3.1) watching the kernel. A managed, immutable platform inverts
it: the sensor you get for free watches the **control plane**, and the kernel-level one is present but
switched off — and switching it on is exactly the kind of node mutation the platform exists to
prevent. This lesson arms it anyway, with `auditctl` at run time, and says plainly what that costs:
the rules are **ephemeral**, lost on the next reboot, and the supported alternative is a MachineConfig,
which edits the immutable OS.

**Attribution is a third mechanism again, and the platform hands it to you.** 2.2.1 had to infer the
workload from its pid namespace; 2.3.1 used the container id the kubelet supplies. Here every pod gets
its own **SELinux MCS category pair**, and the kernel stamps it into the `subj=` field of every
`type=SYSCALL` record it produces — so an audit event ties to one pod exactly. The obvious key, uid, is
*wrong* here and measurably so: the image's `USER 1001` is shared with node components, so a uid rule
also catches `service-ca-operator`. uid decides what gets recorded; MCS decides whose it was.

The correlation has one subtlety worth knowing, because getting it wrong under-reports silently: an
audit *event* is a `type=SYSCALL` record plus `type=PATH` companions sharing a serial. The pod's MCS is
on the SYSCALL record (`subj=`, the process); the PATH record's `obj=` is the FILE's context, which
carries the pod's MCS only for files in the container's own layer and never for `/proc` or `/sys`.
Matching PATH records by MCS finds the backdoor and misses every `/proc` read — measured at 2/13 where
the truth is higher — so this leaf resolves serials first.

    ../../../infra/openshift-sno/install.sh    # bring the shared cluster up (once, ~2 h)
    ./run.sh
"""

from __future__ import annotations

import sys
from pathlib import Path

import nodeaudit
import openshift as oc
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
RESULTS = REPO_ROOT / "results" / "2.4.1.json"
NS = "sbx-2-4-1"
GROUPS = "reach,abuse,kernel,cost"

#: 1.4.1's pod, unchanged. No `runAsUser` — on OpenShift the project assigns one, and that omission is
#: the whole of 1.4.2.
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

#: probe -> the file path fragment its attack opens, which is what the node's auditd can fingerprint.
#: A `type=PATH` record naming one of these, in an event whose SYSCALL record carries this pod's MCS,
#: IS the attack's trail.
#: Probes with no file to open (the network attacks, `kernel_identity`) are honest NO_SENSOR: a
#: path-based rule cannot see them, and pretending otherwise would invent coverage.
AUDIT_PATHS = {
    "read_credentials": ("id_rsa", "id_ed25519", "credentials", "hosts.yml", ".netrc", ".env"),
    "plant_backdoor": (".bashrc", ".profile", "authorized_keys", "agent-probe"),
    # NOT "site-packages": pip's own files live there, so that fragment marks this LOGGED on any
    # run where pip merely imported itself. Only the typosquat's uniquely-named artefact counts.
    "malicious_package": ("agent_probe_evil",),
    "kallsyms_readable": ("kallsyms",),
    "sys_module_count": ("/sys/module", "/proc/modules"),
}
LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def agent_pod(node_kernel: str) -> dict[str, object]:
    """1.4.1's pod, with one line added that changes no boundary: it prints its own SELinux level.

    The MCS pair is assigned at ADMISSION and does not appear in `.status`, so the only place to read
    it is from inside. Printing it before the suite runs costs nothing and makes the audit mapping
    exact rather than inferred.
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
            "securityContext": POD_SECURITY,
            "containers": [
                {
                    "name": "agent",
                    "image": oc.IMAGE,
                    "command": [
                        "/bin/sh",
                        "-c",
                        'echo "SBX_MCS=$(cat /proc/self/attr/current 2>/dev/null)"; '
                        f"exec python3 -m attacks.run --groups {GROUPS}",
                    ],
                    "securityContext": CONTAINER_SECURITY,
                    "resources": RESOURCES,
                    "env": [{"name": k, "value": v} for k, v in env.items()],
                    "volumeMounts": [
                        {"name": "suite", "mountPath": f"{oc.SUITE_MOUNT}/attacks"},
                        {"name": "tmp", "mountPath": "/tmp"},
                    ],
                }
            ],
            "volumes": [
                {"name": "suite", "configMap": {"name": "attack-suite"}},
                {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}},
            ],
        },
    }


def node_recorded(paths: set[str]) -> dict[str, str]:
    """Resolve each probe from the file paths the node's auditd attributed to this pod."""
    out: dict[str, str] = {}
    for probe, fragments in AUDIT_PATHS.items():
        hit = any(any(f in p for p in paths) for f in fragments)
        out[probe] = LOGGED if hit else NOT_LOGGED
    return out


def combine(card: Card, node: dict[str, str], api: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:
            continue
        name = finding["name"]
        states = [s for s in (node.get(name), api.get(name)) if s is not None]
        state = NO_SENSOR if not states else (LOGGED if LOGGED in states else NOT_LOGGED)
        finding["recorded"] = state
        out[name] = state
    return out


def _mark(state: str | None) -> str:
    if state == LOGGED:
        return "LOGGED"
    if state == NOT_LOGGED:
        return "not logged"
    return "— (blind)"


def main() -> None:
    node_kernel = oc.node_kernel()
    banner("Part 1 — 1.4.1's pod, and the two sensors this platform actually has")
    print(f"  cluster node kernel: {node_kernel}")
    print("\n  What the node's auditd is watching BEFORE we touch it:")
    for line in nodeaudit.default_rules().strip().splitlines():
        print(f"    {line}")
    print("\n  Two exclude rules and nothing else — auditd is RUNNING and cannot see a workload.")
    print("  The kube-apiserver's audit log, by contrast, needs no arming at all.")

    oc.ensure_namespace(NS)
    try:
        oc.apply(oc.suite_configmap(), NS)
        print("\n  Arming the node's auditd (auditctl, at run time — ephemeral, lost on reboot):")
        for line in nodeaudit.arm(NS).strip().splitlines():
            print(f"    {line}")

        banner("Part 2 — Turn the rogue agent loose, with both sensors watching")
        phase, logs, reason = oc.run_pod(agent_pod(node_kernel), NS)
        print(f"  pod finished in phase {phase} (terminated: {reason or 'n/a'})")
        mcs = nodeaudit.mcs_of(logs)
        print(f"  the platform gave this pod SELinux level: {mcs or 'UNKNOWN'}\n")
        card = Card.parse(logs, allow_partial=True)
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        banner("Assert the boundary AND both sensors engaged")
        raw, segments = nodeaudit.trail()
        paths = nodeaudit.paths_seen(raw, mcs)
        events = nodeaudit.apiserver_events()
        lost = nodeaudit.lost_count()
        checks = {
            "the suite actually ran (a ConfigMap-mounted package imported)": len(card.findings) > 3,
            "fresh filesystem (host creds unreachable)": card.contained("read_credentials") is True,
            "no service-account token (automount off engaged)": card.contained("k8s_sa_token") is True,
            "the pod reported an SELinux level (the attribution key exists)": bool(mcs),
            "the node's auditd attributed file opens to THIS pod": len(paths) > 0,
            "the apiserver audit log is readable": len(events) > 0,
            # Without this the whole RECORDED column is a coin flip: a dropped record and a
            # boundary that hid something are indistinguishable in the trail.
            f"the kernel dropped NO audit records (lost={lost})": lost == 0,
        }
        for label, okv in checks.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(checks.values()):
            sys.exit("  assertion FAILED — a boundary or a sensor did not engage; not reporting.")

        banner("Part 3 — What each sensor wrote down")
        node = node_recorded(paths)
        # No scored probe of this suite touches the control plane: 1.4.1's pod has no service-account
        # token, so `k8s_sa_token` is contained and never becomes a request. Reported as such rather
        # than folded in as a silent blank.
        api: dict[str, str] = {}
        recorded = combine(card, node, api)
        print(f"    {'probe':<20} {'node auditd':<14} {'apiserver':<12}")
        print(f"    {'-' * 20} {'-' * 14} {'-' * 12}")
        for name in recorded:
            print(f"    {name:<20} {_mark(node.get(name)):<14} {_mark(api.get(name)):<12}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down.")
        sample = sorted(
            p for p in paths if any(k in p for k in ("id_rsa", "/proc/", "/sys/", "bashrc", "evil", ".env"))
        )[:6]
        if sample:
            print("    sample of what it caught: " + ", ".join(sample))
        print(f"  Read {len(segments)} audit segment(s): {', '.join(segments)} — the node rotates at 8 MB")
        print("  and this suite fills a segment in under a minute, so reading only audit.log is a")
        print("  coin flip (measured: 4/13 then 0/13 on back-to-back runs, with lost=0 both times).")
        print(f"  The node's auditd attributed {len(paths)} distinct file paths to this pod, matched by")
        print(f"  its SELinux MCS ({mcs}) in the subj= field of each type=SYSCALL record.")
        print(f"  The apiserver recorded {len(events)} requests in the same window — none of them the")
        print("  workload's, because 1.4.1's pod has no service-account token to make one with.")

        banner("Part 4 — The inversion this rung is about")
        print("  Every earlier rung had a sensor you INSTALLED, watching the kernel. Here the sensor")
        print("  you get for free watches the CONTROL PLANE, and the kernel-level one ships switched")
        print("  off: two exclude rules, no syscall rules, on a node you are not supposed to mutate.")
        print()
        print("  This lesson armed it with `auditctl` at run time. That is honest about what it costs:")
        print("  the rules are EPHEMERAL — gone at the next reboot — and the supported way to make them")
        print("  stick is a MachineConfig, which edits the immutable OS. A platform that reconciles your")
        print("  node back to a known image also reconciles away your sensor.")
        print()
        print("  Note which key did the attributing. Chapter 2 inferred the workload from its pid")
        print("  namespace; chapter 3 used the kubelet's container id; here the PLATFORM labels every")
        print("  pod with its own SELinux MCS and the kernel stamps it on every record. Three rungs,")
        print("  three different keys — each one forced by what the layer underneath makes available.")
        print("  uid is the trap: the image's USER 1001 is shared with node components, so a uid rule")
        print("  also catches service-ca-operator. It decides what is recorded, never whose it was.")

        card.save(
            RESULTS,
            lesson="2.4.1",
            mode="network-on",
            engine="openshift",
            node_kernel=node_kernel,
            boundary="hardened Pod on OpenShift; node auditd (armed at run time, attributed by SELinux MCS) + kube-apiserver audit log (phase-2 audit of 1.4.1)",
            pod_mcs=mcs,
            node_paths_attributed=len(paths),
            apiserver_events=len(events),
            node_sensor_logged=sum(1 for v in node.values() if v == LOGGED),
            audit_records_lost=lost,
            audit_segments_read=len(segments),
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        nodeaudit.disarm()
        oc.delete_namespace(NS)


if __name__ == "__main__":
    main()
