"""Lesson 7 — the kernel boundary, as one field.

The shortest lesson in the tutorial, deliberately. Lesson 3 installed `runsc` and passed
``--runtime runsc`` by hand. Here the identical boundary is:

    runtimeClassName: gvisor

That is the whole change. Everything else — the securityContext, the limits, the NetworkPolicy, the
image, the attack suite — is byte-identical to lesson 6, which is what makes Part 3 a measurement of
the runtime rather than of two different pods.

What collapses is attack 8. ``/sys/module`` empties, ``bpf()`` and ``io_uring_setup`` answer
``ENOSYS``, and the kernel identifies as gVisor's own rather than the node's. What does **not** move
is every network row: gVisor's boundary is the syscall interface, and it has never had an opinion
about HTTP. It cannot tell you which binary opened a connection or which method it used, and it
still writes nothing down. That is lesson 9's territory, and lesson 7 leaves it untouched on purpose.

The boundary lives in single-node k3s on this box, with `runsc` registered as a containerd runtime by
``infra/substrates/70-k8s-gvisor.sh``. gVisor's default **systrap** platform uses ``seccomp-bpf`` and
needs no KVM — the widespread claim that gVisor requires hardware virtualisation is simply wrong.

    cd tutorial/lesson-07-k8s-gvisor && uv sync && uv run python -u main.py
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

import k8s
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[2]
NAMESPACE = "sbx-lesson-07"
RESULTS = REPO_ROOT / "results" / "lesson-07.json"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")

#: The one field this lesson is about. `70-k8s-gvisor.sh` created the RuntimeClass with this name.
RUNTIME_CLASS = "gvisor"
#: A name nothing registered, used to show what a missing RuntimeClass actually looks like.
MISSING_CLASS = "gvisor-not-installed"

# Identical to lesson 6, on purpose — see the module docstring. The duplication across leaves is the
# repo's convention: a learner reads one directory top to bottom without chasing a shared package.
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
#: See lesson 6 — a NetworkPolicy is written by a controller reacting to the pod's creation, so it is
#: not yet in force during the pod's first seconds.
POLICY_SETTLE_S = 20


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def probe_env(gateway_ip: str) -> dict[str, str]:
    env = {
        "PROBE_GROUPS": GROUPS,
        "PROBE_NODE_KERNEL": platform.release(),
        # Writable on purpose: this row must report "is there a path policy", not "is the rootfs
        # read-only". Lesson 14's Landlock experiment depends on it meaning that.
        "PROBE_READONLY_PATH": "/tmp/agent-probe-canary",
        "PROBE_GATEWAY_URL": f"http://{gateway_ip}:{k8s.GATEWAY_PORT}",
    }
    if METADATA_URL:
        env["PROBE_METADATA_URL"] = METADATA_URL
    return env


def agent_pod(gateway_ip: str, runtime_class: str | None) -> dict[str, object]:
    """The pod. ``runtime_class=None`` is lesson 6's rung — the same object minus one field."""
    env = probe_env(gateway_ip)
    spec: dict[str, object] = {
        "restartPolicy": "Never",
        "automountServiceAccountToken": False,
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
                # $HOME stays on the read-only rootfs — see lesson 6. Only /tmp is writable.
                "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
            }
        ],
        "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
    }
    if runtime_class:
        spec["runtimeClassName"] = runtime_class  # <-- THE ENTIRE LESSON
    name = "agent-gvisor" if runtime_class else "agent-runc"
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": {"app": "agent-sandbox"}},
        "spec": spec,
    }


def network_policy() -> dict[str, object]:
    """Identical to lesson 6's, so the rungs differ by the runtime and nothing else."""
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


def merge_pod_death(card: Card, reason: str, label: str) -> Card:
    """Fill in the one row a dead pod could not report — see lesson 6, which meets this first.

    It matters more here. Under `runsc` the sentry and its per-task stub processes are charged to the
    container's own cgroup, so attack 7 exhausts the 256Mi budget faster and more thoroughly than it
    does on runc — lesson 3 recorded exactly this (``capped:sandbox-killed``, exit 137). The pod dies,
    the cap is what killed it, and the kubelet is the only witness left.

    ``OOMKilled`` is required before claiming containment: a pod that died for another reason was not
    demonstrably capped, and ``contained=None`` reports that honestly as ``n/a``.
    """
    if card.complete or card.get("resource_exhaustion") is not None:
        return card
    oom = reason == "OOMKilled"
    print(f"  ! the {label} pod did not survive the suite (terminated: {reason or 'unknown'})")
    print(f"    {len(card.findings)} findings streamed out first — which is why the suite prints")
    print("    each finding as it is produced rather than only a final card.")
    return card.add(
        {
            "name": "resource_exhaustion",
            "value": "capped:pod-oomkilled" if oom else f"pod-died:{reason or 'unknown'}",
            "contained": True if oom else None,
            "group": "abuse",
            "detail": "the memory limit killed the pod mid-attack (host-observed, from the kubelet)",
        }
    )


def assert_gvisor_engaged(card: Card) -> None:
    """Prove `runsc` actually ran this pod — from the kernel it reported, never from the field posted.

    This is the assertion the whole repo is built around. A pod that names a RuntimeClass the node
    cannot honour does not quietly run on runc — it fails outright — but a *misconfigured* runtime
    (a handler pointing at the wrong binary, a shim that fell back) is exactly the silent success
    this catches: the suite would run, every row would look plausible, and the kernel rows would
    simply report the node's kernel while the lesson claimed a user-space one.
    """
    ident = card.get("kernel_identity")
    reported = str(ident["value"]) if ident else "(missing)"
    checks = {
        f"the sandbox reports its OWN kernel, not the node's ({reported})": ident is not None
        and ident["contained"] is True,
        "and it identifies as gVisor": "gvisor" in reported.lower(),
        "the ALLOWED destination still works (a policy, not a dead network)": (
            card.contained("egress_gateway") is True
        ),
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  boundary assertion FAILED — this pod was not run by gVisor; not reporting a result.")


def show_missing_runtimeclass(gateway_ip: str) -> None:
    """Ask for a RuntimeClass nothing registered, and print what the cluster says.

    Worth doing once, because it is how you learn the field is real rather than decorative. It asks
    for a name that does not exist rather than deleting the working `gvisor` class — same lesson, no
    chance of breaking the boundary halfway through its own lesson.
    """
    pod = agent_pod(gateway_ip, MISSING_CLASS)
    pod["metadata"] = {"name": "agent-missing-rtclass"}  # pyright: ignore[reportArgumentType]
    print(f"  Asking for runtimeClassName: {MISSING_CLASS}, which nothing registered...\n")
    reason = k8s.reason_for_failure(pod, NAMESPACE)
    print(f"    {reason}\n")
    print("  Rejected outright, by the API server, before anything was scheduled: there is a")
    print("  RuntimeClass admission check, and an unknown name is Forbidden. That is the good case —")
    print("  you find out in the same second you asked, not from a pod stuck in a waiting state.")
    print("\n  It is also exactly why Part 2 asserts the KERNEL rather than the field. This failure")
    print("  mode is loud, but the dangerous one is silent: a RuntimeClass that exists and points at")
    print("  a misconfigured handler is admitted happily, and only the sandbox's own answer to")
    print("  'whose kernel are you' can tell you it did not engage.")


def main() -> None:
    ensure_image()
    print(f"  RuntimeClasses on this cluster: {k8s.runtime_classes()}")
    k8s.ensure_namespace(NAMESPACE)
    try:
        banner("Part 1 — The simplest thing that works: one field")
        print("  Everything is lesson 6's pod. The entire difference is:\n")
        print(f"      spec:\n        runtimeClassName: {RUNTIME_CLASS}\n")
        gateway_ip = k8s.start_gateway(NAMESPACE)
        k8s.apply(network_policy(), NAMESPACE)
        print(f"  gateway pod at {gateway_ip}:{k8s.GATEWAY_PORT}, NetworkPolicy applied (both as lesson 6)")

        banner("Part 2 — Turn the rogue agent loose, behind a user-space kernel")
        phase, logs, reason = k8s.run_pod(agent_pod(gateway_ip, RUNTIME_CLASS), NAMESPACE)
        print(f"  pod finished in phase {phase} (terminated: {reason or 'n/a'})\n")
        card = merge_pod_death(Card.parse(logs, allow_partial=True), reason, "gvisor")
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")
        if not card.complete:
            print("  (partial card: the sandbox died mid-suite — attack 7 does that under runsc,")
            print("   which is why the suite streams each finding as it is produced)")

        banner("Assert gVisor engaged (from the kernel reported, never from the field posted)")
        assert_gvisor_engaged(card)

        banner("Part 3 — What just changed (the SAME pod without the field, on this same box)")
        prev_phase, prev_logs, prev_reason = k8s.run_pod(agent_pod(gateway_ip, None), NAMESPACE)
        print(f"  the runc pod finished in phase {prev_phase} (terminated: {prev_reason or 'n/a'})\n")
        prev = merge_pod_death(Card.parse(prev_logs, allow_partial=True), prev_reason, "runc")
        print(card.diff_against(prev, "pod (runc)", "pod (gvisor)"))
        print("\n  Every row that moved is a kernel row. Not one network row moved, and that is the")
        print("  point: gVisor's boundary is the syscall interface. It never reads HTTP.")
        print()
        print(card.cost_delta(prev, "pod (runc)", "pod (gvisor)"))
        print("\n  Read those two together rather than as one number: syscall-bound work pays a real")
        print("  tax, CPU-bound work pays almost nothing. 'gVisor is slow' and 'gVisor is free' are")
        print("  both wrong; which KIND of work you do decides.")

        banner("Part 3b — What a RuntimeClass that does not exist looks like")
        show_missing_runtimeclass(gateway_ip)

        banner("Part 4 — What is still open (the next lessons' reason to exist)")
        for f in card.reached():
            print(f"    {f['name']:<20} {f['value']}")
        print("\n  The kernel column is closed and the network column is exactly where lesson 6 left")
        print("  it. gVisor has no idea WHICH binary made a request or WHICH method it used, and it")
        print("  keeps no record — so attacks 2, 4, 5, 6 and 9 are untouched. Lesson 8 reaches the")
        print("  same kernel result by a completely different route, and keeps Landlock while doing")
        print("  it; lesson 9 is the one that closes the rest.")

        card.save(
            RESULTS,
            lesson="lesson-07-k8s-gvisor",
            mode="network-on",
            engine="k3s",
            node_kernel=platform.release(),
            boundary=f"hardened Pod, runtimeClassName: {RUNTIME_CLASS}, scoped NetworkPolicy egress",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        k8s.delete_namespace(NAMESPACE)


if __name__ == "__main__":
    main()
