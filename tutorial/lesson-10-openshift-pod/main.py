"""Lesson 10 — the same agent, the same pod, on OpenShift.

Chapter 3 ended with a hardened Pod on k3s. This lesson submits the closest thing to that manifest
on OpenShift and runs the identical attack suite, so the chapter starts from a measured baseline
rather than an assumption.

Two things are genuinely different, and neither is a security control:

* **The suite arrives as a ConfigMap, not an image.** Chapter 3 built `sandboxing-tutorial/agent:v1`
  with podman and side-loaded it into the node's containerd. RHCOS has no podman to build with, and
  the internal registry needs the `*.apps` route this cluster deliberately does not have. So the
  same `attacks/` package is mounted in from disk — identical code, different delivery. If it were
  not identical the ladder would stop being a ladder.
* **The lesson runs on your machine.** Chapters 1-3 rsync the repo onto the box and run there.
  RHCOS is an immutable image with no package manager and no uv, so the driver is here and the
  boundary is on the node — which is where it always was.

What is NOT different is the pod: the same securityContext, the same limits, the same
`automountServiceAccountToken: false`. The surprise is what happens to it in lesson 11.

    cd tutorial/lesson-10-openshift-pod && ./run.sh
"""

from __future__ import annotations

import sys
from pathlib import Path

import openshift as oc
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS = REPO_ROOT / "results" / "lesson-10.json"
NS = "sbx-lesson-10"
GROUPS = "reach,abuse,kernel,cost"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


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


def agent_pod(node_kernel: str) -> dict[str, object]:
    """Chapter 3's hardened pod, with one deliberate omission.

    There is no `runAsUser` here. Lesson 6 pinned uid 1000; on OpenShift that is exactly what gets a
    manifest refused, because the project has its own UID range and admission assigns from it. The
    omission is the OpenShift-correct spelling of the same intent, and lesson 11 is about why.
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
                    "command": ["python3", "-m", "attacks.run", "--groups", GROUPS],
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


def main() -> None:
    node_kernel = oc.node_kernel()
    banner("Part 1 — The simplest thing that works: the chapter-3 pod, on OpenShift")
    print(f"  cluster node kernel: {node_kernel}")
    print(f"  image:               {oc.IMAGE}")
    print("  suite:               mounted from infra/images/agent/attacks/ as a ConfigMap")
    print("\n  Note what is missing from the spec: runAsUser. Lesson 6 pinned uid 1000; here the")
    print("  project assigns one. That omission is the whole of lesson 11.")

    oc.ensure_namespace(NS)
    try:
        oc.apply(oc.suite_configmap(), NS)
        banner("Part 2 — Turn the rogue agent loose")
        phase, logs, reason = oc.run_pod(agent_pod(node_kernel), NS)
        print(f"  pod finished in phase {phase} (terminated: {reason or 'n/a'})\n")
        card = Card.parse(logs, allow_partial=True)
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        banner("Assert the boundary engaged (from the readings, never from the manifest)")
        checks = {
            "the suite actually ran (a ConfigMap-mounted package imported)": len(card.findings) > 3,
            "fresh filesystem (host creds unreachable)": card.contained("read_credentials") is True,
            "no service-account token (automount off engaged)": card.contained("k8s_sa_token") is True,
        }
        for label, okv in checks.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(checks.values()):
            sys.exit("  boundary assertion FAILED — not reporting a result.")

        banner("Part 3 — What is still open")
        for f in card.reached():
            print(f"    {f['name']:<20} {f['value']}")
        print("\n  The kernel rows are the node's: a pod on OpenShift is still namespaces and cgroups")
        print("  on the node's kernel, exactly as on k3s. OpenShift adds admission, not isolation —")
        print("  which is lesson 11 — and the kernel column waits for lesson 12.")

        card.save(
            RESULTS,
            lesson="lesson-10-openshift-pod",
            mode="network-on",
            engine="openshift-sno",
            node_kernel=node_kernel,
            boundary="hardened Pod on OpenShift, suite mounted as a ConfigMap",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        oc.delete_namespace(NS)


if __name__ == "__main__":
    main()
