"""Lesson 11 — the cluster refuses to run the agent at all.

Every other rung in this tutorial contains an agent that is **already running**. This one is a
different kind of boundary: it is the cluster declining to start the workload in the first place —
the earliest and cheapest place to stop a bad one.

The one-sentence version of an SCC: *on plain Kubernetes you **ask** for privileges in your pod spec
and the cluster generally gives them to you; on OpenShift a gatekeeper checks that request against a
policy bound to your account and **rejects the pod before it ever starts**.*

Lesson 6's hardening worked because we wrote a careful spec. Nothing stopped us writing a careless
one. Here, nothing *permits* a careless one — and the teaching moment is a failure, not a success:
the manifest that a reasonable person writes gets refused, and the fix is usually to **delete** your
own `runAsUser` and let OpenShift assign one from the project's range.

    cd tutorial/chapter-4-openshift/lesson-11-openshift-scc && ./run.sh
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import openshift as oc
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[3]
RESULTS = REPO_ROOT / "results" / "lesson-11.json"
NS = "sbx-lesson-11"
SA = "rogue"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def privileged_pod() -> dict[str, object]:
    """What an attacker — or a careless engineer — writes. Every line here is a request for power."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "rogue-privileged"},
        "spec": {
            "serviceAccountName": SA,
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "agent",
                    "image": oc.IMAGE,
                    "command": ["/bin/sh", "-c", "id; echo I_AM_ROOT_ON_THE_NODE"],
                    "securityContext": {
                        "privileged": True,  # the whole node, effectively
                        "runAsUser": 0,  # root
                        "allowPrivilegeEscalation": True,
                    },
                }
            ],
            # Mounting the host filesystem is the other half of "privileged" in practice.
            "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
        },
    }


def compliant_pod() -> dict[str, object]:
    """The same workload, asking for nothing.

    Note what is NOT here: `runAsUser`. On OpenShift that is the fix rather than an omission — the
    project has a UID range and admission assigns one. Pinning a UID yourself is the single most
    common reason a manifest that works on vanilla Kubernetes is rejected here.
    """
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "compliant"},
        "spec": {
            "serviceAccountName": SA,
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "agent",
                    "image": oc.IMAGE,
                    "command": ["/bin/sh", "-c", "id; echo ADMITTED"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                        "runAsNonRoot": True,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                }
            ],
        },
    }


def setup() -> None:
    oc.ensure_namespace(NS)
    oc.oc("-n", NS, "create", "sa", SA, check=False)
    # RBAC FIRST, and this is Trap #13. Without `edit`, a bare service account cannot create a pod at
    # all — and the error says "cannot get resource pods", which is RBAC talking, not SCC. You would
    # conclude admission rejected the privileged pod when in fact nothing ever evaluated it. Granting
    # RBAC makes SCC the ONLY thing left that can refuse, which is the whole point of the experiment.
    oc.oc("-n", NS, "adm", "policy", "add-role-to-user", "edit", f"system:serviceaccount:{NS}:{SA}", check=False)


def attempt(manifest: dict[str, object], label: str) -> tuple[bool, str]:
    """Create a pod AS the restricted service account. Returns (admitted, message)."""
    rc, out, err = oc.oc_result(
        "-n", NS, f"--as=system:serviceaccount:{NS}:{SA}", "create", "-f", "-",
        stdin=json.dumps(manifest),
    )  # fmt: skip
    msg = (err or out).strip()
    print(f"  {label}: {'ADMITTED' if rc == 0 else 'REFUSED'}")
    return rc == 0, msg


def main() -> None:
    node_kernel = oc.node_kernel()
    banner("Part 1 — The simplest thing that works: nothing new to install")
    print("  SCC admission is already running on every OpenShift cluster. There is no operator to")
    print("  add and no field to set — the boundary is the cluster's opinion about your pod spec.\n")
    sccs = oc.oc("get", "scc", "--no-headers", check=False).splitlines()
    print(f"  {len(sccs)} SecurityContextConstraints exist on this cluster, e.g.:")
    for line in sccs[:5]:
        print(f"    {line.split()[0]}")

    setup()
    try:
        banner("Part 2 — Turn the rogue agent loose: it never gets to run")
        print("  Creating a privileged pod AS a service account that holds only `edit` RBAC.\n")
        admitted_priv, priv_msg = attempt(privileged_pod(), "privileged pod")
        print()
        for line in priv_msg.splitlines()[:2]:
            print(f"    {line[:200]}")

        print("\n  Read that message: it enumerated EVERY SCC on the cluster and gave a reason for")
        print("  each. Two of them are the interesting ones —")
        print("    * runAsUser 0 is outside the project's assigned range")
        print("    * privileged: true is not allowed by restricted-v2")
        print("  The rest simply are not bound to this account. No container was ever created.")

        banner("Part 3 — The same workload, asking for nothing")
        admitted_ok, ok_msg = attempt(compliant_pod(), "compliant pod")
        if not admitted_ok:
            print(f"    {ok_msg[:300]}")
        scc = oc.assigned_scc("compliant", NS) if admitted_ok else ""
        print(f"\n  admitted under SCC: {scc or '(none)'}")
        print("\n  The fix was to DELETE `runAsUser`, not to add anything. OpenShift assigns a UID")
        print("  from the project's range; pinning one yourself is the commonest reason a manifest")
        print("  that works on vanilla Kubernetes is refused here.")

        banner("Assert the boundary engaged (a refusal by SCC, not by RBAC)")
        checks = {
            "the privileged pod was REFUSED": not admitted_priv,
            "refused by SCC admission, not RBAC (Trap #13)": "security context constraint" in priv_msg.lower(),
            "the compliant pod was ADMITTED": admitted_ok,
            "and OpenShift recorded which SCC allowed it": bool(scc),
        }
        for label, okv in checks.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(checks.values()):
            sys.exit("  boundary assertion FAILED — this is not a demonstration of SCC admission.")

        banner("Part 4 — What is different about this rung")
        print("  Every other boundary in this tutorial CONTAINS a running agent. This one refuses to")
        print("  start it. That is a different thing, and it is cheaper: no container, no image pull,")
        print("  no syscall to intercept, no audit record to keep — because nothing ran.")
        print("\n  It is also the one boundary that cannot be measured with the attack suite. There is")
        print("  no scorecard of nine attacks here, because the agent never executed a single one.")
        print("  The finding IS the rejection, so that is what this lesson records.")

        card = Card([
            {"name": "scc_privileged_refused", "value": "Forbidden" if not admitted_priv else "ADMITTED",
             "contained": not admitted_priv, "group": "policy",
             "detail": "an over-privileged pod never started"},
            {"name": "scc_refused_by_admission", "value": "security-context-constraint",
             "contained": "security context constraint" in priv_msg.lower(), "group": "policy",
             "detail": "SCC, not RBAC — the SA was granted `edit` first (Trap #13)"},
            {"name": "scc_compliant_admitted", "value": scc or "none", "contained": admitted_ok,
             "group": "policy", "detail": "the same workload, with no runAsUser, is allowed"},
            {"name": "scc_count", "value": len(sccs), "contained": None, "group": "policy",
             "detail": "SCCs evaluated against every pod"},
        ])  # fmt: skip
        print()
        print(card.render())
        card.save(
            RESULTS,
            lesson="lesson-11-openshift-scc",
            mode="admission",
            engine="openshift-sno",
            node_kernel=node_kernel,
            boundary="SCC admission — the cluster refuses an over-privileged pod before it starts",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        oc.delete_namespace(NS)


if __name__ == "__main__":
    main()
