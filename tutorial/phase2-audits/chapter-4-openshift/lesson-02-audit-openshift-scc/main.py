"""Lesson 2.4.2 — auditing SCC admission. The only boundary in this tutorial that writes down what it refused.

Audits 1.4.2. It makes the same two requests — an over-privileged pod and a compliant one, both as a
service account holding nothing but `edit` — and then goes looking for them in the **kube-apiserver
audit log**.

**This is the inversion phase 2 has been building to.** Run back through the ladder and the same gap
appears at every rung:

  * 2.2.1 — podman's seccomp refuses `bpf` at syscall entry. The boundary blocked it and left **no
    record**, because a syscall refused before its body runs never reaches a kernel-side sensor.
  * 2.2.4 / 2.3.4 — `fs_policy_write` is denied by Landlock before it resolves to anything an auditor
    can name. Neither auditd nor OCSF sees it: *a host auditor records what the workload DID, not what
    the boundary REFUSED.*
  * 2.3.6 — behind a VM, the host sensor records nothing at all.

Here that flips. The refusal **is** an API request, the API server audits every request, and the
denial lands in the trail with a `403`, the full SCC evaluation, and the identity that asked. Nothing
had to be armed, nothing was installed, and no MachineConfig was involved — unlike 2.4.1's node
auditd, which had to be switched on and forgets at the next reboot.

The reason generalizes past OpenShift, and it is the sentence worth carrying out of this chapter:
**a boundary records what it refused only when the decision is itself an event the platform already
audits.** Landlock, seccomp and a guest kernel make their decisions in silence. Admission control
makes its decision by answering an API call.

1.4.2's Part 4 says "no audit record to keep — because nothing ran". That is exactly half right, and
this lesson is the other half: nothing ran, **and the refusal was recorded anyway.**

    ../../../infra/openshift-sno/install.sh    # bring the shared cluster up (once, ~2 h)
    ./run.sh
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import nodeaudit
import openshift as oc
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
RESULTS = REPO_ROOT / "results" / "2.4.2.json"
NS = "sbx-2-4-2"
SA = "rogue"
LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def privileged_pod() -> dict[str, object]:
    """1.4.2's over-privileged pod, unchanged: the thing admission must refuse."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "rogue-privileged"},
        "spec": {
            "serviceAccountName": SA,
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "rogue",
                    "image": oc.IMAGE,
                    "command": ["sleep", "30"],
                    "securityContext": {"privileged": True, "runAsUser": 0},
                }
            ],
        },
    }


def compliant_pod() -> dict[str, object]:
    """The same workload asking for nothing — admitted, and also recorded."""
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "compliant"},
        "spec": {
            "serviceAccountName": SA,
            "restartPolicy": "Never",
            "containers": [
                {
                    "name": "compliant",
                    "image": oc.IMAGE,
                    "command": ["sleep", "30"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "capabilities": {"drop": ["ALL"]},
                    },
                }
            ],
        },
    }


def setup() -> None:
    oc.ensure_namespace(NS)
    oc.oc("-n", NS, "create", "sa", SA, check=False)
    # RBAC FIRST (1.4.2's Trap #13): without `edit` the refusal comes from RBAC, not SCC, and the
    # experiment measures the wrong thing.
    oc.oc("-n", NS, "adm", "policy", "add-role-to-user", "edit", f"system:serviceaccount:{NS}:{SA}", check=False)


def attempt(manifest: dict[str, object], label: str) -> tuple[bool, str]:
    rc, out, err = oc.oc_result(
        "-n", NS, f"--as=system:serviceaccount:{NS}:{SA}", "create", "-f", "-",
        stdin=json.dumps(manifest),
    )  # fmt: skip
    msg = (err or out).strip()
    print(f"  {label}: {'ADMITTED' if rc == 0 else 'REFUSED'}")
    return rc == 0, msg


def find_decisions(pod_name: str) -> list[dict[str, object]]:
    """Every apiserver audit event that is a `create pods` for this pod name.

    Matched on the objectRef rather than by grepping the raw line, because the SCC message is long
    enough to be truncated in tooling and the identity fields are what the mapping actually needs.
    """
    out: list[dict[str, object]] = []
    for e in nodeaudit.apiserver_events():
        ref = e.get("objectRef")
        if not isinstance(ref, dict) or ref.get("resource") != "pods":
            continue
        if ref.get("name") != pod_name or ref.get("namespace") != NS:
            continue
        if e.get("verb") != "create":
            continue
        out.append(e)
    return out


def summarize(events: list[dict[str, object]]) -> tuple[int, str, str]:
    """(response code, the impersonated identity, the reason) from the most informative event."""
    best: tuple[int, str, str] = (0, "", "")
    for e in events:
        rs = e.get("responseStatus")
        code = int(rs.get("code", 0)) if isinstance(rs, dict) else 0
        who = ""
        imp = e.get("impersonatedUser")
        if isinstance(imp, dict):
            who = str(imp.get("username", ""))
        if not who:
            u = e.get("user")
            who = str(u.get("username", "")) if isinstance(u, dict) else ""
        msg = str(rs.get("message", "")) if isinstance(rs, dict) else ""
        # Prefer a 403: that is the decision this lesson is about.
        if code == 403 or best[0] == 0:
            best = (code, who, msg)
    return best


def main() -> None:
    node_kernel = oc.node_kernel()
    banner("Part 1 — Nothing to arm: the control plane is already auditing")
    print("  2.4.1 had to switch the node's auditd on with `auditctl`, and those rules die at the")
    print("  next reboot. The kube-apiserver's audit log needs none of that — it is on, it is")
    print("  per-request, and `oc adm node-logs --role=master` serves it.")

    setup()
    try:
        banner("Part 2 — Make the two requests 1.4.2 makes")
        admitted_priv, priv_msg = attempt(privileged_pod(), "privileged pod")
        for line in priv_msg.splitlines()[:1]:
            print(f"    {line[:180]}")
        admitted_ok, _ = attempt(compliant_pod(), "compliant pod")
        scc = oc.assigned_scc("compliant", NS) if admitted_ok else ""
        print(f"  compliant pod admitted under SCC: {scc or '(none)'}")

        banner("Part 3 — Now find both decisions in the apiserver's own trail")
        denied = find_decisions("rogue-privileged")
        allowed = find_decisions("compliant")
        d_code, d_who, d_msg = summarize(denied)
        a_code, a_who, _ = summarize(allowed)
        print(f"  REFUSED pod : {len(denied)} audit event(s), code={d_code}, asked by {d_who or '?'}")
        if d_msg:
            print(f"    the trail carries the reason verbatim:\n      {d_msg[:190]}")
        print(f"  ADMITTED pod: {len(allowed)} audit event(s), code={a_code}, asked by {a_who or '?'}")

        banner("Assert the boundary engaged AND the refusal was recorded")
        checks = {
            "the privileged pod was REFUSED": not admitted_priv,
            "refused by SCC admission, not RBAC (Trap #13)": "security context constraint" in priv_msg.lower(),
            "the compliant pod was ADMITTED": admitted_ok,
            "the apiserver recorded the REFUSAL, with a 403": d_code == 403,
            "the record names WHO asked": SA in d_who,
            "the record carries the SCC reason, not just a status": "security context constraint" in d_msg.lower(),
            "the admitted pod was recorded too": a_code in (200, 201),
        }
        for label, okv in checks.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(checks.values()):
            sys.exit("  assertion FAILED — this is not a demonstration of an audited refusal.")

        banner("Part 4 — The one boundary on the ladder that writes down what it refused")
        print("  Every other rung forgets its denials, and phase 2 measured each one:")
        print("    2.2.1  seccomp refuses bpf at syscall ENTRY  -> no kernel-side sensor can see it")
        print("    2.2.4  Landlock denies the write to /etc     -> neither auditd nor OCSF records it")
        print("    2.3.6  a guest kernel hides the workload     -> the host sensor reads zero")
        print()
        print("  Here the refusal IS an API request, and the API server audits every request. So the")
        print("  denial arrives with a 403, the identity that asked, and the full SCC evaluation —")
        print("  without anything being installed, armed, or made to survive a reboot.")
        print()
        print("  The rule that generalizes past OpenShift: a boundary records what it refused only")
        print("  when its decision is itself an event the platform already audits. Landlock, seccomp")
        print("  and a guest kernel decide in silence. Admission control decides by answering a call.")
        print()
        print("  1.4.2 closed on 'no audit record to keep — because nothing ran'. Half right: nothing")
        print("  ran, and the refusal was recorded anyway. That is the half worth having.")

        card = Card([
            {"name": "scc_privileged_refused", "value": "Forbidden" if not admitted_priv else "ADMITTED",
             "contained": not admitted_priv, "group": "policy", "recorded": LOGGED if d_code == 403 else NOT_LOGGED,
             "detail": "an over-privileged pod never started"},
            {"name": "scc_refused_by_admission", "value": "security-context-constraint",
             "contained": "security context constraint" in priv_msg.lower(), "group": "policy",
             "recorded": LOGGED if "security context constraint" in d_msg.lower() else NOT_LOGGED,
             "detail": "SCC, not RBAC — the SA was granted `edit` first (Trap #13)"},
            {"name": "scc_compliant_admitted", "value": scc or "none", "contained": admitted_ok,
             "group": "policy", "recorded": LOGGED if a_code in (200, 201) else NOT_LOGGED,
             "detail": "the same workload, with no runAsUser, is allowed"},
            {"name": "admission_records", "value": len(denied) + len(allowed), "contained": None,
             "group": "evidence",
             "detail": "kube-apiserver audit events for these two decisions — no sensor was installed"},
        ])  # fmt: skip
        print()
        print(card.render())
        card.save(
            RESULTS,
            lesson="2.4.2",
            mode="admission",
            engine="openshift-sno",
            node_kernel=node_kernel,
            boundary="SCC admission + the kube-apiserver audit log — the refusal itself is recorded (phase-2 audit of 1.4.2)",
            denial_code=d_code,
            denial_identity=d_who,
            audit_events_for_decisions=len(denied) + len(allowed),
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        oc.delete_namespace(NS)


if __name__ == "__main__":
    main()
