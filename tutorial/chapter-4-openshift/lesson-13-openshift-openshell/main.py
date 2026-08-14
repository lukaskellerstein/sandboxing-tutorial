"""Lesson 13 — policy and audit on OpenShift, where the policy engine must itself pass admission.

Lesson 12 closed the kernel column with a per-pod VM and left everything else exactly where lesson
10 had it: a VM does not read HTTP, does not know which binary opened a socket, and writes nothing
down. This rung closes those, with the network still on — the same thing lesson 9 did on k3s.

What makes it a *different* lesson from lesson 9 is the collision with lesson 11. OpenShell's
supervisor builds a nested network namespace with veth pairs, which needs privileges that
`restricted-v2` refuses. So before the policy engine can enforce anything, it has to be *let in*:

    oc adm policy add-scc-to-user privileged -z openshell-sandbox -n openshell

That single line is the lesson. A policy sandbox is not exempt from admission control — it is
subject to it, and on OpenShift you must consciously decide to grant it. Every other rung's
boundary was something you switched on; this one you have to be *permitted* to switch on.

    cd tutorial/chapter-4-openshift/lesson-13-openshift-openshell && ./run.sh
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

import openshift as oc
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[3]
RESULTS = REPO_ROOT / "results" / "lesson-13.json"
NS = "sbx-lesson-13"
GW_NS = "openshell"
POLICY_SRC = Path(__file__).parent / "policy.yaml"
POLICY_OUT = Path("/tmp/lesson-13-policy.yaml")

#: OpenShell caps sandbox names at 19 characters and rejects a longer one with a message that never
#: mentions length. Counted, not estimated.
SANDBOX = "sbx-l13-openshift"

GROUPS = "reach,abuse,kernel,policy,cost"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


#: A gateway accepts a SINGLE compute driver, so this configuration cannot be shared with lesson 5's
#: podman one. Get it wrong and sandboxes simply refuse to create, with no mention of drivers.
OSH_ENV = {"OPENSHELL_DRIVERS": "kubernetes", "OPENSHELL_GATEWAY": "ocp"}


def osh(*args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    """The openshell CLI, pinned to the gateway's version by this leaf's pyproject."""
    return subprocess.run(
        ["openshell", *args],
        capture_output=True, text=True, timeout=timeout, check=False,
        env={**os.environ, **OSH_ENV},
    )  # fmt: skip


def preflight() -> str:
    banner("Part 1 — The boundary that must first be admitted")
    if osh("--version").returncode != 0:
        sys.exit("  the openshell CLI is not on PATH — run through ./run.sh so uv provides it.")
    version = osh("--version").stdout.strip()

    # The SCC grant IS the lesson, so show that it is really there rather than assuming it.
    #
    # `oc adm policy add-scc-to-user -z <sa> -n <ns>` writes a NAMESPACED RoleBinding, not a
    # ClusterRoleBinding — checking only the cluster-scoped object reports "not granted" about a
    # cluster where the grant is present and working, which would abort the lesson on a false
    # negative. Both are checked because the same grant can legitimately be made either way.
    subjects = oc.oc(
        "get", "rolebinding,clusterrolebinding", "-n", GW_NS, "-A",
        "-o", "jsonpath={range .items[?(@.roleRef.name=='system:openshift:scc:privileged')]}"
        "{.subjects[*].name}{'\\n'}{end}", check=False,
    )  # fmt: skip
    granted = "openshell-sandbox" in subjects
    print(f"  openshell CLI: {version}")
    print(f"  privileged SCC granted to the openshell-sandbox SA: {'yes' if granted else 'NO'}")
    if not granted:
        sys.exit(
            "  The OpenShell sandbox service account does not hold the privileged SCC, so its\n"
            "  supervisor cannot build the nested network namespace it needs and every sandbox will\n"
            "  die with `ContainerExited: code 1`. This is lesson 11 acting on lesson 13:\n"
            "    oc adm policy add-scc-to-user privileged -z openshell-sandbox -n openshell"
        )

    status = osh("status", timeout=120).stdout
    if "Connected" not in status:
        sys.exit(f"  the in-cluster OpenShell gateway is not Connected:\n{status}")
    print("  gateway: Connected")
    return version


def render_policy(gateway_host: str) -> Path:
    text = POLICY_SRC.read_text(encoding="utf-8").replace("__GATEWAY_HOST__", gateway_host)
    POLICY_OUT.write_text(text, encoding="utf-8")
    return POLICY_OUT


def sandbox_pod() -> str:
    """The pod OpenShell created for our sandbox — needed to deliver the attack suite.

    OpenShell owns this pod spec, so the suite cannot be baked into an image we control (there is no
    registry to push to on this cluster) nor mounted by us. Copying it in afterwards is the honest
    remaining option, and it keeps the suite byte-identical to every other rung's.
    """
    for _ in range(30):
        pods = oc.oc("-n", GW_NS, "get", "pods", "--no-headers", check=False).splitlines()
        for line in pods:
            name = line.split()[0]
            if SANDBOX[:12] in name and "Running" in line:
                return name
        time.sleep(5)
    return ""


def wait_ready(timeout_s: int = 420) -> None:
    """`sandbox create` returns before the supervisor accepts work, and an exec in that window HANGS.

    Lesson 5 hit this and lesson 9 inherited the fix. The cluster driver only widens the window,
    because a pod has to be scheduled and an image pulled first.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for line in osh("sandbox", "list", timeout=60).stdout.splitlines():
            if SANDBOX in line and "Ready" in line:
                return
        time.sleep(5)
    print(f"  warning: {SANDBOX} never reported Ready within {timeout_s}s; continuing anyway")


def deliver_suite(pod: str) -> bool:
    """Copy `infra/images/agent/attacks/` into the running sandbox, and prove it landed.

    An OpenShell sandbox pod carries more than one container — the supervisor that enforces policy
    sits alongside the workload — and `oc cp` with no `-c` picks a default. Copying the suite into
    the supervisor would succeed, print a warning nobody reads, and then fail much later as an
    unexplained ModuleNotFoundError. So each container is tried until the suite is visible from
    where the lesson will actually run it: through `openshell sandbox exec`, not through `oc`.
    """
    if not pod:
        return False
    src = REPO_ROOT / "infra" / "images" / "agent" / "attacks"
    containers = oc.oc(
        "-n", GW_NS, "get", "pod", pod, "-o", "jsonpath={.spec.containers[*].name}", check=False,
    ).split()  # fmt: skip
    print(f"  containers in the sandbox pod: {', '.join(containers) or '(none reported)'}")

    for container in containers or [""]:
        cp = [str(oc.OC), "-n", GW_NS, "cp", str(src), f"{pod}:/tmp/attacks"]
        if container:
            cp += ["-c", container]
        done = subprocess.run(
            cp, capture_output=True, text=True, timeout=300,
            env={**os.environ, "KUBECONFIG": str(oc.KUBECONFIG)},
        )  # fmt: skip
        if done.returncode != 0:
            print(f"  - {container or 'default'}: copy failed, {done.stderr.strip().splitlines()[-1][:120]}")
            continue
        # The assertion that matters: visible from INSIDE the policy boundary.
        seen = osh("sandbox", "exec", "-n", SANDBOX, "--", "/bin/sh", "-c", "ls /tmp/attacks/run.py", timeout=180)
        if seen.returncode == 0 and "run.py" in seen.stdout:
            print(f"  - {container or 'default'}: suite present at /tmp/attacks")
            return True
        print(f"  - {container or 'default'}: copied, but the sandbox cannot see it — wrong container")
    print("  ! the attack suite could not be delivered to the sandbox container")
    return False


def probe_env(gateway: str, collector: str) -> list[str]:
    """The probes' configuration, passed at CREATE so `exec` needs no shell to set it.

    Every value here could have been prefixed onto the exec command with `env ...` instead. It is
    not, and the reason is the whole point of this rung: the policy scopes egress **per binary**, so
    whatever wraps the command becomes part of the execution path. `sh -c 'env … python3 …'` puts
    `/bin/sh` there, and then the thing being judged is no longer the thing the lesson describes.
    Baking the environment into the pod spec keeps `exec` down to a single process.
    """
    pairs = {
        "PYTHONPATH": "/tmp",
        "PROBE_GATEWAY_URL": f"http://{gateway}:{oc.STANDIN_PORT}",
        "PROBE_OFFPOLICY_URL": f"http://{collector}:{oc.STANDIN_PORT}/",
        "PROBE_EXFIL_URL": f"http://{collector}:{oc.STANDIN_PORT}/collect",
        "PROBE_STAGE_URL": f"http://{collector}:{oc.STANDIN_PORT}/stage.sh",
        "PROBE_NODE_KERNEL": oc.node_kernel(),
        "PROBE_READONLY_PATH": "/etc/agent-probe-canary",
    }
    return [arg for k, v in pairs.items() for arg in ("--env", f"{k}={v}")]


def run_suite() -> Card | None:
    done = osh(
        "sandbox", "exec", "-n", SANDBOX, "--workdir", "/tmp", "--",
        "python3", "-m", "attacks.run", "--groups", GROUPS,
        timeout=1200,
    )  # fmt: skip
    if done.stderr.strip():
        print("  --- sandbox stderr (last lines) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-8:]))
    try:
        return Card.parse(done.stdout, allow_partial=True)
    except ValueError as exc:
        print(f"  ! no scorecard from the sandbox: {exc}")
        return None


def audit_records() -> tuple[int, list[str]]:
    """Measured out here — a process cannot see the record kept about it."""
    time.sleep(4)
    out = osh("logs", SANDBOX, "--since", "20m", "-n", "500", "--source", "sandbox", timeout=120).stdout
    lines = [ln for ln in out.splitlines() if ln.strip()]
    decisions = [ln for ln in lines if any(k in ln.lower() for k in ("denied", "allowed", "deny", "block"))]
    return len(decisions), decisions[:6]


def cleanup() -> None:
    # No `--force`: 0.0.99's `sandbox delete` does not have that flag (it takes bare names and an
    # `--all`). Passing it makes the CLI exit on an unknown argument, and because this runs in a
    # `finally` that ignores the return code, the sandbox would leak in silence.
    osh("sandbox", "delete", SANDBOX, timeout=300)
    oc.delete_namespace(NS)


def main() -> None:
    version = preflight()
    oc.ensure_namespace(NS)
    try:
        gateway = oc.start_service(NS, "sbx-gateway")
        collector = oc.start_service(NS, "sbx-collector")
        print(f"\n  gateway   (named in the policy): {gateway}:{oc.STANDIN_PORT}")
        print(f"  collector (named nowhere)      : {collector}:{oc.STANDIN_PORT}")
        print("  Same image, same protocol, same port. One line of policy separates them.")

        policy = render_policy(gateway)
        banner("Part 2 — A policy-governed sandbox, with the network ON")
        # `-- echo ready`, NOT `-- sleep 3600`. `sandbox create` RUNS the command and waits for it to
        # exit, so a long-lived command blocks the CLI for its whole duration — measured here as a
        # create that had not returned after ten minutes while the pod was Running and Ready the
        # whole time. The pod's lifetime is the Sandbox object's, not this command's, so a command
        # that exits immediately is both correct and the only kind that works.
        create = osh(
            "sandbox", "create", "--name", SANDBOX, "--no-tty", "--no-auto-providers",
            "--from", oc.IMAGE, *probe_env(gateway, collector), "--policy", str(policy),
            "--", "echo", "ready",
            timeout=900,
        )  # fmt: skip
        if create.returncode != 0:
            sys.exit(f"  sandbox create failed:\n{create.stdout}\n{create.stderr}")
        wait_ready()
        osh("settings", "set", SANDBOX, "--key", "ocsf_json_enabled", "--value", "true", timeout=120)
        reload_ = osh("policy", "set", SANDBOX, "--policy", str(policy), "--wait", timeout=300)
        if reload_.returncode != 0:
            print(f"  ! policy reload: {reload_.stderr.strip()[:200]}")
        print(f"  sandbox {SANDBOX} Ready, OCSF armed, policy applied")

        pod = sandbox_pod()
        print(f"  sandbox pod: {pod or '(not found)'}")
        card = run_suite() if deliver_suite(pod) else None
        if card is None:
            sys.exit(
                "  the attack suite did not run inside the sandbox, so there is nothing to report.\n"
                "  Not writing a scorecard: a lesson with no measurement is not a lesson."
            )
        print()
        print(card.render())

        banner("Assert the policy engaged (the allowed GET succeeded AND the same host's POST did not)")
        checks = {
            "the allowed GET reached the gateway (a policy, not a dead network)": (
                card.contained("egress_gateway") is True
            ),
            "the SAME host's POST was denied (method-aware, which L3/L4 cannot be)": (
                card.contained("http_method_denied") is True
            ),
            "an unlisted binary was denied (per-binary, which no kernel sandbox sees)": (
                card.contained("binary_scoped") is True
            ),
            "the off-policy host was denied": card.contained("egress_offpolicy") is True,
        }
        for label, okv in checks.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(checks.values()):
            sys.exit("  policy assertion FAILED — these readings are not evidence of an enforced policy.")

        banner("Part 3 — Attack 9 dies here, on OpenShift too")
        count, sample = audit_records()
        card.add({
            "name": "audit_records", "value": count, "contained": count > 0, "group": "evidence",
            "detail": "OCSF decisions recorded by the L7 proxy, including the attempts that failed",
        })  # fmt: skip
        print(f"  {count} policy decisions recorded. A sample:\n")
        for line in sample:
            print(f"    {line[:160]}")
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        banner("Part 4 — What is still open, and the composition question")
        for f in card.reached():
            print(f"    {f['name']:<20} {f['value']}")
        print("\n  The kernel rows are the node's: this runs on ordinary runc, so lesson 12's column")
        print("  is wide open again. gVisor and Kata close the kernel and leave policy untouched;")
        print("  OpenShell does the reverse. Disjoint columns — which is what makes stacking them")
        print("  tempting, and what lesson 19 measures on this cluster's Kata (lesson 16 on gVisor).")
        print("\n  OpenShift adds a wrinkle the other rungs do not have: the policy engine itself had")
        print("  to be granted the privileged SCC before it could enforce anything. A control plane")
        print("  that refuses privilege refuses it to your security tooling too.")

        card.save(
            RESULTS,
            lesson="lesson-13-openshift-openshell",
            mode="network-on",
            engine="openshift-sno",
            node_kernel=oc.node_kernel(),
            openshell_version=version,
            boundary="OpenShell on OpenShift: per-binary + method-aware egress on runc, OCSF audit",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
