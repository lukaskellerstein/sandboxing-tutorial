"""Lesson 2.4.4 — auditing the OpenShell rung on OpenShift. Three sensors, and the gap none of them close.

Audits 1.4.4. The same policy file, the same sandbox, the same suite — with every sensor this
platform can offer pointed at it at once:

  * **OCSF**, OpenShell's own L7 decision trail — the network attacks, by binary, method and
    endpoint, and the only sensor here that records what the policy DENIED.
  * **the node's `auditd`**, armed exactly as 2.4.1 arms it — the local attacks. OpenShell runs on
    ordinary runc, so unlike 2.4.3's Kata pod the sandbox's syscalls reach the node's kernel and
    carry an SELinux MCS to attribute them by.
  * **the kube-apiserver audit log** — the control plane, on by default.

This is 2.2.4's two-sensor result and 2.3.4's three-column one, on the platform where the sandbox
pod is a first-class object. The finding holds across all three: **full coverage is the union of
sensors with disjoint blind spots**, and one attack still escapes every one of them —
`fs_policy_write`, a write Landlock denies before it resolves to anything an auditor can name.

Read that against 2.4.2, which is the same cluster's other half. Admission refuses a pod and the
refusal is recorded in full, because the decision is an API call. Landlock refuses a write and
nothing anywhere records it, because the decision is a kernel verdict. Same platform, same run,
opposite outcomes — and the difference is not how strong the boundary is, it is whether its
decision happens to be an event something already audits.

    ../../../infra/openshift-sno/install.sh    # bring the shared cluster up (once, ~2 h)
    ./run.sh
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import nodeaudit
import openshift as oc
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
RESULTS = REPO_ROOT / "results" / "2.4.4.json"
NS = "sbx-2-4-4"
GW_NS = "openshell"
POLICY_SRC = Path(__file__).parent / "policy.yaml"
POLICY_OUT = Path("/tmp/lesson-2-4-4-policy.yaml")

#: OpenShell caps sandbox names at 19 characters and rejects a longer one with a message that never
#: mentions length. Counted, not estimated.
SANDBOX = "sbx-244-audit-osh"

GROUPS = "reach,abuse,kernel,policy,cost"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


#: A gateway accepts a SINGLE compute driver, so this configuration cannot be shared with lesson 1.2.4's
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
            "  die with `ContainerExited: code 1`. This is lesson 1.4.2 acting on lesson 1.4.4:\n"
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

    Lesson 1.2.4 hit this and lesson 1.3.4 inherited the fix. The cluster driver only widens the window,
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


# --- the audit layer this leaf adds on top of 1.4.4's boundary ----------------

Decision = dict[str, str]
_DECISION = re.compile(
    r"(?P<klass>NET|HTTP|SSH|PROC|FINDING):(?P<activity>\S+)\s+\[(?P<sev>[A-Z]+)\s*\]\s+(?P<action>ALLOWED|DENIED)\b(?P<detail>.*)"
)
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BINARY = re.compile(r"(?P<binary>/\S+?)\((?P<pid>\d+)\)")
_HTTP = re.compile(r"\b(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT)\s+(?P<url>https?://\S+)")
_ENDPOINT = re.compile(r"->\s*(?P<endpoint>\S+)")

#: 2.3.4's predicates, unchanged. The OCSF trail is the one sensor that is identical on every driver,
#: so its mapping must be too — a difference between the rungs has to be the boundary, not the parse.
OCSF_MATCH: dict[str, Callable[[Decision], bool]] = {
    "exfiltrate": lambda d: "/collect" in d["target"],
    "cloud_metadata": lambda d: "169.254" in d["target"],
    "reverse_shell": lambda d: "/stage" in d["target"],
    "malicious_package": lambda d: "pypi" in d["target"] or "/simple" in d["target"],
    "egress_gateway": lambda d: d["action"] == "ALLOWED" and "sbx-gateway" in d["target"],
    "egress_offpolicy": lambda d: (
        d["action"] == "DENIED"
        and "sbx-collector" in d["target"]
        and "/collect" not in d["target"]
        and "/stage" not in d["target"]
    ),
    "http_method_denied": lambda d: d["action"] == "DENIED" and d["method"] == "POST" and "sbx-gateway" in d["target"],
    "binary_scoped": lambda d: "/tmp/" in d["binary"],
}
#: The local attacks the node's auditd can fingerprint, by the path each opens. 2.4.1's map.
AUDIT_PATHS = {
    "read_credentials": ("id_rsa", "id_ed25519", "credentials", "hosts.yml", ".netrc", ".env"),
    "plant_backdoor": (".bashrc", ".profile", "authorized_keys", "agent-probe"),
    "malicious_package": ("agent_probe_evil",),
    "kallsyms_readable": ("kallsyms",),
    "sys_module_count": ("/sys/module", "/proc/modules"),
}
LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def ocsf_decisions() -> list[Decision]:
    """Parse OpenShell's decision trail into fields, rather than counting lines as 1.4.4 does."""
    time.sleep(4)
    raw = osh("logs", SANDBOX, "--since", "20m", "-n", "800", "--source", "sandbox", timeout=120).stdout
    out: list[Decision] = []
    for line in _ANSI.sub("", raw).splitlines():
        m = _DECISION.search(line)
        if not m:
            continue
        head = m.group("detail").split("[policy:", 1)[0]
        binary = _BINARY.search(head)
        http = _HTTP.search(head)
        endpoint = _ENDPOINT.search(head)
        out.append(
            {
                "action": m.group("action"),
                "method": http.group("method") if http else "",
                "binary": binary.group("binary") if binary else "",
                "target": (http.group("url") if http else (endpoint.group("endpoint") if endpoint else head.strip())),
                "raw": line.strip(),
            }
        )
    return out


def ocsf_recorded(decisions: list[Decision]) -> dict[str, str]:
    return {name: (LOGGED if any(match(d) for d in decisions) else NOT_LOGGED) for name, match in OCSF_MATCH.items()}


def node_recorded(paths: set[str]) -> dict[str, str]:
    return {
        probe: (LOGGED if any(any(f in p for p in paths) for f in frags) else NOT_LOGGED)
        for probe, frags in AUDIT_PATHS.items()
    }


def combine(card: Card, node: dict[str, str], ocsf: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:
            continue
        name = finding["name"]
        states = [s for s in (node.get(name), ocsf.get(name)) if s is not None]
        state = NO_SENSOR if not states else (LOGGED if LOGGED in states else NOT_LOGGED)
        finding["recorded"] = state
        out[name] = state
    return out


def _mark(state: str | None) -> str:
    return "LOGGED" if state == LOGGED else ("not logged" if state == NOT_LOGGED else "— (blind)")


def pod_containers(pod: str) -> list[str]:
    """The pod's real container names, read from the spec.

    Guessing them (`sandbox`, `workload`, ...) is what made the uid lookup return nothing on the first
    run: OpenShell owns this pod and names its containers, so the only reliable source is the object.
    """
    names = oc.oc("-n", GW_NS, "get", "pod", pod, "-o", "jsonpath={.spec.containers[*].name}", check=False)
    return names.split()


def sandbox_uid(pod: str) -> int:
    """The uid OpenShell's sandbox actually runs as, read from the running pod.

    Not guessable: the sandbox pod is OpenShell's object, admitted under the privileged SCC it was
    granted, so its uid is neither the stock image's 1001 nor the lesson namespace's assigned range.
    """
    # From the SPEC, not by exec'ing. `oc exec` into an OpenShell-managed pod goes through its
    # supervisor and is exactly the call that goes flaky after repeated sandbox churn — and a uid the
    # lesson needs BEFORE the suite runs must not depend on the least reliable path available.
    for jsonpath in (
        "{.spec.containers[0].securityContext.runAsUser}",
        "{.spec.securityContext.runAsUser}",
    ):
        out = oc.oc("-n", GW_NS, "get", "pod", pod, "-o", f"jsonpath={jsonpath}", check=False).strip()
        if out.isdigit():
            return int(out)
    for container in pod_containers(pod):
        out = oc.oc("-n", GW_NS, "exec", pod, "-c", container, "--", "id", "-u", check=False, timeout=60).strip()
        if out.isdigit():
            return int(out)
    return 0


def sandbox_mcs(pod: str) -> str:
    """The sandbox pod's SELinux level, read from inside it — the node-auditd attribution key.

    OpenShell owns this pod spec, so unlike 2.4.1 the lesson cannot have the workload print its own
    level. `oc exec` into the pod after the fact gives the same answer: the MCS is a property of the
    pod, not of one process.
    """
    for container in pod_containers(pod):
        out = oc.oc(
            "-n", GW_NS, "exec", pod, "-c", container, "--", "cat", "/proc/self/attr/current",
            check=False, timeout=90,
        )  # fmt: skip
        m = re.search(r"c\d+,c\d+", out)
        if m:
            return m.group(0)
    return ""


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
        # Arm the node sensor HERE: after the sandbox exists (so its real uid can be read) and before
        # the suite runs (so nothing is missed). OpenShell picks the uid, not this lesson.
        sb_uid = sandbox_uid(pod)
        print(f"\n  The sandbox runs as uid {sb_uid or '?'} — OpenShell's choice, not ours. Arming the")
        print("  node's auditd for it (2.4.1's rules, ephemeral — lost at the next reboot):")
        for line in nodeaudit.arm(GW_NS, (sb_uid,) if sb_uid else ()).strip().splitlines():
            print(f"    {line}")
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

        banner("Part 3 — Three sensors on one run")
        decisions = ocsf_decisions()
        card.add({
            "name": "audit_records", "value": len(decisions), "contained": len(decisions) > 0, "group": "evidence",
            "detail": "OCSF decisions recorded by the L7 proxy, including the attempts that failed",
        })  # fmt: skip
        mcs = sandbox_mcs(pod)
        raw, segments = nodeaudit.trail()
        paths = nodeaudit.paths_seen(raw, mcs)
        lost = nodeaudit.lost_count()
        events = nodeaudit.apiserver_events()
        node = node_recorded(paths)
        ocsf = ocsf_recorded(decisions)
        recorded = combine(card, node, ocsf)
        blocked, applicable = card.tally()
        print(f"  boundaries that held: {blocked}/{applicable}")
        print(f"\n    {'probe':<20} {'node auditd':<14} {'OCSF (L7)':<12}")
        print(f"    {'-' * 20} {'-' * 14} {'-' * 12}")
        for name in recorded:
            print(f"    {name:<20} {_mark(node.get(name)):<14} {_mark(ocsf.get(name)):<12}")
        logged = sum(1 for v in recorded.values() if v == LOGGED)
        print(f"\n  {logged}/{len(recorded)} attacks were written down, by the union of the two sensors")
        print(f"  that can see this workload. The node's auditd attributed {len(paths)} file paths to the")
        print(f"  sandbox pod by its SELinux MCS ({mcs or 'none'}); OpenShell's trail carried")
        print(f"  {len(decisions)} policy decisions. Read across {len(segments)} audit segment(s), lost={lost}.")
        print(f"  The apiserver recorded {len(events)} requests in the same window — the control-plane")
        print("  column, which no syscall sensor has and which no attack in this suite reaches.")

        banner("Part 4 — The gap all three sensors share, and its opposite one rung away")
        gaps = [n for n, v in recorded.items() if v != LOGGED]
        print(f"  Recorded by nothing: {', '.join(gaps) or '(none)'}.")
        print()
        print("  `fs_policy_write` is the one that matters, and it is the same structural gap 2.2.4 and")
        print("  2.3.4 found on two other platforms: the write is DENIED by Landlock before it resolves")
        print("  to a file an auditor could name, and Landlock is a kernel verdict rather than an L7")
        print("  one, so OpenShell's own trail never sees it either. A host auditor records what the")
        print("  workload DID; only the enforcing layer knows what it REFUSED, and this one does not say.")
        print()
        print("  Now put that beside 2.4.2, on this same cluster. There, admission refuses a pod and the")
        print("  refusal is recorded in full — 403, the identity, the entire SCC evaluation — because")
        print("  the decision IS an API request and the apiserver audits every request. Two refusals,")
        print("  one run apart, opposite outcomes. The difference is not which boundary is stronger.")
        print("  It is whether the decision is an event the platform already audits.")
        print()
        print("  And the kernel rows are the node's again: this is ordinary runc, so 1.4.3's column is")
        print("  wide open. gVisor and Kata close the kernel and leave policy untouched; OpenShell does")
        print("  the reverse — which is what 2.4.6 measures when the two are stacked.")
        print("\n  OpenShift adds a wrinkle the other rungs do not have: the policy engine itself had")
        print("  to be granted the privileged SCC before it could enforce anything. A control plane")
        print("  that refuses privilege refuses it to your security tooling too.")

        card.save(
            RESULTS,
            lesson="2.4.4",
            mode="network-on",
            engine="openshift-sno",
            node_kernel=oc.node_kernel(),
            openshell_version=version,
            boundary="OpenShell on OpenShift; OCSF (L7) + node auditd (SELinux MCS) + apiserver audit (phase-2 audit of 1.4.4)",
            pod_mcs=mcs,
            node_paths_attributed=len(paths),
            node_sensor_logged=sum(1 for v in node.values() if v == LOGGED),
            ocsf_logged=sum(1 for v in ocsf.values() if v == LOGGED),
            apiserver_events=len(events),
            audit_records_lost=lost,
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        nodeaudit.disarm()
        cleanup()


if __name__ == "__main__":
    main()
