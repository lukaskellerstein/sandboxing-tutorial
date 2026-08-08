"""Lesson 9 — policy and audit at cluster scale.

Lesson 6 closed attacks 2, 4, 5 and 6 with a NetworkPolicy, and then showed the ceiling: a `POST` to
the same allowed host succeeded, a `curl` copied to an unnamed path succeeded, and nothing anywhere
recorded that either was attempted. Lessons 7 and 8 changed the kernel underneath and moved none of
those rows, because neither gVisor nor Kata reads HTTP.

This rung closes them. OpenShell's **kubernetes** driver runs each sandbox as a policy-governed pod
with egress left **on** but per-binary and method-aware, plus an OCSF audit trail — so attack 9 dies
here and nowhere else.

Lesson 5 did the same thing with the **podman** driver, on one machine. What is worth noticing is how
little changes: the policy file is lesson 5's, and the only line that had to move is the endpoint's
host, because a sandbox is now a Pod and the gateway is now a Service. The policy language does not
know which compute driver is underneath it.

Note what this rung does NOT close: it runs on ordinary runc, so the host kernel is fully exposed and
attack 8 works again. **gVisor and OpenShell are strong in disjoint columns** — that observation is
what lesson 14 is built on, and this lesson is its clean control: nothing is stacked underneath.

    cd tutorial/lesson-09-k8s-openshell && uv sync && uv run python -u main.py
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import k8s
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[2]
NAMESPACE = "sbx-lesson-09"
RESULTS = REPO_ROOT / "results" / "lesson-09.json"
POLICY_SRC = Path(__file__).parent / "policy.yaml"
#: Rendered at run time with the gateway's real cluster DNS name — see policy.yaml's header.
POLICY_OUT = Path("/tmp/lesson-09-policy.yaml")

#: OpenShell caps sandbox names at 19 characters and rejects a longer one at create time, with a
#: message that never mentions length. Counted, not estimated: this is exactly 19.
SANDBOX = "sbx-l9-k8s-openshel"

GROUPS = "reach,abuse,kernel,policy,cost"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def osh(*args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openshell", *args], capture_output=True, text=True, timeout=timeout, check=False)


def preflight() -> str:
    """Confirm the CLI is talking to the in-cluster gateway, on the KUBERNETES driver.

    A gateway accepts a **single** compute driver. Lesson 5's gateway is podman; this one is
    kubernetes, and they cannot share a configuration. Getting it wrong does not produce a message
    about drivers — sandboxes simply refuse to create — so it is checked here, once, by name.
    """
    if os.environ.get("OPENSHELL_DRIVERS") != "kubernetes":
        sys.exit(
            "  OPENSHELL_DRIVERS is not 'kubernetes'. A gateway takes ONE compute driver, and this\n"
            "  lesson needs the cluster one. `source ~/.sandboxing-tutorial.env` (substrate 90 wrote it)."
        )
    status = osh("status", timeout=120).stdout
    if "Connected" not in status:
        sys.exit(f"  the OpenShell gateway is not Connected:\n{status}")
    raw = osh("--version", timeout=60).stdout.strip()
    version = raw.splitlines()[0] if raw else "unknown"
    print(f"  openshell {version}, gateway Connected, driver=kubernetes")
    return version


def render_policy(gateway_host: str) -> Path:
    """Substitute the gateway's real Service DNS name into the policy.

    Generated rather than committed as a literal: the namespace is this lesson's to choose, and a
    hardcoded FQDN that silently stops matching is exactly how a policy comes to look enforced while
    permitting everything it was meant to name.
    """
    text = POLICY_SRC.read_text(encoding="utf-8").replace("__GATEWAY_HOST__", gateway_host)
    POLICY_OUT.write_text(text, encoding="utf-8")
    return POLICY_OUT


def create_sandbox(policy: Path, gateway: str, collector: str) -> None:
    """Create the policy-governed sandbox pod.

    The policy is applied at CREATE, not afterwards, because its `process`, `filesystem_policy` and
    `landlock` sections are locked at startup — `policy set` on a live sandbox refuses them outright.
    Only `network_policies` is hot-reloadable, which is what Part 2b then reloads.
    """
    argv = [
        "sandbox", "create", "--name", SANDBOX,
        "--no-tty", "--no-auto-providers",
        # NOT :latest. OpenShell owns this pod spec, so we cannot set imagePullPolicy ourselves —
        # and Kubernetes defaults a :latest tag to Always, which sends the kubelet to Docker Hub for
        # an image already on the node and parks the sandbox in ImagePullBackOff.
        "--from", k8s.IMAGE,
        "--env", f"PROBE_GATEWAY_URL=http://{gateway}:{k8s.GATEWAY_PORT}",
        "--env", f"PROBE_EXFIL_URL=http://{collector}:{k8s.GATEWAY_PORT}/collect",
        "--env", f"PROBE_OFFPOLICY_URL=http://{collector}:{k8s.GATEWAY_PORT}/",
        "--env", f"PROBE_STAGE_URL=http://{collector}:{k8s.GATEWAY_PORT}/stage.sh",
        "--env", f"PROBE_GROUPS={GROUPS}",
        "--env", f"PROBE_NODE_KERNEL={platform.release()}",
        # The image sets WORKDIR /app, but `sandbox exec` does not start there. PYTHONPATH fixes the
        # import without wrapping the command in `sh -c` — which matters more here than anywhere
        # else, because the policy is PER BINARY and a shell would put `sh` in the execution path.
        "--env", "PYTHONPATH=/app",
        "--policy", str(policy),
    ]  # fmt: skip
    if METADATA_URL:
        argv += ["--env", f"PROBE_METADATA_URL={METADATA_URL}"]
    argv += ["--", "echo", "ready"]
    done = osh(*argv, timeout=900)
    if done.returncode != 0:
        sys.exit(f"  sandbox create failed:\n{done.stdout}\n{done.stderr}")


def wait_ready(timeout_s: int = 300) -> None:
    """Block until the sandbox reports Ready.

    `sandbox create` returns before the supervisor is accepting work, and an `exec` issued in that
    window does not fail — it HANGS. Polling for Ready turns a mystifying stall into a bounded wait.
    Lesson 5 hit this and the fix is the same; the cluster driver only makes the window longer,
    because a pod has to be scheduled and pulled first.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for line in osh("sandbox", "list", timeout=60).stdout.splitlines():
            if SANDBOX in line and "Ready" in line:
                return
        time.sleep(3)
    print(f"  warning: {SANDBOX} never reported Ready within {timeout_s}s; continuing anyway")


def apply_policy(policy: Path) -> None:
    """Arm the OCSF writer FIRST, then reload the policy — the reload is what activates it.

    Enable OCSF after applying the policy and the trail stays empty, which looks exactly like a
    broken feature rather than a sequencing mistake.
    """
    osh("settings", "set", SANDBOX, "--key", "ocsf_json_enabled", "--value", "true", timeout=120)
    done = osh("policy", "set", SANDBOX, "--policy", str(policy), "--wait", timeout=300)
    if done.returncode != 0:
        sys.exit(f"  policy reload failed:\n{done.stdout}\n{done.stderr}")


def run_suite() -> Card:
    done = osh(
        "sandbox", "exec", "-n", SANDBOX, "--",
        "python", "-m", "attacks.run", "--groups", GROUPS,
        timeout=1200,
    )  # fmt: skip
    if done.stderr:
        print("  --- sandbox stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-16:]))
        print()
    return Card.parse(done.stdout, allow_partial=True)


def audit_records() -> tuple[int, list[str]]:
    """The `evidence` row — measured out here, because a process cannot see the record kept about it.

    A zero here is a bug on THIS rung and the finding on every other one.
    """
    time.sleep(4)
    done = osh("logs", SANDBOX, "--since", "20m", "-n", "500", "--source", "sandbox", timeout=120)
    lines = [ln for ln in done.stdout.splitlines() if ln.strip()]
    decisions = [ln for ln in lines if any(k in ln.lower() for k in ("deny", "denied", "allow", "block"))]
    return len(decisions), decisions[:6]


def cleanup() -> None:
    osh("sandbox", "delete", SANDBOX, "--force", timeout=300)
    k8s.delete_namespace(NAMESPACE)


def assert_policy_engaged(card: Card) -> None:
    """Prove the POLICY is what produced these readings, not a dead network.

    The distinguishing pair is the whole lesson: the allowed GET must succeed and the same host's
    POST must not. If both failed, egress is simply broken and every BLOCKED row is meaningless; if
    both succeeded, no policy is being enforced. Only the split proves an L7 decision happened.
    """
    checks = {
        "the allowed GET reached the gateway (this is a policy, not a dead network)": (
            card.contained("egress_gateway") is True
        ),
        "the SAME host's POST was denied (method-aware, which L3/L4 cannot be)": (
            card.contained("http_method_denied") is True
        ),
        "an unlisted binary was denied (per-binary, which no kernel sandbox can see)": (
            card.contained("binary_scoped") is True
        ),
        "the off-policy host was denied": card.contained("egress_offpolicy") is True,
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  policy assertion FAILED — these readings are not evidence of an enforced policy.")


def main() -> None:
    version = preflight()
    subprocess.run(
        ["sudo", "bash", str(REPO_ROOT / "infra" / "images" / "agent" / "import-k3s.sh")],
        check=True, capture_output=True, timeout=900,
    )  # fmt: skip
    k8s.ensure_namespace(NAMESPACE)
    try:
        banner("Part 1 — The simplest thing that works: a policy-governed sandbox pod")
        gateway = k8s.start_service(NAMESPACE, "sbx-gateway")
        collector = k8s.start_service(NAMESPACE, "sbx-collector")
        print(f"  gateway   (allowed by policy): {gateway}:{k8s.GATEWAY_PORT}")
        print(f"  collector (named nowhere)    : {collector}:{k8s.GATEWAY_PORT}")
        print("  Same image, same protocol, same port. One line of policy separates them.\n")
        policy = render_policy(gateway)
        create_sandbox(policy, gateway, collector)
        wait_ready()
        apply_policy(policy)
        print(f"  sandbox {SANDBOX} is Ready, OCSF armed, policy applied")

        banner("Part 2 — Turn the rogue agent loose, under policy, with the network ON")
        card = run_suite()
        print(card.render())

        banner("Assert the policy engaged (the allowed GET succeeded AND the same host's POST did not)")
        assert_policy_engaged(card)

        banner("Part 3 — Attack 9 dies here: the audit trail")
        count, sample = audit_records()
        card.add(
            {
                "name": "audit_records",
                "value": count,
                "contained": count > 0,
                "group": "evidence",
                "detail": "OCSF decisions recorded by the L7 proxy, including the attempts that failed",
            }
        )
        print(f"  {count} policy decisions recorded. A sample:\n")
        for line in sample:
            print(f"    {line}")
        print("\n  Every rung before this one recorded NOTHING — not the exfiltration it blocked, not")
        print("  the metadata request, not the typosquat. A boundary that forgets cannot tell you")
        print("  what your agent tried to do, and 'it was blocked' is not an incident report.")
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        banner("Part 4 — What is still open (and why lesson 14 exists)")
        for f in card.reached():
            print(f"    {f['name']:<20} {f['value']}")
        print("\n  The kernel rows are wide open, and that is not a defect — it is the finding. This")
        print("  runs on ordinary runc, so attack 8 works exactly as it did in lesson 6. gVisor and")
        print("  Kata closed that column and left this one untouched; OpenShell does the reverse.")
        print("  The two are strong in DISJOINT columns, which is what makes stacking them tempting")
        print("  — and lesson 14 measures what happens when you do.")

        card.save(
            RESULTS,
            lesson="lesson-09-k8s-openshell",
            mode="network-on",
            engine="k3s",
            node_kernel=platform.release(),
            openshell_version=version,
            boundary="OpenShell kubernetes driver: per-binary + method-aware egress on runc, OCSF audit",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
