"""Lesson 1.3.6 — Composition: OpenShell over Kata. The stack that actually works.

Lesson 1.3.5 stacked OpenShell's policy on gVisor and watched the filesystem clause silently vanish,
because gVisor answers `ENOSYS` to `landlock()`. This rung stacks the SAME policy on Kata instead —
`runtimeClassName: kata-qemu`, the one field lesson 1.3.3 selected — and the clause holds.

The reason is the whole point of the ladder's Kata rung: Kata boots a **real guest kernel**, and a
real Linux kernel ships Landlock. So OpenShell's `landlock()` call succeeds inside the guest, the
filesystem policy is enforced, and `fs_policy_write` stays **blocked** exactly as it did on runc in
lesson 1.3.4. Nothing regressed. Read against lesson 1.3.5, this is the positive half of the same finding:

    composition fails when the lower layer removes a kernel feature the upper layer depends on —
    and it *succeeds* when the lower layer keeps that feature.

Kata is heavier than gVisor (a VM per pod, not a user-space kernel), and that weight is exactly what
buys back the Landlock the composition depends on. See `docs/isolation-layers.md` § *The trap*.

    # 1. start the cluster (once):
    cd ../../../../infra && ./up.sh chapter-03-k8s
    # 2. then run this lesson on it (from your machine, it runs ON the box):
    cd tutorial/phase1-attacks/chapter-3-kubernetes/lesson-06-compose-kata-openshell && uv sync && uv run python -u main.py
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

import k8s
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "1.3.6"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
NAMESPACE = "sbx-1-3-6"
RESULTS = REPO_ROOT / "results" / "1.3.6.json"
POLICY_SRC = Path(__file__).parent / "policy.yaml"
POLICY_HARD_SRC = Path(__file__).parent / "policy-hard.yaml"
POLICY_OUT = Path("/tmp/lesson-17-policy.yaml")
POLICY_HARD_OUT = Path("/tmp/lesson-17-policy-hard.yaml")

#: The lower runtime this lesson stacks OpenShell onto. kata-qemu boots a per-pod KVM VM with its own
#: guest kernel, selected per sandbox through OpenShell's driver-config overlay.
RUNTIME_CLASS = "kata-qemu"
DRIVER_CONFIG = {"kubernetes": {"pod": {"runtime_class_name": RUNTIME_CLASS}}}

#: OpenShell's kubernetes driver places each sandbox pod in the gateway's namespace (substrate 90).
GW_NS = "openshell"

#: OpenShell caps sandbox names at 19 characters. Counted, not estimated.
SANDBOX = "sbx-l17-kata"
SANDBOX_HARD = "sbx-l17-kata-hard"

#: kernel shows the Kata GUEST kernel in the card; policy carries `fs_policy_write` and the L7 proofs.
GROUPS = "kernel,policy"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def osh(*args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openshell", *args], capture_output=True, text=True, timeout=timeout, check=False)


def preflight() -> str:
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


def render_policy(src: Path, out: Path, gateway_host: str) -> Path:
    out.write_text(src.read_text(encoding="utf-8").replace("__GATEWAY_HOST__", gateway_host), encoding="utf-8")
    return out


def create_sandbox(
    name: str, policy: Path, gateway: str, collector: str, *, timeout: int = 900
) -> subprocess.CompletedProcess[str]:
    """Create a policy-governed sandbox on the Kata runtime class. Returns the result, unraised.

    Same shape as lesson 1.3.5 — the runtime is chosen with `--driver-config-json`, the policy is applied
    at CREATE (its static sections are locked at startup). A Kata pod has to boot a VM first, so the
    caller should allow a longer Ready wait than a gVisor or runc pod needs.
    """
    argv = [
        "sandbox", "create", "--name", name,
        "--no-tty", "--no-auto-providers",
        "--from", k8s.IMAGE,
        "--driver-config-json", json.dumps(DRIVER_CONFIG),
        "--env", f"PROBE_GATEWAY_URL=http://{gateway}:{k8s.GATEWAY_PORT}",
        "--env", f"PROBE_OFFPOLICY_URL=http://{collector}:{k8s.GATEWAY_PORT}/",
        "--env", f"PROBE_GROUPS={GROUPS}",
        "--env", f"PROBE_NODE_KERNEL={platform.release()}",
        "--env", "PYTHONPATH=/app",
        "--policy", str(policy),
        "--", "echo", "ready",
    ]  # fmt: skip
    return osh(*argv, timeout=timeout)


def wait_ready(name: str, timeout_s: int = 420) -> None:
    """Block until Ready. A Kata pod widens the window further — a VM has to boot before the exec lands."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for line in osh("sandbox", "list", timeout=60).stdout.splitlines():
            if name in line and "Ready" in line:
                return
        time.sleep(3)
    print(f"  warning: {name} never reported Ready within {timeout_s}s; continuing anyway")


def sandbox_pod(name: str) -> str:
    for _ in range(20):
        out = k8s.kubectl("-n", GW_NS, "get", "pods", "--no-headers", check=False)
        for line in out.splitlines():
            fields = line.split()
            if fields and name[:12] in fields[0]:
                return fields[0]
        time.sleep(3)
    return ""


def pod_runtime_class(pod: str) -> str:
    if not pod:
        return ""
    return k8s.kubectl("-n", GW_NS, "get", "pod", pod, "-o", "jsonpath={.spec.runtimeClassName}", check=False)


def kernel_inside(name: str) -> str:
    """`uname -r` from inside the sandbox. On k3s the Kata GUEST kernel differs from the node's."""
    return osh("sandbox", "exec", "-n", name, "--", "uname", "-r", timeout=180).stdout.strip()


def apply_policy(name: str, policy: Path) -> None:
    osh("settings", "set", name, "--key", "ocsf_json_enabled", "--value", "true", timeout=120)
    osh("policy", "set", name, "--policy", str(policy), "--wait", timeout=300)


def run_suite(name: str) -> Card:
    done = osh("sandbox", "exec", "-n", name, "--", "python", "-m", "attacks.run", "--groups", GROUPS, timeout=1200)
    if done.stderr:
        print("  --- sandbox stderr (last lines) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-12:]))
    return Card.parse(done.stdout, allow_partial=True)


def landlock_witness(name: str) -> list[str]:
    """The audit trail's word on Landlock. Under Kata it reports Landlock AVAILABLE and the ruleset
    BUILT — the positive mirror of lesson 1.3.5's HIGH 'WITHOUT restrictions' finding."""
    time.sleep(4)
    out = osh("logs", name, "--since", "20m", "-n", "500", "--source", "sandbox", timeout=120).stdout
    return [ln for ln in out.splitlines() if "landlock" in ln.lower()][:6]


def cleanup() -> None:
    osh("sandbox", "delete", SANDBOX, "--force", timeout=300)
    osh("sandbox", "delete", SANDBOX_HARD, "--force", timeout=300)
    k8s.delete_namespace(NAMESPACE)


def main() -> None:
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        ip = box_ip_if_any()
        if not ip:
            refuse_no_box()
            return  # unreachable — refuse_no_box exits — but narrows ip to str for the type checker
        raise SystemExit(run_on_box(ip))

    version = preflight()
    subprocess.run(
        ["sudo", "bash", str(REPO_ROOT / "infra" / "images" / "agent" / "import-k3s.sh")],
        check=True, capture_output=True, timeout=900,
    )  # fmt: skip
    k8s.ensure_namespace(NAMESPACE)
    node_kernel = platform.release()
    try:
        banner("Part 1 — The same policy as lesson 1.3.4, on a Kata sandbox instead of runc")
        gateway = k8s.start_service(NAMESPACE, "sbx-gateway")
        collector = k8s.start_service(NAMESPACE, "sbx-collector")
        policy = render_policy(POLICY_SRC, POLICY_OUT, gateway)
        created = create_sandbox(SANDBOX, policy, gateway, collector)
        if created.returncode != 0:
            sys.exit(f"  sandbox create failed:\n{created.stdout}\n{created.stderr}")
        wait_ready(SANDBOX)

        # Assert Kata engaged FROM INSIDE: the pod's runtimeClassName, and a guest kernel that differs
        # from the node's. On k3s the Kata guest kernel is not the node's — that difference is the VM.
        pod = sandbox_pod(SANDBOX)
        rc = pod_runtime_class(pod)
        guest_kernel = kernel_inside(SANDBOX)
        print(f"  sandbox pod: {pod or '(not found)'}")
        print(f"  pod .spec.runtimeClassName: {rc or '(none)'}   (expected: {RUNTIME_CLASS})")
        print(f"  guest kernel from inside: {guest_kernel or '(unknown)'}   (node: {node_kernel})")
        if rc != RUNTIME_CLASS or not guest_kernel or guest_kernel == node_kernel:
            sys.exit(
                "  the sandbox is NOT running in a Kata VM — runtimeClassName is wrong or the guest\n"
                "  kernel matches the node. Refusing to report: this rung would be measuring runc."
            )

        apply_policy(SANDBOX, policy)
        card = run_suite(SANDBOX)
        print()
        print(card.render())

        banner("Assert the policy engaged (L7 control), then read the filesystem clause")
        l7 = {
            "the allowed GET reached the gateway (L7, kernel-agnostic)": card.contained("egress_gateway"),
            "the SAME host's POST was denied (method-aware L7)": card.contained("http_method_denied"),
            "an unlisted binary was denied (per-binary L7)": card.contained("binary_scoped"),
        }
        for label, okv in l7.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(l7.values()):
            sys.exit("  the L7 policy did not engage — the readings are not trustworthy; not reporting.")

        fs_blocked = card.contained("fs_policy_write")
        witness = landlock_witness(SANDBOX)
        print()
        if fs_blocked:
            print("  fs_policy_write: BLOCKED. The filesystem clause held — the write to /etc that lesson")
            print("  1.3.4 refused is refused here too, on the SAME policy. Landlock is present in the Kata")
            print("  guest kernel, so nothing regressed. This is what lesson 1.3.5 could not do on gVisor.")
        else:
            print("  fs_policy_write: ALLOWED. Unexpected — Kata is supposed to ship Landlock. Investigate")
            print("  before trusting this; a Kata guest without Landlock would be a real surprise.")
        print("\n  the audit trail's independent witness (Landlock available / ruleset built):")
        for line in witness:
            print(f"    {line[:160]}")

        banner("Part 2 — hard_requirement is satisfiable here (the positive control)")
        hard = render_policy(POLICY_HARD_SRC, POLICY_HARD_OUT, gateway)
        # Passed at CREATE, never `policy set`. On gVisor (lesson 1.3.5) this refuses to start; here it
        # should START, because Landlock is genuinely available and the hard requirement is met.
        created_hard = create_sandbox(SANDBOX_HARD, hard, gateway, collector, timeout=600)
        started = created_hard.returncode == 0
        if started:
            print("  create SUCCEEDED — hard_requirement is satisfied, because Landlock is really there.")
            print("  The same file that makes gVisor refuse to start runs cleanly on Kata.")
        else:
            print("  create REFUSED — unexpected on Kata. If best_effort blocked the write above, this")
            print("  should have started; the two are inconsistent and worth investigating.")
            tail = (created_hard.stdout + "\n" + created_hard.stderr).strip().splitlines()
            for line in tail[-4:]:
                print(f"    {line[:160]}")

        banner("What this rung teaches")
        print("  Composing OpenShell over Kata keeps BOTH columns: Kata's per-pod VM closes the kernel")
        print("  surface, and OpenShell's policy — filesystem clause included — is fully enforced,")
        print("  because the guest ships the Landlock the policy depends on. This is the composition")
        print("  gVisor could not sustain (lesson 1.3.5). The cost is Kata's weight: a VM per pod rather")
        print("  than a user-space kernel — which is exactly what buys the Landlock back.")

        card.add({
            "name": "runtime_class", "value": rc, "contained": None, "group": "policy",
            "detail": f"read from the pod, not the flag; guest kernel: {guest_kernel} (node {node_kernel})",
        })  # fmt: skip
        card.add({
            "name": "landlock_hard_started", "value": "started" if started else "refused", "contained": started,
            "group": "policy", "detail": "hard_requirement is satisfiable when the guest ships Landlock",
        })  # fmt: skip
        card.save(
            RESULTS,
            lesson=LESSON,
            mode="compose-kata",
            engine="k3s",
            node_kernel=node_kernel,
            runtime_class=rc,
            guest_kernel=guest_kernel,
            openshell_version=version,
            boundary="OpenShell kubernetes driver stacked on Kata (runtimeClassName: kata-qemu)",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        cleanup()


def box_ip_if_any() -> str | None:
    try:
        for line in STATE_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("BOX_IP="):
                return line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        return None
    return None


def run_on_box(ip: str) -> int:
    runner = REPO_ROOT / "infra" / "run.sh"
    print(f"Box for {LESSON} is up ({ip}). Running the lesson ON it via infra/run.sh …\n")
    return subprocess.run([str(runner), LESSON]).returncode


def refuse_no_box() -> None:
    print(f"No box for {LESSON} is up — nothing to run.")
    print("This lesson only runs on the shared chapter-3 cluster (k3s + Agent Sandbox + the OpenShell")
    print("gateway + Kata), installed on the box by its substrates. Start it, then run from here:\n")
    print("    cd ../../../../infra && ./up.sh chapter-03-k8s")
    print("    uv run python -u main.py                # runs it on the box and brings the card home")
    raise SystemExit(2)


if __name__ == "__main__":
    main()
