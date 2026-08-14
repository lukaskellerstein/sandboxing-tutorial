"""Lesson 16 — Composition: OpenShell over gVisor. Where stacking makes you *less* safe.

Lesson 9 ran OpenShell's policy on ordinary runc and every clause held: the L7 egress rules, the
per-binary scoping, and the filesystem clause that keeps `/etc` read-only. This rung applies the
**same policy file** to a sandbox whose lower runtime is gVisor — `runtimeClassName: gvisor`, the
one field lesson 7 selected — and measures which clauses survive the swap.

The finding is a **failure mode**, not a stronger boundary — and, measured on OpenShell 0.0.99, a
subtler one than the folklore. gVisor shrinks the host-kernel attack surface (the kernel rows close,
exactly as in lesson 7), and the L7 policy is unaffected because OpenShell's proxy does not read the
kernel. But OpenShell's filesystem policy leans on **Landlock**, and gVisor's user-space kernel
answers `ENOSYS` to the `landlock()` syscall — so the filesystem clause **silently loses its Landlock
backing**, flagged only by a HIGH `"Landlock Filesystem Sandbox Unavailable"` line in the audit
trail. The write to `/etc` nonetheless stays **blocked**, because this driver *also* backs the
read-only paths with a read-only root filesystem, which needs no Landlock. So the lost layer is
**masked**: `fs_policy_write` reads identically to the safe Kata stack, and the audit finding is the
only signal that a defense-in-depth layer vanished. `policy-hard.yaml` (`hard_requirement`) is the
fix — it refuses to start rather than run a policy it cannot fully enforce. Under Kata (lesson 17)
nothing is lost, because the guest ships Landlock.

The rule still generalizes: **composition fails when the lower layer removes a kernel feature the
upper layer depends on** — here the failure is silent in the attack outcome and visible only in the
audit trail, which is the sharper warning: *verify enforcement, do not infer it.* See
`docs/isolation-layers.md` § *The trap*.

    # 1. start the cluster (once):
    cd ../../../infra && ./up.sh chapter-03-k8s
    # 2. then run this lesson on it (from your machine, it runs ON the box):
    cd tutorial/chapter-3-kubernetes/lesson-16-compose-gvisor-openshell && uv sync && uv run python -u main.py
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

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSON = "lesson-16-compose-gvisor-openshell"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
NAMESPACE = "sbx-lesson-16"
RESULTS = REPO_ROOT / "results" / "lesson-16.json"
POLICY_SRC = Path(__file__).parent / "policy.yaml"
POLICY_HARD_SRC = Path(__file__).parent / "policy-hard.yaml"
POLICY_OUT = Path("/tmp/lesson-16-policy.yaml")
POLICY_HARD_OUT = Path("/tmp/lesson-16-policy-hard.yaml")

#: The lower runtime this lesson stacks OpenShell onto. gVisor is selected per sandbox through
#: OpenShell's driver-config overlay, which lands as the pod's `spec.runtimeClassName`.
RUNTIME_CLASS = "gvisor"
DRIVER_CONFIG = {"kubernetes": {"pod": {"runtime_class_name": RUNTIME_CLASS}}}

#: OpenShell's kubernetes driver places each sandbox pod in the gateway's namespace (substrate 90
#: installs the gateway into `openshell`). That is where we read `runtimeClassName` back from — never
#: from the flag we passed, which cannot tell a runtime that engaged from one that was ignored.
GW_NS = "openshell"

#: OpenShell caps sandbox names at 19 characters and rejects a longer one with a message that never
#: mentions length. Counted, not estimated.
SANDBOX = "sbx-l16-gvisor"
SANDBOX_HARD = "sbx-l16-gv-hard"

#: kernel proves gVisor engaged in the card; policy carries `fs_policy_write` and the L7 proofs.
GROUPS = "kernel,policy"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def osh(*args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openshell", *args], capture_output=True, text=True, timeout=timeout, check=False)


def preflight() -> str:
    """Confirm the CLI is talking to the in-cluster gateway, on the kubernetes driver (lesson 9's check)."""
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
    """Substitute the gateway's real Service DNS name into a policy file (see policy.yaml's header)."""
    out.write_text(src.read_text(encoding="utf-8").replace("__GATEWAY_HOST__", gateway_host), encoding="utf-8")
    return out


def create_sandbox(
    name: str, policy: Path, gateway: str, collector: str, *, timeout: int = 900
) -> subprocess.CompletedProcess[str]:
    """Create a policy-governed sandbox pod on the gVisor runtime class. Returns the result, unraised.

    The runtime is chosen with OpenShell's per-sandbox `--driver-config-json` overlay, which lands as
    the pod's `spec.runtimeClassName`. The policy is applied at CREATE because its `filesystem_policy`
    and `landlock` sections are locked at startup — which is also why Part 2's hard policy is passed
    here and never through `policy set`.

    The caller decides what a non-zero exit means: for best_effort it is a failure, for
    `hard_requirement` on gVisor it is the expected fail-closed result.
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


def wait_ready(name: str, timeout_s: int = 300) -> None:
    """Block until the sandbox reports Ready — an exec issued before then HANGS (lesson 9's fix)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for line in osh("sandbox", "list", timeout=60).stdout.splitlines():
            if name in line and "Ready" in line:
                return
        time.sleep(3)
    print(f"  warning: {name} never reported Ready within {timeout_s}s; continuing anyway")


def sandbox_pod(name: str) -> str:
    """The pod OpenShell created for this sandbox, in the gateway namespace — or '' if not found yet."""
    for _ in range(20):
        out = k8s.kubectl("-n", GW_NS, "get", "pods", "--no-headers", check=False)
        for line in out.splitlines():
            fields = line.split()
            if fields and name[:12] in fields[0]:
                return fields[0]
        time.sleep(3)
    return ""


def pod_runtime_class(pod: str) -> str:
    """`spec.runtimeClassName` read back from the pod — the runtime that ACTUALLY engaged, not the flag."""
    if not pod:
        return ""
    return k8s.kubectl("-n", GW_NS, "get", "pod", pod, "-o", "jsonpath={.spec.runtimeClassName}", check=False)


def kernel_inside(name: str) -> str:
    """`uname -r` from inside the sandbox. gVisor answers `4.19.0-gvisor`, a runc pod the node kernel."""
    return osh("sandbox", "exec", "-n", name, "--", "uname", "-r", timeout=120).stdout.strip()


def apply_policy(name: str, policy: Path) -> None:
    """Arm the OCSF writer FIRST, then reload the (network half of the) policy — the reload activates it."""
    osh("settings", "set", name, "--key", "ocsf_json_enabled", "--value", "true", timeout=120)
    osh("policy", "set", name, "--policy", str(policy), "--wait", timeout=300)


def run_suite(name: str) -> Card:
    done = osh("sandbox", "exec", "-n", name, "--", "python", "-m", "attacks.run", "--groups", GROUPS, timeout=1200)
    if done.stderr:
        print("  --- sandbox stderr (last lines) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-12:]))
    return Card.parse(done.stdout, allow_partial=True)


def landlock_witness(name: str) -> tuple[int, list[str]]:
    """The audit trail's word on Landlock — the ONLY signal that a defense layer silently vanished.

    Under gVisor the `landlock()` syscall answers ENOSYS, and OpenShell 0.0.99 emits a HIGH finding
    (`type:landlock-unavailable`, "Landlock Filesystem Sandbox Unavailable") and CONTINUES. Its
    presence is what tells you the filesystem clause lost its Landlock backing — the attack outcome
    cannot, because the read-only rootfs still blocks the write (see the README). Matched on the
    wording this CLI version actually prints, verified on the box, not the prior art's phrasing.
    """
    time.sleep(4)
    out = osh("logs", name, "--since", "20m", "-n", "500", "--source", "sandbox", timeout=120).stdout
    high = [ln for ln in out.splitlines() if "landlock" in ln.lower() and "unavailable" in ln.lower()]
    return len(high), high[:6]


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
    try:
        banner("Part 1 — The same policy as lesson 9, on a gVisor sandbox instead of runc")
        gateway = k8s.start_service(NAMESPACE, "sbx-gateway")
        collector = k8s.start_service(NAMESPACE, "sbx-collector")
        policy = render_policy(POLICY_SRC, POLICY_OUT, gateway)
        created = create_sandbox(SANDBOX, policy, gateway, collector)
        if created.returncode != 0:
            sys.exit(f"  sandbox create failed:\n{created.stdout}\n{created.stderr}")
        wait_ready(SANDBOX)

        # Assert the boundary FROM INSIDE, never from the flag: the pod's runtimeClassName, and the
        # kernel the sandbox actually reports. If either is wrong, this lesson is not measuring gVisor.
        pod = sandbox_pod(SANDBOX)
        rc = pod_runtime_class(pod)
        kernel = kernel_inside(SANDBOX)
        print(f"  sandbox pod: {pod or '(not found)'}")
        print(f"  pod .spec.runtimeClassName: {rc or '(none)'}   (expected: {RUNTIME_CLASS})")
        print(f"  kernel from inside the sandbox: {kernel or '(unknown)'}   (expected: *-gvisor)")
        if rc != RUNTIME_CLASS or "gvisor" not in kernel.lower():
            sys.exit(
                "  the sandbox is NOT running on gVisor — runtimeClassName or kernel is wrong.\n"
                "  Refusing to report: a composition lesson that quietly ran on runc measures nothing."
            )

        apply_policy(SANDBOX, policy)
        card = run_suite(SANDBOX)
        print()
        print(card.render())

        banner("The clauses that survived the swap, and the one that did not")
        # The L7 half is kernel-agnostic and must still hold; if it does not, egress is simply broken
        # and every reading is meaningless. This is lesson 9's assertion, and it is the CONTROL that
        # makes the fs_policy_write result trustworthy rather than a dead network.
        l7 = {
            "the allowed GET still reached the gateway (L7, kernel-agnostic)": card.contained("egress_gateway"),
            "the SAME host's POST was still denied (method-aware L7)": card.contained("http_method_denied"),
            "an unlisted binary was still denied (per-binary L7)": card.contained("binary_scoped"),
        }
        for label, okv in l7.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(l7.values()):
            sys.exit("  the L7 policy did not engage — the readings are not trustworthy; not reporting.")

        fs_blocked = card.contained("fs_policy_write")
        n_high, sample = landlock_witness(SANDBOX)
        print()
        print(
            f"  Landlock under gVisor: {'UNAVAILABLE' if n_high else 'available'} "
            f"({n_high} HIGH 'landlock-unavailable' audit finding(s))"
        )
        print(f"  fs_policy_write: {'BLOCKED' if fs_blocked else 'ALLOWED'}")
        if n_high and fs_blocked:
            print("\n  Both are true at once, and that is the finding. The filesystem clause lost its")
            print("  Landlock backing — silently; the sandbox kept running and reported healthy. Yet the")
            print("  write to /etc is STILL refused, because OpenShell's kubernetes driver also backs the")
            print("  read-only paths with a read-only ROOT FILESYSTEM, which needs no Landlock. So the")
            print("  lost layer is MASKED: the attack outcome is identical to the safe Kata stack")
            print("  (lesson 17), and the HIGH audit finding is the ONLY thing that differs. The lesson:")
            print("  a composed boundary can shed a layer with no visible effect — never infer 'both are")
            print("  enforcing' from 'the attack was blocked'. Verify, or make it fail closed (Part 2).")
        elif not n_high:
            print("\n  Landlock did NOT drop under gVisor here — unexpected. The composition premise is that")
            print("  gVisor answers ENOSYS to landlock(); investigate before trusting this run.")
        elif not fs_blocked:
            print("\n  The write flipped to ALLOWED — the read-only rootfs did not cover this path, so the")
            print("  Landlock loss became an observable bypass. A sharper form of the same finding.")
        print("\n  the audit trail's independent witness:")
        for line in sample:
            print(f"    {line[:160]}")

        banner("Part 2 — hard_requirement: make the silent failure refuse to start instead")
        hard = render_policy(POLICY_HARD_SRC, POLICY_HARD_OUT, gateway)
        # Passed at CREATE, never `policy set` — the Landlock section is locked at startup. The create
        # call's own exit status IS the experiment: on gVisor it should refuse rather than run degraded.
        created_hard = create_sandbox(SANDBOX_HARD, hard, gateway, collector, timeout=420)
        refused = created_hard.returncode != 0
        if refused:
            print("  create REFUSED — the sandbox failed CLOSED rather than running without Landlock:")
            tail = (created_hard.stdout + "\n" + created_hard.stderr).strip().splitlines()
            for line in tail[-4:]:
                print(f"    {line[:160]}")
        else:
            print("  create SUCCEEDED — hard_requirement did NOT fail closed here. Investigate before")
            print("  trusting best_effort's regression above; the two should be consistent.")

        banner("What this rung teaches")
        print("  gVisor closed the kernel column and OpenShell's L7 policy is untouched — but the")
        print("  filesystem clause lost its Landlock backing, silently. Here that loss was MASKED by")
        print("  the read-only rootfs, so the write stayed blocked and the attack outcome matched the")
        print("  safe Kata stack — the audit trail was the only difference. That is the danger: a")
        print("  composed boundary can shed a layer with no visible effect. hard_requirement is the")
        print("  fix — it refuses to start rather than run a policy it cannot fully enforce. Under Kata")
        print("  (lesson 17) nothing is lost, because the guest ships Landlock. The rule holds:")
        print("  composition fails when the lower layer removes a kernel feature the upper layer needs.")

        card.add({
            "name": "runtime_class", "value": rc, "contained": None, "group": "policy",
            "detail": f"read from the pod, not the flag; kernel inside: {kernel}",
        })  # fmt: skip
        card.add({
            "name": "landlock_available", "value": "unavailable" if n_high else "available", "contained": None,
            "group": "evidence",
            "detail": f"{n_high} HIGH landlock-unavailable finding(s); the read-only rootfs masks the loss",
        })  # fmt: skip
        card.add({
            "name": "landlock_hard_refused", "value": "refused" if refused else "started", "contained": refused,
            "group": "policy", "detail": "hard_requirement refuses to start when Landlock is absent — the fail-closed fix",
        })  # fmt: skip
        card.save(
            RESULTS,
            lesson=LESSON,
            mode="compose-gvisor",
            engine="k3s",
            node_kernel=platform.release(),
            runtime_class=rc,
            landlock="unavailable" if n_high else "available",
            openshell_version=version,
            boundary="OpenShell kubernetes driver stacked on gVisor (runtimeClassName: gvisor)",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        cleanup()


def box_ip_if_any() -> str | None:
    """The IP of this lesson's box, from infra's state file — or None if there is no box (lesson 9's gate)."""
    try:
        for line in STATE_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("BOX_IP="):
                return line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        return None
    return None


def run_on_box(ip: str) -> int:
    """A box is up but this is not it — run the lesson ON the box via infra/run.sh (lesson 9's delegate)."""
    runner = REPO_ROOT / "infra" / "run.sh"
    print(f"Box for {LESSON} is up ({ip}). Running the lesson ON it via infra/run.sh …\n")
    return subprocess.run([str(runner), LESSON]).returncode


def refuse_no_box() -> None:
    """No box is up — say how to start one, and exit having run NOTHING."""
    print(f"No box for {LESSON} is up — nothing to run.")
    print("This lesson only runs on the shared chapter-3 cluster (k3s + Agent Sandbox + the OpenShell")
    print("gateway + gVisor), installed on the box by its substrates. Start it, then run from here:\n")
    print("    cd ../../../infra && ./up.sh chapter-03-k8s")
    print("    uv run python -u main.py                # runs it on the box and brings the card home")
    raise SystemExit(2)


if __name__ == "__main__":
    main()
