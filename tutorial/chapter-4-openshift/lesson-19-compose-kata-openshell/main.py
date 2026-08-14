"""Lesson 19 — Composition: OpenShell over Kata, on OpenShift. The commercially-relevant proof.

Lesson 17 showed OpenShell's policy holding on Kata on k3s: a real guest kernel ships Landlock, so
the filesystem clause that vanished under gVisor (lesson 16) stays enforced. This rung runs the same
composition on the platform an enterprise actually buys it on — OpenShift's **sandboxed-containers
operator**, where Kata is the product (`RuntimeClass kata`, lesson 12) and OpenShell's policy engine
must itself pass **SCC admission** (the collision lesson 11 sets up and lesson 13 pays).

Two boundaries that each had to be *admitted* by the control plane, stacked and both enforcing:

- Kata is selected per sandbox with OpenShell's driver-config overlay landing as
  `runtimeClassName: kata` — the operator's single class, not k3s's 25.
- OpenShell's sandbox service account holds the **privileged SCC**, or its supervisor cannot build
  the nested network namespace and every sandbox dies at admission (lesson 13's preflight).

The expected reading is lesson 17's: `fs_policy_write` **blocked**, because Landlock is present in
the operator's Kata guest. **Assert the VM from inside by DMI=KVM / virtio, never the kernel string**
— Red Hat builds the guest kernel from the same RHEL base as the node's, so `uname -r` matches the
node and a kernel-difference test returns a false "no VM" (Trap #12; lesson 12; REPRODUCE.md).

    ../../../infra/openshift-sno/install.sh     bring the cluster up — ONCE, shared by lessons 10-13,19
    cd tutorial/chapter-4-openshift/lesson-19-compose-kata-openshell && ./run.sh
    ../../../infra/down.sh openshift-sno        DESTROY it — EUR 0.263/hr until you do
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import openshift as oc
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[3]
RESULTS = REPO_ROOT / "results" / "lesson-19.json"
NS = "sbx-lesson-19"
GW_NS = "openshell"
POLICY_SRC = Path(__file__).parent / "policy.yaml"
POLICY_HARD_SRC = Path(__file__).parent / "policy-hard.yaml"
POLICY_OUT = Path("/tmp/lesson-19-policy.yaml")
POLICY_HARD_OUT = Path("/tmp/lesson-19-policy-hard.yaml")

#: The lower runtime. On OpenShift the sandboxed-containers operator registers exactly ONE class,
#: called `kata` (lesson 12) — not k3s's `kata-qemu`. Selected per sandbox via the driver-config overlay.
RUNTIME_CLASS = "kata"
DRIVER_CONFIG = {"kubernetes": {"pod": {"runtime_class_name": RUNTIME_CLASS}}}

#: OpenShell caps sandbox names at 19 characters. Counted, not estimated.
SANDBOX = "sbx-l19-kata"
SANDBOX_HARD = "sbx-l19-kata-hard"

GROUPS = "kernel,policy"

#: A gateway accepts a SINGLE compute driver; this cannot share lesson 5's podman config.
OSH_ENV = {"OPENSHELL_DRIVERS": "kubernetes", "OPENSHELL_GATEWAY": "ocp"}

#: Read from inside the sandbox to prove the VM — DMI names the hypervisor and virtio devices exist
#: only in a guest. NOT the kernel string: Red Hat's Kata guest kernel matches the node's (Trap #12).
DMI_PROBE = r"""
echo "KERNEL=$(uname -r)"
echo "DMI_PRODUCT=$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
echo "DMI_VENDOR=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
echo "NPROC=$(nproc)"
echo "VIRTIO=$(ls /sys/bus/virtio/devices 2>/dev/null | wc -l)"
echo "MEM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo)"
"""


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def osh(*args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["openshell", *args],
        capture_output=True, text=True, timeout=timeout, check=False,
        env={**os.environ, **OSH_ENV},
    )  # fmt: skip


def preflight() -> str:
    """Both admissions must already be in place: the `kata` RuntimeClass, and the privileged SCC grant."""
    banner("Part 1 — Two boundaries the control plane had to admit, about to be stacked")
    if osh("--version").returncode != 0:
        sys.exit("  the openshell CLI is not on PATH — run through ./run.sh so uv provides it.")
    version = osh("--version").stdout.strip()

    classes = oc.oc("get", "runtimeclass", "-o", "jsonpath={.items[*].metadata.name}", check=False).split()
    if RUNTIME_CLASS not in classes:
        sys.exit(
            f"  no '{RUNTIME_CLASS}' RuntimeClass. The sandboxed-containers operator + KataConfig must\n"
            "  be installed first — infra/openshift-sno/install.sh does it, or see REPRODUCE.md §3.6."
        )

    # The privileged SCC grant is lesson 11 reaching into this lesson, exactly as it does lesson 13:
    # a namespaced RoleBinding, so check both scopes or a false negative aborts on a working cluster.
    subjects = oc.oc(
        "get", "rolebinding,clusterrolebinding", "-n", GW_NS, "-A",
        "-o", "jsonpath={range .items[?(@.roleRef.name=='system:openshift:scc:privileged')]}"
        "{.subjects[*].name}{'\\n'}{end}", check=False,
    )  # fmt: skip
    if "openshell-sandbox" not in subjects:
        sys.exit(
            "  The OpenShell sandbox service account does not hold the privileged SCC, so its\n"
            "  supervisor cannot build the nested network namespace it needs and every sandbox will\n"
            "  die at admission. This is lesson 11 acting on lesson 19:\n"
            "    oc adm policy add-scc-to-user privileged -z openshell-sandbox -n openshell"
        )

    status = osh("status", timeout=120).stdout
    if "Connected" not in status:
        sys.exit(f"  the in-cluster OpenShell gateway is not Connected:\n{status}")
    print(f"  openshell CLI: {version}")
    print(f"  RuntimeClass '{RUNTIME_CLASS}' present, privileged SCC granted, gateway Connected")
    return version


def render_policy(src: Path, out: Path, gateway_host: str) -> Path:
    out.write_text(src.read_text(encoding="utf-8").replace("__GATEWAY_HOST__", gateway_host), encoding="utf-8")
    return out


def probe_env(gateway: str, collector: str) -> list[str]:
    """The probes' configuration, passed at CREATE so `exec` needs no shell (which would break per-binary
    scoping — see lesson 13). PROBE_READONLY_PATH names the path `fs_policy_write` writes to."""
    pairs = {
        "PYTHONPATH": "/tmp",
        "PROBE_GATEWAY_URL": f"http://{gateway}:{oc.STANDIN_PORT}",
        "PROBE_OFFPOLICY_URL": f"http://{collector}:{oc.STANDIN_PORT}/",
        "PROBE_NODE_KERNEL": oc.node_kernel(),
        "PROBE_READONLY_PATH": "/etc/agent-probe-canary",
    }
    return [arg for k, v in pairs.items() for arg in ("--env", f"{k}={v}")]


def create_sandbox(
    name: str, policy: Path, env_args: list[str], *, timeout: int = 900
) -> subprocess.CompletedProcess[str]:
    """Create a policy-governed sandbox on the Kata runtime class. Returns the result, unraised.

    `-- echo ready`, NOT a long-lived command: `sandbox create` RUNS the command and waits for it to
    exit (lesson 13). The runtime is chosen with `--driver-config-json`; the policy is applied at
    CREATE because its Landlock section is locked at startup.
    """
    return osh(
        "sandbox", "create", "--name", name, "--no-tty", "--no-auto-providers",
        "--from", oc.IMAGE, "--driver-config-json", json.dumps(DRIVER_CONFIG),
        *env_args, "--policy", str(policy), "--", "echo", "ready",
        timeout=timeout,
    )  # fmt: skip


def wait_ready(name: str, timeout_s: int = 480) -> None:
    """`sandbox create` returns before the supervisor accepts work, and an exec then HANGS (lesson 13).
    A Kata pod widens the window further — a VM boots before the supervisor is up."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for line in osh("sandbox", "list", timeout=60).stdout.splitlines():
            if name in line and "Ready" in line:
                return
        time.sleep(5)
    print(f"  warning: {name} never reported Ready within {timeout_s}s; continuing anyway")


def sandbox_pod(name: str) -> str:
    for _ in range(30):
        for line in oc.oc("-n", GW_NS, "get", "pods", "--no-headers", check=False).splitlines():
            fields = line.split()
            if fields and name[:12] in fields[0] and "Running" in line:
                return fields[0]
        time.sleep(5)
    return ""


def pod_runtime_class(pod: str) -> str:
    if not pod:
        return ""
    return oc.oc("-n", GW_NS, "get", "pod", pod, "-o", "jsonpath={.spec.runtimeClassName}", check=False)


def dmi_from_inside(name: str) -> dict[str, str]:
    """Run the DMI/virtio probe inside the sandbox and parse it. This is the VM assertion (Trap #12)."""
    out = osh("sandbox", "exec", "-n", name, "--", "/bin/sh", "-c", DMI_PROBE, timeout=180).stdout
    return dict(ln.split("=", 1) for ln in out.splitlines() if "=" in ln)


def deliver_suite(pod: str) -> bool:
    """Copy `infra/images/agent/attacks/` into the sandbox and prove it landed (lesson 13's routine).

    The stock ubi9 image carries no attack suite, and there is no registry to bake one into on a
    `platform: none` SNO. `oc cp` into each container until the suite is visible from where the lesson
    runs it — through `openshell sandbox exec`, not `oc`.
    """
    if not pod:
        return False
    src = REPO_ROOT / "infra" / "images" / "agent" / "attacks"
    containers = oc.oc("-n", GW_NS, "get", "pod", pod, "-o", "jsonpath={.spec.containers[*].name}", check=False).split()
    print(f"  containers in the sandbox pod: {', '.join(containers) or '(none reported)'}")
    for container in containers or [""]:
        cp = [str(oc.OC), "-n", GW_NS, "cp", str(src), f"{pod}:/tmp/attacks"]
        if container:
            cp += ["-c", container]
        done = subprocess.run(
            cp, capture_output=True, text=True, timeout=300, env={**os.environ, "KUBECONFIG": str(oc.KUBECONFIG)}
        )  # fmt: skip
        if done.returncode != 0:
            print(f"  - {container or 'default'}: copy failed, {done.stderr.strip().splitlines()[-1][:120]}")
            continue
        seen = osh("sandbox", "exec", "-n", SANDBOX, "--", "/bin/sh", "-c", "ls /tmp/attacks/run.py", timeout=180)
        if seen.returncode == 0 and "run.py" in seen.stdout:
            print(f"  - {container or 'default'}: suite present at /tmp/attacks")
            return True
        print(f"  - {container or 'default'}: copied, but the sandbox cannot see it — wrong container")
    print("  ! the attack suite could not be delivered to the sandbox container")
    return False


def run_suite() -> Card | None:
    done = osh(
        "sandbox", "exec", "-n", SANDBOX, "--workdir", "/tmp", "--",
        "python3", "-m", "attacks.run", "--groups", GROUPS, timeout=1200,
    )  # fmt: skip
    if done.stderr.strip():
        print("  --- sandbox stderr (last lines) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-8:]))
    try:
        return Card.parse(done.stdout, allow_partial=True)
    except ValueError as exc:
        print(f"  ! no scorecard from the sandbox: {exc}")
        return None


def landlock_witness(name: str) -> list[str]:
    time.sleep(4)
    out = osh("logs", name, "--since", "20m", "-n", "500", "--source", "sandbox", timeout=120).stdout
    return [ln for ln in out.splitlines() if "landlock" in ln.lower()][:6]


def cleanup() -> None:
    # No `--force` — 0.0.99's `sandbox delete` has no such flag and would exit on it, leaking the
    # sandbox from this `finally` (lesson 13's note).
    osh("sandbox", "delete", SANDBOX, timeout=300)
    osh("sandbox", "delete", SANDBOX_HARD, timeout=300)
    oc.delete_namespace(NS)


def main() -> None:
    version = preflight()
    oc.ensure_namespace(NS)
    node_kernel = oc.node_kernel()
    try:
        gateway = oc.start_service(NS, "sbx-gateway")
        collector = oc.start_service(NS, "sbx-collector")
        print(f"\n  gateway   (named in the policy): {gateway}:{oc.STANDIN_PORT}")
        print(f"  collector (named nowhere)      : {collector}:{oc.STANDIN_PORT}")

        policy = render_policy(POLICY_SRC, POLICY_OUT, gateway)
        env_args = probe_env(gateway, collector)
        banner("Part 2 — A policy-governed sandbox, on Kata, with the network ON")
        created = create_sandbox(SANDBOX, policy, env_args)
        if created.returncode != 0:
            sys.exit(f"  sandbox create failed:\n{created.stdout}\n{created.stderr}")
        wait_ready(SANDBOX)
        osh("settings", "set", SANDBOX, "--key", "ocsf_json_enabled", "--value", "true", timeout=120)
        osh("policy", "set", SANDBOX, "--policy", str(policy), "--wait", timeout=300)

        pod = sandbox_pod(SANDBOX)
        rc = pod_runtime_class(pod)
        dmi = dmi_from_inside(SANDBOX)
        print(f"  sandbox pod: {pod or '(not found)'}")
        print(f"  pod .spec.runtimeClassName: {rc or '(none)'}   (expected: {RUNTIME_CLASS})")

        banner("Assert the VM from inside — DMI + virtio, NEVER the kernel string (Trap #12)")
        for k, v in dmi.items():
            print(f"    {k:<12} {v}")
        dmi_kvm = "kvm" in dmi.get("DMI_PRODUCT", "").lower() or "kvm" in dmi.get("DMI_VENDOR", "").lower()
        virtio = int(dmi.get("VIRTIO", "0") or 0)
        cpus = int(dmi.get("NPROC", "0") or 0)
        node_cpu = int(oc.oc("get", "node", "-o", "jsonpath={.items[0].status.capacity.cpu}", check=False) or 0)
        same_kernel = dmi.get("KERNEL", "") == node_kernel
        print(
            f"\n    the guest kernel {'MATCHES' if same_kernel else 'differs from'} the node's "
            f"({node_kernel}) — {'expected on RHEL; ' if same_kernel else ''}assert by DMI, not this."
        )
        checks = {
            f"runtimeClassName is '{RUNTIME_CLASS}' on the pod": rc == RUNTIME_CLASS,
            f"DMI names a hypervisor: {dmi.get('DMI_PRODUCT')} / {dmi.get('DMI_VENDOR')}": dmi_kvm,
            f"virtio devices present ({virtio}) — they exist only in a VM": virtio > 0,
            f"CPU is the VM's, not the node's ({cpus} vs {node_cpu})": 0 < cpus < node_cpu,
        }
        for label, okv in checks.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(checks.values()):
            sys.exit("  boundary assertion FAILED — this sandbox is not a Kata VM; not reporting.")

        banner("Part 3 — Deliver the suite, read the policy (the same one lesson 13 ran on runc)")
        card = run_suite() if deliver_suite(pod) else None
        if card is None:
            sys.exit(
                "  the attack suite did not run inside the sandbox, so there is nothing to report.\n"
                "  Not writing a scorecard: a lesson with no measurement is not a lesson."
            )
        print()
        print(card.render())

        l7 = {
            "the allowed GET reached the gateway (L7, kernel-agnostic)": card.contained("egress_gateway"),
            "the SAME host's POST was denied (method-aware L7)": card.contained("http_method_denied"),
            "an unlisted binary was denied (per-binary L7)": card.contained("binary_scoped"),
        }
        print()
        for label, okv in l7.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(l7.values()):
            sys.exit("  the L7 policy did not engage — the readings are not trustworthy; not reporting.")

        fs_blocked = card.contained("fs_policy_write")
        witness = landlock_witness(SANDBOX)
        print()
        if fs_blocked:
            print("  fs_policy_write: BLOCKED. The filesystem clause held on OpenShift's Kata, exactly as")
            print("  it did on k3s (lesson 17) and on runc (lesson 13). The operator's guest ships")
            print("  Landlock, so nothing regressed — this is the composition gVisor could not sustain.")
        else:
            print("  fs_policy_write: ALLOWED. Unexpected on Kata — investigate before trusting it.")
        print("\n  the audit trail's independent witness (Landlock available / ruleset built):")
        for line in witness:
            print(f"    {line[:160]}")

        banner("Part 4 — hard_requirement is satisfiable here too")
        hard = render_policy(POLICY_HARD_SRC, POLICY_HARD_OUT, gateway)
        created_hard = create_sandbox(SANDBOX_HARD, hard, env_args, timeout=600)
        started = created_hard.returncode == 0
        print(
            "  create "
            + (
                "SUCCEEDED — hard_requirement is satisfied; Landlock is really present."
                if started
                else "REFUSED — unexpected on Kata; investigate."
            )
        )

        card.add({
            "name": "runtime_class", "value": rc, "contained": None, "group": "policy",
            "detail": f"read from the pod; DMI={dmi.get('DMI_PRODUCT', '?')}, kernel matches node by design",
        })  # fmt: skip
        card.add({
            "name": "kata_dmi_product", "value": dmi.get("DMI_PRODUCT", "?"), "contained": dmi_kvm,
            "group": "kernel", "detail": "a VM reports its hypervisor; metal reports a motherboard",
        })  # fmt: skip
        card.add({
            "name": "landlock_hard_started", "value": "started" if started else "refused", "contained": started,
            "group": "policy", "detail": "hard_requirement is satisfiable when the guest ships Landlock",
        })  # fmt: skip
        card.save(
            RESULTS,
            lesson="lesson-19-compose-kata-openshell",
            mode="compose-kata",
            engine="openshift-sno",
            node_kernel=node_kernel,
            runtime_class=rc,
            openshell_version=version,
            boundary="OpenShell on OpenShift stacked on Kata (runtimeClassName: kata), through SCC admission",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        cleanup()


if __name__ == "__main__":
    main()
