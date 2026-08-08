"""Lesson 8 — the same kernel result as gVisor, by a completely different route.

Lesson 7 changed one field and got a **user-space** kernel. This lesson changes the same field and
gets a **real Linux kernel, in its own VM, per pod**. The workload manifest differs from lesson 6's
by one line, exactly as lesson 7's did — but everything under it is different, and the scorecard
shows where that matters.

This is also where chapter 2's awkwardness pays off. Lesson 4 had to stand up a whole second
container stack (containerd + nerdctl beside podman) because Kata is a containerd shim-v2 and podman
cannot drive it. On a cluster that cost simply vanishes: containerd is already what the kubelet talks
to, so Kata is a node install plus a RuntimeClass.

**The RuntimeClass name is read, never guessed.** kata-deploy registers one class per enabled shim
and the set moves between releases, so this lesson asks the cluster what exists rather than assuming
`kata` or `kata-qemu`.

Two readings deserve attention before you see them:

* Kata's guest kernel is **less hardened than the node's**, so ``bpf()`` and ``io_uring_setup``
  *reopen* here after a plain pod refused them. Lesson 4 measured the same reversal. A stronger
  isolation boundary is not a uniformly stronger scorecard, which is why the syllabus says to read
  the matrix and never the count.
* The famous per-pod VM boot tax is **printed rather than asserted**. The prior art measured that
  scheduling swamped it; a lesson that claims a tax without showing the number teaches folklore.

    cd tutorial/lesson-08-k8s-kata && uv sync && uv run python -u main.py
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
NAMESPACE = "sbx-lesson-08"
RESULTS = REPO_ROOT / "results" / "lesson-08.json"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")

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
POLICY_SETTLE_S = 20


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def pick_runtime_class() -> str:
    """Ask the cluster which Kata class it has. Never hardcode it — the syllabus's warning is real.

    kata-deploy registers one RuntimeClass per enabled shim (`kata-qemu`, `kata-clh`,
    `kata-qemu-runtime-rs`, ...) and which ones appear depends on the release and the node. A
    hardcoded guess fails as "RuntimeClass not found", which reads like a broken install rather than
    a stale assumption — and sends you debugging the substrate instead of the name.
    """
    classes = k8s.runtime_classes()
    print(f"  RuntimeClasses on this cluster: {classes or '(none)'}")
    kata = [c for c in classes if c.startswith("kata")]
    if not kata:
        sys.exit("  no kata* RuntimeClass exists — substrate 80-k8s-kata.sh did not register one.")
    chosen = "kata-qemu" if "kata-qemu" in kata else kata[0]
    print(f"  using: {chosen}")
    return chosen


def probe_env(gateway_ip: str) -> dict[str, str]:
    env = {
        "PROBE_GROUPS": GROUPS,
        "PROBE_NODE_KERNEL": platform.release(),
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
                "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
            }
        ],
        "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
    }
    if runtime_class:
        spec["runtimeClassName"] = runtime_class  # <-- THE ENTIRE LESSON
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "agent-kata" if runtime_class else "agent-runc", "labels": {"app": "agent-sandbox"}},
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
    """Fill in the row a dead pod could not report — see lesson 6, which meets this first.

    Kata changes *who* does the killing, and that is the interesting part. The 256Mi limit is now
    enforced by the **guest** kernel inside the VM, before the node's cgroup ever sees pressure — so
    the OOM happens one kernel further in than it did on runc.
    """
    if card.complete or card.get("resource_exhaustion") is not None:
        return card
    oom = reason == "OOMKilled"
    print(f"  ! the {label} pod did not survive the suite (terminated: {reason or 'unknown'})")
    return card.add(
        {
            "name": "resource_exhaustion",
            "value": "capped:pod-oomkilled" if oom else f"pod-died:{reason or 'unknown'}",
            "contained": True if oom else None,
            "group": "abuse",
            "detail": "the memory limit killed the pod mid-attack (host-observed, from the kubelet)",
        }
    )


def assert_kata_engaged(card: Card, runtime_class: str, dmi: str) -> None:
    """Prove a real VM booted. Either witness suffices; neither is available everywhere.

    Two independent readings, and the honest logic is **or**, not **and**:

    * **A different kernel is decisive.** If the sandbox reports a kernel the node is not running,
      something booted its own. Nothing else explains it.
    * **DMI is the fallback for the case that defeats the kernel test** — a host where the guest
      kernel legitimately *matches* the node's. Red Hat builds Kata's guest kernel from the same
      RHEL base, so on OpenShift the strings are identical and "different kernel" would report no VM
      where there plainly is one. Chapter 4 confirmed a real VM there by DMI (`sys_vendor=KVM`).

    Requiring BOTH — which this function did at first — fails on the very cluster it was written for.
    Measured here: neither `kata-clh` nor `kata-qemu` exposes `/sys/class/dmi` at all, because a
    minimal guest need not build SMBIOS support in. The kernel was `6.18.35` against the node's
    `6.8.0-106-generic`, so the VM was never in doubt; only the assertion was wrong.
    """
    ident = card.get("kernel_identity")
    reported = str(ident["value"]) if ident else "(missing)"
    kernel_differs = ident is not None and ident["contained"] is True
    dmi_proves = bool(dmi) and "no such file" not in dmi.lower()

    print(f"    kernel: sandbox={reported}  node={platform.release()}  -> {'differs' if kernel_differs else 'SAME'}")
    print(f"    DMI   : {dmi or '(absent)'}{'' if dmi_proves else '  (not available in this guest)'}")
    checks = {
        "a real VM booted (a differing kernel, or DMI naming a hypervisor)": kernel_differs or dmi_proves,
        "the ALLOWED destination still works (a policy, not a dead network)": (
            card.contained("egress_gateway") is True
        ),
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit(f"  boundary assertion FAILED — no VM under runtimeClassName {runtime_class}; not reporting.")


def main() -> None:
    ensure_image()
    runtime_class = pick_runtime_class()
    k8s.ensure_namespace(NAMESPACE)
    try:
        banner("Part 1 — The simplest thing that works: still one field")
        print("  The manifest is lesson 6's. The entire difference is:\n")
        print(f"      spec:\n        runtimeClassName: {runtime_class}\n")
        print("  ...but underneath it, a whole Linux kernel boots in its own VM, per pod.")
        gateway_ip = k8s.start_gateway(NAMESPACE)
        k8s.apply(network_policy(), NAMESPACE)
        print(f"  gateway pod at {gateway_ip}:{k8s.GATEWAY_PORT}, NetworkPolicy applied (both as lesson 6)")

        banner("Part 2 — Turn the rogue agent loose, inside a per-pod VM")
        # Read, but never required — see assert_kata_engaged. A minimal guest kernel need not build
        # SMBIOS support in, and neither kata-clh nor kata-qemu exposes /sys/class/dmi here.
        #
        # Normalised to "absent" rather than kept as `cat`'s error text. The raw string would end up
        # in the saved card as a `guest_dmi` value that reads like a reading, and a scorecard field
        # whose content is really an error message is how a later comparison gets confused.
        raw_dmi = k8s.read_from_pod(NAMESPACE, runtime_class, ["cat", "/sys/class/dmi/id/sys_vendor"], name="dmi-probe")
        dmi = "" if (not raw_dmi or "no such file" in raw_dmi.lower()) else raw_dmi
        print(f"  DMI sys_vendor from inside the sandbox: {dmi or 'absent (this guest exposes no DMI)'}\n")
        phase, logs, reason = k8s.run_pod(agent_pod(gateway_ip, runtime_class), NAMESPACE)
        print(f"  pod finished in phase {phase} (terminated: {reason or 'n/a'})\n")
        card = merge_pod_death(Card.parse(logs, allow_partial=True), reason, "kata")
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        banner("Assert Kata engaged (a differing kernel OR DMI, from inside — never from the field posted)")
        assert_kata_engaged(card, runtime_class, dmi)

        banner("Part 3 — What just changed (the SAME pod without the field, on this same box)")
        prev_phase, prev_logs, prev_reason = k8s.run_pod(agent_pod(gateway_ip, None), NAMESPACE)
        print(f"  the runc pod finished in phase {prev_phase} (terminated: {prev_reason or 'n/a'})\n")
        prev = merge_pod_death(Card.parse(prev_logs, allow_partial=True), prev_reason, "runc")
        print(card.diff_against(prev, "pod (runc)", "pod (kata)"))
        print("\n  Look for rows marked OPENED, because there usually are some. Kata's guest kernel is")
        print("  a stock kernel, and it is LESS hardened than the node Ubuntu spent effort on — so")
        print("  bpf() and io_uring can start succeeding here after a plain pod refused them. The")
        print("  boundary is stronger and the scorecard is not uniformly better. Read the matrix,")
        print("  never the count.")
        print("\n  Watch attack 7 too, because the same verdict arrives by a different route. The runc")
        print(f"  pod was killed outright (terminated: {prev_reason or 'n/a'}); the Kata pod")
        print(f"  finished in phase {phase} and REPORTED its own cap. The limit is enforced by the")
        print("  GUEST kernel inside the VM, one kernel further in, so it refuses the allocation")
        print("  before the node's cgroup ever sees pressure. Same cap, smaller blast radius.")
        print()
        print(card.cost_delta(prev, "pod (runc)", "pod (kata)"))
        print("\n  syscall_ms goes DOWN, which surprises people who expect a VM to cost more. Kata")
        print("  charges no interception toll — the guest kernel answers syscalls directly, and it")
        print("  is a stock kernel without the node's hardening. Compare gVisor's 2.5x in lesson 7:")
        print("  same kernel column closed, opposite cost profile.")

        banner("Part 3b — The per-pod VM boot tax, measured rather than asserted")
        kata_start = k8s.time_pod_startup(NAMESPACE, runtime_class)
        runc_start = k8s.time_pod_startup(NAMESPACE, None)
        ratio = f"{kata_start / runc_start:.2f}x" if runc_start else "n/a"
        print("  a do-nothing pod, min of 3, apply -> terminal phase:")
        print(f"    runc : {runc_start:>6.2f}s")
        print(f"    kata : {kata_start:>6.2f}s   ({ratio})")
        print("\n  That number is the point of measuring instead of asserting. 'Kata boots a VM per")
        print("  pod' is true and says nothing about what you WAIT for: scheduling, image handling")
        print("  and the kubelet's own loop are in this figure too, and the prior art found they")
        print("  swamped the boot. Whatever it says on your cluster, that is your number.")

        banner("Part 4 — What is still open (the next lesson's reason to exist)")
        for f in card.reached():
            print(f"    {f['name']:<20} {f['value']}")
        print("\n  The same rows lesson 7 left open, for the same reason: a VM per pod buys attack 8")
        print("  and buys nothing on attacks 2, 4, 5, 6 or 9. Kata does not read HTTP, does not know")
        print("  which binary opened a socket, and writes nothing down. Lesson 9 does all three.")
        print("\n  One difference from lesson 7 matters later: this is a REAL kernel, so it ships")
        print("  Landlock, which gVisor's user-space kernel answers ENOSYS to. Lesson 14 stacks a")
        print("  policy engine on both and finds that the same composition works here and silently")
        print("  fails there.")

        card.save(
            RESULTS,
            lesson="lesson-08-k8s-kata",
            mode="network-on",
            engine="k3s",
            node_kernel=platform.release(),
            boundary=f"hardened Pod, runtimeClassName: {runtime_class} (per-pod VM), scoped NetworkPolicy",
            guest_dmi=dmi,
            startup_s_kata=kata_start,
            startup_s_runc=runc_start,
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        k8s.delete_namespace(NAMESPACE)


if __name__ == "__main__":
    main()
