"""Lesson 12 — Kata as a supported product, not a DIY install.

Lesson 8 stood Kata up on k3s with `kata-deploy`'s Helm chart: a DaemonSet, a containerd drop-in, a
`k8sDistribution` value that had to be right, and a set of RuntimeClasses whose names move between
releases. It worked, and it was clearly a thing you assembled.

Here the same boundary arrives as an **operator**. `KataConfig` is a two-line custom resource, the
operator drives a MachineConfig, the node reboots once, and a RuntimeClass called exactly `kata`
appears. The workload manifest is then byte-identical to lesson 8's. This is the deployment a large
audience will actually meet, and the interesting part is what it does NOT change.

**The reading that matters, and the reason this lesson cannot reuse lesson 8's assertion:** Red Hat
builds the Kata guest kernel from the same RHEL base as the node's, so `uname -r` inside the VM is
**identical** to the node's. Lesson 8 on k3s proves its VM by a differing kernel; that test run here
returns "no VM" on the rung that isolates most thoroughly. Assert by DMI, virtio and the CPU/memory
gap instead — never the kernel string. (Trap #12.)

    cd tutorial/chapter-4-openshift/lesson-12-openshift-kata && ./run.sh
"""

from __future__ import annotations

import sys
from pathlib import Path

import openshift as oc
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[3]
RESULTS = REPO_ROOT / "results" / "lesson-12.json"
NS = "sbx-lesson-12"

#: Read, never guessed — but note how much shorter the list is than lesson 8's. kata-deploy on k3s
#: registered 25 classes; the operator registers one, called `kata`. That is the productisation.
PREFERRED = "kata"

PROBE = r"""
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


def probe_pod(name: str, runtime_class: str | None) -> dict[str, object]:
    """The same pod either way. `runtime_class=None` is the ordinary runc pod, for contrast."""
    spec: dict[str, object] = {
        "restartPolicy": "Never",
        "containers": [
            {
                "name": "probe",
                "image": oc.IMAGE,
                "command": ["/bin/sh", "-c", PROBE],
                "resources": {"limits": {"memory": "256Mi", "cpu": "1"}},
            }
        ],
    }
    if runtime_class:
        spec["runtimeClassName"] = runtime_class  # <-- THE ENTIRE LESSON
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name}, "spec": spec}


def parse(logs: str) -> dict[str, str]:
    return dict(ln.split("=", 1) for ln in logs.splitlines() if "=" in ln)


def main() -> None:
    banner("Part 1 — The simplest thing that works: a two-line custom resource")
    classes = oc.oc("get", "runtimeclass", "-o", "jsonpath={.items[*].metadata.name}", check=False).split()
    print(f"  RuntimeClasses on this cluster: {classes or '(none)'}")
    if PREFERRED not in classes:
        sys.exit(
            f"  no '{PREFERRED}' RuntimeClass. The sandboxed-containers operator + KataConfig must be\n"
            "  installed first — infra/openshift-sno/install.sh does it, or see REPRODUCE.md §3.6."
        )
    csv = oc.oc(
        "get", "csv", "-n", "openshift-sandboxed-containers-operator",
        "-o", "jsonpath={.items[0].metadata.name}", check=False,
    )  # fmt: skip
    print(f"  operator: {csv or '(unknown)'}")
    print("\n  Compare lesson 8: a Helm chart, a k8sDistribution value, a DaemonSet, and 25")
    print("  RuntimeClasses to choose between. Here: one operator, one KataConfig, one class.")

    oc.ensure_namespace(NS)
    try:
        banner("Part 2 — Is it a real VM? Assert from inside, and NOT by the kernel string")
        phase, logs, _ = oc.run_pod(probe_pod("kata-probe", PREFERRED), NS)
        kata = parse(logs)
        print(f"  pod finished in phase {phase}\n")
        for k, v in kata.items():
            print(f"    {k:<12} {v}")

        node_kernel = oc.node_kernel()
        node_cpu = oc.oc("get", "node", "-o", "jsonpath={.items[0].status.capacity.cpu}", check=False)
        node_mem = oc.oc("get", "node", "-o", "jsonpath={.items[0].status.capacity.memory}", check=False)
        print("\n  the node, for contrast:")
        print(f"    {'KERNEL':<12} {node_kernel}")
        print(f"    {'NPROC':<12} {node_cpu}")
        print(f"    {'MEM':<12} {node_mem}")

        same_kernel = kata.get("KERNEL", "") == node_kernel
        dmi_kvm = "kvm" in kata.get("DMI_PRODUCT", "").lower()
        virtio = int(kata.get("VIRTIO", "0") or 0)
        mem_kb = int(kata.get("MEM_KB", "0") or 0)
        cpus = int(kata.get("NPROC", "0") or 0)

        banner("The trap this lesson exists to show")
        if same_kernel:
            print(f"  The guest kernel is IDENTICAL to the node's ({node_kernel}).")
            print("  Lesson 8 proves its VM on k3s by the kernel DIFFERING. That test, run here,")
            print("  would report NO VM — a false negative on the strongest isolation on the ladder.")
            print("  Red Hat builds the Kata guest kernel from the same RHEL base. Never assert on it.")
        else:
            print(f"  The guest kernel differs ({kata.get('KERNEL')} vs {node_kernel}).")
            print("  That is not guaranteed here and must not be relied on — see Trap #12.")

        banner("Assert Kata engaged (DMI + virtio + the resource gap, all from inside)")
        checks = {
            f"DMI names a hypervisor: {kata.get('DMI_PRODUCT')} / {kata.get('DMI_VENDOR')}": dmi_kvm,
            f"virtio devices present ({virtio}) — they exist only in a VM": virtio > 0,
            f"CPU is the VM's, not the node's ({cpus} vs {node_cpu})": cpus > 0 and cpus < int(node_cpu or 0),
            f"memory is the VM's, not the node's ({mem_kb} kB)": 0 < mem_kb < 8_000_000,
        }
        for label, okv in checks.items():
            print(f"    [{'OK' if okv else '!!'}] {label}")
        if not all(checks.values()):
            sys.exit("  boundary assertion FAILED — this pod is not running in a VM; not reporting.")

        banner("Part 3 — The same pod without the field, for contrast")
        _, runc_logs, _ = oc.run_pod(probe_pod("runc-probe", None), NS)
        runc = parse(runc_logs)
        # Width from the data, not a guess: the RHEL kernel string is 29 characters and overflowed a
        # hardcoded 26, running the two columns together in the one row a reader most wants to compare.
        w = max(len(str(v)) for v in list(kata.values()) + list(runc.values())) + 2
        print(f"    {'':<14}{'kata':<{w}}{'runc'}")
        for k in ("KERNEL", "DMI_PRODUCT", "NPROC", "VIRTIO", "MEM_KB"):
            mark = "" if kata.get(k) == runc.get(k) else "   <-- differs"
            print(f"    {k:<14}{kata.get(k, '?'):<{w}}{runc.get(k, '?')}{mark}")
        print("\n  The runc pod sees the node: its CPU count, its memory, no virtio, no KVM in DMI.")
        print("  One field moved all of that into a VM the node cannot be reached from.")

        banner("Part 4 — What this rung does and does not buy")
        print("  Peer pods and Confidential Containers are the two extensions people ask about next.")
        print("  Peer pods create the VM through a REMOTE hypervisor, which sidesteps the bare-metal")
        print("  requirement in clouds that will not give you a metal node; CoCo adds attestation.")
        print("  Both are out of scope here — this box IS metal, so the plain path is the honest one.")
        print("\n  And what it does not buy is the same as lesson 8: a VM per pod closes the kernel")
        print("  column and nothing else. Kata does not read HTTP, does not know which binary opened")
        print("  a socket, and writes nothing down. That is lesson 13.")

        card = Card([
            {"name": "kata_dmi_product", "value": kata.get("DMI_PRODUCT", "?"), "contained": dmi_kvm,
             "group": "kernel", "detail": "a VM reports its hypervisor; metal reports a motherboard"},
            {"name": "kata_virtio_devices", "value": virtio, "contained": virtio > 0,
             "group": "kernel", "detail": "virtio devices exist only inside a VM"},
            {"name": "kata_guest_cpus", "value": cpus, "contained": cpus < int(node_cpu or 0),
             "group": "kernel", "detail": f"node has {node_cpu}"},
            {"name": "kata_guest_mem_kb", "value": mem_kb, "contained": 0 < mem_kb < 8_000_000,
             "group": "kernel", "detail": f"node has {node_mem}"},
            {"name": "kata_kernel_identity", "value": kata.get("KERNEL", "?"), "contained": None,
             "group": "kernel",
             "detail": "INFO, never scored here: identical to the node's by design (Trap #12)"},
            {"name": "kata_runtimeclass", "value": PREFERRED, "contained": None, "group": "policy",
             "detail": f"registered by {csv or 'the sandboxed-containers operator'}"},
        ])  # fmt: skip
        print()
        print(card.render())
        card.save(
            RESULTS,
            lesson="lesson-12-openshift-kata",
            mode="runtimeclass",
            engine="openshift-sno",
            node_kernel=node_kernel,
            operator=csv,
            boundary=f"OpenShift sandboxed containers: runtimeClassName: {PREFERRED} (per-pod KVM VM)",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        oc.delete_namespace(NS)


if __name__ == "__main__":
    main()
