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

Part 3b then changes the same field again — ``kata-fc`` instead of ``kata-qemu`` — and swaps the
**hypervisor** under the runtime. Lesson 4 taught that mechanism on a host, where it took a shim
config and a block-device snapshotter; here the whole of it is one word in a pod spec. Two things
are worth arriving with: the security matrix comes back **identical**, because a VMM is not a
boundary; and ``kata-fc`` has been in ``kubectl get runtimeclass`` since kata-deploy was installed
while never working, because Firecracker needs storage nobody had configured. Registered is not
working.

    # 1. start the box (once):
    cd ../../../infra && ./up.sh lesson-08-k8s-kata     # or press 'u' in the sbx-tui panel
    # 2. then, as often as you like (on your machine this runs the lesson ON the box):
    cd tutorial/chapter-3-kubernetes/lesson-08-k8s-kata && uv sync && uv run python -u main.py
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

import k8s
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[3]
LESSON = "lesson-08-k8s-kata"
#: What infra records about this lesson's box. Read only to make the refusal ACTIONABLE — "no box at
#: all" and "the box is up, you are just not on it" need different next steps. Missing means missing:
#: the leaf still runs from a clone that has never touched infra/, nothing is imported from it, and
#: nothing breaks if the file never appears.
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
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


def pick_runtime_classes() -> tuple[str, str]:
    """Ask the cluster which Kata classes it has. Never hardcode one — the syllabus's warning is real.

    kata-deploy registers one RuntimeClass per enabled shim (`kata-qemu`, `kata-clh`, `kata-fc`,
    `kata-qemu-runtime-rs`, ...) and which ones appear depends on the release and the node. A
    hardcoded guess fails as "RuntimeClass not found", which reads like a broken install rather than
    a stale assumption — and sends you debugging the substrate instead of the name.

    Returns ``(qemu class, firecracker class)``. Both are read, and **being in the list is not the
    same as working**: `kata-fc` is registered on every cluster kata-deploy has touched, and until
    substrate 75 put a devmapper snapshotter on this node, naming it got you a pod that never
    started. That gap is this repo's characteristic failure wearing a RuntimeClass, which is why
    Part 3b runs a workload under it rather than trusting the listing.
    """
    classes = k8s.runtime_classes()
    print(f"  RuntimeClasses on this cluster: {len(classes)}")
    print(f"    {' '.join(classes) or '(none)'}")
    kata = [c for c in classes if c.startswith("kata")]
    if not kata:
        sys.exit("  no kata* RuntimeClass exists — substrate 80-k8s-kata.sh did not register one.")
    chosen = "kata-qemu" if "kata-qemu" in kata else kata[0]
    if "kata-fc" not in kata:
        sys.exit("  no kata-fc RuntimeClass — substrate 80-k8s-kata.sh registered no Firecracker shim.")
    print(f"  using: {chosen} for the measured rung, kata-fc for Part 3b's comparison")
    return chosen, "kata-fc"


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


def agent_pod(gateway_ip: str, runtime_class: str | None, name: str | None = None) -> dict[str, object]:
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
        "metadata": {
            "name": name or ("agent-kata" if runtime_class else "agent-runc"),
            "labels": {"app": "agent-sandbox"},
        },
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


#: Five readings, one pod start. Every start here boots a VM and costs seconds, and they have to
#: describe the SAME guest anyway to be about one sandbox.
#:
#: The PCI count is the load-bearing one, because the kernel string cannot tell the two hypervisors
#: apart — both boot the identical guest kernel, which is this comparison's finding rather than a
#: weakness of the probe. Firecracker boots `pci=off` and puts virtio on MMIO; QEMU emulates a PCI
#: host bridge and hangs virtio off that.
HYPERVISOR_PROBE = (
    'echo "$(uname -r) '
    "$(ls /sys/bus/pci/devices 2>/dev/null | wc -l) "
    "$(readlink /sys/bus/virtio/devices/virtio0 | sed 's|.*/devices/||; s|/virtio0$||') "
    "$(grep ' / ' /proc/mounts | head -1 | cut -d' ' -f3) "
    "$(ls /sys/devices/system/memory 2>/dev/null | grep -c '^memory')\""
)
_PROBE_KEYS = ("kernel", "pci_devices", "virtio_transport", "rootfs", "memory_blocks")

#: What each hypervisor's process is called on the node. `ps` truncates `comm` to 15 characters,
#: which is why QEMU is matched on a prefix rather than on `qemu-system-x86_64`.
_VMM_COMM = {"qemu": "qemu-system", "fc": "firecracker"}


def hypervisor_facts(runtime_class: str, name: str) -> dict[str, str]:
    """What machine is under this pod? Asked of the guest, never inferred from the class name."""
    fields = k8s.read_from_pod(NAMESPACE, runtime_class, ["sh", "-c", HYPERVISOR_PROBE], name=name).split()
    return dict(zip(_PROBE_KEYS, (fields + ["?"] * len(_PROBE_KEYS))[: len(_PROBE_KEYS)], strict=True))


def report_hypervisors(card: Card, gateway_ip: str, qemu_class: str, fc_class: str) -> dict[str, object]:
    """Part 3b — the same field, a different machine underneath it.

    Lesson 4 taught the *mechanism*: a hypervisor is a component below the runtime, selected by the
    config the shim loads, and Firecracker additionally needs a block-device rootfs. None of that
    survives into a pod spec. Here the entire choice collapses into the value of one field, chosen
    from a menu of RuntimeClasses that also holds `gvisor` — which is what this chapter is about.

    The finding is a negative one and it is measured rather than asserted: swapping the VMM moves
    **no row** of the security matrix. Both sit on KVM and hand the workload the same guest kernel.
    """
    print("  The whole of lesson 4's Part 3b — a shim config, a snapshotter, a block device —")
    print("  arrives here as one word:\n")
    print(f"      runtimeClassName: {qemu_class}      ->  QEMU")
    print(f"      runtimeClassName: {fc_class}        ->  Firecracker\n")
    print("  ...and that is the trap this rung is worth teaching. Both classes have been in")
    print("  `kubectl get runtimeclass` since kata-deploy was installed. Until this cluster grew a")
    print("  devmapper snapshotter, a pod naming kata-fc never started: Firecracker has no")
    print("  virtio-fs, so its rootfs must be a block device. REGISTERED IS NOT WORKING.")

    print("\n  CAPABILITIES — asked of each guest, never inferred from the field\n")
    qemu = hypervisor_facts(qemu_class, "hv-qemu")
    fc = hypervisor_facts(fc_class, "hv-fc")
    print(f"    {'reading':<24} {qemu_class:<26} {fc_class:<26}")
    print("    " + "-" * 76)
    for key, label in (
        ("kernel", "guest kernel"),
        ("pci_devices", "/sys/bus/pci/devices"),
        ("virtio_transport", "virtio sits on"),
        ("rootfs", "rootfs filesystem"),
        ("memory_blocks", "hotpluggable mem blocks"),
    ):
        print(f"    {label:<24} {qemu[key]:<26} {fc[key]:<26}")

    if fc["kernel"] == platform.release():
        sys.exit(f"  boundary assertion FAILED — the {fc_class} pod reports the NODE kernel; no VM booted.")
    if fc["pci_devices"] != "0":
        sys.exit(
            f"  boundary assertion FAILED — the {fc_class} guest has {fc['pci_devices']} PCI devices.\n"
            "  Firecracker has no PCI bus at all, so this is QEMU under the kata-fc name."
        )

    print("\n  THE SECURITY MATRIX — the same suite again, under the other hypervisor\n")
    fc_phase, fc_logs, fc_reason = k8s.run_pod(agent_pod(gateway_ip, fc_class, name="agent-kata-fc"), NAMESPACE)
    fc_card = merge_pod_death(Card.parse(fc_logs, allow_partial=True), fc_reason, "kata-fc")
    print(f"  the {fc_class} pod finished in phase {fc_phase} (terminated: {fc_reason or 'n/a'})\n")
    scored = [f["name"] for f in card.findings if card.contained(f["name"]) is not None]
    moved = [n for n in scored if card.contained(n) != fc_card.contained(n)]
    print(fc_card.diff_against(card, qemu_class, fc_class))
    qemu_score, applicable = card.tally()
    fc_score, _ = fc_card.tally()
    print(f"\n    {qemu_class} {qemu_score}/{applicable}    {fc_class} {fc_score}/{applicable}")
    if moved:
        print(f"\n    {len(moved)} row(s) MOVED: {', '.join(moved)} — a surprise worth chasing rather")
        print("    than averaging away, because the two hypervisors boot the same guest kernel.")
    else:
        print("\n    NOTHING moved, and that is the finding. The VMM is not the boundary: both sit on")
        print("    KVM and give the workload the same guest kernel, so what an attack can reach is")
        print("    unchanged by the choice. Read the matrix, never the count — and here the matrix")
        print("    says the interesting differences are somewhere other than security.")

    print("\n  SPEED — a do-nothing pod, min of 3, apply -> terminal phase\n")
    startup = {
        "runc": k8s.time_pod_startup(NAMESPACE, None),
        qemu_class: k8s.time_pod_startup(NAMESPACE, qemu_class),
        fc_class: k8s.time_pod_startup(NAMESPACE, fc_class),
    }
    for label, secs in startup.items():
        ratio = f"   ({secs / startup['runc']:.2f}x of runc)" if startup["runc"] and label != "runc" else ""
        print(f"    {label:<12} {secs:>6.2f}s{ratio}")
    print("\n    Lesson 4 measured the same two hypervisors through `nerdctl run` and Firecracker came")
    print("    out ahead. Whether that survives to here is the question this row exists to answer:")
    print("    scheduling, image handling and the kubelet's loop are all in this figure, and the")
    print("    prior art found they swamped the VM boot entirely. Whatever it says, that is your")
    print("    number — the point is that it was measured on your cluster rather than quoted.")

    print("\n  WEIGHT — the VMM process on the NODE, while one pod of each is up\n")
    rss = {
        qemu_class: k8s.vmm_footprint(NAMESPACE, qemu_class, _VMM_COMM["qemu"]),
        fc_class: k8s.vmm_footprint(NAMESPACE, fc_class, _VMM_COMM["fc"]),
    }
    for label, mb in rss.items():
        print(f"    {label:<12} {mb:>8.1f} MB RSS")
    print("\n    The only probe in this chapter that looks OUT of the sandbox rather than into it,")
    print("    and it has to: the guests are identical by construction — same kernel, same rootfs,")
    print("    same default_memory — so no reading from inside could tell them apart. The whole")
    print("    difference is the host-side process, which is where Firecracker's five emulated")
    print("    devices, no BIOS, no PCI and no ACPI actually show up.")

    return {
        # `startup_s_kata` keeps the shorter name it has always had rather than growing a `_qemu`
        # suffix to match its new neighbour: nothing downstream reads these names (Card.save passes
        # them through verbatim and infra/report/ hardcodes none), so renaming it would be churn
        # with no consumer, and the old cards would stop lining up with the new ones.
        "startup_s_runc": startup["runc"],
        "startup_s_kata": startup[qemu_class],
        "startup_s_kata_fc": startup[fc_class],
        "vmm_rss_mb_qemu": rss[qemu_class],
        "vmm_rss_mb_fc": rss[fc_class],
        "hypervisor_facts": {qemu_class: qemu, fc_class: fc},
        "hypervisor_rows_moved": len(moved),
    }


def box_ip_if_any() -> str | None:
    """The IP of this lesson's box, from infra's state file — or None if there is no box.

    A refusal decision only, never imported logic: the leaf stays runnable from a clone that has
    never touched ``infra/`` (the file is simply absent → None → "start a box first"). Nothing here
    talks to Scaleway; "state file present" is a good enough proxy for "a box is up" to tell someone
    what to do next, and being wrong only means the message points at ``run.sh`` instead of ``up.sh``.
    """
    try:
        for line in STATE_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("BOX_IP="):
                return line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        return None
    return None


def run_on_box(ip: str) -> int:
    """A box is up but this is not it — run the lesson ON the box, exactly as ./run.sh does.

    This is what makes ``uv run main.py`` the only command a reader needs: start the box, then run
    it from here as often as you like. It delegates to infra/run.sh so there is a single
    implementation of "run this lesson on its box" — that run sets SANDBOXING_TUTORIAL_DISPOSABLE=1,
    so the copy of main.py which executes ON the box takes the real path rather than delegating
    again (no loop).
    """
    runner = REPO_ROOT / "infra" / "run.sh"
    print(f"Box for {LESSON} is up ({ip}). Running the lesson ON it via infra/run.sh …\n")
    return subprocess.run([str(runner), LESSON]).returncode


def refuse_no_box() -> None:
    """No box is up — say how to start one, and exit having run NOTHING.

    The boundary this lesson measures exists only on its disposable box, so the first thing a local
    run hits is a failure that has nothing to do with the lesson. Refusing here, with the next step
    attached, is the honest version of that failure.
    """
    print(f"No box for {LESSON} is up — nothing to run.")
    print("This lesson only runs on its own disposable Scaleway box:")
    print("the rung is k3s plus the Kata RuntimeClass booting a guest kernel through /dev/kvm, which")
    print("only the box has.")
    print("Start the box, then run it from here:\n")
    print(f"    cd ../../../infra && ./up.sh {LESSON}      # or press 'u' in the sbx-tui panel")
    print("    uv run python -u main.py                # runs it on the box and brings the card home")
    raise SystemExit(2)


def main() -> None:
    # `uv run main.py` is the one command. On the disposable box it runs for real (infra sets
    # SANDBOXING_TUTORIAL_DISPOSABLE=1 there). On your machine it runs the lesson ON the box when
    # one is up, and tells you to start one when none is.
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        ip = box_ip_if_any()
        if not ip:
            refuse_no_box()
            return  # unreachable — refuse_no_box exits — but narrows ip to str for the type checker
        raise SystemExit(run_on_box(ip))

    ensure_image()
    runtime_class, fc_class = pick_runtime_classes()
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
        print("\n  Hold on to that matrix, because Part 3b runs the identical suite again on a")
        print("  DIFFERENT hypervisor — Firecracker instead of QEMU — and gets the same rows back.")
        print("  A VMM swap is not a boundary change: what decides these verdicts is the guest")
        print("  kernel, and both hypervisors hand the workload the same one.")
        print("\n  syscall_ms goes DOWN, which surprises people who expect a VM to cost more. Kata")
        print("  charges no interception toll — the guest kernel answers syscalls directly, and it")
        print("  is a stock kernel without the node's hardening. Compare gVisor's 2.5x in lesson 7:")
        print("  same kernel column closed, opposite cost profile.")

        banner("Part 3b — The same field, a DIFFERENT machine underneath (QEMU vs Firecracker)")
        hypervisors = report_hypervisors(card, gateway_ip, runtime_class, fc_class)

        banner("Part 4 — What is still open (the next lesson's reason to exist)")
        for f in card.reached():
            print(f"    {f['name']:<20} {f['value']}")
        print("\n  The same rows lesson 7 left open, for the same reason: a VM per pod buys attack 8")
        print("  and buys nothing on attacks 2, 4, 5, 6 or 9. Kata does not read HTTP, does not know")
        print("  which binary opened a socket, and writes nothing down. Lesson 9 does all three.")
        print("\n  One difference from lesson 7 matters later: this is a REAL kernel, so it ships")
        print("  Landlock, which gVisor's user-space kernel answers ENOSYS to. Lesson 17 stacks a")
        print("  policy engine on this same Kata runtime and the composition holds; lesson 16 stacks")
        print("  it on gVisor and it silently fails.")

        card.save(
            RESULTS,
            lesson="lesson-08-k8s-kata",
            mode="network-on",
            engine="k3s",
            node_kernel=platform.release(),
            boundary=f"hardened Pod, runtimeClassName: {runtime_class} (per-pod VM), scoped NetworkPolicy",
            guest_dmi=dmi,
            **hypervisors,
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        k8s.delete_namespace(NAMESPACE)


if __name__ == "__main__":
    main()
