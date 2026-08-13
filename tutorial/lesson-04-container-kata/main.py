"""Lesson 4 — the same kernel result as gVisor, by a completely different route: a real guest VM.

gVisor closed attack 8 by *reimplementing* the kernel in user space. Kata closes it by booting a
**real Linux kernel inside a per-container virtual machine**. The scorecard rows end up looking
similar; what differs is what each one keeps, and that only bites later — a reimplementation drops
features it has not implemented (gVisor answers ``ENOSYS`` to Landlock), a real kernel ships them.

The visible cost of this rung is a **second container stack**. Kata is a containerd shim-v2, and
Podman cannot drive a shim-v2 on any OS — so this lesson stands up containerd + nerdctl alongside
podman rather than passing a different ``--runtime`` to the engine the last two lessons used. That
is not incidental: it is precisely the argument for chapter 3, where the cluster already runs
containerd and Kata collapses back into a single field.

Like every rung of this ladder it runs with the engine's **ordinary network**, and on this rung that
produces the sharpest result in the tutorial: the *strongest* kernel boundary here — a separate guest
kernel in a separate VM, with a per-container hypervisor — leaves attacks 2, 4, 5 and 6 exactly as
open as a plain ``podman run`` does. A VM boundary is not a network policy, because that distinction
lives in HTTP and no kernel reads HTTP.

**Proving a VM booted needs care.** ``uname -r`` differing from the node is good evidence here, but
it is not proof in general — on RHEL-family hosts the guest kernel is built from the same base and
the strings match. The load-bearing check is **DMI**: a virtual machine reports its hypervisor as
the system vendor, bare metal reports its motherboard manufacturer. This lesson asserts both.

Part 3b then swaps the **hypervisor** underneath that runtime — QEMU for Firecracker — and the
headline is a negative result: the isolation model does not move. Same KVM, same guest kernel, same
scorecard, so the score stays 7/13 and every row it adds is INFO. What moves is the machine: no PCI
bus, a block-device rootfs instead of a shared one, and a host-side process that weighs half as
much. Which is a *runtime* and which is a *hypervisor* is ``docs/isolation-layers.md``, not here.

    # 1. start the box (once):
    cd ../../infra && ./up.sh lesson-04-container-kata     # or press 'u' in the sbx-tui panel
    # 2. then, as often as you like (on your machine this runs the lesson ON the box):
    cd tutorial/lesson-04-container-kata && uv sync && uv run python -u main.py
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path

from scorecard import Card, Finding, render_report

REPO_ROOT = Path(__file__).resolve().parents[2]
LESSON = "lesson-04-container-kata"
#: What infra records about this lesson's box. Read only to make the refusal ACTIONABLE — "no box at
#: all" and "the box is up, you are just not on it" need different next steps. Missing means missing:
#: the leaf still runs from a clone that has never touched infra/, nothing is imported from it, and
#: nothing breaks if the file never appears.
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
IMAGE = "sandboxing-tutorial/agent:latest"
RESULTS = REPO_ROOT / "results" / "lesson-04.json"
GROUPS = "reach,abuse,kernel,cost"
# Attack 4's target, inherited from the environment rather than hardcoded, and forwarded into every
# sandbox below. `infra/run.sh` points it at the cloud this box actually runs on: Scaleway answers on
# 169.254.42.42, AWS on 169.254.169.254, and a probe aimed at the wrong one reads BLOCKED for a
# reason that has nothing to do with the boundary under test. Empty means "use the suite's default".
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["-e", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []

#: The two hypervisors this box has under Kata. Same runtime, same shim binary, same guest kernel —
#: what differs is the host-side process the guest talks to. Firecracker is NOT another rung on the
#: ladder: it sits in the slot QEMU sits in, one layer BELOW the runtime. See docs/isolation-layers.md.
KATA_RUNTIME = "io.containerd.kata.v2"
KATA_FC_RUNTIME = "io.containerd.kata-fc.v2"

#: Firecracker's device model has virtio-block and no virtio-fs, so its rootfs cannot be shared in
#: from the host the way QEMU's is — it has to arrive as a block device. `--snapshotter devmapper`
#: is that requirement, visible at the point of use rather than buried in a config file. Without it
#: the container dies mounting its own rootfs (ENOENT), which reads like a Kata bug and is storage.
FC_SNAPSHOTTER = "devmapper"

#: What each hypervisor's host-side process is called in `ps`. `comm` is truncated to 15 characters,
#: which is why QEMU is matched on a prefix rather than on `qemu-system-x86_64`.
_VMM_COMM = {KATA_RUNTIME: "qemu-system", KATA_FC_RUNTIME: "firecracker"}

# Identical to lessons 2 and 3, minus podman's spelling. nerdctl takes the same flags, which is
# lucky rather than guaranteed — the point is that the caps are the same numbers.
HARDENING = [
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/tmp:rw,exec,size=64m",
    "--memory", "256m",
    "--pids-limit", "128",
    "--cpus", "1",
]  # fmt: skip


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def preflight() -> list[str]:
    """Refuse to pretend. Returns the nerdctl argv prefix, or exits with what is actually missing.

    Every failure mode here produces a *different* wrong lesson if it is papered over, so each is
    named. The Apple Silicon case in particular is not a missing package: the tutorial measured it
    (see syllabus § Verified on this hardware) and a guest kernel genuinely boots — host↔guest vsock
    is what never connects, because libkrun already owns the vsock domain.
    """
    problems: list[str] = []

    if platform.system() != "Linux":
        sys.exit(
            "  Kata cannot run here.\n"
            f"  This is {platform.system()}; Kata needs a Linux host with hardware virtualisation.\n"
            "  On an Apple Silicon Mac it fails even inside the podman machine: a guest kernel boots,\n"
            "  but host<->guest vsock times out because libkrun already owns the vsock domain\n"
            "  (measured — see syllabus § Verified on this hardware). There is no workaround.\n"
            "  Run this lesson on its box:  cd infra && ./up.sh lesson-04-container-kata\n"
            "                               ./run.sh lesson-04-container-kata"
        )

    if not Path("/dev/kvm").exists():
        problems.append("/dev/kvm is absent — Kata needs hardware virtualisation, not just a Linux host")
    if not Path("/dev/vhost-vsock").exists():
        problems.append("/dev/vhost-vsock is absent — the Kata runtime talks to its agent over vsock")
    if shutil.which("nerdctl") is None:
        problems.append("nerdctl is not installed — run infra/substrates/chapter-2/30-containerd-kata.sh")

    if problems:
        sys.exit("  Kata preflight failed:\n" + "\n".join(f"    - {p}" for p in problems))

    # containerd is root-only here, and so is the shim. Rootless Kata is a separate project.
    return ["sudo", "nerdctl"] if shutil.which("sudo") else ["nerdctl"]


def ensure_image(nerdctl: list[str]) -> None:
    """Build the agent image into containerd's store. Podman's store is a different store."""
    print("  building the image into containerd's store (podman's is a SEPARATE store)")
    # Every run, not just when missing: a skipped rebuild silently measures a stale suite.
    build_dir = REPO_ROOT / "infra" / "images" / "agent"
    subprocess.run([*nerdctl, "build", "-t", IMAGE, str(build_dir)], check=True, capture_output=True)


def runtime_flags(runtime: str | None) -> list[str]:
    """The flags that select one hypervisor — the whole of Part 3b's mechanism, in one place.

    Firecracker names its **snapshotter** as well as its runtime, and that second flag is not
    boilerplate: it is the storage requirement of a VMM with no virtio-fs, surfacing on the command
    line. Nothing else on this box changes snapshotter, so overlayfs stays the default and QEMU
    stays exactly where the rest of this lesson measured it.
    """
    if runtime == KATA_FC_RUNTIME:
        return ["--snapshotter", FC_SNAPSHOTTER, "--runtime", runtime]
    return ["--runtime", runtime] if runtime else []


def run_suite(nerdctl: list[str], runtime: str | None) -> tuple[Card, int]:
    # No --net flag, deliberately: the default network is what an agent that must reach a model API
    # is given, and it is what both sides of Part 3's comparison get, so a row that moves there
    # moved because of the runtime rather than the network.
    argv = [*nerdctl, "run", "--rm", "--user", "1000:1000", *HARDENING, *runtime_flags(runtime)]
    argv += ["-e", f"PROBE_GROUPS={GROUPS}", "-e", f"PROBE_NODE_KERNEL={platform.release()}", *METADATA_ENV, IMAGE]
    print(f"  $ {' '.join(argv)}\n")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    if done.stderr:
        print("  --- box stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-14:]))
        print()
    return Card.parse(done.stdout, allow_partial=True), done.returncode


def merge_sandbox_death(card: Card, rc: int, runtime: str) -> Card:
    """Same host-side rescue as lesson 3 — see its docstring. A dead box still reported a verdict."""
    if card.complete or card.get("resource_exhaustion") is not None:
        return card
    print(f"  ! the sandbox did not survive the suite (exit {rc}) — {len(card.findings)} findings streamed out")
    return card.add(
        Finding(
            name="resource_exhaustion",
            value="capped:sandbox-killed",
            contained=True,
            group="abuse",
            detail=f"{runtime} sandbox exited {rc} mid-attack (host-observed)",
        )
    )


def guest_exec(nerdctl: list[str], script: str, runtime: str = KATA_RUNTIME) -> str:
    """Run one shell snippet inside a Kata guest, under the SAME hardening the measured run used.

    Repeating the hardening flags is not belt-and-braces: an evidence container that is *less*
    confined than the measured one is not evidence about the measured one — it would, for instance,
    report a writable rootfs for a run that had a read-only one.

    ``runtime`` defaults to QEMU because every reading in Parts 1-3 is about the guest this lesson
    measured. Part 3b passes the Firecracker runtime to ask the same questions of the other one.
    """
    done = subprocess.run(
        [
            *nerdctl,
            "run",
            "--rm",
            "--user",
            "1000:1000",
            *HARDENING,
            *runtime_flags(runtime),
            "--entrypoint",
            "sh",
            IMAGE,
            "-c",
            script,
        ],  # fmt: skip
        capture_output=True,
        text=True,
        timeout=300,
    )
    out = (done.stdout or "").strip()
    return out.splitlines()[-1] if out else "?"


def vm_evidence(nerdctl: list[str]) -> dict[str, str]:
    """Ask the guest what hardware it thinks it is on. DMI is the check that does not lie.

    ``--entrypoint sh`` is load-bearing. The agent image's entrypoint runs the attack suite and
    *ignores* the command, so ``... IMAGE uname -r`` does not run ``uname`` at all — it runs the whole
    suite, unhardened, and the "DMI reading" comes back as a page of scorecard JSON. That is not a
    hypothetical: it is what this function did on its first run, and every assertion below it silently
    compared garbage. The hardening flags are repeated here for the same reason — an evidence
    container that is *less* confined than the measured one is not evidence about the measured one.
    """

    return {
        "guest kernel": guest_exec(nerdctl, "uname -r"),
        "DMI sys_vendor": guest_exec(nerdctl, "cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo no-dmi"),
        "DMI product": guest_exec(nerdctl, "cat /sys/class/dmi/id/product_name 2>/dev/null || echo no-dmi"),
        "guest CPUs": guest_exec(nerdctl, "nproc"),
        "guest MemTotal": guest_exec(nerdctl, "awk '/MemTotal/{print int($2/1024)\"MB\"}' /proc/meminfo"),
        "guest CapEff": guest_exec(nerdctl, "awk '/CapEff/{print $2}' /proc/self/status"),
    }


#: Four readings, one guest start. Every start here boots a VM and costs seconds, and they have to
#: describe the SAME guest anyway to be about one sandbox.
#:
#: The PCI count is the load-bearing one, because the kernel string cannot tell the two hypervisors
#: apart — both boot the identical guest kernel, which is this comparison's finding rather than a
#: weakness of the probe. Firecracker boots with `pci=off` and puts virtio on MMIO; QEMU emulates a
#: PCI host bridge and hangs virtio off that. The `virtio0` symlink says which, in one string.
_HYPERVISOR_PROBE = (
    'echo "$(uname -r) '
    "$(ls /sys/bus/pci/devices 2>/dev/null | wc -l) "
    "$(readlink /sys/bus/virtio/devices/virtio0 | sed 's|.*/devices/||; s|/virtio0$||') "
    "$(grep ' / ' /proc/mounts | head -1 | cut -d' ' -f3)\""
)


def hypervisor_facts(nerdctl: list[str], runtime: str) -> dict[str, str]:
    """What machine is under this guest? Asked of the guest, never inferred from the runtime name.

    That is not a style point here. The first draft of this lesson's substrate registered the
    Firecracker runtime with a plain shim symlink; every container it started reported a perfectly
    convincing guest kernel, and every one of them was QEMU. The runtime name proved nothing, and
    only the PCI bus caught it.
    """
    fields = guest_exec(nerdctl, _HYPERVISOR_PROBE, runtime).split()
    keys = ("kernel", "pci_devices", "virtio_transport", "rootfs")
    return dict(zip(keys, fields + ["?"] * (len(keys) - len(fields)), strict=True))


def startup_seconds(nerdctl: list[str], runtime: str | None, reps: int = 3) -> float:
    """Wall clock for a do-nothing container, min of ``reps``.

    Min rather than mean, for the reason lesson 8's ``time_pod_startup`` gives: one sample on a
    shared machine measures the box's mood as much as the runtime, and the minimum is the closest
    thing to "what this costs when nothing else is in the way".

    This is the shortest path either hypervisor has — `nerdctl run` and nothing else. Lesson 8 times
    the same thing through a scheduler and a kubelet, where the prior art found the VM boot got
    swamped; if a boot advantage is visible anywhere, it is visible here.
    """
    best = float("inf")
    for _ in range(reps):
        started = time.monotonic()
        argv = [*nerdctl, "run", "--rm", "--net", "none", *runtime_flags(runtime)]
        subprocess.run([*argv, "--entrypoint", "sh", IMAGE, "-c", "true"], capture_output=True, timeout=300)
        best = min(best, time.monotonic() - started)
    return round(best, 2)


def _max_rss_mb(comm_prefix: str) -> float:
    """The largest RSS among host processes whose `comm` starts with ``comm_prefix``, in MB."""
    out = subprocess.run(["ps", "-eo", "comm=,rss="], capture_output=True, text=True, timeout=60).stdout
    sizes = [int(parts[-1]) for ln in out.splitlines() if (parts := ln.split()) and parts[0].startswith(comm_prefix)]
    return round(max(sizes) / 1024, 1) if sizes else 0.0


def vmm_rss_mb(nerdctl: list[str], runtime: str) -> float:
    """How heavy the VMM process is on the HOST while one sandbox of it is up.

    This is the only probe in the lesson that looks outward instead of inward, and it has to be:
    the guests are the same size by construction — same kernel, same rootfs, same `default_memory` —
    so nothing read from inside can show the difference between the two hypervisors. The weight is
    entirely in the host-side process, which is exactly where Firecracker's design lives.
    """
    name = f"vmm-weigh-{runtime.rsplit('.', 2)[1]}"
    subprocess.run([*nerdctl, "rm", "-f", name], capture_output=True, timeout=120)
    argv = [*nerdctl, "run", "-d", "--name", name, "--net", "none", *runtime_flags(runtime)]
    subprocess.run([*argv, "--entrypoint", "sh", IMAGE, "-c", "sleep 120"], capture_output=True, timeout=300)
    try:
        # The VMM allocates as the guest boots, so weighing it the instant `run -d` returns measures
        # a machine still coming up rather than a running one.
        time.sleep(6)
        return _max_rss_mb(_VMM_COMM[runtime])
    finally:
        subprocess.run([*nerdctl, "rm", "-f", name], capture_output=True, timeout=120)


def vmm_on_disk() -> dict[str, float]:
    """What each VMM weighs on disk, in MB — the cheapest, most vivid version of the same claim.

    kata-static ships both side by side, so this is a measurement rather than a quotation. QEMU's
    figure is its binary *plus* the firmware it loads: BIOS images, EDK2 builds and device ROMs are
    what a full device model needs and what Firecracker's five emulated devices do not have.
    """
    kata = Path("/opt/kata")
    qemu = next(iter(sorted((kata / "bin").glob("qemu-system-*"))), None)
    firmware = sum(f.stat().st_size for f in (kata / "share" / "kata-qemu").rglob("*") if f.is_file())
    return {
        "firecracker": round((kata / "bin" / "firecracker").stat().st_size / 1e6, 1),
        "qemu": round(qemu.stat().st_size / 1e6, 1) if qemu else 0.0,
        "qemu_firmware": round(firmware / 1e6, 1),
    }


#: DMI system vendors that mean "a hypervisor built this machine". Bare metal reports a motherboard
#: manufacturer here instead (Dell, Supermicro, ASUSTeK), which is what makes this the check that
#: cannot be fooled by a kernel version string.
_HYPERVISOR_VENDORS = ("qemu", "kvm", "cloud hypervisor", "bochs", "amazon ec2")


def assert_vm_engaged(card: Card, evidence: dict[str, str], node_kernel: str, node_cpus: int) -> None:
    """Prove a real VM booted — from inside it, and from more than one kind of evidence.

    Two checks are fatal. A guest kernel identical to the node's means no VM was created and the
    whole lesson is a lie. And egress must be genuinely open: if this VM came up with no network,
    every network row would read BLOCKED and the page would credit a per-container hypervisor with
    stopping exfiltration it never touched — the exact false comfort this rung exists to refute,
    since its headline finding is that a VM boundary buys *nothing* on the network axis.

    The remaining two are corroboration whose absence is worth printing but is not proof of failure:
    DMI can be masked, and a Kata config could in principle hand the guest every CPU the node has.
    """
    vendor = evidence["DMI sys_vendor"].lower()
    kernel_differs = evidence["guest kernel"] not in ("?", node_kernel)
    egress_open = card.contained("exfiltrate") is False

    checks = {
        f"guest kernel {evidence['guest kernel']} != node kernel {node_kernel}": kernel_differs,
        "egress genuinely OPEN (the network this rung claims to measure)": egress_open,
        f"DMI names a hypervisor, not a motherboard ({evidence['DMI sys_vendor']})": any(
            v in vendor for v in _HYPERVISOR_VENDORS
        ),
        f"guest is sized like a VM ({evidence['guest CPUs']} cpu) not like the node ({node_cpus})": (
            evidence["guest CPUs"] != str(node_cpus)
        ),
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '..'}] {label}")
    if not kernel_differs:
        sys.exit("  Kata assertion FAILED — the container ran on the node kernel. No VM was created.")
    if not egress_open:
        sys.exit("  Kata assertion FAILED — egress was not actually open; this run proves nothing.")


#: What `--memory` asks for, in MB. Kept next to HARDENING so the two cannot drift apart.
REQUESTED_MEMORY_MB = 256

#: Sysctls a distro hardens and an upstream kernel does not. These are the reason attack 8's syscall
#: rows can *open* on this rung while the kernel rows close.
_HARDENING_SYSCTLS = ("kernel/unprivileged_bpf_disabled", "kernel/perf_event_paranoid")


def report_guest_hardening(nerdctl: list[str]) -> dict[str, str]:
    """Compare the node's kernel hardening with the guest's — the surprise of this lesson.

    A per-container VM gives the workload *someone else's kernel*, and that cuts both ways. It is a
    far stronger boundary than a shared kernel, and it is also a kernel your distro never hardened:
    Ubuntu ships `unprivileged_bpf_disabled=2` and `perf_event_paranoid=4`, while Kata's guest boots
    with the upstream defaults `0` and `2`. So a container whose capabilities are entirely dropped
    (`CapEff: 0000000000000000`) can still create a BPF map inside the guest, because unprivileged BPF
    was never disabled there.

    That is not Kata failing. It is the honest shape of the trade: isolation improved, and the local
    hardening you were relying on did not come with it.
    """
    rows: dict[str, str] = {}
    print(f"    {'sysctl':<34} {'node':>6} {'guest':>7}")
    print("    " + "-" * 49)
    for path in _HARDENING_SYSCTLS:
        try:
            node = Path("/proc/sys", path).read_text().strip()
        except OSError:
            node = "?"
        guest = guest_exec(nerdctl, f"cat /proc/sys/{path} 2>/dev/null || echo '?'")
        rows[path] = f"node={node} guest={guest}"
        print(f"    {path:<34} {node:>6} {guest:>7}")
    print()
    print("    The guest runs upstream defaults, not your distro's. That is why a fully cap-dropped")
    print("    workload can still create a BPF map in there: nothing disabled unprivileged BPF.")
    print("    A stronger boundary, and a less-hardened kernel behind it — both are true at once.")
    return rows


def report_limit_semantics(card: Card, evidence: dict[str, str]) -> None:
    """Say out loud what the guest was actually given, because it is not what we asked for.

    This is the most useful surprise in the lesson and the easiest one to miss. Under runc the cgroup
    caps bite directly and attack 7 reports ``capped``. Under Kata the container's limits size a
    *host* cgroup around the VMM, while the workload lives inside a guest sized by Kata's own
    ``default_memory`` — so the fork bomb never meets the 256 MB ceiling and attack 7 honestly reports
    ``no-cap``. Nothing failed; the boundary simply relocated the limit, and a reader who assumes the
    flag still means what it meant one rung ago will size a production sandbox wrong.
    """
    guest_mb = evidence.get("guest MemTotal", "?")
    print(f"    asked for            --memory {REQUESTED_MEMORY_MB}m --cpus 1 --pids-limit 128")
    print(f"    the guest received   {guest_mb}, {evidence.get('guest CPUs', '?')} cpu")
    print(f"    attack 7 reported    {(card.get('resource_exhaustion') or {}).get('value')}")
    print()
    print("    Those limits sized a host cgroup around the VMM, not the kernel the workload runs on.")
    print("    The guest was sized by Kata's own default_memory instead, so the fork bomb never met")
    print("    the ceiling the flag names. To cap a Kata workload you configure the sandbox, not just")
    print("    the container — and OOM is then handled by the GUEST kernel before the node ever sees")
    print("    it, which is also why an OOM here looks different in the node's logs.")


def report_matrix_tie(kata: Card, fc: Card) -> int:
    """Does swapping the hypervisor move any row? Measured rather than asserted, and it must be.

    "Both hypervisors have the same security properties" is the kind of claim this repo does not
    let a lesson make for free — so the whole suite runs again under Firecracker and the two cards
    are diffed. The expected answer is **nothing moved**, and a boundary that is expected to change
    nothing is exactly the case where an unmeasured assertion would never be caught being wrong.

    Returns the number of rows that moved, so the caller can report a surprise instead of hiding it.
    """
    scored = [f["name"] for f in kata.findings if kata.contained(f["name"]) is not None]
    moved = [n for n in scored if kata.contained(n) != fc.contained(n)]
    print(fc.diff_against(kata, "kata-qemu", "kata-fc"))
    kata_score, applicable = kata.tally()
    fc_score, _ = fc.tally()
    print(f"\n    kata-qemu {kata_score}/{applicable}    kata-fc {fc_score}/{applicable}")
    if moved:
        print(f"\n    {len(moved)} row(s) MOVED: {', '.join(moved)}")
        print("    That is a surprise worth chasing, not a result to average away — the two")
        print("    hypervisors boot the same guest kernel, so a moved row means something other")
        print("    than the boundary changed between the runs.")
    else:
        print("\n    NOTHING moved. Every row identical, and that is the finding: the VMM is not")
        print("    the boundary. Both hypervisors sit on KVM and hand the workload the same guest")
        print("    kernel, so the thing that decides what an attack can reach is unchanged by the")
        print("    choice. Which is why this Part is scored INFO and the lesson still reads 7/13.")
    return len(moved)


def report_hypervisors(nerdctl: list[str], node_kernel: str, kata: Card) -> tuple[dict[str, object], dict[str, str]]:
    """Part 3b — the same runtime, a different machine underneath it.

    Kata is the *runtime*. The hypervisor is a component one layer BELOW it, and this box has two
    installed, so the choice is a real one rather than a description. What the reader should take
    away is the negative result first: **swapping the VMM does not change the isolation model.**
    Both sit on KVM, both boot the same guest kernel, and the scorecard would be identical row for
    row — which is why nothing here is scored and every number below is INFO.

    What does change is the host-side process the guest talks to, and that is measured on three
    axes: what the machine can do, how fast it starts, what it weighs.

    Returns ``(card fields, the Firecracker readings)`` — the second is merged into ``vm_evidence``
    at save time so the HTML report shows the guest this Part measured beside the one Part 2 did.
    """
    qemu = hypervisor_facts(nerdctl, KATA_RUNTIME)
    fc = hypervisor_facts(nerdctl, KATA_FC_RUNTIME)

    print("  Kata ships one shim binary and picks the machine from a config file. On the command")
    print("  line that is one flag — and, for Firecracker, a second one that is not decoration:\n")
    print(f"    --runtime {KATA_RUNTIME}")
    print(f"    --runtime {KATA_FC_RUNTIME} --snapshotter {FC_SNAPSHOTTER}\n")

    print("  CAPABILITIES — asked of each guest, never inferred from the flag\n")
    print(f"    {'reading':<22} {'kata-qemu':<26} {'kata-fc':<26}")
    print("    " + "-" * 74)
    for key, label in (
        ("kernel", "guest kernel"),
        ("pci_devices", "/sys/bus/pci/devices"),
        ("virtio_transport", "virtio sits on"),
        ("rootfs", "rootfs filesystem"),
    ):
        print(f"    {label:<22} {qemu[key]:<26} {fc[key]:<26}")

    # The lesson refuses to describe a machine it did not run. A guest with a PCI bus is QEMU, no
    # matter which runtime name started it — and that failure mode is real: it is what a plain
    # `containerd-shim-kata-fc-v2` symlink produces, silently, exiting 0 the whole way.
    if fc["kernel"] == node_kernel:
        sys.exit("  Firecracker assertion FAILED — the guest reports the node kernel. No VM was created.")
    if fc["pci_devices"] != "0":
        sys.exit(
            f"  Firecracker assertion FAILED — the guest has {fc['pci_devices']} PCI devices.\n"
            "  Firecracker has no PCI bus at all, so this is QEMU wearing the kata-fc runtime name."
        )

    print()
    print("    Same kernel, both times — that is the finding, not a gap in the probe. The rows that")
    print("    move are the MACHINE: Firecracker boots `pci=off` and puts virtio on MMIO, where QEMU")
    print("    emulates a PCI host bridge. And the rootfs row is the `--snapshotter` flag seen from")
    print("    the inside: with no virtio-fs to share a directory in, Firecracker takes its rootfs as")
    print("    a block device. Same isolation model, a smaller machine implementing it.")

    print("\n  THE SECURITY MATRIX — the same suite again, on the other hypervisor\n")
    fc_card, fc_rc = run_suite(nerdctl, KATA_FC_RUNTIME)
    fc_card = merge_sandbox_death(fc_card, fc_rc, "kata-fc")
    moved = report_matrix_tie(kata, fc_card)

    print("\n  SPEED — a do-nothing container, min of 3, `nerdctl run` and nothing else\n")
    startup = {
        "runc": startup_seconds(nerdctl, None),
        "kata-qemu": startup_seconds(nerdctl, KATA_RUNTIME),
        "kata-fc": startup_seconds(nerdctl, KATA_FC_RUNTIME),
    }
    for label, secs in startup.items():
        against = f"   ({secs / startup['kata-qemu']:.2f}x of kata-qemu)" if label == "kata-fc" else ""
        print(f"    {label:<12} {secs:>6.2f}s{against}")

    print("\n  WEIGHT — the host-side process, while one sandbox of each is up\n")
    rss = {"qemu": vmm_rss_mb(nerdctl, KATA_RUNTIME), "fc": vmm_rss_mb(nerdctl, KATA_FC_RUNTIME)}
    disk = vmm_on_disk()
    print(f"    {'':<12} {'RSS while running':>18} {'binary on disk':>16} {'+ firmware':>12}")
    print("    " + "-" * 60)
    print(f"    {'qemu':<12} {rss['qemu']:>15.1f} MB {disk['qemu']:>13.1f} MB {disk['qemu_firmware']:>9.1f} MB")
    print(f"    {'firecracker':<12} {rss['fc']:>15.1f} MB {disk['firecracker']:>13.1f} MB {'-':>12}")

    print()
    print("    The guests weigh the same by construction — same kernel, same rootfs, same")
    print("    default_memory — so this difference is entirely the VMM process, which is exactly")
    print("    where Firecracker's design lives: five emulated devices (virtio-net, virtio-block,")
    print("    virtio-vsock, serial, a minimal keyboard controller), no BIOS, no PCI, no ACPI.")
    print("    QEMU's firmware column is the other half of the same story — BIOS images, EDK2 builds")
    print("    and device ROMs are what a full device model needs and Firecracker never loads.")

    card_fields: dict[str, object] = {
        "startup_s_runc": startup["runc"],
        "startup_s_kata_qemu": startup["kata-qemu"],
        "startup_s_kata_fc": startup["kata-fc"],
        "vmm_rss_mb_qemu": rss["qemu"],
        "vmm_rss_mb_fc": rss["fc"],
        "vmm_disk_mb": disk,
        "hypervisor_facts": {"kata-qemu": qemu, "kata-fc": fc},
        "hypervisor_rows_moved": moved,
    }
    return card_fields, {f"kata-fc {k}": v for k, v in fc.items()}


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
    print("the rung is containerd + Kata booting a per-container guest VM through /dev/kvm and")
    print("/dev/vhost-vsock, which only the box has.")
    print("Start the box, then run it from here:\n")
    print(f"    cd ../../infra && ./up.sh {LESSON}      # or press 'u' in the sbx-tui panel")
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

    nerdctl = preflight()
    ensure_image(nerdctl)
    node_kernel = platform.release()

    banner("Part 1 — The simplest thing that works: a per-container VM")
    print(f"  node kernel: {node_kernel}")
    print("  Kata is a containerd shim-v2. Podman cannot drive a shim-v2 on any OS, so this lesson")
    print("  uses nerdctl over containerd — installed alongside podman, which is untouched (podman is")
    print("  daemonless and never looks at containerd). That second stack IS the cost of this rung,")
    print("  and it is exactly what chapter 3 removes: a cluster already runs containerd.")
    print("\n  Same flags as lessons 2 and 3:")
    print("    " + " ".join(HARDENING))

    banner("Part 2 — Turn the rogue agent loose, inside a real VM")
    kata, kata_rc = run_suite(nerdctl, KATA_RUNTIME)
    kata = merge_sandbox_death(kata, kata_rc, "kata")
    print(kata.render())
    blocked, applicable = kata.tally()
    print(f"\n  boundaries that held: {blocked}/{applicable}")

    banner("Assert a real VM booted (kernel string alone is NOT proof)")
    evidence = vm_evidence(nerdctl)
    for k, v in evidence.items():
        print(f"    {k:<16} {v}")
    print()
    assert_vm_engaged(kata, evidence, node_kernel, len(os.sched_getaffinity(0)))

    banner("A limit means something different inside a VM — read this before Part 3")
    report_limit_semantics(kata, evidence)

    banner("A guest kernel is a STRONGER boundary and a LESS-HARDENED kernel")
    sysctls = report_guest_hardening(nerdctl)

    banner("Part 3 — What just changed (the previous rung, re-run live on this same box)")
    plain, plain_rc = run_suite(nerdctl, None)
    plain = merge_sandbox_death(plain, plain_rc, "runc")
    print(kata.diff_against(plain, "container", "+ Kata"))
    print("\n  The price of the boundary:\n")
    print(kata.cost_delta(plain, "container", "+ Kata"))
    print("\n  Note what is NOT in that table: the per-container VM boot. It is real, it is the")
    print("  headline objection to Kata, and it is paid once at startup rather than per syscall —")
    print("  which is why a syscall-tax comparison flatters Kata and a startup comparison does not.")
    print("\n  Note WHICH rows moved: the kernel ones, and not one network row. Both sides ran with")
    print("  the same ordinary network, so the network rows sit identical on each and drop out of")
    print("  the diff — which is the finding rather than a gap.")

    banner("Part 3b — The same runtime, a DIFFERENT machine underneath (QEMU vs Firecracker)")
    hypervisors, fc_evidence = report_hypervisors(nerdctl, node_kernel, kata)

    banner("Part 4 — What is still open")
    for f in kata.reached():
        print(f"    {f['name']:<20} {f['value']}")
    print("\n  This is the sharpest version of the whole tutorial's argument. Kata is the STRONGEST")
    print("  kernel boundary on this ladder — a separate guest kernel in a separate VM, with a")
    print("  per-container hypervisor — and attacks 2, 4, 5 and 6 are left exactly as open as a")
    print("  plain `podman run` leaves them. A VM boundary is not a network policy: that distinction")
    print("  lives in HTTP, and no kernel reads HTTP. Spending a VM per container buys attack 8. It")
    print("  does not buy attacks 2, 4, 5 or 6, and no amount of kernel isolation ever will.")
    print("\n  Exactly the same rows gVisor left open, because Kata is strong in the same column:")
    print("  neither knows WHICH binary made a request or WHICH method it used, and neither writes")
    print("  anything down. That is lesson 5.")
    print("\n  The difference that only matters in lesson 14: this is a REAL kernel, so it ships")
    print("  Landlock. gVisor's user-space kernel answers ENOSYS to it — and a policy engine layered")
    print("  on top then silently stops enforcing filesystem rules while still looking healthy.")
    print("\n  And note which of those rows Part 3b did NOT move. Firecracker is a different machine")
    print("  under the same runtime, not a different rung: it changes what the VM is made of, not")
    print("  what the boundary is worth. The four rows above stay open under both, for the reason")
    print("  they stay open under gVisor — a hypervisor does not read HTTP either.")

    kata.save(
        RESULTS,
        lesson="lesson-04-container-kata",
        mode="network-on",
        engine="nerdctl/containerd",
        boundary="hardened container + Kata Containers (per-container VM), ordinary network",
        node_kernel=node_kernel,
        # The Firecracker readings ride along in vm_evidence because that is the dict the HTML report
        # expands into its meta block — so the second hypervisor shows up in report.html without
        # infra/report/ needing to know this lesson grew a Part 3b.
        vm_evidence={**evidence, **fc_evidence},
        guest_sysctls=sysctls,
        runtime_exit_code=kata_rc,
        **hypervisors,
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
    report = Path(__file__).parent / "report.html"
    if render_report(REPO_ROOT):
        print(f"  report written to  {report.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
