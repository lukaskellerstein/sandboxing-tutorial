"""Lesson 2.2.3 — auditing the Kata rung. The host sensor goes fully blind; the sensor moves in-guest.

Audits 1.2.3. This is the sharpest rung of the backwards-observability ladder. Under Kata the workload
runs in a per-container VM with its OWN guest kernel, so the host eBPF sensor that saw a whole
container in 2.2.1 (Tetragon) records NOTHING here — the attacks' syscalls cross the guest kernel and
never touch the host's, the one the probe lives in. Isolation reached its strongest kernel boundary on
this ladder, and observability fell to zero at the same step.

Where 2.2.2 recovered coverage by switching to a gVisor-native sensor (the sentry's own strace), a real
VM hands the operator no such readout — the guest kernel is opaque. Coverage returns only by putting a
sensor INSIDE the guest, and even there the guest kernel's audit subsystem is FENCED off from a
workload container (auditctl returns EPERM inside the guest even as root with CAP_AUDIT_CONTROL and host
namespaces — measured). The sensor that works from within a single container is a ptrace tracer: strace
traces the children it spawns, needs no audit netlink, and sees every syscall the suite makes. A
kernel-side sensor (auditd / eBPF) needs the guest's init context — a privileged pod sidecar — which is
the cluster's job, and lands in 2.3.3.

    cd ../../../../infra && ./up.sh 2.2.3   # provisions chapter-02-audit-host (podman + runsc + kata + Tetragon)
    uv run python -u main.py
"""

from __future__ import annotations

import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.2.3"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
AGENT_IMAGE = "sandboxing-tutorial/agent:latest"
STRACE_IMAGE = "sandboxing-tutorial/agent-kata-strace:latest"
RESULTS = REPO_ROOT / "results" / "2.2.3.json"
GROUPS = "reach,abuse,kernel,cost"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["-e", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []

KATA_RUNTIME = "io.containerd.kata.v2"
KERNEL_ANN = "io.katacontainers.config.hypervisor.kernel"
KPARAMS_ANN = "io.katacontainers.config.hypervisor.kernel_params"
#: The substrate resolved the BTF/AUDITSYSCALL debug kernel and left its path here; the default guest
#: kernel has neither (audit boots disabled, no /sys/kernel/btf), so the in-guest sensor needs this one.
DEBUG_KERNEL_FILE = Path("/etc/kata-containers-debug-kernel")
TRACE_DIR = Path("/tmp/sbx-kata-trace")
TETRAGON_OUT = Path("/tmp/sbx-tetragon.jsonl")
TETRAGON_POLICY = "/etc/tetragon/sbx-sandboxing.yaml"
TETRAGON_BPF_LIB = "/usr/local/lib/tetragon/bpf"
#: The same attach window 2.2.1 waits, and for the same reason — a probe that is still attaching when
#: the container starts would report a false blank, which on THIS rung is indistinguishable from the
#: finding. The zero here has to be Kata's doing, not a race.
ATTACH_SECONDS = 20

#: Identical to 1.2.3 — the same hardened container, so the containment scorecard is the one 1.2.3
#: measured (7/13) rather than a differently-confined stand-in.
HARDENING = [
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
    "--tmpfs", "/tmp:rw,exec,size=64m", "--memory", "256m", "--pids-limit", "128", "--cpus", "1",
]  # fmt: skip

LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"

#: Probes with a syscall the in-guest strace traces. A probe absent here (the k8s/env/home info rows)
#: is scored `null` and never reaches the recorded band.
_TRACEABLE = (
    "read_credentials", "exfiltrate", "cloud_metadata", "plant_backdoor", "malicious_package",
    "reverse_shell", "resource_exhaustion", "kallsyms_readable", "sys_module_count",
    "bpf", "io_uring_setup", "perf_event_open",
)  # fmt: skip


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def nerdctl() -> list[str]:
    """Rootful nerdctl over containerd — Kata is a containerd shim-v2 and cannot be driven rootless."""
    if not shutil.which("nerdctl"):
        sys.exit("  nerdctl is not installed — run infra/substrates/chapter-2/30-containerd-kata.sh")
    return ["sudo", "nerdctl"] if os.geteuid() != 0 else ["nerdctl"]


def debug_kernel() -> str:
    dk = DEBUG_KERNEL_FILE.read_text(encoding="utf-8").strip() if DEBUG_KERNEL_FILE.exists() else ""
    if not dk:
        sys.exit(f"  no debug kernel recorded at {DEBUG_KERNEL_FILE} — run chapter-2-audit/kata-debug-kernel.sh")
    return dk


def ensure_agent_image(nc: list[str]) -> None:
    """The one shared attack image, in containerd's store — the canonical measured run uses it."""
    build_dir = REPO_ROOT / "infra" / "images" / "agent"
    subprocess.run([*nc, "build", "-t", AGENT_IMAGE, str(build_dir)], check=True, capture_output=True)


def ensure_strace_image(nc: list[str]) -> None:
    """Build the in-guest-sensor image: the shared attack context + strace + the trace wrapper. The
    build context is assembled from infra/images/agent so attacks/ is byte-identical to the measured
    image; BuildKit cannot use a local containerd image as a base, so this derives from the registry."""
    agent_dir = REPO_ROOT / "infra" / "images" / "agent"
    sensor_dir = Path(__file__).parent / "guest-sensor"
    with tempfile.TemporaryDirectory() as tmp:
        ctx = Path(tmp)
        shutil.copytree(agent_dir, ctx, dirs_exist_ok=True)
        shutil.copy(sensor_dir / "guest-strace-run.sh", ctx / "guest-strace-run.sh")
        shutil.copy(sensor_dir / "Dockerfile", ctx / "Dockerfile.strace")
        subprocess.run(
            [*nc, "build", "-f", str(ctx / "Dockerfile.strace"), "-t", STRACE_IMAGE, str(ctx)],
            check=True,
            capture_output=True,
        )


def _in_container(proc: dict) -> bool:
    """True when this process sits in its OWN pid namespace — that is, inside a container.

    This replaces the obvious `process.docker` test, which is WRONG on this rung and measurably so.
    Tetragon derives that id from the cgroup, and under ROOTLESS podman it lands on the HOST-side
    runtime processes while the workload's own process gets none — the exact inverse of what the
    mapping needs. Measured 2026-08-15 on chapter-02-audit-host: the container's `/bin/cat` had no
    docker id and pid.inum=4026532425, while `/usr/bin/podman`, `/usr/bin/crun` and `/usr/bin/conmon`
    on the host carried the id with pid.inum=4026531836 (the init namespace). Gating on the id would
    have credited the workload with the runtime's execs and missed everything it actually did.

    The pid namespace is also a stricter test than the `container.id != host` clause a Falco ruleset
    would carry, because the kernel's own view cannot be fooled by a runtime's bookkeeping.

    Needs `--enable-process-ns`. Tetragon's JSON omits `is_host` when it is false, so the test is
    "the pid namespace block EXISTS and does not say host" — demanding it exist is what stops a
    missing flag from silently making every host process look like a container.
    """
    pid_ns = (proc.get("ns") or {}).get("pid")
    # `inum` must be there. Tetragon emits a synthetic `<kernel>` process whose ns block exists but is
    # EMPTY, and an empty dict is "not host" by the naive reading — which put one phantom fingerprint
    # in 2.2.3's host trail and broke that lesson's "the host sensor is fully blind" headline with a
    # 1 that was never a workload event. No identified namespace means the event cannot be attributed.
    if not isinstance(pid_ns, dict) or not pid_ns.get("inum"):
        return False
    return not pid_ns.get("is_host", False)


def _tetragon_tags() -> set[str]:
    """The `sbx_probe` fingerprints Tetragon wrote — expected EMPTY under Kata, which is the whole
    finding. Read exactly as 2.2.1 reads it (policy `tags` on process_kprobe, an exec inside a
    container for `exec`, both gated on the pid namespace), so an empty set here means the SENSOR saw
    nothing, not that this lesson parsed the trail differently from the rung it is compared against."""
    seen: set[str] = set()
    text = subprocess.run(["sudo", "cat", str(TETRAGON_OUT)], capture_output=True, text=True, check=False).stdout
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        for kind, body in event.items():
            if not isinstance(body, dict) or not _in_container(body.get("process", {})):
                continue
            if kind == "process_exec":
                seen.add("exec")
            elif kind == "process_kprobe":
                # tags and message carry the same policy-declared literal; both are read because they
                # entered the event schema in different Tetragon releases (see 2.2.1).
                for tag in [*body.get("tags", []), body.get("message", "")]:
                    m = re.match(r"^sbx_probe=(\w+)$", str(tag))
                    if m:
                        seen.add(m.group(1))
    return seen


def run_suite_kata_tetragon(nc: list[str]) -> tuple[Card, set[str]]:
    """Part 1 — the SAME hardened container as 1.2.3, under Kata, with the host Tetragon watching.
    Returns the containment card and the set of attack fingerprints Tetragon managed to record
    (expected: none)."""
    ensure_agent_image(nc)
    subprocess.run(["sudo", "rm", "-f", str(TETRAGON_OUT)], check=False)
    tetragon = subprocess.Popen(
        [
            "sudo",
            "tetragon",
            "--bpf-lib",
            TETRAGON_BPF_LIB,
            "--enable-process-ns",
            "--tracing-policy",
            TETRAGON_POLICY,
            "--export-filename",
            str(TETRAGON_OUT),
        ],  # fmt: skip
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    print(f"  Tetragon (host CO-RE eBPF) loading its policy and attaching kprobes ({ATTACH_SECONDS}s) …")
    time.sleep(ATTACH_SECONDS)
    argv = [
        *nc, "run", "--rm", "--runtime", KATA_RUNTIME, "--user", "1000:1000", *HARDENING,
        "-e", f"PROBE_GROUPS={GROUPS}", "-e", f"PROBE_NODE_KERNEL={platform.release()}", *METADATA_ENV, AGENT_IMAGE,
    ]  # fmt: skip
    print(f"  $ {' '.join(argv)}\n")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    time.sleep(3)
    subprocess.run(["sudo", "pkill", "-x", "tetragon"], check=False)
    try:
        tetragon.wait(timeout=15)
    except subprocess.TimeoutExpired:
        subprocess.run(["sudo", "pkill", "-9", "-x", "tetragon"], check=False)
    return Card.parse(done.stdout, allow_partial=True), _tetragon_tags()


def guest_exec(nc: list[str], script: str, *, debug: bool = False, audit: bool = False) -> str:
    """Run one shell snippet inside a Kata guest and return its last line. `debug` boots the debug
    kernel; `audit` adds `audit=1` to the guest cmdline (lights the guest's own audit trail)."""
    anns: list[str] = []
    if debug:
        anns += ["--annotation", f"{KERNEL_ANN}={debug_kernel()}"]
    if audit:
        anns += ["--annotation", f"{KPARAMS_ANN}=audit=1"]
    done = subprocess.run(
        [
            *nc,
            "run",
            "--rm",
            "--net",
            "none",
            "--runtime",
            KATA_RUNTIME,
            *anns,
            "--entrypoint",
            "sh",
            AGENT_IMAGE,
            "-c",
            script,
        ],  # fmt: skip
        capture_output=True,
        text=True,
        timeout=300,
    )
    out = (done.stdout or "").strip()
    return out.splitlines()[-1] if out else "?"


def assert_vm_engaged(card: Card, node_kernel: str, nc: list[str]) -> str:
    """Prove a real VM booted — the reason the host sensor is blind. Guest kernel must differ from the
    node's; egress must be genuinely open (else network rows would read BLOCKED for the wrong reason)."""
    guest_kernel = guest_exec(nc, "uname -r")
    dmi = guest_exec(nc, "cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo no-dmi")
    kernel_differs = guest_kernel not in ("?", node_kernel)
    egress_open = card.contained("exfiltrate") is False
    print(f"    guest kernel {guest_kernel}   node kernel {node_kernel}   DMI {dmi}")
    print(f"    [{'OK' if kernel_differs else '..'}] a separate guest kernel booted (not the node's)")
    print(f"    [{'OK' if egress_open else '..'}] egress genuinely open (the network this rung measures)")
    if not kernel_differs:
        sys.exit("  Kata assertion FAILED — the container ran on the node kernel. No VM was created.")
    return guest_kernel


def _trace_files() -> list[str]:
    r = subprocess.run(
        ["sudo", "bash", "-c", f"ls {TRACE_DIR}/*.log 2>/dev/null"], capture_output=True, text=True, check=False
    )
    return r.stdout.split()


def _trace_has(ere: str, files: list[str]) -> bool:
    """Whether any trace line matches the ERE — grepped on the box with -a, never read into Python."""
    if not files:
        return False
    r = subprocess.run(["sudo", "grep", "-aEl", "--", ere, *files], capture_output=True, text=True, check=False)
    return bool(r.stdout.strip())


def _connect_ips(files: list[str]) -> set[str]:
    """Destination IPs the suite connected to, from the strace `connect(...sin_addr=inet_addr("..."))`
    lines — 169.254.* is the metadata service, anything else is exfiltrate's raw egress."""
    if not files:
        return set()
    quoted = " ".join(shlex.quote(f) for f in files)
    cmd = rf"""grep -aoE 'sin_addr=inet_addr\("[0-9.]+' {quoted} | grep -oE '[0-9][0-9.]+' | sort -u"""
    r = subprocess.run(["sudo", "bash", "-c", cmd], capture_output=True, text=True, check=False)
    return set(r.stdout.split())


def run_suite_kata_strace(nc: list[str]) -> Card:
    """Part 3 — the SAME suite under the debug kernel with `audit=1`, wrapped in the in-guest strace.
    The trace lands in a bind-mounted dir on the box; the suite still prints its scorecard to stdout."""
    ensure_strace_image(nc)
    subprocess.run(["sudo", "rm", "-rf", str(TRACE_DIR)], check=False)
    subprocess.run(["sudo", "mkdir", "-p", str(TRACE_DIR)], check=False)
    subprocess.run(["sudo", "chmod", "777", str(TRACE_DIR)], check=False)
    argv = [
        *nc, "run", "--rm", "--runtime", KATA_RUNTIME,
        "--annotation", f"{KERNEL_ANN}={debug_kernel()}",
        "--annotation", f"{KPARAMS_ANN}=audit=1",
        "--user", "1000:1000", *HARDENING,
        "-v", f"{TRACE_DIR}:/trace",
        "-e", f"PROBE_GROUPS={GROUPS}", "-e", f"PROBE_NODE_KERNEL={platform.release()}", *METADATA_ENV, STRACE_IMAGE,
    ]  # fmt: skip
    print(f"  $ {' '.join(argv)}\n")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    return Card.parse(done.stdout, allow_partial=True)


def strace_recorded(card: Card) -> dict[str, str]:
    """Map each scored probe to LOGGED / NOT_LOGGED from the in-guest strace. The sensor lives in the
    guest, so — unlike the host Tetragon — it sees every syscall the suite makes."""
    files = _trace_files()
    ips = _connect_ips(files)
    has_metadata = any(ip.startswith("169.254") for ip in ips)
    has_egress = any(not ip.startswith("169.254") for ip in ips)
    execve = _trace_has(r" execve\(", files)

    def state_for(name: str) -> str:
        if name == "exfiltrate":
            return LOGGED if has_egress else NOT_LOGGED
        if name == "cloud_metadata":
            return LOGGED if has_metadata else NOT_LOGGED
        if name == "read_credentials":
            return (
                LOGGED
                if _trace_has(r'openat[0-9]*\([^,]*, "[^"]*(\.aws|id_rsa|id_ed25519|credentials|\.ssh|\.env)', files)
                else NOT_LOGGED
            )
        if name == "kallsyms_readable":
            return LOGGED if _trace_has(r'openat[0-9]*\([^,]*, "/proc/kallsyms"', files) else NOT_LOGGED
        if name == "sys_module_count":
            return LOGGED if _trace_has(r'openat[0-9]*\([^,]*, "(/proc/modules|/sys/module)', files) else NOT_LOGGED
        if name in ("plant_backdoor", "malicious_package", "reverse_shell", "resource_exhaustion"):
            return LOGGED if execve else NOT_LOGGED
        if name in ("bpf", "io_uring_setup", "perf_event_open"):
            return LOGGED if _trace_has(rf" {name}\(", files) else NOT_LOGGED
        return NO_SENSOR

    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None or finding["name"] not in _TRACEABLE:
            continue
        state = state_for(finding["name"])
        finding["recorded"] = state
        out[finding["name"]] = state
    return out


def audit_capability(nc: list[str]) -> str:
    """One reading that carries the 'why not just run auditd in the guest' point: with `audit=1` the
    debug kernel's own audit trail is alive (records in the guest ring buffer), yet a workload container
    cannot control it (auditctl -> EPERM). So a kernel-side sensor needs the guest's init context."""
    probe = (
        "dmesg 2>/dev/null | grep -c 'audit(' || echo 0; "
        "auditctl -l >/dev/null 2>&1 && echo audit-controllable || echo audit-EPERM"
    )
    out = subprocess.run(
        [
            *nc,
            "run",
            "--rm",
            "--net",
            "none",
            "--runtime",
            KATA_RUNTIME,
            "--annotation",
            f"{KERNEL_ANN}={debug_kernel()}",
            "--annotation",
            f"{KPARAMS_ANN}=audit=1",
            "--cap-add",
            "AUDIT_CONTROL",
            "--cap-add",
            "AUDIT_READ",
            "--entrypoint",
            "sh",
            AGENT_IMAGE,
            "-c",
            probe,
        ],  # fmt: skip
        capture_output=True,
        text=True,
        timeout=300,
    )
    lines = [ln for ln in out.stdout.strip().splitlines() if ln.strip()]
    records = lines[0] if lines else "?"
    control = lines[-1] if lines else "?"
    return f"guest audit records in dmesg: {records}; workload container control: {control}"


def box_ip_if_any() -> str | None:
    try:
        for line in STATE_ENV.read_text(encoding="utf-8").splitlines():
            if line.startswith("BOX_IP="):
                return line.split("=", 1)[1].strip().strip('"') or None
    except OSError:
        return None
    return None


def main() -> None:
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        ip = box_ip_if_any()
        if not ip:
            print(f"No box for {LESSON} is up. Start one:  cd ../../../../infra && ./up.sh {LESSON}")
            raise SystemExit(2)
        raise SystemExit(subprocess.run([str(REPO_ROOT / "infra" / "run.sh"), LESSON]).returncode)

    nc = nerdctl()
    node_kernel = platform.release()

    banner("Part 1 — The same hardened container as 1.2.3, under Kata, with host Tetragon watching")
    print("  A container shared the host kernel, so in 2.2.1 Tetragon saw straight through it. Kata")
    print("  the workload its OWN guest kernel in a VM. The question this rung asks is whether the host")
    print("  sensor can still see anything at all.")
    card, tetragon_tags = run_suite_kata_tetragon(nc)
    print(card.render())
    blocked, applicable = card.tally()
    print(f"\n  boundaries that held: {blocked}/{applicable}")

    banner("Assert a real VM booted (the reason the host sensor is about to read empty)")
    guest_kernel = assert_vm_engaged(card, node_kernel, nc)

    banner("Part 2 — Was any of it written down? (Tetragon, the SAME host sensor 2.2.1 used)")
    host_logged = len(tetragon_tags)
    print(f"  Tetragon recorded {host_logged} attack fingerprint(s) this run.")
    print("  A container shares the host kernel; a Kata guest does not. The attacks' syscalls were made")
    print("  against the GUEST kernel, inside the VM — they never crossed Tetragon's host probe. The")
    print("  strongest kernel boundary on this ladder is also the darkest to a host sensor.")

    banner("Part 3 — Recovering coverage: the sensor has to move INTO the guest")
    print("  A real VM gives the operator no native readout (unlike gVisor's sentry in 2.2.2). And the")
    print("  guest kernel's audit subsystem is fenced from a workload container:")
    print(f"    {audit_capability(nc)}")
    print("  So the sensor that works from inside a single container is a ptrace tracer. Re-running the")
    print("  SAME suite under an in-guest strace, on the BTF/AUDITSYSCALL debug kernel:\n")
    strace_card = run_suite_kata_strace(nc)
    recorded = strace_recorded(card)
    in_guest_logged = sum(1 for v in recorded.values() if v == LOGGED)
    for name, state in recorded.items():
        mark = "LOGGED    " if state == LOGGED else ("NOT LOGGED" if state == NOT_LOGGED else "no sensor ")
        print(f"    {name:<20} {mark}")
    print(
        f"\n  in-guest strace recorded {in_guest_logged}/{len(recorded)} attacks;  host Tetragon recorded {host_logged}."
    )
    print("  That gap is the finding: the host sensor is blind behind the VM, and coverage returns only")
    print("  by placing a sensor in the guest with the workload. A kernel-side sensor (auditd/eBPF) needs")
    print("  the guest's init context — a privileged pod sidecar — which is the cluster's job, in 2.3.3.")
    if not strace_card.complete:
        print("  (the in-guest run's sandbox did not survive the fork bomb; the probes before it are traced.)")

    card.save(
        RESULTS,
        lesson="2.2.3",
        mode="network-on",
        node_kernel=node_kernel,
        guest_kernel=guest_kernel,
        boundary="hardened container + Kata (per-container VM); host Tetragon blind, in-guest strace (phase-2 audit of 1.2.3)",
        engine="nerdctl/containerd",
        host_sensor_logged=host_logged,
        in_guest_logged=in_guest_logged,
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
    if render_report(REPO_ROOT):
        print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
