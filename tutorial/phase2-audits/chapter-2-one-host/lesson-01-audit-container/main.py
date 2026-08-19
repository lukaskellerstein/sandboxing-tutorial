"""Lesson 2.2.1 — auditing the container rung. A container blocks more, but hides no more.

Audits 1.2.1. It runs the SAME suite in the SAME hardened rootless podman container that 1.2.1 does,
with **Tetragon** (a host-kernel sensor, CO-RE eBPF) watching, then reports per attack whether
Tetragon wrote it down.

The finding is the second beat of the backwards-observability thesis. A container BLOCKS more than the
bare host (1.2.1 scores 7/13 against 1.1.1's 3/13): the read-only rootfs, dropped capabilities and
cgroup caps stop several attacks. But it HIDES no more. A container shares the host kernel, so its
syscalls cross Tetragon's eBPF probe exactly as the bare host's crossed auditd in 2.1.1 — the
namespace/cgroup boundary that isolates the workload is transparent to a sensor sitting in the kernel
under it. Isolation went up; observability did not move. That only starts to change at gVisor and
Kata, where the kernel the workload talks to is no longer the one the sensor lives in.

Tetragon is the ONE host sensor phase 2 uses on every rung it applies to, and that is a measurement
decision rather than a preference: a reader comparing this rung to the k8s rung has to be able to
attribute a difference to the BOUNDARY, not to the instrument. The version is pinned by the substrate.

    cd ../../../../infra && ./up.sh 2.2.1     # provisions chapter-02-audit-host (podman + Tetragon)
    uv run python -u main.py
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "2.2.1"
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
IMAGE = "sandboxing-tutorial/agent:latest"
RESULTS = REPO_ROOT / "results" / "2.2.1.json"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["-e", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []

#: The same everyday hardening 1.2.1 applies — one throwaway container, read-only rootfs, no caps,
#: cgroup caps. The attacks still MAKE their syscalls (which Tetragon sees); several just fail to land.
HARDENING = [
    "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--read-only",
    "--tmpfs", "/tmp:rw,exec,size=64m", "--memory", "256m", "--memory-swap", "256m",
    "--pids-limit", "128", "--cpus", "1",
]  # fmt: skip

#: probe → the `sbx_probe` fingerprint its Tetragon kprobe tags. A probe absent here has nothing
#: watching it (NO_SENSOR). The two network attacks share one kprobe (a connect is a connect); the
#: four exec-based attacks share `exec`, which is not a kprobe at all — Tetragon exports process_exec
#: for every execve as a BASE event. /proc reads (sys_module_count, kallsyms_readable) and uname
#: (kernel_identity) have no hook — an honest NO_SENSOR, and the shape of a targeted policy vs.
#: auditd's catch-all in 2.1.1.
PROBE_TAG = {
    "read_credentials": "read_credentials",
    "exfiltrate": "network",
    "cloud_metadata": "network",
    "plant_backdoor": "exec",
    "malicious_package": "exec",
    "reverse_shell": "exec",
    "resource_exhaustion": "exec",
    "bpf": "bpf",
    "io_uring_setup": "io_uring_setup",
    "perf_event_open": "perf_event_open",
}
#: The three kernel-surface probes are hooked and still read NOT LOGGED, and that is the sharpest
#: finding on this rung rather than a gap in the policy. MEASURED 2026-08-15 on chapter-02-audit-host:
#: podman's default seccomp profile ALLOWs bpf and perf_event_open only with CAP_SYS_ADMIN and lists
#: io_uring_setup nowhere, so with --cap-drop ALL all three fall to its `defaultAction:
#: SCMP_ACT_ERRNO`. seccomp is evaluated in syscall_trace_enter BEFORE the sys_enter tracepoint, and a
#: filter that returns an errno never runs the syscall body — so the kprobe cannot fire, and neither
#: can any tracepoint or auditd exit hook. The proof it is seccomp and not the kernel: the node has
#: CONFIG_IO_URING=y and the same call SUCCEEDS (fd=3) under --security-opt seccomp=unconfined, and
#: perf_event_open's errno changes from EPERM (the filter) to EACCES (the kernel's own check).
#:
#: So the boundary BLOCKED these three and left no record of having done so. That is worth stating
#: plainly: a syscall refused at ENTRY is invisible to every kernel-side sensor, and the only thing
#: that can witness it is the enforcing mechanism itself (seccomp's own SECCOMP_RET_LOG / auditd
#: type=SECCOMP). Compare 2.2.2, where the sentry records all three: gVisor's kernel is in user space,
#: so the call reaches a sensor before anything refuses it.
TETRAGON_OUT = Path("/tmp/sbx-tetragon.jsonl")
TETRAGON_POLICY = "/etc/tetragon/sbx-sandboxing.yaml"
TETRAGON_BPF_LIB = "/usr/local/lib/tetragon/bpf"
#: Tetragon has to load a policy and attach five kprobes before the container starts, or the first
#: attacks run unwatched and the lesson reports a false NOT_LOGGED. Measured on this box shape:
#: attachment completes well inside this window; the same figure is what check.sh waits at provision.
ATTACH_SECONDS = 20
_TAG_RE = re.compile(r"^sbx_probe=(\w+)$")
LOGGED, NOT_LOGGED, NO_SENSOR = "LOGGED", "NOT_LOGGED", "NO_SENSOR"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def engine() -> str:
    for eng in ("podman", "docker"):
        if shutil.which(eng):
            return eng
    sys.exit("No container engine found. Install podman (preferred) or docker.")


def ensure_image(eng: str) -> None:
    build = REPO_ROOT / "infra" / "images" / "agent" / "build.sh"
    subprocess.run(["bash", str(build)], check=True, capture_output=True, env={**os.environ, "CONTAINER_ENGINE": eng})


def node_kernel(eng: str) -> str:
    out = subprocess.run(
        [eng, "run", "--rm", "--entrypoint", "uname", IMAGE, "-r"], capture_output=True, text=True, timeout=120
    )
    return out.stdout.strip() or platform.release()


def run_with_tetragon(eng: str) -> Card:
    """Start Tetragon, run the attack container, stop Tetragon. The only container alive during the
    capture is the attack, and every event is additionally required to come from inside a pid
    namespace, so the box's own systemd/ssh traffic cannot be mistaken for the workload's."""
    ensure_image(eng)
    # Read the node's kernel BEFORE the sensor starts. It costs a throwaway container, and a container
    # inside the capture window is indistinguishable from the attack's: it carries a container id and
    # it execs, so its exec event would satisfy the `exec` fingerprint on its own and mark four
    # attacks LOGGED that the workload might never have made. The only container alive while Tetragon
    # watches must be the attack.
    kernel_for_probe = node_kernel(eng)
    # Tetragon writes the trail as root; /tmp's sticky bit means the agent cannot delete a root-owned
    # file, so clear last run's with sudo rather than Path.unlink (which would raise PermissionError).
    subprocess.run(["sudo", "rm", "-f", str(TETRAGON_OUT)], check=False)
    # Load ONLY the sandboxing policy — five kprobes, each tagging the attack it fingerprints — so the
    # trail is the attack's and nothing else. Tetragon needs root for the eBPF probe. The substrate
    # leaves the shipped systemd unit disabled precisely so this instance owns the pinned BPF maps.
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
    print(f"  Tetragon loading its policy and attaching kprobes ({ATTACH_SECONDS}s) …")
    time.sleep(ATTACH_SECONDS)
    argv = [
        eng, "run", "--rm", "--user", "1000:1000", *HARDENING,
        "-e", "PROBE_GROUPS=reach,abuse,kernel,cost",
        "-e", f"PROBE_NODE_KERNEL={kernel_for_probe}", *METADATA_ENV, IMAGE,
    ]  # fmt: skip
    print(f"  $ {' '.join(argv)}\n")
    done = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    time.sleep(3)  # let Tetragon flush the last events
    # Kill by process NAME (-x), never by full command line (-f). `pkill -f 'tetragon --bpf-lib'`
    # also matches any shell whose argv contains that literal — which is how it killed check.sh's own
    # ssh wrapper. The probe must be gone before the next lesson on this shared box starts its own.
    subprocess.run(["sudo", "pkill", "-x", "tetragon"], check=False)
    try:
        tetragon.wait(timeout=15)
    except subprocess.TimeoutExpired:
        subprocess.run(["sudo", "pkill", "-9", "-x", "tetragon"], check=False)
    if done.stderr:
        print("  --- container stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[:12]))
        print()
    return Card.parse(done.stdout)


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


def tetragon_tags_seen() -> set[str]:
    """The set of `sbx_probe` fingerprints Tetragon recorded, from its JSON export.

    Two event shapes carry them. A `process_kprobe` carries the policy's own `tags` array, which is a
    real field rather than a substring of a rendered message — the mapping is by field, not by
    scraping. A `process_exec` carries no tag at all (it is a base event, not a policy hit), so an
    exec inside a container IS the `exec` fingerprint.

    Both are gated on `_in_container` — the process's own pid namespace — which is what keeps the
    box's own sshd, systemd and the container RUNTIME out of the trail. Without it a host-side connect
    would read as the workload's exfiltration.
    """
    seen: set[str] = set()
    try:
        text = subprocess.run(["sudo", "cat", str(TETRAGON_OUT)], capture_output=True, text=True, check=False).stdout
    except OSError:
        return seen
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
                # `tags` and `message` are both declared by the policy and carry the same literal, so
                # reading either is reading a policy field — not scraping a rendered output string.
                # Both are checked because the two fields entered the event schema in different
                # Tetragon releases, and a pin that moves should not silently blank the trail.
                for tag in [*body.get("tags", []), body.get("message", "")]:
                    m = _TAG_RE.match(str(tag))
                    if m:
                        seen.add(m.group(1))
    return seen


def tetragon_recorded(card: Card) -> dict[str, str]:
    """Resolve each scored probe to LOGGED / NOT_LOGGED / NO_SENSOR from Tetragon's fingerprints."""
    tags = tetragon_tags_seen()
    out: dict[str, str] = {}
    for finding in card.findings:
        if finding["contained"] is None:
            continue
        name = finding["name"]
        tag = PROBE_TAG.get(name)
        if tag is None:
            state = NO_SENSOR
        else:
            state = LOGGED if tag in tags else NOT_LOGGED
        finding["recorded"] = state
        out[name] = state
    return out


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
    print(f"    cd ../../../../infra && ./up.sh {LESSON}")
    print("    uv run python -u main.py")
    raise SystemExit(2)


def main() -> None:
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        ip = box_ip_if_any()
        if not ip:
            refuse_no_box()
            return
        raise SystemExit(run_on_box(ip))

    eng = engine()
    banner("Part 1 — The same hardened container as 1.2.1, but Tetragon is watching")
    print("  A container is a real boundary: read-only rootfs, dropped caps, cgroup caps. It BLOCKS")
    print("  several attacks 1.1.1 could not. The question phase 2 asks is whether it also HIDES them.")

    card = run_with_tetragon(eng)
    print(card.render())
    blocked, applicable = card.tally()
    print(f"\n  boundaries that held: {blocked}/{applicable}  (a container blocks more than the bare host)")

    banner("Part 2 — Was any of it written down? (Tetragon, the host eBPF sensor)")
    recorded = tetragon_recorded(card)
    logged = sum(1 for v in recorded.values() if v == LOGGED)
    for name, state in recorded.items():
        mark = "LOGGED    " if state == LOGGED else ("NOT LOGGED" if state == NOT_LOGGED else "no sensor ")
        print(f"    {name:<20} {mark}")
    print(f"\n  {logged}/{len(recorded)} attacks crossed Tetragon's probe and were written down.")
    print("  A container shares the host kernel, so Tetragon sees straight through the namespace")
    print("  boundary that isolates it — the same coverage 2.1.1's auditd had on the bare host.")
    print("  Isolation went up from 1.1.1; observability did NOT. That trade turns at gVisor and Kata.")
    print()
    print("  The three NOT LOGGED rows are the sharp edge. bpf / io_uring_setup / perf_event_open are")
    print("  hooked, and still leave no record: podman's default seccomp refuses them at syscall ENTRY,")
    print("  before the syscall body and so before any kprobe, tracepoint or audit exit hook. The")
    print("  boundary BLOCKED them and forgot it did. Only the enforcing mechanism itself could say so")
    print("  (seccomp's SECCOMP_RET_LOG), and 2.2.2 shows the contrast: gVisor's kernel is in user")
    print("  space, so the sentry sees all three before anything refuses them.")

    kernel = card.get("kernel_identity")
    card.save(
        RESULTS,
        lesson="2.2.1",
        mode="network-on",
        node_kernel=str(kernel["value"]) if kernel else platform.release(),
        boundary="hardened rootless container + host Tetragon (phase-2 audit of 1.2.1)",
        engine=eng,
    )
    print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
    if render_report(REPO_ROOT):
        print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
