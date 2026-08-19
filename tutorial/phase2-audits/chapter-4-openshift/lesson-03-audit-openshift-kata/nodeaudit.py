"""The two sensors OpenShift gives you, and the one thing that ties a record to a pod.

Plumbing only; the findings live in ``main.py`` and the README.

**Everything here is read through the API.** ``oc adm node-logs`` serves files under the node's
``/var/log``, and ``oc debug node/<n>`` gives a shell in a pod that chroots the host — so neither
sensor needs ssh to the node, a kubeconfig on the box, or anything copied onto RHCOS. That matters
more than convenience: the node is an immutable image, and a lesson that had to log into it would be
teaching a workflow the platform is designed to prevent.
"""

from __future__ import annotations

import json
import re
import subprocess

import openshift as oc

#: The audit key every rule this module loads carries, so they can be listed and removed as a set.
KEY = "sbx_audit"

#: The image's own `USER`, and the project's assigned range. A rule is loaded for BOTH because which
#: one a pod actually gets depends on the SCC it is admitted under, and the lesson must not have to
#: run the pod once to find out. Neither uid is the ATTRIBUTION key — see `mcs_of` — they only decide
#: which syscalls the kernel bothers to record.
IMAGE_UID = 1001


def _node() -> str:
    return oc.oc("get", "nodes", "-o", "jsonpath={.items[0].metadata.name}")


def node_shell(script: str, timeout: int = 240) -> str:
    """Run a script on the node, as root, through `oc debug`.

    `-q` keeps oc's own chatter out of the output, and `chroot /host` is what makes the debug pod's
    view the node's rather than the pod's.
    """
    return subprocess.run(
        [str(oc.OC), "debug", f"node/{_node()}", "-q", "--", "chroot", "/host", "/bin/bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=oc._env(),  # noqa: SLF001 - one env builder, deliberately shared with the oc wrapper
    ).stdout


def uid_range(namespace: str) -> tuple[int, int]:
    """The project's assigned uid range, from the namespace annotation OpenShift writes."""
    raw = oc.oc(
        "get", "ns", namespace, "-o",
        "jsonpath={.metadata.annotations.openshift\\.io/sa\\.scc\\.uid-range}",
        check=False,
    )  # fmt: skip
    if "/" not in raw:
        return (IMAGE_UID, IMAGE_UID + 1)
    lo, span = raw.split("/", 1)
    return (int(lo), int(lo) + int(span))


def arm(namespace: str) -> str:
    """Load the syscall rules that make the node's auditd able to see a workload at all.

    RHCOS ships auditd RUNNING but with only two `exclude` rules — nothing that records a syscall. So
    a lesson that just read the trail would find its attacks missing and could not tell "the boundary
    hid them" from "nothing was watching", which is this repo's characteristic false blank.

    The rules are added with `auditctl` at RUN TIME, and that is a deliberate and stated compromise:
    it needs no MachineConfig, so it does not mutate the immutable OS the way the supported route
    would — and it is EPHEMERAL, lost on the next reboot. Chapter 4 teaches what OpenShift ships, and
    what it ships is a node whose audit subsystem is present and switched off for workloads.
    """
    lo, hi = uid_range(namespace)
    # RAISE THE BACKLOG FIRST, and this is not tuning — it is the difference between a measurement and
    # a coin flip. The rule below audits every `openat` the pod makes, and a Python interpreter makes
    # tens of thousands of them just importing. RHCOS ships `backlog_limit 8192`, which that flood
    # overruns; the kernel then DROPS records, and the drops are silent in the trail itself. Measured
    # on this cluster: back-to-back identical runs reported 5/13 and then 0/13 attacks recorded, which
    # is exactly the intermittency 2.1.1 documented on the no-sandbox rung and fixed the same way.
    #
    # `lost` is read back after the run (see `lost_count`) so the lesson can refuse to report a
    # NOT_LOGGED that is really a dropped record.
    return node_shell(
        f"auditctl -D >/dev/null 2>&1\n"
        f"auditctl -b 65536 >/dev/null 2>&1\n"
        f"auditctl --backlog_wait_time 60000 >/dev/null 2>&1\n"
        f"auditctl -a always,exit -F arch=b64 -S openat,open -F 'uid={IMAGE_UID}' -k {KEY} 2>&1 | head -1\n"
        f"auditctl -a always,exit -F arch=b64 -S openat,open -F 'uid>={lo}' -F 'uid<{hi}' -k {KEY} 2>&1 | head -1\n"
        f"echo loaded=$(auditctl -l | grep -c {KEY}) backlog_limit=$(auditctl -s | sed -n 's/.*backlog_limit \\([0-9]*\\).*/\\1/p')"
    )


def lost_count() -> int:
    """How many audit records the kernel DROPPED. A non-zero value invalidates every NOT_LOGGED.

    Reported by `auditctl -s` as `lost N`. This is the guard that keeps a flooded backlog from
    masquerading as a boundary that hid something.
    """
    out = node_shell("auditctl -s 2>/dev/null | tr ' ' '\\n' | grep -A1 '^lost$' | tail -1")
    for tok in out.split():
        if tok.isdigit():
            return int(tok)
    return -1


def disarm() -> None:
    """Remove every rule this module loaded. The node is shared by the whole chapter."""
    node_shell(f"auditctl -l | grep -q {KEY} && auditctl -D >/dev/null 2>&1; echo cleared")


def default_rules() -> str:
    """What auditd is watching BEFORE the lesson arms it — the honest starting point."""
    return node_shell("auditctl -l 2>&1 | head -6; echo count=$(auditctl -l 2>/dev/null | wc -l)")


def _one_log(node: str, path: str) -> str:
    return subprocess.run(
        [str(oc.OC), "adm", "node-logs", node, f"--path=audit/{path}"],
        capture_output=True,
        text=True,
        timeout=600,
        env=oc._env(),  # noqa: SLF001
    ).stdout


def trail() -> tuple[str, list[str]]:
    """The node's audit trail — the current log AND the segments it rotated into during the run.

    READING ONLY `audit.log` IS THE BUG THAT MAKES THIS LESSON INTERMITTENT, and it is 2.2.4's trap
    wearing RHCOS's clothes. The node ships `max_log_file = 8` (MB) with `max_log_file_action =
    ROTATE`, and the rule this lesson arms records every `openat` the pod makes — which a Python
    interpreter does tens of thousands of times just importing. A segment fills in well under a
    minute, so the attack's records are rotated into `audit.log.1` before the lesson reads.
    Back-to-back runs then report 4/13 and 0/13 with `lost=0` on both, because nothing was dropped —
    it simply moved.

    Chapter 2 fixed the same thing by raising `max_log_file` in `auditd.conf`. That is not available
    here: `auditd.conf` on RHCOS is part of the immutable image, and changing it means a
    MachineConfig. So the lesson reads the ROTATED SEGMENTS instead, oldest first, which mutates
    nothing and is what an operator on this platform would have to do too.

    Returns `(text, segments_read)`.
    """
    node = _node()
    listing = _one_log(node, "")
    segments = sorted(
        (ln.split()[-1] for ln in listing.splitlines() if "audit.log" in ln),
        key=lambda n: (0 if n.endswith(".log") else 1, n),
        reverse=True,
    )
    # Oldest first, so records read in the order they were written; cap at three segments (24 MB) —
    # more than one run produces, and enough that a mid-run rotation cannot hide the attack phase.
    segments = [s for s in segments if s.startswith("audit.log")][:3]
    parts = [_one_log(node, seg) for seg in segments]
    return ("\n".join(parts), segments)


_MCS_RE = re.compile(r"c\d+,c\d+")
#: The serial that ties the records of ONE audit event together: `msg=audit(<ts>:<serial>)`.
_SERIAL_RE = re.compile(r"msg=audit\([0-9.]+:(\d+)\)")


def mcs_of(pod_logs: str) -> str:
    """The pod's SELinux MCS pair — THE attribution key on this platform.

    OpenShift gives every pod its own MCS category pair, and the kernel stamps it into the `subj=`
    field of every `type=SYSCALL` record the process produces. So an audit event can be tied to one
    pod exactly, with no inference — and unlike chapter 2's pid namespace or chapter 3's container id,
    it is a label the PLATFORM assigns and the kernel enforces. (`subj=`, on the SYSCALL record — the
    PATH companion's `obj=` is the FILE's context and is a different thing; see `paths_seen`.)

    The obvious alternative, uid, is WRONG here and measurably so: the image's `USER 1001` is shared
    with node components (measured 2026-08-15 — a uid=1001 rule also caught `service-ca-operator`),
    so uid selects which syscalls are recorded but cannot say whose they were.

    Read out of the pod's own first log line rather than the pod object, because the level is assigned
    at admission and does not appear in `.status`.
    """
    for line in pod_logs.splitlines():
        if "SBX_MCS=" in line:
            m = _MCS_RE.search(line)
            if m:
                return m.group(0)
    return ""


def paths_seen(raw_trail: str, mcs: str) -> set[str]:
    """Every file path the audit trail attributes to THIS pod.

    THE SUBTLETY THAT MAKES THIS CORRECT, and it is easy to get wrong in a way that silently
    under-reports. An audit *event* is several records sharing one serial — a `type=SYSCALL` record
    plus one or more `type=PATH` companions:

        type=SYSCALL msg=audit(1786816292.381:1595): ... subj=...container_t:s0:c10,c26
        type=PATH    msg=audit(1786816292.381:1595): name="/proc/kallsyms" ... obj=...proc_t:s0

    `subj=` on the SYSCALL record is the **process's** context and carries the pod's MCS. `obj=` on
    the PATH record is the **file's** context — which carries the pod's MCS only for files in the
    container's own writable layer, and never for `/proc`, `/sys` or anything on the host. Matching
    PATH records by MCS therefore finds the backdoor the agent wrote and silently misses every
    `/proc` read it made. Measured: that spelling reported 2/13 where the truth is higher.

    So: find the serials whose SYSCALL record is this pod's, then take the names from the PATH
    records sharing those serials.

    RHCOS writes the log in ENRICHED format (interpreted fields appended without a separator), the
    same trap 2.2.4 hit on Debian — so every match here is anchored on a labelled field
    (`name="..."`, `subj=`) rather than on a whole-line shape the enrichment would break.
    """
    if not mcs:
        return set()
    ours: set[str] = set()
    for line in raw_trail.splitlines():
        if "type=SYSCALL" not in line or mcs not in line:
            continue
        m = _SERIAL_RE.search(line)
        if m:
            ours.add(m.group(1))
    if not ours:
        return set()
    out: set[str] = set()
    for line in raw_trail.splitlines():
        if "type=PATH" not in line:
            continue
        m = _SERIAL_RE.search(line)
        if not m or m.group(1) not in ours:
            continue
        n = re.search(r'name="([^"]+)"', line)
        if n:
            out.add(n.group(1))
    return out


def apiserver_events(since_marker: str = "") -> list[dict[str, object]]:
    """The kube-apiserver audit log, parsed. This is the sensor OpenShift turns on for you.

    Unlike the node's auditd, nothing has to be armed: the control plane audits every request at
    Metadata level out of the box, and `oc adm node-logs --role=master` serves it.
    """
    raw = subprocess.run(
        [str(oc.OC), "adm", "node-logs", "--role=master", "--path=kube-apiserver/audit.log"],
        capture_output=True,
        text=True,
        timeout=300,
        env=oc._env(),  # noqa: SLF001
    ).stdout
    events: list[dict[str, object]] = []
    for line in raw.splitlines():
        if since_marker and since_marker not in line:
            pass
        brace = line.find("{")
        if brace < 0:
            continue
        try:
            events.append(json.loads(line[brace:]))
        except ValueError:
            continue
    return events


def keyed_records(raw_trail: str) -> int:
    """How many records in the trail carry THIS lesson's audit key.

    The liveness guard for a rung whose whole result is a zero: it proves auditd was recording
    *something* in the window, so "nothing attributable to the pod" is a statement about the boundary
    rather than about a sensor that was never armed.
    """
    return sum(1 for line in raw_trail.splitlines() if f'key="{KEY}"' in line)
