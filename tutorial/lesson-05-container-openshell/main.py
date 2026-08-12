"""Lesson 5 — the attacks a container could only kill by killing the network, and the one it never could.

Lessons 3 and 4 shrank the kernel. Neither of them can answer three questions, and they are not
weaker versions of attack 8 — they are a different axis:

  * **which binary** made this request? To a kernel-level sandbox a syscall is a syscall.
  * **which HTTP method**? The kernel sees bytes on a socket, not ``POST /collect``.
  * **what was attempted?** ``evidence`` has read 0 on every rung so far. A container blocks and
    forgets.

The motivating scenario is lesson 1's web injection, now made containable. A browsing agent *must*
have egress to read pages, so the previous rungs faced a false choice: turn the network off and
break the agent, or leave it on and let the injected payload exfiltrate. This lesson leaves egress
**on** and scopes it — the agent still GETs the gateway it needs, while the injected POST to the
attacker, the package install from an unlisted index, and the curl that was never an allowed binary
are each denied *individually*.

To make that concrete without depending on anything external, the lesson runs **two HTTP listeners
on this host**: one standing in for the model gateway the agent legitimately needs, one standing in
for the attacker's collector. The policy names the first and not the second. They are the same
protocol, the same host, and one port apart — so nothing but the policy can be what separates them,
which is the point a blanket on/off switch cannot express.

    # 1. start the box (once):
    cd ../../infra && ./up.sh lesson-05-container-openshell     # or press 'u' in the sbx-tui panel
    # 2. then, as often as you like (on your machine this runs the lesson ON the box):
    cd tutorial/lesson-05-container-openshell && uv sync && uv run python -u main.py

Verified against the OpenShell version printed at the top of the run. OpenShell is **alpha**: the
version is recorded in the scorecard so a future drift is visible rather than mysterious.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from scorecard import Card, Finding, render_report

REPO_ROOT = Path(__file__).resolve().parents[2]
LESSON = "lesson-05-container-openshell"
#: What infra records about this lesson's box. Read only to make the refusal ACTIONABLE — "no box at
#: all" and "the box is up, you are just not on it" need different next steps. Missing means missing:
#: the leaf still runs from a clone that has never touched infra/, nothing is imported from it, and
#: nothing breaks if the file never appears.
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
# Fully qualified on purpose. OpenShell hands the name to podman, which refuses a short name it
# cannot resolve ("did not resolve to an alias and no unqualified-search registries are defined").
# `localhost/` is what a locally-built image is actually called.
IMAGE = "localhost/sandboxing-tutorial/agent:latest"
RESULTS = REPO_ROOT / "results" / "lesson-05.json"
POLICY = Path(__file__).parent / "policy.yaml"
#: OpenShell caps sandbox names at 19 characters, and rejects a longer one at create time.
SANDBOX = "sbx-tutorial-l5"
GROUPS = "reach,abuse,kernel,policy,cost"
# Attack 4's target, inherited from the environment and forwarded into the sandbox so this rung
# probes the same address as every other one. `infra/run.sh` sets it; empty means the suite default.
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")
METADATA_ENV = ["--env", f"PROBE_METADATA_URL={METADATA_URL}"] if METADATA_URL else []


#: Inside a sandbox, ``localhost`` is the sandbox. The host is reached at this alias.
HOST_ALIAS = "host.openshell.internal"
GATEWAY_PORT = 18410  # the model gateway the agent legitimately needs — ALLOWED by the policy
COLLECTOR_PORT = 18411  # the attacker's collector — never named by the policy, therefore DENIED


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


# --- the two listeners -------------------------------------------------------


#: Every request that actually ARRIVED at either listener. This is the lesson's ground truth: the
#: sandbox reports what it attempted, and only the listener can say what got through.
HITS: list[str] = []


class _Listener(BaseHTTPRequestHandler):
    """A stand-in for the gateway and for the collector — identical, which is the whole point.

    Same protocol, same host, one port apart. Nothing about the *service* distinguishes them, so a
    difference in outcome can only be the policy.
    """

    label = "?"

    def _record(self) -> None:
        HITS.append(f"{self.command} {self.label}{self.path}")
        body = json.dumps({"object": "list", "data": []}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _record
    do_POST = _record

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - the base class names it `format`
        """Silence the default stderr access log — the lesson prints what matters itself."""


def serve(port: int, label: str) -> ThreadingHTTPServer:
    handler = type(f"Listener{port}", (_Listener,), {"label": label})
    # 0.0.0.0 so the sandbox can reach it via host.openshell.internal. This is a throwaway box that
    # `infra/down.sh` destroys; binding wide on a machine you keep would be a different decision.
    srv = ThreadingHTTPServer(("0.0.0.0", port), handler)  # noqa: S104
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


# --- the openshell CLI -------------------------------------------------------


def osh(*args: str, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["openshell", *args], capture_output=True, text=True, timeout=timeout, check=False)


def preflight() -> str:
    """Refuse to pretend, and name the exact reason. Returns the OpenShell version."""
    if shutil.which("openshell") is None:
        sys.exit(
            "  OpenShell is not installed.\n"
            "    curl -LsSf https://raw.githubusercontent.com/NVIDIA/OpenShell/main/install.sh | sh\n"
            "  Note `uv tool install openshell` is NOT enough — it installs the CLI but not the\n"
            "  `openshell-gateway` daemon, and every command below needs the daemon."
        )
    version = osh("--version", timeout=30).stdout.strip() or "unknown"

    # `doctor check` is ADVISORY here, deliberately. It shells out to a docker-compatible CLI, and
    # under podman-docker emulation it fails on a `docker info` template field while the driver
    # itself is perfectly healthy. Gating the lesson on it would refuse to run a working sandbox.
    # The load-bearing check is the next one: the gateway either reports Connected or it does not.
    doctor = osh("doctor", "check", timeout=90)
    if "All checks passed" not in doctor.stdout:
        print("  note: `openshell doctor check` was not fully clean (advisory):")
        for line in (doctor.stdout + doctor.stderr).strip().splitlines()[-4:]:
            print(f"    {line}")

    status = osh("status", timeout=60)
    if "Connected" not in status.stdout:
        sys.exit(
            f"  The OpenShell gateway is not reachable:\n{status.stdout}{status.stderr}\n"
            "  The gateway is a DAEMON, separate from the CLI. Two things commonly stop it:\n"
            "    * the wrong active gateway — `openshell gateway list`, then `gateway select <name>`\n"
            "    * a PUBLIC default-route IP. OpenShell's rootless-podman driver refuses to expose\n"
            "      its callback on a public address, which is every cloud box's default route. It\n"
            "      needs a NAT topology (a private primary IP on the default-route interface).\n"
            "      See infra/substrates/README.md — this is measured, not folklore."
        )
    return version


def cleanup() -> None:
    """Delete the sandbox and WAIT for it to actually be gone.

    ``sandbox delete`` returns before the sandbox has been removed — the mirror image of trap 4 in
    this lesson's README, where ``create`` returns before the sandbox is Ready. Part 2b deletes and
    immediately recreates (the static half of a policy can only be set at startup), so without this
    wait the recreate loses the race and dies with ``sandbox '<name>' already exists`` — one step
    after Part 2a has just proved default-deny works.
    """
    osh("sandbox", "delete", SANDBOX, timeout=180)
    for _ in range(60):
        if SANDBOX not in osh("sandbox", "list", timeout=30).stdout:
            return
        time.sleep(2)
    print(f"  warning: {SANDBOX} is still listed after delete — the next create may fail")


def ensure_image() -> None:
    """Build the agent image into the LOCAL podman store OpenShell will pull it from.

    Every run, for the same reason as the other lessons: a skipped rebuild silently measures a stale
    attack suite. OpenShell runs this as a bring-your-own container, so the image has to exist here
    before `sandbox create` — it is never fetched from a registry.
    """
    print(f"  building {IMAGE} into the local podman store")
    build_dir = REPO_ROOT / "infra" / "images" / "agent"
    done = subprocess.run(
        ["podman", "build", "-q", "-t", IMAGE, str(build_dir)], capture_output=True, text=True, timeout=1800
    )
    if done.returncode != 0:
        sys.exit(f"  image build failed:\n{done.stdout}\n{done.stderr}")


# --- the lesson --------------------------------------------------------------


def create_sandbox(policy: Path | None) -> None:
    """Create the sandbox from our own image, with the probe URLs injected as environment.

    The create command must be **quick**. A long-running one blocks the CLI; everything real happens
    through `exec` afterwards against a sandbox that stays Ready.

    ``policy`` is applied *here* rather than later because a policy has static halves —
    ``process``, ``filesystem_policy``, ``landlock`` — that are locked at startup. Trying to
    introduce them with ``policy set`` on a live sandbox is refused outright:
    *"process policy cannot be changed on a live sandbox (applied at startup)"*. Only
    ``network_policies`` is hot-reloadable, which is what Part 2b then reloads.
    """
    argv = [
        "sandbox", "create", "--name", SANDBOX,
        "--no-tty", "--no-auto-providers",
        "--from", IMAGE,
        "--env", f"PROBE_GATEWAY_URL=http://{HOST_ALIAS}:{GATEWAY_PORT}",
        "--env", f"PROBE_EXFIL_URL=http://{HOST_ALIAS}:{COLLECTOR_PORT}/collect",
        "--env", f"PROBE_OFFPOLICY_URL=http://{HOST_ALIAS}:{COLLECTOR_PORT}/",
        "--env", f"PROBE_STAGE_URL=http://{HOST_ALIAS}:{COLLECTOR_PORT}/stage.sh",
        "--env", f"PROBE_GROUPS={GROUPS}",
        "--env", f"PROBE_NODE_KERNEL={platform.release()}",
        # The image sets WORKDIR /app, but `sandbox exec` does not start there, so `python -m
        # attacks.run` cannot find the package (ModuleNotFoundError: No module named 'attacks').
        # PYTHONPATH fixes it without wrapping the command in `sh -c`, which would matter here more
        # than anywhere else in the tutorial: OpenShell's policy is PER BINARY, so running the suite
        # through a shell would put `sh` — a binary the policy never names — in the execution path.
        "--env", "PYTHONPATH=/app",
        # Same target as every other rung, so the row stays comparable — and here it is the policy
        # that denies it, not the routing. The sandbox's egress goes through OpenShell's L7 proxy,
        # which records the decision by binary and method:
        #
        #     HTTP:GET [MED] DENIED /usr/bin/curl(36) -> GET http://169.254.42.42/
        #
        # So `cloud_metadata` reads 403 rather than a timeout, and Part 4's audit trail can show
        # exactly which binary attempted the SSRF that lesson 1 landed.
        *METADATA_ENV,
    ]  # fmt: skip
    if policy:
        argv += ["--policy", str(policy)]
    argv += ["--", "echo", "ready"]
    done = osh(*argv, timeout=600)
    if done.returncode != 0:
        sys.exit(f"  sandbox create failed:\n{done.stdout}\n{done.stderr}")


def wait_ready(timeout_s: int = 120) -> None:
    """Block until the sandbox reports Ready.

    `sandbox create` returns before the supervisor inside the sandbox is accepting work, and an
    `exec` issued in that window does not fail — it HANGS, until whatever timeout the caller set.
    Polling for Ready turns a mystifying stall into a bounded wait.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        listing = osh("sandbox", "list", timeout=60).stdout
        for line in listing.splitlines():
            if SANDBOX in line and "Ready" in line:
                return
        time.sleep(3)
    print(f"  warning: {SANDBOX} never reported Ready within {timeout_s}s; continuing anyway")


def probe_default_deny() -> str:
    """Before any policy exists, the sandbox denies everything. Establish that, or the rest proves nothing."""
    try:
        done = osh(
            "sandbox", "exec", "-n", SANDBOX, "--",
            "/usr/bin/curl", "-sS", "-m", "8", "-o", "/dev/null", "-w", "%{http_code}",
            f"http://{HOST_ALIAS}:{GATEWAY_PORT}/v1/models",
            timeout=60,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        # A request that never returns is denied as surely as one that 403s — the connection went
        # nowhere. Report it as such rather than crashing the lesson.
        return "timeout"
    return (done.stdout or "000").strip().splitlines()[-1] if done.stdout.strip() else "000"


def apply_policy() -> None:
    """Order matters: arm the OCSF writer FIRST, then apply the policy — the reload activates it.

    Enable OCSF after applying the policy and the JSONL file stays empty, which looks exactly like a
    broken feature rather than a sequencing mistake.
    """
    # The SAME file the sandbox was created with. A reload must carry the static sections unchanged:
    # omit them and OpenShell reads it as a removal ("filesystem policy cannot be removed on a live
    # sandbox"); change them and it refuses too ("process policy cannot be changed ... applied at
    # startup"). Identical is the only accepted shape, and it is enough — the reload is not there to
    # change anything, it is there to start the OCSF writer.
    osh("settings", "set", SANDBOX, "--key", "ocsf_json_enabled", "--value", "true", timeout=120)
    done = osh("policy", "set", SANDBOX, "--policy", str(POLICY), "--wait", timeout=300)
    if done.returncode != 0:
        sys.exit(f"  policy reload failed:\n{done.stdout}\n{done.stderr}")


def run_suite() -> Card:
    done = osh(
        "sandbox", "exec", "-n", SANDBOX, "--",
        "python", "-m", "attacks.run", "--groups", GROUPS,
        timeout=900,
    )  # fmt: skip
    if done.stderr:
        print("  --- box stderr (human view) ---")
        print("\n".join("  " + ln for ln in done.stderr.strip().splitlines()[-16:]))
        print()
    return Card.parse(done.stdout, allow_partial=True)


def audit_records() -> tuple[int, list[str]]:
    """The `evidence` row — measured out here, because a process cannot see the record kept about it.

    The L7 proxy flushes its decision log a second or three late, so this waits before reading. A
    zero here on an OpenShell rung is a bug; a zero on every other rung is the finding.
    """
    time.sleep(4)
    done = osh("logs", SANDBOX, "--since", "15m", "-n", "500", "--source", "sandbox", timeout=120)
    lines = [ln for ln in done.stdout.splitlines() if ln.strip()]
    decisions = [ln for ln in lines if any(k in ln.lower() for k in ("deny", "denied", "allow", "block"))]
    return len(decisions), decisions[:6]


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
    print("the rung runs INSIDE a libvirt NAT guest on the box (OpenShell's rootless driver refuses")
    print("a public default route), a topology the box's substrates build.")
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

    version = preflight()
    ensure_image()

    banner("Part 1 — The simplest thing that works: a declarative policy on ordinary runc")
    print(f"  OpenShell {version} — ALPHA. This run's version is recorded in the scorecard.")
    print("  No kernel boundary here at all: the host kernel is fully exposed, and attack 8 will")
    print("  work again. What OpenShell adds is orthogonal — WHICH binary, WHICH method, and a record.")
    print("\n  Two listeners on this host, one port apart:")
    print(f"    :{GATEWAY_PORT}  the model gateway the agent legitimately needs   -> policy ALLOWS GET")
    print(f"    :{COLLECTOR_PORT}  the attacker's collector                         -> never named, DENIED")
    gateway = serve(GATEWAY_PORT, "gateway")
    collector = serve(COLLECTOR_PORT, "collector")

    try:
        banner("Part 2a — Default-deny, before any policy exists")
        cleanup()
        create_sandbox(None)
        wait_ready()
        status = probe_default_deny()
        print(f"    agent tool -> GET gateway/v1/models : {status}  ", end="")
        print("(denied — a sandbox with no policy permits nothing)" if not status.startswith("2") else "(REACHED)")

        banner("Part 2b — Recreate WITH the policy, arm the audit trail, then reload")
        # A fresh sandbox, because the static half of a policy can only be set at startup.
        cleanup()
        create_sandbox(POLICY)
        wait_ready()
        apply_policy()
        print(f"    ocsf_json_enabled=true, then policy set --wait  ({POLICY.name})")
        print("    (that order is load-bearing: the writer activates on the policy reload)")

        banner("Part 2c — Turn the rogue agent loose, with egress ON but scoped")
        card = run_suite()
        n_records, sample = audit_records()
        card.add(
            Finding(
                name="audit_records",
                value=n_records,
                contained=n_records > 0,
                group="evidence",
                detail="policy decisions recorded by the gateway",
            )
        )
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        banner("Part 3 — Read the policy rows in pairs, or they mean nothing")
        print("    egress_gateway     should ALLOW   ->", card.get("egress_gateway"))
        print("    egress_offpolicy   should DENY    ->", card.get("egress_offpolicy"))
        print("    http_method_denied POST, DENY     ->", card.get("http_method_denied"))
        print("    binary_scoped      unlisted curl  ->", card.get("binary_scoped"))
        print("    fs_policy_write    Landlock       ->", card.get("fs_policy_write"))
        print("\n  An allow-list that denies everything is not a policy, it is a switch — which is")
        print("  what lesson 2 had. Reporting only the denials would let a completely broken sandbox")
        print("  look maximally secure, so the ALLOW must pass in the same run as the DENY.")
        print("\n  binary_scoped is the sharpest of the five: the SAME curl, byte for byte, copied to")
        print("  a path the policy does not name, making the identical request — denied. No kernel-")
        print("  level sandbox can see that distinction, by construction.")

        banner("Part 3b — What the listeners actually received (ground truth, not the sandbox's word)")
        for hit in HITS or ["(nothing reached either listener)"]:
            print(f"    {hit}")
        print("\n  Requests to the collector port are the ones that should be ABSENT. The sandbox")
        print("  attempted them; the policy is why they never arrived.")

        banner("Part 4 — The row that has read 0 on every rung until now")
        print(f"    audit_records  {n_records}")
        for line in sample:
            print(f"      {line[:110]}")
        print("\n  Attack 9 dies here: every attempt is recorded, including the ones that failed.")

        banner("Part 4b — And what OpenShell does NOT close")
        for f in card.reached():
            print(f"    {f['name']:<20} {f['value']}")
        print("\n  The kernel row is back. OpenShell runs on ordinary runc with the host kernel fully")
        print("  exposed, so `kernel_identity` reads the node's own kernel here exactly as it did in")
        print("  lesson 2 — no user-space kernel, no guest, nothing between the workload and Linux.")
        print("  One row does differ from lesson 2, and it is worth not glossing over: this sandbox")
        print("  exposes no /sys/module at all, so `sys_module_count` reads 0 where lesson 2 read 179.")
        print("  That is a filesystem the sandbox does not present, not a kernel boundary — the kernel")
        print("  underneath is still the node's, which is the whole point of the row above it.")
        print("\n  gVisor and OpenShell are strong in DISJOINT columns — which is what makes composing")
        print("  them tempting, and what lesson 14 shows going wrong: on gVisor, Landlock returns")
        print("  ENOSYS and the filesystem half of this policy silently stops being enforced.")

        card.save(
            RESULTS,
            lesson="lesson-05-container-openshell",
            # OpenShell's sandbox is online and policed, never offline: its egress-off equivalent is
            # the default-deny state Part 2 already probes before any policy exists. So this rung
            # has one mode, and it is the one the other rungs' network-on cards compare against.
            mode="network-on",
            engine="openshell",
            openshell_version=version,
            # The kernel this sandbox actually shares. Recorded like every other rung so the overall
            # report can tell when two rungs were measured on different machines — and here they
            # genuinely are: this lesson runs inside the NAT'd guest, not on the box the other
            # lessons use, so its kernel rows are about a different kernel. Leaving this out did not
            # make the difference go away, it only made the comparison silently unguarded.
            node_kernel=platform.release(),
            boundary="ordinary runc + OpenShell policy (per-binary, method-aware) + OCSF audit",
            listener_hits=HITS,
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        report = Path(__file__).parent / "report.html"
        if render_report(REPO_ROOT):
            print(f"  report written to  {report.relative_to(REPO_ROOT)}")
    finally:
        gateway.shutdown()
        collector.shutdown()
        cleanup()


if __name__ == "__main__":
    main()
