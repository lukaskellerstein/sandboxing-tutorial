"""Lesson 1.3.1 — the same attacks, now in a hardened Pod that a cluster scheduled.

Kubernetes **composes** what lesson 1.2.1 already showed and invents no new boundary. Every control here
appeared there — dropped capabilities, a read-only rootfs, a non-root user, memory and CPU caps —
and the pod still runs on the node's kernel, which Part 2 proves rather than asserts. What the
cluster adds is a scheduler, a declarative way to ask, and two things a single host never had:

  * **a service-account token**, mounted at a fixed path unless you say otherwise. Untrusted code
    that finds one stops being a process on a node and becomes an authenticated principal talking to
    the control plane. It is the one attack surface the cluster *adds*, and ``automountServiceAccount
    Token: false`` is what takes it away — measured here as ``k8s_sa_token``, never assumed.
  * **a network verdict better than on/off.** Lesson 1.2.1's container could say "network" or "no
    network" and nothing in between, so with the network an agent actually needs, attacks 2, 4, 5
    and 6 all came back. A NetworkPolicy can say *this destination, that port* — so this rung keeps
    them closed **with the network on**, which no rung before it managed.

Part 4 is where that second point stops flattering the cluster. A NetworkPolicy is **L3/L4**: it
judges an address and a port. It cannot see *which binary* opened the connection or *which HTTP
method* it used, and it writes **nothing down** when it drops a packet. Those are not claims here —
they are the ``policy`` rows on this lesson's own scorecard, and they are lesson 1.3.4's reason to exist.

The boundary lives in single-node k3s on this box's own kernel — the same kernel `uname -r` reports
on the node. See ``infra/substrates/chapter-3/60-k8s.sh``.

    # 1. start the box (once):
    cd ../../../../infra && ./up.sh 1.3.1     # or press 'u' in the sbx-tui panel
    # 2. then, as often as you like (on your machine this runs the lesson ON the box):
    cd tutorial/phase1-attacks/chapter-3-kubernetes/lesson-01-k8s && uv sync && uv run python -u main.py
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

import k8s
from scorecard import Card, render_report

REPO_ROOT = Path(__file__).resolve().parents[4]
LESSON = "1.3.1"
#: What infra records about this lesson's box. Read only to make the refusal ACTIONABLE — "no box at
#: all" and "the box is up, you are just not on it" need different next steps. Missing means missing:
#: the leaf still runs from a clone that has never touched infra/, nothing is imported from it, and
#: nothing breaks if the file never appears.
STATE_ENV = REPO_ROOT / "infra" / ".state" / f"{LESSON}.env"
NAMESPACE = "sbx-1-3-1"
RESULTS = REPO_ROOT / "results" / "1.3.1.json"
SUITE_DIR = REPO_ROOT / "infra" / "images" / "agent"
METADATA_URL = os.environ.get("PROBE_METADATA_URL", "")

# The boundary this lesson teaches, as the two securityContexts a Pod actually carries. Every line
# has a lesson-1.2.1 twin; what changed is that you now *declare* it and admission could refuse you.
POD_SECURITY = {
    "runAsNonRoot": True,
    "runAsUser": 1000,
    "runAsGroup": 1000,
    "fsGroup": 1000,
    "seccompProfile": {"type": "RuntimeDefault"},
}
CONTAINER_SECURITY = {
    "allowPrivilegeEscalation": False,  # a child can never regain privilege
    "readOnlyRootFilesystem": True,  # immutable root filesystem...
    "capabilities": {"drop": ["ALL"]},  # drop every Linux capability
}
# `ephemeral-storage` is the one limit with no lesson-2 equivalent: it is how a cluster caps the disk
# half of attack 7, evicting the pod at a known number instead of filling the node.
RESOURCES = {
    "limits": {"memory": "256Mi", "cpu": "1", "ephemeral-storage": "256Mi"},
    "requests": {"memory": "128Mi", "cpu": "100m", "ephemeral-storage": "64Mi"},
}
# Lesson 1.2.1's flags, re-run live in Part 3 so the comparison is two boundaries and not two machines.
CONTAINER_HARDENING = [
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--read-only",
    "--tmpfs", "/tmp:rw,exec,size=64m",
    "--memory", "256m", "--memory-swap", "256m",
    "--pids-limit", "128",
    "--cpus", "1",
]  # fmt: skip

#: Probes the pod runs. `policy` is unusual on a non-OpenShell rung and is the point of this one:
#: it is what turns "a NetworkPolicy is L3/L4 and silent" from a sentence into two REACHED rows.
GROUPS = "reach,abuse,kernel,policy,cost"

#: Seconds the pod waits before starting the suite — and NOT padding.
#:
#: A NetworkPolicy is not a property the cluster holds; it is rules a controller writes when it
#: notices a pod. The controller reacts to the pod's *creation*, so for the first seconds of a pod's
#: life the rules governing it do not exist yet, and a container that opens a socket on its first
#: instruction beats the controller to it. Measured on this cluster: a pod that curls immediately
#: gets the same answer with and without a deny-all policy — the policy is real and simply was not
#: in force yet. Every CNI-based policy has this window; it is worth knowing rather than papering
#: over, which is why the number is named here instead of buried in a sleep.
#:
#: If it is ever too short, this lesson does not quietly report a weaker boundary: `exfiltrate` reads
#: REACHED, `assert_boundary_engaged` fails, and no result is written at all.
POLICY_SETTLE_S = 20
#: What lesson 1.2.1 ran, so Part 3's diff compares like with like.
GROUPS_CONTAINER = "reach,abuse,kernel,cost"


def banner(text: str) -> None:
    print("\n" + "=" * 74)
    print(text)
    print("=" * 74)


def probe_env(gateway_ip: str) -> dict[str, str]:
    """Environment both runs share, so the only difference between them is the boundary.

    ``PROBE_READONLY_PATH`` points at a **writable** path on purpose. Left at its default it names a
    path on the read-only rootfs, and ``fs_policy_write`` would then report BLOCKED — crediting this
    rung with a filesystem *policy* it does not have, when all that happened is that a mount was
    read-only. Pointed at a writable path the row reads REACHED, which is the honest answer: nothing
    here judges paths. Lesson 1.3.5's Landlock experiment depends on that row meaning what it says.
    """
    env = {
        "PROBE_GROUPS": GROUPS,
        "PROBE_NODE_KERNEL": platform.release(),
        "PROBE_READONLY_PATH": "/tmp/agent-probe-canary",
        "PROBE_GATEWAY_URL": f"http://{gateway_ip}:{k8s.GATEWAY_PORT}",
    }
    if METADATA_URL:
        env["PROBE_METADATA_URL"] = METADATA_URL
    return env


def agent_pod(gateway_ip: str) -> dict[str, object]:
    env = probe_env(gateway_ip)
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "agent-sandbox", "labels": {"app": "agent-sandbox"}},
        "spec": {
            "restartPolicy": "Never",  # one throwaway pod per run; never resurrect a rogue agent
            "automountServiceAccountToken": False,  # untrusted code gets NO cluster credential
            "securityContext": POD_SECURITY,
            "containers": [
                {
                    "name": "agent",
                    "image": k8s.IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    # Wait for the egress rules to be written, THEN hand over to the image's normal
                    # entrypoint — see POLICY_SETTLE_S. `exec` so the suite is still PID 1's process
                    # and its exit status is the pod's.
                    "command": ["/bin/sh", "-c", f"sleep {POLICY_SETTLE_S}; exec /app/entrypoint.sh"],
                    "securityContext": CONTAINER_SECURITY,
                    "resources": RESOURCES,
                    "env": [{"name": k, "value": v} for k, v in env.items()],
                    # /tmp is the ONLY writable path, and $HOME deliberately is not one.
                    #
                    # The obvious move is to mount an emptyDir at /sandbox so $HOME is writable. Do
                    # that and attack 3 starts SUCCEEDING: the backdoor lands in ~/.bashrc, in a
                    # volume that happens to be thrown away afterwards. "It was ephemeral" is not
                    # containment — the write was permitted, and the scorecard would correctly say
                    # so while the rung looked weaker than lesson 1.2.1 for no reason but this mount.
                    # Lesson 1.2.1 leaves $HOME on the read-only rootfs; matching it is what keeps the
                    # Part 3 diff a comparison of container-versus-pod and not of two filesystems.
                    "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                }
            ],
            "volumes": [{"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "64Mi"}}],
        },
    }


def network_policy() -> dict[str, object]:
    """Deny all egress, then punch exactly two holes: DNS, and the gateway.

    DNS is allowed deliberately, and not as a convenience. With it denied, every blocked request
    *times out* in the resolver instead of failing to route — so a working policy looks like a hung
    agent, and the reader debugs the image instead of reading the boundary. Allowing DNS also matches
    what a real agent needs, which is the entire premise of running this rung with the network on.
    """
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
    """Build the agent image and hand it to k3s's containerd. Every run, as chapter 2 does."""
    script = REPO_ROOT / "infra" / "images" / "agent" / "import-k3s.sh"
    subprocess.run(["sudo", "bash", str(script)], check=True, capture_output=True, timeout=900)


def previous_rung(gateway_ip: str) -> tuple[Card | None, str]:
    """Lesson 1.2.1's rung — the hardened container — re-run live on this very box.

    Reading the recorded ``results/1.2.1.json`` would compare a pod here against a container
    measured on a *different machine* last week, so any difference could be the hardware. Running it
    now, minutes apart on the same silicon, makes the difference the deployment target and nothing
    else.

    One variable is held constant rather than copied: this runs **rootful** podman, because the
    kubelet running the pod is root too. Lesson 1.2.1's own headline rung is rootless — so this is not a
    re-creation of lesson 1.2.1's card, it is lesson 1.2.1's *boundary* at the pod's privilege level, which
    is what makes "container versus pod" the only thing that moved.
    """
    if os.environ.get("SANDBOXING_TUTORIAL_DISPOSABLE") != "1":
        return None, "not a disposable box — skipping the live container re-run"
    env = {**probe_env(gateway_ip), "PROBE_GROUPS": GROUPS_CONTAINER}
    argv = ["sudo", "podman", "run", "--rm", "--user", "1000:1000", *CONTAINER_HARDENING]
    for key, value in env.items():
        argv += ["-e", f"{key}={value}"]
    argv.append(k8s.IMAGE)
    done = subprocess.run(argv, capture_output=True, text=True, timeout=900)
    return Card.parse(done.stdout, allow_partial=True), "measured live, just now, on this box"


def merge_pod_death(card: Card, reason: str) -> Card:
    """Fill in the one row a dead pod could not report, from the only place the answer survives.

    Attack 7 allocates against a 256Mi limit. Lesson 1.2.1's container survives it and reports
    ``capped:pids,mem`` — the allocation is refused and the process carries on. This pod does not
    survive: it ends in phase Failed with ``[abuse]`` holding two rows instead of three, because the
    kill arrives before the probe can report its own result.

    That difference is worth recording rather than smoothing over, and it is not a quirk of this
    lesson's manifest — the cap is the same 256Mi as lesson 1.2.1's. Under cgroup v2, a container's
    memory cgroup is configured to kill as a **group**, so an OOM does not merely refuse the
    offending allocation, it takes every process in the container with it. Same limit, same number,
    much larger blast radius — and the row that proves the cap engaged is the one row the box never
    got to print. The kubelet is then the only witness.

    ``OOMKilled`` is required before claiming containment. A pod that died for some *other* reason
    was not demonstrably capped, and saying otherwise would invent a boundary — so anything else
    lands as ``contained=None``, which reports as ``n/a`` and makes the assertion below fail loudly
    instead of quietly crediting a rung with something it never showed.
    """
    if card.complete or card.get("resource_exhaustion") is not None:
        return card
    oom = reason == "OOMKilled"
    print(f"  ! the pod did not survive the suite (terminated: {reason or 'unknown'})")
    print(f"    {len(card.findings)} findings streamed out before it died, which is why the suite")
    print("    prints each one as it is produced rather than only a final card.")
    if oom:
        print("    OOMKilled IS the result here: the 256Mi limit engaged, and in a Pod it took the")
        print("    container's init process with it rather than merely refusing the allocation.")
    return card.add(
        {
            "name": "resource_exhaustion",
            "value": "capped:pod-oomkilled" if oom else f"pod-died:{reason or 'unknown'}",
            "contained": True if oom else None,
            "group": "abuse",
            "detail": "the memory limit killed the pod mid-attack (host-observed, from the kubelet)",
        }
    )


def assert_boundary_engaged(card: Card) -> None:
    """Prove the pod is the pod we asked for — from the readings, never from the manifest we posted.

    A manifest that was accepted is not a boundary that engaged. The check that matters most is the
    last one: if the gateway were unreachable, every network row would read BLOCKED and this lesson
    would announce that a NetworkPolicy stops exfiltration — when in truth the pod simply had no
    working network at all. That is the same false comfort in the opposite direction, and it would be
    indistinguishable from a real result.
    """
    checks = {
        "fresh filesystem (host creds unreachable)": card.contained("read_credentials") is True,
        "no service-account token (automount off engaged)": card.contained("k8s_sa_token") is True,
        "off-policy egress denied (NetworkPolicy engaged)": card.contained("exfiltrate") is True,
        "resource cap bit (limits engaged)": card.contained("resource_exhaustion") is True,
        "the ALLOWED destination still works (this is a policy, not a dead network)": (
            card.contained("egress_gateway") is True
        ),
    }
    for label, ok in checks.items():
        print(f"    [{'OK' if ok else '!!'}] {label}")
    if not all(checks.values()):
        sys.exit("  boundary assertion FAILED — the pod did not engage as configured; not reporting a result.")


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
    print("the boundary lives in single-node k3s installed on the box, and the pod runs on that")
    print("node's kernel — which is the lesson's whole claim.")
    print("Start the box, then run it from here:\n")
    print(f"    cd ../../../../infra && ./up.sh {LESSON}      # or press 'u' in the sbx-tui panel")
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
    k8s.ensure_namespace(NAMESPACE)
    try:
        banner("Part 1 — The simplest thing that works: one hardened Pod")
        print(f"  namespace {NAMESPACE}, image {k8s.IMAGE}")
        print("  bringing up the stand-in model gateway the policy is written around...")
        gateway_ip = k8s.start_gateway(NAMESPACE)
        print(f"  gateway pod at {gateway_ip}:{k8s.GATEWAY_PORT} — the one destination egress will allow")
        k8s.apply(network_policy(), NAMESPACE)
        print("  NetworkPolicy/agent-sandbox-egress applied: deny all, allow DNS + that pod\n")
        print(f"  pod securityContext:       {POD_SECURITY}")
        print(f"  container securityContext: {CONTAINER_SECURITY}")
        print(f"  limits:                    {RESOURCES['limits']}")

        banner("Part 2 — Turn the rogue agent loose (the same attacks, now in a Pod)")
        phase, logs, reason = k8s.run_pod(agent_pod(gateway_ip), NAMESPACE)
        print(f"  pod finished in phase {phase} (terminated: {reason or 'n/a'})\n")
        card = merge_pod_death(Card.parse(logs, allow_partial=True), reason)
        print(card.render())
        blocked, applicable = card.tally()
        print(f"\n  boundaries that held: {blocked}/{applicable}")

        banner("Assert the boundary engaged (from the readings, never from the manifest)")
        assert_boundary_engaged(card)

        banner("Part 3 — What just changed (lesson 1.2.1's container, re-run live on this same box)")
        prev, source = previous_rung(gateway_ip)
        if prev is None:
            print(f"  ({source})")
        else:
            print(f"  ({source})\n")
            print(card.diff_against(prev, "container", "pod"))
            print("\n  The kernel rows do not move, and that is the headline: a pod is namespaces and")
            print("  cgroups on the node's kernel, exactly as the container was. Kubernetes scheduled")
            print("  the boundary; it did not strengthen it. Lessons 1.3.2 and 1.3.3 are where that changes.")
            print("\n  One row is the same verdict by a different route. Both rungs cap memory at")
            print("  256Mi, but the container REFUSES the allocation and keeps running, while the pod")
            print("  is killed outright — cgroup v2 kills a container's cgroup as a group. Same cap,")
            print("  same reading, and a blast radius worth knowing about before you rely on it.")
            print()
            print(card.cost_delta(prev, "container", "pod"))

        banner("Part 4 — What is still open (the next lessons' reason to exist)")
        for f in card.reached():
            print(f"    {f['name']:<20} {f['value']}")
        print("\n  Read the [policy] rows above. The gateway GET was allowed and the off-policy host")
        print("  was denied — a container could express neither. But the POST to the SAME allowed")
        print("  host also succeeded, and so did a curl copied to an unnamed path: a NetworkPolicy")
        print("  judges an address and a port, never a method and never a binary. Nor did it write")
        print("  one line down about what it dropped. That is lesson 1.3.4.")
        print("\n  And every kernel row is still the node's — attack 8 is as open as it was in lesson")
        print("  1.1.1. Lesson 1.3.2 changes one field and watches it collapse.")

        card.save(
            RESULTS,
            lesson="1.3.1",
            mode="network-on",
            engine="k3s",
            node_kernel=platform.release(),
            boundary="hardened Pod, scoped NetworkPolicy egress",
        )
        print(f"\n  scorecard written to {RESULTS.relative_to(REPO_ROOT)}")
        if render_report(REPO_ROOT):
            print(f"  report written to  {(Path(__file__).parent / 'report.html').relative_to(REPO_ROOT)}")
    finally:
        # The namespace owns every object this lesson made, so one delete is the whole teardown —
        # and it runs even when the lesson fails, because a rogue agent's pod must never outlive it.
        k8s.delete_namespace(NAMESPACE)


if __name__ == "__main__":
    main()
