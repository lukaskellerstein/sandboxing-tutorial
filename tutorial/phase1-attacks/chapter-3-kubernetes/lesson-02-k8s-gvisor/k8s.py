"""Talking to the cluster: manifests as dicts, ``kubectl`` as the transport.

Plumbing only. Everything that *is* the lesson — the Pod's securityContext, the resource limits, the
NetworkPolicy — stays in ``main.py`` where a reader meets it. What lives here is the machinery that
would otherwise bury it: running ``kubectl``, waiting for a phase, pulling logs back, and standing up
the stand-in gateway the policy is written around.

Manifests are Python dicts serialised as **JSON**, not YAML. ``kubectl apply`` accepts JSON happily,
YAML is a superset of JSON, and this way the lesson needs no third-party parser — the leaf keeps
zero runtime dependencies, and a reader can see the exact object that was submitted.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

#: The agent image, side-loaded onto the node by ``infra/substrates/chapter-3/60-k8s.sh``.
#:
#: NOT ``:latest``, and that is a Kubernetes fact rather than a preference: a ``:latest`` tag defaults
#: ``imagePullPolicy`` to ``Always``, so the kubelet would go to Docker Hub for an image already on
#: the node's disk and fail with ``ErrImagePull``. Any other tag defaults to ``IfNotPresent``.
IMAGE = "docker.io/sandboxing-tutorial/agent:v1"

#: The stand-in for the model gateway a real agent must reach.
#:
#: It answers **200 to every method**, and that is the whole reason it is nine lines of inline Python
#: rather than an off-the-shelf image. ``python -m http.server`` returns 501 to a POST, and the
#: ``http_method_denied`` probe would then read "the POST was denied" — scoring a NetworkPolicy with
#: a method-awareness it does not have and cannot have. The stand-in must be indifferent to method,
#: so that any difference the probes see is attributable to policy and to nothing else.
GATEWAY_SRC = """
import http.server


class H(http.server.BaseHTTPRequestHandler):
    def _ok(self):
        body = b'{"object":"list","data":[]}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = _ok

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
"""

GATEWAY_LABEL = "sbx-gateway"
GATEWAY_PORT = 8080


def _env() -> dict[str, str]:
    """kubectl's environment. Falls back to the path ``60-k8s.sh`` writes the kubeconfig to.

    ``infra/run.sh`` sources ``~/.sandboxing-tutorial.env`` and so already has ``KUBECONFIG`` set;
    the fallback is for the reader who follows the README and runs this lesson by hand.
    """
    env = dict(os.environ)
    env.setdefault("KUBECONFIG", str(Path.home() / ".kube" / "config"))
    return env


def kubectl(*args: str, stdin: str | None = None, check: bool = True, timeout: int = 180) -> str:
    done = subprocess.run(["kubectl", *args], input=stdin, capture_output=True, text=True, timeout=timeout, env=_env())
    if check and done.returncode != 0:
        raise RuntimeError(f"kubectl {' '.join(args)} failed ({done.returncode}):\n{done.stderr.strip()}")
    return done.stdout.strip()


def apply(obj: dict[str, object], namespace: str) -> None:
    kubectl("-n", namespace, "apply", "-f", "-", stdin=json.dumps(obj))


def ensure_namespace(name: str) -> None:
    """Create the namespace, idempotently. `create --dry-run=client | apply` is the standard trick."""
    manifest = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}}
    kubectl("apply", "-f", "-", stdin=json.dumps(manifest))


def delete_namespace(name: str) -> None:
    """Tear the whole lesson down in one object.

    ``--wait=false`` on purpose: everything inside is garbage-collected with the namespace, and the
    lesson has already read every result it needs. Blocking here would add ~30 s to a run to watch a
    deletion whose outcome cannot change the scorecard.
    """
    kubectl("delete", "namespace", name, "--ignore-not-found", "--wait=false", check=False)


def start_gateway(namespace: str) -> str:
    """Bring up the stand-in gateway and return its **pod IP**.

    A pod IP rather than a Service ClusterIP, deliberately. A NetworkPolicy selects *pods*, and a
    ClusterIP is DNAT'd by kube-proxy on the way through — so allowing "the Service" and then
    watching the packet arrive with a rewritten destination is a well-known way to write a policy
    that looks right and behaves unpredictably across CNIs. Talking to the pod directly means the
    address the probe uses is the address the policy names.
    """
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": GATEWAY_LABEL, "labels": {"app": GATEWAY_LABEL}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [
                {
                    "name": "gateway",
                    "image": IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "-c", GATEWAY_SRC],
                    "ports": [{"containerPort": GATEWAY_PORT}],
                    "resources": {"limits": {"memory": "128Mi", "cpu": "500m"}},
                }
            ],
        },
    }
    apply(pod, namespace)
    kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{GATEWAY_LABEL}", "--timeout=180s")
    ip = kubectl("-n", namespace, "get", "pod", GATEWAY_LABEL, "-o", "jsonpath={.status.podIP}")
    if not ip:
        raise RuntimeError("the stand-in gateway came up with no pod IP")
    return ip


def run_pod(manifest: dict[str, object], namespace: str, *, timeout: int = 900) -> tuple[str, str, str]:
    """Run one pod to completion. Returns ``(phase, logs, termination_reason)``.

    The third value is why the container stopped — ``OOMKilled``, ``Error``, ``Completed``. It is not
    a nicety: attack 7 exhausts memory, and a cgroup limit that bites hard enough takes the whole
    container with it, so the very row that proves the cap engaged is the one row the box never got
    to print. The kubelet records it and nothing else does.

    Polls rather than using ``kubectl wait --for=condition=...``: a pod that *fails* is a perfectly
    valid outcome here (attack 7 is allowed to kill it, and under a kernel sandbox it sometimes
    does), and `wait` would simply time out on it. What the lesson needs is "stopped running, and
    here is what it said before it stopped" — which is Succeeded **or** Failed, plus the logs either
    way. Losing the logs of a pod that died is losing exactly the evidence that death produced.
    """
    name = str(manifest["metadata"]["name"])  # pyright: ignore[reportIndexIssue]
    kubectl("-n", namespace, "delete", "pod", name, "--ignore-not-found", "--now", check=False)
    apply(manifest, namespace)

    deadline = time.monotonic() + timeout
    phase = "Unknown"
    while time.monotonic() < deadline:
        phase = kubectl("-n", namespace, "get", "pod", name, "-o", "jsonpath={.status.phase}", check=False)
        if phase in ("Succeeded", "Failed"):
            break
        # A pod that cannot start never reaches a terminal phase, so surface WHY rather than
        # spending the whole timeout on it. These three are the ones that actually happen here.
        reason = kubectl(
            "-n", namespace, "get", "pod", name,
            "-o", "jsonpath={.status.containerStatuses[0].state.waiting.reason}",
            check=False,
        )  # fmt: skip
        if reason in ("ErrImagePull", "ImagePullBackOff", "CreateContainerConfigError"):
            raise RuntimeError(
                f"pod {name} is stuck in {reason}. For an image already on the node this is almost "
                f"always the :latest imagePullPolicy trap — see infra/images/agent/import-k3s.sh."
            )
        time.sleep(2)

    # Read BOTH before deleting: the logs and the termination reason live on the pod object, and
    # deleting it first is how you end up with a scorecard and no explanation for the missing row.
    logs = kubectl("-n", namespace, "logs", name, check=False, timeout=120)
    reason = kubectl(
        "-n", namespace, "get", "pod", name,
        "-o", "jsonpath={.status.containerStatuses[0].state.terminated.reason}",
        check=False,
    )  # fmt: skip
    kubectl("-n", namespace, "delete", "pod", name, "--ignore-not-found", "--now", "--wait=false", check=False)
    return phase, logs, reason


def reason_for_failure(manifest: dict[str, object], namespace: str, *, timeout: int = 90) -> str:
    """Create a pod expected to fail, and report the cluster's own words for why.

    Used to show what asking for a RuntimeClass nobody registered actually looks like. Measured
    answer: the API server **rejects it at admission** — there is a RuntimeClass admission check, and
    an unknown name comes back ``Forbidden`` immediately.

    The status/events path below is still needed and is not dead code. It covers the failures that
    admission cannot catch, which are the ones that matter: a RuntimeClass that exists but whose
    handler is misconfigured is admitted happily and fails where the sandbox is actually created.
    """
    name = str(manifest["metadata"]["name"])  # pyright: ignore[reportIndexIssue]
    kubectl("-n", namespace, "delete", "pod", name, "--ignore-not-found", "--now", check=False)
    try:
        apply(manifest, namespace)
    except RuntimeError as exc:  # the API server DID reject it — say so verbatim
        return f"rejected at admission: {exc}"

    deadline = time.monotonic() + timeout
    detail = ""
    while time.monotonic() < deadline:
        phase = kubectl("-n", namespace, "get", "pod", name, "-o", "jsonpath={.status.phase}", check=False)
        detail = kubectl(
            "-n", namespace, "get", "pod", name,
            "-o", "jsonpath={.status.containerStatuses[0].state.waiting.reason}"
                  "{.status.containerStatuses[0].state.waiting.message}{.status.message}",
            check=False,
        )  # fmt: skip
        if detail or phase == "Failed":
            break
        time.sleep(2)
    if not detail:
        # Nothing in status: the kubelet records it as an event on the pod instead.
        detail = kubectl(
            "-n", namespace, "get", "events", "--field-selector", f"involvedObject.name={name}",
            "-o", "jsonpath={.items[-1:].message}", check=False,
        ) or "(the cluster reported nothing — which would itself be a finding)"  # fmt: skip
    kubectl("-n", namespace, "delete", "pod", name, "--ignore-not-found", "--now", "--wait=false", check=False)
    return detail.strip()


def runtime_classes() -> list[str]:
    """What the cluster actually offers. Lessons 7 and 8 read this instead of guessing a name."""
    out = kubectl("get", "runtimeclass", "-o", "jsonpath={.items[*].metadata.name}", check=False)
    return out.split()
