"""Talking to the cluster: manifests as dicts, ``kubectl`` as the transport.

Plumbing only, and deliberately less of it than lessons 6–8 carry. This lesson does not build pods:
**OpenShell does**, from the policy. All that is needed out here is a namespace to work in and the
two stand-in HTTP servers the policy is written around — one named in it, one not.

Everything that *is* the lesson lives in ``main.py`` and ``policy.yaml``, which is the point: at this
rung the boundary is a declarative document rather than a manifest field.

Manifests are Python dicts serialised as **JSON**, not YAML. ``kubectl apply`` accepts JSON happily,
YAML is a superset of JSON, and this way the lesson needs no third-party parser — the leaf keeps
zero runtime dependencies, and a reader can see the exact object that was submitted.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

#: The agent image, side-loaded onto the node by ``infra/substrates/60-k8s.sh``.
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


def start_service(namespace: str, name: str, *, port: int = GATEWAY_PORT) -> str:
    """Bring up one stand-in HTTP server behind a Service, and return its cluster DNS name.

    Lesson 6 deliberately talked to a **pod IP**, because a NetworkPolicy selects pods and a
    ClusterIP is DNAT'd on the way through. Here the opposite is right: nothing in this lesson is a
    NetworkPolicy. OpenShell's policy names a *host*, the way an operator would actually write one,
    and a Service's DNS name is that host. It is also what makes the policy readable — `sbx-gateway`
    versus `sbx-collector` says what the rule means, where two pod IPs one digit apart would not.

    Two of these run: the gateway the agent legitimately needs, and a collector standing in for the
    attacker's listener. Same image, same protocol, same port — the ONLY thing separating them is
    one line of policy. That is the distinction lesson 6's NetworkPolicy could draw too; the ones it
    could not are method and binary, and those come later in the same file.
    """
    pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": name, "labels": {"app": name}},
        "spec": {
            "restartPolicy": "Never",
            "automountServiceAccountToken": False,
            "containers": [
                {
                    "name": "server",
                    "image": IMAGE,
                    "imagePullPolicy": "IfNotPresent",
                    "command": ["python", "-c", GATEWAY_SRC],
                    "ports": [{"containerPort": port}],
                    "resources": {"limits": {"memory": "128Mi", "cpu": "500m"}},
                }
            ],
        },
    }
    service = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name},
        "spec": {"selector": {"app": name}, "ports": [{"port": port, "targetPort": port}]},
    }
    apply(pod, namespace)
    apply(service, namespace)
    kubectl("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=180s")
    return f"{name}.{namespace}.svc.cluster.local"
