"""Talking to the chapter-4 cluster: manifests as dicts, ``oc`` as the transport.

Plumbing only — everything that *is* the lesson stays in ``main.py``.

Two things differ from chapter 3's ``k8s.py``, and both are forced by OpenShift rather than chosen:

* **The lesson runs on your machine, not on the box.** Chapters 1-3 rsync the repo onto the box and
  run there. The OpenShift node is RHCOS: an immutable image with no package manager, no repo
  checkout and no uv. So the driver runs here and the *boundary* stays on the node, which is where it
  has to be anyway.
* **`oc`, pinned, from the cluster's own release.** Not `kubectl`: SCC is an OpenShift API, and
  `oc adm policy` has no kubectl equivalent. The binary is the one ``install.sh`` staged, so the
  client and the cluster can never disagree about versions.

The kubeconfig points at the node's **IP** while verifying the certificate's real SAN
(``api.sno.spike.lab``) via ``tls-server-name``. That is what makes it possible to drive the cluster
without editing ``/etc/hosts`` and without pushing a 185 MB `oc` to the node — the two things the
original runbook did (Trap #10, Trap #11).
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SNO = REPO_ROOT / "infra" / "openshift-sno"
OC = SNO / "oc"
KUBECONFIG = SNO / "cfg" / "gen" / "auth" / "kubeconfig"

#: The image the attack suite runs in — a STOCK image, not this repo's agent image.
#:
#: Chapter 3 built `sandboxing-tutorial/agent:v1` with podman and side-loaded it into the node's
#: containerd. Neither half of that works here: RHCOS has no podman to build with, and pushing to
#: the internal registry needs the `*.apps` route this cluster deliberately does not have.
#:
#: Red Hat's UBI rather than `python:3.12-slim` for one concrete reason — the suite shells out to
#: the real `/usr/bin/curl` binary (OpenShell's policy is per-binary, so every rung must go through
#: the same executable), and a `-slim` Debian image ships without curl. A probe that reports
#: "curl absent — attack NOT measured" is not a boundary result, and missing tooling must never be
#: mistaken for a boundary that held.
IMAGE = "registry.access.redhat.com/ubi9/python-312:latest"

#: Where the attack suite is mounted inside the pod. The suite itself is IDENTICAL to the one every
#: other rung runs — it is carried in as a ConfigMap built from `infra/images/agent/attacks/` rather
#: than baked into an image. That is what keeps chapter 4 on the same ladder: the box changes, the
#: suite does not, which is the only reason two rungs are comparable at all.
SUITE_MOUNT = "/suite"


def _env() -> dict[str, str]:
    return {**os.environ, "KUBECONFIG": str(KUBECONFIG)}


def oc(*args: str, stdin: str | None = None, check: bool = True, timeout: int = 180) -> str:
    if not OC.exists():
        raise RuntimeError(f"no oc binary at {OC} — run infra/openshift-sno/install.sh first")
    if not KUBECONFIG.exists():
        raise RuntimeError(f"no kubeconfig at {KUBECONFIG} — the cluster is not installed")
    done = subprocess.run([str(OC), *args], input=stdin, capture_output=True, text=True, timeout=timeout, env=_env())
    if check and done.returncode != 0:
        raise RuntimeError(f"oc {' '.join(args)} failed ({done.returncode}):\n{done.stderr.strip()}")
    return done.stdout.strip()


def oc_result(*args: str, stdin: str | None = None, timeout: int = 180) -> tuple[int, str, str]:
    """Run `oc` and hand back the full result instead of raising.

    Lessons 11 and 13 are *about* commands that are supposed to be refused, and the refusal text is
    the finding. Raising on non-zero would throw away the very thing being measured.
    """
    done = subprocess.run([str(OC), *args], input=stdin, capture_output=True, text=True, timeout=timeout, env=_env())
    return done.returncode, done.stdout.strip(), done.stderr.strip()


def apply(obj: dict[str, object], namespace: str | None = None) -> None:
    args = ["apply", "-f", "-"]
    if namespace:
        args = ["-n", namespace, *args]
    oc(*args, stdin=json.dumps(obj))


def ensure_namespace(name: str) -> None:
    oc("apply", "-f", "-", stdin=json.dumps({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name}}))


def delete_namespace(name: str) -> None:
    oc("delete", "namespace", name, "--ignore-not-found", "--wait=false", check=False)


def suite_configmap(name: str = "attack-suite") -> dict[str, object]:
    """Carry `infra/images/agent/attacks/` into the cluster as a ConfigMap.

    Read straight off disk at run time rather than vendored into this leaf, so chapter 4 measures the
    same suite chapters 1-3 did. If it ever drifts, the ladder stops being a ladder — every rung's
    number would be answering a slightly different question.
    """
    src = REPO_ROOT / "infra" / "images" / "agent" / "attacks"
    files = {p.name: p.read_text(encoding="utf-8") for p in sorted(src.glob("*.py"))}
    if "suite.py" not in files:
        raise RuntimeError(f"no attack suite at {src}")
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": name},
        "data": files,
    }


#: A server that answers 200 to EVERY method. Nine lines rather than an off-the-shelf image because
#: `python -m http.server` returns 501 to a POST — and the `http_method_denied` probe would then
#: report "the POST was denied" when nothing denied it. The stand-in must be indifferent to method,
#: so any difference the probes see is attributable to policy and to nothing else.
STANDIN_SRC = """
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
STANDIN_PORT = 8080


def start_service(namespace: str, name: str) -> str:
    """One stand-in HTTP server behind a Service; returns its cluster DNS name.

    Two of these run: the gateway the agent legitimately needs, and a collector standing in for the
    attacker's listener. Same image, same protocol, same port — the ONLY thing separating them is
    one line of policy, which is exactly the distinction being measured.
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
                    "command": ["python3", "-c", STANDIN_SRC],
                    "ports": [{"containerPort": STANDIN_PORT}],
                    "resources": {"limits": {"memory": "128Mi", "cpu": "500m"}},
                }
            ],
        },
    }
    svc = {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": name},
        "spec": {"selector": {"app": name}, "ports": [{"port": STANDIN_PORT, "targetPort": STANDIN_PORT}]},
    }
    apply(pod, namespace)
    apply(svc, namespace)
    oc("-n", namespace, "wait", "--for=condition=Ready", f"pod/{name}", "--timeout=180s")
    return f"{name}.{namespace}.svc.cluster.local"


def node_name() -> str:
    return oc("get", "nodes", "-o", "jsonpath={.items[0].metadata.name}")


def node_kernel() -> str:
    return oc("get", "node", "-o", "jsonpath={.items[0].status.nodeInfo.kernelVersion}")


def assigned_scc(pod: str, namespace: str) -> str:
    """Which SCC admission actually granted this pod — recorded by OpenShift as an annotation.

    This is the honest way to report lesson 11's result: not "the manifest looked compliant" but
    "the cluster validated it against *this* policy and said yes".
    """
    return oc(
        "-n", namespace, "get", "pod", pod,
        "-o", r"jsonpath={.metadata.annotations.openshift\.io/scc}",
        check=False,
    )  # fmt: skip


def run_pod(manifest: dict[str, object], namespace: str, *, timeout: int = 600) -> tuple[str, str, str]:
    """Run one pod to completion. Returns ``(phase, logs, termination_reason)``.

    Same shape as chapter 3's helper, and for the same reason: a pod that *fails* is a valid outcome
    (attack 7 is allowed to kill it), so this polls for a terminal phase rather than waiting on a
    Ready condition, and reads the logs and the kubelet's termination reason before deleting.
    """
    name = str(manifest["metadata"]["name"])  # pyright: ignore[reportIndexIssue]
    oc("-n", namespace, "delete", "pod", name, "--ignore-not-found", "--now", check=False)
    apply(manifest, namespace)

    deadline = time.monotonic() + timeout
    phase = "Unknown"
    while time.monotonic() < deadline:
        phase = oc("-n", namespace, "get", "pod", name, "-o", "jsonpath={.status.phase}", check=False)
        if phase in ("Succeeded", "Failed"):
            break
        reason = oc(
            "-n", namespace, "get", "pod", name,
            "-o", "jsonpath={.status.containerStatuses[0].state.waiting.reason}",
            check=False,
        )  # fmt: skip
        if reason in ("ErrImagePull", "ImagePullBackOff", "CreateContainerConfigError"):
            raise RuntimeError(f"pod {name} is stuck in {reason}")
        time.sleep(3)

    logs = oc("-n", namespace, "logs", name, check=False, timeout=120)
    term = oc(
        "-n", namespace, "get", "pod", name,
        "-o", "jsonpath={.status.containerStatuses[0].state.terminated.reason}",
        check=False,
    )  # fmt: skip
    oc("-n", namespace, "delete", "pod", name, "--ignore-not-found", "--now", "--wait=false", check=False)
    return phase, logs, term
