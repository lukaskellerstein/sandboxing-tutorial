# Sandboxing Tutorial

A hands-on tutorial on **sandboxing agentic workloads** — running an AI agent and
the code it generates behind a real isolation boundary, on local containers and
on Kubernetes.

The through-line is one workload run repeatedly under progressively stronger
isolation, so each step is a measured comparison rather than a standalone demo:

| Step | Boundary | What it buys |
| :-- | :-- | :-- |
| no sandbox | none — the host | the baseline, and the reason the rest exists |
| container | namespaces + cgroups, host kernel | process/filesystem isolation |
| [gVisor](https://gvisor.dev/) | user-space kernel (`runsc`) | shrinks the host kernel attack surface |
| [Kata Containers](https://katacontainers.io/) | per-pod lightweight VM | hardware-backed isolation, its own guest kernel |
| [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) | per-binary + L7 policy on runc | *which* binary, *which* HTTP method, and an audit trail |

gVisor and OpenShell are strong in **disjoint** columns — kernel surface versus
per-binary/L7 policy and auditing — which is what makes composing them
interesting, and occasionally surprising.

> [!note]
> **Status: scaffolding.** The repo layout, tooling and Claude Code
> configuration are in place; `syllabus.md` and the lessons are not written yet.
> The syllabus is the source of truth for what lessons exist — it comes first,
> before any lesson directory.

## Prerequisites

- **Python 3.12+** and [`uv`](https://docs.astral.sh/uv/)
- **[Podman](https://podman.io/)** (preferred) with `podman compose`. Docker is
  the fallback where a tool does not support Podman — each lesson states which
  it needs and why.
- A local Kubernetes for the k8s lessons
- macOS on Apple Silicon is the development machine; several isolation
  technologies are Linux-kernel features and therefore run inside a Linux VM
  rather than natively.

## Structure

```text
syllabus.md            # source of truth for lessons and ordering (not written yet)
tutorial/              # one directory per lesson, each a standalone uv project
```

Each lesson is self-contained — `cd` into it, `uv sync && uv run python main.py`,
see results. No shared state between lessons.

## Related

- [`agent-eval-benchmark`](https://github.com/lukaskellerstein/agent-eval-benchmark) —
  where this material started, as one phase of a larger benchmark project
- [`harbor-tutorial`](https://github.com/lukaskellerstein/harbor-tutorial) —
  evaluating agents in containers

## License

MIT
