# Sandboxing Tutorial

A hands-on tutorial on **sandboxing agentic workloads** — running an AI agent and
the code it generates behind a real isolation boundary, on containers, on
Kubernetes and on OpenShift.

The through-line is one workload run repeatedly under progressively stronger
isolation, so each step is a measured comparison rather than a standalone demo:

| Step | Boundary | What it buys |
| :-- | :-- | :-- |
| no sandbox | none — the host | the baseline, and the reason the rest exists |
| container | namespaces + cgroups, host kernel | process/filesystem isolation |
| [gVisor](https://gvisor.dev/) | user-space kernel (`runsc`) | shrinks the host kernel attack surface |
| [Kata Containers](https://katacontainers.io/) | per-container lightweight VM | hardware-backed isolation, its own guest kernel |
| [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) | per-binary + L7 policy on runc | *which* binary, *which* HTTP method, and an audit trail |

gVisor and OpenShell are strong in **disjoint** columns — kernel surface versus
per-binary/L7 policy and auditing — which is what makes composing them
interesting, and occasionally surprising.

> [!note]
> **Status: syllabus agreed, lessons not written.** The repo layout, tooling and
> Claude Code configuration are in place. [`syllabus.md`](syllabus.md) is the
> source of truth for what lessons exist and in what order — read it first. No
> lesson directory exists yet.

## Where this runs

**On bare-metal Linux, provisioned per session and destroyed after** — not on your
laptop. That is deliberate, and measured:

- On macOS a "plain container" is **already inside a VM**, so the baseline of the
  ladder is stronger than the lesson claims and every comparison built on it is
  quietly off. On bare metal a container is genuinely namespaces on the host
  kernel.
- A disposable box can demonstrate **what actually goes wrong** with no boundary —
  real exfiltration of planted credentials, a real fork bomb — instead of only
  proving what *could* be reached.
- **Kata Containers cannot run on an Apple Silicon Mac at all**, and OpenShift
  sandboxed containers require bare metal.

The last lesson is the exception and runs on your own machine: what changes on
macOS, and what it quietly lies to you about.

## Prerequisites

- **Python 3.12+** and [`uv`](https://docs.astral.sh/uv/)
- A **[Scaleway](https://www.scaleway.com/)** account and the `scw` CLI —
  `infra/` provisions and destroys the hosts. Whole tutorial ≈ **€1–2**.
- A **Red Hat** account for the OpenShift chapter (free; pull secret only)
- [Podman](https://podman.io/) locally for the final lesson

## Structure

```text
syllabus.md            # source of truth for lessons and ordering
infra/                 # provisions the hosts and every substrate on them
results/               # lesson scorecards; the final table is rendered from these
tutorial/              # one directory per lesson, each a standalone uv project
```

Each lesson is self-contained — `cd` into it, `uv sync && uv run python -u main.py`,
see results. No shared state between lessons.

```bash
cd infra && ./up.sh      # provision + install every substrate
# ... work through the lessons ...
cd infra && ./down.sh    # destroy everything; this is what keeps it cheap
```

## Related

- [`agent-eval-benchmark`](https://github.com/lukaskellerstein/agent-eval-benchmark) —
  where this material started, as one phase of a larger benchmark project
- [`harbor-tutorial`](https://github.com/lukaskellerstein/harbor-tutorial) —
  evaluating agents in containers

## License

MIT
