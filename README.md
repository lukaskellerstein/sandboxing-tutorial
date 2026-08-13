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

**On a disposable Linux box, provisioned per lesson — or one per chapter, where its
lessons share — and destroyed after**, not on your laptop. That is deliberate, and
measured:

- On macOS a "plain container" is **already inside a VM you did not ask for and the
  lesson never mentions**, so the baseline of the ladder is stronger than the lesson
  claims and every comparison built on it is quietly off. On a box you provisioned,
  a container is namespaces on the kernel you just measured.
- A disposable box can demonstrate **what actually goes wrong** with no boundary —
  real exfiltration of planted credentials, a real fork bomb — instead of only
  proving what *could* be reached.
- **Kata Containers cannot run on an Apple Silicon Mac at all.**

Chapters 1–3 and 5 run on Scaleway **VMs** (€0.028–0.055/hr, up in under a minute).
Only chapter 4 needs **bare metal**, because OpenShift sandboxed containers do.
Which lesson gets which box is declared once, in
[`infra/terraform/lessons.json`](infra/terraform/lessons.json), and applied by
Terraform.

The last lesson is the exception and runs on your own machine: what changes on
macOS, and what it quietly lies to you about.

## Prerequisites

- **Python 3.12+** and [`uv`](https://docs.astral.sh/uv/)
- A **[Scaleway](https://www.scaleway.com/)** account and the `scw` CLI —
  `infra/` provisions and destroys the hosts. Chapters 1–3 ≈ **€1**.
- **[Terraform](https://developer.hashicorp.com/terraform)** ≥ 1.9, which is what
  `infra/up.sh` and `infra/down.sh` drive. It reads the same `~/.config/scw/`
  credentials the CLI does, so there is nothing extra to configure.
- A **Red Hat** account for the OpenShift chapter (free; pull secret only)
- [Podman](https://podman.io/) locally for the final lesson

## Structure

```text
syllabus.md            # source of truth for lessons and ordering
ATTACKS.md             # what every probe does and why it matters, in plain language
infra/                 # terraform + substrates; provisions and destroys the boxes
results/               # lesson scorecards + overall.html; generated, gitignored
tutorial/              # one folder per chapter; each lesson a standalone uv project
    chapter-N-.../
        lesson-NN-.../
            run.sh         # THE command: provision -> run -> destroy
            report.html    # this lesson's scorecard, generated after each run
            report.json    # the same, machine-readable
```

## Running a lesson

One command, from the lesson's own folder. It provisions that lesson's box, runs the
lesson on it, and destroys the box — **even if the lesson fails**:

```bash
cd tutorial/chapter-2-one-host/lesson-03-container-gvisor
./run.sh              # provision -> run -> destroy
./run.sh --keep       # ...leave the box up afterwards, for poking around
```

Each lesson writes `report.html` and `report.json` **next to itself**, covering that
lesson only, so its report is final the moment the lesson finishes. To compare rungs,
build the overall report from those files whenever you like:

```bash
python3 infra/report/overall.py --open      # -> results/overall.html
```

An attack is **BLOCKED** (the boundary stopped it) or it **SUCCEEDED** (it got what it
wanted). A **low** number is correct for lesson 1: it is the no-sandbox baseline, and
the attacks succeeding there are what everything else is measured against.
[`ATTACKS.md`](ATTACKS.md) explains every probe.

Each lesson is self-contained — `cd` into it, `uv sync && uv run python -u main.py`,
see results. No shared state between lessons.

```bash
cd infra
./up.sh   lesson-01-no-sandbox   # terraform apply + substrates + assert the boundary
./run.sh  lesson-01-no-sandbox   # run it there, fetch the scorecard
./down.sh --all                  # destroy everything; this is what keeps it cheap
```

## Related

- [`agent-eval-benchmark`](https://github.com/lukaskellerstein/agent-eval-benchmark) —
  where this material started, as one phase of a larger benchmark project
- [`harbor-tutorial`](https://github.com/lukaskellerstein/harbor-tutorial) —
  evaluating agents in containers

## License

MIT
