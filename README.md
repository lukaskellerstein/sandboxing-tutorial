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
interesting, and occasionally surprising. **Which boundary to reach for, at what
cost, and when to compose two of them** is the one-page conclusion in
[`docs/decision-table.md`](docs/decision-table.md).

> [!note]
> **Status: phase 1 built.** Lessons 1.1.1–1.4.6 exist under
> `tutorial/phase1-attacks/`. [`syllabus.md`](syllabus.md) is the source of
> truth for what lessons exist and in what order — read it first.

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

Chapters 1–3 run on Scaleway **VMs** (€0.028–0.055/hr, up in under a minute),
composition leaves included. Only chapter 4 needs **bare metal**, because OpenShift
sandboxed containers do.
Which lesson gets which box is declared once, in
[`infra/lessons.json`](infra/lessons.json), and read by the `scw`-based
scripts in `infra/`.

The last lesson is the exception and runs on your own machine: what changes on
macOS, and what it quietly lies to you about.

## Prerequisites

- **Python 3.12+** and [`uv`](https://docs.astral.sh/uv/)
- A **[Scaleway](https://www.scaleway.com/)** account and the `scw` CLI —
  `infra/` provisions and destroys the hosts. Chapters 1–3 ≈ **€1**.
- A **Red Hat** account for the OpenShift chapter (free; pull secret only)
- [Podman](https://podman.io/) locally for the final lesson

## Structure

```text
syllabus.md            # source of truth for lessons and ordering
ATTACKS.md             # what every probe does and why it matters, in plain language
infra/                 # scw provisioning + substrates; provisions and destroys the boxes
results/               # lesson scorecards + overall.html; generated, gitignored
tutorial/              # one folder per phase, then per chapter; each lesson a standalone uv project
    phase1-attacks/
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
cd tutorial/phase1-attacks/chapter-2-one-host/lesson-02-container-gvisor
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
wanted). A **low** number is correct for lesson 1.1.1: it is the no-sandbox baseline, and
the attacks succeeding there are what everything else is measured against.
[`ATTACKS.md`](ATTACKS.md) explains every probe.

A phase-2 (audit) lesson's page asks the other question first — **how many of those attacks
were recorded** — with a segmented coverage bar (logged / crossed a sensor, unrecorded / no
sensor), the attacks that succeeded and left no record called out, and a containment × record
grid; the containment score sits beside it, since it is the same suite as the phase-1 twin.

Each lesson is self-contained — `cd` into it, `uv sync && uv run python -u main.py`,
see results. No shared state between lessons.

```bash
cd infra
./up.sh   1.1.1      # provision + substrates + assert the boundary
./run.sh  1.1.1      # run it there, fetch the scorecard
./down.sh --all      # destroy everything; this is what keeps it cheap
```

## Related

- [`agent-eval-benchmark`](https://github.com/lukaskellerstein/agent-eval-benchmark) —
  where this material started, as one phase of a larger benchmark project
- [`harbor-tutorial`](https://github.com/lukaskellerstein/harbor-tutorial) —
  evaluating agents in containers

## License

MIT
