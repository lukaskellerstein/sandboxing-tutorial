---
description: Project configuration — architecture, paths, dev environment
---

# Project Config

<!-- Filled from what the repo actually contains. Every line must be verifiable
     by reading a file in the repo — never write an aspiration here. Delete any
     bullet that does not apply rather than leaving a placeholder. -->

> [!important]
> **Chapters 1–4 are built as of 2026-08-10.** `syllabus.md` and lessons 01–13 exist,
> as does `infra/`. Lessons **01–09 are green end-to-end on Scaleway VMs** (01–05
> verified 2026-08-06, 06–09 on 2026-08-07) and **10–13 are green on single-node
> OpenShift 4.18.49** on `EM-B112X-SSD` bare metal, verified 2026-08-10.
> **Chapter 5 is still unwritten.** Update this file the moment any of that stops
> being true.
>
> Chapter 4 breaks the per-lesson-box model on purpose: all four lessons share ONE
> cluster, so `tutorial/chapter-4-openshift/lesson-1N-*/run.sh` neither provisions nor destroys, and the
> teardown (`infra/down.sh openshift-sno`) is a step a human owns. Nothing will do it
> for you, and the box is €0.263/hr.

- **Project**: sandboxing-tutorial — a hands-on tutorial on sandboxing agentic
  workloads: running an AI agent and the code it generates behind a real
  isolation boundary, on local containers and on Kubernetes
- **Architecture**: independently-runnable lesson leaves. No application; the
  lessons *are* the deliverable. **Thirteen leaves exist (lessons 01–13).**
- **Structure**: `tutorial/` (the lesson leaves), `syllabus.md` (the source of
  truth for the lesson list and ordering — it comes before any lesson directory),
  `infra/` (`scw`-based provisioning + substrate scripts for the per-lesson disposable box)
- **Build**: nothing is built. `uv sync` in a leaf resolves that leaf's
  dependencies against its own `.venv`.
- **Run a lesson**: `cd tutorial/<chapter>/<lesson> && ./run.sh` — for lessons 01–09 that
  provisions its Scaleway VM, runs the lesson there, destroys the box (including on
  failure), and writes `report.html` + `report.json` beside the lesson.
  **Lessons 10–13 are the exception**: they run against the one shared OpenShift
  cluster and neither provision nor destroy it.
- **Test**: no repo-wide suite. That same command *is* the test: provision → run →
  validate → investigate on failure → destroy, per lesson — see `06-testing.md`.
- **Key dependencies**: none declared yet. Per-lesson extras go in each leaf's
  own `pyproject.toml`.
- **Package manager**: `uv`, always. Never `pip install`.
- **Container engine**: **podman is preferred**; Docker is the fallback only
  where a tool genuinely does not support podman. A lesson that needs Docker
  says so in its README and says why.

## Subject matter

The through-line is one workload run repeatedly under progressively stronger
isolation, so every step is a measured comparison rather than a standalone demo:

| Boundary | Mechanism | The column it is strong in |
|:--|:--|:--|
| none | the host | the baseline, and the reason the rest exists |
| container | namespaces + cgroups, host kernel | process / filesystem isolation |
| gVisor | user-space kernel (`runsc`) | shrinks the host kernel attack surface |
| Kata Containers | per-pod lightweight VM, own guest kernel | hardware-backed isolation |
| NVIDIA OpenShell | per-binary + L7 policy on ordinary runc | *which* binary, *which* HTTP method, and an audit trail |

The point that must survive editing: **gVisor and OpenShell are strong in
disjoint columns** — kernel surface versus per-binary/L7 policy and auditing —
which is what makes composing them interesting, and occasionally surprising.

Two granularities cut across that ladder: sandboxing the **tool** the agent
calls (a code-execution service) versus sandboxing the **whole agent process**.

## Prior art — read before writing a lesson

This material began as one phase of another repo. It is the reference
implementation, and it has already paid for the mistakes:

- **`~/Projects/Github/lukaskellerstein/agent-eval-benchmark/tutorial/03_sandboxing`**
  — the same ladder, already built and measured, with a shared probe suite and a
  comparison table. Read the relevant cell before writing its lesson here.
- **`~/Projects/Github/lukaskellerstein/harbor-tutorial`** — the repo *shape*
  this one copies: kebab-case leaves, one `syllabus.md` as source of truth, root
  tooling config, per-leaf `pyproject.toml`.

Both paths are on this machine; verify with `ls` before citing a file inside
them.

## Leaves

This repo is **not one project**. Each leaf is independently runnable and keeps
its own environment — no workspaces, by design.

| Leaf | Count | Notes |
|:--|:--|:--|
| `tutorial/` | **13** | lessons 01–13; chapters 1–4 of the syllabus |

Every leaf carries its own `pyproject.toml` (with `[tool.ruff]` extending the
root `ruff.toml`), `uv.lock`, `.gitignore` and `.venv`.

**`pyrightconfig.json` exists** and lists every leaf that has a `.venv`. Regenerate
it whenever a leaf is added:

```bash
python3 ~/Projects/Github/lukaskellerstein/mac-setup/projects/scripts/gen-pyrightconfig.py .
```

Re-run it whenever a leaf is added, and diff before committing. Without it
basedpyright reports spurious unresolved imports across the whole tree.

A lesson leaf's shape — leaves live under their chapter folder
(`tutorial/chapter-N-<name>/`), and the tree is the only place that
lesson→chapter mapping exists (`infra/run.sh` resolves it with a glob;
`lessons.json` stays keyed by bare lesson name):

```text
chapter-N-<name>/
└── lesson-NN-<name>/
    ├── main.py           the runnable entrypoint (< ~200 lines)
    ├── README.md         the lesson text
    ├── pyproject.toml    deps + [tool.ruff] extending the root config
    ├── uv.lock
    └── .gitignore
```
