---
description: Project configuration — architecture, paths, dev environment
---

# Project Config

<!-- Filled from what the repo actually contains. Every line must be verifiable
     by reading a file in the repo — never write an aspiration here. Delete any
     bullet that does not apply rather than leaving a placeholder. -->

> [!important]
> **Chapters 1–2 are built as of 2026-08-06.** `syllabus.md` and lessons 01–05
> exist, as does `infra/` with a Terraform-provisioned box per lesson. Lessons
> **01–05 are all green end-to-end on Scaleway VMs**, verified 2026-08-06; lesson
> 05's old `openshell sandbox exec` hang is fixed by `wait_ready()` polling for
> `Ready` before the first `exec`. Chapters 3–5 are still unwritten. Update this file
> the moment any of that stops being true.

- **Project**: sandboxing-tutorial — a hands-on tutorial on sandboxing agentic
  workloads: running an AI agent and the code it generates behind a real
  isolation boundary, on local containers and on Kubernetes
- **Architecture**: independently-runnable lesson leaves. No application; the
  lessons *are* the deliverable. **Five leaves exist (lessons 01–05).**
- **Structure**: `tutorial/` (the lesson leaves), `syllabus.md` (the source of
  truth for the lesson list and ordering — it comes before any lesson directory),
  `infra/` (Terraform + substrate scripts for the per-lesson disposable box)
- **Build**: nothing is built. `uv sync` in a leaf resolves that leaf's
  dependencies against its own `.venv`.
- **Run a lesson**: `cd tutorial/<lesson> && ./run.sh` — provisions its Scaleway VM,
  runs the lesson there, destroys the box (including on failure), and writes
  `report.html` + `report.json` beside the lesson
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
| `tutorial/` | **0** | empty; lessons are written after `syllabus.md` exists |

Every leaf carries its own `pyproject.toml` (with `[tool.ruff]` extending the
root `ruff.toml`), `uv.lock`, `.gitignore` and `.venv`.

**`pyrightconfig.json` does not exist yet, deliberately.** The generator refuses
to write one until at least one leaf has a `.venv`, since an empty
`executionEnvironments` list is worse than no file. The moment the first lesson
is created and synced:

```bash
python3 ~/Projects/Github/lukaskellerstein/mac-setup/projects/scripts/gen-pyrightconfig.py .
```

Re-run it whenever a leaf is added, and diff before committing. Without it
basedpyright reports spurious unresolved imports across the whole tree.

A lesson leaf's intended shape *(convention — none exists yet)*:

```text
lesson-N-<name>/
├── main.py           the runnable entrypoint (< ~200 lines)
├── README.md         the lesson text
├── pyproject.toml    deps + [tool.ruff] extending the root config
├── uv.lock
└── .gitignore
```
