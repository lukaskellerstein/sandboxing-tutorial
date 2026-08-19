---
description: Project configuration — architecture, paths, dev environment
---

# Project Config

<!-- Filled from what the repo actually contains. Every line must be verifiable
     by reading a file in the repo — never write an aspiration here. Delete any
     bullet that does not apply rather than leaving a placeholder. -->

> [!important]
> **Chapters 1–4 are built as of 2026-08-10; composition leaves added (spec 04, 2026-08-14).**
> `syllabus.md` and the boundary lessons (1.1.1, 1.2.1–1.2.4, 1.3.1–1.3.4, 1.4.1–1.4.4)
> exist, as does `infra/`. Lessons **1.1.1, 1.2.1–1.2.4 and 1.3.1–1.3.4 are green
> end-to-end on Scaleway VMs** (1.1.1 and 1.2.1–1.2.4 verified 2026-08-06, 1.3.1–1.3.4 on
> 2026-08-07) and **1.4.1–1.4.4 are green on single-node OpenShift 4.18.49** on
> `EM-B112X-SSD` bare metal, verified 2026-08-10.
> **Chapter 5 is dissolved** (spec 04): composition is demonstrated in-chapter.
> **Lessons 1.3.5 and 1.3.6 are runnable and green on `chapter-03-k8s`** (verified 2026-08-14);
> **lesson 1.4.6 is written but UNVERIFIED** — it needs the human-owned SNO cluster;
> **lessons 1.2.5, 1.2.6, 1.4.5 are documentation-only README stubs** (no `main.py`, no box, not
> in `lessons.json`). Update this file the moment any of that stops being true.
>
> Chapter 4 breaks the per-lesson-box model on purpose: all four lessons share ONE
> cluster, so `tutorial/phase1-attacks/chapter-4-openshift/lesson-*/run.sh` neither provisions nor destroys, and the
> teardown (`infra/down.sh openshift-sno`) is a step a human owns. Nothing will do it
> for you, and the box is €0.263/hr.
>
> **The box topology is one shared box per chapter as of 2026-08-13**: lessons 1.2.1–1.2.3 share
> `chapter-02-host` (PRO2-XS), lessons 1.3.1–1.3.4 share `chapter-03-k8s` (PRO2-S), lesson 1.2.4 keeps
> its own box by hard constraint (OpenShell's NAT-guest re-point), and chapters 1 and 4
> were already one box each. Shared-lesson `run.sh` still provisions and destroys — the
> chapter box, via an EXIT trap — and `infra/chapter-02.sh` / `chapter-03.sh` amortize the
> build across each chapter. `CLAUDE.md` § at a glance carries the measured detail.

- **Project**: sandboxing-tutorial — a hands-on tutorial on sandboxing agentic
  workloads: running an AI agent and the code it generates behind a real
  isolation boundary, on local containers and on Kubernetes
- **Architecture**: independently-runnable lesson leaves. No application; the
  lessons *are* the deliverable. **Nineteen phase-1 leaves exist (1.1.1, 1.2.1–1.2.6,
  1.3.1–1.3.6, 1.4.1–1.4.6; of those, 1.2.5, 1.2.6 and 1.4.5 are documentation-only
  stubs)**, plus **fifteen runnable phase-2 audit leaves (2.1.1, 2.2.1–2.2.4, 2.3.1–2.3.6,
  2.4.1–2.4.4)** and **four documentation-only ones (2.2.5, 2.2.6, 2.4.5, 2.4.6)** under
  `tutorial/phase2-audits/` — the audit twins that ask whether each boundary would have *recorded* the
  attack. **All four audit chapters are built.** 2.4.6 is BLOCKED rather than impossible: its phase-1
  twin 1.4.6 does not work on OpenShift because the OSC Kata **guest image** omits `veth.ko`, which
  OpenShell's L7 proxy needs (the guest *kernel* is the node's RHEL kernel — not a config difference).
  Red Hat has it scheduled as KATA-5840 for OSC 1.14. **2.4.6's own README is the handoff record** —
  read it before retrying; see also spec 05's `current_status.md`.
- **Structure**: `tutorial/` (the lesson leaves), `syllabus.md` (the source of
  truth for the lesson list and ordering — it comes before any lesson directory),
  `infra/` (`scw`-based provisioning + substrate scripts for the per-lesson disposable box)
- **Build**: nothing is built. `uv sync` in a leaf resolves that leaf's
  dependencies against its own `.venv`.
- **Run a lesson**: `cd tutorial/<phase>/<chapter>/<lesson> && ./run.sh` — for lessons
  1.1.1, 1.2.1–1.2.4 and 1.3.1–1.3.4 that
  provisions its Scaleway VM (the shared chapter box, where the lesson carries `box`),
  runs the lesson there, destroys the box (including on failure), and writes
  `report.html` + `report.json` beside the lesson.
  **Lessons 1.4.1–1.4.4 are the exception**: they run against the one shared OpenShift
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
| `tutorial/phase1-attacks/` | **19** | lessons 1.1.1, 1.2.1–1.2.6, 1.3.1–1.3.6, 1.4.1–1.4.6; chapters 1–4 of the syllabus |
| `tutorial/phase2-audits/` | **15 runnable + 4 doc-only** | the audit twins 2.1.1, 2.2.1–2.2.4, 2.3.1–2.3.6, 2.4.1–2.4.4; 2.2.5/2.2.6/2.4.5 are documentation-only; 2.4.6 is blocked (1.4.6 fails on OpenShift) and its README is the handoff record |

Every leaf carries its own `pyproject.toml` (with `[tool.ruff]` extending the
root `ruff.toml`), `uv.lock`, `.gitignore` and `.venv`.

**`pyrightconfig.json` exists** and lists every leaf that has a `.venv`. Regenerate
it whenever a leaf is added:

```bash
python3 ~/Projects/Github/lukaskellerstein/mac-setup/projects/scripts/gen-pyrightconfig.py .
```

Re-run it whenever a leaf is added, and diff before committing. Without it
basedpyright reports spurious unresolved imports across the whole tree.

A lesson leaf's shape — leaves live under their phase and chapter folders
(`tutorial/phaseN-<name>/chapter-N-<name>/`), and the tree is the only place that
id→leaf mapping exists (`infra/run.sh` resolves it with a glob;
`lessons.json` stays keyed by dotted id):

```text
phaseN-<name>/
└── chapter-N-<name>/
    └── lesson-NN-<name>/
        ├── main.py           the runnable entrypoint (< ~200 lines)
        ├── README.md         the lesson text
        ├── pyproject.toml    deps + [tool.ruff] extending the root config
        ├── uv.lock
        └── .gitignore
```
