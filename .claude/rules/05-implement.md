---
description: "Step 3: Implement — coding rules and this project's layout"
---

# Step 3: Implement

Write clean code from the start. Follow these rules during implementation:

- Do NOT commit via `git` unless explicitly instructed by the user
- When creating diagrams or graphs, use `mermaid`
- Write clean code from the start — don't plan to "clean it up later"
- Refactor continuously — improve code structure immediately when you see issues
- Remove dead code — delete unused functions, variables, imports, and commented code
- Before changing any signature, renaming, or deleting something shared, find
  every caller with `findReferences` where the `LSP` tool is available — grep
  misses the ones spelled differently and finds ones that are not calls.
  [`lsp.md`](lsp.md)
- After writing code: review comments, clean up imports, check for side effects

## `syllabus.md` comes first

`syllabus.md` is the source of truth for which lessons exist and in what order —
and **it is not written yet**. Do not create a lesson directory that the syllabus
does not list. If a task calls for a lesson and the syllabus has no entry, that
is a signal to write or extend the syllabus and get it agreed, not to invent a
leaf and reconcile later. Changing the lesson list or ordering always needs
confirmation.

## `tutorial/` — the lesson leaves

One directory per lesson, each a **standalone `uv` project**. No workspace, no
shared package, no imports across leaves: a learner clones the repo, `cd`s into
one lesson, and runs it.

Every leaf carries:

```text
lesson-N-<name>/
├── main.py           the runnable entrypoint (< ~200 lines)
├── README.md         the lesson text
├── pyproject.toml    deps + [tool.ruff] extending the root ruff.toml
├── uv.lock
└── .gitignore        .venv/, __pycache__/, *.pyc, .python-version
```

`pyproject.toml` must extend the root config explicitly — a leaf carrying
`[tool.ruff]` **shadows** the root rather than merging with it, so without the
`extend` line the leaf silently runs ruff's own defaults while looking correctly
configured:

```toml
[tool.ruff]
extend = "../../../ruff.toml"   # count the directories — depth varies with nesting
src = ["."]
```

If `main.py` outgrows ~200 lines, extract helpers into a sibling module in the
same leaf — never into a shared package.

**Lesson prose is the product.** The root `ruff.toml` excludes `**/*.md` for
exactly this reason: ruff would reformat Python inside README fences and collapse
the hand-aligned trailing comment columns that make the code teachable. Do not
remove that exclusion.

## What must NOT go in this repo

- Application code that is not a lesson. Anything that is really a project of its
  own belongs in its own repo.
- Shared libraries across leaves. The duplication between lessons is deliberate —
  it is what keeps each one readable on its own.
- A credential, in any file, ever. Not in a `.env`, not in a policy YAML, not in
  a kubeconfig. [`12-security.md`](12-security.md).

## Writing sandboxing lessons specifically

- **Prefer podman.** Reach for Docker only where a tool genuinely does not
  support podman, and when you do, say so in the lesson README *and say why*.
  `DOCKER_HOST=unix:///var/run/docker.sock` is the usual bridge on this machine.
- **Pin versions of alpha tooling.** OpenShell in particular is alpha; a lesson
  that does not name the version it was verified against rots silently.
- **State the host.** These are Linux kernel features being driven from macOS on
  Apple Silicon — say which VM or cluster the boundary actually lives in, or the
  learner will conclude the demo is doing something it is not.
- **A comparison needs a probe, not a claim.** The value of the ladder is that
  each rung is *measured* the same way. A lesson that asserts "gVisor blocks
  this" without running the probe that shows it is not finished.
- **Never demonstrate an escape against anything but this repo's own throwaway
  sandbox.** The subject is defensive: showing that a boundary holds, and where
  it does not.

## Repository structure

```text
sandboxing-tutorial/
├── README.md                  what this is, the isolation ladder, prerequisites
├── syllabus.md                NOT WRITTEN YET — source of truth for lessons
├── tutorial/                  the lesson leaves (currently empty)
├── ruff.toml                  root lint/format policy for every leaf
├── .editorconfig              shfmt's only config source
├── .shellcheckrc              shellcheck opt-in
├── .hadolint.yaml             hadolint opt-in (Dockerfiles)
├── .markdownlint-cli2.yaml    markdownlint opt-in (lesson prose)
├── .mcp.json                  playwright-sandboxing-tutorial
└── .claude/                   this workflow
```
