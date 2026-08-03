# WORKFLOW — MANDATORY FOR ANY PROMPT THAT RESULTS IN CHANGES

**If you are going to use the Edit or Write tool, or run a command that changes
files, containers, pods or cluster state, you MUST complete the workflow in
`rules/` before reporting completion.** Applies to every type of work — a new
lesson, a fix to an existing one, the syllabus, setup scripts, docs. No
exceptions.

Steps, in order (each phase's detailed procedure is in the correspondingly-numbered
`rules/` file — already loaded into context, no need to open it):

1. **Understand** → [`rules/02-understand.md`](rules/02-understand.md)
2. **Plan** → [`rules/03-plan.md`](rules/03-plan.md) *(skip for trivial changes)*
3. **Implement** → [`rules/05-implement.md`](rules/05-implement.md)
4. **Test** → [`rules/06-testing.md`](rules/06-testing.md)
5. **Report** → [`rules/08-report.md`](rules/08-report.md)

Reference files: [`rules/01-project-config.md`](rules/01-project-config.md)
(what this project is, the isolation ladder, and the prior-art repo to read
first), [`rules/09-code-quality.md`](rules/09-code-quality.md),
[`rules/10-tech-stack.md`](rules/10-tech-stack.md),
[`rules/11-communication.md`](rules/11-communication.md),
[`rules/12-security.md`](rules/12-security.md),
[`rules/machine-tools.md`](rules/machine-tools.md) (the `nvim-tools` and
`lukas-ps` CLIs — pre-approved, read-only),
[`rules/lsp.md`](rules/lsp.md) (the `LSP` tool — only in repos that opted in,
and deferred, so it must be loaded before it can be called).

**NEVER report completion without first running the affected lesson end-to-end
against a live container engine or cluster.** "The code looks right" is not a
test, and in this repo it fails in a specific, silent way: a lesson that
*intends* to run under gVisor or Kata but quietly fell back to `runc` exits 0 and
prints everything the lesson expects. Assert the runtime from inside the sandbox,
never from the flag you passed. Verification is YOUR responsibility — the user
should never need to ask you to test.

**Trivial changes** (a typo in a lesson README, a comment, a version bump in one
`pyproject.toml`): skip step 2. State what you'll do and proceed.

## sandboxing-tutorial at a glance

- **Status: scaffolding (2026-08-03).** Tooling, `.claude/` and `README.md`
  exist. **`syllabus.md` does not, and neither does a single lesson.** The
  syllabus is the source of truth for what lessons exist and in what order, and
  it is written *before* any lesson directory — do not create a leaf the syllabus
  does not list.
- **The subject** — running an agent and its generated code behind a real
  isolation boundary, as a ladder: no sandbox → container → **gVisor** → **Kata
  Containers** → **NVIDIA OpenShell**, across local containers and Kubernetes.
  The finding worth preserving: gVisor and OpenShell are strong in *disjoint*
  columns (kernel attack surface vs. per-binary/L7 policy and audit).
- **Read the prior art before writing anything.**
  `~/Projects/Github/lukaskellerstein/agent-eval-benchmark/tutorial/03_sandboxing`
  already built and measured this ladder; this repo is the standalone tutorial
  version of it. `~/Projects/Github/lukaskellerstein/harbor-tutorial` is the repo
  *shape* being copied.
- **podman is the preferred engine**, Docker only where a tool cannot do podman —
  and the lesson must say which and why.
- **Each lesson is self-contained** — `cd <lesson> && uv sync && uv run python main.py`.
  No workspace, no shared package, no imports across leaves. Running it *is* the
  test; there is no repo-wide suite.
- **This is macOS on Apple Silicon driving Linux kernel features.** The boundary
  lives in the podman machine or a cluster node, not on the host. A lesson that
  does not say where is misleading.
- **`pyrightconfig.json` is deliberately absent** until the first leaf has a
  `.venv`; `nvim-tools` will report `types` as `gated-off` until then. Generating
  it is one command — see [`rules/01-project-config.md`](rules/01-project-config.md).

Full facts → [`rules/01-project-config.md`](rules/01-project-config.md); stack and
conventions → [`rules/10-tech-stack.md`](rules/10-tech-stack.md).

## Standing authorizations — do NOT ask before doing these

These actions are pre-approved. Run them yourself when the situation calls for it.

### Read-only inspection (always safe)

- Reading any file in this repo, and in the two prior-art repos named above
- `git status`, `git diff`, `git log`, `git show`
- `podman ps`, `podman images`, `podman machine list`, `podman compose ps`,
  `podman compose logs`, `podman inspect`
- `docker ps`, `docker images`, `docker compose ps`, `docker compose logs`
- `kubectl config current-context`, `kubectl get` / `describe` / `logs`,
  `kubectl get runtimeclass` — **read-only verbs only**
- `uv tree` / `uv pip list` inside a lesson leaf
- `--help` / `--version` on any of the sandbox tooling (`runsc`, `kata-runtime`,
  `openshell`, `podman`, `kubectl`)

This machine's own `nvim-tools` and `lukas-ps` are pre-approved too, and are
documented once in [`rules/machine-tools.md`](rules/machine-tools.md) — do not
restate them here.

### Pre-approved mutations

Each is scoped to a **named** target — a lesson leaf you state, or this repo's
own throwaway sandboxes. None of them is a licence to act repo-wide or
cluster-wide.

- `uv sync` / `uv lock` inside one named lesson leaf
- Running a lesson end-to-end in a named leaf: `uv run python main.py`. This is
  the test step, and it will pull images and start containers.
- Creating, running and removing containers and pods **that this repo's lessons
  create**, under any runtime
- `podman compose up -d`, `podman compose restart <service>`,
  `podman compose logs` — this repo's own stack only
- Pulling an image a lesson declares it needs
- Creating a new lesson directory when `syllabus.md` lists it, following
  [`rules/05-implement.md`](rules/05-implement.md)
- Regenerating `pyrightconfig.json` with the mac-setup script after adding a leaf

### Requires confirmation — always ask first

- **Anything that writes to a Kubernetes cluster** — `kubectl apply`, `create`,
  `delete`, `patch`, or installing a `RuntimeClass`, operator or Helm chart.
  State `kubectl config current-context` first, every time. A cluster here may be
  the external home lab, not a throwaway.
- Installing a system-level runtime (`runsc`, Kata, OpenShell) or editing an
  engine's config (`/etc/containers/`, `daemon.json`) — it changes the machine,
  not the repo
- `podman machine rm` / `stop`, `docker system prune`, or removing any image or
  volume this repo did not create
- Writing or changing `syllabus.md`'s lesson list or ordering — it is the source
  of truth and lessons reference each other
- Deleting or renaming an existing lesson leaf
- Any edit spanning more than one lesson leaf
- Anything that would run an escape or exploit technique against something other
  than this repo's own throwaway sandbox

- `git push`, `git push --force`, branch deletes — **never commit unless the user
  explicitly asks**.
- Anything touching secrets, TLS material, tokens, or credential files. A secret
  never enters this repo in plaintext; if one must be versioned at all it is
  SOPS+age — [`rules/12-security.md`](rules/12-security.md). A **kubeconfig is a
  credential**: it is gitignored here and must stay out of the repo.

When in doubt: ask. This is teaching material about security boundaries, which
makes a wrong lesson worse than no lesson — a learner who is shown a sandbox that
was never actually engaged will carry that false confidence into real work.
