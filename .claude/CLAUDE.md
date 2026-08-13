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

This repo **did** opt in, for Python and shell (`lsp-python`, `lsp-bash`). Shell
is the one worth remembering: `infra/` is ~30 scripts that `source` each other,
and `infra/lib.sh`'s functions are called from most of them — `findReferences`
before changing one of those signatures, not `grep`. What shell's server cannot
do is diagnose; `shellcheck` findings come from `nvim-tools`, per
[`rules/machine-tools.md`](rules/machine-tools.md).

**NEVER report completion without first running the affected lesson end-to-end on
its own disposable box.** The cycle is **provision → run → validate → investigate
on failure → destroy**, per lesson, and it is one command: `cd tutorial/<chapter>/<lesson>
&& ./run.sh`. Verification is YOUR responsibility — the user should never need to
ask you to test, and never has to tell you to tear a box down.

"The code looks right" is not a test, and in this repo it fails in a specific,
silent way: a lesson that *intends* to run under gVisor or Kata but quietly fell
back to `runc` exits 0 and prints everything the lesson expects. Assert the runtime
from inside the sandbox, never from the flag you passed.

Three failures that have actually happened here, each of which looks like success:

- **Running `main.py` locally to "test quickly."** It overwrites that lesson's card
  with a laptop stand-in, so the next comparison is a laptop against a VM.
- **Piping a test run through `grep`.** The traceback body is discarded and the
  failure costs another full provision to diagnose. Redirect to a file, grep the file.
- **Trusting `destroyed, billing stopped`.** It prints before the API has finished.
  Verify against the account — servers *and* volumes *and* IPs.

A lesson that fails once and passes on re-run with unchanged code is **intermittent,
not fixed**. Report it as such rather than shipping the green run.

**Trivial changes** (a typo in a lesson README, a comment, a version bump in one
`pyproject.toml`): skip step 2. State what you'll do and proceed.

## sandboxing-tutorial at a glance

- **Status: chapters 1–4 built (2026-08-10).** Lessons 01–13 are written and green:
  01–09 on Scaleway VMs, 10–13 on single-node OpenShift 4.18.49 on bare metal.
  **Chapter 5 is unwritten.** The syllabus is still the source of truth for what
  lessons exist and in what order, and it is written *before* any lesson directory —
  do not create a leaf the syllabus does not list.
- **Two chapters share a box, and a lesson declares it with `box` in `lessons.json`.**
  `lib.sh`'s `lesson_box()` is the only place that resolves it; every driver calls it
  before touching state, ssh or rsync. **`./down.sh <a shared lesson>` refuses** — the
  lesson owns no box, and printing `destroyed, billing stopped` over a live cluster is a
  false all-clear.
  - **Chapter 3 lessons 6–8 share `chapter-03-k8s`** (2026-08-13), one k3s VM carrying
    `60`/`70`/`80` — every boundary a workload selects with `runtimeClassName` — so that field
    is a real choice from a menu rather than the only runtime installed. **Measured on one
    node:** `gvisor` and `kata-qemu` coexist, three kernels answer from inside
    (`6.8.0-106-generic` / `4.19.0-gvisor` / guest `6.18.35`), Kata does not become the
    default, and 6/7/8 reproduce 14/16/14 of 19 exactly. **Lesson 9 keeps its own box** —
    OpenShell is not runtime-class-selected (its sandboxes take that from the gateway), and
    its resident gateway pushed an 8 GB node over during lesson 8's repeated Kata boots.
    **Every VM type above `PLAY2-MICRO` is quota 0/0 on this account** (POP2, PRO2, BASIC3 all
    checked), and this `scw` has no `account quota` subcommand — so a bigger box costs a failed
    provision to discover. Raise that quota and all four fit again in two lines of
    `lessons.json`. Teardown stays automatic — an EXIT trap in `infra/chapter-03.sh`
    (which destroys **every** box it used) and in each leaf's `run.sh`. **Substrate order
    60 → 70 → 80 is load-bearing**: 70 is the only one that restarts k3s, and a restart after
    80 terminates the kata-deploy DaemonSet, which reverts its own install on the way out.
  - **Chapter 4 (lessons 10–13) shares `openshift-sno`**, so its `run.sh` does not
    provision or destroy. `infra/openshift-sno/install.sh` brings the cluster up (~1.5–2 h)
    and **`infra/down.sh openshift-sno` is a step you own** — €0.263/hr until you run it.
    Its `--from <stage>` resume path is the one people reach for; `REPRODUCE.md` §8 is the
    catalogue of what breaks there and why each fault looks like a broken cluster when it
    is not. It is **not** a substrate and cannot be one: the install replaces the box's OS
    mid-flight, leaving no `agent` user, no repo checkout and no `uv`.
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
- **Each lesson is self-contained** — `cd tutorial/<chapter>/<lesson> && ./run.sh` provisions
  the box it runs on, runs it there, and destroys it. No workspace, no shared package, no
  imports across leaves. Running it *is* the test; there is no repo-wide suite. Each
  lesson writes `report.html` + `report.json` beside itself;
  `infra/report/overall.py` builds the cross-lesson view from those. For chapter 3 the
  chapter-level runner is the cheaper path: `cd infra && ./chapter-03.sh`
  provisions once, runs 06→09, and destroys on an EXIT trap.
- **This is macOS on Apple Silicon driving Linux kernel features.** Lessons do not
  run here: `infra/` provisions a disposable Scaleway box per lesson and the lesson
  runs *there*. A lesson that does not say where its boundary lives is misleading.
- **`infra/lessons.json` is the only per-lesson hardware table**, read by `infra/lib.sh`
  with `jq` — never add a second copy. A row names *either* its own hardware *or* a `box`
  it shares, never both. Substrate scripts are grouped per chapter
  (`infra/substrates/chapter-2/`, `chapter-3/`) and the arrays carry that path;
  `check.sh` dispatches on the basename. Boxes are provisioned with the `scw` CLI directly
  (no Terraform: each box is independent, created/destroyed by its own id, so there is no
  shared-state lock and parallel provisioning / cancel are trivial). Lessons 1–5 run on
  **VMs** (say "VM", not "Instance"); only chapter 4's OpenShift box needs bare metal. That
  was measured, not assumed — `syllabus.md` § *Verified on this hardware*.

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
- **Testing one named lesson end-to-end: `cd tutorial/<chapter>/<lesson> && ./run.sh`.** This
  is the test step. It provisions a Scaleway VM, runs the lesson there, and destroys
  it — including on failure. Provisioning is billable and therefore pre-approved
  *only* through this path, for one named lesson at a time, and only because the
  same command guarantees the teardown.
- `infra/up.sh` / `run.sh` / `ssh.sh` / `down.sh` for one named lesson, and
  `infra/down.sh --all`, when a failure needs the box kept for inspection
- `python3 infra/report/render.py <lesson>` and `infra/report/overall.py`
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
