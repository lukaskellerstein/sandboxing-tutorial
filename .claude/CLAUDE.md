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
on failure → destroy**, per lesson, and it is one command: `cd tutorial/<phase>/<chapter>/<lesson>
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

- **PHASE 2 EXISTS AND IS PARTLY BUILT (spec 05, 2026-08-15).** The tree gained a phase level:
  `tutorial/phase1-attacks/` (the attack lessons, ids `1.C.L`) and `tutorial/phase2-audits/`
  (the audit twins, ids `2.C.L`). Phase 2 asks the second question — *would you ever know the
  attempt was made?* — by running the SAME attack suite behind the same boundary with a sensor
  watching, and reporting a per-attack RECORDED verdict. **Built and verified: 2.1.1, 2.2.1–2.2.4 and
  ALL SIX of 2.3.1–2.3.6, plus 2.4.1–2.4.4** — every audit chapter is now built, and **2.2.5 / 2.2.6 /
  2.4.5 are documentation-only leaves**. **2.4.6 is BLOCKED, not impossible**: its phase-1 twin 1.4.6
  does not work on OpenShift — OpenShell's supervisor needs a **veth pair** for its L7 proxy, and the
  OSC Kata **guest image** ships a module set that omits `veth.ko` (`ip link add … type veth` →
  `Unknown device type`), while the identical overlay works on k3s. The guest *kernel* is fine — it is
  the node's RHEL kernel version; do not go looking for a kernel-config difference. Red Hat has the fix
  scheduled: **KATA-5840, fixVersion OSC 1.14 (planned 2026-10-01)**. The full record — versions,
  why no workaround exists, and a five-minute probe to run before any lesson work — is
  **2.4.6's README**, which is a handoff document, not a lesson. Every built leaf is a true audit
  twin: **zero rows differ** from its phase-1 containment card. The host eBPF sensor
  is **Tetragon, pinned v1.7.0** (migrated from Falco 2026-08-15) — one sensor across every rung so a
  reader can attribute a rung-to-rung difference to the BOUNDARY rather than to the instrument.
  **The handoff doc is [`docs/my-specs/05-phase-split-and-audit-coverage/current_status.md`](../docs/my-specs/05-phase-split-and-audit-coverage/current_status.md)** — read it before touching phase 2;
  it carries the sensor mechanics that are easy to get wrong and expensive to rediscover.
  - **Do NOT set Tetragon's `--enable-k8s-api`** (measured 2026-08-15, five rounds on a live k3s box):
    it enables a TracingPolicy CRD watcher the release tarball ships no CRDs for so tetragon *exits*,
    it never resolves `process.pod` even with `--enable-cri` against k3s's containerd socket, and it
    holds every event up to **30 s** in the EventCache — which turns a prompt capture window into a
    trail of false NOT_LOGGED. The chapter-3 leaves attribute events to one named POD by **container
    id** (`process.docker` matched against the pod's `containerID` from the k8s API) instead. The rule
    inverts by chapter: rootless podman leaves `process.docker` EMPTY on the workload (2.2.1 uses the
    pid namespace); the kubelet populates it, and the pid namespace cannot separate the attack pod
    from the gateway pod beside it.
  - **Chapter-3 audit substrate order is load-bearing**: `60-k8s → k8s-api-audit → 70-k8s-gvisor →
    72-k8s-gvisor-trace → 75-k8s-devmapper → 80-k8s-kata → 85-kata-debug-kernel → 90-k8s-openshell →
    tetragon`. Everything that restarts k3s must land before 80 (a restart terminates the kata-deploy
    DaemonSet, which reverts its own install on the way out); `85-kata-debug-kernel` must land AFTER
    80 (kata-deploy lays down /opt/kata when it starts) and restarts nothing, as does `tetragon`.
  - **Chapter 4's audit thesis: the platform audits the CONTROL PLANE, not the kernel.** The
    kube-apiserver audit log is on by default; the node's `auditd` runs with two `exclude` rules and no
    syscall rules, and arming it means `auditctl` at run time (ephemeral) or a MachineConfig (mutates
    the immutable OS). **Attribution is by SELinux MCS** — a third key after chapter 2's pid namespace
    and chapter 3's container id; uid is the trap (`USER 1001` is shared with `service-ca-operator`).
    Correlate by audit event SERIAL: the MCS is on the SYSCALL record's `subj=`, while the PATH
    companion's `obj=` is the FILE's context and misses every `/proc` read. Two RHCOS traps make it
    intermittent until handled — the 8192 backlog (raise it, assert `lost=0`) and `max_log_file = 8`
    MB with ROTATE (read the rotated segments; `auditd.conf` is in the immutable image). For an
    OpenShell sandbox scope the rule by `subj_type=container_t`, NOT uid — OpenShell sets no
    `runAsUser`. **2.4.2 is the sharpest finding in phase 2**: SCC admission is the only boundary on
    the ladder that records what it refused, because its decision IS an API request.
  - **2.3.3 CORRECTED discovery gate G1.** A privileged sidecar in a Kata pod does NOT get the guest's
    init context: `privileged` + `runAsUser: 0` + full `CapEff` + `hostPID: true` all still get EPERM
    from the guest's audit netlink, because `hostPID` under Kata is the SANDBOX's namespace, not the
    VM's init. The in-guest sensor is a **ptrace** tracer, enabled by `shareProcessNamespace: true`
    (which nerdctl has no equivalent for). eBPF *does* load in the guest — the fence is audit-specific.
    Under kata-deploy the qemu config is a **symlink** and `sed -i` replaces it rather than editing the
    target; the pod then hangs in ContainerCreating, which reads like a broken Kata install.

- **Status: chapters 1–4 built (2026-08-10); composition leaves added (spec 04, 2026-08-14).**
  The boundary lessons (1.1.1, 1.2.1–1.2.4, 1.3.1–1.3.4, 1.4.1–1.4.4) are written and
  green: 1.1.1, 1.2.1–1.2.4 and 1.3.1–1.3.4 on Scaleway VMs, 1.4.1–1.4.4 on single-node
  OpenShift 4.18.49 on bare metal. **Chapter 5 is dissolved** — composition is now
  demonstrated in-chapter: **lessons 1.3.5, 1.3.6 are runnable and green on `chapter-03-k8s`**
  (verified 2026-08-14), **lesson 1.4.6 is written but UNVERIFIED** (needs the human-owned
  SNO cluster), and **lessons 1.2.5, 1.2.6, 1.4.5 are documentation-only README stubs** (no
  `main.py`, no box, not in `lessons.json`). The syllabus is still the source of truth
  for what lessons exist and in what order, and it is written *before* any lesson
  directory — do not create a leaf the syllabus does not list.
- **The composition finding (measured 2026-08-14, and it diverges from the prior art).**
  OpenShell-over-gVisor (lesson 1.3.5) was the never-run combo. On OpenShell 0.0.99 the
  prior art's predicted `fs_policy_write → ALLOWED` does **not** reproduce: gVisor drops
  Landlock (HIGH `landlock-unavailable` audit finding), but the k8s driver's read-only
  ROOT FILESYSTEM still blocks the write, so the scored result equals the safe Kata
  stack — the audit trail is the only witness, and `hard_requirement` fails closed.
  OpenShell-over-Kata (lessons 1.3.6, 1.4.6) keeps Landlock. The tutorial's headline was
  reframed from "the write flips to ALLOWED" to "Landlock silently disappears; verify
  via the audit trail or fail closed".
- **One shared box per chapter (2026-08-13), declared with `box` in `lessons.json`.**
  `lib.sh`'s `lesson_box()` is the only place that resolves it; every driver calls it
  before touching state, ssh or rsync. **`./down.sh <a shared lesson>` refuses** — the
  lesson owns no box, and printing `destroyed, billing stopped` over a live cluster is a
  false all-clear. The one exception is **lesson 1.2.4, on its own box by hard constraint**:
  OpenShell's rootless-podman driver needs a private primary address on the default-route
  interface, so `50-nat-vm` builds a Debian-13 guest and re-points the whole box inside
  it — which cannot co-host the host-level lessons (`chapter-02-host`'s `why` has the
  full story and the rejected alternatives).
  - **Chapter 2 lessons 1.2.1–1.2.3 share `chapter-02-host`** (PRO2-XS, 16 GB), carrying
    `10`/`20`/`30`/`35` — crun stays rootless podman's default beside opt-in runsc,
    kata-qemu and kata-fc, all asserted from inside at provision time. Order
    10 → 20 → 30 → 35: 20's smoke needs podman, 35 restarts containerd after 30; no
    revert-on-restart trap host-side (kata-static is files, not a DaemonSet).
  - **Chapter 3 lessons 1.3.1–1.3.4 share `chapter-03-k8s`** (PRO2-S, 32 GB), one k3s VM carrying
    `60`/`70`/`75`/`80`/`90`. **Measured on one node:** four kernels answer from inside
    (`6.8.0-106-generic` / `4.19.0-gvisor` / guest `6.18.35` under kata-qemu and kata-fc),
    Kata does not become the default, the OpenShell gateway is Connected beside them, and
    1.3.1/1.3.2/1.3.3 reproduce 14/16/14 of 19 with the gateway resident — the OOM that used to split
    lesson 1.3.4 onto its own 8 GB box does not reproduce on 32 GB. The old **quota 0/0 on
    everything above PLAY2-MICRO was an identity gate**, lifted by verification; `scw`
    still has no `account quota` subcommand, so a new ceiling costs a failed provision to
    discover. Teardown stays automatic — an EXIT trap in `infra/chapter-02.sh` and
    `infra/chapter-03.sh` (each destroys **every** box it used) and in each leaf's
    `run.sh`. **Substrate order 60 → 70 → 75 → 80 → 90 is load-bearing**: 70 and 75
    restart k3s, a restart after 80 terminates the kata-deploy DaemonSet (which reverts
    its own install on the way out), and 90 must stay restart-free — it is, touching only
    `systemctl --user` services.
  - **Chapter 4 (lessons 1.4.1–1.4.4) shares `openshift-sno`**, so its `run.sh` does not
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
- **Each lesson is self-contained** — `cd tutorial/<phase>/<chapter>/<lesson> && ./run.sh` provisions
  the box it runs on, runs it there, and destroys it. No workspace, no shared package, no
  imports across leaves. Running it *is* the test; there is no repo-wide suite. Each
  lesson writes `report.html` + `report.json` beside itself;
  `infra/report/overall.py` builds the cross-lesson view from those. For chapters 2 and 3
  the chapter-level runner is the cheaper path: `cd infra && ./chapter-02.sh` (or
  `./chapter-03.sh`) provisions each chapter's boxes once, runs its lessons in order, and
  destroys on an EXIT trap.
- **This is macOS on Apple Silicon driving Linux kernel features.** Lessons do not
  run here: `infra/` provisions a disposable Scaleway box per lesson and the lesson
  runs *there*. A lesson that does not say where its boundary lives is misleading.
- **`infra/lessons.json` is the only per-lesson hardware table**, read by `infra/lib.sh`
  with `jq` — never add a second copy. A row names *either* its own hardware *or* a `box`
  it shares, never both. Substrate scripts are grouped per chapter
  (`infra/substrates/chapter-2/`, `chapter-3/`) and the arrays carry that path;
  `check.sh` dispatches on the basename. Boxes are provisioned with the `scw` CLI directly
  (no Terraform: each box is independent, created/destroyed by its own id, so there is no
  shared-state lock and parallel provisioning / cancel are trivial). Lessons 1.1.1 and 1.2.1–1.2.4 run on
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
- **Testing one named lesson end-to-end: `cd tutorial/<phase>/<chapter>/<lesson> && ./run.sh`.** This
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
