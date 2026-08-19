# Spec 05 — Two phases (attacks / audits), per-chapter renumbering to `phase.chapter.lesson`, and the audit-coverage lessons

**Status:** ready to implement — **structural refactor + large new-lesson build; discovery-first for every unverified sensor path (§7, §9)**
**Targets:** `tutorial/` (add `phase1-attacks/`+`phase2-audits/` levels, renumber every leaf, add 19 audit leaves), `infra/lib.sh` + `run.sh` + `up.sh`/`down.sh`/`ssh.sh`/`check.sh` + `ctl.py` (id-keyed resolver), `infra/lessons.json` (re-key to dotted ids, add phase-2 boxes), `infra/chapter-0N.sh` (+ new audit runners), `infra/substrates/` (new sensor substrates), `infra/report/{render,overall}.py` + `infra/images/agent/attacks/{suite,report}.py` (RECORDED dimension), `pyrightconfig.json`, `syllabus.md`, `docs/{isolation-layers,decision-table,orchestration}.md`, `ATTACKS.md`, every leaf `README.md`/`main.py`/`run.sh`/`pyproject.toml`, `.claude/CLAUDE.md` + `rules/*.md`, root `README.md`
**Written:** 2026-08-14
**Depends on, in order:** spec-01 → spec-02 → spec-03 → **spec-04 committed** (this spec renumbers the leaves spec-04 created; land it on a clean tree).

---

## 0. Read this first

Read `.claude/CLAUDE.md`, then the load-bearing wiring this touches (all confirmed at these
locations):

1. `infra/run.sh:31-37` — the `tutorial/*/${LESSON}` two-level glob + "exactly one match" contract; the box-side `cd` at `:79`.
2. `infra/lib.sh:262` — `lesson_box` (`.box // $l`), and its **five duplicate copies**: `chapter-02.sh:52,97`, `chapter-03.sh:50,94`, `ctl.py:158`.
3. `infra/report/render.py:119-122` — `results/lesson-{number}.json` derived by `lesson.split("-")[1]`; and `overall.py:51-55` — "path sort = ladder order" assumption.
4. `infra/lessons.json` — keyed by bare lesson name; the **hardware table and NOWHERE else** (`lib.sh:11`). Re-key it; never split it; never add a second lesson→path source of truth.
5. `docs/my-specs/02-chapter-foldered-layout/spec.md` — the *last* time this move was done (flat→chaptered). It **chose not to renumber and kept `results/` flat because names were globally unique** (`02:§3`). This spec reverses both; §3 below is why that is now safe.

**Three repo rules that will bite:** never commit (the user commits); do every move with `git mv`
so `git log --follow` survives; never "quickly test" by running `main.py` on the workstation — it
overwrites the card with a laptop stand-in.

---

## 1. Context — why this change

Two needs, one restructure:

- **Phase 1 taught "does the boundary hold?" Phase 2 teaches "would you ever know it was tried?"** Every phase-1 lesson blocks (or not) and *forgets*; `audit_records` reads 0 on every rung but the three OpenShell ones. The tutorial is ~95% *Protect*, ~5% *Detect*. Phase 2 mirrors the phase-1 structure so each boundary's audit story sits **beside** the boundary the reader already measured — the dark cells are explained by the phase-1 boundary doing its job.
- **The two-phase split forces a numbering that no longer works globally.** Mirroring means two lessons per boundary; a global 01…N sequence stops being meaningful. Renumber to `phase.chapter.lesson` (e.g. `1.2.3`), each chapter restarting at 01.

> **The finding phase 2 exists to make visible, in one sentence:** the observability ladder runs
> *backwards* to the isolation ladder — host-side sensors see everything on runc, only the sentry
> under gVisor, and **nothing inside a Kata guest** — so full audit coverage is always two sensors
> with disjoint blind spots, and the only sensor that survives every rung (OpenShell's L7 OCSF trail)
> can see network attacks only.

This is a large change deliberately staged (§5 restructure → §6 scoreboard → §7 lessons); each
stage lands and verifies before the next.

### Scope

| In scope | Out of scope |
|:--|:--|
| Add `phase1-attacks/` + `phase2-audits/` levels; renumber every leaf per-chapter | Changing any phase-1 lesson's probes, boundary, or scores |
| Re-key `lessons.json` + all resolvers to the dotted id | Splitting `lessons.json`; adding a lesson→path field |
| Per-attack **RECORDED** dimension on the scorecard (§6) | The external ASCII "nine attacks" graphic (not in this repo) |
| 19 phase-2 audit leaves incl. sensor infra (§7) | Shipping a SPIKE leaf whose mechanism a discovery gate has not confirmed |

---

## 2. What this is NOT

- Not a rename that preserves numbers — it **is** a renumber; `results/`, sandbox names, namespaces, and every cross-reference move.
- Not a second source of truth for lesson→path — the id is *computed from folder positions* (§3), never stored twice.
- Not a "green everywhere" claim for phase 2 — unverified sensor paths are gated, not asserted (§7, §9).
- Not a co-resident sensor install on the phase-1 boxes — that would tax phase-1's `syscall_ms` (§7 box rule).

---

## 3. The two structural decisions, and the collision they resolve

1. **Dotted id `P.C.L` is the canonical key**, computed from folder positions — phase number from `phaseP-*`, chapter number from `chapter-C-*`, lesson number from `lesson-LL-*`. The resolver walks `tutorial/phase*-*/chapter-*-*/lesson-*-*`, builds an `id → relpath` map once, and asserts every `lessons.json` key matches exactly one path. The tree stays the single source of truth; the id is derived, not duplicated.
2. **Four-level tree** `tutorial/<phase>/<chapter>/<lesson>/` — every `parents[3]`→`parents[4]`, every `../../../`→`../../../../`, every `tutorial/*/…` glob → `tutorial/*/*/…`.

**Why this is now safe where spec-02 said "do not renumber":** spec-02 kept global numbers because
resolution was by *name glob* and names were globally unique. Under restart-at-01 that breaks two
ways — the name glob matches multiple chapters (`run.sh:34` dies "matches more than one"), and the
three `compose-gvisor-openshell` / three `compose-kata-openshell` leaves collapse to duplicate
`lesson-0N-compose-*` names (a hard `lessons.json` key collision). The dotted id dissolves both: keys
become `1.2.5`/`1.3.5`/`1.4.5`, unique by construction.

---

## 4. Target layout + authoritative id map

```text
tutorial/
├── phase1-attacks/
│   ├── chapter-1-no-sandbox/          lesson-01-no-sandbox
│   ├── chapter-2-one-host/            lesson-01..06
│   ├── chapter-3-kubernetes/          lesson-01..06
│   └── chapter-4-openshift/           lesson-01..06
└── phase2-audits/
    ├── chapter-1-no-sandbox/          lesson-01-audit-no-sandbox
    ├── chapter-2-one-host/            lesson-01..06 (audit mirrors)
    ├── chapter-3-kubernetes/          lesson-01..06
    └── chapter-4-openshift/           lesson-01..06
```

Chapter folders keep their number+name; the leaf number restarts at 01 per chapter; the descriptive
suffix is preserved (only the leading number changes).

### Phase-1 mapping (git mv the existing 19 leaves)

| new id | new leaf path (under `phase1-attacks/`) | was |
|:--|:--|:--|
| 1.1.1 | chapter-1-no-sandbox/lesson-01-no-sandbox | 01 |
| 1.2.1 | chapter-2-one-host/lesson-01-container | 02 |
| 1.2.2 | chapter-2-one-host/lesson-02-container-gvisor | 03 |
| 1.2.3 | chapter-2-one-host/lesson-03-container-kata | 04 |
| 1.2.4 | chapter-2-one-host/lesson-04-container-openshell | 05 |
| 1.2.5 | chapter-2-one-host/lesson-05-compose-gvisor-openshell | 14 (stub) |
| 1.2.6 | chapter-2-one-host/lesson-06-compose-kata-openshell | 15 (stub) |
| 1.3.1 | chapter-3-kubernetes/lesson-01-k8s | 06 |
| 1.3.2 | chapter-3-kubernetes/lesson-02-k8s-gvisor | 07 |
| 1.3.3 | chapter-3-kubernetes/lesson-03-k8s-kata | 08 |
| 1.3.4 | chapter-3-kubernetes/lesson-04-k8s-openshell | 09 |
| 1.3.5 | chapter-3-kubernetes/lesson-05-compose-gvisor-openshell | 16 (runnable) |
| 1.3.6 | chapter-3-kubernetes/lesson-06-compose-kata-openshell | 17 (runnable) |
| 1.4.1 | chapter-4-openshift/lesson-01-openshift-pod | 10 |
| 1.4.2 | chapter-4-openshift/lesson-02-openshift-scc | 11 |
| 1.4.3 | chapter-4-openshift/lesson-03-openshift-kata | 12 |
| 1.4.4 | chapter-4-openshift/lesson-04-openshift-openshell | 13 |
| 1.4.5 | chapter-4-openshift/lesson-05-compose-gvisor-openshell | 18 (stub) |
| 1.4.6 | chapter-4-openshift/lesson-06-compose-kata-openshell | 19 (runnable) |

### Phase-2 mapping (new leaves; mirror all 6 per chapter)

Each `2.C.L` mirrors `1.C.L`, runs the **same** attack suite, adds the audit sensor stack for that
boundary, and reports per-attack RECORDED. Verification status drives the §9 gate.

| new id | leaf (`phase2-audits/…/lesson-LL-audit-<suffix>`) | sensor stack | status |
|:--|:--|:--|:--|
| 2.1.1 | ch1/lesson-01-audit-no-sandbox | auditd (host) | BUILD |
| 2.2.1 | ch2/lesson-01-audit-container | Tetragon (+a TracingPolicy tagging each attack) | BUILD |
| 2.2.2 | ch2/lesson-02-audit-container-gvisor | ~~host gVisor event source~~ → `runsc --strace` (G2) | SPIKE (podman `--pod-init-config`) |
| 2.2.3 | ch2/lesson-03-audit-container-kata | in-guest sidecar (needs BTF debug kernel) | SPIKE (kernel-debug present?) |
| 2.2.4 | ch2/lesson-04-audit-container-openshell | OCSF (exists) + auditd-in-guest | BUILD |
| 2.2.5 | ch2/lesson-05-audit-compose-gvisor-openshell | doc-mirror of 1.2.5 | STUB |
| 2.2.6 | ch2/lesson-06-audit-compose-kata-openshell | doc-mirror of 1.2.6 | STUB |
| 2.3.1 | ch3/lesson-01-audit-k8s | Tetragon + k3s API audit | BUILT (see the 2026-08-15 amendment: NOT k8s-enriched) |
| 2.3.2 | ch3/lesson-02-audit-k8s-gvisor | `runsc trace` + API audit (G2) | SPIKE (k3s runsc bridge) |
| 2.3.3 | ch3/lesson-03-audit-k8s-kata | k8s API audit + in-guest sidecar | SPIKE |
| 2.3.4 | ch3/lesson-04-audit-k8s-openshell | OCSF + Tetragon + API audit | BUILD |
| 2.3.5 | ch3/lesson-05-audit-compose-gvisor-openshell | OCSF + `runsc trace` (G2) | SPIKE |
| 2.3.6 | ch3/lesson-06-audit-compose-kata-openshell | OCSF (+ optional sidecar) | BUILD (OCSF-over-Kata proven by 1.3.6) |
| 2.4.1 | ch4/lesson-01-audit-openshift-pod | node auditd + OpenShift API audit | SPIKE (RHCOS auditd on?) |
| 2.4.2 | ch4/lesson-02-audit-openshift-scc | node auditd + API audit | SPIKE |
| 2.4.3 | ch4/lesson-03-audit-openshift-kata | API audit + in-guest sidecar | SPIKE |
| 2.4.4 | ch4/lesson-04-audit-openshift-openshell | OCSF + node auditd + API audit | SPIKE |
| 2.4.5 | ch4/lesson-05-audit-compose-gvisor-openshell | doc-mirror | STUB |
| 2.4.6 | ch4/lesson-06-audit-compose-kata-openshell | OCSF (+ sidecar) | SPIKE |

---

## 5. Stage A — restructure & renumber (mechanical, verify before Stage B)

Do this whole stage first and prove nothing behavioural changed on the existing lessons.

**A1. Move + rename** — `mkdir` the two phase dirs and four chapter dirs under each; `git mv` each of
the 19 leaves to its §4 path (renaming the leaf number). Preserve history.

**A2. Re-key `lessons.json`** — lesson keys → dotted ids per §4; **box keys stay descriptive**
(`chapter-02-host`, `chapter-03-k8s`, `openshift-sno` are boxes, not lessons — `lesson_box`'s `// $l`
still distinguishes them). Add phase-2 boxes (§7). Substrate arrays unchanged.

**A3. The resolver (single implementation, kill the duplicates)** — replace the name-glob in
`run.sh:31-37` and its box-side use `:79` with the id→path map from §3. Route every other resolver
through the same map: `render.py:324,340`, `overall.py:55`, `ctl.py:1044,1668`. Collapse the six
`.box // $l` jq copies (§0.2) to one `lesson_box` in `lib.sh` and have `chapter-0N.sh` + `ctl.py`
call it rather than re-implement it.

**A4. Depth off-by-one** (pattern, all 16 code leaves): `main.py` `parents[3]→[4]`; `run.sh`
`INFRA=…/../../../infra → ../../../../infra`; `pyproject.toml` `extend="../../../ruff.toml" →
"../../../../ruff.toml"` (and fix the stale "count the dirs" comment — now leaf→chapter→phase→tutorial→root);
the generated `report.html` `../../../ATTACKS.md → ../../../../ATTACKS.md` (in `render.py:298`).

**A5. Id-derived identifiers** — `results/lesson-{number}.json → results/{id}.json` (`render.py:119-122`,
`load_card`, and `short()` at `render.py:93-96`/`overall.py:44-46` re-derived from the id).
`overall.py` ordering: sort by `(phase,chapter,lesson)` parsed from id, **grouped by phase** (phase-1
= the attack ladder; phase-2 = the RECORDED coverage table). Per-leaf `main.py` constants: `LESSON`,
`RESULTS`, `NAMESPACE`/`NS`, `POLICY_OUT`, the `Card(lesson=…)` arg, and any `PREVIOUS =
results/lesson-NN.json` re-pointed to the new id. **Cloud-safe id**: Scaleway/console/state names must
not contain dots — `box_name` (`lib.sh:286`), `.state/<key>.env`, tags, hostnames, and OpenShell
`SANDBOX`/`NAMESPACE` use the id with `.`→`-` (`1.2.4`→`1-2-4`, e.g. `sbx-1-2-4`), honouring the
19-char sandbox cap.

**A6. Chapter runners** — rewrite the hardcoded lesson arrays in `chapter-02.sh:35-40` and
`chapter-03.sh:33-38` to the new ids; keep `SHARED=chapter-0N-*`.

**A7. `pyrightconfig.json`** — regenerate (32 hardcoded paths moved):
`python3 ~/Projects/Github/lukaskellerstein/mac-setup/projects/scripts/gen-pyrightconfig.py .`; diff before commit.

**A8. Hardcoded full paths** — `openshift-sno/install.sh:743,745,1053` (the `:743` `openshell` path is
executable and fails *soft* to a no-op) and `ctl.py:1842` / `tui/src/app.tsx:842` "lesson-10..13"
strings → new ids.

---

## 6. Stage B — the per-attack RECORDED dimension (the phase-2 scoreboard)

Evidence stops being one `audit_records` integer and becomes an attribute of every probe — the
scoreboard phase-2 needs.

- **`infra/images/agent/attacks/report.py`** — `Finding` gains `recorded: str|None` with four states: `LOGGED` (a record names this attack), `NOT_LOGGED` (this attack crossed a sensor that *could* record it and nothing was written — the alarming state), `NO_SENSOR` (nothing in this stack can observe it), `NOT_RUN`. Keep `evidence` host-side-merged (a process cannot see its own trail); the per-probe recorded status is computed by the lesson `main.py` from sensor logs, mapped to each probe by destination/identity (collector URL→exfiltrate, metadata IP→cloud_metadata, gateway+method→egress/http_method, `/tmp` curl clone→binary_scoped). Reuse the ready-made parser at `~/Projects/Github/lukaskellerstein/agent-eval-benchmark/shared/shared/core/openshell/audit.py` (`parse_decisions`) instead of the crude substring filter now in the OpenShell leaves.
- **`infra/report/render.py`** — a `RECORDED` band, one cell per probe, its own palette (the teal of the `evidence` group at three intensities, or filled/hollow/absent glyph — **never** the verdict green/red, which is an orthogonal axis). Encode by glyph+label, not colour alone. Explicitly badge the worst cell, `SUCCEEDED + NOT_LOGGED` (e.g. `plant_backdoor` on the OpenShell rungs). Render `NO_SENSOR`/empty as a deliberate solid band, never blank (blank reads as "not measured").
- **`infra/report/overall.py`** — phase-2 view: the RECORDED matrix across rungs. Phase-1 view unchanged.
- Retire the standalone `audit_records` scored row where the per-probe band replaces it, and reconcile the `x/19` tally (it dropped one scored row — mirror spec-04's honesty about tally changes rather than silently shifting the headline).

Phase-1 leaves keep running the suite; their RECORDED band is a wall of `NO_SENSOR` — which *is* the
finding, and the motivation for phase 2.

---

## 7. Stage C — the 19 phase-2 audit leaves

> **AMENDMENT 2026-08-15 — the host eBPF sensor is Tetragon (pinned v1.7.0), not Falco.** Everywhere
> below that says Falco, read Tetragon; `substrates/chapter-{2,3}-audit/falco` is
> `.../tetragon`, and `check.sh`'s arm dispatches on `tetragon`. This is **not** a capability
> ranking — on the runc rungs both sensors see the same thing, and by the conventional measures
> Falco is the more established choice (CNCF *graduated* Feb 2024; Tetragon is not a CNCF project).
> The reason is **not mixing instruments across rungs**: if the container rung used one sensor and
> the k8s rung another, a reader could not tell whether a difference between them came from the
> *boundary* or the tool, which is the same argument phase 1 makes for one fixed attack suite.
> Tetragon covers the three positions phase 2 needs with one mechanism — host, Kubernetes with
> native pod enrichment, and the candidate in-guest sidecar under Kata (2.3.3) — where Falco needs
> the k3s containerd socket wired by hand and is still not the in-guest story. The *boundary* findings
> are untouched — G2's gVisor blindness and 2.2.3's Kata zero are properties of **where** a host
> sensor sits, not of which one it is (Falco removed its gVisor source; Tetragon never had one).
>
> **One rung's number DID move, and it is a correction rather than a regression: 2.2.1 reads 7/13,
> not 10/13.** `bpf`, `io_uring_setup` and `perf_event_open` are hooked and still read `NOT_LOGGED`,
> because podman's default seccomp refuses all three at **syscall entry** under `--cap-drop ALL` (it
> allows the first two only with `CAP_SYS_ADMIN` and does not list `io_uring_setup` at all, so it
> falls to `defaultAction: SCMP_ACT_ERRNO`). seccomp is evaluated before the `sys_enter` tracepoint
> and an errno verdict never runs the syscall body, so **no** host sensor can see them — which is why
> the old `LOGGED` cannot have been the workload's call. Measured proof that it is the filter and not
> the kernel: the node carries `CONFIG_IO_URING=y`, the identical call returns `fd=3` under
> `--security-opt seccomp=unconfined`, and `perf_event_open`'s errno moves `EPERM` (the filter) →
> `EACCES` (the kernel's own check). The boundary blocked these three and left no evidence it had
> done so; the only possible witness is the enforcing mechanism itself (`SECCOMP_RET_LOG` → auditd
> `type=SECCOMP`). 2.2.2 is the contrast — gVisor's kernel is in user space, so the sentry records
> all three *before* anything refuses them.
>
> Three mechanics the migration pinned down on the box, each of which had already produced a wrong
> reading before it was found:
> - `read_credentials` hooks **both `sys_open` and `sys_openat`**, not `security_file_open`. The LSM
>   hook only fires once an inode is resolved, so a read of a credential file that does not exist —
>   the hardened container's case — never reaches it, and the probe would read `NOT_LOGGED` for a
>   boundary that blocked a *visible* attempt. Both syscalls, because glibc routes `open()` to
>   `openat` while musl on x86_64 calls `open` directly; hooking one silently misses the other libc.
> - Events are attributed to the workload by their **pid namespace** (`process.ns.pid`, needs
>   `--enable-process-ns`), **never** by `process.docker`. Measured: under rootless podman that id
>   lands on the host-side `podman`/`crun`/`conmon` and *not* on the container's own process — the
>   inverse of what the mapping needs. `check.sh` asserts the attribution at provision time.
> - The pid namespace must carry an **`inum`**. Tetragon emits a synthetic `<kernel>` process whose
>   ns block exists but is empty, and "empty is not host" put one phantom fingerprint in 2.2.3's host
>   trail — breaking its "fully blind" headline with a 1 that was never a workload event.

**Box topology (co-residency rule):** a **host eBPF sensor (Tetragon) taxes `syscall_ms`**, so
it must not share a box with a phase-1 lesson. Phase-2 chapters 2 and 3 therefore get their **own**
shared audit boxes carrying that chapter's phase-1 substrates **plus** the sensor substrates:
`chapter-02-audit-host`, `chapter-03-audit-k8s`. Phase-2 chapter 1 gets its own small box
(`chapter-01-audit`). Phase-2 chapter 4 **shares `openshift-sno`** — a second bare-metal cluster is
unaffordable, and its sensors are host-*passive* (auditd, API audit) or in-guest (sidecar), not host
eBPF, so co-residency does not corrupt a cost metric. New audit runners `infra/chapter-02-audit.sh`,
`chapter-03-audit.sh` mirror the EXIT-trap pattern of the existing ones.

**New substrate scripts** (numeric prefix = order, per chapter's audit box):
- `substrates/chapter-2-audit/`: `auditd`, **`tetragon`** (pinned tarball install + the `sbx-sandboxing` TracingPolicy; the shipped systemd unit is DISABLED so the lesson owns the capture window and the pinned BPF maps), `kata-debug-kernel` (make the BTF/AUDITSYSCALL debug kernel selectable per run by annotation) + in-guest sidecar manifest.
- `substrates/chapter-3-audit/`: **`tetragon`** (same install and policy as chapter 2, and the SAME configuration — see the amendment below; `--enable-k8s-api` was specified here and is NOT used), `k8s-api-audit` (audit policy + file backend on the k3s apiserver), `72-k8s-gvisor-trace` (a second `gvisor-trace` RuntimeClass selecting runsc with `--strace`), and the Kata sidecar/kernel pieces for 2.3.3.
- `check.sh` gains assertion arms for each new substrate basename (dispatch is on `${sub##*/}`).

**Each phase-2 leaf** = the phase-1 twin's shape + a sensor stack + host-side per-probe RECORDED
merge + a README whose "Dark" column is explained by the phase-1 boundary. Carry the OpenShell/Kata
version pins already in the repo.

**Discovery-first gate for every SPIKE leaf (mirrors spec-04 §8).** Before building a SPIKE leaf, run
its step-0 and **STOP + report** if it fails — do not fabricate a green leaf:

| Gate | For | Check | If it fails |
|:--|:--|:--|:--|
| G1 | 2.2.3, 2.3.3, 2.4.3, 2.4.6 | `ls /opt/kata/share/kata-containers/ \| grep -i debug` on `chapter-02-host` — is the BTF `kernel-debug` in the pinned Kata 4.0.0 tarball? | leaf needs a custom kernel build; report scope change |
| G2 | 2.2.2, 2.3.2, 2.3.5 | a host sensor's gVisor event source under **podman** (2.2.2) / **k3s** (2.3.x): does `--pod-init-config` wire up and stream? | fall back to Docker for that leaf and say why, or mark doc-only |
| G3 | 2.4.1, 2.4.2, 2.4.4 | `oc debug node/… -- systemctl is-active auditd` — is RHCOS auditd already on? | if on, the "0 recorded" claim is already false for phase-1 ch4 — note it; if off, enable via MachineConfig |
| G4 | 2.2.3/2.3.3 sidecar | can a sidecar be injected into an OpenShell-managed `Sandbox` CR (for the OpenShell-composed audit leaves)? | mark the sidecar half doc-only for those leaves |

**Substrate order stays load-bearing** on the k8s audit box: nothing may restart k3s after Kata
(`80`) — the tetragon substrate restarts nothing (it disables the shipped unit), but the gVisor `pod_init_config` edits
containerd config (a restart) and must sit with the gVisor substrate, never in a post-Kata script.

---

## 8. Prose & cross-reference updates (~200 sites — rule + gotchas, not an enumeration)

**Mechanical rule:** every `lesson N` / `lesson-NN` / `lessons X–Y` / link href and **link text** →
the new dotted id per §4; every `tutorial/<chapter>/<lesson>` path → `tutorial/<phase>/<chapter>/<lesson>`.
The implementing agent greps each file; the high-value part is the gotchas a naive find-replace gets wrong:

- **Cross-chapter relative links break at the new depth.** Leaf READMEs that already point across chapters with a single `../` (e.g. `lesson-04-container-kata/README.md:265 → ../lesson-08-k8s-kata/`, `lesson-12/README.md:87`, `lesson-13/README.md:9`) are wrong even today and must become `../../chapter-3-kubernetes/…`; adding the phase level makes every cross-*phase* link need `../../../phaseN-…`. Audit every relative link, don't pattern-swap numbers only.
- **`docs/decision-table.md:77-79` link *text* is the bare number** (`[16]`,`[17]`,`[19]`) → `[1.3.5]`,`[1.3.6]`,`[1.4.6]`, hrefs re-pathed; `:97` "lessons 14, 15 and 18" → new ids.
- **`syllabus.md`** is the source of truth and needs the most: the ladder table `:143-147`, hardware table `:206-212` ("lessons 2–4", "6–9"), the **Repository-layout ASCII tree `:458-486`** (redraw with both phases), the "composition leaves continue the global sequence (14–19)" paragraph `:488-493` (now per-chapter ids), the four lesson tables (`:509,546,640,727` — add a phase-2 lesson table per chapter), the Composition section `:809-830`, and the **Totals `:834-846`** (19→38 leaves; recompute durations). Adding lessons to the syllabus lesson list requires the user's sign-off (it is source of truth) — the spec author gets it before creating leaves.
- **`ATTACKS.md`** — the `x/13`,`x/19` tallies and "lesson N" references, plus the §6 tally reconciliation.
- **`docs/isolation-layers.md`**, **`docs/orchestration.md`** — lesson-number and `tutorial/…` path refs (agent-catalogued lists exist).
- **`.claude/CLAUDE.md` + `rules/01,02,05,06`** and root **`README.md`** — every `cd tutorial/<chapter>/<lesson>` becomes three-level (or point at the id-resolving `infra/run.sh <id>` as the canonical entry), the status blocks ("13 leaves", "01–13"), the leaves-table row `rules/01:102`, and the tree drawings. Root `README.md:48` also has a pre-existing wrong path (`infra/terraform/lessons.json` → `infra/lessons.json`) — fix in passing.
- **Older specs go stale but are historical record** — do **not** rewrite specs 01–04; note in §11 that they predate the id scheme.

---

## 9. Verification (staged; each stage gates the next)

**Stage A (restructure) — prove nothing behavioural changed:**
- [ ] `git mv` throughout; `git log --follow` traces each moved leaf
- [ ] resolver: `id → path` map asserts exactly one path per `lessons.json` key; a bad id fails loud
- [ ] one cheap lesson per chapter runs green via `./run.sh <id>` (e.g. `1.1.1`, `1.2.1`) + the shared cluster once via `chapter-03.sh`
- [ ] `overall.py` finds every `tutorial/*/*/report.json`, orders by id, groups by phase
- [ ] `pyrightconfig.json` regenerated; `nvim-tools --json --all` adds no findings vs baseline
- [ ] no `tutorial/*/lesson-*` two-level literal or `parents[3]`/`../../../` remains (grep gate)
- [ ] **account verified empty** after smoke runs (`scw instance server list` / `block volume list` / `instance ip list`, zone `fr-par-1`)

**Stage B (scoreboard):** re-run one phase-1 lesson per chapter; RECORDED band renders (`NO_SENSOR`
wall); re-run an OpenShell leaf — its band shows LOGGED/NOT_LOGGED per probe and badges the
`SUCCEEDED+NOT_LOGGED` cell; tally reconciled and stated.

**Stage C (each phase-2 leaf):** its discovery gate (§7) passed *before* it was built; the leaf runs
green on its **own** audit box (chapters 2–3) or `openshift-sno` (chapter 4); the sensor is asserted
**from inside/against the log**, never from the flag; RECORDED matches the §4 sensor-stack expectation;
`report.html`+`report.json`+`results/<id>.json` written; account verified empty. A leaf whose gate
fails is reported as blocked, not shipped green. **Intermittency rule:** a leaf that fails once and
passes on re-run with unchanged code is intermittent, not fixed — report as such.

---

## 10. Risks

| Risk | Detail | Mitigation |
|:--|:--|:--|
| **Resolver misses/mismaps an id** | zero/many match silently breaks runs | one map, assert exactly one; per-chapter smoke run (§9) |
| **A `tutorial/*/…` or `parents[3]` left behind** | silent "no reports"/wrong root | grep gate in Stage-A DoD |
| **`results/lesson-NN.json` collision** | 4 chapters' `01` overwrite one file | id filenames land first (A5) before any phase-2 run |
| **Cross-chapter `../` link left wrong** | broken lesson navigation | audit every relative link, not number-only swap (§8) |
| **Sensor on a shared phase-1 box** | eBPF taxes `syscall_ms`, corrupts phase-1 cost | own audit boxes for ch2/ch3; passive/in-guest only on shared ch4 (§7) |
| **SPIKE leaf shipped on unverified infra** | a fake-green audit lesson — the exact dishonesty this repo forbids | discovery gate + STOP-and-report per SPIKE (§7) |
| **k3s restart after Kata** | reverts kata-deploy DaemonSet | gVisor `pod_init_config` stays with the gVisor substrate; the tetragon substrate restarts nothing (§7) |
| **Chapter-runner `boxes()` drifts from ids** | EXIT trap tears down nothing → billable box left up | route runners through the single `lesson_box` (A3); teardown-verify in DoD |
| **Doubled cost** | +3 audit boxes | chapter 4 reuses the cluster; audit boxes are per-run and torn down like phase-1 |

---

## 11. Interaction with prior specs / related decisions

- **Depends on spec-04 committed** — renumbers the leaves it created; land on a clean tree.
- **Reverses spec-02 §3's "do not renumber / flat results"** by the user's instruction — §3 documents why the name-glob rationale no longer holds. Specs 01–04 are left as historical record (they predate the id scheme); do not rewrite them.
- **User decisions (2026-08-14):** dotted id canonical (over unique-name glob); full build in one spec (over staged sensor infra); mirror all 6 composition leaves (over runnable-only). The concern that "full build" encodes unverified infra is honoured by the §7/§9 discovery gates, not by narrowing scope.

---

## Amendment (2026-08-15) — §7's Kubernetes pod-enrichment claim is withdrawn

§7 justified Tetragon partly on **native Kubernetes pod enrichment**: `--enable-k8s-api` would stamp
every event with its pod and namespace, so the k8s rung would need no containerd socket wired by hand
and a lesson could map an event to its workload by name. **Measured on a live k3s box, none of that
holds**, and the flag is actively harmful:

1. Tetragon **exits** with it — the flag also enables a TracingPolicy CRD watcher, and the release
   tarball ships no CRDs (`no matches for kind "TracingPolicy" in version "cilium.io/v1alpha1"`).
   `check.sh` saw this as `hits=0`, i.e. exactly like a sensor that observed nothing.
2. With the CRD watcher off it runs and still resolves **no pod** — `process.pod` is null, with and
   without `NODE_NAME`.
3. Tetragon itself asks for `--enable-cri` against k3s's **non-standard** containerd socket — the
   hand-wiring §7 said Tetragon avoided and Falco would have needed.
4. With `--enable-cgidmap --enable-cri --cri-endpoint=…` the CRI client initialises cleanly and
   `process.pod` is **still** null.
5. The flag delays every event up to **30 s** in the EventCache while retrying a lookup that never
   resolves, so a capture window closing promptly reports `NOT LOGGED` for everything the workload did.

**The choice of Tetragon still stands**, on §7's *other* and stronger argument: one instrument across
every rung, so a rung-to-rung difference is attributable to the boundary rather than to the tool. The
enrichment was a bonus that does not exist. The leaves attribute events to one named pod by
**container id** (`process.docker` matched against the pod's `containerID` read from the k8s API),
which is stronger than the sensor's self-report and keeps the sensor configuration byte-identical to
chapter 2's.

Note the attribution rule **inverts** between chapters, and both directions are measured: under
rootless podman `process.docker` is empty on the workload and lands on the host-side runtime (so 2.2.1
uses the pid namespace); under the kubelet it is populated, and the pid namespace is not specific
enough because the stand-in gateway is a second pod in the same namespace.

---

## Amendment (2026-08-15) — G1's Kubernetes sidecar prediction is withdrawn

§ the discovery gates reframed G1 as: a workload container under nerdctl cannot stand up a kernel-side
sensor inside the Kata guest, **but** a privileged *Kubernetes* pod holding "the guest's init context"
can — so the eBPF/auditd sidecar lands in 2.3.3.

**Measured while building 2.3.3, and it is wrong.** All four combinations return `EPERM` from the
guest's audit netlink:

| sidecar | CapEff | result |
| :-- | :-- | :-- |
| uid 1000 + `capabilities.add` | `0000000000000000` (added caps are dropped for a non-root user) | EPERM |
| `runAsUser: 0` + explicit caps | `000000e0e82c25fb` | EPERM |
| `runAsUser: 0` + `privileged: true` | `000001ffffffffff` | EPERM |
| the above **+ `hostPID: true`** | `000001ffffffffff` | EPERM |

The kernel gates the audit netlink on the **initial pid namespace**, and Kata's agent puts the whole
pod in a child one. The decisive evidence is that the process list under `hostPID: true` is
**identical** — `pause` is still PID 1 — so **under Kata the kubelet's "host" is the sandbox, not the
VM's init**. No pod-spec field reaches the guest's init namespace, and privilege is not what is being
checked.

**What Kubernetes actually contributes** is `shareProcessNamespace: true`: one pid namespace for every
container in the pod, *inside the guest*. That is enough for a **ptrace** tracer, which needs no
netlink and no initial namespace — and it is something nerdctl cannot offer at all, because there one
container is one VM and there is nothing to share. So the rung is rescued, with a different sensor
than predicted.

The guest kernel is **not** the limitation: 2.3.3's sidecar loads a real two-instruction eBPF program
successfully, with BTF present on the debug kernel. The fence is specific to audit; eBPF is not
namespace-gated. A CO-RE eBPF sensor could live in the guest — at the same per-pod deployment cost the
tracer pays, which is the finding the lesson closes on.

---

## Amendment (2026-08-15) — chapter 4 built; G3 passes with a caveat, G4 is unnecessary, 2.4.6 is impossible

The SNO cluster was built, used and destroyed on 2026-08-15, and all four buildable chapter-4 audit
leaves (2.4.1–2.4.4) are verified. Three things the spec did not anticipate:

**G3 passes, and the caveat becomes the chapter's finding.** RHCOS runs `auditd`, but with two
`exclude` rules and no syscall rules — it is switched on and watching nothing. Rules can be added at
run time via `oc debug node` + `auditctl` (no MachineConfig, no reboot) and the trail is readable with
`oc adm node-logs`, but those rules are **ephemeral**. So the sensor a managed platform gives you for
free watches the **control plane**, not the kernel, which is the phase-2 mirror of chapter 4's phase-1
thesis that OpenShift adds admission rather than isolation.

**G4 is unnecessary.** OpenShell on OpenShift is ordinary runc, so the node's auditd sees the sandbox
directly (923 paths attributed in 2.4.4) — no sidecar needed. Where one *would* be needed, behind Kata
in 2.4.3, the platform blocks it: no `strace` in the stock UBI image, no way to build one (RHCOS has
no podman; no `*.apps` route to a registry), and `dnf` refused.

**2.4.6 is blocked, because 1.4.6 does not work.** OpenShell's supervisor builds a nested network
namespace with a veth pair, and the OSC Kata **guest image** ships a module set that omits `veth.ko` —
`ip link add … type veth` fails with `Unknown device type` and the sandbox crashloops. The guest
*kernel* is the node's RHEL kernel version (`5.14.0-427.138.1.el9_4`, identical strings), so this is a
packaging difference, not a kernel-config one; Red Hat's KATA-5628 is the same bug class for `nfsv4` /
`dns_resolver`. The identical driver-config overlay works on k3s (1.3.6 / 2.3.6), so nothing here is a
flaw in the composition. **Red Hat has it scheduled — KATA-5840, fixVersion OSC 1.14 (2026-10-01).**
1.4.6's README asserts the composition holds on OpenShift; that assertion is untested-and-false and
needs reframing. The full record, including why no workaround exists on our side and the probe to run
before retrying, is 2.4.6's README (`tutorial/phase2-audits/chapter-4-openshift/lesson-06-audit-compose-kata-openshell/README.md`).

**Attribution needed a third mechanism.** Chapter 2 uses the pid namespace, chapter 3 the container
id, chapter 4 the pod's **SELinux MCS** — each forced by what the layer underneath exposes. uid is the
trap on OpenShift (`USER 1001` is shared with node components), and the MCS lives on the SYSCALL
record's `subj=`, not on the PATH companion's `obj=`, so records must be correlated by audit event
serial.
