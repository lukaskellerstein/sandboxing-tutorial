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
| 2.2.1 | ch2/lesson-01-audit-container | Falco (+custom rules 7,8) | BUILD |
| 2.2.2 | ch2/lesson-02-audit-container-gvisor | Falco gVisor event source | SPIKE (podman `--pod-init-config`) |
| 2.2.3 | ch2/lesson-03-audit-container-kata | in-guest sidecar (needs BTF debug kernel) | SPIKE (kernel-debug present?) |
| 2.2.4 | ch2/lesson-04-audit-container-openshell | OCSF (exists) + auditd-in-guest | BUILD |
| 2.2.5 | ch2/lesson-05-audit-compose-gvisor-openshell | doc-mirror of 1.2.5 | STUB |
| 2.2.6 | ch2/lesson-06-audit-compose-kata-openshell | doc-mirror of 1.2.6 | STUB |
| 2.3.1 | ch3/lesson-01-audit-k8s | Falco + k3s API audit | BUILD |
| 2.3.2 | ch3/lesson-02-audit-k8s-gvisor | Falco gVisor source + API audit | SPIKE (k3s runsc bridge) |
| 2.3.3 | ch3/lesson-03-audit-k8s-kata | k8s API audit + in-guest sidecar | SPIKE |
| 2.3.4 | ch3/lesson-04-audit-k8s-openshell | OCSF + Falco + API audit | BUILD |
| 2.3.5 | ch3/lesson-05-audit-compose-gvisor-openshell | OCSF + Falco gVisor source | SPIKE |
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

**Box topology (co-residency rule):** a **host eBPF sensor (Falco/Tetragon) taxes `syscall_ms`**, so
it must not share a box with a phase-1 lesson. Phase-2 chapters 2 and 3 therefore get their **own**
shared audit boxes carrying that chapter's phase-1 substrates **plus** the sensor substrates:
`chapter-02-audit-host`, `chapter-03-audit-k8s`. Phase-2 chapter 1 gets its own small box
(`chapter-01-audit`). Phase-2 chapter 4 **shares `openshift-sno`** — a second bare-metal cluster is
unaffordable, and its sensors are host-*passive* (auditd, API audit) or in-guest (sidecar), not host
eBPF, so co-residency does not corrupt a cost metric. New audit runners `infra/chapter-02-audit.sh`,
`chapter-03-audit.sh` mirror the EXIT-trap pattern of the existing ones.

**New substrate scripts** (numeric prefix = order, per chapter's audit box):
- `substrates/chapter-2-audit/`: `auditd`, `falco` (with custom rules for attacks 7/8), `falco-gvisor` (generate `--gvisor-config`, wire the runtime), `kata-ebpf-kernel` (register a `kata-qemu-ebpf` RuntimeClass/config pointing at the BTF debug kernel) + in-guest sidecar manifest.
- `substrates/chapter-3-audit/`: `falco` (`--set collectors.containerd.socket=/run/k3s/containerd/containerd.sock`), `k8s-api-audit` (audit policy + webhook/file backend), `falco-gvisor`, the Kata sidecar/kernel pieces.
- `check.sh` gains assertion arms for each new substrate basename (dispatch is on `${sub##*/}`).

**Each phase-2 leaf** = the phase-1 twin's shape + a sensor stack + host-side per-probe RECORDED
merge + a README whose "Dark" column is explained by the phase-1 boundary. Carry the OpenShell/Kata
version pins already in the repo.

**Discovery-first gate for every SPIKE leaf (mirrors spec-04 §8).** Before building a SPIKE leaf, run
its step-0 and **STOP + report** if it fails — do not fabricate a green leaf:

| Gate | For | Check | If it fails |
|:--|:--|:--|:--|
| G1 | 2.2.3, 2.3.3, 2.4.3, 2.4.6 | `ls /opt/kata/share/kata-containers/ \| grep -i debug` on `chapter-02-host` — is the BTF `kernel-debug` in the pinned Kata 4.0.0 tarball? | leaf needs a custom kernel build; report scope change |
| G2 | 2.2.2, 2.3.2, 2.3.5 | Falco gVisor event source under **podman** (2.2.2) / **k3s** (2.3.x): does `--pod-init-config` wire up and stream? | fall back to Docker for that leaf and say why, or mark doc-only |
| G3 | 2.4.1, 2.4.2, 2.4.4 | `oc debug node/… -- systemctl is-active auditd` — is RHCOS auditd already on? | if on, the "0 recorded" claim is already false for phase-1 ch4 — note it; if off, enable via MachineConfig |
| G4 | 2.2.3/2.3.3 sidecar | can a sidecar be injected into an OpenShell-managed `Sandbox` CR (for the OpenShell-composed audit leaves)? | mark the sidecar half doc-only for those leaves |

**Substrate order stays load-bearing** on the k8s audit box: nothing may restart k3s after Kata
(`80`) — Falco's Helm install does not restart k3s (safe), but the gVisor `pod_init_config` edits
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
| **k3s restart after Kata** | reverts kata-deploy DaemonSet | gVisor `pod_init_config` stays with the gVisor substrate; Falco Helm doesn't restart k3s (§7) |
| **Chapter-runner `boxes()` drifts from ids** | EXIT trap tears down nothing → billable box left up | route runners through the single `lesson_box` (A3); teardown-verify in DoD |
| **Doubled cost** | +3 audit boxes | chapter 4 reuses the cluster; audit boxes are per-run and torn down like phase-1 |

---

## 11. Interaction with prior specs / related decisions

- **Depends on spec-04 committed** — renumbers the leaves it created; land on a clean tree.
- **Reverses spec-02 §3's "do not renumber / flat results"** by the user's instruction — §3 documents why the name-glob rationale no longer holds. Specs 01–04 are left as historical record (they predate the id scheme); do not rewrite them.
- **User decisions (2026-08-14):** dotted id canonical (over unique-name glob); full build in one spec (over staged sensor infra); mirror all 6 composition leaves (over runnable-only). The concern that "full build" encodes unverified infra is honoured by the §7/§9 discovery gates, not by narrowing scope.
