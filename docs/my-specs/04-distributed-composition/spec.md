# Spec 04 — Composition of the rungs, distributed across chapters (Chapter 5 dissolved)

**Status:** ready to implement — **discovery-first** for the one combo never actually run (§8)
**Targets:** six new composition leaves across `tutorial/chapter-2/3/4`, `infra/lessons.json`,
`syllabus.md` (Chapter 5 removed; per-chapter composition entries added), `docs/isolation-layers.md`,
`docs/decision-table.md` (new)
**Written:** 2026-08-13
**Depends on, in order:** **spec-01** committed → **spec-02** (chapter folders — the composition
leaves live inside them) → **spec-03** (chapter-3 box carries `90-k8s-openshell` beside gVisor and
Kata; the OpenShift box is chapter 4's). Do not start until spec-02's folders and spec-03's
chapter-3 fold-in exist.

---

## 0. Read this first

Read `.claude/CLAUDE.md`, then:

1. `syllabus.md` — the source of truth this spec **restructures** (Chapter 5 removed). Read the
   Chapter 2/3/4 lesson tables and the current Chapter 5 (`:705-724`)
2. `tutorial/.../lesson-09-k8s-openshell/` — `main.py:103` (`create_sandbox`) and **`policy.yaml`**,
   whose `landlock`/`filesystem_policy` comments were authored *as the composition control*
3. `tutorial/.../lesson-05-container-openshell/README.md` § *What OpenShell does not close* — the
   "disjoint columns" headline and the fail-open preview
4. The three impossibility facts, verified in the tree:
   `lesson-03/README.md:44` (rootless podman cannot drive `runsc`),
   `lesson-04/README.md:46` (podman cannot drive a containerd shim-v2 → no Kata),
   `syllabus.md:1017` (gVisor is not a supported OpenShift runtime)
5. Prior art: `~/Projects/Github/lukaskellerstein/agent-eval-benchmark/tutorial/03_sandboxing/`
   `3.2.8_compose_and_compare/` (gVisor combo — **never actually executed**) and
   `3.2.9_k8s_with_kata/` (Kata combo — measured)

Three repo rules that will bite: **never run `main.py` on your workstation** (it writes
`results/…json` from the wrong machine); **never pipe a run through `grep`** (redirect to a file);
**never commit**.

---

## 1. Context — why distribute, not centralise

The composition — OpenShell stacked over a *lower* runtime — was going to be one synthesis lesson in a
Chapter 5. The decision is to **demonstrate each composition in the chapter whose boundary it
composes**, and to **document it, with the reason, in the chapters where the mechanism forbids it**.
Chapter 5 is dissolved; its three parts land as follows:

| Old Chapter 5 part | New home |
|:--|:--|
| Part 1 — cross-rung comparison table from `results/*.json` | **`infra/report/overall.py` already renders this** (`results/overall.html`); no new lesson. Link it from the decision table |
| Part 2 — the composition experiment | **Distributed** into per-chapter composition leaves (§3) |
| Part 3 — the decision table | **`docs/decision-table.md`** (new), linked from the end of chapter 4 and the top-level README |

The finding is unchanged and is a **failure mode**, not a stronger boundary:

> **Composition fails when the lower layer removes a kernel feature the upper layer depends on.**
> OpenShell's filesystem policy leans on **Landlock**. gVisor answers `ENOSYS` to Landlock, so the
> filesystem half of the policy **silently stops being enforced** — `fs_policy_write` flips from
> `PermissionError` to **ALLOWED** and the audit emits a HIGH *"Running WITHOUT filesystem
> restrictions"* finding. `landlock.compatibility: hard_requirement` makes it **fail closed**. Under
> **Kata**, the same write is **blocked** — a real guest kernel ships Landlock.

### Still discovery-first for one combo

**gVisor+OpenShell has never actually been executed** (prior art `3.2.8` is "Expected Output";
`PLAN_KATA.md:327-331`). Kata+OpenShell *was* measured. So the real gVisor leaf (§8) reproduces on a
live box before its prose is written; a non-reproduction is a **reported finding, not a faked row**.

---

## 2. What this is NOT

- **Not new rungs.** OpenShell-over-gVisor is *weaker* on the filesystem axis (Landlock gone). The
  teaching is the rule, not a score.
- **Only Kubernetes hosts both combos.** Kata is a containerd shim-v2 Podman cannot drive, and
  rootless podman cannot drive `runsc` — so **neither combo has a mechanism on the chapter-2 host**.
  OpenShift hosts **Kata+OpenShell only** (no gVisor runtime there). Do not invent combinations, and
  do not force a combo onto a chapter whose driver cannot express it.

---

## 3. The composition matrix — which leaf is real, which is a README stub

Six new leaves (existing lessons 01–13 keep their names and numbers, per spec-02 §3; composition
leaves continue the global sequence as unique ids — the **chapter folder** conveys the chapter, so a
`lesson-15` under `chapter-2` is expected and fine):

| # | Leaf (under its chapter folder) | Combo | Real / stub | Why |
|:--|:--|:--|:--|:--|
| 14 | `chapter-2-one-host/lesson-14-compose-gvisor-openshell` | gVisor+OpenShell | **README stub** | rootless podman cannot drive `runsc` (`lesson-03/README.md:44`) |
| 15 | `chapter-2-one-host/lesson-15-compose-kata-openshell` | Kata+OpenShell | **README stub** | podman cannot drive a shim-v2 (`lesson-04/README.md:46`) |
| 16 | `chapter-3-kubernetes/lesson-16-compose-gvisor-openshell` | gVisor+OpenShell | **REAL** — `box: chapter-03-k8s` | k8s driver + `runtimeClassName: gvisor`. **The never-run combo — discovery-first (§8)** |
| 17 | `chapter-3-kubernetes/lesson-17-compose-kata-openshell` | Kata+OpenShell | **REAL** — `box: chapter-03-k8s` | k8s driver + `runtimeClassName: kata-qemu`. The measured-good combo |
| 18 | `chapter-4-openshift/lesson-18-compose-gvisor-openshell` | gVisor+OpenShell | **README stub** | gVisor unsupported on OpenShift (`syllabus.md:1017`) |
| 19 | `chapter-4-openshift/lesson-19-compose-kata-openshell` | Kata+OpenShell | **REAL** — `box: openshift-sno` | Kata is the OpenShift product; OpenShell meets SCC. The commercially-relevant proof |

Chapter 1 gets no composition leaf — there is no boundary to compose.

---

## 4. The composition mechanism (for the three real leaves)

### Lesson 9 is already the written control

`lesson-09/policy.yaml` was authored for this: its `fs_policy_write` target and
`landlock.compatibility: best_effort` comments name the composition and say lesson 9 is "the clean
CONTROL … nothing is stacked underneath it yet" — OpenShell over **runc**, Landlock present, write
**blocked**. The real leaves flip the runtime under the *same* policy and probe.

### Selecting the lower runtime under OpenShell

Lesson 9 creates the sandbox with `openshell sandbox create --policy` (`main.py:103`) and passes **no**
runtime class (cluster default = runc); `90-k8s-openshell` sets no `defaultRuntimeClassName`. Prior
art selected the runtime with OpenShell's **per-sandbox driver-config overlay** that lands as pod
`spec.runtimeClassName`:

```python
# agent-eval-benchmark 3.2.8/main.py:66, 3.2.9/main.py:80-81
{"kubernetes": {"pod": {"runtime_class_name": "gvisor"}}}   # or "kata-qemu"
# passed as: openshell sandbox create … --driver-config-json '<json>'
```

**Whether this repo's pinned OpenShell CLI supports `--driver-config-json` per sandbox is Step-0
question 1 (§8).** If only a gateway-wide default is available, switch it between combos (a helm
upgrade plus gateway restart) or stand up two gateways — record which, prefer the smallest change
that keeps the combos comparable.

The `fs_policy_write` probe and the `landlock.compatibility` knob already exist in
`lesson-09/policy.yaml`. Each real leaf reuses the probe and supplies **two** policies: the existing
`best_effort` (shows the fail-open) and a new `policy-hard.yaml` (`hard_requirement`; shows
refuse-to-start).

---

## 5. The README stubs (leaves 14, 15, 18) — write the explanation, keep the upgrade path

A stub leaf is **README-only and not runnable**: no `main.py`, no `run.sh`, **not** in `lessons.json`
(no box), so nothing tries to provision it. It is teaching content — the *reason* the composition has
no mechanism here — with a one-line upgrade path (replace the README with a real lesson if the
mechanism ever arrives). It does not appear in `overall.py`'s ladder table (composition is not an
attack-rung), so **no `overall.py` change is needed**. The syllabus lists it in its chapter, marked
*documentation only*.

Draft prose for each stub (tighten to the repo's voice on implementation; link
`docs/isolation-layers.md` for the layer concept rather than re-explaining it):

- **14 — chapter 2, gVisor+OpenShell:** OpenShell's chapter-2 delivery is its **rootless-podman**
  driver — the reason lesson 5 runs inside a NAT'd guest. Composing it over gVisor would need rootless
  podman to drive `runsc`, and it cannot: `runsc` insists on creating the container's cgroup and
  unprivileged it cannot (lesson 3 measured exactly this and is rootful for that reason). So this
  composition has **no mechanism on the chapter-2 host**. It is demonstrated for real in **chapter 3,
  lesson 16**, where OpenShell's kubernetes driver selects the runtime with `runtimeClassName`.
- **15 — chapter 2, Kata+OpenShell:** Kata is a **containerd shim-v2** (`io.containerd.kata.v2`), and
  Podman cannot drive a shim-v2 on any OS (lesson 4 stands Kata up under containerd + nerdctl for
  exactly this reason). OpenShell's chapter-2 driver is podman, so it cannot place a sandbox on Kata
  here. Demonstrated for real in **chapter 3, lesson 17** and **chapter 4, lesson 19**.
- **18 — chapter 4, gVisor+OpenShell:** gVisor is **not a supported OpenShift runtime** — it would
  mean hand-installing `runsc` on RHCOS via MachineConfig, which chapter 4 deliberately does not do
  (chapter 4 teaches what OpenShift ships — Kata). There is no `runtimeClassName: gvisor` to select.
  Demonstrated for real in **chapter 3, lesson 16**.

Each stub ends with: *"If \<the mechanism\> ever ships, replace this README with a runnable lesson."*

---

## 6. The real k8s leaves (16, 17) — on `chapter-03-k8s`

Both declare `"box": "chapter-03-k8s"` (the spec-03 consolidated node carrying 60/70/75/80/90). Copy
lesson 9's OpenShell plumbing into each leaf (leaves do not share packages — the duplication is
deliberate). The only new inputs are the runtime-class overlay (§4) and `policy-hard.yaml`.

- **16 — gVisor+OpenShell (discovery-first):** `best_effort` → expect `fs_policy_write` **ALLOWED** +
  the HIGH audit finding; `hard_requirement` → expect **refuse-to-start**. Assert `runtimeClassName:
  gvisor` from the pod and the gVisor kernel from inside — never the flag. **If it does not reproduce,
  report it (§8 gate).**
- **17 — Kata+OpenShell:** expect `fs_policy_write` **blocked** (Landlock present); assert the Kata
  guest kernel from inside.
- **`card.save`** each writes `results/lesson-16.json` / `lesson-17.json` (verdicts, the audit-finding
  counts, the runtime class asserted from the pod). Field names pass through `Card.save` verbatim.
- **Runner:** each gets a standalone `run.sh` (copy lesson 6's — resolves `box` and tears the **box**
  down). The cheap path is the chapter-3 handoff: `chapter-03.sh --keep`, then the leaf's `run.sh
  --keep`, then `infra/down.sh chapter-03-k8s`.

---

## 7. The real OpenShift leaf (19) — on `openshift-sno`

`"box": "openshift-sno"`. Like lessons 10–13, its `run.sh` **neither provisions nor destroys** — the
SNO cluster is human-owned (€0.263/hr, ~1.5–2 h install; `infra/openshift-sno/install.sh`; teardown
`infra/down.sh openshift-sno`). Kata is the **operator** here (RuntimeClass `kata`, per lesson 12 /
`REPRODUCE.md`), and OpenShell must satisfy **SCC admission** (the lesson-11/lesson-13 regime).

- Expect `fs_policy_write` **blocked** (Landlock present in the operator's Kata guest); assert the VM
  from inside by **DMI=KVM / virtio**, *not* the kernel string — Red Hat builds the guest kernel from
  the same RHEL base, so the version matches the node (`REPRODUCE.md`, `syllabus.md:676`).
- Writes `results/lesson-19.json`.
- **This is the one expensive run.** Batch it with any other chapter-4 work on the SNO box, and do the
  human-owned teardown after. Verify the box against the account when done.

---

## 8. Step-0 — discovery for lesson 16 (gates §6's gVisor leaf)

On the `chapter-03-k8s` box (after spec-03), **run the gVisor combo before writing its prose**.
Capture to a file (`> /tmp/ch3-compose-discovery.log 2>&1`); never through `grep`.

| # | Question | Why |
|:--|:--|:--|
| 1 | Does the pinned OpenShell CLI accept `sandbox create --driver-config-json '{"kubernetes":{"pod":{"runtime_class_name":"gvisor"}}}'`, and does the pod show `spec.runtimeClassName: gvisor`? | §4 fork. Read it back from the pod, not the flag |
| 2 | gVisor+OpenShell `best_effort`: `fs_policy_write` **ALLOWED**? HIGH *"Running WITHOUT filesystem restrictions"* audit finding present? | The never-run claim. If still blocked, the premise is wrong — **stop and report** |
| 3 | gVisor+OpenShell `hard_requirement`: sandbox **refuses to start**? | The fail-closed half |
| 4 | Both sandbox families up without OOM on `PRO2-S`? | Gateway + gVisor pod + (for lesson 17) Kata VM co-resident |

> **Gate.** No per-sandbox mechanism *and* no clean gateway-wide switch, or no reproduction of the
> fail-open → do **not** write lesson 16 as if it worked. Report the blocker with the log. Lesson 17
> (Kata) and lesson 19 (OpenShift) are the measured-good combos and are not gated on this.

---

## 9. Implementation details

- **`infra/lessons.json`:** add rows for **16, 17** (`box: chapter-03-k8s`) and **19**
  (`box: openshift-sno`), each `why` mirroring lessons 6–9 / 10–13 depth. **14, 15, 18 get NO row**
  (stub leaves are not provisioned).
- **`syllabus.md`:** **remove Chapter 5** (`:705-724`); add a *Composition* entry to each of Chapter
  2, 3, 4's lesson tables (real vs "documentation only"); update *Totals* (13 boundary lessons + 3
  real composition + 3 doc-only) and durations; point *Where results go* / the closing at
  `docs/decision-table.md`. **This spec is the sign-off for removing Chapter 5 and adding these
  entries** — no other lesson-list change.
- **`docs/decision-table.md`** (new): the "which boundary for which threat, at what cost" table (old
  Chapter 5 part 3), linking `results/overall.html` (the cross-rung table `overall.py` already
  renders) and the three real composition leaves.
- **`docs/isolation-layers.md`:** the composition failure-mode note (Landlock under gVisor vs Kata),
  and that OpenShift ships Kata only — linked from the leaves, not restated in each README.
- **`pyrightconfig.json`:** regenerate after adding the real leaves (they have `.venv`s); the stubs
  have none.

---

## 10. Verification

Real leaves are tested by running them on their box (redirect to a file, never `grep` the run):

```bash
# after spec-03 + spec-02:
cd infra && ./chapter-03.sh --keep            # brings up chapter-03-k8s once
cd tutorial/chapter-3-kubernetes/lesson-16-compose-gvisor-openshell && ./run.sh --keep
cd tutorial/chapter-3-kubernetes/lesson-17-compose-kata-openshell   && ./run.sh --keep
cd infra && ./down.sh chapter-03-k8s
# lesson 19 batched with chapter-4 work on the human-owned SNO box
```

### Definition of Done

- [ ] **Leaves 16, 17, 19 ran on their boxes** (not transcribed); runtime asserted from inside each
      sandbox/pod (gVisor kernel / Kata guest / DMI=KVM), never the flag
- [ ] Lesson 16 gVisor `best_effort` → `fs_policy_write` **ALLOWED** + HIGH audit finding — **or**
      the divergence reported with the captured log (§8)
- [ ] Lesson 16 `hard_requirement` → **refuse-to-start**; lessons 17 & 19 → **blocked** (Landlock)
- [ ] `results/lesson-16.json`, `lesson-17.json`, `lesson-19.json` + `report.html`/`report.json`
      beside each real leaf; `overall.py` still renders the ladder table
- [ ] **Stub leaves 14, 15, 18 exist as README-only, are not in `lessons.json`, and are not
      runnable**; each states the mechanism reason + the upgrade line
- [ ] **Chapter 5 removed from `syllabus.md`**; per-chapter composition entries added; totals updated;
      `docs/decision-table.md` written and linked
- [ ] `pyrightconfig.json` regenerated; `nvim-tools --json --all` adds no findings vs baseline
- [ ] **Account verified empty** — `scw instance server list` / `block volume list` / `instance ip
      list` (zone `fr-par-1`); SNO box torn down (human-owned) if lesson 19 used it

**Intermittency rule:** a run that fails once and passes on re-run with unchanged code is
*intermittent, not fixed*.

---

## 11. Risks

| Risk | Detail | Mitigation |
|:--|:--|:--|
| **gVisor+OpenShell (16) does not reproduce** | Never run upstream | §8 gate — reproduce or report; never fake |
| **No per-sandbox runtime class** | Pinned CLI may only support gateway-wide default | §4 fork — switch the gateway default between combos; record which |
| **Expensive SNO run (19)** | Bare metal, human-owned teardown | Batch with chapter-4 work; DoD checks the box is gone |
| **Stub leaf looks broken to the runner** | A leaf with no `run.sh`/box | Stubs are not in `lessons.json` and not globbed by `overall.py`'s ladder; the syllabus marks them *documentation only* |
| **Syllabus totals drift** | Chapter 5 removed, six leaves added | §9 updates totals explicitly; DoD checks it |
| **`:latest`/live-Landlock traps** | Prior-art traps on the OpenShell path | Use the side-loaded `agent:v1` tag; supply policy at `create`, recreate to switch |

---

## 12. Related decisions already made

- **Chapter 5 dissolved** (user, 2026-08-13). Composition demonstrated in-chapter (real where the
  mechanism allows, README-stub where it does not); the cross-rung table stays `overall.py`; the
  decision table becomes `docs/decision-table.md`.
- **Chapter 4 gets a real Kata+OpenShell** (user) — on the SNO box, the commercially-relevant
  platform, accepting one expensive run.
- **gVisor+OpenShell has exactly one real home** (chapter 3, lesson 16) — chapter 2 (no runsc under
  rootless podman) and chapter 4 (no gVisor on OpenShift) can only document it.
- **Measure, don't transcribe** — the never-run gVisor combo reproduces before it is written up.
- **Stub leaves are README-only and not runnable** (user) — teaching content with an upgrade path,
  outside the runnable-leaf machinery.
- **No renumbering of 01–13** — composition leaves continue the global sequence as unique ids; the
  chapter folder (spec-02) conveys the chapter (§3).
