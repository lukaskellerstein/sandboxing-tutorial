# Spec 02 — Chapter-foldered layout for `tutorial/` and `infra/`

**Status:** ready to implement — **structural refactor, do it on a clean tree**
**Targets:** `tutorial/` (move all leaves under chapter folders), `infra/run.sh`,
`infra/report/overall.py` (+ `render.py` if it globs), `pyrightconfig.json`, `syllabus.md`
(repository-layout section), `.claude/` prose that carries `tutorial/<lesson>` paths,
`infra/substrates/` naming alignment
**Written:** 2026-08-13
**Sequencing:** land **after spec-01 is committed** (it edits flat paths in-flight) and **before
spec-04** (spec-04's new composition leaves live in the chapter folders this spec creates). spec-03
is mostly orthogonal but shares the path-resolution touch points — see §7.

---

## 0. Read this first

Read `.claude/CLAUDE.md`, then the four load-bearing wiring points this refactor touches:

1. `infra/run.sh:67` — `cd sandboxing-tutorial/tutorial/${LESSON}`, the flat assumption that must
   become chapter-aware
2. `infra/report/overall.py:7,207,233` — globs `tutorial/lesson-*/report.json`
3. `infra/chapter-03.sh:8-9` — the comment that **explicitly decided against** grouping folders:
   *"`tutorial/` stays one directory per lesson, so there is no folder there implying a grouping the
   repo does not otherwise have."* This spec **reverses that decision** — rewrite the comment, don't
   leave it contradicting the tree
4. `infra/lessons.json` — keys are **lesson names**, not paths; the refactor must keep it that way
   (§3). Never split it per chapter — it is the single hardware table

**Never commit** (the user commits). **Do the moves with `git mv`** so history follows the files.

---

## 1. Context — why this change

The repo is organised by chapter everywhere *except* the filesystem: `syllabus.md` is chaptered,
`infra/substrates/` is already `chapter-2/` and `chapter-3/`, `lessons.json` groups lessons by a
shared `box`, and the chapter runners are `chapter-0N.sh`. Only `tutorial/` is flat, and that was a
deliberate choice (`chapter-03.sh:8-9`) now reversed by decision: lessons should live **under their
chapter**, and `infra/` should follow the same grouping.

This is a **pure reorganisation** — no lesson's behaviour, probes, or scores change. It is a
prerequisite for spec-04, which adds composition leaves *into* chapter folders.

### Scope

| In scope | Out of scope |
|:--|:--|
| Move `tutorial/lesson-*` → `tutorial/chapter-N-*/lesson-*` | Renaming or renumbering existing lessons (§3 — names stay, churn stays low) |
| Make path resolution chapter-aware (`run.sh`, `overall.py`) | Splitting `lessons.json` — it stays one file, keyed by lesson name |
| Align `infra/` grouping (§5) | Any change to substrate contents or lesson `main.py` |
| Docs/prose that carry `tutorial/<lesson>` paths | `results/` layout — stays flat (§3), lesson names are globally unique |

---

## 2. Target layout

```text
tutorial/
├── chapter-1-no-sandbox/
│   └── lesson-01-no-sandbox/
├── chapter-2-one-host/
│   ├── lesson-02-container/
│   ├── lesson-03-container-gvisor/
│   ├── lesson-04-container-kata/
│   └── lesson-05-container-openshell/
├── chapter-3-kubernetes/
│   ├── lesson-06-k8s/
│   ├── lesson-07-k8s-gvisor/
│   ├── lesson-08-k8s-kata/
│   └── lesson-09-k8s-openshell/
└── chapter-4-openshift/
    ├── lesson-10-openshift-pod/
    ├── lesson-11-openshift-scc/
    ├── lesson-12-openshift-kata/
    └── lesson-13-openshift-openshell/
```

Chapter folder names are kebab-case from `syllabus.md`'s chapter titles. Chapter 5 does **not** get a
folder — it is dissolved by spec-04.

---

## 3. The three decisions that keep churn low

1. **Lesson directory names do not change.** `lesson-04-container-kata` stays
   `lesson-04-container-kata`, only its parent changes. This keeps `lessons.json` keys, `results/`
   filenames, and every `results/lesson-NN.json` reference stable. **Do not renumber.**
2. **Resolution is by glob, not a second source of truth.** Rather than add a `chapter` field to
   `lessons.json` (a second place a lesson→chapter mapping could drift), resolve the directory with a
   glob: a lesson name is globally unique, so `tutorial/*/${LESSON}` matches exactly one path. This
   is robust to future chapter renames and adds no data to maintain.
3. **`results/` stays flat.** `results/lesson-NN.json` is keyed by the globally-unique lesson name;
   nesting it buys nothing and would touch `overall.py`'s reader and every render path. Leave it.

---

## 4. Implementation — `tutorial/` and the two resolvers

### 4a. Move the leaves

```bash
mkdir -p tutorial/chapter-1-no-sandbox tutorial/chapter-2-one-host \
         tutorial/chapter-3-kubernetes tutorial/chapter-4-openshift
git mv tutorial/lesson-01-no-sandbox        tutorial/chapter-1-no-sandbox/
git mv tutorial/lesson-02-container         tutorial/chapter-2-one-host/
# … through lesson-13, into the chapter folder from §2
```

### 4b. `infra/run.sh` — chapter-aware `cd`

Line 67 currently hardcodes `cd sandboxing-tutorial/tutorial/${LESSON}`. Resolve the chapter with a
glob computed once near where `LESSON` is set, and use it on the box side too (the rsync at
`run.sh:45` copies the whole repo, so the new tree is already on the box — only the `cd` path
changes). Pattern:

```bash
# one lesson dir, under exactly one chapter folder; a glob keeps the mapping in one place (the tree)
LESSON_REL=$(cd "${REPO_ROOT}" && ls -d tutorial/*/"${LESSON}" 2>/dev/null | head -1)
[ -n "${LESSON_REL}" ] || die "no tutorial/*/${LESSON} — is the lesson under a chapter folder?"
```

Then `cd sandboxing-tutorial/${LESSON_REL}` on the box. Assert exactly one match (a zero/multi match
is a real error, not a silent first-wins).

### 4c. `infra/report/overall.py` (+ `render.py`)

Change the glob `tutorial/lesson-*/report.json` → `tutorial/*/lesson-*/report.json` at `:7` (doc),
`:207` (the footer string), and `:233` (the "no report yet" path check). Grep `infra/report/` for any
other `tutorial/lesson-*` literal and fix each. Re-run `overall.py` after a lesson to confirm it still
finds reports.

### 4d. `pyrightconfig.json`

Regenerate — the leaf paths moved:
`python3 ~/Projects/Github/lukaskellerstein/mac-setup/projects/scripts/gen-pyrightconfig.py .`
Diff before the user commits; without it basedpyright reports spurious unresolved imports.

### 4e. Docs and prose

- `infra/chapter-03.sh:8-9` — rewrite the "flat tutorial" comment to describe the chapter-foldered
  layout (it currently asserts the opposite).
- `syllabus.md` § *Repository layout* and `.claude/rules/01-project-config.md` / `05-implement.md` —
  update the `tutorial/` tree drawings and any `tutorial/<lesson>` path that is an instruction (leave
  illustrative prose that only names a lesson). CLAUDE.md's `cd tutorial/<lesson> && ./run.sh` becomes
  `cd tutorial/<chapter>/<lesson> && ./run.sh` — or note that the glob-resolving `infra/run.sh <lesson>`
  is the chapter-agnostic entry point.

---

## 5. Implementation — `infra/` grouping

`infra/` is **already** largely chaptered: `substrates/chapter-2/`, `substrates/chapter-3/`, and
`chapter-0N.sh` runners. "Follow the structure in `infra/`" means aligning the rest to that
convention **without** creating a second hardware table.

- **Substrate directory names**: align to the chapter folder names for consistency
  (`substrates/chapter-2/` → `substrates/chapter-2-one-host/`, `chapter-3/` →
  `chapter-3-kubernetes/`). This touches: `lessons.json` substrate arrays (the `"chapter-2/10-podman"`
  strings), `up.sh` (reads `substrates/${sub}.sh`), and `check.sh` (dispatches on `${sub##*/}`
  **basename**, so the directory rename does not affect dispatch). **Weigh this against its churn** —
  if the rename's only gain is cosmetic alignment, it is legitimate to **keep `chapter-2`/`chapter-3`
  as-is** and note that they are already chapter-grouped. Decide once, state it, do not do half.
- **Chapter runners** (`chapter-02.sh`, `chapter-03.sh`): stay in `infra/` — they are chapter-scoped
  by name already. No move.
- **`infra/openshift-sno/`**: chapter-4's cluster tooling. Leave in place (it is referenced by
  `REPRODUCE.md`, `install.sh`, `down.sh`); note in prose that it is chapter 4's substrate.
- **`lessons.json`**: **one file, unchanged in shape.** Keys stay lesson names. Do **not** split it.

> The safe default for §5 is the minimum that makes `infra/` *consistent*: substrates are already
> grouped, runners are already named per chapter, `lessons.json` stays single. If the substrate-dir
> rename is not worth its churn, say so and stop there — the goal is one legible convention, not
> motion for its own sake.

---

## 6. Verification

This is a refactor: the proof is that **nothing changed behaviourally**.

- [ ] `git mv` used throughout — `git log --follow` still traces each lesson
- [ ] One representative lesson per chapter runs green end-to-end via `cd infra && ./run.sh <lesson>`
      (glob resolves the new path); pick the cheapest per chapter (e.g. lesson 01, 02) and the shared
      cluster once (`chapter-03.sh`), **not** all thirteen — the boundaries are unchanged, the path
      resolver is what is under test
- [ ] `python3 infra/report/overall.py` finds every `tutorial/*/lesson-*/report.json` and renders
- [ ] `pyrightconfig.json` regenerated; `nvim-tools --json --all` adds no findings vs baseline
- [ ] No `tutorial/lesson-*` literal remains in `infra/` or `.claude/` prose (grep to confirm)
- [ ] `chapter-03.sh`'s "flat tutorial" comment is gone
- [ ] **Account verified empty** after the smoke runs (`scw instance server list` / `block volume
      list` / `instance ip list`, zone `fr-par-1`)

---

## 7. Interaction with the other specs

- **spec-01 (in-flight)**: edits flat `tutorial/lesson-04`/`lesson-08` paths. **Commit spec-01 first**,
  then run this refactor on the clean tree, so the moves don't collide with uncommitted edits.
- **spec-03 (box consolidation)**: shares the `run.sh` / `overall.py` touch points and adds
  `chapter-02.sh`. If spec-03 lands first, this spec rebases its `run.sh` edit onto spec-03's; if this
  lands first, spec-03's `chapter-02.sh` is authored against the new layout. Either order works;
  **state which you did** in the report.
- **spec-04 (composition)**: **depends on this spec.** Its composition leaves are created directly
  under the chapter folders this spec establishes.

---

## 8. Risks

| Risk | Detail | Mitigation |
|:--|:--|:--|
| **Path resolver misses a lesson** | A glob that matches zero or many silently breaks a run | Assert exactly one match (§4b); the smoke run per chapter (§6) catches it |
| **A `tutorial/lesson-*` literal left behind** | overall.py or a script silently reads nothing | Grep gate in the DoD; nothing may glob the old flat path |
| **Colliding with in-flight spec-01** | Uncommitted edits + a big move = merge pain | Land spec-01 first (§7) |
| **Substrate-dir rename churn** | Renaming `chapter-2/` etc. touches lessons.json + up.sh + check.sh | Optional; the safe default is to leave them (§5). Do it fully or not at all |
| **`git mv` not used** | History detaches from moved files | Mandated in §0; `git log --follow` in the DoD |

---

## 9. Related decisions already made

- **Reverses the flat-`tutorial/` decision** (`chapter-03.sh:8-9`) by the user's instruction. That
  comment is rewritten, not left contradicting the tree.
- **No renumbering, glob resolution, flat `results/`** (§3) — the three choices that keep a
  structural move from becoming a repo-wide rename.
- **`lessons.json` stays one file** — the header's own warning against a "generated second copy" is
  the reason; chaptering the filesystem must not chapter the hardware table.
