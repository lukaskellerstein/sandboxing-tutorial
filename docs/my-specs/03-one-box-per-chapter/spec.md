# Spec 03 — One shared box per chapter

**Status:** ready to implement
**Targets:** `infra/lessons.json`, `infra/chapter-02.sh` (new), `infra/chapter-03.sh`,
`infra/check.sh` (no new cases), `tutorial/lesson-02..09` (`box` fields only), `syllabus.md`, `docs/`
**Written:** 2026-08-13
**Depends on:** spec-01 (`docs/my-specs/01-kata-qemu-firecracker/`) is in-flight in the working tree.
This spec builds on top of its substrates (`chapter-2/35-containerd-devmapper`,
`chapter-3/75-k8s-devmapper`). If spec-01 has **not** landed, drop `35`/`75` from the substrate
lists below — nothing else in this spec changes.

**Interacts with spec-02** (chapter-foldered layout). This spec is topology, spec-02 is filesystem
layout — mostly orthogonal, but both touch `infra/run.sh`'s path resolution and this spec adds
`infra/chapter-02.sh`. Whichever lands first, the other rebases its `run.sh`/runner edit onto it;
state which order you used. If spec-02 has landed, author `chapter-02.sh` and the lesson paths against
the `tutorial/chapter-N/lesson-M` layout; if not, the flat paths here are correct as written.

---

## 0. Read this first

You are implementing a change in **sandboxing-tutorial**, a hands-on tutorial repo about running an
AI agent behind real isolation boundaries. Lessons are the product; there is no application.

Before writing code, read, in order:

1. `.claude/CLAUDE.md` — the mandatory workflow and the standing authorizations
2. `infra/lessons.json` — the **only** per-lesson hardware table, and its long header `_comment`.
   Read the `chapter-03-k8s`, `lesson-09-k8s-openshell` and every `lesson-0N` `why` field
3. `infra/lib.sh` around `lesson_box()` (`:262`), `lesson_substrates()` (`:273`), and
   `box_create_vm()` (`:332`)
4. `infra/chapter-03.sh` — the chapter-runner **pattern this spec copies** for chapter 2, and edits
   for the lesson-9 fold-in
5. `infra/up.sh:120-159` — the substrate loop and the NAT-guest re-point (`:140`), which is the
   reason chapter 2 cannot be a single box (§4)
6. `tutorial/lesson-05-container-openshell/README.md` § *Where this can run* and
   `infra/substrates/chapter-2/50-nat-vm.sh:1-24` — the pasta / podman-5 / public-IP constraint that
   pins lesson 5 to its own box

Three repo rules that will bite you if you skip them:

- **Never run a lesson's `main.py` on your workstation.** It writes `results/lesson-NN.json` from
  whatever machine you are on, silently replacing a real measurement with a laptop stand-in. The
  only correct way to run a lesson is `cd tutorial/<lesson> && ./run.sh` (or the chapter runner),
  which provisions a disposable Scaleway box, runs it there, and destroys it.
- **Never pipe a test run through `grep`.** Redirect the whole run to a file, then grep the file.
- **Never commit.** Not `git commit`, not `git add`. The user commits.

---

## 1. Context — why this change

Today the box topology is uneven:

| Chapter | Lessons | Boxes today |
|:--|:--|:--|
| 1 | 1 | one box (one lesson) |
| 2 | 2, 3, 4, 5 | **four boxes, one per lesson** |
| 3 | 6, 7, 8, 9 | 6/7/8 share `chapter-03-k8s`; **9 has its own box** |
| 4 | 10–13 | one shared box (`openshift-sno`) |

The goal is **one shared box per chapter**: fewer provisions, and — where a chapter's lessons select
between boundaries — an honest menu, because each rung is measured on a node where the others are
installed and working beside it.

**What newly makes this possible.** The account's identity is now verified, lifting the `PLAY2-MICRO`
(8 GB) ceiling that forced lesson 9 onto its own box. `PRO2-XS` (4 vCPU / 16 GB) and `PRO2-S`
(8 vCPU / 32 GB) are now purchasable ×4. `infra/lessons.json`'s `chapter-03-k8s` `why` already
anticipates this: *"If that quota is ever raised, adding `chapter-3/90-k8s-openshell` back to this
list and giving lesson-09 a `box` is a two-line change."* This spec is that change, plus the
chapter-2 consolidation.

### Scope

| In scope | Out of scope |
|:--|:--|
| Chapter 2: new `chapter-02-host` for lessons 2/3/4 + `infra/chapter-02.sh` | **Lesson 5 stays on its own box** — see §4. Not a regression; a documented exception |
| Chapter 3: fold lesson 9 onto `chapter-03-k8s`; edit `chapter-03.sh` | Chapter 5 / lesson 14 — that is spec-04 |
| `infra/lessons.json` box topology + `why` fields | Any change to a lesson's `main.py`, probes, or **measured behaviour**. This is a topology change; scores must not move (§5) |
| `syllabus.md` § *Where this runs*, `infra/README.md`, `infra/substrates/README.md` | New substrates. This spec adds none; it only unions existing ones onto shared boxes |

---

## 2. Per-chapter design

| Chapter | Target | What changes |
|:--|:--|:--|
| **1** (lesson 1) | one box already | **No functional change.** A one-lesson chapter *is* one box. Note conformance in prose; do not churn `lesson-01`. |
| **2** (lessons 2–4) | **NEW `chapter-02-host`** carrying `10-podman, 20-runsc, 30-containerd-kata, 35-containerd-devmapper` | Lessons 2/3/4 get `"box": "chapter-02-host"`. New `infra/chapter-02.sh` runner. |
| **2** (lesson 5) | **own box, unchanged** | The pasta / podman-5 / public-IP constraint (§4) forces a nested Debian-13 guest that re-points the whole box. Stays `lesson-05-container-openshell` with its own hardware row. |
| **3** (lessons 6–9) | fold lesson 9 into `chapter-03-k8s` | Add `chapter-3/90-k8s-openshell` to the shared box's substrates; give `lesson-09` `"box": "chapter-03-k8s"`; drop the lesson-9 special-case from `chapter-03.sh`; bump the box type. |
| **4** (lessons 10–13) | already one box (`openshift-sno`) | **No change.** Document conformance. |

**Net box count: 6 → then chapter 5 (spec-04) reuses chapter 3's box.** Chapter 1: 1. Chapter 2:
2 (`chapter-02-host` + `lesson-05`). Chapter 3: 1 (`chapter-03-k8s`). Chapter 4: 1 (`openshift-sno`).

---

## 3. The mechanism already exists — reuse it, do not invent

Consolidation is **adding `box` fields + one box entry + a chapter runner**. Every primitive is built
and proven by chapter 3:

- **`lesson_box()`** (`lib.sh:262`) resolves a lesson's `box` field, defaulting to the lesson's own
  name (`.[$l].box // $l`). Every hardware accessor resolves through it (`lesson_kind`,
  `lesson_type`, `lesson_substrates` — `lib.sh:267-275`), so a shared lesson carries **no**
  `kind`/`type`/`image`/`substrates` of its own. Duplicating those is exactly the "generated second
  copy" the `lessons.json` header warns against.
- **`down.sh`'s shared-lesson guard** (`down.sh:88-92`) already refuses `./down.sh <a shared lesson>`
  with a message pointing at the owning box. It works for any `box` field, so it covers the new
  shared lessons for free — no edit needed.
- **`check.sh` dispatches per-substrate** (`check.sh:156-161`, `case "${sub##*/}"`), so a box
  carrying N substrates fires all N boundary assertions once, after all substrates finish
  (`up.sh:161-163`). A consolidated box therefore proves every boundary at provision time with no
  new cases.
- **`chapter-03.sh`** is the runner pattern: `up` the shared box once, loop `up`+`run` per lesson
  (idempotent `up` is a no-op for the already-running box), teardown via an `EXIT` trap that destroys
  **every distinct box** the lessons resolve to (`boxes()` derives the set from `lessons.json`, never
  hardcoded).

**Do not touch `lib.sh`, `down.sh`, or `check.sh`'s dispatch.** They are already box-shape-agnostic.

---

## 4. The chapter-2 exception, recorded so it is not "fixed" later

Lesson 5 **cannot** share the chapter-2 host box, and this section is the standing answer to any
future "why isn't chapter 2 a single box?" It was analysed against the live substrates on 2026-08-13.

OpenShell's rootless-podman driver **refuses to start when the host's default-route address is
public** (`50-nat-vm.sh:6-16`, `lesson-05/README.md:93-107`):

```text
compute driver 'podman' requested the gateway default-route interface, but its resolved
address <public ip> is not a private IPv4 address
```

Every Scaleway box has a public default route. The real mechanism is **pasta** (rootless podman's
default network backend): it anchors the sandbox on the host's primary default-route address, and
faking the route's `src` gets the gateway to *start* and then fails at the callback bind, because
pasta pins `host.containers.internal` to its own fixed alias (`50-nat-vm.sh:14-16`). What OpenShell
needs is a **genuine private primary address on the default-route interface**, which `50-nat-vm`
manufactures with a libvirt guest on `virbr0` (`192.168.122.0/24`, masqueraded). Lesson 5 then runs
**inside** that guest, and `up.sh:140-157` re-points the box's `.state` at the guest IP — so after
that substrate, *every* subsequent `run.sh`/`ssh.sh` for that box targets the guest, terminally.
That box-global relocation is what makes co-hosting host-level lessons (2/3/4) impossible.

A second, independent hard requirement pins the guest's OS: OpenShell needs **podman 5 + pasta by
default**, and Ubuntu 24.04 ships podman 4.9.3, which fails it — so the guest is **Debian 13**
(`50-nat-vm.sh:23`) while lessons 2/3/4's host is **Ubuntu Noble**.

Two true-one-box alternatives were considered and rejected:

- **Cloud private-default-route (Scaleway Private Network + Public Gateway).** Would give the host
  itself a private default route so no nested guest is needed. Rejected: `box_create_vm` builds none
  of that, the Public Gateway is a billed resource that must be torn down, **and** it forces the host
  to run podman 5 + pasta — i.e. a Debian-13 host — which re-opens lessons 2/3/4's measurements
  (scored on Ubuntu Noble / podman 4.9.3).
- **Per-lesson libvirt guest-hop** (rework `up.sh`/`run.sh`/`.state` so the guest is an addon and
  only lesson 5 hops in). A genuine true-one-box path with no re-measurement, but a moderate infra
  change with its own regression surface. **Deferred by decision.** If chapter 2's two-box shape ever
  needs to collapse, this is the path — not the cloud one.

**Consequence, and it is a benefit:** the heavy 3 GB NAT guest stays isolated on lesson 5's own box,
so `chapter-02-host` (lessons 2/3/4, no NAT guest) is light — `PRO2-XS` is ample.

---

## 5. Step-0 discovery on live boxes (before writing the runner / editing json)

None of this can be settled from a workstation. Provision, inspect read-only, destroy, verify against
the account (§7).

### 5a. `chapter-02-host` — do the three host boundaries coexist?

Provision a `PRO2-XS` box carrying `10 → 20 → 30 → 35` and confirm from inside each sandbox:

| # | Question | Why |
|:--|:--|:--|
| 1 | Does `podman` default to crun (lesson 2), `podman --runtime runsc` reach a gVisor kernel (lesson 3), and `nerdctl --runtime io.containerd.kata.v2` reach a guest kernel (lesson 4) — **on the same box**? | The chapter-3 node already proves gvisor+kata coexist; this proves it host-side. A silent fallback here is this repo's characteristic failure. |
| 2 | Does installing runsc as an opt-in podman runtime change lesson 2's default path? | Lesson 2 must stay on crun; `20-runsc.sh` registers runsc as opt-in precisely so the default is untouched — confirm. |
| 3 | Ordering: any substrate whose restart reverts an earlier one? `30-containerd-kata` restarts host containerd; `35` (spec-01) restarts it once more after 30; `20-runsc` registers a podman runtime. | Chapter 3's post-80 trap has **no** chapter-2 analogue known, but verify. Order is `10 → 20 → 30 → 35`. |
| 4 | Peak RAM/disk with a Kata guest (2 GB) up. | Confirm `PRO2-XS` (4/16) fits with headroom; size disk (Kata 9.3 GB + 35's thin-pool). |

### 5b. `chapter-03-k8s` — is `90` safe after `80`?

Provision the shared cluster with `60 → 70 → 75 → 80 → 90` and confirm:

| # | Question | Why |
|:--|:--|:--|
| 5 | Does **`90-k8s-openshell` restart k3s**? | If it does, it reverts kata-deploy (the post-80 trap). Static read says **no** — it only touches `systemctl --user` openshell services (`90:107-140`) — but a k3s restart after 80 silently reverts Kata, so verify on the live box (`kubectl get runtimeclass` still lists `kata-qemu` after 90; a Kata pod still boots a guest kernel). |
| 6 | Does the OpenShell gateway + agent-sandbox controller coexist with repeated Kata boots **on `PRO2-S` (32 GB)** without the OOM that took the 8 GB node down? | This is the whole reason lesson 9 was separate. 32 GB is expected to remove it; **measure**, don't assume. Run lesson 8's Part 3b (repeated Kata boots) with the gateway resident. |
| 7 | Do all four `check.sh` cases (60/70→75/80/90) pass on the one node? | The menu is the point: `none`/`gvisor`/`kata-qemu`(/`kata-fc`) all answer, and OpenShell's gateway is `Connected`. |

> **If question 6 still OOMs on `PRO2-S`, STOP** and report it rather than shipping an intermittent
> cluster. The fallback is `PRO2-M`/larger if quota allows, or reverting lesson 9 to its own box with
> a note. Do not tune the lesson to fit a too-small box.

---

## 6. Implementation

### 6.1 Chapter 2 — `chapter-02-host` + `infra/chapter-02.sh`

**`infra/lessons.json`:**

- Add a `chapter-02-host` **box entry** (not a lesson): `kind: vm`, `type: PRO2-XS`,
  `image: ubuntu_noble`, `root_volume_gb: 60`, `substrates: ["chapter-2/10-podman",
  "chapter-2/20-runsc", "chapter-2/30-containerd-kata", "chapter-2/35-containerd-devmapper"]`, and a
  `why` explaining: it is the shared host for lessons 2/3/4; the four boundaries are installed side by
  side so each lesson measures its own on a box where the others exist; **lesson 5 is NOT here** and
  why (§4, one sentence + pointer); `PRO2-XS` because no NAT guest lives here; `60 GB` for Kata +
  the 35 thin-pool. Mirror the depth of the existing `chapter-03-k8s` `why`.
- Lessons 2, 3, 4: **replace** each row's `kind`/`type`/`image`/`root_volume_gb`/`substrates` with a
  single `"box": "chapter-02-host"` + keep the `why` (rewrite the `why` to note it now shares the
  host and what it still uniquely selects — mirror lessons 6/7/8's `why`). Do **not** leave both a
  `box` and hardware fields: a row names *either* its own hardware *or* a `box`, never both.
- **Lesson 5: unchanged.**

**`infra/chapter-02.sh`** (new): copy `infra/chapter-03.sh` structure exactly and adapt:

- `LESSONS=(lesson-02-container lesson-03-container-gvisor lesson-04-container-kata
  lesson-05-container-openshell)`. Include lesson 5 in the runner so the chapter is runnable in one
  command, even though it resolves to a **different** box — `boxes()` (the `jq '.[$l].box // $l'`
  set) handles that: it yields `{chapter-02-host, lesson-05-container-openshell}`, and the `EXIT`
  trap destroys both. This is the same shape `chapter-03.sh` already uses for lesson 9's separate box.
- `SHARED=chapter-02-host`; `up` it once up front, then the per-lesson `up`+`run` loop (idempotent
  `up` no-ops the shared host; for lesson 5 it provisions its own box when the loop reaches it).
- Keep the `--keep`, the collect-failures-and-continue, and the trap-destroys-every-box behaviour
  verbatim. Update the header comment to chapter 2's arithmetic (host built once carries three
  substrates; lesson 5 is a separate box for the pasta reason — one-line pointer to §4).

### 6.2 Chapter 3 — fold lesson 9 in

**`infra/lessons.json`:**

- `chapter-03-k8s`: append `"chapter-3/90-k8s-openshell"` to `substrates` (order
  `60 → 70 → 75 → 80 → 90`); change `type` `PLAY2-MICRO → PRO2-S`; extend `why` — remove the "WHY
  LESSON 9 IS NOT HERE … capacity limit … quota 0/0" paragraph and replace it with: lesson 9 now
  shares this node because identity verification lifted the quota; `PRO2-S` (32 GB) carries the
  resident OpenShell gateway + agent-sandbox controller beside Kata's repeated boots without the OOM
  that took the 8 GB node down; **`90` runs after `80` and must not restart k3s** (it doesn't — only
  `systemctl --user` services), so kata-deploy is not reverted. Keep the existing order/restart
  paragraph and the 75/devmapper detail from spec-01.
- `lesson-09-k8s-openshell`: **replace** its hardware fields with `"box": "chapter-03-k8s"` + a `why`
  matching lessons 6/7/8 (it runs on the shared cluster; OpenShell is the one boundary **not**
  selected by `runtimeClassName` — its sandbox pods take their class from the gateway — but it is
  installed on the same node so the audit/policy axis is measured beside the runtime menu).

**`infra/chapter-03.sh`:** the `LESSONS` array is unchanged (it already lists lesson 9). The
`boxes()` set now collapses to a single box (`chapter-03-k8s`), which the trap and the header comment
should reflect — update the comment that currently explains "lesson 9 owns its own box" to "all four
share one node now (identity-verified quota)". No logic change is required; `boxes()` derives the set
from `lessons.json`, so it self-corrects. **Verify** the header prose no longer claims lesson 9 is
separate.

**`root_volume_gb`:** stays 80 (spec-01 already sized it for the 75 thin-pool; the OpenShell gateway
image is small). Confirm in Step-0 6b.

### 6.3 `infra/check.sh`

**No new cases.** `90-k8s-openshell` already has a case (`check.sh:300-308`, the gateway-Connected
assertion). On the folded box it now fires as part of the same per-substrate loop. Confirm it does.

### 6.4 Chapters 1 and 4 — conformance notes only

- **Chapter 1**: `lesson-01` is already one box. No edit. State conformance in `syllabus.md`.
- **Chapter 4**: `openshift-sno` is already the shared box for 10–13 (`run.sh` neither provisions nor
  destroys; teardown is human-owned). No edit. State conformance.

### 6.5 `syllabus.md` and `infra/` docs

- `syllabus.md` § *Where this runs, and why not on your laptop* / § *Verified on this hardware*: state
  the new topology — one shared box per chapter, chapter 2's documented two-box exception, chapter 3
  now four-on-one after the quota lift. **Do not change the lesson list or ordering.**
- `infra/README.md` and `infra/substrates/README.md`: reflect `chapter-02-host`, `chapter-02.sh`, and
  the lesson-9 fold-in wherever box topology is described.

> `syllabus.md` is the source of truth and changing it normally needs sign-off. **This spec is that
> sign-off**, for the topology/prose edits above only.

---

## 7. Verification — three runs

Running each chapter's box **is** the test. Redirect to a file; never pipe the run through `grep`.

```bash
cd infra && ./chapter-02.sh          > /tmp/chapter-02.log 2>&1   # host box (2,3,4) + lesson 5's own box
cd infra && ./chapter-03.sh          > /tmp/chapter-03.log 2>&1   # 6,7,8,9 on ONE node
```

Lesson 5 is exercised by `chapter-02.sh` on its own box; a standalone
`cd tutorial/lesson-05-container-openshell && ./run.sh` must also still pass unchanged.

### Definition of Done

- [ ] `chapter-02-host` carries lessons 2/3/4; each asserts its own runtime **from inside** the
      sandbox (crun / runsc / kata guest kernel), not from the flag passed
- [ ] Lesson 5 still runs inside its Debian-13 NAT guest on its **own** box, unchanged
- [ ] `chapter-03-k8s` carries 6/7/8/9; `check.sh` fires all boundary assertions (menu answers
      `none`/`gvisor`/`kata-qemu`(/`kata-fc`), OpenShell gateway `Connected`) and Kata is not the
      default; **no OOM** during lesson 8's Part 3b with the gateway resident
- [ ] **Every score unchanged** (pin exact values from `results/lesson-NN.json` before starting;
      known: lesson 2 = 7/13, 3 = 9/13, 4 = 7/13, 5 = 16/19; 6/7/8 reproduce 14/16/14 of 19; lesson 9
      unchanged). **A moved score is a stop-and-investigate, never a number to update.**
- [ ] `report.html` + `report.json` beside each lesson; `results/lesson-0{2..9}.json` written;
      `python3 infra/report/overall.py` regenerates cleanly (no "different hardware" warnings within a
      chapter)
- [ ] `down.sh <a shared lesson>` still refuses with the owning-box message
- [ ] `nvim-tools --json --all` adds no findings versus the baseline taken before you started
      (shellcheck on the new `chapter-02.sh`, shfmt via `.editorconfig`)
- [ ] **Account verified empty** — against the account, not the scripts' output:

  ```bash
  scw instance server list zone=fr-par-1
  scw block volume list   zone=fr-par-1   # sbs root volumes; `instance volume list` CANNOT see them
  scw instance ip list    zone=fr-par-1
  ```

**Intermittency rule:** a run that fails once and passes on re-run with unchanged code is
*intermittent, not fixed*. Report it as such.

---

## 8. What to report back

- The new topology, and what Step-0 (§5) found on each box — especially whether `90` after `80` left
  Kata intact, and whether `PRO2-S` removed the OOM that separated lesson 9
- Every score, confirmed unchanged against `results/*.json`
- Confirmation all boxes are gone, verified against the account
- Anything left undone and why

---

## 9. Risks

| Risk | Detail | Mitigation |
|:--|:--|:--|
| **Measurement drift** | Co-installing four host boundaries could shift a lesson's score if a probe reads the wrong runtime | §5a discovery + the score-unchanged DoD; each lesson asserts its runtime from inside |
| **`90` reverts Kata** | A k3s restart after `80` terminates kata-deploy, which reverts its own install | §5b q5 — verified no-restart, order `…80 → 90`; assert `kata-qemu` still present after 90 |
| **OOM returns** | The 8 GB node died with the gateway resident beside Kata boots | `PRO2-S` (32 GB); §5b q6 **measures** it rather than assuming |
| **Chapter 2 not literally one box** | Lesson 5's pasta/podman-5 constraint | Accepted and documented (§4); the one exception, with the collapse path (per-lesson hop) recorded for later |
| **Forgetting the lesson-9 quota note is stale** | `lessons.json` still says a bigger box is unavailable | §6.2 rewrites that paragraph; DoD checks the prose no longer claims lesson 9 must be separate |

---

## 10. Related decisions already made

- **Chapter 2 = two boxes (option A), not a true-one-box rework.** The cloud private-default-route
  path (B2) and the per-lesson guest-hop (B1) were both considered; A was chosen for lowest risk and
  no re-measurement. Full reasoning in §4.
- **Bigger boxes via verified identity**, not the retired quota workaround. `PRO2-XS`/`PRO2-S` replace
  `PLAY2-*` for the shared boxes.
- **No new substrates, no `main.py` changes.** This is a topology change; the lessons' measured
  behaviour is held constant, which is what the score-unchanged DoD enforces.
- **Chapter 5 reuses chapter 3's consolidated box** — see spec-04. That is why chapter 3's fold-in
  (all four boundaries on one node) is the load-bearing half of this spec.
