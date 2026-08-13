# Spec 01 — Kata with QEMU *and* Firecracker, on both the host and Kubernetes rungs

**Status:** ready to implement
**Targets:** `tutorial/lesson-04-container-kata`, `tutorial/lesson-08-k8s-kata`,
`tutorial/lesson-12-openshift-kata` (docs only), `infra/`, `docs/`
**Written:** 2026-08-13

---

## 0. Read this first

You are implementing a change in **sandboxing-tutorial**, a hands-on tutorial repo about running an
AI agent behind real isolation boundaries. Lessons are the product; there is no application.

Before writing code, read, in order:

1. `.claude/CLAUDE.md` — the mandatory workflow and the standing authorizations
2. `syllabus.md` — the source of truth for which lessons exist, the nine-attack spine, and the
   fixed four-part lesson shape
3. `infra/lessons.json` — the only per-lesson hardware table. Read the `lesson-04-container-kata`
   and `chapter-03-k8s` entries' `why` fields in full
4. `tutorial/lesson-04-container-kata/` and `tutorial/lesson-08-k8s-kata/` — the two leaves you are
   changing
5. **`docs/isolation-layers.md`** — the conceptual doc that already explains the layer this spec
   works in: a *runtime* (gVisor, Kata) and a *hypervisor* (QEMU, Firecracker, Cloud Hypervisor)
   are different kinds of thing, `Kata ==> FIRECRACKER` slots into the hypervisor socket, and
   "Kata + gVisor" is a category error. **Do not re-explain any of this** — the lessons link to it
6. **`docs/app.md`** — states the goal this spec serves: explain the boxes and solutions
   (`no, gvisor, kata, firecracker, openshell`) per lesson, and *"demonstrate a proof on the boxes
   that the solutions are available/installed."* That second clause is what the `check.sh` work
   delivers for Firecracker

Three repo rules that will bite you if you skip them:

- **Never run a lesson's `main.py` on your workstation.** It writes `results/lesson-NN.json` from
  whatever machine you are on, silently replacing a real measurement with a laptop stand-in. The
  only correct way to run a lesson is `cd tutorial/<lesson> && ./run.sh`, which provisions a
  disposable Scaleway box, runs it there, and destroys it.
- **Never pipe a test run through `grep`.** Redirect the whole run to a file, then grep the file. A
  filtered pipeline discards the traceback body, and an undiagnosable failure costs another full
  provision.
- **Never commit.** Not `git commit`, not `git add`. The user commits.

---

## 1. Context — why this change

`syllabus.md:886` currently lists Firecracker under **Deliberately out of scope**:

> *A VMM, one layer below an OCI runtime — never a `--runtime` value. Reachable only as
> `hypervisor = firecracker` under Kata, which additionally needs the devmapper snapshotter.
> Documented in lesson 4, not demonstrated.*

**That decision is reversed.** Firecracker gets demonstrated as a second hypervisor under Kata, on
**both** Kata rungs — the single host (lesson 4) and Kubernetes (lesson 8) — selectable per
container and per pod.

`docs/app.md:6,8` already names `firecracker` among the solutions to explain and prove per box, so
this executes a goal that was already written down rather than adding a new one.

### What this is NOT

**Firecracker is not a new rung on the isolation ladder, and must not be presented as one.**

Both hypervisors run under Kata: same `kata-agent`, same guest kernel package. The security matrix is
expected to be **identical row-for-row** — same `bpf`/`io_uring` reopening, same four network attacks
SUCCEEDED, same evidence row 0. Each lesson must state this tie plainly *as the finding*, not hide it
or imply a difference the numbers do not contain.

The comparison is on three **other** axes: **capabilities, speed, resource efficiency**.

Consequence for the scoreboards: **lesson 4 must remain 7/13 and lesson 8 must remain 14/19.** Every
row this spec adds is `INFO`, in the `cost` group, and INFO rows are never scored. If a score moves,
something is wrong — stop and investigate rather than updating the expected number.

### The headline finding both lessons are built to produce

> **Swapping the VMM does not change your isolation model.** Both sit on KVM and the guest-kernel
> boundary is identical. What changes is the **host-side process the guest talks to** — and that is
> where `kata-fc` is expected to be the *lighter* combination.

That is the sentence the whole change exists to demonstrate. QEMU carries roughly 1.4M lines of C and
decades of device emulation — full PCI, USB, legacy hardware, SCSI, audio. Firecracker is minimal
Rust with **five** emulated devices (virtio-net, virtio-block, virtio-vsock, serial, a minimal
keyboard controller), no BIOS, no PCI, no ACPI, and is built for millions of short-lived microVMs.
Expected consequences, in the order the lessons should present them: **smaller host-side surface**,
**faster boot**, **lower memory per VM**.

**This comparison must be produced by measurement, not quoted.** `docs/isolation-layers.md` does
*not* contain a QEMU-vs-Firecracker weight table — that was checked. Link it for the *layer* concept
(runtime vs hypervisor) and build the weight comparison from your own numbers.

> [!warning]
> **Two ways the "lighter" claim can fail to show up, and neither licenses tuning the measurement
> until it does.**
>
> 1. **Lesson 8's startup number may be swamped.** `time_pod_startup()` measures the whole
>    apply → terminal-phase round trip on purpose, and its own docstring (`k8s.py:250-257`) records
>    the prior art's finding that scheduling, image handling and the kubelet loop **swamped** the VM
>    boot. A Firecracker boot advantage can disappear inside that. Lesson 4's `nerdctl run` path is
>    far shorter and is where it should show most cleanly.
> 2. **Guest RAM is identical** — same guest kernel, same rootfs. Only the *VMM process* differs, so
>    `vmm_footprint()` is the probe that carries the memory half of the claim, not anything read from
>    inside the guest.
>
> If a number comes back flat or contradicts the expectation, **print it and explain it.** A lesson
> that asserts a tax without showing the number teaches folklore — the exact wording lesson 8 already
> uses about the VM boot tax. Do not quietly drop the row, and do not adjust the method until it
> agrees.

### The anti-duplication split — the two lessons teach different things

Running the same comparison twice would be pointless repetition. It is avoided by giving each rung a
different **subject**. The measured numbers appear on both rungs; the prose does not repeat.

| | Subject | What the reader learns |
|:--|:--|:--|
| **Lesson 4** (host) | the **mechanism** | a hypervisor is a component *under* the runtime. Kata ships one shim per hypervisor, and the shim picks its config from its own binary name (`containerd-shim-kata-fc-v2` → `configuration-fc.toml`). Firecracker needs a block-device rootfs, which is visible right on the command line as `nerdctl --snapshotter devmapper` |
| **Lesson 8** (k8s) | the **selection** | the same choice collapses into one `runtimeClassName` field on a pod — declarative, per-pod, chosen from a menu that also holds `gvisor` |

### Scope boundaries

| In scope | Out of scope |
|:--|:--|
| `tutorial/lesson-04-container-kata` — full demonstration | Consolidating chapters onto shared boxes ("all lessons of a chapter on one machine") — separate future work |
| `tutorial/lesson-08-k8s-kata` — full demonstration | Any new lesson leaf. **Do not create one.** The syllabus lists 14 lessons; do not add a 15th |
| `tutorial/lesson-12-openshift-kata` — **documentation only**, §5.3 | `tutorial/lesson-05`, `lesson-09`, `lesson-13` (OpenShell) — untouched |
| `infra/substrates/chapter-2/`, `chapter-3/`, `check.sh`, `lessons.json` | Cloud Hypervisor (`kata-clh`), peer pods, Confidential Containers |
| `syllabus.md`, `docs/isolation-layers.md` | |

---

## 2. The blocker you are fixing

Firecracker under Kata **requires the devmapper snapshotter**. Firecracker's device model has
virtio-block but **no virtio-fs and no 9p**, so the container rootfs must be hot-plugged as a block
device. Upstream how-to:
<https://github.com/kata-containers/kata-containers/blob/main/docs/how-to/how-to-use-kata-containers-with-firecracker.md>

Nothing in this repo configures devmapper today — `grep -rn "devmapper\|snapshotter" infra/` returns
**zero hits**. Both rungs default to overlayfs.

The two rungs solve it differently, and **lesson 4's way is simpler**:

| Rung | How Firecracker gets a block rootfs |
|:--|:--|
| **Lesson 4** — host containerd + `nerdctl` | `nerdctl` accepts `--snapshotter devmapper` **per run**. QEMU keeps overlayfs; Firecracker asks for devmapper at the point of use. No per-runtime config needed |
| **Lesson 8** — k3s containerd | needs a **per-runtime snapshotter** in containerd's config so `kata-qemu` stays on overlayfs while `kata-fc` gets devmapper. containerd `2.3.2-k3s2` supports this |

On the k8s side there is a second wrinkle: kata-deploy registers ~25 RuntimeClasses including
`kata-fc` (`syllabus.md:566`), so **`kata-fc` already exists on that cluster and simply does not
work**. A pod using it fails at creation with a snapshotter error.

**Registered ≠ working.** This is the same class of failure `infra/check.sh:252` already guards
against for gVisor (*"the RuntimeClass was accepted and runc ran anyway, the silent fallback"*).

---

## 3. The critical constraint: substrate ordering on the k3s box

From `infra/lessons.json`, `chapter-03-k8s` → `why`:

> ORDER IS LOAD-BEARING and it is about restarts, not files: `70` runs `systemctl restart k3s`, and
> **nothing may restart k3s after `80`**, because a restart terminates the kata-deploy DaemonSet pod
> and that pod reverts its own install on termination.

Configuring devmapper requires a containerd/k3s restart. Therefore the new k3s devmapper substrate
**must run before 80**, and no post-80 restart is available to you.

The design question this creates: kata-deploy *writes* the `kata-fc` runtime block into k3s's
containerd config, and you need `snapshotter = "devmapper"` inside that block. Either the line is
pre-seeded into k3s's template before kata-deploy appends, or it must be merged into what kata-deploy
writes — with no restart afterwards. **Step 0 settles this.**

Lesson 4's box has no equivalent constraint: host containerd is restarted once by the new substrate,
which runs after `30-containerd-kata`, and `--snapshotter` is then a per-run flag.

---

## 4. Step 0 — Discovery on live boxes (before writing any code)

None of this can be settled from a workstation. Both boxes, read-only, destroyed after.

### 4a. Lesson 4's box

```bash
cd infra && ./up.sh lesson-04-container-kata && ./ssh.sh lesson-04-container-kata
```

| # | Question | Why it matters |
|:--|:--|:--|
| 1 | Does `kata-static` ship a Firecracker binary and an `configuration-fc.toml`, and can `containerd-shim-kata-fc-v2` be symlinked the way `30-containerd-kata.sh:26` symlinks the generic shim? | Decides whether §5.1's substrate is a symlink + config block or a larger install |
| 2 | Does `nerdctl --runtime io.containerd.kata-fc.v2 --snapshotter devmapper` work once a thin-pool exists? | This is the whole lesson-4 mechanism |

### 4b. The chapter-3 box

```bash
cd infra && ./up.sh chapter-03-k8s && ./ssh.sh chapter-03-k8s
```

| # | Question | Why it matters |
|:--|:--|:--|
| 3 | Is `kata-fc` in `kubectl get runtimeclass` on **this** cluster? | The ~25-class count is from a 2026-08-08 measurement on an older, per-lesson box |
| 4 | What exactly does a `kata-fc` pod fail with today? | Expected: snapshotter error. A different failure means the devmapper premise is wrong |
| 5 | Where is k3s's containerd template (`/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.tmpl`), and does kata-deploy append to it? | Decides the shape of §5.2's substrate — see §3 |

### 4c. The gate — applies to both rungs

Firecracker uses **virtio over MMIO and has no PCI bus at all**; Kata's QEMU config uses
**virtio-PCI**. So from inside the guest:

```
kata-qemu  →  /sys/bus/pci/devices/  populated
kata-fc    →  /sys/bus/pci/devices/  empty, /sys/devices/platform/*.virtio_mmio present
```

This is expected but **unverified**. It matters because this repo's core rule is *assert the boundary
from inside the sandbox, never from the flag you passed*. DMI cannot substitute — measured here,
neither `kata-clh` nor `kata-qemu` exposes `/sys/class/dmi` at all (`infra/check.sh:283`,
`lesson-08-k8s-kata/main.py:204`).

> **If the discriminator does not hold, STOP.** Do not ship either lesson until you find a
> from-inside proof of *which VMM* booted. Trusting the runtime name is exactly the silent failure
> this repo exists to prevent. Report the blocker instead.

Destroy both boxes when discovery is done — `./down.sh <name>` — and verify against the account
(§6).

---

## 5. Implementation

### 5.1 Lesson 4 — the host rung, teaching the mechanism

#### New substrate `infra/substrates/chapter-2/35-containerd-devmapper.sh`

Runs **after** `30-containerd-kata`. Creates a devmapper thin-pool, registers the devmapper
snapshotter in host containerd's config, and installs the Firecracker shim so
`io.containerd.kata-fc.v2` resolves.

- Thin-pool backed by sparse data + metadata files (suggested `/var/lib/containerd-devmapper`).
  Size conservatively — see §8.
- Mirror `30-containerd-kata.sh:26`'s symlink pattern for the fc shim. The shim selects its config
  from its **own binary name**, so `containerd-shim-kata-fc-v2` reads `configuration-fc.toml`.
- **Assert, do not assume.** End with a smoke test in the style of `30-containerd-kata.sh:42` —
  a real container under the fc runtime, reporting a guest kernel. A substrate that silently no-ops
  produces a lesson that teaches something false.
- Must pass `shellcheck` and be formatted by `shfmt` (`.shellcheckrc`, `.editorconfig`).
- Document it in `infra/substrates/README.md`, matching the existing entries' depth.

#### `infra/lessons.json` → `lesson-04-container-kata`

- Add `"chapter-2/35-containerd-devmapper"` to `substrates`, after `30-containerd-kata`.
- Raise `root_volume_gb` **40 → 60** for the thin-pool.
- **Do not change `type`** — stays `PLAY2-MICRO`; see §5.2 for why larger is not purchasable.
- Extend the entry's `why` with the pool and the volume growth.

#### `infra/check.sh`

Extend the existing `30-containerd-kata` case with a `kata-fc` assertion: a container under the fc
runtime runs at all, its guest kernel ≠ node kernel, and **`/sys/bus/pci/devices` is empty**.

#### `tutorial/lesson-04-container-kata/main.py`

- `KATA_RUNTIME` at **line 59** is currently the single `"io.containerd.kata.v2"`. Add the
  Firecracker runtime alongside it.
- `run_suite()` (**line 123**) and `guest_exec()` (**line 156**) take the runtime as an argument
  already — reuse them rather than writing new launchers.
- Add a **Part 3b** banner carrying the three axes. Lesson 4 has no 3b today; its banners run
  Part 1 (372) → Part 2 (381) → assertions (388/395/398) → Part 3 (401) → Part 4 (414).
  `tutorial/lesson-08-k8s-kata/main.py` has the 3b pattern to copy.
- **Keep the fixed four-part shape — no Part 5.** Keep `main.py` under ~200 lines; extract helpers
  into a sibling module *in the same leaf* if needed — **never** a shared package.
- **Lines 429-430** print *"Firecracker, for the record, is a VMM one layer BELOW an OCI runtime …
  reachable only as `hypervisor = firecracker` under Kata."* Still true, but the "for the record"
  framing is stale once this lesson demonstrates it. Rewrite it. (An earlier draft of this spec
  argued for leaving `main.py` alone to avoid a re-run; that no longer applies — lesson 4 is being
  re-run regardless.)

#### `tutorial/lesson-04-container-kata/README.md`

- The section at **line 160** is headed `## Scoped out, named on purpose` and lists Firecracker.
  **That heading is now false.** Firecracker moves out of it into the lesson body.
- New sections + sample output matching what the run actually printed.
- Where the runtime-vs-hypervisor distinction needs stating, **link `docs/isolation-layers.md`**
  rather than restating it — a second prose copy is how the two drift apart.

### 5.2 Lesson 8 — the Kubernetes rung, teaching the selection

#### New substrate `infra/substrates/chapter-3/75-k8s-devmapper.sh`

Thin-pool + the devmapper snapshotter in k3s's containerd config, with **`kata-fc` pinned to
devmapper per-runtime** so **`kata-qemu` stays on overlayfs**.

- **Numbered 75** — after 70 (the only substrate that restarts k3s), before 80 (kata-deploy). Its
  own restart happens before kata-deploy ever runs. See §3; this is not a cosmetic choice.
- Same assert-don't-assume rule, `shellcheck`/`shfmt`, and `infra/substrates/README.md` entry.

#### `infra/lessons.json` → `chapter-03-k8s`

- Add `"chapter-3/75-k8s-devmapper"` to `substrates`, **between** `70` and `80`.
- Raise `root_volume_gb` **60 → 80**.
- Extend the `why` with the ordering constraint and the qemu-on-overlayfs / fc-on-devmapper split.

**Do not change `type`.** It stays `PLAY2-MICRO`. Every larger VM type reports quota `0/0` on this
account (POP2-4C-16G, PRO2-XS, BASIC3-X4C-16G, BASIC3-X6C-24G all checked), and `scw` has no
`account quota` subcommand, so a bigger box costs a failed provision to discover. Firecracker is the
*lighter* VMM anyway — the pressure here is disk, not RAM.

`lessons.json` is the **only** per-lesson hardware table. Never create a second copy.

#### `infra/check.sh`

- **New case `75-k8s-devmapper`**: thin-pool exists, snapshotter registered.
- **Extend the `80-k8s-kata` case** with a `kata-fc` assertion mirroring the `kata-qemu` shape
  already there: the pod runs, guest kernel ≠ node kernel (fail with the existing "the shim fell
  back" message if equal), and `/sys/bus/pci/devices` is empty.
- Read class names from the cluster; never hardcode. Follow the precedence logic at
  `check.sh:260-270`.

#### `tutorial/lesson-08-k8s-kata/`

| Axis | Probe | Where it runs |
|:--|:--|:--|
| Capabilities | PCI bus vs virtio-MMIO; CPU/memory hotplug (`/sys/devices/system/memory/`); virtio-fs vs block-only rootfs | inside the guest |
| Speed | a third `time_pod_startup` call under `kata-fc` | **reuse `k8s.py:250` unchanged** |
| Efficiency | VMM process RSS on the node while a pod of each class is up | **new** `vmm_footprint()` in `k8s.py` |

The efficiency probe is new capability for the whole repo: every existing probe runs *inside* the
sandbox, and the VMM's own footprint is a host-side property no lesson has measured. It is also the
only place Firecracker's real design advantage becomes visible — a minimal VMM with five emulated
devices (virtio-net, virtio-block, virtio-vsock, serial, a minimal keyboard controller), no BIOS,
no PCI, no ACPI.

- **`main.py`** — widen the existing Part 3b to three rows (`runc` / `kata-qemu` / `kata-fc`); add
  the capability table; extend Part 2 prose to state that the two hypervisors **tie on the security
  matrix** and that this *is* the finding, tying back to the chapter's refrain *read the matrix,
  never the count*.
- **`k8s.py`** — add `vmm_footprint()`; reuse `time_pod_startup()` as-is (min-of-3, already correct).
- **`card.save(...)`** — add `startup_s_kata_fc`, `vmm_rss_mb_qemu`, `vmm_rss_mb_fc`.
- **`README.md`** — new sections and sample output; link `docs/isolation-layers.md`.

### 5.3 Lesson 12 — documentation only, so the limitation is obvious

OpenShift sandboxed containers ships **QEMU only**. The operator (v1.12.1) registers RuntimeClass
`kata`, and `infra/openshift-sno/REPRODUCE.md:291` records the guest as *"real KVM VM
(QEMU/`kata-monitor` on node)"*. There is no Firecracker option in the product, so the hypervisor
choice lessons 4 and 8 demonstrate **does not exist here**.

Write that down where a reader meets it:

- **`tutorial/lesson-12-openshift-kata/README.md`** — a short note stating the limitation and why:
  chapter 4 teaches what OpenShift actually ships, and QEMU is what it ships. Contrast it with
  lessons 4 and 8 by name.
- **`docs/isolation-layers.md`** — that doc draws three hypervisors under Kata
  (QEMU / Firecracker / Cloud Hypervisor). State which of them OpenShift actually gives you: one.

> **Do not touch `tutorial/lesson-12-openshift-kata/main.py`.** Changing what it prints obliges a
> re-run, and lesson 12's cluster is single-node OpenShift on **bare metal at €0.263/hr with a
> ~1.5–2 h install** that a human owns (`infra/openshift-sno/install.sh`, teardown
> `infra/down.sh openshift-sno`). Prose in a README costs nothing and says the same thing.

### 5.4 `syllabus.md` and `docs/`

- **Remove** the Firecracker row from *Deliberately out of scope* (line 886).
- Update the **chapter 2 lesson-4** and **chapter 3 lesson-8** entries, and § *Engine policy*.
- Add measured numbers to § *Verified on this hardware* **after** both runs are green.

> `syllabus.md` is the source of truth and changing it normally needs sign-off. **This spec is that
> sign-off**, for these edits only. **Do not change the lesson list or its ordering.**

---

## 6. Verification — two boxes

Running each lesson on its box **is** the test. There is no repo-wide suite.

```bash
cd tutorial/lesson-04-container-kata && ./run.sh > /tmp/lesson-04.log 2>&1
cd infra && ./chapter-03.sh                     > /tmp/chapter-03.log 2>&1
```

Redirect to a file and grep the file — never pipe the run itself through `grep`.

`chapter-03.sh` is used rather than lesson 8's own `run.sh` because substrate 75 must not disturb
lessons 6 and 7, which share that node. Chapter 2 needs no equivalent check: lessons 2 and 3 have
their own boxes and do not carry substrate 30 or 35, so nothing there can be affected.

### Definition of Done

- [ ] Both hypervisors run on **each** rung — per container on lesson 4, per pod on lesson 8 —
      and neither becomes the default
- [ ] The Firecracker proof comes from **inside** the guest (PCI-empty), never from the flag passed
- [ ] Guest kernel ≠ node kernel under both hypervisors on both rungs
- [ ] Security matrices **identical** under both hypervisors, both lessons say so, and the scores are
      unchanged: **lesson 4 = 7/13, lesson 8 = 14/19**
- [ ] Speed and VMM-RSS numbers printed on both rungs, and the **"`kata-fc` is the lighter
      combination"** finding either shown by those numbers or explicitly reported as not
      reproducing — never asserted without them (§1)
- [ ] The two lessons' prose does **not** repeat — lesson 4 teaches the mechanism, lesson 8 the
      selection (§1)
- [ ] `check.sh` fires every boundary assertion at provision time, including both new `kata-fc` ones
- [ ] `report.html` + `report.json` beside each lesson; `results/lesson-04.json` and
      `results/lesson-08.json` written
- [ ] Lessons 6 and 7 still green on the shared node
- [ ] Both READMEs match what the runs actually printed
- [ ] Lesson 12's README and `docs/isolation-layers.md` state the QEMU-only limitation
- [ ] `nvim-tools --json --all` adds no findings versus the baseline taken before you started
- [ ] **Account verified empty** — against the account, not the scripts' output:

  ```bash
  scw instance server list zone=fr-par-1
  scw block volume list   zone=fr-par-1   # sbs root volumes; `instance volume list` CANNOT see them
  scw instance ip list    zone=fr-par-1
  ```

**Intermittency rule:** a lesson that fails once and passes on re-run with unchanged code is
*intermittent, not fixed*. Report it as such rather than shipping the green run.

---

## 7. What to report back

- What was implemented, and what Step 0 (§4) actually found on each box
- The measured numbers per rung: startup, VMM RSS, and confirmation both scores held (7/13, 14/19)
- **Whether "`kata-fc` is lighter" actually reproduced**, on which rung, and by how much — including
  a flat or contradictory result, which is a finding and not a failure
- Whether the PCI/MMIO discriminator held
- Confirmation both boxes are gone, verified against the account
- Anything left undone and why

---

## 8. Risks

| Risk | Detail | Mitigation |
|:--|:--|:--|
| **Disk** | Kata alone measured 9.3 GB; a Scaleway VM's default root is 8 GB usable and `kata-static` has died mid-tar with `No space left on device` before. The chapter-3 volume also carries runsc and the agent image | 40 → 60 GB (lesson 4), 60 → 80 GB (chapter 3). If a pool still does not fit, **shrink the pool** — larger VM types are quota 0/0 |
| **The post-80 restart trap** | Any devmapper change needing a containerd restart *after* kata-deploy silently reverts Kata, and the cluster then looks broken for unrelated reasons | Substrate numbered 75; §4 question 5 designs this out instead of discovering it |
| **`kata-fc` broken upstream** | It may be non-functional in kata-deploy 4.0.0 rather than merely unconfigured. There is a live upstream issue on exactly this combination — *"firecracker install working, devmapper issues"*, [kata-containers#12558](https://github.com/kata-containers/kata-containers/issues/12558). **Read it before starting §5.2** | Report it. Do not work around it and do not fake a result |
| **The "lighter" claim not reproducing** | Lesson 8's startup figure can be swamped by scheduling; guest RAM is identical by construction | §1 — print the flat number and explain it. Never tune the method until it agrees |
| **Memory on the k3s node** | The 8 GB node was previously taken down by lesson 8's repeated Kata boots when an OpenShell gateway was also resident | Lesson 9 keeps its own box; do not add `90-k8s-openshell` to this node |
| **Two rungs now cost two boxes** | Every future Firecracker change must re-verify lesson 4 as well as chapter 3 | Accepted deliberately — see §9 |

---

## 9. Related decisions already made

- **Firecracker standalone** (no Kata) was considered and rejected: nothing in the OCI harness
  transfers — the agent image is an OCI image, results come back as one `SCORECARD_JSON` line on
  stdout, and the measured hardening is OCI flags (`--user`, `--read-only`, cap-drop). A standalone
  Firecracker rung would change delivery, hardening and boundary at once, making any moved row
  unattributable.
- **A separate Firecracker lesson** was rejected: the security matrices tie, so a new leaf would
  claim a boundary difference that does not exist. It belongs inside the existing Kata rungs.
- **Both rungs, not just lesson 8.** Doing it only on Kubernetes was proposed and rejected — a
  reader who stops after chapter 2 would never see it. The cost is a second box per test cycle, and
  the duplication is avoided by the mechanism/selection split in §1 rather than by dropping a rung.
- **The no-A/B rule was narrowed, not scrapped.** It still forbids running the *same* measurement in
  two modes (the `egress-off` vs `network-on` design that caused a real defect in lesson 2's Part 3).
  It does not apply to two variants compared on *different* axes, which is what this is.
