# `infra/` — a predefined box per lesson, or per chapter

Every lesson in this tutorial runs on a **disposable Scaleway box**, brought up by one
command and destroyed by another. That is not convenience: the rogue agent writes a
backdoor, installs a package that executes code at install time, and exhausts resources.
Those are real side effects, and they are only acceptable on a machine that is deleted
minutes later.

Usually that box is the lesson's own. **Two chapters instead share one**, and a lesson says
so by carrying `box` in `lessons.json` instead of hardware:

| Chapter | Box | Why it shares | Who tears it down |
| :-- | :-- | :-- | :-- |
| 3 (lessons 6–**8**) | `chapter-03-k8s` | So every runtime a workload can select is installed at once and each lesson's `runtimeClassName` is a real choice | an EXIT trap, as everywhere else |
| 4 (lessons 10–13) | `openshift-sno` | Installing single-node OpenShift takes longer than a lesson does | **you**, and nothing else will |

**Lesson 9 keeps its own box.** OpenShell is the one chapter-3 boundary not chosen with
`runtimeClassName` — its sandboxes take that from the gateway — so it was never part of the menu
the shared cluster exists to show, and its resident gateway is what pushed an 8 GB node over during
lesson 8's repeated Kata guest boots. `infra/lessons.json` records the measurement and the account
quota ceiling that ruled out simply buying a bigger box.

`lesson_box()` in `lib.sh` is the one place that resolves it, and every driver calls it
before touching state, ssh or rsync. `./down.sh lesson-06-k8s` therefore **refuses**: the
lesson does not own a box, and reporting `destroyed, billing stopped` over a cluster that
is still running is the expensive half of the 2026-08-10 incident wearing a different hat.

```bash
cd infra
./up.sh --list                          # which lessons have a box definition
./up.sh   lesson-03-container-gvisor    # provision + substrates + assert the boundary
./run.sh  lesson-03-container-gvisor    # run the lesson there, fetch results/
./ssh.sh  lesson-03-container-gvisor    # a shell on it
./down.sh lesson-03-container-gvisor    # destroy it
./down.sh --all                         # destroy everything, then sweep for orphans
```

**Those scripts are the interface and stay independently runnable.** Everything below is a client of
them, never a replacement — a reader who types `./up.sh lesson-03-container-gvisor` gets exactly what
they always got, with or without any of it installed.

## Watching, from a prompt or from a panel

An `up` on the chapter-4 cluster takes about two hours and the box has no console. Two things follow:
a run has to outlive the terminal that started it, and it has to leave a post-mortem behind. Both
live in [`ctl.py`](ctl.py), which runs every operation **detached** and writes two files per run —
`.state/<target>/run-*.log` (every byte the driver printed) and `run-*.ndjson` (the structured event
stream). Watching is re-reading those files, so closing a watcher never kills the work and two
watchers cost nothing.

**A run started by hand writes the same two files** — `lib.sh`'s `run_track` opens them whenever no
supervisor has, so `./up.sh …` and `./openshift-sno/install.sh` are watchable stage by stage from any
other terminal. Before that, visibility was a property of *how* a script was started rather than of
the script, which left the one run long enough to need it — the cluster install the runbook tells you
to type — reporting nothing at all.

```bash
python3 ctl.py status                   # what exists, what is running, what it costs
python3 ctl.py status openshift-sno     # its stage table: done, running (with its own clock), ahead
python3 ctl.py stages openshift-sno     # every stage id and its shipped duration
python3 ctl.py timings lesson-02-container     # n, avg, min, max, last per stage, from past runs
python3 ctl.py up openshift-sno --from kata    # resume at a stage; status names which one
python3 ctl.py logs openshift-sno -f    # follow a run someone else started
python3 ctl.py stop openshift-sno       # SIGTERM the whole process group
python3 ctl.py audit                    # ask the ACCOUNT what is still billable
python3 ctl.py reconcile --prune        # drop state naming boxes the account no longer has
```

`ctl.py` never prompts (`down` takes `--yes`), emits escape sequences only to a real terminal, and
its exit codes discriminate: **0** fine, **1** the operation failed, **2** usage, **4** nothing to
do. `--json` on `status`, `logs`, `audit`, `stages` and `timings`.

[`tui/`](tui/README.md) is the interactive version of the same thing — select a target, watch stages
tick over, read the log, stop, destroy, with a header line that keeps asking the account what is
still billing. It is **optional**: it is the only Node in this repo and nothing else depends on it.

```bash
./tui/sbx-tui                # the panel
./tui/sbx-tui openshift-sno  # focused on the cluster
```

## What each lesson gets

Defined in [`lessons.json`](lessons.json), which is the **only** place the mapping
lives — `lib.sh` reads it with `jq` to build each `scw` create. One table, one reader:
a generated second copy is how tables drift apart, and a drifted one provisions one box
while the lesson believes it got another.

| Lesson | Box | Root vol | €/hr | Why that box |
|:--|:--|:--|--:|:--|
| 1 no-sandbox | `PLAY2-NANO` VM | 20 GB | 0.028 | the bare box *is* the lesson |
| 2 container | `PLAY2-NANO` VM | 20 GB | 0.028 | rootless podman on this VM's own kernel |
| 3 gvisor | `PLAY2-NANO` VM | 20 GB | 0.028 | `runsc` is user-space; no hardware feature needed |
| 4 kata | `PLAY2-MICRO` VM | **40 GB** | 0.055 | needs `/dev/kvm` **and** `/dev/vhost-vsock`, which this VM has |
| 5 openshell | `PLAY2-MICRO` VM | 40 GB | 0.055 | OpenShell refuses a public default-route IP, so the box builds a NAT'd guest |

**VM, not bare metal — and that was measured rather than assumed.** Lessons 1–3 used
to take Elastic Metal on the argument that only metal makes "a container shares
*this* kernel" literally true. Tested on 2026-08-06, lesson 1's scorecard is
row-for-row identical on a VM, gVisor still reports `4.19.0-gvisor`, and Kata still
boots guest kernel `6.18.35` because a Scaleway VM exposes `/dev/kvm` and
`/dev/vhost-vsock`. The full measurement is in `syllabus.md` § *Verified on this
hardware*.

What metal cost was never the money — it was a default `ELASTIC_METAL` quota of
**2** (four metal lessons could not be up at once), per-offer stock, and a 10–15
minute OS install per box against under a minute for a VM.

The honest price of the switch: on a VM there **is** a hypervisor underneath, so
"nothing beneath this kernel" is false. Escaping the container still gives you the
whole machine, which is the claim lessons 1–3 actually make. Chapter 4's OpenShift
box remains genuine bare metal — `"kind": "baremetal"` in `lessons.json` routes
`box_create` to `scw baremetal server create` instead.

## Prerequisites

- A **Scaleway account** with `scw init` done (project, zone, credentials). Everything
  provisions through the `scw` CLI reading `~/.config/scw/config.yaml`, so there is
  nothing else to configure and no key in this repo.
- The **`scw` CLI** and **`jq`** on `PATH`. No Terraform, no other tooling.
- An **SSH key registered as a Scaleway IAM key**. The scripts default to a
  *throwaway* keypair, deliberately — every box here runs hostile code, so the
  credential that reaches it should be disposable too:

  ```bash
  mkdir -p ~/.config/sandboxing-tutorial && chmod 700 ~/.config/sandboxing-tutorial
  ssh-keygen -t ed25519 -N '' -f ~/.config/sandboxing-tutorial/id_ed25519
  scw iam ssh-key create name=sandboxing-tutorial \
      public-key="$(cat ~/.config/sandboxing-tutorial/id_ed25519.pub)"
  ```

  Override with `SANDBOXING_TUTORIAL_SSH_KEY` / `…_SSH_KEY_NAME`. **No private key
  ever enters this repo**, and `infra/.state/` is gitignored because it names live,
  billable resources.
- `jq` and `rsync` locally.

## Cost

Roughly **€0.19/hr** with all five boxes up at once, and a lesson occupies its box
for well under an hour — so the whole chapter is well under a euro, *provided
`down.sh` runs*. `up.sh` prints the running rate, read live from the Scaleway
catalogue rather than from a hardcoded table that can quietly go stale.

**Isolation is structural.** A single `./down.sh <lesson>` terminates EXACTLY its own
box by id and never sweeps — so it cannot touch another lesson's box, tracked or not.
Independent boxes mean there is no whole-set apply to race and no keep-list to get
wrong. On 2026-08-10 a single `down` destroyed lesson 2's live box because the old
Terraform-era sweep terminated every `sbx-*` it saw; that class of bug simply cannot
happen when a single down never sweeps.

Only `./down.sh --all` sweeps the prefix, to catch anything untracked, and then checks
the leftovers a `terminate` should have taken with it: **detached volumes** and
**unattached IPs** each keep billing on their own while the server list reads empty.
`terminate with-ip with-block` removes both, so the sweep only *warns* — it never
deletes a volume, which could belong to work outside this repo.

That check asks **two** volume APIs, and asking one is a false all-clear. Every lesson's
root volume is `sbs`, which lives in the Block API; `scw instance volume list` returns
`l_ssd`/`b_ssd` only and reports `0` for an sbs orphan. A 20 GB volume detached on
2026-08-08 billed unnoticed until `scw block volume list` was run on 2026-08-13. Since a
block volume is named after its image rather than carrying the `sbx-` prefix, there is no
safe way to attribute it automatically — `down.sh` prints each id with the exact
`scw block volume delete` line and lets a human decide.

## When state and the account disagree

A `.state/*.env` file is a cache, not a fact, and the gap between them is where money
hides. `up.sh` guards on the state file's existence, so a stale one — naming a box the
account no longer has — makes `./up.sh` report "already has a box" and **refuse to
rebuild** the lesson until it is cleared.

```bash
python3 ctl.py reconcile              # which state files name a box the account lacks
python3 ctl.py reconcile --prune      # clear them via down.sh (also terminates any lingering box)
```

`status` reconciles on every call, for free: whoever last asked the account a real
question (`audit`, `status --account`, `reconcile`) leaves the answer in
`.state/.account.json`, and `status` reads it. Three states, kept deliberately
distinct — `up` confirmed against the account, `up?` nobody has asked recently, and
`GONE` the account does not have it. Treating "unverified" as "up" is the original
bug; treating it as "gone" would cry wolf on every fresh provision, since a reading
taken before a box existed knows nothing about it.

## Traps that cost time once

| Trap | Symptom | Fix |
|:--|:--|:--|
| **Default root volume is 8 GB** | `tar: ... No space left on device` unpacking `kata-static` | size it per lesson in `lessons.json`; Kata needs 40 GB. Metal's big local SSD is why this never showed up before |
| **A VM logs in as `root`** | lesson 2 claims "rootless" while running as root | cloud-init (rendered by `lib.sh`, passed to `scw create`) makes the unprivileged `agent` user. Elastic Metal logs in as `ubuntu` |
| **cloud-init is not done when sshd answers** | the `agent` user does not exist yet; `Permission denied (publickey)` | `up.sh` waits on `cloud-init status --wait` before touching the box |
| **`root-volume=local:` on PLAY2** | `couldn't find a local image for this commercial type` | PLAY2 has no local storage — its root volume is Block SSD. `box_create` uses `sbs:`; override with `root_volume_type` in `lessons.json` |
| **Client MTU blackhole** | ssh hangs at "banner exchange" while `ping` is perfect | `sudo ifconfig <default-if> mtu 1400` on your workstation (revert with `1500`) |
| **Host key churn** | MITM warnings after a rebuild | expected — we cause every rebuild, so the scripts use `StrictHostKeyChecking=no` with `UserKnownHostsFile=/dev/null` |
| **A run asked for mid-provision** | the `up` dies in its `sync` stage with rsync rc 23 — the run's mirror and the provision's mirror `--delete` each other's temp files | `up.sh` appends `BOX_READY=1` to `.state/<lesson>.env` only after every stage passed, and `run.sh`'s first stage (`wait-box`) polls it every second, printing `box is being provisioned ... (Ns)` until the box is ready — so `r` seconds after `u` queues instead of racing |

## `check.sh` asserts from the inside

`up.sh` finishes by running [`check.sh`](check.sh), which asks each sandbox **whose
kernel answered** rather than trusting the flag that was passed. This repo's
characteristic failure is a lesson that intends to run under gVisor, silently falls
back to `runc`, exits 0, and prints everything the lesson expects. Setup time is
the only place that failure is cheap to catch.

The checker has to survive that standard itself. Two bugs found in it on 2026-08-06
are worth knowing about, because both are easy to reintroduce:

- `$(… | grep -c Connected || echo 0)` reports the OpenShell gateway **healthy when
  it is down** — `grep -c` prints `0` *and* exits 1, so the capture is `"0\n0"`,
  which is not equal to `"0"`. Match on the pipeline with `grep -q` instead.
- lesson 5's NAT-guest assertion must be asked of the **host**, via `box_ssh_host`.
  By the time it runs, `up.sh` has re-pointed the lesson at the guest, and the guest
  has no libvirt — so the obvious `box_ssh` can never pass.

## Layout

```text
infra/
├── lessons.json             the per-lesson box definitions — the only hardware mapping
├── cloud-init.yaml.tmpl     the unprivileged `agent` user, rendered per box and passed to scw
├── lib.sh                   shared helpers (sourced, never executed): scw provisioning + events
├── up.sh · run.sh · ssh.sh · down.sh · check.sh
├── stages.json              what steps each operation has, and how long each MEASURED
├── timings.db               COMMITTED sqlite: every stage duration ever recorded, for the averages
├── ctl.py                   the headless core: detached runs, one JSON answer, per-run logs
├── tui/                     the optional Ink panel — a client of ctl.py, the only Node here
├── openshift-sno/           the chapter-4 cluster: install.sh + its runbook and traps
├── substrates/              one script per boundary, run ON the box, grouped by chapter
│   ├── chapter-2/           10..50 — one box per lesson
│   └── chapter-3/           60..90 — ALL FOUR onto the one cluster lessons 6-9 share
├── report/                  scorecard -> report.html (stdlib only, no deps)
└── images/agent/            the one image every lesson runs
```

`stages.json` is to operations what `lessons.json` is to hardware: **one file, read by
both** `jq` in the shell and `json` in Python. Its `expect_s` values are measurements, not
estimates — `ctl.py` overrides them from the last successful run, so they self-calibrate when the
hardware moves. A generated second copy is how the two readers come to disagree, which is the same
argument `lessons.json` makes in its own header. `install.sh` reads its own stage ids from there
too, which is not decoration: it kept a second copy once, the two drifted by one stage, and
`--from preflight` then ran nothing and reported success.

### Every duration says where it came from

`~16m00s expected` is stages.json's shipped figure — one box, one day, someone else's timezone.
`~9s avg of 10 runs` is an average over **this** machine's own history. They are not the same claim,
so the panel never prints one as if it were the other; the number that gets over-trusted is always
the one nobody has re-measured.

The averages live in [`timings.db`](timings.db), a SQLite file that **is committed**, and it is the
one thing this tool writes that is. `.state/` is gitignored because it names live, billable
machines; durations name nothing, they are the only part of a run worth keeping, and a fresh clone
that inherits them starts out knowing what a `kata` substrate install really costs on this hardware
instead of quoting one measurement from one box on one day.

The trade, because a binary in git has one: **it cannot be diffed or merged.** Two clones that both
run lessons will conflict on it, and the only resolution is to pick a side — or delete it, since
nothing in it is unrecoverable while the run files exist.

Which is the second rule: **derived, never authoritative.** Every row is rebuilt from
`.state/<target>/run-*.ndjson`, and any read ingests runs it has not seen yet — so a hand-started
`./up.sh`, which has no supervisor to write it away, still lands in the store. Deleting the file is
a complete repair. That property is the only thing stopping a store like this from becoming a second
source of truth that quietly disagrees with the runs.

```bash
python3 ctl.py timings <target> --rebuild   # after deleting a run that should not count
sqlite3 infra/timings.db 'select * from stage_stats'   # ask it anything else
```

SQLite and not DuckDB: `sqlite3` is in the Python standard library, so `infra/` still works on a
clone with nothing installed. DuckDB is a wheel to install before the tutorial's own tooling runs.

**What may be stored there**: durations, stage ids, operation names, timestamps, verdicts. Never an
IP, a server id or a hostname — the moment that file carries a fact about a live machine it stops
being safe to commit, and it is committed.

Three things bound what gets averaged, each load-bearing. The **window** (10 newest samples per
stage): a stage's duration is a property of the code as it is *now*, so an average dragging in runs
from before a script got faster keeps quoting a number nobody can reproduce. **Same operation
only**: `up` and `run` both own a `sync` that means different amounts of work. **Successful runs
only**: "took 40 minutes before something else broke" is not a duration.

```console
$ python3 ctl.py timings lesson-01-no-sandbox
lesson-01-no-sandbox  ·  up  ·  10 successful run(s) sampled (window 10)
  stage                       n      avg      min      max     last  manifest
  provision                10       9s       7s      10s       8s     1m30s
  sync                     10    1m02s      47s    1m31s      49s     1m00s
```

That `min`/`max` spread is the reason the command exists as well as the average: a stage whose two
ends are a factor of three apart is one to distrust a single number about.

A stage may declare **substages** — one level, for the few steps too long to be a single row.
`openshift-sno`'s `api` is an hour and declares three. They are emitted as ordinary stage events
with a `parent/child` id, so a reader that knows nothing about them simply skips an id it cannot
find, and `--from` still takes only the top-level names. The rule for adding one: a substage may
exist only where the driver can *observe* the boundary. `install-to-disk` and the pivot reboot are
one substage rather than two because from the workstation they are indistinguishable — the box stops
answering, and later a node appears.
