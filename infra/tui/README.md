# `sbx-tui` — the interactive control panel

```bash
./sbx-tui                  # the panel
./sbx-tui openshift-sno    # opens focused on that target
./sbx-tui --once           # one frame, then exit — works in a pipe
```

Create a box for any lesson, watch it provision stage by stage, read its log, stop it, destroy it,
and see at a glance what is done and what is ahead — with a permanent line at the top saying what
the **account** thinks is still billable.

## It is optional, and that is the point

This is the only Node in the repository. Nothing else depends on it: `../ctl.py` and every shell
script run on a fresh clone with nothing installed, which is what keeps the tutorial runnable by a
reader who only came for the lessons. If `node` is missing, `./sbx-tui` says so and points at
`python3 ../ctl.py status`, which shows the same information.

`node_modules/` is gitignored; `package-lock.json` is committed — it pins what a
reader's `npm install` resolves to, like any lockfile.

## It owns nothing

Every action shells out to [`../ctl.py`](../ctl.py); every reading comes from
`ctl.py status --json`; the log pane is the raw run log on disk. Kill this process mid-install and
nothing is lost — the operation is a *detached* process `ctl.py` started, so reattaching is just
reading the same files again. Two people, or a person and an agent, can watch the same run at once.

The rule that keeps it honest: **anything you can do here, you can do from `ctl.py`.** A capability
reachable only by keypress is one an agent cannot use, and the path that rots is always the one
being used at 2am on a box that bills by the hour.

The footer offers only the keys that apply to the selected target right now — `u` with no box,
`r`/`d` on an idle box, `s` while an operation is in flight (`r` also queues behind a live `up`).
A key it is not offering answers with the reason instead of acting; ctl.py enforces the same rules
either way.

| Key | Does | Equivalent |
|:--|:--|:--|
| `↑` `↓` / `k` `j` | select a target | — |
| `u` | create the box / build the cluster — or, on a cluster whose install stopped part-way, finish it (asks `y` first) | `ctl.py up <t> [--from <stage>] --detach` |
| `f` | choose which stage to restart the cluster install at (asks `y` first) | `ctl.py up openshift-sno --from <stage> --detach` |
| `r` | run the lesson | `ctl.py run <t> --detach` |
| `s` | stop the running operation | `ctl.py stop <t>` |
| `d` | destroy the box (asks `y` first) | `ctl.py down <t> --yes` |
| `c` | clear state for boxes the account no longer has (asks `y` first) | `ctl.py reconcile --prune` |
| `a` | refresh now | — |
| `q` | quit — **does not stop anything** | — |

## Two things about the display that are deliberate

**The `STATE` column has three truths, not two.** `up` means the account confirms the box exists,
`up?` (yellow) means nobody has asked it recently, and `GONE` (red) means the account does not have
the box this target's state file names — which is not cosmetic, because `lib.sh` would re-create it
on the next `up`. A `GONE` box is also excluded from the burn total: it is not billing, whatever the
state file claims. The reconciliation costs nothing per tick — the account poll that already runs
every 30 s leaves its answer in `.state/.account.json`, and `ctl.py status` reads that.

**Log lines go through Ink's `<Static>`**, which prints permanently above the live region and is
never repainted. Only the small status block redraws. This repo's characteristic failure is a
machine with no console that goes dark, and the post-mortem is whatever the terminal still holds —
a full-screen repaint would throw exactly that away. The same lines are also on disk in
`.state/<target>/run-*.log` regardless.

**The detail panel looks forward when idle.** An operation in flight renders its live progress —
done stages, the running one, the ETA. An idle target renders the *plan*: the stages the next
operation would run (`up` without a box, `run` with one, `down` for the cluster) and what each
should take. History depends on whether a box exists: on a live box the last operation's finished
stages render in full above the plan (they are what the box holds — hiding them made a provisioned
machine read as an empty one), while with no box the last verdict is a single dim line (a finished
run's whole stage table in that slot made ten-hour-old history read as "what happens next").

**One stage list at a time**, which is the rule those two tenses have to obey to stay legible. A
finished run's `✔` rows stacked above a plan's `○` rows read as a single checklist that stopped
part-way — `8/8 done` with four unfinished steps beneath it — and a separator does not fix that,
because both lists look like the same kind of thing. So when history is on screen the plan collapses
to its names on one line:

```text
lesson-05-container-openshell · up · succeeded · ended 33m ago
 ✔ provision                     8s
 …
  8/8 done

next: run · ~11m00s expected
  wait-box → sync → lesson → fetch
```

It expands in the two cases where the plan *is* what you are reading: no history at all (the cluster
before its first build, where the shape of the next two hours is the whole question), and a resume,
where the list is the answer — exactly which stages this box has left to do.

**Every duration says where it came from.** `~16m00s expected` is `../stages.json`'s shipped figure,
measured on one box on one day; `~9s avg of 10 runs` is an average over this machine's own history
of that stage. A confident "~1h12m remaining" that is wrong is worse than no estimate, so the
numbers self-calibrate — from the last ten *successful* runs of the same operation, averaged rather
than "whatever the last run did", which let one stalled rollout become the expectation for every run
after it. They come out of `../timings.db`, a committed SQLite file, so a fresh clone inherits every
timing this repo has recorded. `../ctl.py timings <target>` prints the evidence: n, avg, min, max,
last, and the shipped figure beside them.

**The stage in flight carries its own clock** — `▶ api  41m18s  of ~1h02m`. Elapsed on its own is
not progress: the whole reason a stage table is worth having is that it separates a slow step from a
hung one, and this repo has already lost 37 minutes to reading one as the other.

**A long stage nests one level.** `api` is an hour, so naming it is not an answer; it reports the
three phases it can observe, each with its own clock:

```text
  ▶ api                        41m18s  of ~1h02m
    └ ✔ bootkube                 7m02s
    └ ▶ install-to-disk         34m16s  of ~37m00s
    └ ○ operators                        ~18m00s
```

They show in every tense — in the plan before you start, live while it runs, and in history
afterwards — because the shape of an hour is most worth seeing *before* you commit to it. Declared
in `../stages.json` beside their parent and emitted as ordinary stage events with a `parent/child`
id, which is what lets a **cancel point at `api/install-to-disk`** rather than at an hour-wide
stage. Only top-level ids are resume points: `--from` takes `api`, never `api/operators`.

**A run started by hand appears here too**, marked `started by hand`. `./up.sh`, `./down.sh` and
`openshift-sno/install.sh` open their own event stream (`lib.sh`'s `run_track`) when no supervisor
has given them one, so the two-hour cluster install is watchable stage by stage whether it was
launched from this panel or typed at a prompt — it used to be invisible unless it came through
`ctl.py`, which is precisely backwards, since the runbook tells you to type it. The one thing that
differs: `s` on such a run ends the script and nothing tears down a box it had already created, so
the footer says so rather than implying a cleanup that cannot happen.

**A cluster whose install stopped part-way** gets a third kind of plan — neither `run` nor `down`
but the rest of the same `up`, trimmed to the stages this box has not done and labelled with the
`--from` that starts there. `u` takes it; `f` picks a different one, because a stage can succeed and
still leave what it built broken. Both confirm first, and the confirmation is not always the same
question: a resume that would pass through the stage which re-images the box says so, since that
destroys the cluster currently on it.

## Developing

```bash
npm install       # once
npm run typecheck # tsc --noEmit
npm start         # same as ./sbx-tui
```

`src/app.tsx` is the whole application. There is no build artifact: `tsx` transpiles on the fly, so
there is nothing to rebuild and nothing to keep in sync.
