#!/usr/bin/env python3
"""The headless core: one place that knows how to create, watch, stop and destroy this repo's boxes.

    ./ctl.py status                     what exists, what is running, what it costs
    ./ctl.py up lesson-04-container-kata
    ./ctl.py up openshift-sno --from kata
    ./ctl.py run lesson-04-container-kata
    ./ctl.py logs openshift-sno -f
    ./ctl.py stop openshift-sno
    ./ctl.py timings lesson-04-container-kata   what past runs say each stage costs
    ./ctl.py down lesson-04-container-kata --yes
    ./ctl.py audit                      ask the ACCOUNT what is still billable
    ./ctl.py reconcile --prune          drop state files naming boxes the account no longer has

It **drives the shell scripts, it does not replace them.** `up.sh`, `run.sh`, `down.sh` and
`openshift-sno/install.sh` stay independently runnable and are still the tutorial's real interface —
a reader who types `./up.sh lesson-03-container-gvisor` must get exactly what they always got. This
adds three things those scripts cannot give themselves: a detached run that outlives the terminal,
one machine-readable answer to "where is it", and a durable per-run log.

TWO AUDIENCES, ONE IMPLEMENTATION. The Ink TUI in ./tui is a client of this file, and so is an
agent, and so are you at a prompt. There is deliberately no capability here that only the TUI can
reach: a second code path for the pretty case is a second code path that rots, and the one that rots
is always the one being used at 2am on a box that bills by the hour.

Consequences, each of which is a rule rather than a preference:

* **Nothing here ever prompts.** `down` takes `--yes`. A core that asks a question does not degrade
  for a non-interactive caller, it hangs forever.
* **Exit codes discriminate**: 0 fine, 1 the operation failed, 2 usage, 4 there was nothing to do.
  "Failed" and "no-op" being indistinguishable is how a wrapper script decides everything is fine.
* **Escape sequences only when stdout is a terminal**, so a captured run and the log file stay
  greppable.

Standard library only, and no build step, so `infra/` still works on a fresh clone with nothing
installed — the same rule `report/render.py` states for itself. Node is needed only by ./tui, which
nothing else depends on.
"""

from __future__ import annotations

import argparse
import calendar
import json
import os
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

INFRA = Path(__file__).resolve().parent
REPO = INFRA.parent
STATE = INFRA / ".state"
STAGES_JSON = INFRA / "stages.json"
LESSONS_JSON = INFRA / "lessons.json"
#: The last real answer the ACCOUNT gave, so the 2-second poll can reconcile without paying for
#: three `scw` round trips a tick. Written by whoever asks a real question; see _cache_account.
ACCOUNT_CACHE = STATE / ".account.json"

#: The one target that is a cluster rather than a lesson box: it has its own driver, its own stage
#: list, and it is shared by lessons 10-13 rather than owned by any of them.
CLUSTER = "openshift-sno"

EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_NOOP = 0, 1, 2, 4

TTY = sys.stdout.isatty()


# --- tiny presentation helpers ------------------------------------------------
#
# Colour only for a real terminal. The log file and an agent's captured stdout must not carry escape
# sequences, or every later `grep` has to know about them.


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if TTY else text


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


def green(t: str) -> str:
    return _c("32", t)


def red(t: str) -> str:
    return _c("31", t)


def yellow(t: str) -> str:
    return _c("33", t)


_ANSI = re.compile(r"\033\[[0-9;]*m")


def pad(text: str, width: int) -> str:
    """Left-justify to a VISIBLE width.

    `f"{s:<26}"` counts the escape bytes, so a coloured cell is padded about nine characters short
    and every column to its right steps left — which only happens on a real terminal, never in the
    piped output you would check it with.
    """
    return text + " " * max(0, width - len(_ANSI.sub("", text)))


def fmt_dur(seconds: float | int | None) -> str:
    """`7m12s`. Durations here are read by someone deciding whether to keep waiting."""
    if seconds is None:
        return "-"
    s = int(seconds)
    if s >= 3600:
        return f"{s // 3600}h{(s % 3600) // 60:02d}m"
    if s >= 60:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s}s"


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        die(f"cannot read {path}: {exc}")


def die(msg: str, code: int = EXIT_USAGE) -> NoReturn:
    print(f"FATAL: {msg}", file=sys.stderr)
    raise SystemExit(code)


# --- the tables ---------------------------------------------------------------


def lessons() -> dict:
    """Every target we can provision, from the one per-lesson hardware table."""
    return {k: v for k, v in load_json(LESSONS_JSON).items() if not k.startswith("_")}


def box_of(target: str) -> str:
    """The machine a target runs on — itself, unless it names a shared one.

    Chapter 3's four lessons carry ``"box": "chapter-03-k8s"`` and share one cluster, so a lesson
    name and a box name have come apart. Everything that reaches for state, liveness, age or price
    means the BOX; everything that reaches for a directory, a report or a run history means the
    TARGET. The mirror of lib.sh's ``lesson_box``.
    """
    return lessons().get(target, {}).get("box", target)


def scrub(stage: dict) -> dict:
    """A stage without stages.json's `//`-prefixed comment keys.

    Those keys exist because JSON has no comments and the reasoning behind a stage belongs beside it.
    They are not data, though, and shipping them through `status --json` puts a paragraph of prose on
    a wire a panel reads every two seconds.
    """
    out = {k: v for k, v in stage.items() if not k.startswith("//")}
    if out.get("substages"):
        out["substages"] = [scrub(s) for s in out["substages"]]
    return out


def stage_table(target: str, op: str = "up") -> list[dict]:
    """The stages this target's driver will run for this operation, in order.

    Keyed on the OPERATION as well as the target: `down` and `run` have their own short pipelines,
    and rendering a teardown against the `up` table reports "2/6 done" on a teardown that fully
    succeeded — which reads as a half-finished destroy, the single most alarming thing this tool
    could get wrong.

    A lesson's substrate stages are expanded from lessons.json rather than listed in stages.json,
    because that file is the only per-lesson table and duplicating the substrate list into a second
    one is precisely the drift its own header warns about.
    """
    manifest = load_json(STAGES_JSON)
    if op in ("down", "run"):
        return [scrub(st) for st in manifest[op]["stages"]]
    if target == CLUSTER:
        return [scrub(st) for st in manifest[CLUSTER]["stages"]]
    subs = lessons().get(box_of(target), {}).get("substrates", [])
    hints = manifest.get("substrate_expect_s", {})
    out: list[dict] = []
    for st in manifest["lesson"]["stages"]:
        if st["id"] != "substrates":
            out.append(dict(st))
            continue
        for sub in subs:
            out.append(
                {
                    "id": f"substrate:{sub}",
                    "title": f"substrate {sub}",
                    "detail": manifest["lesson"]["stages"][0].get("detail", ""),
                    "expect_s": hints.get(sub, 0),
                    "billable": True,
                }
            )
    return out


def run_op(events: list[dict]) -> str | None:
    """Which operation an event stream belongs to, from its own `op_start`.

    Stage ids repeat across operations — `up` and `run` both have a `sync` — and they name different
    amounts of work, so anything that reads a past run has to know which one it is reading.
    """
    for e in events:
        if e.get("event") == "op_start":
            return (e.get("msg") or "").split(" ")[0] or None
    return None


# --- the timing store ---------------------------------------------------------
#
# `infra/timings.db` — every stage duration this repo has recorded, in one SQLite file, and unlike
# everything else this tool writes, it is COMMITTED.
#
#     ./ctl.py timings lesson-02-container
#     sqlite3 infra/timings.db 'select * from stage_stats'
#
# `.state/` is gitignored: it names live, billable machines, and a stale copy in someone else's
# clone is how the wrong box gets destroyed. Durations carry none of that, they are the only part of
# a run worth keeping, and a fresh clone that inherits them starts out knowing what a `kata`
# substrate install really costs on this hardware instead of quoting one measurement from one box on
# one day.
#
# The trade, stated because a binary in git has one: this file cannot be diffed or merged. Two
# clones that both run lessons will conflict on it and the only resolution is to pick a side — or
# delete it, since nothing here is unrecoverable while the run files exist.
#
# WHAT MAY BE STORED HERE. Durations, stage ids, operation names, timestamps, verdicts. Never an IP,
# a server id, a hostname, or anything else out of `.state` — the moment this file carries a fact
# about a live machine it stops being safe to commit, and it is committed. db_ingest() reads only
# the event stream's stage and elapsed fields for exactly that reason.
#
# SQLite and not DuckDB: `sqlite3` is in the standard library, so `infra/` still works on a clone
# with nothing installed — the rule this file's header states. DuckDB would be a wheel to install
# before the tutorial's own tooling runs.
#
# DERIVED, NEVER AUTHORITATIVE. Every row can be rebuilt from `.state/<target>/run-*.ndjson`, which
# the drivers write and which remain the record. If this file is ever wrong, deleting it and letting
# the next read re-ingest is a complete repair — and that property is the only thing keeping a store
# like this from becoming a second source of truth that quietly disagrees with the runs.
DB_PATH = INFRA / "timings.db"

#: Bump when the schema below changes, and add the migration. Read from SQLite's own `user_version`,
#: so a clone with an older file is detectable rather than mysteriously empty.
SCHEMA_VERSION = 1

#: How many samples per stage an average is taken over, newest first. A window and not "everything"
#: because a stage's duration is a property of the code as it is NOW: a substrate script that stops
#: building from source gets faster, and an average dragging in runs from before that keeps quoting
#: a number nobody can reproduce.
SAMPLE_WINDOW = 10

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id   TEXT PRIMARY KEY,   -- '<target>/run-<utc stamp>', the run file it came from
    target   TEXT NOT NULL,
    op       TEXT NOT NULL,      -- up | run | down
    started  TEXT NOT NULL,      -- UTC, from the run's own first event
    ended    TEXT,
    status   TEXT                -- ok | fail | cancelled
);
CREATE TABLE IF NOT EXISTS stage_timings (
    run_id     TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
    stage      TEXT NOT NULL,    -- 'api', or 'api/bootkube' for a substage
    parent     TEXT,             -- NULL at the top level; the composed id split for querying
    status     TEXT NOT NULL,    -- ok | fail
    elapsed_s  INTEGER NOT NULL,
    PRIMARY KEY (run_id, stage)
);
CREATE INDEX IF NOT EXISTS stage_lookup ON stage_timings (stage, status);

-- Everything the panel asks, as one queryable thing, so `sqlite3 timings.db` answers the same
-- questions ctl.py does. Unwindowed on purpose: this is the whole history, and the window belongs
-- to the estimate rather than to the record.
CREATE VIEW IF NOT EXISTS stage_stats AS
    SELECT r.target,
           r.op,
           t.stage,
           COUNT(*)                  AS n,
           CAST(ROUND(AVG(t.elapsed_s)) AS INTEGER) AS avg_s,
           MIN(t.elapsed_s)          AS min_s,
           MAX(t.elapsed_s)          AS max_s,
           MAX(r.started)            AS last_run
      FROM stage_timings t
      JOIN runs r ON r.run_id = t.run_id
     WHERE r.status = 'ok' AND t.status = 'ok' AND t.elapsed_s > 0
     GROUP BY r.target, r.op, t.stage;
"""


def db_connect() -> sqlite3.Connection:
    """Open the store, creating it if this is a clone that has never had one.

    The default rollback journal, NOT WAL: WAL leaves `-wal` and `-shm` files beside the database,
    and a committed database whose sidecars must be gitignored is a trap for whoever adds the next
    ignore rule. The timeout covers the only contention that exists here — two runs finishing at
    the same moment, each ingesting itself.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.executescript(DB_SCHEMA)
    if conn.execute("PRAGMA user_version").fetchone()[0] < SCHEMA_VERSION:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()
    return conn


def _run_id(target: str, path: Path) -> str:
    return f"{target}/{path.stem}"


def db_ingest(conn: sqlite3.Connection) -> int:
    """Add every FINISHED run that is not in the store yet. Returns how many were added.

    Idempotent, and cheap in the steady state: the run ids already stored are one query, the rest is
    a glob, and only files that are genuinely new are opened. That is what makes it safe to call on
    every read — a hand-started `./up.sh` has no supervisor to do the writing, so "whoever reads
    next ingests" is the only rule that catches every run without a daemon.

    Unfinished runs are skipped, not partially stored. A run with no `op_end` may still be writing,
    and a row saying `status=NULL, elapsed=…` for a stage that is currently executing is a
    measurement of nothing.
    """
    known = {row[0] for row in conn.execute("SELECT run_id FROM runs")}
    added = 0
    for run_file in sorted(STATE.glob("*/run-*.ndjson")):
        target = run_file.parent.name
        rid = _run_id(target, run_file)
        if rid in known:
            continue
        events = read_events(run_file)
        if not events:
            continue
        end = next((e for e in events if e.get("event") == "op_end"), None)
        if end is None:
            continue  # still running, or died without closing — either way, not a measurement yet
        start = next((e for e in events if e.get("event") == "op_start"), None)
        op = (start or {}).get("msg", "").split(" ")[0]
        if not op:
            continue
        rows = []
        for e in events:
            stage, event = e.get("stage"), e.get("event")
            if not stage or event not in ("stage_ok", "stage_fail"):
                continue
            try:
                elapsed = int(e.get("data", {}).get("elapsed_s", -1))
            except (TypeError, ValueError):
                continue
            if elapsed < 0:
                continue  # `die` reports a failure with no duration; there is nothing to record
            parent = stage.split("/", 1)[0] if "/" in stage else None
            rows.append((rid, stage, parent, "ok" if event == "stage_ok" else "fail", elapsed))
        conn.execute(
            "INSERT OR REPLACE INTO runs (run_id, target, op, started, ended, status) VALUES (?,?,?,?,?,?)",
            (rid, target, op, events[0].get("ts", ""), end.get("ts"), end.get("data", {}).get("status")),
        )
        # REPLACE, because a stage that failed and was re-reported (die, then run_track's own close)
        # arrives twice for the same run — the later one carries the duration and should win.
        conn.executemany("INSERT OR REPLACE INTO stage_timings VALUES (?,?,?,?,?)", rows)
        added += 1
    if added:
        conn.commit()
    return added


def db_samples(conn: sqlite3.Connection, target: str, op: str, window: int = SAMPLE_WINDOW) -> dict[str, list[int]]:
    """Per stage, the most recent durations, newest first — the raw material for every estimate.

    Windowed per STAGE rather than per run: a substage added last week would otherwise be starved
    by ten older runs that never emitted it, and report "no measurement" on a stage that has now run
    five times.

    Successful runs and successful stages only. "Took 40 minutes before something else broke" is not
    a duration, and `up` and `run` both own a `sync` that means different amounts of work — which is
    why op is part of the question and not a detail.

    Zero IS a sample. `check` finishes inside the same second about half the time, and excluding
    those readings gave it five samples where every other stage had ten — which is not a smaller
    average, it is a different question being answered, and it degraded the plan's total to "averaged
    over past runs" because no single run count applied. A genuinely absent reading is already
    filtered at ingest, where the missing key becomes -1.
    """
    rows = conn.execute(
        """
        WITH ranked AS (
            SELECT t.stage AS stage,
                   t.elapsed_s AS elapsed_s,
                   ROW_NUMBER() OVER (PARTITION BY t.stage ORDER BY r.started DESC) AS rn
              FROM stage_timings t
              JOIN runs r ON r.run_id = t.run_id
             WHERE r.target = ? AND r.op = ? AND r.status = 'ok'
               AND t.status = 'ok' AND t.elapsed_s >= 0
        )
        SELECT stage, elapsed_s FROM ranked WHERE rn <= ? ORDER BY stage, rn
        """,
        (target, op, window),
    ).fetchall()
    out: dict[str, list[int]] = {}
    for row in rows:
        out.setdefault(row["stage"], []).append(int(row["elapsed_s"]))
    return out


def db_rebuild(conn: sqlite3.Connection) -> int:
    """Throw the store away and re-ingest from the run files. Returns how many runs came back.

    The repair, and the thing that keeps "derived, never authoritative" true in practice rather than
    in principle. It is needed because this file is committed and therefore permanent: a run that
    should never have been recorded — a rehearsal, a run against borrowed hardware, anything that
    would drag an average towards a number this machine cannot reproduce — outlives the deletion of
    its own run file unless something drops it.

    So the sequence is: delete the offending `.state/<target>/run-*.ndjson`, then rebuild. What
    survives is exactly what the run files still say, which is the definition this store is supposed
    to satisfy.
    """
    conn.execute("DELETE FROM stage_timings")
    conn.execute("DELETE FROM runs")
    conn.commit()
    return db_ingest(conn)


def db_run_count(conn: sqlite3.Connection, target: str, op: str) -> int:
    """Successful runs of this operation on record — the denominator behind "avg of N"."""
    return int(
        conn.execute(
            "SELECT COUNT(*) FROM runs WHERE target = ? AND op = ? AND status = 'ok'", (target, op)
        ).fetchone()[0]
    )


def stage_samples(target: str, op: str = "up") -> dict[str, list[int]]:
    """Every recorded duration per stage, newest first, from the committed timing store.

    Ingest-then-query, on every call: a run started by hand has no supervisor to write it away, so
    "whoever reads next files it" is the only rule that catches every run without a daemon. It is
    cheap — the ids already stored are one query and only genuinely new files are opened.

    A store that cannot be opened is not fatal. `timings.db` is derived from the run files and is
    rebuilt by deleting it; a read-only checkout or a corrupt file should cost the estimates, which
    are a nicety, and not `status`, which is how anyone finds out what is billing.
    """
    try:
        with db_connect() as conn:
            db_ingest(conn)
            return db_samples(conn, target, op)
    except sqlite3.Error as exc:
        print(dim(f"  (timing store unavailable: {exc})"), file=sys.stderr)
        return {}


def calibrated_stages(target: str, op: str = "up") -> list[dict]:
    """The stage table, with `expect_s` replaced by the AVERAGE of what past runs actually took.

    A confident "~1h12m remaining" that is wrong is worse than no estimate at all, and the shipped
    numbers are measurements of one particular box on one particular day. Later runs are better
    evidence about the next one, so the manifest's values are a floor to fall back on.

    Averaged rather than "whatever the last run did", which is what this used to do: a single
    unlucky run — one stalled operator rollout, one slow mirror — became the expectation for every
    run afterwards, so the estimate swung as hard as the thing it was estimating. Both the source
    and the sample count travel with the number, because "~37m" from one run and "~37m" from eight
    are not the same claim and a reader deciding whether to keep waiting is entitled to know which
    one they are looking at.
    """
    table = stage_table(target, op)
    samples = stage_samples(target, op)

    def calibrate(stage: dict, key: str) -> dict:
        # Copied, never mutated in place: stage_table hands out dicts parsed from the manifest, and
        # writing a measurement into one would leak into the next caller's "shipped default".
        out = dict(stage)
        values = samples.get(key) or []
        out["expect_source"] = "measured" if values else "manifest"
        if values:
            out["expect_s"] = mean_s(values)
            out["expect_n"] = len(values)
        return out

    calibrated = []
    for st in table:
        row = calibrate(st, st["id"])
        if st.get("substages"):
            row["substages"] = [calibrate(sub, f"{st['id']}/{sub['id']}") for sub in st["substages"]]
        calibrated.append(row)
    return calibrated


def resume_stage(target: str) -> str | None:
    """The first `up` stage the box this target currently holds has NOT completed.

    None means either no box, no recorded install, or an install that finished — in all three the
    next step is something other than resuming. This is what makes a two-hour cluster install
    interruptible in practice: `--from api` is the documented recovery move, and the question it
    always begs ("from where?") has an answer in the event stream.

    ACCUMULATED across runs, not read from the newest one. A resumed install records only the stages
    it ran, so the newest run of `--from api` alone reports the first five as unfinished on a cluster
    that is one stage from done. Bounded by the box's own creation time so a rebuilt box never
    inherits the previous machine's progress — the state file is written the moment the box has an
    id, with a minute of slack for the ordering of the two writes.
    """
    box = STATE / f"{target}.env"
    if not box.exists():
        return None
    try:
        since = box.stat().st_mtime - 60
    except OSError:
        return None
    finished: set[str] = set()
    for run in sorted(run_files(target)):
        events = read_events(run)
        if run_op(events) != "up" or not events:
            continue
        started_at = parse_ts(events[0].get("ts"))
        if started_at is not None and started_at < since:
            continue
        finished |= {e["stage"] for e in events if e.get("event") == "stage_ok" and e.get("stage")}
    if not finished:
        return None
    for st in stage_table(target, "up"):
        if st["id"] not in finished:
            return st["id"]
    return None


def plan(target: str) -> dict:
    """The NEXT operation this target is waiting for: its stages, and what each should take.

    The forward-looking complement of progress(). That one is the last run's history — history the
    moment it ends — and a panel rendering it in the "what happens next" slot answers yesterday's
    question. No box means the next step is `up`; a live box means `run` — except the cluster,
    which lessons 10-13 use in place and whose one remaining human-owned step is the teardown it
    bills EUR 0.263/hr until.

    A box with an UNFINISHED install is the third case, and it is the cluster's normal state for the
    two hours it is being built: the next step is neither `run` nor `down` but the rest of the same
    `up`, so the plan is trimmed to the stages that are actually left and carries the `--from` that
    starts there. Offering `down` to someone 80 minutes into an install is not a neutral default.
    """
    resume = resume_stage(target) if (target == CLUSTER and box_state(target)) else None
    if resume:
        op = "up"
    elif box_state(target):
        op = "down" if target == CLUSTER else "run"
    else:
        op = "up"
    table = calibrated_stages(target, op)
    if resume:
        ids = [st["id"] for st in table]
        if resume in ids:
            table = table[ids.index(resume) :]
    # The total has a provenance of its own, and it is not always the same as its parts'. It is the
    # sum of whatever each stage currently believes — averages where runs exist, the manifest where
    # they do not — so calling it "expected" while every row underneath says "avg of 3 runs" reads
    # as a number that ignored them. It never did; only the label was generic.
    counted = [st for st in table if has_estimate(st)]
    measured = [st for st in counted if st.get("expect_source") == "measured"]
    runs = {st.get("expect_n") for st in measured}
    return {
        "op": op,
        "resume_from": resume,
        "stages": table,
        "expect_total_s": sum(int(st.get("expect_s") or 0) for st in table) or None,
        "expect_total_source": ("measured" if len(measured) == len(counted) else "mixed") if measured else "manifest",
        # The run count only when every measured stage agrees on it, which is the normal case — one
        # run records every stage. A mixed set gets no single number, because there is not one.
        "expect_total_n": runs.pop() if len(runs) == 1 else None,
        "expect_measured_stages": len(measured),
        "expect_total_stages": len(counted),
    }


# --- per-target run state -----------------------------------------------------
#
# The filesystem is the IPC. No daemon, no socket, no protocol to version: an operation is a
# detached process that appends to files, and every watcher — the TUI, an agent, a second terminal —
# is a stateless reader of those files. Reattaching is just reading again, and two watchers cost
# nothing. REPRODUCE.md §3b argues for exactly this shape ("start long jobs detached, then poll").


def target_dir(target: str) -> Path:
    return STATE / target


def current_file(target: str) -> Path:
    return target_dir(target) / "current.json"


def run_files(target: str) -> list[Path]:
    return sorted(target_dir(target).glob("run-*.ndjson"))


def read_events(path: Path) -> list[dict]:
    """Parse an NDJSON run. A partial last line is normal — we may be reading it as it is written."""
    out: list[dict] = []
    try:
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except OSError:
        pass
    return out


def parse_ts(ts: str | None) -> float | None:
    """The `%Y-%m-%dT%H:%M:%SZ` that both the worker and lib.sh write, as an epoch.

    `timegm` and not `mktime`: those stamps are UTC (`date -u`, `time.gmtime`), and reading them as
    local time puts every one of them a whole timezone out — which turns "failed 2 minutes ago" into
    "failed 2 hours ago" on this machine, silently and only in summer.
    """
    if not ts:
        return None
    try:
        return calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return None


def alive(pid: int | None) -> bool:
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _ended(events: Path) -> bool:
    return events.exists() and any(e.get("event") == "op_end" for e in read_events(events))


def current_run(target: str) -> dict | None:
    """The operation in flight for this target, or None.

    `alive` is recomputed every call rather than trusted from the file, and it needs BOTH halves.
    A stale `current.json` is normally left behind by the very thing it describes — a process that
    died without cleaning up — so the pid must be checked. But the pid alone is not enough either:
    an exited child that nobody reaped is a zombie, and `os.kill(pid, 0)` says a zombie is alive.
    `op_end` in the event stream is the only unambiguous "this is over".
    """
    f = current_file(target)
    if not f.exists():
        return None
    try:
        info = json.loads(f.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    info["alive"] = alive(info.get("pid")) and not _ended(Path(info.get("events", "")))
    return info


def progress(target: str) -> dict:
    """Where this target's most recent run got to: done stages, current stage, what is ahead."""
    info = current_run(target)
    runs = run_files(target)
    table = calibrated_stages(target, (info or {}).get("op", "up"))
    events = (
        read_events(Path(info["events"]))
        if info and Path(info["events"]).exists()
        else (read_events(runs[-1]) if runs else [])
    )

    done: dict[str, int] = {}
    failed: set[str] = set()
    started: dict[str, str] = {}
    # How long each stage RAN, whether it succeeded or not. Kept apart from `done`, which decides
    # the state: a failed stage still has a duration, and on a cancel it is the interesting one —
    # "install-to-disk, 41m, then killed" is a diagnosis where a blank column is a shrug.
    took: dict[str, int] = {}
    op_status, error, ended_epoch = None, None, None
    for e in events:
        st, ev = e.get("stage"), e.get("event")
        # Op-level first, and BEFORE the `if not st` skip. A driver that dies during its own
        # argument checks fails before any stage has begun, so its stage_fail carries an empty
        # stage — and skipping those made a failed run render as one that had not started yet.
        if ev == "op_end":
            op_status = e.get("data", {}).get("status")
            ended_epoch = parse_ts(e.get("ts"))
        if ev == "stage_fail":
            error = e.get("msg") or error
        if not st:
            continue
        if ev == "stage_start":
            started[st] = e.get("ts", "")
        elif ev == "stage_ok":
            try:
                done[st] = int(e.get("data", {}).get("elapsed_s", 0))
            except (TypeError, ValueError):
                done[st] = 0
            took[st] = done[st]
        elif ev == "stage_fail":
            failed.add(st)
            # `die` reports a failure with no duration; run_track's EXIT close reports one. Whichever
            # arrives is used, and a second one simply refines the first.
            try:
                took[st] = int(e.get("data", {}).get("elapsed_s", 0))
            except (TypeError, ValueError):
                pass

    # A substage arrives as `parent/child`, so the two are told apart by the separator and nothing
    # else. Both are tracked: the top-level one answers "which stage", the nested one "where in it".
    running: str | None = None
    running_sub: str | None = None
    if info and info.get("alive"):
        for st in reversed(list(started)):
            if st in done or st in failed:
                continue
            if "/" in st:
                running_sub = running_sub or st
            else:
                running = running or st
        # A substage of a stage that is no longer running is not running either — it is one whose
        # close was lost (a kill -9 between the two events). Showing it as live would be a spinner
        # over a dead process, which is the one thing this panel must never do.
        if running_sub and running_sub.split("/", 1)[0] != running:
            running_sub = None

    def row(st: dict, key: str, live: str | None) -> dict:
        """One rendered stage, parent or child — the state machine is identical for both."""
        if key in failed:
            state = "failed"
        elif key in done:
            state = "done"
        elif key == live:
            state = "running"
        else:
            state = "pending"
        # The RUNNING stage gets a live figure, computed from its own stage_start rather than left
        # null until it ends. The stage you are waiting on is the only one whose duration you cannot
        # look up, and "api, 41m of an expected 1h02m" is the difference between a slow stage and a
        # hung one — which on this repo's most expensive box was once a 37-minute misread.
        elapsed = took.get(key)
        if state == "running":
            t0 = parse_ts(started.get(key))
            elapsed = int(time.time() - t0) if t0 else None
        return {**st, "state": state, "elapsed_s": elapsed, "started_at": started.get(key)}

    rows, ahead_s = [], 0
    for st in table:
        sid = st["id"]
        r = row(st, sid, running)
        if r["state"] == "pending":
            # Parents only. A substage's expectation is already inside its parent's, and counting
            # both would advertise an hour of work twice over.
            ahead_s += int(st.get("expect_s") or 0)
        if st.get("substages"):
            r["substages"] = [row(sub, f"{sid}/{sub['id']}", running_sub) for sub in st["substages"]]
        rows.append(r)

    elapsed_now = None
    if running and info:
        try:
            elapsed_now = int(time.time() - float(info.get("started_epoch", 0)))
        except (TypeError, ValueError):
            elapsed_now = None

    return {
        "target": target,
        "op": (info or {}).get("op", "up"),
        "stages": rows,
        # Top-level only, both of them: `done` counts the same things `total` does, or an `api` that
        # finished its three substages reports 4 of 10 stages complete on the strength of one.
        "done": len([k for k in done if "/" not in k]),
        "total": len(table),
        "running_stage": running,
        "failed_stages": sorted(failed),
        # THE distinction this whole structure hangs on, and the one it used to leave implicit:
        # everything else here describes the LAST OPERATION, which is history the moment it ends.
        # Only `running` is a fact about the target right now. `current.json` is written when an
        # operation starts and never cleared, so without this a caller reading `op_status` gets a
        # verdict from an hour ago and has no way to tell — which is how a finished run came to be
        # rendered as a target's state, in the table and in the log pane alike.
        "running": bool(info and info.get("alive")),
        "op_status": op_status if op_status else ("running" if info and info.get("alive") else None),
        "error": error,
        # Only an operation still IN FLIGHT has work ahead. Once it has ended — succeeded or failed —
        # the stages still marked pending are stages that will never run, and summing them advertises
        # "~11m of work ahead" for a plan nobody is executing. On a failed run that reads as though
        # the thing were still grinding away, which is the opposite of what happened.
        "eta_s": (ahead_s or None) if (info and info.get("alive")) else None,
        "elapsed_s": elapsed_now,
        # How long ago it ended. Without this a failure is timeless: one from twenty minutes back is
        # rendered identically to one from five seconds back, and the panel keeps reporting a stale
        # verdict as if it were news.
        "age_s": (int(time.time() - ended_epoch) if ended_epoch and not (info and info.get("alive")) else None),
        "run": info,
    }


# --- box state and money ------------------------------------------------------


def box_state(target: str) -> dict | None:
    """The `.env` lib.sh writes per BOX: the server id and IP of a live, billable machine.

    Resolved through `box_of`, so a shared lesson reports the state of the cluster it runs on rather
    than reporting no box at all. Everything downstream — liveness, age, the panel's `run` advice —
    is built on this one lookup and inherits the resolution for free.
    """
    f = STATE / f"{box_of(target)}.env"
    if not f.exists():
        return None
    out: dict[str, str] = {}
    for line in f.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"')
    return out or None


def tracked_targets() -> list[str]:
    """Every target with a `.state/*.env` — what this repo BELIEVES is up, before anyone checks."""
    return sorted(p.stem for p in STATE.glob("*.env"))


_PRICE_CACHE: dict[tuple[str, str], float | None] = {}


def hourly_price(type_: str, kind: str) -> float | None:
    """Live from the Scaleway catalogue, never a table in this repo.

    Cached per process: `status` asks for every target at once and the answer cannot move within one
    invocation. A stale hardcoded price is worse than none — lib.sh says the same and for the same
    reason, which is why this shells out to the same catalogue rather than keeping a copy.
    """
    key = (type_, kind)
    if key in _PRICE_CACHE:
        return _PRICE_CACHE[key]
    if not shutil.which("scw"):
        _PRICE_CACHE[key] = None
        return None
    if kind == "baremetal":
        cmd = ["scw", "baremetal", "offer", "list", f"zone={zone()}", "-o", "json"]
        pk, name = "price_per_hour", "name"
    else:
        cmd = ["scw", "instance", "server-type", "list", f"zone={zone()}", "-o", "json"]
        pk, name = "hourly_price", "name"
    try:
        rows = json.loads(subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True).stdout)
        for r in rows:
            if r.get(name) == type_:
                p = r.get(pk) or {}
                _PRICE_CACHE[key] = (p.get("units") or 0) + (p.get("nanos") or 0) / 1e9
                return _PRICE_CACHE[key]
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        pass
    _PRICE_CACHE[key] = None
    return None


def zone() -> str:
    return os.environ.get("SCW_DEFAULT_ZONE", "fr-par-1")


# --- account truth ------------------------------------------------------------


def account() -> dict:
    """What the ACCOUNT says is billable — not what this repo's state files believe.

    down.sh prints "destroyed, billing stopped" when the terminate call returns, which is before the
    API has finished (a server sits in `stopping` for seconds after), so that line is not proof. And
    a terminated server can leave a volume or an IP behind, each billing on its own, while the server
    list reads empty and looks like all-clear.
    down.sh's sweep already asks these questions once at teardown; the point of having it here is
    that a watcher can ask them continuously.

    Read-only. Nothing in this file deletes a cloud resource — that is down.sh's job, and it only
    ever touches the `sbx-` prefix.
    """
    if not shutil.which("scw"):
        return {"available": False}
    z = zone()

    def q(args: list[str]) -> list:
        try:
            r = subprocess.run(
                ["scw", *args, f"zone={z}", "-o", "json"], capture_output=True, text=True, timeout=45, check=True
            )
            return json.loads(r.stdout) or []
        except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
            return []

    vms = q(["instance", "server", "list"])
    metal = q(["baremetal", "server", "list"])
    vols = [v for v in q(["instance", "volume", "list"]) if not v.get("server")]
    ips = [i for i in q(["instance", "ip", "list"]) if not i.get("server")]
    ours = lambda rows: [r for r in rows if str(r.get("name", "")).startswith("sbx-")]  # noqa: E731
    acc = {
        "available": True,
        # Stamped on the in-memory dict, not just on the cache file. box_live compares this against
        # a state file's mtime, so an unstamped reading reads as epoch 0 — older than everything,
        # and therefore "unverified" forever. That made a FRESH account query less informative than
        # a cached one, which is precisely backwards.
        "read_epoch": time.time(),
        "zone": z,
        # `created` is the billing clock, and it comes from the ACCOUNT rather than from a state
        # file's mtime for the usual reason: the file is rewritten at the END of a provision (and
        # again when lesson 5 re-points at its NAT guest), so its timestamp is minutes younger than
        # the machine and gets younger still every time anything touches it.
        "vms": [
            {"name": v.get("name"), "id": v.get("id"), "state": v.get("state"), "created": v.get("creation_date")}
            for v in ours(vms)
        ],
        "baremetal": [
            {"name": v.get("name"), "id": v.get("id"), "status": v.get("status"), "created": v.get("created_at")}
            for v in ours(metal)
        ],
        "orphan_volumes": len(vols),
        "orphan_ips": len(ips),
        "foreign": [r.get("name") for r in vms + metal if not str(r.get("name", "")).startswith("sbx-")],
    }
    _cache_account(acc)
    return acc


def _cache_account(acc: dict) -> None:
    """Persist the reading, so a fast poller can reconcile without asking the API itself.

    Three `scw` round trips is far too slow for a two-second tick, and that arithmetic is the whole
    reason the panel used to trust `.state/*.env` unconditionally — the choice on the table was a
    cache or no reconciliation at all. Whoever asks the account a real question (`audit`,
    `status --account`, `reconcile`) leaves the answer here for everyone else.
    """
    try:
        STATE.mkdir(parents=True, exist_ok=True)
        ACCOUNT_CACHE.write_text(json.dumps(acc, indent=2), encoding="utf-8")
    except OSError:
        pass  # A cache that cannot be written costs an "unverified", never a wrong answer.


def cached_account() -> dict | None:
    try:
        acc = json.loads(ACCOUNT_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return acc if acc.get("available") else None


def box_age_s(target: str, acc: dict | None = None) -> int | None:
    """How long this target's box has existed, in seconds — the number that is actually billing.

    None when nobody has asked the account recently, or when the account does not have the box; a
    guess would be worse than a blank in the one column people use to decide whether to tear
    something down.

    Not the state file's mtime, which is written at the END of a provision and rewritten whenever
    anything else touches it, and not the last run's timestamps, which say nothing at all about a
    box created by hand. The account knows when it started charging.
    """
    box = box_state(target)
    acc = acc if acc is not None else cached_account()
    if not box or not acc or not acc.get("available"):
        return None
    wanted = str(box.get("BOX_ID", "")).rsplit("/", 1)[-1]
    created = next(
        (r.get("created") for r in [*acc.get("vms", []), *acc.get("baremetal", [])] if r.get("id") == wanted), None
    )
    if not created:
        return None
    try:
        # Scaleway returns RFC 3339 with fractional seconds, sometimes `Z` rather than an offset.
        # fromisoformat handles the offset form on every Python this repo runs on; the swap covers
        # the other spelling without a second parser.
        started = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int(datetime.now(timezone.utc).timestamp() - started.timestamp()))


def box_live(target: str, acc: dict | None = None) -> bool | None:
    """Does the ACCOUNT still hold the box that `.state/<target>.env` names?

    THREE-valued, and the third value is the point. `None` means nobody has asked recently, and it
    has to render differently from `False`: on a panel "unverified" and "gone" are the same shade of
    wrong, and only one of them should send anyone to the console.

    The freshness rule is an ORDERING, not a timeout. A reading taken before the state file was
    written knows nothing about the box that file describes — so without it every fresh `up` would
    show a red `gone` until the next account poll, which is a false alarm on the one screen whose
    entire job is making real alarms believable.

    Matched on the server id, so this needs no opinion about main.tf naming lesson-02-container's
    box `sbx-02-container`. lib.sh stores the zoned id (`fr-par-1/<uuid>`), the API lists the bare
    uuid; comparing the last path segment is what makes those the same fact.
    """
    box = box_state(target)
    if not box:
        return None
    acc = acc if acc is not None else cached_account()
    if not acc or not acc.get("available"):
        return None
    try:
        if float(acc.get("read_epoch", 0)) < (STATE / f"{box_of(target)}.env").stat().st_mtime:
            return None
    except OSError:
        return None
    wanted = str(box.get("BOX_ID", "")).rsplit("/", 1)[-1]
    if not wanted:
        return None
    return any(r.get("id") == wanted for r in [*acc.get("vms", []), *acc.get("baremetal", [])])


# --- launching an operation ---------------------------------------------------


def driver_argv(op: str, target: str, extra: list[str]) -> list[str]:
    """Which script actually does the work. Every one of these is runnable by hand, unchanged."""
    if op == "up":
        if target == CLUSTER:
            return [str(INFRA / "openshift-sno" / "install.sh"), *extra]
        return [str(INFRA / "up.sh"), target, *extra]
    if op == "down":
        return [str(INFRA / "down.sh"), target, *extra]
    if op == "run":
        # Chapter 4's lessons are not in lessons.json and have no box of their own: they run on the
        # workstation against the shared cluster, so their own run.sh is the driver. Dispatching on
        # "does this lesson have a box" rather than on the lesson number keeps that true if the set
        # of box-less lessons ever changes.
        leaf = REPO / "tutorial" / target / "run.sh"
        if target not in lessons() and leaf.exists():
            return [str(leaf), *extra]
        return [str(INFRA / "run.sh"), target, *extra]
    die(f"unknown operation '{op}'")


def start(op: str, target: str, extra: list[str], detach: bool) -> int:
    """Spawn the operation detached, then either follow it or return.

    Detached ALWAYS, even when we are about to follow it. One code path means the TUI, an agent and
    a terminal all watch the same kind of thing, and closing whichever of them you started from
    never kills a two-hour install.

    `start_new_session=True` and not `setsid`: setsid(1) does not exist on macOS, which is this
    repo's development machine. Python's flag does the portable equivalent.
    """
    d = target_dir(target)
    d.mkdir(parents=True, exist_ok=True)

    running = current_run(target)
    if running and running.get("alive"):
        if op == "run" and running.get("op") == "up":
            # Deliberately NOT a refusal: run.sh's first stage (wait-box) blocks until up.sh has
            # appended BOX_READY to the state file, so a queued run can no longer rsync over the
            # provision — the race that used to kill an up with rsync rc 23. The panel follows the
            # run from here on; the up keeps writing its own log and events to completion.
            print(f"{target}: up still provisioning (pid {running['pid']}) — the run will wait for the box, then start")
        else:
            print(
                f"{target}: {running['op']} already running (pid {running['pid']}). `stop` it first, or `logs -f`.",
                file=sys.stderr,
            )
            return EXIT_NOOP

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    events = d / f"run-{stamp}.ndjson"
    log = d / f"run-{stamp}.log"
    argv = driver_argv(op, target, extra)
    if not Path(argv[0]).exists():
        die(f"no driver at {argv[0]}")

    worker = [sys.executable, str(Path(__file__).resolve()), "__worker", op, target, str(events), str(log), "--", *argv]
    proc = subprocess.Popen(
        worker,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        cwd=str(INFRA),
    )
    current_file(target).write_text(
        json.dumps(
            {
                "op": op,
                "target": target,
                "pid": proc.pid,
                "argv": argv,
                "events": str(events),
                "log": str(log),
                "started_epoch": time.time(),
                "started": stamp,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"{bold(target)}: {op} started (pid {proc.pid})")
    print(dim(f"  log    {log}"))
    print(dim(f"  events {events}"))
    if detach:
        print(dim(f"  follow with: ./ctl.py logs {target} -f"))
        return EXIT_OK
    return follow(target, from_start=True)


def worker(op: str, target: str, events: Path, log: Path, argv: list[str]) -> int:
    """Runs inside the detached session: execute the driver, capture everything, bracket it.

    Two sinks, on purpose. `log` is every byte the driver printed, which is the post-mortem when a
    console-less box goes dark and is what rules/06-testing.md asks for. `events` is the structured
    stream the driver emits through lib.sh's emit(), which is what a watcher renders. Neither is
    derived from the other; a line that fails to be structured still lands in the log.

    CANCELLING is this function's other job, and the reason it — not the shell driver — owns the
    signal. `stop` sends SIGTERM to THIS process (not the whole group), so the driver keeps running
    just long enough to be torn down deliberately. The driver runs in its OWN process group so we
    can signal the whole subtree (a shell blocked in `scw create` or a long ssh leaves that child
    orphaned if only the shell is signalled) without signalling ourselves. And for an `up`, a cancel
    then runs `down.sh` to destroy whatever box the killed provision had started — the difference
    between "cancel" and "leave a machine billing that nothing knows about".
    """
    env = {**os.environ, "SBX_EVENT_FILE": str(events), "SBX_OP": f"{op}:{target}"}
    started = time.time()
    cancelled = {"v": False}
    driver: dict[str, subprocess.Popen | None] = {"proc": None}

    def ev(event: str, msg: str, **data: object) -> None:
        with events.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "stage": "",
                        "event": event,
                        "msg": msg,
                        "data": data,
                    }
                )
                + "\n"
            )

    def on_term(_signum: int, _frame: object) -> None:
        cancelled["v"] = True
        proc = driver["proc"]
        if proc and proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except (OSError, ProcessLookupError):
                pass

    signal.signal(signal.SIGTERM, on_term)

    ev("op_start", f"{op} {target}", argv=" ".join(argv))
    rc = 1
    try:
        with log.open("a", encoding="utf-8", buffering=1) as fh:
            proc = subprocess.Popen(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                env=env,
                cwd=str(INFRA),
                # Its own process group, so on_term can kill the driver and its children (scw,
                # ssh) without killing this supervisor — which must survive to do the cleanup.
                start_new_session=True,
            )
            driver["proc"] = proc
            assert proc.stdout is not None
            for line in proc.stdout:
                fh.write(line)
            rc = proc.wait()
            if cancelled["v"] and op == "up":
                # The box may exist and may not be in any state file (killed mid-provision). down.sh
                # terminates by id from .state, or by name if there is none — so it destroys the
                # partial box either way, and touches only this lesson's box. Run it WITHOUT
                # SBX_EVENT_FILE so the teardown's stages do not merge into this up's stream; its
                # human output still lands in the log, which is where a post-mortem looks.
                fh.write("\n==> cancelled — destroying any box this provisioning had started\n")
                fh.flush()
                clean_env = {k: v for k, v in env.items() if k != "SBX_EVENT_FILE"}
                down = subprocess.run(
                    [str(INFRA / "down.sh"), target],
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                    env=clean_env,
                    cwd=str(INFRA),
                )
                if down.returncode != 0:
                    fh.write(f"!! automatic cleanup failed — run ./down.sh {target}\n")
    except OSError as exc:
        ev("op_end", f"could not run: {exc}", status="fail", rc=1)
        return 1
    status = "cancelled" if cancelled["v"] else ("ok" if rc == 0 else "fail")
    ev("op_end", f"{op} {target} finished", status=status, rc=rc, elapsed_s=int(time.time() - started))
    return 0 if status == "ok" else 1


def follow(target: str, from_start: bool = False) -> int:
    """Stream a running operation's raw log, and exit with its exit code.

    Deliberately the *raw* log rather than a re-render of the events: what the driver printed is
    what a reader following along by hand would have seen, and this must not become a second, prettier
    truth that disagrees with the file.
    """
    info = current_run(target)
    if not info:
        print(f"{target}: nothing running", file=sys.stderr)
        return EXIT_NOOP
    log = Path(info["log"])
    for _ in range(50):
        if log.exists():
            break
        time.sleep(0.1)
    pos = 0 if from_start else log.stat().st_size if log.exists() else 0
    try:
        while True:
            if log.exists():
                with log.open(encoding="utf-8", errors="replace") as fh:
                    fh.seek(pos)
                    chunk = fh.read()
                    pos = fh.tell()
                if chunk:
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
            if op_finished(target) or not alive(info.get("pid")):
                # One last read: the child can write between our final read and its exit.
                if log.exists():
                    with log.open(encoding="utf-8", errors="replace") as fh:
                        fh.seek(pos)
                        sys.stdout.write(fh.read())
                        sys.stdout.flush()
                break
            time.sleep(0.4)
    except KeyboardInterrupt:
        print(dim(f"\n[detached — {target} is still running; ./ctl.py stop {target} to end it]"))
        return EXIT_OK
    return op_result(target)


def op_finished(target: str) -> bool:
    """Has the operation actually ended? Read from its own event stream, not from the pid.

    NOT `alive(pid)`. A finished child whose parent has not reaped it is a ZOMBIE, and `os.kill(pid,
    0)` succeeds on a zombie — the pid still exists in the process table. Waiting on liveness alone
    therefore hangs forever on a run that completed in two seconds, which is exactly what it did.
    The worker writes `op_end` as its last act, so that is the signal with a real meaning.
    """
    info = current_run(target)
    path = Path(info["events"]) if info else (run_files(target)[-1] if run_files(target) else None)
    return bool(path and _ended(path))


def op_result(target: str) -> int:
    """The exit code of the last finished operation, from its own event stream."""
    info = current_run(target)
    path = Path(info["events"]) if info else (run_files(target)[-1] if run_files(target) else None)
    if not path or not path.exists():
        return EXIT_OK
    for e in reversed(read_events(path)):
        if e.get("event") == "op_end":
            return EXIT_OK if e.get("data", {}).get("status") == "ok" else EXIT_FAILED
    return EXIT_FAILED


def stop(target: str) -> int:
    """SIGTERM the SUPERVISOR, and let it tear the operation down deliberately.

    Not the process group — the supervisor (the __worker) is the thing we signal, and it decides
    what happens next: it kills the driver's own group (so a scw create still in flight goes with it,
    the thing that must never be left running unattended) and, for a cancelled `up`, destroys the
    box that provision had started. Signalling the group directly would kill the supervisor too,
    and then nothing would be left to do the cleanup — which is how a cancelled provision used to
    leave a billing machine that nothing tracked.
    """
    info = current_run(target)
    if not info or not info.get("alive"):
        print(f"{target}: nothing running", file=sys.stderr)
        return EXIT_NOOP
    pid = int(info["pid"])
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError as exc:
        die(f"could not signal {pid}: {exc}", EXIT_FAILED)
    print(f"{target}: stopping (pid {pid})")
    if info.get("external"):
        # No supervisor: the pid is the driver's own shell (lib.sh's run_track recorded it), so the
        # SIGTERM ends the script and nothing follows it. Saying "cancelled" and stopping there would
        # imply the cleanup that a ctl.py-started `up` does and this cannot.
        print(dim("  started by hand, so nothing will tear down a box it had already created"))
        print(dim(f"  check with ./ctl.py status, and ./down.sh {target} if there is one"))
    elif info.get("op") == "up":
        print(dim("  a cancelled provision destroys the box it had started — follow the log to watch"))
    return EXIT_OK


# --- rendering ----------------------------------------------------------------

GLYPH = {"done": "✔", "running": "▶", "failed": "✖", "pending": "○"}
PAINT = {"done": green, "running": yellow, "failed": red, "pending": dim}


def render_status(targets: list[str], with_account: bool) -> None:
    acc = account() if with_account else cached_account()
    print(bold(f"{'TARGET':<32}{'BOX':<22}{'STATE':<30}{'EUR/hr':>7}"))
    burn, live_boxes, gone = 0.0, 0, []
    for t in targets:
        meta = lessons().get(t, {})
        box = box_state(t)
        alive_in_account = box_live(t, acc)
        # Price belongs to the MACHINE, never to a lesson that merely runs on one. Chapter 3's four
        # lessons all resolve to the same cluster, and that cluster has its own row in this table —
        # so pricing them here would charge for one box four times in the single number people act
        # on. Keyed on `box` being present rather than on type/kind being absent: the latter works
        # today only because hourly_price("", "") happens to return None, which is an accident to
        # depend on rather than a rule.
        pr = None if "box" in meta else (hourly_price(meta.get("type", ""), meta.get("kind", "")) if box else None)
        # A box the account does not have is not costing anything, whatever the state file says.
        # Adding its price back would make the one number people act on the wrong number.
        if pr and alive_in_account is not False:
            burn += pr
            live_boxes += 1
        info = current_run(t)
        p = progress(t)
        # STATE is the PRESENT TENSE, and nothing else: is an operation in flight, is there a box,
        # does the account agree it exists. A finished run's verdict is not a state — a `run` that
        # failed twenty minutes ago says nothing about what is true now, and while it occupied this
        # column it hid the answer that was actually needed ("there is no box"). That verdict lives
        # in the detail panel, which is where a past event belongs and where it carries its age.
        if info and p["running"]:  # `running` implies `info`; naming both is what narrows the type
            cur = p["running_stage"] or info["op"]
            state = yellow(f"{info['op']}: {cur} ({p['done']}/{p['total']})")
        elif box and alive_in_account is False:
            gone.append(t)
            state = red("GONE (not in account)")
        elif box:
            state = green("up") if alive_in_account else yellow("up?")
        else:
            state = dim("-")
        # One dim annotation, subordinate to the state rather than replacing it. Without it a failed
        # or cancelled `up` that never got as far as creating a box leaves an entirely blank row, and
        # that is the case where knowing your last attempt failed matters most.
        if not p["running"] and p["op_status"] in ("fail", "cancelled"):
            verb = "cancelled" if p["op_status"] == "cancelled" else "failed"
            state += dim(f"  (last {p['op']} {verb})")
        print(f"{t:<32}{(box or {}).get('BOX_IP', '-'):<22}{pad(state, 30)}{(f'{pr:.4f}' if pr else '-'):>7}")
    print()
    if burn:
        print(f"  burn: {bold(f'EUR {burn:.4f}/hr')} across {live_boxes} live box(es)")
    if gone:
        print(red(f"  {len(gone)} target(s) name a box the account does not have: {', '.join(gone)}"))
        print(dim("  ./up.sh sees the state file and refuses to rebuild — clear it: ./ctl.py reconcile --prune"))
    elif acc is None:
        print(dim("  box state is unverified — `./ctl.py status --account` asks Scaleway"))
    if with_account and acc and acc.get("available"):
        print(
            f"  account: {len(acc['vms'])} vm · {len(acc['baremetal'])} baremetal · {acc['orphan_volumes']} orphan volume(s) · {acc['orphan_ips']} orphan IP(s)"
        )
        if acc["orphan_volumes"] or acc["orphan_ips"]:
            print(red("  a detached volume and an unattached IP each keep billing on their own — ./down.sh --all"))
        for name in acc["foreign"]:
            print(dim(f"  (not ours, left alone) {name}"))


def mean_s(values: list[int]) -> int:
    """The average duration, rounded half UP.

    One function because two roundings of the same samples is a bug that looks like a data problem:
    `check` averaged 0.5s and printed as `0s` in the timings table and `~1s` in the plan. Python's
    round() is banker's — round(0.5) is 0 and round(2.5) is 2 — which for a duration reads as an
    off-by-one rather than as the convention it is. SQLite's ROUND(), which the stage_stats view
    uses, is half-away-from-zero, so this matches the view as well.
    """
    return int(sum(values) / len(values) + 0.5)


def print_timing_row(key: str, shipped: dict, indent: str, values: list[int]) -> None:
    """One stage's history. `shipped` is its manifest entry, printed last so drift is visible.

    Padding is applied BEFORE dim(), never after: the escape sequence counts towards an f-string's
    width and every column to its right steps left — and only on a real terminal, never in the
    piped output anyone would check it with. Same trap `pad()` exists for.
    """
    label = key.split("/")[-1]
    width = 30 - len(indent)
    manifest = fmt_dur(shipped.get("expect_s"))
    if not values:
        print(dim(f"{indent}{label:<{width}}{'-':>3}{'':>36}{manifest:>10}"))
        return
    avg = mean_s(values)
    print(
        f"{indent}{label:<{width}}{len(values):>3}{fmt_dur(avg):>9}{fmt_dur(min(values)):>9}"
        f"{fmt_dur(max(values)):>9}{fmt_dur(values[0]):>9}" + dim(f"{manifest:>10}")
    )


def render_timings(target: str) -> None:
    """What this target's own history says each stage costs, per operation.

    The panel shows one number per stage; this is the evidence behind it. Worth having as its own
    command for the two questions the single number cannot answer: how much a stage VARIES (a
    min/max a factor of three apart is a stage worth distrusting an average of), and how far the
    manifest's shipped figure has drifted from what this machine actually does.
    """
    found = False
    for op in ("up", "run", "down"):
        samples = stage_samples(target, op)
        if not samples:
            continue
        found = True
        runs = max(len(v) for v in samples.values())
        print(bold(f"{target}  ·  {op}  ·  {runs} successful run(s) sampled (window {SAMPLE_WINDOW})"))
        print(dim(f"  {'stage':<28}{'n':>3}{'avg':>9}{'min':>9}{'max':>9}{'last':>9}{'manifest':>10}"))
        for st in stage_table(target, op):
            rows = [(st["id"], st, "  ")]
            rows += [(f"{st['id']}/{sub['id']}", sub, "    └ ") for sub in st.get("substages", [])]
            for key, shipped, indent in rows:
                print_timing_row(key, shipped, indent, samples.get(key) or [])
        print()
    if not found:
        print(f"{target}: no successful runs recorded yet — the estimates are stages.json's own")


def reconcile(prune: bool) -> int:
    """Compare every `.state/*.env` against the ACCOUNT, and optionally clear the ones that lie.

    A state file naming a box that no longer exists is not cosmetic bookkeeping: `up.sh` guards on
    the state file's existence, so a stale one makes it report "already has a box" and refuse to
    rebuild — the lesson is stuck until the file is cleared. `--prune` goes through down.sh, which
    removes the state file and also terminates any box still lingering under that name.
    """
    acc = account()  # Always a fresh read. Nothing is ever pruned on the strength of a cache.
    if not acc.get("available"):
        die("scw is not installed — cannot ask the account", EXIT_FAILED)
    tracked = tracked_targets()
    if not tracked:
        print("no .state/*.env files — nothing here claims to be up")
        return EXIT_OK

    stale = []
    for t in tracked:
        live = box_live(t, acc)
        if live is False:
            stale.append(t)
        mark = green("live") if live else (red("GONE") if live is False else dim("unverified"))
        print(f"  {t:<32}{(box_state(t) or {}).get('BOX_IP', '-'):<18}{mark}")

    if not stale:
        print(f"\nstate matches the account ({len(tracked)} tracked)")
        return EXIT_OK
    print(f"\n{len(stale)} target(s) name a box the account does not have.")
    if not prune:
        print(dim("  Left alone, ./up.sh sees the state file and refuses to rebuild the box."))
        print(dim("  Clear it with:  ./ctl.py reconcile --prune"))
        return EXIT_FAILED
    rc = EXIT_OK
    for t in stale:
        print(f"\n{bold(t)}: pruning via down.sh (clears .state, terminates any box still under that name)")
        if start("down", t, [], detach=False) != EXIT_OK:
            rc = EXIT_FAILED
    return rc


def total_source(plan_: dict) -> str:
    """Where a PLAN's total came from, in the same voice its rows use.

    Three cases, because a total is only as good as its weakest stage: every stage measured, some
    of them, or none. The mixed one is the one worth spelling out — "~1h12m" over a plan where two
    stages out of ten have ever run is a different promise from the same figure over ten.
    """
    if plan_.get("expect_total_source") == "measured":
        n = plan_.get("expect_total_n")
        return f"avg of {n} run{'' if n == 1 else 's'}" if n else "averaged over past runs"
    if plan_.get("expect_total_source") == "mixed":
        return f"{plan_.get('expect_measured_stages')} of {plan_.get('expect_total_stages')} stages averaged"
    return "expected"


def has_estimate(st: dict) -> bool:
    """Is there a figure worth printing for this stage?

    `expect_s == 0` is overloaded and the two meanings are opposite: from the manifest it means
    nobody knows (`wait-box` is "instant on a ready box, otherwise polls until the box is ready"),
    while from a measurement it means the stage really does finish inside a second. Truthiness
    cannot tell those apart; the source can.
    """
    return st.get("expect_source") == "measured" or int(st.get("expect_s") or 0) > 0


def expect_source(st: dict) -> str:
    """Where a stage's estimate came from, in three words.

    Always shown, never inferred by the reader. `~37m00s` off the manifest is a measurement of one
    box on one day in someone else's timezone; `~37m00s` averaged over eight runs of THIS box is a
    forecast. Printing both as a bare `~37m00s` invites the second reading of the first, and the
    number that gets over-trusted is the one nobody has re-measured since.
    """
    if st.get("expect_source") != "measured":
        return " expected"
    n = st.get("expect_n") or 0
    return f" avg of {n} run{'' if n == 1 else 's'}"


def print_stage(st: dict, indent: str = "  ", width: int = 30) -> None:
    """One stage row. Parents and substages differ only by the indent they are given."""
    g, paint = GLYPH[st["state"]], PAINT[st["state"]]
    took = fmt_dur(st["elapsed_s"]) if st["elapsed_s"] is not None else ""
    # `of ~1h02m` on the running stage, `~1h02m` on one still ahead. Same number, but on the stage
    # in flight it is what turns an elapsed figure into progress.
    expect = ""
    if has_estimate(st) and st["state"] in ("pending", "running"):
        expect = ("of " if st["state"] == "running" else "") + f"~{fmt_dur(st.get('expect_s') or 0)}"
    # A stage nobody has timed, with no figure in the manifest either, would print as an empty row —
    # which reads as missing data rather than the honest "we do not know" that it is.
    elif st["state"] == "pending":
        expect = "no estimate yet"
    source = expect_source(st) if expect else ""
    print(f"{indent}{paint(g)} {st['id']:<{width}}{took:>8} {dim(expect)}{dim(source)}")
    # A parent about to list its substages has already said what it is doing, in more detail and
    # with a clock on each part. The continuation line is indented with spaces, not with a repeat of
    # the branch glyph, which would read as another child.
    if st["state"] in ("running", "failed") and not st.get("substages"):
        print(dim(f"{' ' * len(indent)}    {st.get('detail', '')}"))


def render_progress(target: str) -> None:
    p = progress(target)
    info = p["run"]
    age = box_age_s(target)
    head = f"{target}"
    if info:
        verdict = {
            "ok": green("succeeded"),
            "fail": red("FAILED"),
            "cancelled": yellow("cancelled"),
            "running": yellow("running"),
        }.get(p["op_status"] or "", "finished")
        head += f"  ·  {info['op']}  ·  {verdict}"
        if p["elapsed_s"]:
            head += f"  ·  elapsed {fmt_dur(p['elapsed_s'])}"
        # On a LIVE box, how old the machine is beats how long ago the operation ended: one is the
        # billing clock and the other is trivia about a run that is over. "ended 48m ago" on a box
        # that has been charging for an hour answers a question nobody asked.
        if age is not None:
            head += f"  ·  {green('running ' + fmt_dur(age))}"
        elif p["age_s"]:
            head += dim(f"  ·  ended {fmt_dur(p['age_s'])} ago")
        if info.get("external"):
            head += dim("  ·  started by hand")
    print(bold(head))
    if p["error"]:
        print(red(f"  {p['error']}"))
    for st in p["stages"]:
        print_stage(st)
        for sub in st.get("substages", []):
            print_stage(sub, indent="    └ ", width=26)
    tail = f"  {p['done']}/{p['total']} done"
    if p["eta_s"]:
        tail += f"  ·  ~{fmt_dur(p['eta_s'])} of work ahead"
    print(tail)
    if p["running"]:
        return
    # Idle: the section above is history, so say what the obvious next step is and what it costs
    # in time — the question someone deciding whether to press the key is actually asking.
    n = plan(target)
    head = bold(f"next: {n['op']}" + (f" --from {n['resume_from']}" if n["resume_from"] else ""))
    if n["expect_total_s"]:
        head += dim(f"  ·  ~{fmt_dur(n['expect_total_s'])} {total_source(n)}")
    print(f"\n{head}")
    if n["resume_from"]:
        print(dim("  the install stopped part-way — these are the stages this box has not done yet"))
    # The plan is the same rows in the future tense, drawn by the same function — so the columns
    # cannot drift apart, and starting the operation does not reflow the panel.
    for st in n["stages"]:
        pending = {**st, "state": "pending", "elapsed_s": None}
        print_stage(pending)
        for sub in st.get("substages", []):
            print_stage({**sub, "state": "pending", "elapsed_s": None}, indent="    └ ", width=26)


# --- CLI ----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ctl.py", description="create, watch, stop and destroy this repo's boxes")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_target(p: argparse.ArgumentParser) -> None:
        p.add_argument("target", help="a lesson name, or openshift-sno")

    p = sub.add_parser("status", help="what exists, what is running, what it costs")
    p.add_argument("target", nargs="?", help="one target, for its full stage table")
    p.add_argument("--json", action="store_true")
    p.add_argument("--account", action="store_true", help="also ask Scaleway what is billable (slow)")

    p = sub.add_parser("up", help="create the box / build the cluster")
    add_target(p)
    p.add_argument("--from", dest="from_stage", help="resume at a stage (openshift-sno)")
    p.add_argument("--detach", action="store_true", help="return immediately instead of following")

    p = sub.add_parser("run", help="run a lesson")
    add_target(p)
    p.add_argument("--detach", action="store_true")
    p.add_argument("rest", nargs=argparse.REMAINDER, help="args after -- go to the lesson")

    p = sub.add_parser("down", help="destroy the box")
    add_target(p)
    p.add_argument("--yes", action="store_true", help="required: this destroys a live machine")
    p.add_argument("--detach", action="store_true")

    p = sub.add_parser("logs", help="the raw log of the current or last run")
    add_target(p)
    p.add_argument("-f", "--follow", action="store_true")
    p.add_argument("--json", action="store_true", help="the structured event stream instead")

    p = sub.add_parser("stop", help="SIGTERM a running operation")
    add_target(p)

    p = sub.add_parser("audit", help="ask the ACCOUNT what is still billable")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("reconcile", help="compare .state against the ACCOUNT; --prune clears what vanished")
    p.add_argument("--prune", action="store_true", help="clear state for boxes the account no longer has")

    p = sub.add_parser("stages", help="the stage table for a target")
    add_target(p)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("timings", help="what past runs say each stage costs: n, avg, min, max, last")
    add_target(p)
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--rebuild",
        action="store_true",
        help="drop timings.db and re-ingest from .state — the repair after deleting a bad run",
    )

    # Internal. Not in --help because it is not an interface: it is how `start` re-enters itself
    # inside the detached session.
    p = sub.add_parser("__worker")
    p.add_argument("op")
    p.add_argument("target")
    p.add_argument("events")
    p.add_argument("log")
    p.add_argument("rest", nargs=argparse.REMAINDER)

    a = ap.parse_args(argv)
    STATE.mkdir(parents=True, exist_ok=True)

    if a.cmd == "__worker":
        return worker(a.op, a.target, Path(a.events), Path(a.log), [x for x in a.rest if x != "--"])

    known = list(lessons()) + [d.name for d in (REPO / "tutorial").glob("lesson-*") if d.is_dir()]
    if getattr(a, "target", None) and a.cmd != "status" and a.target not in known:
        die(f"unknown target '{a.target}'. Known: {', '.join(sorted(set(known)))}")

    if a.cmd == "status":
        if a.target:
            if a.json:
                print(json.dumps(progress(a.target), indent=2, default=str))
            else:
                render_progress(a.target)
            return EXIT_OK
        targets = list(lessons())
        if a.json:
            # Opt-in for the live query: `account()` is three `scw` round trips, and a watcher
            # polling every couple of seconds must not make them on every tick. The CACHE, though,
            # is free — so `box_live` is answered on every tick regardless, which is what stops a
            # panel reporting `up` for a machine that was terminated an hour ago.
            acc = account() if a.account else cached_account()
            print(
                json.dumps(
                    {
                        "account": acc if a.account else None,
                        "account_cached_epoch": (acc or {}).get("read_epoch"),
                        "targets": {
                            t: {
                                "box": box_state(t),
                                # true live / false vanished / null nobody has asked. The consumer
                                # must keep the three apart; see box_live.
                                "box_live": box_live(t, acc),
                                # Seconds since the ACCOUNT says the machine was created — the
                                # billing clock, and null when nobody has asked recently.
                                "box_age_s": box_age_s(t, acc),
                                "kind": lessons()[box_of(t)].get("kind"),
                                "type": lessons()[box_of(t)].get("type"),
                                # The machine this target runs on. Equal to the target for the usual
                                # one-box-per-lesson case; a different name means it shares, and a
                                # consumer summing prices must skip those rows or bill one cluster
                                # once per lesson on it.
                                "box_name": box_of(t),
                                # The cluster is the one target with a resumable multi-hour `up`,
                                # and a client should not have to hardcode its name to know that.
                                "cluster": t == CLUSTER,
                                # Priced only when a box exists AND this target owns it. Summing the
                                # catalogue price of every lesson would invent a bill nobody is
                                # paying; pricing a shared lesson would bill its cluster four times.
                                "hourly_price": (
                                    hourly_price(lessons()[t].get("type", ""), lessons()[t].get("kind", ""))
                                    if box_state(t) and "box" not in lessons()[t]
                                    else None
                                ),
                                "progress": progress(t),
                                "plan": plan(t),
                            }
                            for t in targets
                        },
                    },
                    indent=2,
                    default=str,
                )
            )
        else:
            render_status(targets, a.account)
        return EXIT_OK

    if a.cmd == "stages":
        table = calibrated_stages(a.target)
        if a.json:
            print(json.dumps(table, indent=2))
        else:
            for st in table:
                print(f"  {st['id']:<24} ~{fmt_dur(st.get('expect_s')):>7}  {st.get('title', '')}")
                # Unlike the progress view, the whole tree shows here whatever its state: this
                # command IS the catalogue, and `--from` takes only the top-level ids.
                for sub in st.get("substages", []):
                    print(dim(f"    └ {sub['id']:<22} ~{fmt_dur(sub.get('expect_s')):>7}  {sub.get('title', '')}"))
        return EXIT_OK

    if a.cmd == "timings":
        if a.rebuild:
            with db_connect() as conn:
                print(f"timings.db rebuilt from .state: {db_rebuild(conn)} run(s)")
        if a.json:
            # The samples themselves, not just the average — a caller doing its own statistics
            # should not have to re-derive them from the runs, and this is the whole record.
            print(
                json.dumps(
                    {
                        "target": a.target,
                        "window": SAMPLE_WINDOW,
                        "ops": {op: stage_samples(a.target, op) for op in ("up", "run", "down")},
                    },
                    indent=2,
                )
            )
        else:
            render_timings(a.target)
        return EXIT_OK

    if a.cmd == "audit":
        acc = account()
        if a.json:
            print(json.dumps(acc, indent=2))
            return EXIT_OK
        if not acc.get("available"):
            die("scw is not installed — cannot ask the account", EXIT_FAILED)
        print(
            f"zone {acc['zone']}: {len(acc['vms'])} vm, {len(acc['baremetal'])} baremetal, {acc['orphan_volumes']} orphan volume(s), {acc['orphan_ips']} orphan IP(s)"
        )
        for v in acc["vms"] + acc["baremetal"]:
            print(f"  {v['name']:<28}{v.get('state') or v.get('status')}")
        for name in acc["foreign"]:
            print(dim(f"  (not ours, left alone) {name}"))
        # Billable leftovers are a FAILURE for a caller that just tore down, not a note.
        return (
            EXIT_FAILED if (acc["vms"] or acc["baremetal"] or acc["orphan_volumes"] or acc["orphan_ips"]) else EXIT_OK
        )

    if a.cmd == "reconcile":
        return reconcile(a.prune)

    if a.cmd == "logs":
        info = current_run(a.target)
        runs = run_files(a.target)
        if not info and not runs:
            die(f"{a.target}: no runs recorded", EXIT_NOOP)
        if a.json:
            path = Path(info["events"]) if info else runs[-1]
            for e in read_events(path):
                print(json.dumps(e))
            return EXIT_OK
        if a.follow and info and info.get("alive"):
            return follow(a.target)
        path = Path(info["log"]) if info else runs[-1].with_suffix(".log")
        if path.exists():
            sys.stdout.write(path.read_text(encoding="utf-8", errors="replace"))
        return op_result(a.target)

    if a.cmd == "stop":
        return stop(a.target)

    if a.cmd == "down":
        if not a.yes:
            # Never a prompt. A core that asks a question hangs a non-interactive caller forever,
            # and this is the one command that ends a machine.
            die(f"refusing to destroy {a.target} without --yes", EXIT_USAGE)
        return start("down", a.target, [], a.detach)

    if a.cmd == "up":
        extra = ["--from", a.from_stage] if a.from_stage else []
        if a.from_stage and a.target != CLUSTER:
            die("--from only applies to openshift-sno; a lesson box is cheap enough to rebuild")
        if a.from_stage:
            # Here rather than in the driver: a bad stage name otherwise fails five lines into a
            # DETACHED log, where the caller has to go looking for a message that is a typo.
            ids = [st["id"] for st in stage_table(a.target, "up")]
            if a.from_stage not in ids:
                die(f"'{a.from_stage}' is not a stage of {a.target}. Known: {', '.join(ids)}")
        return start("up", a.target, extra, a.detach)

    if a.cmd == "run":
        # A lesson that owns a box cannot run without one. Letting the driver discover that produces
        # `FATAL: no box recorded` five lines into a DETACHED log — which reads as "this lesson is
        # broken" rather than "there is no box", especially in a panel that is still showing the
        # previous run's "up ... running now" in its scrollback. Refuse here, where the message is
        # attached to the thing the caller just asked for.
        #
        # Only targets that own a box: chapter 4's lessons run on the workstation against the shared
        # cluster and are box-less by construction, so `lessons()` membership is the right test
        # rather than a hardcoded lesson number. An `up` in flight counts as a box on the way: the
        # state file appears seconds into provisioning, and run.sh's wait-box stage covers the gap.
        if a.target == CLUSTER:
            # The cluster is not a lesson and has no `main.py`. Chapter 4's lessons run against it
            # from the workstation, so `run` belongs to them — dispatching here would hand run.sh a
            # target it can only fail on, in a detached log, five lines in.
            print(f"{CLUSTER} is a cluster, not a lesson — run lesson-10..13 against it instead", file=sys.stderr)
            return EXIT_USAGE
        cr = current_run(a.target)
        # An `up` triggered through a shared lesson is recorded against the BOX — up.sh resolves the
        # name before it calls run_track, because what is being provisioned is the cluster. So look
        # there too, or `run` issued straight after `up` reports "no box" about a machine that is
        # visibly being built.
        up_cr = cr if box_of(a.target) == a.target else (cr or current_run(box_of(a.target)))
        up_in_flight = bool(up_cr and up_cr.get("alive") and up_cr.get("op") == "up")
        if a.target in lessons() and not box_state(a.target) and not up_in_flight:
            print(f"{a.target}: no box — nothing to run on. `./ctl.py up {a.target}` first.", file=sys.stderr)
            return EXIT_NOOP
        rest = [x for x in a.rest if x != "--"]
        return start("run", a.target, (["--", *rest] if rest else []), a.detach)

    die(f"unhandled command {a.cmd}")


if __name__ == "__main__":
    sys.exit(main())
