/**
 * sbx-tui — the interactive half of infra/ctl.py.
 *
 *   ./sbx-tui            the panel
 *   ./sbx-tui --once     render one frame and exit (works without a terminal; useful in a pipe)
 *
 * THIS OWNS NO STATE AND NO LOGIC. Every action shells out to ../ctl.py, every reading comes from
 * `ctl.py status --json`, and the log pane is the raw run log on disk. If this process is killed
 * mid-install nothing is lost, because it was never the thing doing the work — the operation is a
 * detached process that ctl.py started, and reattaching is just reading the same files again.
 *
 * The one rule worth stating: **anything you can do here, you can do from ctl.py.** A capability
 * that exists only behind a keypress is one an agent cannot use and one that rots, and the path
 * that rots is always the one being used at 2am on a box that bills by the hour.
 *
 * Scrollback is a hard requirement, not a nicety. This repo's characteristic failure is a machine
 * with no console that goes dark, and the post-mortem is whatever the terminal still holds — so log
 * lines go through <Static>, which Ink prints permanently above the live region and never repaints.
 * Only the small status block below it redraws.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Box, Static, Text, render, useApp, useInput } from 'ink'
import { execFile } from 'node:child_process'
import { existsSync, statSync, createReadStream } from 'node:fs'
import { fileURLToPath } from 'node:url'
import path from 'node:path'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const CTL = path.resolve(HERE, '..', '..', 'ctl.py')
const ONCE = process.argv.includes('--once')
//: `./sbx-tui openshift-sno` opens focused on the cluster instead of the first lesson. With --once
//: it is the only way to choose, since there are no keys to press.
const WANTED = process.argv.slice(2).find((a) => !a.startsWith('-')) ?? null

const POLL_MS = 2000
//: The account query is three `scw` round trips, so it runs on its own slower clock. Stale by up to
//: half a minute is fine for "is anything still billing"; making it every tick is not.
const ACCOUNT_MS = 30000

type Stage = {
  id: string
  title?: string
  detail?: string
  expect_s?: number
  //: Where expect_s came from — stages.json's shipped figure, or an average of this target's own
  //: past runs, with expect_n saying how many. See expectLabel().
  expect_source?: 'manifest' | 'measured'
  expect_n?: number
  state: 'done' | 'running' | 'failed' | 'pending'
  elapsed_s: number | null
  //: The steps inside a stage long enough that naming it is not an answer — `api` is an hour. Same
  //: shape as the parent, one level only, and present only on the stages that declare them.
  substages?: Stage[]
}
type Progress = {
  target: string
  op: string
  stages: Stage[]
  done: number
  total: number
  running_stage: string | null
  failed_stages: string[]
  //: The ONLY present-tense fact in this object. Everything else describes the last operation,
  //: which is history the moment it ends — see ctl.py's progress().
  running: boolean
  op_status: string | null
  error: string | null
  eta_s: number | null
  elapsed_s: number | null
  //: Seconds since the operation ended, null while it is still running. A verdict with no age is a
  //: verdict that never gets old, and this panel is read by someone deciding whether to act on it.
  age_s: number | null
  run: {
    op: string
    pid: number
    alive: boolean
    log: string
    events: string
    started?: string
    //: Started by hand (`./install.sh`, `./up.sh`) rather than by ctl.py — lib.sh's run_track wrote
    //: this file itself. Same stages, same log; what differs is that there is no supervisor, so a
    //: cancel is not followed by an automatic teardown.
    external?: boolean
  } | null
}
type PlanStage = {
  id: string
  title?: string
  detail?: string
  expect_s?: number
  expect_source?: 'manifest' | 'measured'
  expect_n?: number
  //: Set on the one stage that replaces the box's operating system. Carried in stages.json so the
  //: confirmation below is computed from the manifest rather than from a stage name spelled here.
  rewrites_box?: boolean
  substages?: PlanStage[]
}
//: ctl.py's plan(): the operation this target is WAITING for and what its stages should take —
//: `up` when there is no box, `run` when there is one, `down` for the cluster. The forward-looking
//: complement of Progress, which is always the last run's history.
//: `resume_from` is the third case and the cluster's normal state while it is being built: a box
//: whose install stopped part-way, where the next step is the REST of the same `up`.
type Plan = {
  op: string
  resume_from: string | null
  stages: PlanStage[]
  expect_total_s: number | null
  //: The total's own provenance. It is the sum of whatever each stage currently believes — averages
  //: where runs exist, the manifest where they do not — so it needs its own label rather than
  //: inheriting a generic one. See totalLabel().
  expect_total_source?: 'manifest' | 'mixed' | 'measured'
  expect_total_n?: number | null
  expect_measured_stages?: number
  expect_total_stages?: number
}
type TargetInfo = {
  box: Record<string, string> | null
  //: openshift-sno: the one target with a resumable multi-hour `up`. From ctl.py, so this file
  //: never has to recognise the cluster by name.
  cluster?: boolean
  //: true live · false the account has no such box · null nobody has asked recently. Keeping the
  //: third value distinct is the whole point: rendering "unverified" as "gone" cries wolf on every
  //: fresh `up`, and rendering it as "up" is the bug this field exists to fix. ctl.py decides;
  //: this file only paints.
  box_live: boolean | null
  //: Seconds since the ACCOUNT says the machine was created — the billing clock. null when nobody
  //: has asked recently, or when the account does not have this box.
  box_age_s: number | null
  kind?: string
  type?: string
  hourly_price: number | null
  progress: Progress
  plan: Plan
}
type Status = {
  account: Account | null
  targets: Record<string, TargetInfo>
}
type Account = {
  available: boolean
  vms: { name: string }[]
  baremetal: { name: string }[]
  orphan_volumes: number
  orphan_ips: number
}

function ctl(args: string[], timeoutMs = 60000): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile('python3', [CTL, ...args], { timeout: timeoutMs, maxBuffer: 32 * 1024 * 1024 }, (err, stdout, stderr) => {
      // A non-zero exit is DATA here, not a crash: ctl.py's codes discriminate (1 failed, 4 no-op),
      // and `audit` exits non-zero precisely when it has found something billable. ctl.py's refusals
      // ("nothing running", "no box") arrive on stderr with an EMPTY stdout, so the rejection must
      // carry stderr's first line — the Node error object's own message is a stack-traced wall that
      // buries the one sentence worth showing.
      if (err && !stdout) reject(new Error(stderr.trim().split('\n')[0] || String(err)))
      else resolve(stdout)
    })
  })
}

function fmtDur(s: number | null | undefined): string {
  if (s === null || s === undefined) return '-'
  const n = Math.floor(s)
  if (n >= 3600) return `${Math.floor(n / 3600)}h${String(Math.floor((n % 3600) / 60)).padStart(2, '0')}m`
  if (n >= 60) return `${Math.floor(n / 60)}m${String(n % 60).padStart(2, '0')}s`
  return `${n}s`
}

const GLYPH = { done: '✔', running: '▶', failed: '✖', pending: '○' } as const
const COLOR = { done: 'green', running: 'yellow', failed: 'red', pending: 'gray' } as const

/**
 * Where an estimate came from, always shown beside it and never left for the reader to infer.
 *
 * `~37m00s` off stages.json is a measurement of one box on one day; `~37m00s` averaged over eight
 * runs of this box is a forecast. Rendering both as a bare `~37m00s` invites the second reading of
 * the first — and the number that then gets over-trusted is precisely the one nobody has
 * re-measured since it was written down.
 */
/**
 * The same question for a plan's TOTAL, which is only as good as its weakest stage. The mixed case
 * is the one worth spelling out: "~1h12m" over a plan where two stages of ten have ever run is a
 * different promise from the same figure over ten.
 */
function totalLabel(plan: Plan): string {
  if (plan.expect_total_source === 'measured')
    return plan.expect_total_n ? `avg of ${plan.expect_total_n} run${plan.expect_total_n === 1 ? '' : 's'}` : 'averaged over past runs'
  if (plan.expect_total_source === 'mixed')
    return `${plan.expect_measured_stages} of ${plan.expect_total_stages} stages averaged`
  return 'expected'
}

function expectLabel(s: { expect_s?: number; expect_source?: string; expect_n?: number }): string {
  // `expect_s === 0` is overloaded and the two meanings are opposite: from the manifest it means
  // nobody knows (`wait-box`), from a measurement that the stage really does finish inside a
  // second. Truthiness cannot tell those apart; the source can.
  if (s.expect_source !== 'measured' && !s.expect_s) return ''
  const src = s.expect_source === 'measured' ? ` avg of ${s.expect_n ?? 0} run${s.expect_n === 1 ? '' : 's'}` : ' expected'
  return `~${fmtDur(s.expect_s ?? 0)}${src}`
}

/**
 * Which of the four target keys apply to the selected target RIGHT NOW. The lifecycle only ever
 * offers a subset: no box → `u`; box up and idle → `r` and `d`; an operation in flight → `s`
 * (plus `r` behind a live `up`, which ctl.py queues — run.sh's wait-box stage holds it until the
 * box is ready). Showing all four regardless taught the wrong model — `d` during a provision is
 * refused by ctl.py (`stop` first, which also destroys the partial box), and a hint offering it
 * anyway makes the refusal look like a bug.
 *
 * This mirrors ctl.py's refusals, it never replaces them: the state can move between the poll and
 * the keypress, and ctl.py still has the last word either way.
 */
function available(info: TargetInfo | null) {
  const running = info?.progress.running ?? false
  const op = running ? info?.progress.run?.op : undefined
  const box = Boolean(info?.box)
  //: A box whose install never finished. ctl.py works it out from the event stream; here it is only
  //: the reason `u` stays on offer with a box present, which for the cluster is the case that
  //: matters — two hours of install is interrupted often, and finishing it is the usual next step.
  const resumable = Boolean(info?.cluster && box && info?.plan.op === 'up')
  return {
    up: Boolean(info) && !running && (!box || resumable),
    //: Choosing a different resume point than the one ctl.py suggests. Cluster only: a lesson box
    //: has no stage worth resuming from — it is minutes and a euro-cent to rebuild whole.
    from: Boolean(info?.cluster) && !running,
    //: A GONE box (state says up, account says no) gets `d` — down.sh clears the state and
    //: terminates any leftover by name — but not `r`: there is no machine to ssh into. Nor does the
    //: cluster, ever: it is not a lesson, and chapter 4's lessons run against it from here.
    run: !info?.cluster && ((!running && box && info?.box_live !== false) || op === 'up'),
    down: !running && box,
    stop: running,
  }
}

/** Poll `ctl.py status --json`. One source of truth, re-read rather than accumulated. */
function useStatus() {
  const [status, setStatus] = useState<Status | null>(null)
  const [error, setError] = useState<string | null>(null)
  const tick = useCallback(async () => {
    try {
      setStatus(JSON.parse(await ctl(['status', '--json'])))
      setError(null)
    } catch (e) {
      setError(String(e))
    }
  }, [])
  useEffect(() => {
    void tick()
    if (ONCE) return
    const t = setInterval(() => void tick(), POLL_MS)
    return () => clearInterval(t)
  }, [tick])
  return { status, error, refresh: tick }
}

function useAccount() {
  const [account, setAccount] = useState<Account | null>(null)
  const load = useCallback(async () => {
    try {
      setAccount(JSON.parse(await ctl(['audit', '--json'])))
    } catch {
      /* scw missing or offline — the account bar simply says unknown */
    }
  }, [])
  useEffect(() => {
    void load()
    if (ONCE) return
    const t = setInterval(() => void load(), ACCOUNT_MS)
    return () => clearInterval(t)
  }, [load])
  return account
}

/**
 * Tail the selected target's run log into <Static> lines.
 *
 * Incremental from a byte offset, and the offset resets when the path changes — a new run writes a
 * new file, and carrying the old offset into it would silently skip that many bytes of the thing
 * you most want to read.
 *
 * A FINISHED run is not replayed — the pane starts at end-of-file instead of byte 0.
 *
 * `current.json` names the last operation forever (it is written at start and never cleared, and
 * `up.sh`/`down.sh` run by hand never touch it at all, by design), so adopting that log at offset 0
 * dumps a completed run into the pane as though it were happening. Through <Static>, which never
 * repaints, a destroyed box's `up ... running now` then sits at the top of the panel indefinitely —
 * an invitation to press `r` on a machine that no longer exists, which is exactly how this was
 * found. This pane answers "what is happening"; a finished run is answered by the detail panel
 * below it and by `ctl.py logs <target>`, both of which say plainly that it is over.
 */
function useLogTail(logPath: string | null | undefined, live: boolean, limit = 200) {
  const [lines, setLines] = useState<{ key: string; text: string }[]>([])
  const offset = useRef(0)
  const current = useRef<string | null>(null)
  const seq = useRef(0)

  useEffect(() => {
    if (current.current !== logPath) {
      current.current = logPath ?? null
      // Live: from the top, so joining late still shows what you missed. Finished: from the end,
      // so nothing at all is replayed.
      offset.current = live && logPath && existsSync(logPath) ? 0 : logPath && existsSync(logPath) ? statSync(logPath).size : 0
      seq.current = 0
      setLines([])
    }
    if (!logPath) return
    const read = () => {
      if (!existsSync(logPath)) return
      const size = statSync(logPath).size
      if (size <= offset.current) {
        // Truncated or replaced underneath us — start over rather than read from beyond the end.
        if (size < offset.current) offset.current = 0
        else return
      }
      const stream = createReadStream(logPath, { start: offset.current, encoding: 'utf8' })
      let buf = ''
      stream.on('data', (c) => (buf += c))
      stream.on('end', () => {
        offset.current += Buffer.byteLength(buf, 'utf8')
        const fresh = buf.split('\n').filter((l) => l.length > 0)
        if (!fresh.length) return
        setLines((prev) => [...prev, ...fresh.map((text) => ({ key: `l${seq.current++}`, text }))].slice(-limit))
      })
    }
    read()
    if (ONCE) return
    const t = setInterval(read, 700)
    return () => clearInterval(t)
    // `live` is deliberately NOT a dependency: it decides only where to START reading when a path is
    // adopted. Listing it would re-seek to EOF the instant a run you are watching finishes, throwing
    // away its final lines — the ones that say how it ended.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [logPath, limit])

  return lines
}

function TargetRow({ name, info, selected }: { name: string; info: TargetInfo; selected: boolean }) {
  const p = info.progress
  // PRESENT TENSE ONLY. A finished run's verdict is not a state: `run failed` from twenty minutes
  // ago says nothing about what is true now, and while it sat here it hid the answer that was
  // actually wanted — "there is no box". The verdict belongs to the detail panel below, where it is
  // a past event and carries its age.
  let state = <Text dimColor>-</Text>
  if (p.running) {
    state = (
      <Text color="yellow">
        {p.op}: {p.running_stage ?? '…'} ({p.done}/{p.total})
      </Text>
    )
  } else if (info.box && info.box_live === false) {
    state = <Text color="red">GONE (not in account)</Text>
  } else if (info.box) {
    // `up?` when unverified. Green is a claim, and the only thing a state file proves is that
    // something once wrote it down.
    state = info.box_live ? <Text color="green">up</Text> : <Text color="yellow">up?</Text>
  }
  // Subordinate annotation, not a state: a failed or cancelled `up` that never created a box would
  // otherwise leave a completely blank row, and that is the case where it matters most.
  const lastEnded = !p.running && (p.op_status === 'fail' || p.op_status === 'cancelled')
  const lastVerb = p.op_status === 'cancelled' ? 'cancelled' : 'failed'
  return (
    <Box>
      <Text color={selected ? 'cyan' : undefined}>{selected ? '›' : ' '} </Text>
      <Box width={32}>
        <Text bold={selected}>{name}</Text>
      </Box>
      <Box width={18}>
        <Text dimColor>{info.box?.BOX_IP ?? '-'}</Text>
      </Box>
      <Box width={28}>
        {state}
        {lastEnded ? <Text dimColor> (last {p.op} {lastVerb})</Text> : null}
      </Box>
      <Text dimColor>{info.hourly_price ? info.hourly_price.toFixed(4) : ''}</Text>
    </Box>
  )
}

/**
 * One stage row, and its substages beneath it when it has any.
 *
 * Parent and child render through the same component because the difference between them is two
 * characters of indent and a narrower id column — not a different kind of thing. `history` drops
 * the `~expect` on pending rows: a stage of an ENDED run will never run, so an estimate for it is
 * an invitation to wait for something that is not coming.
 *
 * A stage with substages shows them ALWAYS — in the plan, while running, and in history. They were
 * briefly hidden until the parent started, on a noise argument that does not survive contact with
 * the actual number: three rows. Hiding them meant the shape of the hour only appeared once you
 * were inside it, which is exactly too late to be planning around.
 */
function StageRow({ s, history, depth = 0 }: { s: Stage; history?: boolean; depth?: number }) {
  const child = depth > 0
  return (
    <>
      <Box>
        {/* flexShrink=0, or Ink steals the padding from the glyph the moment a detail string is
            long enough to wrap, and the column walks left on exactly the row being watched. */}
        <Box flexShrink={0}>
          <Text color={COLOR[s.state]}>
            {child ? '   └ ' : ' '}
            {GLYPH[s.state]}{' '}
          </Text>
        </Box>
        {/* 30, because the longest id in the repo is `substrate:30-containerd-kata` at 28 and a
            column narrower than its content does not clip — it WRAPS, so the duration lands inside
            the id and the tail of the name appears on its own line. truncate-end is the belt to
            that braces: a longer id added later degrades to an ellipsis, never to a broken row. */}
        <Box width={child ? 26 : 30} flexShrink={0}>
          <Text dimColor={s.state === 'pending' || child} wrap="truncate-end">
            {s.id}
          </Text>
        </Box>
        {/* ctl.py fills elapsed_s LIVE for whatever is running, parent and child alike, so this
            column answers "how long has it been in this one" instead of going blank until it ends. */}
        <Box width={9} flexShrink={0}>
          <Text color={s.state === 'running' ? 'yellow' : undefined}>{s.elapsed_s !== null ? fmtDur(s.elapsed_s) : ''}</Text>
        </Box>
        <Text dimColor wrap="truncate-end">
          {/* A stage nobody has timed and the manifest gives no figure for renders as an empty row,
              which reads as missing data rather than as the honest "we do not know" it is — and in
              a list of pending rows that is the difference between "not yet" and "broken". */}
          {!history && s.state === 'pending' ? expectLabel(s) || 'no estimate yet' : ''}
          {/* Elapsed alone is not progress. `of ~1h02m` is what separates a slow stage from a hung
              one, and this repo has already lost 37 minutes to that exact misreading. The detail is
              dropped on a parent that is about to list its substages: they say the same thing with
              a clock on each part. */}
          {s.state === 'running'
            ? `${expectLabel(s) ? `of ${expectLabel(s)}  ` : ''}${s.substages?.length ? '' : (s.detail ?? '')}`
            : ''}
        </Text>
      </Box>
      {s.substages?.map((sub) => <StageRow key={sub.id} s={sub} history={history} depth={depth + 1} />)}
    </>
  )
}

//: The plan is the same rows in the future tense. Mapping it onto Stage rather than laying out a
//: second set of columns is what stops the two drifting — and it is why starting an operation does
//: not reflow the panel: the same component drew it a moment ago.
const asPending = (s: PlanStage): Stage => ({
  ...s,
  state: 'pending',
  elapsed_s: null,
  substages: s.substages?.map(asPending),
})

/**
 * The detail panel for the selected target, and it has TWO tenses. An operation in flight renders
 * its live progress: done stages, the running one, the ETA. An idle target renders the PLAN —
 * the stages the next operation would run and what each should take, calibrated by ctl.py from
 * the last successful run of that same operation.
 *
 * What history gets is decided by whether a BOX exists. On a live box the last operation's
 * finished stages render in full above the plan — they are what the box currently holds, and
 * hiding them made a fully provisioned machine read as an empty one. With no box, history is one
 * dim `last:` line: rendering a finished run's whole stage table there made ten-hour-old history
 * read as "what happens next", which is backwards in exactly the slot people look at to decide.
 */
function StagePanel({ p, plan, hasBox, boxAgeS }: { p: Progress; plan: Plan; hasBox: boolean; boxAgeS: number | null }) {
  if (p.running) {
    return (
      <Box flexDirection="column" marginTop={1}>
        <Text>
          <Text bold>{p.target}</Text>
          <Text dimColor> · {p.op} · </Text>
          <Text color="yellow">running</Text>
          {p.elapsed_s ? <Text dimColor> · elapsed {fmtDur(p.elapsed_s)}</Text> : null}
          {boxAgeS !== null ? <Text color="green"> · running {fmtDur(boxAgeS)}</Text> : null}
          {p.run?.external ? <Text dimColor> · started by hand</Text> : null}
        </Text>
        {p.error ? <Text color="red"> {p.error}</Text> : null}
        {p.stages.map((s) => (
          <StageRow key={s.id} s={s} />
        ))}
        <Text dimColor>
          {'  '}
          {p.done}/{p.total} done{p.eta_s ? ` · ~${fmtDur(p.eta_s)} of work ahead` : ''}
        </Text>
      </Box>
    )
  }
  const lastVerdict =
    p.op_status === 'fail' ? (
      <Text color="red">FAILED</Text>
    ) : p.op_status === 'cancelled' ? (
      <Text color="yellow">cancelled</Text>
    ) : p.op_status === 'ok' ? (
      <Text dimColor>succeeded</Text>
    ) : null
  const showHistory = hasBox && lastVerdict !== null
  /**
   * ONE STAGE LIST ON SCREEN AT A TIME. A finished run's ✔ rows stacked above a plan's ○ rows read
   * as a single checklist that stopped part-way — "8/8 done" with four unfinished steps under it —
   * and no amount of separator fixes that, because the two lists look like the same kind of thing.
   * They are not: one is what happened, the other is an operation nobody has started.
   *
   * So with history present the plan collapses to its names on one line. It expands in the two
   * cases where it is the thing being read: no history at all (the cluster before its first build,
   * where the shape of the next two hours is the whole question), and a resume, where the list IS
   * the answer — precisely which stages this box has left.
   */
  const expanded = !showHistory || Boolean(plan.resume_from)
  return (
    <Box flexDirection="column" marginTop={1}>
      {showHistory ? (
        <>
          <Text>
            <Text bold>{p.target}</Text>
            <Text dimColor> · {p.op} · </Text>
            {lastVerdict}
            {/* On a LIVE box the machine's age beats the operation's: one is the billing clock, the
                other is trivia about a run that is over. Only when the box is gone (or unverified)
                does "ended X ago" become the most present-tense thing there is to say. */}
            {boxAgeS !== null ? (
              <Text color="green"> · running {fmtDur(boxAgeS)}</Text>
            ) : p.age_s ? (
              <Text dimColor> · ended {fmtDur(p.age_s)} ago</Text>
            ) : null}
          </Text>
          {p.error ? <Text color="red"> {p.error}</Text> : null}
          {p.stages.map((s) => (
            <StageRow key={s.id} s={s} history />
          ))}
          <Text dimColor>
            {'  '}
            {p.done}/{p.total} done
          </Text>
        </>
      ) : null}
      {/* A BLANK LINE and a bold header, because these two blocks are different tenses and looked
          like one list. Under a finished `up`, the plan's four pending rows read as four steps of
          that up which had somehow not run — "8/8 done" with unfinished steps below it — when they
          are the `run` that has not started. The separation is the only thing that says so, and a
          dim inline label sitting flush with the stage rows above it was not enough. ctl.py prints
          the same blank line for the same reason. */}
      <Box flexDirection="column" marginTop={showHistory ? 1 : 0}>
        <Text>
          {showHistory ? null : <Text bold>{p.target}</Text>}
          <Text dimColor>{showHistory ? '' : ' · '}</Text>
          <Text bold>next: </Text>
          <Text bold color="cyan">
            {plan.op}
            {plan.resume_from ? ` --from ${plan.resume_from}` : ''}
          </Text>
          {plan.expect_total_s ? (
            <Text dimColor>
              {' '}· ~{fmtDur(plan.expect_total_s)} {totalLabel(plan)}
            </Text>
          ) : null}
        </Text>
        {/* An unfinished install is not the same as an idle box, and offering `down` as the obvious
            next step to someone 80 minutes into one is worse than saying nothing. */}
        {plan.resume_from ? (
          <Text dimColor>{'  '}the install stopped part-way — what this box has not done yet</Text>
        ) : null}
        {expanded ? (
          plan.stages.map((s) => <StageRow key={s.id} s={asPending(s)} />)
        ) : (
          <Text dimColor wrap="truncate-end">
            {'  '}
            {plan.stages.map((s) => s.id).join(' → ')}
          </Text>
        )}
      </Box>
      {!showHistory && lastVerdict ? (
        <Text>
          <Text dimColor>
            {'  '}last: {p.op} ·{' '}
          </Text>
          {lastVerdict}
          {p.age_s ? <Text dimColor> · ended {fmtDur(p.age_s)} ago</Text> : null}
        </Text>
      ) : null}
      {/* A failed run's message must survive the demotion — it is the one line a post-mortem needs. */}
      {!showHistory && p.error && p.op_status !== 'ok' ? <Text color="red"> {p.error}</Text> : null}
    </Box>
  )
}

/**
 * Pick the stage an `up` restarts at — `ctl.py up <target> --from <id>`, which for the cluster is
 * the recovery move its runbook prints. It exists as a picker rather than as one key because the
 * right answer is not always the one ctl.py computes: a stage can *succeed* and still leave the
 * thing it built broken, and then the fix is to re-run it rather than the one after it.
 *
 * The stage list comes from `ctl.py stages`, so it is stages.json's order, with its measured
 * durations, and this file cannot drift from what the driver will actually run.
 */
function StagePicker({ target, stages, index }: { target: string; stages: PlanStage[]; index: number }) {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text>
        <Text bold>{target}</Text>
        <Text dimColor> · resume from which stage? </Text>
        <Text dimColor>↑↓ select · enter confirm · any other key cancels</Text>
      </Text>
      {stages.map((s, i) => (
        <Box key={s.id}>
          <Text color={i === index ? 'cyan' : undefined}>{i === index ? ' ›' : '  '} </Text>
          <Box width={26}>
            <Text bold={i === index} dimColor={i !== index}>
              {s.id}
            </Text>
          </Box>
          <Box width={9}>
            <Text dimColor>{s.expect_s ? `~${fmtDur(s.expect_s)}` : ''}</Text>
          </Box>
          <Text dimColor>{s.title ?? ''}</Text>
        </Box>
      ))}
    </Box>
  )
}

/**
 * The account line sits at the TOP of the live region, above the table, because it is the panel's
 * headline fact — "is anything still billing" — and in the footer it was buried under whichever
 * notice or confirmation happened to be on screen. Its warnings travel with it: an orphan or a
 * GONE box is the same fact painted red — a disagreement between the account and the table below.
 */
function AccountBar({ account, burn, gone }: { account: Account | null; burn: number; gone: string[] }) {
  const orphans = (account?.orphan_volumes ?? 0) + (account?.orphan_ips ?? 0)
  return (
    <Box flexDirection="column" marginBottom={1}>
      <Box>
        <Text dimColor>account: </Text>
        {account?.available ? (
          <Text>
            {account.vms.length} vm · {account.baremetal.length} baremetal ·{' '}
            <Text color={orphans ? 'red' : undefined}>
              {account.orphan_volumes} orphan vol · {account.orphan_ips} orphan ip
            </Text>
          </Text>
        ) : (
          <Text dimColor>unknown (scw unavailable)</Text>
        )}
        <Text dimColor> · burn: </Text>
        <Text bold color={burn > 0 ? 'yellow' : undefined}>
          EUR {burn.toFixed(4)}/hr
        </Text>
      </Box>
      {orphans > 0 ? <Text color="red"> a detached volume and an unattached IP each keep billing on their own — press d, or ./down.sh --all</Text> : null}
      {gone.length > 0 ? (
        <Text color="red"> {gone.join(', ')}: state names a box the account does not have — the next up would RE-CREATE it. press c</Text>
      ) : null}
    </Box>
  )
}

function Footer({
  pending,
  notice,
  keys,
}: {
  pending: string | null
  notice: string | null
  //: Built per selected target from available() — the hint line offers only keys that apply.
  keys: string
}) {
  return (
    <Box flexDirection="column" marginTop={1}>
      {pending ? (
        <Text color="red" bold>
          {pending}
        </Text>
      ) : notice ? (
        <Text color="yellow">{notice}</Text>
      ) : (
        <Text dimColor>{keys}</Text>
      )}
    </Box>
  )
}

function App() {
  const { status, error, refresh } = useStatus()
  const account = useAccount()
  const { exit } = useApp()
  const [cursor, setCursor] = useState(0)
  //: Two-key confirmation for anything that ends a machine or rewrites state. The TUI asks; ctl.py
  //: never does — it takes --yes instead, so the same action from a script cannot hang waiting for
  //: a keypress. Carrying the argv rather than a target name is what lets one gate cover both
  //: `down` and `reconcile --prune` without a second confirmation path to keep in step.
  const [pending, setPending] = useState<{ prompt: string; argv: string[] } | null>(null)
  //: A one-line answer for a keypress that cannot apply. Cleared by the next key, so it never
  //: becomes a stale claim sitting in the footer.
  const [notice, setNotice] = useState<string | null>(null)
  //: Open only while choosing a resume stage; it replaces the detail panel rather than sitting
  //: beside it, so the list being read is the only stage list on screen.
  const [picker, setPicker] = useState<{ target: string; stages: PlanStage[]; index: number } | null>(null)

  const names = useMemo(() => (status ? Object.keys(status.targets) : []), [status])
  //: Applied once, when the target list first arrives — not on every poll, or the cursor would snap
  //: back to the named target every two seconds and the arrow keys would be unusable.
  const placed = useRef(false)
  useEffect(() => {
    if (placed.current || !names.length) return
    placed.current = true
    const i = WANTED ? names.indexOf(WANTED) : -1
    if (i >= 0) setCursor(i)
  }, [names])
  const selected = names[Math.min(cursor, Math.max(0, names.length - 1))]
  const info = selected && status ? status.targets[selected] : null
  const avail = available(info)
  const resumeFrom = info?.plan.resume_from ?? null
  const keys = [
    '↑↓ select',
    avail.up ? (resumeFrom ? `u resume (${resumeFrom})` : 'u up') : null,
    avail.from ? 'f from stage…' : null,
    avail.run ? 'r run' : null,
    avail.down ? 'd down' : null,
    avail.stop ? 's stop op' : null,
    'c reconcile',
    'a refresh',
    'q quit',
  ]
    .filter(Boolean)
    .join(' · ')
  const logLines = useLogTail(info?.progress.run?.log, info?.progress.running ?? false)
  //: A box the account does not have is not billing, whatever its state file says. Leaving its price
  //: in the total makes the one number anybody acts on the wrong number, in the alarming direction.
  const burn = useMemo(
    () =>
      status
        ? Object.values(status.targets).reduce((a, t) => a + (t.box_live === false ? 0 : (t.hourly_price ?? 0)), 0)
        : 0,
    [status],
  )
  const gone = useMemo(
    () => (status ? Object.entries(status.targets).filter(([, t]) => t.box && t.box_live === false).map(([n]) => n) : []),
    [status],
  )

  useEffect(() => {
    if (ONCE && status && account !== null) {
      const t = setTimeout(() => exit(), 50)
      return () => clearTimeout(t)
    }
  }, [status, account, exit])

  //: Every keypress action funnels through here: refresh on success, footer notice on refusal.
  //: A bare `.then(refresh)` leaves the rejection unhandled, and under Node's default policy an
  //: unhandled rejection is FATAL — pressing `s` with nothing running took down the entire panel,
  //: which is the one process that must survive while a box is billing.
  const act = (argv: string[], timeoutMs?: number) =>
    void ctl(argv, timeoutMs)
      .then(refresh)
      .catch((e: unknown) => setNotice(e instanceof Error ? e.message : String(e)))

  // `isActive` and not an early `return` inside the handler: Ink puts stdin into raw mode to listen
  // at all, and raw mode does not exist on a pipe. Registering unconditionally makes `--once` throw
  // "Raw mode is not supported" in exactly the non-interactive case it exists to serve.
  //: The confirmation an `up --from` needs — and it is not always the same question. A resume that
  //: will pass through the stage which re-images the box destroys the cluster living on it, and that
  //: is a different decision from "finish the install". Computed from the stages ahead, so the flag
  //: in stages.json decides it rather than a stage name spelled out here.
  const resumePrompt = (target: string, ahead: PlanStage[], id: string) =>
    ahead.some((s) => s.rewrites_box)
      ? `resume ${target} from ${id}? this RE-IMAGES the box — any cluster on it is destroyed — y to confirm`
      : `resume ${target} from ${id}? earlier stages are skipped — y to confirm, any other key to cancel`

  useInput((input, key) => {
    if (picker) {
      if (key.downArrow || input === 'j')
        return setPicker({ ...picker, index: Math.min(picker.index + 1, picker.stages.length - 1) })
      if (key.upArrow || input === 'k') return setPicker({ ...picker, index: Math.max(picker.index - 1, 0) })
      if (key.return) {
        const st = picker.stages[picker.index]
        setPicker(null)
        return setPending({
          prompt: resumePrompt(picker.target, picker.stages.slice(picker.index), st.id),
          argv: ['up', picker.target, '--from', st.id, '--detach'],
        })
      }
      return setPicker(null)
    }
    if (pending) {
      // Confirm or abandon. Any key that is not `y` cancels — the safe outcome is the default.
      // The long timeout is for `reconcile --prune`: it runs down.sh per stale target and waits for
      // each, unlike `down --detach` which returns as soon as the worker is spawned.
      if (input === 'y') {
        act(pending.argv, 600000)
      }
      setPending(null)
      return
    }
    setNotice(null)
    if (input === 'q' || (key.ctrl && input === 'c')) return exit()
    if (key.downArrow || input === 'j') return setCursor((c) => Math.min(c + 1, names.length - 1))
    if (key.upArrow || input === 'k') return setCursor((c) => Math.max(c - 1, 0))
    if (input === 'c')
      return setPending({
        prompt: `reconcile: clear state for ${gone.length || 'any'} box(es) the account no longer has — y to confirm, any other key to cancel`,
        argv: ['reconcile', '--prune'],
      })
    if (!selected) return
    if (input === 'a') return void refresh()
    // The four target keys are gated on available(): a key the hint line is not offering answers
    // with the reason instead of a detached-log FATAL. ctl.py refuses all of these too and that is
    // the enforcement; answering here only saves the trip to a log file to find out why.
    if (input === 'u') {
      if (!avail.up) {
        const op = info?.progress.running ? (info.progress.run?.op ?? 'operation') : null
        return setNotice(
          op ? `${selected}: ${op} in flight — s stops it first` : `${selected}: box already up — r runs the lesson, d destroys it`,
        )
      }
      // Finishing an unfinished install is not the same act as creating a box: there is a live,
      // billing machine involved, and the stages ahead may include the one that re-images it.
      if (resumeFrom && info)
        return setPending({
          prompt: resumePrompt(selected, info.plan.stages, resumeFrom),
          argv: ['up', selected, '--from', resumeFrom, '--detach'],
        })
      return act(['up', selected, '--detach'])
    }
    if (input === 'f') {
      if (!avail.from)
        return setNotice(
          info?.cluster
            ? `${selected}: ${info.progress.run?.op ?? 'an operation'} in flight — s stops it first`
            : `${selected}: --from is openshift-sno only — a lesson box is rebuilt whole in minutes`,
        )
      // The list comes from ctl.py, never from this file: same order, same measured durations, and
      // the same ids the driver will match against.
      return void ctl(['stages', selected, '--json'])
        .then((out) => {
          const stages = JSON.parse(out) as PlanStage[]
          const at = resumeFrom ? stages.findIndex((s) => s.id === resumeFrom) : 0
          setPicker({ target: selected, stages, index: Math.max(0, at) })
        })
        .catch((e: unknown) => setNotice(e instanceof Error ? e.message : String(e)))
    }
    if (input === 'r') {
      // Every target the panel can select owns a box (it lists lessons.json), so `no box` covers
      // chapter 4's box-less lessons never appearing here. A live `up` counts as a box on the way:
      // ctl.py accepts the run and run.sh's wait-box stage holds it until ready.
      if (!avail.run) {
        if (info?.cluster) return setNotice(`${selected}: a cluster, not a lesson — run 1.4.1..1.4.6 against it from their own folders`)
        if (info?.progress.running) return setNotice(`${selected}: ${info.progress.run?.op ?? 'operation'} already running — s stops it`)
        if (info?.box && info.box_live === false) return setNotice(`${selected}: box GONE (not in account) — press c to reconcile`)
        return setNotice(`${selected}: no box — press u first (nothing is running for it)`)
      }
      return act(['run', selected, '--detach'])
    }
    if (input === 's') {
      // `stop` cancels an OPERATION, not a box — the misread this notice exists to catch is an
      // up-but-idle target, where "stop" reads as "stop the machine" and the right key is `d`.
      // ctl.py still enforces (the run can end between poll and keypress); this answers instantly.
      if (!avail.stop) return setNotice(`${selected}: nothing running — s cancels a running up/run; d tears the box down`)
      return act(['stop', selected])
    }
    if (input === 'd') {
      if (!avail.down) {
        const p = info?.progress
        if (p?.running) {
          // The distinction that earns `d` its own refusal text: cancelling an `up` destroys the
          // partial box as part of the cancel, so "stop" is not leaving anything behind.
          return setNotice(
            p.run?.op === 'up'
              ? `${selected}: up in flight — s stops it (and destroys the partial box)`
              : `${selected}: ${p.run?.op ?? 'operation'} running — s stops the operation; the box stays up`,
          )
        }
        return setNotice(`${selected}: no box to destroy`)
      }
      return setPending({
        prompt: `destroy ${selected}? this ends a live machine — y to confirm, any other key to cancel`,
        argv: ['down', selected, '--yes', '--detach'],
      })
    }
  }, { isActive: !ONCE && Boolean(process.stdin.isTTY) })

  if (error && !status) return <Text color="red">ctl.py: {error}</Text>
  // In --once, hold the first paint until everything has landed. Ink repaints on every state change
  // and a pipe keeps all of them, so rendering eagerly produces three half-populated frames above
  // the real one — which reads like flapping data rather than a page still loading.
  if (!status || (ONCE && account === null)) return <Text dimColor>{ONCE ? '' : 'reading state…'}</Text>

  return (
    <Box flexDirection="column">
      {/* Static prints permanently and is never repainted, so the log survives in scrollback and in
          a captured session. Everything below it is the small live region. */}
      <Static items={logLines}>{(l) => <Text key={l.key} dimColor>{`  │ ${l.text}`}</Text>}</Static>

      <AccountBar account={account} burn={burn} gone={gone} />
      <Box>
        <Text bold>{'  '}</Text>
        <Box width={32}>
          <Text bold>TARGET</Text>
        </Box>
        <Box width={18}>
          <Text bold>BOX</Text>
        </Box>
        <Box width={28}>
          <Text bold>STATE</Text>
        </Box>
        <Text bold>EUR/hr</Text>
      </Box>
      {names.map((n, i) => (
        <TargetRow key={n} name={n} info={status.targets[n]} selected={i === cursor} />
      ))}

      {picker ? (
        <StagePicker target={picker.target} stages={picker.stages} index={picker.index} />
      ) : info ? (
        <StagePanel p={info.progress} plan={info.plan} hasBox={Boolean(info.box)} boxAgeS={info.box_age_s} />
      ) : null}
      <Footer pending={pending?.prompt ?? null} notice={notice} keys={keys} />
    </Box>
  )
}

render(<App />, { exitOnCtrlC: true })
