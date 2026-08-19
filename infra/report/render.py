#!/usr/bin/env python3
"""Render ONE lesson's scorecard into ``report.html`` + ``report.json`` in that lesson's folder.

    python3 infra/report/render.py 1.2.2
    python3 infra/report/render.py --open 1.2.1
    python3 infra/report/render.py                 # every lesson that has a scorecard

Each page describes **only its own lesson**. It never reads another lesson's card, so a lesson's
report is complete the moment that lesson finishes and can never go stale because a later lesson
ran. Comparing rungs is the job of ``infra/report/overall.py``, which reads the ``report.json``
files these produce.

``report.json`` is the machine-readable twin of the page: the same findings, plus the verdict
vocabulary and a count, so the aggregator never has to re-derive "what counts as scored".

Wording: an attack is **BLOCKED** (the boundary stopped it) or it **SUCCEEDED** (it got what it
wanted). Rows that only measure something are **INFO** and are never scored.

Two page layouts, one renderer. A phase-1 page leads with the containment question — *N of M attacks
blocked* — and closes with the RECORDED band. A phase-2 (audit) page leads with the other question —
*N of M attacks recorded* — because that is what the lesson measured: the same suite behind the same
boundary, with a sensor watching. It carries a segmented coverage bar (logged / crossed a sensor and
unrecorded / no sensor), the containment reading demoted to second place, the attacks that
succeeded without a record called out, a containment × record grid, and the RECORDED verdict beside
each attack's own row rather than in a detached band. Same vocabulary, same probes, same colours;
only the emphasis flips.

Standard library only, and the HTML is one self-contained file with no external assets, so it
opens from a file:// URL on a machine with nothing installed.
"""

from __future__ import annotations

import html
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import ids  # the id<->path resolver, shared with overall.py

REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS = REPO_ROOT / "results"
TUTORIAL = REPO_ROOT / "tutorial"

#: One line per probe, for the page itself. The *extensive* explanation — why an attacker wants
#: this and why the reading matters — is ATTACKS.md, which every page links to. Short label here,
#: long prose there, deliberately: two copies of the long form would drift.
WHY: dict[str, tuple[str, str]] = {
    "read_credentials": ("1", "Can it read your secrets? Planted API keys and SSH keys in $HOME."),
    "exfiltrate": ("2", "Can it send what it stole to an outside server?"),
    "plant_backdoor": ("3", "Can it leave something behind that runs again later?"),
    "cloud_metadata": ("4", "Can it reach the cloud's credential service? (the classic SSRF)"),
    "malicious_package": ("5", "Can a dependency run code just by being installed?"),
    "reverse_shell": ("6", "Can it download a second payload and open a way in?"),
    "resource_exhaustion": ("7", "Can it take the machine down with a fork bomb?"),
    "kernel_identity": ("8", "Is it talking to the REAL host kernel, or a sandbox's own?"),
    "sys_module_count": ("8", "Can it enumerate the host's loaded kernel modules?"),
    "kallsyms_readable": ("8", "Can it read kernel symbol addresses (exploit aid)?"),
    "bpf": ("8", "Can it call bpf() — a powerful, CVE-rich kernel interface?"),
    "io_uring_setup": ("8", "Can it call io_uring_setup() — a large kernel attack surface?"),
    "perf_event_open": ("8", "Can it call perf_event_open() — kernel profiling?"),
    "egress_gateway": ("P", "Is the ALLOWED destination still reachable? A policy must permit, not only deny."),
    "egress_offpolicy": ("P", "Is an unlisted destination refused, one port from an allowed one?"),
    "http_method_denied": ("P", "Is POST refused to a host where GET is allowed? (needs layer 7)"),
    "binary_scoped": ("P", "Is the SAME binary refused from a path the policy does not name?"),
    "fs_policy_write": ("P", "Is a write outside the allowed paths refused?"),
    "audit_records": ("9", "Was any of it written down? A container blocks and forgets."),
    "home_items": ("-", "How many entries $HOME has — context, not a verdict."),
    "secretish_env": ("-", "Secret-looking environment variables — context, not a verdict."),
    "syscall_ms": ("-", "Syscall-bound work, in ms — the cost this boundary charges."),
    "cpu_ms": ("-", "CPU-bound work, in ms — for comparison."),
    # Probes a single chapter adds beside the shared suite. No ATTACKS.md number: the lesson's own
    # README is their long form.
    "k8s_sa_token": ("", "Can it use the pod's ServiceAccount token against the control plane? (a cluster foothold)"),
    "scc_privileged_refused": ("P", "Is an over-privileged pod refused at admission, before it ever starts?"),
    "scc_refused_by_admission": ("P", "Was it SCC admission that refused it — not RBAC?"),
    "scc_compliant_admitted": ("P", "Is the same workload admitted once it complies? Must permit, not only deny."),
    "admission_records": ("9", "Did the apiserver audit log record those admission decisions?"),
    "landlock_available": ("9", "Does OpenShell's Landlock policy exist under this runtime? gVisor drops it silently."),
    "in_guest_sensor_available": ("9", "Could a sensor be placed inside the guest at all?"),
}

GROUP_LABEL = {
    "reach": "Reach — get to something valuable",
    "abuse": "Abuse — do damage with it",
    "kernel": "Kernel — how much of the real kernel is exposed",
    "policy": "Policy — which binary, which method, which pod spec (needs a policy engine)",
    "evidence": "Evidence — was any of it written down",
    "cost": "Cost — what the boundary charges",
}

BLOCKED, SUCCEEDED, INFO = "BLOCKED", "SUCCEEDED", "INFO"

#: The RECORDED axis — was the attack written down? Orthogonal to the verdict (blocked/succeeded),
#: so it never borrows the verdict's green/red. Glyph + label, never colour alone.
LOGGED, NOT_LOGGED, NO_SENSOR, NOT_RUN = "LOGGED", "NOT_LOGGED", "NO_SENSOR", "NOT_RUN"
RECORDED_GLYPH = {LOGGED: "●", NOT_LOGGED: "○", NO_SENSOR: "▬", NOT_RUN: "·"}
RECORDED_LABEL = {LOGGED: "LOGGED", NOT_LOGGED: "NOT LOGGED", NO_SENSOR: "no sensor", NOT_RUN: "not run"}
#: One clause per state, for legends. Kept beside the glyphs so a legend can never say something the
#: cell does not.
RECORDED_WHY = {
    LOGGED: "a record names it",
    NOT_LOGGED: "crossed a sensor, nothing written",
    NO_SENSOR: "no sensor can see it",
}
#: The states that make up the coverage denominator: every scored attack resolves to one of these
#: three, and the coverage bar is their three segments. A state outside this tuple (NOT_RUN today; a
#: future "nothing happened to record") is excluded from the denominator here and nowhere else — the
#: page, report.json and overall.py all count through recorded_tally().
COVERAGE_STATES = (LOGGED, NOT_LOGGED, NO_SENSOR)


def verdict_of(finding: dict) -> str:
    contained = finding.get("contained")
    if contained is None:
        return INFO
    return BLOCKED if contained else SUCCEEDED


def is_audit(card: dict) -> bool:
    """Phase 2 is the audit phase: ``2.C.L`` audits ``1.C.L`` (syllabus § Phase 2), so the leading digit
    of the id decides the layout — the same split overall.py makes between its two ladders."""
    return str(card.get("lesson", "")).split(".")[0] == "2"


def recorded_of(finding: dict) -> str:
    """The effective RECORDED state. A card that never consulted a sensor leaves ``recorded`` None;
    on a phase-1 rung that IS ``NO_SENSOR`` — the container blocks the attack and forgets it, which
    is the finding phase 2 exists to make visible — so None resolves to NO_SENSOR, never blank."""
    r = finding.get("recorded")
    return r if r in (LOGGED, NOT_LOGGED, NO_SENSOR, NOT_RUN) else NO_SENSOR


def css_class(verdict: str) -> str:
    return {BLOCKED: "blocked", SUCCEEDED: "succeeded", INFO: "info"}[verdict]


def scored_findings(card: dict) -> list[dict]:
    return [f for f in card["findings"] if f.get("contained") is not None]


def tally(card: dict) -> tuple[int, int]:
    scored = scored_findings(card)
    return sum(1 for f in scored if f["contained"]), len(scored)


def recorded_tally(card: dict) -> dict:
    """The RECORDED axis, counted once for the page, report.json and overall.py.

    ``counts`` is one entry per COVERAGE_STATE, so ``sum(counts.values())`` is the denominator. Two
    breach lists cut across the axes, and the distinction between them is the one an operator acts
    on: an **unseen** breach SUCCEEDED where a sensor was watching and wrote nothing (the sensor's
    miss), a **blind** breach SUCCEEDED where no sensor could see (the stack's gap). Together they are
    the attacks that got what they wanted and left no record.
    """
    scored = scored_findings(card)
    counts = {state: 0 for state in COVERAGE_STATES}
    unseen: list[str] = []
    blind: list[str] = []
    for f in scored:
        rec = recorded_of(f)
        if rec in counts:
            counts[rec] += 1
        if f["contained"] is False and rec == NOT_LOGGED:
            unseen.append(f["name"])
        elif f["contained"] is False and rec == NO_SENSOR:
            blind.append(f["name"])
    return {"counts": counts, "logged": counts[LOGGED], "unseen": unseen, "blind": blind}


def short(lesson: str) -> str:
    """A compact label for a dotted id: `1.2.2` -> `1.2.2 container-gvisor` (via the tree)."""
    return ids.short(lesson)


def esc(value: object) -> str:
    return html.escape(str(value))


def fmt_dur(seconds: object) -> str:
    """`1h07m` / `1m03s` / `47s`, matching scorecard.py's fmt_duration so the report and the terminal
    print the run time the same way. Empty for a card that predates duration tracking."""
    if seconds is None:
        return ""
    try:
        s = int(round(float(seconds)))  # pyright: ignore[reportArgumentType]
    except (TypeError, ValueError):
        return ""
    if s >= 3600:
        return f"{s // 3600}h{(s % 3600) // 60:02d}m"
    if s >= 60:
        return f"{s // 60}m{s % 60:02d}s"
    return f"{s}s"


#: Card keys the page renders somewhere specific — the title, the sub-line, the score, the run time,
#: the tables. Everything else a lesson wrote about its box is a measurement and is listed verbatim.
STRUCTURAL_KEYS = frozenset({"lesson", "mode", "boundary", "complete", "findings", "duration_s"})


def measurements(card: dict) -> dict:
    """Everything the lesson recorded about the machine and its sensors, in the order it wrote them:
    ``engine``, ``node_kernel``, and on an audit rung the sensor readings — ``host_sensor_logged``,
    ``in_guest_logged``, ``ocsf_logged`` — that say where the coverage came from. Listed rather than
    curated: a card key that renders nowhere is a reading the lesson paid a box for and nobody sees."""
    return {k: v for k, v in card.items() if k not in STRUCTURAL_KEYS}


def fmt_value(value: object) -> str:
    """A reading as one line: a list joins, a dict reads ``k=v, k=v``, anything else prints as is."""
    if isinstance(value, dict):
        return ", ".join(f"{k}={v}" for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) or "—"
    return "—" if value in (None, "") else str(value)


def meta_rows(card: dict) -> str:
    rows = []
    for key, value in measurements(card).items():
        if isinstance(value, dict):  # one level of nesting reads as `key.sub` — the Kata hypervisor facts
            rows += [f"<dt>{esc(key)}.{esc(k)}</dt><dd>{esc(fmt_value(v))}</dd>" for k, v in value.items()]
        else:
            rows.append(f"<dt>{esc(key)}</dt><dd>{esc(fmt_value(value))}</dd>")
    return "".join(rows)


def load_card(lesson: str) -> dict | None:
    """A lesson's scorecard, by dotted id. `1.2.2` -> results/1.2.2.json."""
    path = RESULTS / f"{lesson}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"  skipping {path.name}: {exc}", file=sys.stderr)
        return None


# --- the machine-readable twin -----------------------------------------------


def build_json(card: dict) -> dict:
    """What ``overall.py`` consumes. Verdicts are resolved here, once.

    **Every rung is measured with the network an agent actually needs**, and that uniformity is what
    makes the top-level findings comparable rung against rung. A rung measured at ``--network none``
    would score several attacks higher for a reason that has nothing to do with its boundary, and
    diffing it against an online neighbour would read like a boundary result while being a mode
    artefact.
    """
    primary = card
    blocked, scored = tally(primary)
    rec = recorded_tally(primary)
    return {
        "lesson": primary["lesson"],
        "mode": primary.get("mode", ""),
        "boundary": primary.get("boundary", ""),
        "generated_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "complete": primary.get("complete", True),
        # How long the lesson ran, as the scorecard recorded it. None on a card written before
        # duration tracking; overall.py and the page both tolerate that.
        "duration_s": primary.get("duration_s"),
        "blocked": blocked,
        "scored": scored,
        # The RECORDED axis, counted once (recorded_tally). `logged` over `sum(recorded_counts)` is the
        # coverage; the two breach counts are SUCCEEDED attacks that left no record — `unseen` where a
        # sensor watched and wrote nothing, `unrecorded` all of them, sensor or no sensor.
        "logged": rec["logged"],
        "recorded_counts": rec["counts"],
        "unseen_breaches": len(rec["unseen"]),
        "unrecorded_breaches": len(rec["unseen"]) + len(rec["blind"]),
        # The machine, kept verbatim. `overall.py` uses it to warn when two rungs were measured on
        # different hosts — a comparison this repo treats as invalid, because then a changed row could
        # be the hardware rather than the boundary.
        "host": {
            k: primary[k] for k in ("engine", "node_kernel", "openshell_version", "runtime_exit_code") if k in primary
        },
        # Everything else the lesson recorded — sensor readings on an audit rung, hypervisor facts on
        # a Kata one — verbatim, so the page's meta block and this file say the same things.
        "measurements": measurements(primary),
        "findings": [
            {
                "name": f["name"],
                "attack": WHY.get(f["name"], ("?", ""))[0],
                "why": WHY.get(f["name"], ("", ""))[1],
                "group": f.get("group", "other"),
                "value": f.get("value"),
                "detail": f.get("detail", ""),
                "verdict": verdict_of(f),
                # The RECORDED axis, resolved once here so the page and overall.py never re-derive it.
                # Only meaningful for scored attacks; INFO rows carry NOT_RUN (nothing to record).
                "recorded": recorded_of(f) if f.get("contained") is not None else NOT_RUN,
            }
            for f in primary["findings"]
        ],
    }


# --- the page ----------------------------------------------------------------


def recorded_cell(finding: dict) -> tuple[str, str]:
    """A scored attack's RECORDED reading as ``(row class, cell html)``: glyph + label, never colour
    alone, and the one badge — an attack that SUCCEEDED where a sensor watched and wrote nothing."""
    rec = recorded_of(finding)
    alarm = finding.get("contained") is False and rec == NOT_LOGGED
    cls = f"rec-{rec.lower().replace('_', '-')}" + (" rec-alarm" if alarm else "")
    badge = ' <span class="rec-badge">unseen breach</span>' if alarm else ""
    # The state class sits on the CELLS, so the reading keeps its own colour inside a row whose tint
    # belongs to the other axis (the verdict's green/red on the combined table).
    cell = (
        f'<td class="rec-glyph {cls}">{RECORDED_GLYPH[rec]}</td>'
        f'<td class="rec-label {cls}">{esc(RECORDED_LABEL[rec])}{badge}</td>'
    )
    return cls, cell


def probe_tables(card: dict, recorded_column: bool = False) -> str:
    """The per-attack tables, one per group in teaching order. On an audit page every scored row also
    carries its RECORDED reading, so the two questions — did it hold, would you know — are answered
    side by side on the row itself instead of in two tables the reader has to zip by hand."""
    # Known groups in teaching order, then anything else. The catch-all is not defensive
    # programming for its own sake: `evidence` was added to the suite and silently vanished from
    # this page, because a group missing from GROUP_LABEL renders as nothing at all. A report that
    # quietly omits a probe is worse than one that looks untidy.
    groups = list(GROUP_LABEL)
    groups += sorted({f.get("group", "other") for f in card["findings"]} - set(groups))

    blocks = []
    for group in groups:
        members = [f for f in card["findings"] if f.get("group") == group]
        if not members:
            continue
        label = GROUP_LABEL.get(group, f"{group} — (ungrouped: add it to GROUP_LABEL)")
        rows = []
        for f in members:
            v = verdict_of(f)
            num, why = WHY.get(f["name"], ("", ""))
            rec_cells = ""
            if recorded_column:
                rec_cells = '<td class="rec-glyph"></td><td class="rec-label"></td>'
                if v != INFO:
                    _, rec_cells = recorded_cell(f)
            rows.append(
                f'<tr class="{css_class(v)}"><td class="num">{esc(num)}</td>'
                f'<td class="probe">{esc(f["name"])}<span class="why">{esc(why)}</span></td>'
                f'<td class="value">{esc(f.get("value"))}</td>'
                f'<td class="detail">{esc(f.get("detail", ""))}</td>'
                f'<td class="verdict">{v}</td>{rec_cells}</tr>'
            )
        blocks.append(f"<h2>{esc(label)}</h2><table><tbody>{''.join(rows)}</tbody></table>")
    return "".join(blocks)


def recorded_band(card: dict) -> str:
    """The RECORDED band: for every scored attack, was the attempt written down?

    A different axis from the verdict — a boundary can *block* an attack and keep no *record* that it
    was tried. On a phase-1 rung the band is a wall of ``no sensor``, and that wall is the finding:
    the container forgets, so full audit coverage is what phase 2 goes on to build. The worst cell is
    an attack that both SUCCEEDED and was NOT LOGGED — badged, because it is the one an operator would
    most want and least get.
    """
    scored = scored_findings(card)
    if not scored:
        return ""
    rows = []
    for f in scored:
        cls, cells = recorded_cell(f)
        num = WHY.get(f["name"], ("", ""))[0]
        rows.append(
            f'<tr class="{cls}"><td class="num">{esc(num)}</td><td class="probe">{esc(f["name"])}</td>{cells}</tr>'
        )
    return (
        "<h2>Recorded — would you ever know it was tried?</h2>"
        '<p class="note">The verdicts above say whether the boundary <em>held</em>. This says whether '
        f"anything <em>wrote the attempt down</em> — an orthogonal axis.<br>{recorded_legend()}</p>"
        f'<table class="recorded"><tbody>{"".join(rows)}</tbody></table>'
    )


def recorded_legend() -> str:
    return " &nbsp; ".join(
        f'<span class="rec-glyph {"rec-" + s.lower().replace("_", "-")}">{RECORDED_GLYPH[s]}</span> {RECORDED_WHY[s]}'
        for s in COVERAGE_STATES
    )


def coverage_bar(counts: dict[str, int]) -> str:
    """The recorded meter: one segment per COVERAGE_STATE, widths in proportion, so a reader sees at a
    glance not just how much was logged but what the rest was — a sensor that watched and wrote
    nothing is a different finding from a layer no sensor reaches."""
    total = sum(counts.values())
    if not total:
        return ""
    segs = []
    for state in COVERAGE_STATES:
        n = counts[state]
        if n:
            title = f"{n} {RECORDED_LABEL[state]}"
            segs.append(
                f'<span class="seg seg-{state.lower().replace("_", "-")}" '
                f'style="width:{100 * n / total:.2f}%" title="{esc(title)}"></span>'
            )
    return f'<span class="bar seg-bar" role="img" aria-label="{total} attacks">{"".join(segs)}</span>'


def all_witnessed_callout(all_blocked: bool, unrecorded: int) -> str:
    """The callout when no attack both SUCCEEDED and went unrecorded. Says which of the two good
    outcomes this is — everything held, or something got through but was seen — and does not let a
    silently-blocked attempt pass as coverage: held-and-unrecorded still loses the intent."""
    if all_blocked and not unrecorded:
        text = "<strong>Nothing got through, and every attempt was recorded.</strong>"
    elif all_blocked:
        text = (
            f"<strong>Nothing got through</strong> — but {unrecorded} blocked attempt{'s' if unrecorded != 1 else ''} "
            "left no record: the boundary held and the intent went unnoticed."
        )
    else:
        text = (
            "<strong>Every attack that succeeded was recorded.</strong> The boundary did not hold everywhere, "
            "but nothing got through unwitnessed."
        )
    return f'<p class="callout ok">{text}</p>'


def coverage_summary(card: dict) -> str:
    """The audit page's headline: N of M attacks recorded, over the segmented bar; the containment
    reading second, since it is the phase-1 twin's number and only here so the two can be read
    together; then the attacks that SUCCEEDED and left no record — the figure to act on."""
    rec = recorded_tally(card)
    counts, total = rec["counts"], sum(rec["counts"].values())
    blocked, scored = tally(card)
    pct = round(100 * rec["logged"] / total) if total else 0
    pct_blocked = round(100 * blocked / scored) if scored else 0

    count_line = " &nbsp;·&nbsp; ".join(
        f'<span class="rec-glyph {"rec-" + s.lower().replace("_", "-")}">{RECORDED_GLYPH[s]}</span> '
        f"<strong>{counts[s]}</strong> {RECORDED_LABEL[s].lower()}"
        for s in COVERAGE_STATES
    )

    unseen, blind = rec["unseen"], rec["blind"]
    if not (unseen or blind):
        breach = all_witnessed_callout(blocked == scored, total - rec["logged"])
    else:
        n = len(unseen) + len(blind)
        parts = []
        if unseen:
            parts.append(
                f"<strong>{len(unseen)}</strong> crossed a sensor that wrote nothing "
                f"(<em>unseen breach</em>): <code>{esc(', '.join(unseen))}</code>"
            )
        if blind:
            parts.append(
                f"<strong>{len(blind)}</strong> happened where no sensor could see: <code>{esc(', '.join(blind))}</code>"
            )
        breach = (
            f'<p class="callout alarm"><strong>{n} attack{"s" if n != 1 else ""} succeeded and left no '
            f"record.</strong> {'; '.join(parts)}.</p>"
        )

    return f"""
<div class="meters">
  <div class="meter primary">
    <p class="score">{rec["logged"]} <small>of {total} attacks recorded</small> <span class="pct">{pct}%</span></p>
    {coverage_bar(counts)}
    <p class="counts">{count_line}</p>
  </div>
  <div class="meter secondary">
    <p class="score">{blocked} <small>of {scored} attacks blocked</small> <span class="pct">{pct_blocked}%</span></p>
    <span class="bar"><span style="width:{pct_blocked}%"></span></span>
    <p class="note">The containment reading — the same suite behind the same boundary as the phase-1
    twin. It answers <em>did it hold</em>; the meter above answers <em>would you know</em>.</p>
  </div>
</div>
{breach}"""


def coverage_grid(card: dict) -> str:
    """Containment × record, as a 2×2 of attack names. The two axes are independent, and every attack
    lands in exactly one cell; the bottom-right cell — SUCCEEDED, no record — is the one an operator
    would most want to see and would never get. INFO rows have no verdict and are not in the grid."""
    cells: dict[tuple[str, bool], list[str]] = {(v, r): [] for v in (BLOCKED, SUCCEEDED) for r in (True, False)}
    for f in scored_findings(card):
        cells[(verdict_of(f), recorded_of(f) == LOGGED)].append(f["name"])

    def cell(verdict: str, recorded: bool, caption: str) -> str:
        names = cells[(verdict, recorded)]
        cls = f"q {css_class(verdict)} {'q-rec' if recorded else 'q-unrec'}"
        listed = f'<span class="names">{esc(", ".join(names))}</span>' if names else '<span class="names">—</span>'
        return f'<td class="{cls}"><span class="n">{len(names)}</span><span class="cap">{caption}</span>{listed}</td>'

    return f"""
<h2>Containment × record — the two questions, crossed</h2>
<p class="note">Rows are the verdict, columns are the record. Every scored attack sits in exactly one cell.</p>
<table class="grid"><thead><tr><th></th>
  <th><span class="rec-glyph rec-logged">{RECORDED_GLYPH[LOGGED]}</span> recorded</th>
  <th><span class="rec-glyph rec-not-logged">{RECORDED_GLYPH[NOT_LOGGED]}</span>
      <span class="rec-glyph rec-no-sensor">{RECORDED_GLYPH[NO_SENSOR]}</span> not recorded</th></tr></thead>
<tbody>
<tr><th class="verdict blocked-h">BLOCKED</th>
  {cell(BLOCKED, True, "held, and you would know")}
  {cell(BLOCKED, False, "held silently — the attempt goes unnoticed")}</tr>
<tr><th class="verdict succeeded-h">SUCCEEDED</th>
  {cell(SUCCEEDED, True, "got through, but the record shows it")}
  {cell(SUCCEEDED, False, "got through unwitnessed — the cell to act on")}</tr>
</tbody></table>"""


CSS = """
:root { color-scheme: light dark;
  --bg:#fff; --fg:#1a1a1a; --dim:#666; --line:#e3e3e3; --card:#fafafa;
  --ok:#0a7d3f; --okbg:#e8f5ee; --bad:#b3261e; --badbg:#fdeceb; --accent:#4338ca; --teal:#0f766e; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#14161a; --fg:#e8e8ea; --dim:#9a9aa2; --line:#2a2d34; --card:#1b1e24;
  --ok:#4ade80; --okbg:#12301f; --bad:#f87171; --badbg:#33191a; --accent:#a5b4fc; --teal:#5eead4; } }
:root[data-theme="dark"] {
  --bg:#14161a; --fg:#e8e8ea; --dim:#9a9aa2; --line:#2a2d34; --card:#1b1e24;
  --ok:#4ade80; --okbg:#12301f; --bad:#f87171; --badbg:#33191a; --accent:#a5b4fc; --teal:#5eead4; }
:root[data-theme="light"] {
  --bg:#fff; --fg:#1a1a1a; --dim:#666; --line:#e3e3e3; --card:#fafafa;
  --ok:#0a7d3f; --okbg:#e8f5ee; --bad:#b3261e; --badbg:#fdeceb; --accent:#4338ca; --teal:#0f766e; }
* { box-sizing:border-box; }
body { margin:0; padding:2rem 1.25rem 4rem; background:var(--bg); color:var(--fg);
  font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif; }
.wrap { max-width:960px; margin:0 auto; }
h1 { font-size:1.55rem; margin:0 0 .2rem; }
h2 { font-size:.78rem; text-transform:uppercase; letter-spacing:.07em; color:var(--dim);
     margin:1.8rem 0 .35rem; font-weight:600; }
.sub { color:var(--dim); margin:0 0 1.2rem; font-size:.9rem; }
.note { color:var(--dim); font-size:.86rem; }
.score { font-size:1.5rem; font-weight:700; margin:.2rem 0 .1rem; }
.score small { font-size:.85rem; font-weight:400; color:var(--dim); }
.bar { display:block; width:100%; max-width:320px; height:8px; border-radius:5px;
  background:var(--badbg); overflow:hidden; margin:.35rem 0 1rem; }
.bar span { display:block; height:100%; background:var(--ok); }
.legend { display:flex; gap:1.25rem; flex-wrap:wrap; font-size:.84rem; color:var(--dim); margin:.6rem 0 0; }
table { border-collapse:collapse; width:100%; font-size:.88rem; }
td { text-align:left; padding:.42rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
.num { color:var(--dim); width:1.4rem; font-size:.78rem; }
.probe { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.83rem;
  font-weight:600; white-space:nowrap; min-width:13rem; }
.why { display:block; font-family:inherit; font-size:.78rem; font-weight:400; color:var(--dim);
  white-space:normal; max-width:30rem; }
.value { font-family:ui-monospace,monospace; font-size:.82rem; word-break:break-word; min-width:5.5rem; max-width:14rem; }
.detail { color:var(--dim); font-size:.82rem; }
.verdict { text-align:right; font-size:.72rem; letter-spacing:.05em; font-weight:700; white-space:nowrap; }
tr.blocked .verdict { color:var(--ok); }
tr.succeeded .verdict { color:var(--bad); }
tr.info .verdict { color:var(--dim); font-weight:400; }
tr.blocked td { background:var(--okbg); }
tr.succeeded td { background:var(--badbg); }
.meta { display:grid; grid-template-columns:auto 1fr; gap:.1rem .8rem; margin:.6rem 0 0;
  font-size:.8rem; color:var(--dim); background:var(--card); border:1px solid var(--line);
  border-radius:8px; padding:.7rem .9rem; }
.meta dt { font-family:ui-monospace,monospace; }
.meta dd { margin:0; }
.warn { background:var(--badbg); border-left:3px solid var(--bad); padding:.6rem .8rem;
  border-radius:0 6px 6px 0; font-size:.86rem; margin:.8rem 0; }
a { color:var(--accent); }
code { font-size:.85em; }
table.recorded td { vertical-align:middle; }
.rec-glyph { font-size:1rem; text-align:center; width:1.6rem; color:var(--dim); }
.rec-label { font-size:.8rem; letter-spacing:.03em; color:var(--dim); white-space:nowrap; }
.rec-glyph.rec-logged, .rec-glyph.rec-not-logged { color:var(--teal); }
.rec-label.rec-logged { color:var(--teal); font-weight:600; }
.rec-glyph.rec-no-sensor { color:var(--dim); }
tr.rec-no-sensor td { background:var(--card); }
.rec-badge { display:block; width:max-content; margin-top:.15rem; padding:.05rem .4rem; border-radius:4px;
  border:1px solid var(--bad); color:var(--bad); font-size:.68rem; font-weight:700; letter-spacing:.04em;
  text-transform:uppercase; }
tr.rec-alarm td { background:var(--badbg); }
.rec-label.rec-alarm { color:var(--bad); font-weight:700; }
/* the audit page: two meters, the recorded one first */
.meters { display:grid; grid-template-columns:minmax(0,3fr) minmax(0,2fr); gap:1rem 2rem; align-items:start;
  margin:.4rem 0 .2rem; }
@media (max-width:640px) { .meters { grid-template-columns:1fr; } }
.meter .score { margin:0 0 .1rem; }
.meter.secondary .score { font-size:1.1rem; }
.meter .bar { max-width:none; height:11px; margin:.35rem 0 .5rem; }
.meter.secondary .bar { height:8px; }
.pct { font-size:.85rem; font-weight:600; color:var(--dim); margin-left:.4rem; }
.counts { font-size:.84rem; color:var(--dim); margin:0; }
.counts .rec-glyph { width:auto; }
/* the three segments echo the three glyphs: filled teal (●), hollow teal (○), flat grey (▬).
   Selectors carry `.seg-bar` so they outrank the generic `.bar span` fill above. */
.seg-bar { display:flex; background:var(--line); }
.seg-bar .seg { display:block; height:100%; }
.seg-bar .seg-logged { background:var(--teal); }
.seg-bar .seg-not-logged { background:var(--bg); box-shadow:inset 0 0 0 2px var(--teal); border-radius:2px; }
.seg-bar .seg-no-sensor { background:var(--dim); opacity:.5; }
.callout { border-left:3px solid var(--dim); padding:.6rem .8rem; border-radius:0 6px 6px 0;
  font-size:.88rem; margin:1rem 0 .4rem; background:var(--card); }
.callout.alarm { border-color:var(--bad); background:var(--badbg); }
.callout.ok { border-color:var(--teal); }
table.grid { table-layout:fixed; margin-top:.4rem; }
table.grid th { font-size:.74rem; text-transform:uppercase; letter-spacing:.05em; color:var(--dim);
  padding:.42rem .6rem; border-bottom:1px solid var(--line); text-align:left; }
table.grid th.verdict { text-align:left; width:6.5rem; font-size:.72rem; }
table.grid th.blocked-h { color:var(--ok); }
table.grid th.succeeded-h { color:var(--bad); }
table.grid th .rec-glyph { width:auto; }
table.grid td.q { padding:.6rem .8rem .7rem; vertical-align:top; }
table.grid td.q .n { display:block; font-size:1.5rem; font-weight:700; line-height:1.1; }
table.grid td.q .cap { display:block; font-size:.78rem; color:var(--dim); margin:.15rem 0 .35rem; }
table.grid td.q .names { display:block; font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
  font-size:.74rem; line-height:1.5; word-break:break-word; }
table.grid td.blocked.q-rec { background:var(--okbg); }
table.grid td.blocked.q-rec .n { color:var(--ok); }
table.grid td.blocked.q-unrec { background:var(--card); }
table.grid td.succeeded.q-rec .n { color:var(--bad); }
table.grid td.succeeded.q-unrec { background:var(--badbg); }
table.grid td.succeeded.q-unrec .n, table.grid td.succeeded.q-unrec .cap { color:var(--bad); }
"""


def render_html(card: dict) -> str:
    audit = is_audit(card)
    blocked, scored = tally(card)
    pct = round(100 * blocked / scored) if scored else 0
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")

    dur = fmt_dur(card.get("duration_s"))
    duration_line = f'<p class="note">Lesson run time: <strong>{esc(dur)}</strong>.</p>' if dur else ""

    warn = ""
    if not card.get("complete", True):
        warn = (
            '<p class="warn"><strong>Partial run.</strong> The sandbox did not survive the whole '
            f"suite (exit {esc(card.get('runtime_exit_code', '?'))}). A box that attack 7 "
            "(<code>resource_exhaustion</code>) takes down mid-suite is itself a finding — see "
            "ATTACKS.md; the rows after it carry what was captured before it died.</p>"
        )

    if audit:
        headline = coverage_summary(card)
        legend_rec = f'<span class="rec-legend">{recorded_legend()}</span>'
        body = coverage_grid(card) + probe_tables(card, recorded_column=True)
        title_kind = "audit"
    else:
        headline = (
            f'<p class="score">{blocked} <small>of {scored} attacks blocked</small></p>'
            f'<span class="bar"><span style="width:{pct}%"></span></span>'
        )
        legend_rec = ""
        body = probe_tables(card) + recorded_band(card)
        title_kind = "scorecard"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(short(card["lesson"]))} — {title_kind}</title>
<style>{CSS}</style></head>
<body><div class="wrap">

<h1>{esc(short(card["lesson"]))}</h1>
<p class="sub">{esc(card.get("boundary", ""))}<br>
Generated {esc(stamp)}. What each probe means, and why it matters:
<a href="../../../../ATTACKS.md">ATTACKS.md</a>.<br>
This page covers <strong>this lesson only</strong>. To compare rungs, build the overall report:
<code>python3 infra/report/overall.py</code>.</p>

{headline}
{duration_line}
{warn}
<div class="legend">
  <span><strong style="color:var(--ok)">BLOCKED</strong> the boundary stopped the attack</span>
  <span><strong style="color:var(--bad)">SUCCEEDED</strong> the attack got what it wanted</span>
  <span><strong>INFO</strong> measured, not scored</span>
  {legend_rec}
</div>
<dl class="meta">{meta_rows(card)}</dl>

{body}
</div></body></html>
"""


def render_one(lesson: str) -> Path | None:
    card = load_card(lesson)
    if card is None:
        return None
    # The leaf directory the dotted id resolves to. lesson_relpath's Python twin: exactly one match,
    # same contract as infra/run.sh — zero or many is a broken tree, not a pick.
    folder = ids.leaf_for_id(lesson)
    if folder is None:
        print(f"  skipping {lesson}: no single leaf for id {lesson}", file=sys.stderr)
        return None
    (folder / "report.json").write_text(json.dumps(build_json(card), indent=2) + "\n", encoding="utf-8")
    out = folder / "report.html"
    out.write_text(render_html(card), encoding="utf-8")
    return out


def main() -> None:
    args = sys.argv[1:]
    do_open = "--open" in args
    wanted = [a for a in args if not a.startswith("--")]
    if not wanted:
        wanted = [lid for lid, _ in ids.iter_leaves()]

    written: list[Path] = []
    for lesson in wanted:
        out = render_one(lesson)
        if out is not None:
            written.append(out)
            print(f"  {out.relative_to(REPO_ROOT)}  +  {out.with_suffix('.json').name}")

    if not written:
        print("  nothing to render — no scorecard in results/ for those lessons yet")
    elif do_open:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.run([opener, str(written[-1])], check=False)


if __name__ == "__main__":
    main()
