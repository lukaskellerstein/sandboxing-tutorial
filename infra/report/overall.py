#!/usr/bin/env python3
"""Build the OVERALL report from each lesson's own ``report.json``.

    python3 infra/report/overall.py
    python3 infra/report/overall.py --open

Reads ``tutorial/lesson-*/report.json`` — the files ``render.py`` writes next to each lesson — and
produces ``results/overall.html``: the ladder as a matrix, plus what changed between consecutive
rungs.

The split matters. A lesson's own report is finished the moment that lesson finishes and never
changes afterwards; this one is a *view across* lessons and is rebuilt whenever you want it. That
is also why this reads the per-lesson JSON rather than ``results/*.json``: a lesson that has never
been rendered has no report to aggregate, which is the honest answer, rather than a card silently
appearing in a comparison whose page nobody has seen.

It refuses to compare rungs measured on different hosts without saying so. With one disposable box
per lesson that is a real risk — run a lesson on your laptop and its card is a laptop card, so a
row that "changed" may be the hardware rather than the boundary.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TUTORIAL = REPO_ROOT / "tutorial"
OUT = REPO_ROOT / "results" / "overall.html"

BLOCKED, SUCCEEDED, INFO = "BLOCKED", "SUCCEEDED", "INFO"
CLS = {BLOCKED: "blocked", SUCCEEDED: "succeeded", INFO: "info"}


def esc(value: object) -> str:
    import html

    return html.escape(str(value))


def short(lesson: str) -> str:
    parts = lesson.split("-", 2)
    return f"{parts[1]} {parts[2]}" if len(parts) > 2 else lesson


def load_reports() -> list[dict]:
    reports = []
    # `lesson-*`, NOT `lesson-0*`. The narrower glob silently dropped every lesson from 10 up:
    # the page rendered fine and simply omitted chapter 4, which is the worst kind of quiet.
    for folder in sorted(TUTORIAL.glob("lesson-*")):
        path = folder / "report.json"
        if not path.exists():
            continue
        try:
            reports.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"  skipping {path.relative_to(REPO_ROOT)}: {exc}", file=sys.stderr)
    return reports


def matrix(reports: list[dict]) -> str:
    order: list[str] = []
    for r in reports:
        for f in r["findings"]:
            if f["verdict"] != INFO and f["name"] not in order:
                order.append(f["name"])

    head = "".join(f"<th>{esc(short(r['lesson']))}</th>" for r in reports)
    rows = []
    for name in order:
        cells, why, num = [], "", ""
        for r in reports:
            found = next((f for f in r["findings"] if f["name"] == name), None)
            if found is None or found["verdict"] == INFO:
                cells.append('<td class="info">·</td>')
            else:
                why, num = found["why"], found["attack"]
                cells.append(
                    f'<td class="{CLS[found["verdict"]]}" title="{esc(found["value"])}">{found["verdict"]}</td>'
                )
        rows.append(
            f'<tr><td class="num">{esc(num)}</td>'
            f'<th class="probe">{esc(name)}<span class="why">{esc(why)}</span></th>'
            f"{''.join(cells)}</tr>"
        )
    totals = "".join(f'<td class="total">{r["blocked"]}/{r["scored"]}</td>' for r in reports)
    return f"""
<div class="scroll"><table class="matrix">
  <thead><tr><th></th><th>probe</th>{head}</tr></thead>
  <tbody>{"".join(rows)}</tbody>
  <tfoot><tr><td></td><th>attacks blocked</th>{totals}</tr></tfoot>
</table></div>"""


def diffs(reports: list[dict]) -> str:
    blocks = []
    for prev, cur in zip(reports, reports[1:], strict=False):
        before = {f["name"]: f for f in prev["findings"]}
        closed, opened, stuck = [], [], []
        for f in cur["findings"]:
            was = before.get(f["name"])
            if was is None or INFO in (was["verdict"], f["verdict"]):
                continue
            pair = (f["name"], f["why"], was["value"], f["value"])
            if was["verdict"] == SUCCEEDED and f["verdict"] == BLOCKED:
                closed.append(pair)
            elif was["verdict"] == BLOCKED and f["verdict"] == SUCCEEDED:
                opened.append(pair)
            elif f["verdict"] == SUCCEEDED:
                stuck.append(pair)

        # Different hosts make a diff ambiguous — a changed row could be the hardware. Both causes
        # are named because they need opposite responses: an accidental mismatch (a lesson run on a
        # laptop) is fixed by re-running, while lesson 5's is architectural — it runs inside the
        # NAT'd guest its gateway requires, so it will never match and re-running would not help.
        warn = ""
        a, b = prev["host"].get("node_kernel"), cur["host"].get("node_kernel")
        if a and b and a != b:
            warn = (
                f'<p class="warn">These two rungs ran on <strong>different kernels</strong> '
                f"({esc(a)} vs {esc(b)}), so a row that changed here may be the machine rather than "
                "the boundary. Expected when a rung runs inside a nested guest (lesson 5); a "
                "mistake if one of them was run somewhere other than its own box — re-run it if so.</p>"
            )

        def rows(items: list[tuple], cls: str, label: str) -> str:
            return "".join(
                f'<tr class="{cls}"><td class="tag">{label}</td>'
                f'<td class="probe">{esc(n)}<span class="why">{esc(w)}</span></td>'
                f'<td class="value">{esc(x)}</td><td class="arrow">→</td><td class="value">{esc(y)}</td></tr>'
                for n, w, x, y in items
            )

        body = rows(closed, "blocked", "NOW BLOCKED") + rows(opened, "succeeded", "RE-OPENED")
        body += rows(stuck, "succeeded", "STILL OPEN")
        table = (
            f'<div class="scroll"><table class="changes"><tbody>{body}</tbody></table></div>'
            if body
            else '<p class="note">No scored row changed.</p>'
        )
        blocks.append(f"<h3>{esc(short(prev['lesson']))} &rarr; {esc(short(cur['lesson']))}</h3>{warn}{table}")
    return "".join(blocks) or '<p class="note">Only one lesson has a report — nothing to compare yet.</p>'


CSS = """
:root { color-scheme: light dark;
  --bg:#fff; --fg:#1a1a1a; --dim:#666; --line:#e3e3e3; --card:#fafafa;
  --ok:#0a7d3f; --okbg:#e8f5ee; --bad:#b3261e; --badbg:#fdeceb; --accent:#4338ca; }
@media (prefers-color-scheme: dark) { :root {
  --bg:#14161a; --fg:#e8e8ea; --dim:#9a9aa2; --line:#2a2d34; --card:#1b1e24;
  --ok:#4ade80; --okbg:#12301f; --bad:#f87171; --badbg:#33191a; --accent:#a5b4fc; } }
:root[data-theme="dark"] {
  --bg:#14161a; --fg:#e8e8ea; --dim:#9a9aa2; --line:#2a2d34; --card:#1b1e24;
  --ok:#4ade80; --okbg:#12301f; --bad:#f87171; --badbg:#33191a; --accent:#a5b4fc; }
:root[data-theme="light"] {
  --bg:#fff; --fg:#1a1a1a; --dim:#666; --line:#e3e3e3; --card:#fafafa;
  --ok:#0a7d3f; --okbg:#e8f5ee; --bad:#b3261e; --badbg:#fdeceb; --accent:#4338ca; }
* { box-sizing:border-box; }
body { margin:0; padding:2rem 1.25rem 4rem; background:var(--bg); color:var(--fg);
  font:15px/1.6 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif; }
.wrap { max-width:1100px; margin:0 auto; }
h1 { font-size:1.6rem; margin:0 0 .25rem; }
h2 { font-size:1.15rem; margin:2.5rem 0 .75rem; padding-bottom:.35rem; border-bottom:2px solid var(--line); }
h3 { font-size:.95rem; margin:1.6rem 0 .4rem; }
.sub { color:var(--dim); margin:0 0 1.5rem; font-size:.9rem; }
.note { color:var(--dim); font-size:.86rem; }
.scroll { overflow-x:auto; -webkit-overflow-scrolling:touch; }
table { border-collapse:collapse; width:100%; font-size:.88rem; }
th, td { text-align:left; padding:.42rem .6rem; border-bottom:1px solid var(--line); vertical-align:top; }
.matrix thead th { font-size:.76rem; color:var(--dim); font-weight:600; white-space:nowrap; }
.num { color:var(--dim); width:1.4rem; font-size:.78rem; }
.probe { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:.83rem;
  font-weight:600; white-space:nowrap; }
.why { display:block; font-family:inherit; font-size:.78rem; font-weight:400; color:var(--dim);
  white-space:normal; max-width:30rem; }
td.blocked, td.succeeded, td.info { text-align:center; font-size:.65rem; font-weight:700;
  letter-spacing:.03em; white-space:nowrap; }
td.blocked { color:var(--ok); background:var(--okbg); }
td.succeeded { color:var(--bad); background:var(--badbg); }
td.info { color:var(--dim); }
.matrix tfoot td.total { text-align:center; font-weight:700; }
.matrix tfoot th, .matrix tfoot td { border-top:2px solid var(--line); border-bottom:none; }
.changes .tag { font-size:.68rem; letter-spacing:.05em; font-weight:700; white-space:nowrap; width:7rem; }
.changes tr.blocked .tag { color:var(--ok); }
.changes tr.succeeded .tag { color:var(--bad); }
.changes .arrow { color:var(--dim); text-align:center; width:1.5rem; }
.value { font-family:ui-monospace,monospace; font-size:.82rem; word-break:break-word; max-width:14rem; }
.warn { background:var(--badbg); border-left:3px solid var(--bad); padding:.6rem .8rem;
  border-radius:0 6px 6px 0; font-size:.86rem; margin:.5rem 0; }
a { color:var(--accent); }
"""


def render(reports: list[dict]) -> str:
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    listed = ", ".join(short(r["lesson"]) for r in reports) or "none"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sandboxing tutorial — overall</title>
<style>{CSS}</style></head>
<body><div class="wrap">
<h1>Sandboxing tutorial — overall</h1>
<p class="sub">Generated {esc(stamp)} from <code>tutorial/lesson-*/report.json</code>.
Included: {esc(listed)}.<br>
A <em>low</em> score is correct for lesson 1 — it is the no-sandbox baseline, and the attacks
succeeding there are what everything else is measured against.
Each probe is explained in <code>ATTACKS.md</code>.</p>

<h2>The ladder — with the network a real agent needs</h2>
<p class="note"><strong>BLOCKED</strong> = the boundary stopped the attack.
<strong>SUCCEEDED</strong> = the attack got what it wanted. Hover a cell for the raw reading.<br>
Every rung is measured with the network on, because that is the only configuration that describes
a deployment anyone ships: an agent that cannot reach a model API is not an agent. Read the network
rows across the row — the container, gVisor and Kata all leave them open, because none of the three
reads HTTP, and a stronger <em>kernel</em> boundary buys nothing on that axis. Only lesson 5 closes
them, with the network still on.</p>
{matrix(reports)}
<h2>What changed, rung by rung</h2>
<p class="note">The rows that stay open are the reason the next lesson exists.</p>
{diffs(reports)}

</div></body></html>
"""


def main() -> None:
    reports = load_reports()
    if not reports:
        print("  no tutorial/lesson-*/report.json yet — run a lesson first")
        return
    # A card written before the two-mode split carries no `mode`, so it cannot be placed in either
    # matrix and would simply not appear — a report that quietly drops a rung reads as "that rung
    # was fine". Say so instead; the fix is to re-run that lesson.
    for r in reports:
        if not r.get("mode"):
            print(f"  WARNING: {r['lesson']} has no mode — stale card, omitted from both ladders. Re-run it.")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(reports), encoding="utf-8")
    print(f"  {OUT.relative_to(REPO_ROOT)}  ({len(reports)} lesson{'' if len(reports) == 1 else 's'})")
    if "--open" in sys.argv[1:]:
        opener = "open" if sys.platform == "darwin" else "xdg-open"
        subprocess.run([opener, str(OUT)], check=False)


if __name__ == "__main__":
    main()
