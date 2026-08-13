#!/usr/bin/env python3
"""Render ONE lesson's scorecard into ``report.html`` + ``report.json`` in that lesson's folder.

    python3 infra/report/render.py lesson-03-container-gvisor
    python3 infra/report/render.py --open lesson-02-container
    python3 infra/report/render.py                 # every lesson that has a scorecard

Each page describes **only its own lesson**. It never reads another lesson's card, so a lesson's
report is complete the moment that lesson finishes and can never go stale because a later lesson
ran. Comparing rungs is the job of ``infra/report/overall.py``, which reads the ``report.json``
files these produce.

``report.json`` is the machine-readable twin of the page: the same findings, plus the verdict
vocabulary and a count, so the aggregator never has to re-derive "what counts as scored".

Wording: an attack is **BLOCKED** (the boundary stopped it) or it **SUCCEEDED** (it got what it
wanted). Rows that only measure something are **INFO** and are never scored.

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
}

GROUP_LABEL = {
    "reach": "Reach — get to something valuable",
    "abuse": "Abuse — do damage with it",
    "kernel": "Kernel — how much of the real kernel is exposed",
    "policy": "Policy — which binary, which method (OpenShell only)",
    "evidence": "Evidence — was any of it written down",
    "cost": "Cost — what the boundary charges",
}

BLOCKED, SUCCEEDED, INFO = "BLOCKED", "SUCCEEDED", "INFO"


def verdict_of(finding: dict) -> str:
    contained = finding.get("contained")
    if contained is None:
        return INFO
    return BLOCKED if contained else SUCCEEDED


def css_class(verdict: str) -> str:
    return {BLOCKED: "blocked", SUCCEEDED: "succeeded", INFO: "info"}[verdict]


def tally(card: dict) -> tuple[int, int]:
    scored = [f for f in card["findings"] if f.get("contained") is not None]
    return sum(1 for f in scored if f["contained"]), len(scored)


def short(lesson: str) -> str:
    """`lesson-03-container-gvisor` -> `03 container-gvisor`."""
    parts = lesson.split("-", 2)
    return f"{parts[1]} {parts[2]}" if len(parts) > 2 else lesson


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


def load_card(lesson: str) -> dict | None:
    """A lesson's scorecard, by lesson name. `lesson-03-container-gvisor` -> results/lesson-03.json."""
    number = lesson.split("-")[1]
    path = RESULTS / f"lesson-{number}.json"
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
        # Everything the lesson recorded about the machine, kept verbatim. `overall.py` uses it to
        # warn when two rungs were measured on different hosts — a comparison this repo treats as
        # invalid, because then a changed row could be the hardware rather than the boundary.
        "host": {
            k: primary[k] for k in ("engine", "node_kernel", "openshell_version", "runtime_exit_code") if k in primary
        },
        "findings": [
            {
                "name": f["name"],
                "attack": WHY.get(f["name"], ("?", ""))[0],
                "why": WHY.get(f["name"], ("", ""))[1],
                "group": f.get("group", "other"),
                "value": f.get("value"),
                "detail": f.get("detail", ""),
                "verdict": verdict_of(f),
            }
            for f in primary["findings"]
        ],
    }


# --- the page ----------------------------------------------------------------


def probe_tables(card: dict) -> str:
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
            rows.append(
                f'<tr class="{css_class(v)}"><td class="num">{esc(num)}</td>'
                f'<td class="probe">{esc(f["name"])}<span class="why">{esc(why)}</span></td>'
                f'<td class="value">{esc(f.get("value"))}</td>'
                f'<td class="detail">{esc(f.get("detail", ""))}</td>'
                f'<td class="verdict">{v}</td></tr>'
            )
        blocks.append(f"<h2>{esc(label)}</h2><table><tbody>{''.join(rows)}</tbody></table>")
    return "".join(blocks)


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
  font-weight:600; white-space:nowrap; }
.why { display:block; font-family:inherit; font-size:.78rem; font-weight:400; color:var(--dim);
  white-space:normal; max-width:30rem; }
.value { font-family:ui-monospace,monospace; font-size:.82rem; word-break:break-word; max-width:14rem; }
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
"""


def render_html(card: dict) -> str:
    blocked, scored = tally(card)
    pct = round(100 * blocked / scored) if scored else 0
    stamp = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M %Z")

    meta = []
    for key in ("engine", "node_kernel", "openshell_version", "runtime_exit_code"):
        if key in card:
            meta.append(f"<dt>{esc(key)}</dt><dd>{esc(card[key])}</dd>")
    for key in ("vm_evidence", "guest_sysctls"):
        for k, v in (card.get(key) or {}).items():
            meta.append(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>")

    dur = fmt_dur(card.get("duration_s"))
    duration_line = f'<p class="note">Lesson run time: <strong>{esc(dur)}</strong>.</p>' if dur else ""

    warn = ""
    if not card.get("complete", True):
        warn = (
            '<p class="warn"><strong>Partial run.</strong> The sandbox did not survive the whole '
            f"suite (exit {esc(card.get('runtime_exit_code', '?'))}). For lesson 3 that is the "
            "expected outcome and is itself a finding — see ATTACKS.md, attack 7.</p>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(short(card["lesson"]))} — scorecard</title>
<style>{CSS}</style></head>
<body><div class="wrap">

<h1>{esc(short(card["lesson"]))}</h1>
<p class="sub">{esc(card.get("boundary", ""))}<br>
Generated {esc(stamp)}. What each probe means, and why it matters:
<a href="../../../ATTACKS.md">ATTACKS.md</a>.<br>
This page covers <strong>this lesson only</strong>. To compare rungs, build the overall report:
<code>python3 infra/report/overall.py</code>.</p>

<p class="score">{blocked} <small>of {scored} attacks blocked</small></p>
<span class="bar"><span style="width:{pct}%"></span></span>
{duration_line}
{warn}
<div class="legend">
  <span><strong style="color:var(--ok)">BLOCKED</strong> the boundary stopped the attack</span>
  <span><strong style="color:var(--bad)">SUCCEEDED</strong> the attack got what it wanted</span>
  <span><strong>INFO</strong> measured, not scored</span>
</div>
<dl class="meta">{"".join(meta)}</dl>

{probe_tables(card)}
</div></body></html>
"""


def render_one(lesson: str) -> Path | None:
    card = load_card(lesson)
    if card is None:
        return None
    # The leaf lives under its chapter folder, and the tree is the only place that mapping exists.
    # Exactly one match, same contract as infra/run.sh: zero or many is a broken tree, not a pick.
    folders = [p for p in TUTORIAL.glob(f"*/{lesson}") if p.is_dir()]
    if len(folders) != 1:
        print(f"  skipping {lesson}: tutorial/*/{lesson} matches {len(folders)} dirs, want 1", file=sys.stderr)
        return None
    folder = folders[0]
    (folder / "report.json").write_text(json.dumps(build_json(card), indent=2) + "\n", encoding="utf-8")
    out = folder / "report.html"
    out.write_text(render_html(card), encoding="utf-8")
    return out


def main() -> None:
    args = sys.argv[1:]
    do_open = "--open" in args
    wanted = [a for a in args if not a.startswith("--")]
    if not wanted:
        wanted = sorted(p.name for p in TUTORIAL.glob("*/lesson-*") if p.is_dir())  # not lesson-0*: ch4 is 10-13

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
