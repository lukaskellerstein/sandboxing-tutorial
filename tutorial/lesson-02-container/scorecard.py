"""Host-side view of a scorecard — parse, render, compare, persist.

The box (the agent image) prints one ``FINDING_JSON {...}`` line per attack as it completes, then a
final ``SCORECARD_JSON {...}`` line; this module is how the lesson, running on the host, reads them
back. It is deliberately a small, standalone copy rather than an import from another leaf: every
lesson is self-contained, so a learner can read one directory top to bottom without chasing a shared
package. The duplication across leaves is the point.

One thing it refuses to do is let a short card pass as a whole one. A sandbox can die mid-suite —
attack 7's fork bomb OOM-kills a gVisor sandbox outright — and the streamed lines mean the host
still has every reading up to that point. That is useful *only* if the lesson has to say so out
loud, so :meth:`Card.parse` reconstructs a partial card only when explicitly asked, and the result
carries ``complete = False`` from then on.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import TypedDict


class Finding(TypedDict):
    """One attack's outcome, as it crosses the wire from the box."""

    name: str
    value: object
    contained: bool | None
    group: str
    detail: str


SENTINEL = "SCORECARD_JSON"
FINDING_SENTINEL = "FINDING_JSON"

_VERDICT: dict[bool | None, str] = {True: "BLOCKED", False: "REACHED", None: "n/a"}
_VERDICT_EVIDENCE: dict[bool | None, str] = {True: "RECORDED", False: "NO RECORD", None: "n/a"}
_GROUPS = ("reach", "abuse", "kernel", "policy", "evidence", "cost")


class Card:
    """A rung's scorecard: the list of findings the box reported."""

    def __init__(self, findings: list[Finding], *, complete: bool = True) -> None:
        self.findings: list[Finding] = findings
        #: False when the box died before printing its final card — see the module docstring.
        self.complete = complete

    @classmethod
    def parse(cls, stdout: str, *, allow_partial: bool = False) -> Card:
        """Read the box's result. Prefers the final card; falls back to the streamed lines.

        ``allow_partial`` is opt-in on purpose. A lesson that expects its box to survive should fail
        loudly when it did not, rather than quietly reporting whichever attacks happened to finish
        first — that is this repo's characteristic silent failure wearing a different hat.
        """
        for line in reversed(stdout.splitlines()):
            if SENTINEL in line:
                payload = line.split(SENTINEL, 1)[1].strip()
                return cls(json.loads(payload)["findings"])

        streamed: list[Finding] = [
            json.loads(line.split(FINDING_SENTINEL, 1)[1].strip())
            for line in stdout.splitlines()
            if FINDING_SENTINEL in line
        ]
        if streamed and allow_partial:
            return cls(streamed, complete=False)

        tail = "\n".join(stdout.strip().splitlines()[-12:]) or "(no output)"
        got = f"{len(streamed)} streamed finding(s) but no final card" if streamed else "no output at all"
        raise ValueError(f"no {SENTINEL} line in the box output ({got}). Tail:\n{tail}")

    def add(self, finding: Finding) -> Card:
        """Append, or replace a finding of the same name — how the host merges in what it measured.

        Two rows can only be filled in from out here: ``evidence`` (a process cannot see the record
        kept *about* it) and any attack whose verdict is the box's own death, which is legible in the
        exit status and nowhere else.
        """
        self.findings = [f for f in self.findings if f["name"] != finding["name"]] + [finding]
        return self

    def get(self, name: str) -> Finding | None:
        return next((f for f in self.findings if f["name"] == name), None)

    def contained(self, name: str) -> bool | None:
        f = self.get(name)
        return None if f is None else f["contained"]

    def reached(self) -> list[Finding]:
        """The attacks that got through — this rung's 'what is still open', and the next lesson's reason."""
        return [f for f in self.findings if f["contained"] is False]

    def tally(self) -> tuple[int, int]:
        applicable = [f for f in self.findings if f["contained"] is not None]
        return sum(1 for f in applicable if f["contained"]), len(applicable)

    def render(self) -> str:
        if not self.findings:
            return "  (no findings)"
        width = max(len(f["name"]) for f in self.findings)
        lines: list[str] = []
        for group in _GROUPS:
            members = [f for f in self.findings if f["group"] == group]
            if not members:
                continue
            lines.append(f"  [{group}]")
            for f in members:
                verdict = (_VERDICT_EVIDENCE if group == "evidence" else _VERDICT)[f["contained"]]
                detail = f"  {f['detail']}" if f["detail"] else ""
                lines.append(f"    {f['name']:<{width}}  {str(f['value']):<26} {verdict}{detail}")
        return "\n".join(lines)

    def diff_against(self, prev: Card, prev_label: str, cur_label: str) -> str:
        """Side-by-side verdicts for the attacks both rungs measured — what this boundary changed."""
        names = [f["name"] for f in self.findings if self.contained(f["name"]) is not None]
        width = max((len(n) for n in names), default=5)
        lines = [f"  {'attack':<{width}}  {prev_label:<12}  {cur_label:<12}  changed?"]
        lines.append("  " + "-" * (width + 38))
        for name in names:
            before, after = prev.contained(name), self.contained(name)
            if before is None:
                continue
            mark = "" if before == after else "  <-- closed" if after else "  <-- OPENED"
            lines.append(f"  {name:<{width}}  {_VERDICT[before]:<12}  {_VERDICT[after]:<12}{mark}")
        return "\n".join(lines)

    def cost_delta(self, prev: Card, prev_label: str, cur_label: str) -> str:
        """The price of this boundary beside the previous one — the `cost` rows, as a ratio.

        A ratio and not a verdict: 'gVisor is slow' is false and 'gVisor is free' is false. The
        honest statement is which *kind* of work pays, and that only shows when syscall-bound and
        CPU-bound work are printed side by side.
        """
        lines = [f"  {'probe':<12}  {prev_label:>12}  {cur_label:>12}  {'ratio':>8}"]
        lines.append("  " + "-" * 48)
        for name in ("syscall_ms", "cpu_ms"):
            before, after = prev.get(name), self.get(name)
            if before is None or after is None:
                continue
            b, a = float(before["value"]), float(after["value"])  # pyright: ignore[reportArgumentType]
            ratio = f"{a / b:.2f}x" if b else "n/a"
            lines.append(f"  {name:<12}  {b:>12.1f}  {a:>12.1f}  {ratio:>8}")
        return "\n".join(lines)

    def save(self, path: Path, **meta: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {**meta, "complete": self.complete, "findings": self.findings}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> Card | None:
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(data["findings"], complete=bool(data.get("complete", True)))


def render_report(repo_root: Path) -> Path | None:
    """Regenerate the HTML report that sits next to this lesson, from the cards on disk.

    Called by every lesson right after it saves its scorecard, so running a lesson the
    self-contained way — ``cd <lesson> && uv run python main.py`` — produces the report too,
    not only ``infra/run.sh``.

    Shelling out to ``infra/report/render.py`` rather than importing it is deliberate: the
    lesson leaves are standalone uv projects that must never import one another or grow a
    shared package, and this is the same pattern the lessons already use for
    ``infra/images/agent/build.sh``.

    A failure here never fails the lesson. The scorecard is the result; the report is a view
    of it, and a missing view is not a reason to lose a measurement that cost a box to take.
    """
    script = repo_root / "infra" / "report" / "render.py"
    if not script.exists():
        return None
    # This file sits IN the lesson folder, so the folder's name is the lesson name — nothing to
    # pass in and nothing to keep in sync. Only this lesson is rendered: a lesson's report covers
    # itself alone, and comparing rungs is `infra/report/overall.py`'s job.
    lesson = Path(__file__).resolve().parent.name
    try:
        subprocess.run([sys.executable, str(script), lesson], check=False, capture_output=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        return None
    return script
