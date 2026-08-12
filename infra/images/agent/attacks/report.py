"""The scorecard: one result shape, printed as a single JSON line the host can parse.

Every attack in :mod:`attacks.suite` returns one :class:`Finding`. The suite collects them into a
:class:`Scorecard` and prints it as ``SCORECARD_JSON {...}`` on stdout — one line, sentinel-prefixed
so a stray ``print`` (or a runtime's ANSI colouring) cannot corrupt the host's parse. Everything a
human reads goes to *stderr*; stdout carries the one machine line only. That discipline is the whole
reason a lesson can run this inside a container, a gVisor sandbox, a pod, or an OpenShell box and get
back the *same* structure every time — the box changes, the scorecard shape does not.

``contained`` is the judgment, and it is deliberately three-valued:

* ``True``  — the boundary held: the attack was blocked, capped, or denied.
* ``False`` — the attack got through. On the no-sandbox rung every row is ``False``; each later rung
  flips some to ``True`` and, crucially, leaves others ``False`` — those are the next lesson's reason
  to exist.
* ``None``  — not applicable on this rung (``policy`` off a policy engine, ``kernel`` off Linux). A
  ``None`` is never counted as a pass; reporting "contained" for a probe that never ran is exactly
  the silent-green failure this tutorial exists to avoid.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import cast

#: Prefixes the single JSON result line. Chosen so an ordinary print cannot collide with it.
SENTINEL = "SCORECARD_JSON"

#: Prefixes one JSON line per finding, emitted the moment that finding is produced.
#:
#: The final ``SCORECARD_JSON`` line is the normal answer; these are what survive when the box does
#: not. A sandbox can die *during* the suite — attack 7 under gVisor kills it outright — and a
#: result that is only printed at the end is a result that is lost. Streaming makes the host's parse
#: degrade to "everything up to the attack that killed the box" instead of to nothing at all, which
#: matters most on exactly the rung whose evidence is hardest to get.
FINDING_SENTINEL = "FINDING_JSON"

#: Report order. ``evidence`` is host-side only — in-box code cannot see its own audit trail, so a
#: lesson merges the audit-record count in after reading the runtime's logs (see the lesson main.py).
GROUPS = ("reach", "abuse", "kernel", "policy", "evidence", "cost")

#: Groups the in-box program knows how to measure itself.
IN_BOX_GROUPS = ("reach", "abuse", "kernel", "policy", "cost")

#: Groups run on every rung. ``policy`` is excluded — it only means something with a policy engine
#: (OpenShell) and a gateway to allow/deny, so a lesson requests it explicitly; run elsewhere it
#: just records "no-gateway" noise. ``evidence`` is host-side (merged in by the lesson).
DEFAULT_GROUPS = ("reach", "abuse", "kernel", "cost")


@dataclass
class Finding:
    """One attack's outcome.

    ``value`` is the raw reading — an int count, an errno name, a kernel string — and it is what
    makes the scorecard *teach* rather than merely assert: ``sys_module_count`` 217 → 0 says more
    than "blocked". ``contained`` is the verdict over that reading (see the module docstring).
    """

    name: str
    value: object
    contained: bool | None = None
    group: str = "reach"
    detail: str = ""

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "value": self.value,
            "contained": self.contained,
            "group": self.group,
            "detail": self.detail,
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict())


@dataclass
class Scorecard:
    """A rung's full result — the currency every lesson reports and lesson 14 renders the table from."""

    findings: list[Finding] = field(default_factory=list)

    def __iter__(self):
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    def add(self, finding: Finding) -> Scorecard:
        """Append, or replace an existing finding of the same name (host-side merges, e.g. evidence)."""
        self.findings = [f for f in self.findings if f.name != finding.name] + [finding]
        return self

    def get(self, name: str) -> Finding | None:
        return next((f for f in self.findings if f.name == name), None)

    def to_json(self) -> str:
        return json.dumps({"findings": [f.as_dict() for f in self.findings]})

    @classmethod
    def from_json(cls, payload: str) -> Scorecard:
        data = cast("dict[str, list[dict[str, object]]]", json.loads(payload))
        out: list[Finding] = []
        for f in data["findings"]:
            contained = f["contained"]
            out.append(
                Finding(
                    name=str(f["name"]),
                    value=f["value"],
                    contained=contained if isinstance(contained, bool) else None,
                    group=str(f["group"]),
                    detail=str(f.get("detail", "")),
                )
            )
        return cls(out)
