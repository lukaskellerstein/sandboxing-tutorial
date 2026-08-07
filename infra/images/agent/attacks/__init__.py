"""The attack suite — the nine attacks, the scorecard, and the script driver that runs them.

This package is baked into the agent image and run *inside the box* on every rung of the ladder.
The host (a lesson's ``main.py``) reads the ``FINDING_JSON`` line each attack prints as it finishes,
and the final ``SCORECARD_JSON`` line if the box lived long enough to print one.
"""

from .report import FINDING_SENTINEL, GROUPS, IN_BOX_GROUPS, SENTINEL, Finding, Scorecard
from .suite import run_groups

__all__ = [
    "FINDING_SENTINEL",
    "GROUPS",
    "IN_BOX_GROUPS",
    "SENTINEL",
    "Finding",
    "Scorecard",
    "run_groups",
]
