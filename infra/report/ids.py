"""Deriving a lesson's dotted id (``P.C.L``) from where its leaf sits in the tree.

The tree is the single source of truth for the id↔path mapping: the id is COMPUTED from the three
folder number prefixes (``phaseP-*`` / ``chapter-C-*`` / ``lesson-LL-*``), never stored a second
time. This is the Python twin of ``lib.sh``'s ``lesson_relpath`` / ``lesson_id_of_dir`` — both
``render.py`` and ``overall.py`` import it so there is one implementation, not three.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TUTORIAL = REPO_ROOT / "tutorial"


def _num(prefix: str, name: str) -> str:
    """The leading number after ``prefix`` in a folder name: ``chapter-2-one-host`` → ``2``."""
    rest = name[len(prefix) :] if name.startswith(prefix) else name
    return rest.split("-", 1)[0]


def id_of_leaf(leaf: Path) -> str:
    """``tutorial/phase1-attacks/chapter-2-one-host/lesson-02-container-gvisor`` → ``1.2.2``."""
    phase = _num("phase", leaf.parent.parent.name)
    chapter = _num("chapter-", leaf.parent.name)
    lesson = str(int(_num("lesson-", leaf.name)))  # drop the zero pad
    return f"{phase}.{chapter}.{lesson}"


def id_sort_key(lesson_id: str) -> tuple[int, int, int]:
    phase, chapter, lesson = lesson_id.split(".")
    return int(phase), int(chapter), int(lesson)


def iter_leaves() -> list[tuple[str, Path]]:
    """Every leaf as ``(id, path)``, ordered by ``(phase, chapter, lesson)``."""
    leaves = [(id_of_leaf(d), d) for d in TUTORIAL.glob("phase*-*/chapter-*-*/lesson-*-*") if d.is_dir()]
    return sorted(leaves, key=lambda t: id_sort_key(t[0]))


def leaf_for_id(lesson_id: str) -> Path | None:
    """The leaf path for a dotted id, or ``None`` if the tree has zero or many matches."""
    matches = [d for lid, d in iter_leaves() if lid == lesson_id]
    return matches[0] if len(matches) == 1 else None


def short(lesson_id: str, leaf: Path | None = None) -> str:
    """A compact label — the id plus the leaf's descriptive suffix: ``1.2.2 container-gvisor``."""
    if leaf is None:
        leaf = leaf_for_id(lesson_id)
    if leaf is None:
        return lesson_id
    parts = leaf.name.split("-", 2)  # lesson-02-container-gvisor -> [lesson, 02, container-gvisor]
    return f"{lesson_id} {parts[2]}" if len(parts) > 2 else lesson_id
