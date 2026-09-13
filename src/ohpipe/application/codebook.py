"""Das Codebuch des Profils: streng laden, Reihenfolge und Eingabebytes erhalten."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = ["load_codebook"]

_FIELDS = frozenset({"id", "label", "definition", "include", "exclude", "examples"})
_ID = re.compile(r"[A-Z][A-Z0-9_]{1,31}\Z")
_HEAD = frozenset({"schema", "corpus", "version", "language", "created", "source_artifacts"})


@dataclass(frozen=True)
class Codebook:
    categories: tuple[dict[str, Any], ...]
    ids: frozenset[str]
    prompt_text: str
    raw: bytes


def load_codebook(path: Path) -> Codebook:
    """Ein Halt nennt Datei und Strukturfehler, niemals Beispiele oder Definitionen."""
    path = Path(path)

    def fail(reason: str) -> None:
        raise ValueError(f"{path}: {reason}. Kein Teilergebnis, nichts geschrieben.")

    try:
        raw = path.read_bytes()
        obj = tomllib.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as exc:
        fail(f"Codebuch fehlt oder ist kein gültiges UTF-8-TOML ({type(exc).__name__})")

    if obj.get("schema") != "ohpipe.l1.codebook.v1":
        fail("schema muss ohpipe.l1.codebook.v1 sein")
    if set(obj) != _HEAD | {"rules", "category"}:
        if not obj.get("category"):
            fail("keine einzige [[category]]")
        fail("Kopfschlüssel, rules oder category fehlen oder sind unbekannt")
    for key in _HEAD - {"source_artifacts"}:
        if not isinstance(obj[key], str) or not obj[key].strip():
            fail(f"Kopffeld {key} muss eine nichtleere Zeichenkette sein")

    def strings(value: Any) -> bool:
        return isinstance(value, list) and all(
            isinstance(item, str) and item.strip() for item in value
        )

    if not strings(obj["source_artifacts"]):
        fail("source_artifacts muss eine Liste nichtleerer Zeichenketten sein")
    rules = obj["rules"]
    if not isinstance(rules, dict) or set(rules) != {"priority"}:
        fail("rules muss genau priority tragen")
    if not strings(rules["priority"]):
        fail("rules.priority muss eine Liste nichtleerer Zeichenketten sein")
    categories = obj["category"]
    if not isinstance(categories, list) or not categories:
        fail("keine einzige [[category]]")
    ids: set[str] = set()
    for n, category in enumerate(categories, start=1):
        if not isinstance(category, dict) or set(category) != _FIELDS:
            missing = sorted(_FIELDS - set(category)) if isinstance(category, dict) else []
            fail(f"Kategorie {n}: Felder fehlen ({', '.join(missing)}) oder sind unbekannt")
        for key in _FIELDS - {"examples"}:
            if not isinstance(category[key], str) or not category[key].strip():
                fail(f"Kategorie {n}: Feld {key} fehlt, ist leer oder keine Zeichenkette")
        if not strings(category["examples"]) or not category["examples"]:
            fail(f"Kategorie {n}: examples muss eine nichtleere Liste von Zeichenketten sein")
        cid = category["id"]
        if not _ID.fullmatch(cid):
            fail(f"Kategorie {n}: ID entspricht nicht ^[A-Z][A-Z0-9_]{{1,31}}$")
        if cid in ids:
            fail(f"ID {cid} doppelt")
        ids.add(cid)
    if "UNGEKLAERT" not in ids:
        fail("ID UNGEKLAERT fehlt")

    # TOML-Mehrzeiler dürfen die erste Leerzeile des Prompts nicht vorziehen.
    def line(value: str) -> str:
        return " ".join(value.split())

    lines = ["Codebuch:"]
    for category in categories:
        lines.extend(
            (
                f"{category['id']}: {line(category['label'])}",
                f"Definition: {line(category['definition'])}",
                f"Einschluss: {line(category['include'])}",
                f"Ausschluss: {line(category['exclude'])}",
            )
        )
    lines.append("Vorrangregeln:")
    lines.extend(f"{n}. {line(rule)}" for n, rule in enumerate(rules["priority"], start=1))
    lines.append("Liefere genau eine ID je Segment, ausschließlich aus dieser Liste.")
    return Codebook(tuple(categories), frozenset(ids), "\n".join(lines), raw)
