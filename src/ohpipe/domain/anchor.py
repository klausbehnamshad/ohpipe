"""Anker und Ankerdrift.

Ein Anker bindet eine Annotation an eine Stelle in einer bestimmten
Transkriptfassung. Ändert sich das Transkript, wird der Anker NICHT still
verschoben. Er bekommt ein sichtbares Ergebnis:

    exact        Zeichenoffsets stimmen noch, Zitat identisch
    unique_move  Das Zitat kommt genau einmal vor — an anderer Stelle
    ambiguous    Das Zitat kommt mehrfach vor; die Maschine entscheidet nicht
    missing      Das Zitat kommt nicht mehr vor

Nur ``exact`` und ``unique_move`` sind maschinell abschließbar. ``ambiguous``
und ``missing`` erzeugen menschliche Arbeit — das ist beabsichtigt und der
ganze Zweck dieses Moduls.

DATENSCHUTZ: ``quote`` und ``context_before/after`` enthalten Transkripttext.
Anker gehören damit in den Datenwurzel-Baum, niemals ins Repository.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .hashing import sha256_text
from .transcript import TranscriptRevision

__all__ = ["Anchor", "ReanchorOutcome", "ReanchorResult", "reanchor"]

#: Kontextfenster in Zeichen je Seite. Groß genug, um Wiederholungen zu trennen,
#: klein genug, um eine Korrektur in der Nachbarschaft zu überleben.
CONTEXT_CHARS = 64


class ReanchorOutcome(str, Enum):
    EXACT = "exact"
    UNIQUE_MOVE = "unique_move"
    AMBIGUOUS = "ambiguous"
    MISSING = "missing"

    @property
    def machine_closable(self) -> bool:
        return self in (ReanchorOutcome.EXACT, ReanchorOutcome.UNIQUE_MOVE)


@dataclass(frozen=True)
class Anchor:
    """Eine Textstelle in genau einer Transkriptfassung."""

    transcript_sha256: str
    start: int
    end: int
    quote: str
    quote_sha256: str
    context_sha256: str

    @classmethod
    def create(cls, rev: TranscriptRevision, start: int, end: int) -> Anchor:
        text = rev.normalized
        if not (0 <= start < end <= len(text)):
            raise ValueError(f"Ungültige Spanne [{start},{end}) für {len(text)} Zeichen")
        quote = text[start:end]
        before = text[max(0, start - CONTEXT_CHARS) : start]
        after = text[end : end + CONTEXT_CHARS]
        return cls(
            transcript_sha256=rev.sha256,
            start=start,
            end=end,
            quote=quote,
            quote_sha256=sha256_text(quote),
            context_sha256=sha256_text(before + "\x00" + after),
        )

    def context_at(self, text: str, start: int, end: int) -> str:
        before = text[max(0, start - CONTEXT_CHARS) : start]
        after = text[end : end + CONTEXT_CHARS]
        return sha256_text(before + "\x00" + after)

    def to_json(self) -> dict[str, Any]:
        return {
            "transcript_sha256": self.transcript_sha256,
            "start": self.start,
            "end": self.end,
            "quote_sha256": self.quote_sha256,
            "context_sha256": self.context_sha256,
        }


@dataclass(frozen=True)
class ReanchorResult:
    outcome: ReanchorOutcome
    anchor: Anchor | None
    candidates: tuple[tuple[int, int], ...] = ()
    note: str = ""

    @property
    def needs_human(self) -> bool:
        return not self.outcome.machine_closable


def _find_all(haystack: str, needle: str) -> list[int]:
    out: list[int] = []
    i = haystack.find(needle)
    while i != -1:
        out.append(i)
        i = haystack.find(needle, i + 1)
    return out


def reanchor(anchor: Anchor, rev: TranscriptRevision) -> ReanchorResult:
    """Setzt ``anchor`` auf die Fassung ``rev`` neu auf.

    Reihenfolge der Prüfungen ist Absicht:

    1. Gleiche Fassung → nichts zu tun.
    2. Offsets passen noch und das Zitat stimmt → ``exact``.
    3. Zitat kommt genau einmal vor → ``unique_move``.
    4. Mehrfach: entscheidet der Kontext eindeutig, ebenfalls ``unique_move``.
       Sonst ``ambiguous`` — die Maschine wählt NICHT.
    5. Gar nicht → ``missing``.

    Schritt 4 ist der einzige Ort, an dem der Kontext-Hash wirkt. Er darf
    Eindeutigkeit herstellen, aber niemals eine Mehrdeutigkeit überstimmen.
    """
    if anchor.transcript_sha256 == rev.sha256:
        return ReanchorResult(ReanchorOutcome.EXACT, anchor, note="gleiche Fassung")

    text = rev.normalized

    if anchor.end <= len(text) and text[anchor.start : anchor.end] == anchor.quote:
        moved = Anchor.create(rev, anchor.start, anchor.end)
        return ReanchorResult(ReanchorOutcome.EXACT, moved, note="Offsets unverändert")

    hits = _find_all(text, anchor.quote)

    if not hits:
        return ReanchorResult(
            ReanchorOutcome.MISSING, None, note="Zitat kommt in dieser Fassung nicht vor"
        )

    if len(hits) == 1:
        s = hits[0]
        return ReanchorResult(
            ReanchorOutcome.UNIQUE_MOVE,
            Anchor.create(rev, s, s + len(anchor.quote)),
            candidates=((s, s + len(anchor.quote)),),
            note=f"eindeutig verschoben um {s - anchor.start:+d} Zeichen",
        )

    spans = tuple((s, s + len(anchor.quote)) for s in hits)
    by_context = [
        (s, e) for (s, e) in spans if anchor.context_at(text, s, e) == anchor.context_sha256
    ]
    if len(by_context) == 1:
        s, e = by_context[0]
        return ReanchorResult(
            ReanchorOutcome.UNIQUE_MOVE,
            Anchor.create(rev, s, e),
            candidates=spans,
            note=f"{len(hits)} Treffer, durch Kontext eindeutig",
        )

    return ReanchorResult(
        ReanchorOutcome.AMBIGUOUS,
        None,
        candidates=spans,
        note=f"{len(hits)} Treffer, Kontext trennt nicht — menschliche Wahl nötig",
    )
