"""Was eine Transkriptkorrektur mit den Ankern gemacht hat, und wo die Maschine nicht waehlt.

``src/ohpipe/domain/anchor.py::reanchor`` ist seit langem gebaut und geprueft und
hatte bis hierher genau einen Aufrufer:
``src/ohpipe/application/l1_suggest.py`` prueft damit die eigenen frisch
gesetzten Anker gegen dieselbe Fassung. Das ist der triviale Fall — er endet
immer auf ``exact``. Der interessante Fall ist der andere: eine korrigierte
Fassung ist aufgenommen, und die Anker der L1-Vorschlaege zeigen auf die
Vorgaengerfassung. Genau dann trennt sich, was eine Maschine schliessen darf,
von dem, was ein Mensch entscheiden muss:

* ``exact`` und ``unique_move`` sind maschinell schliessbar. Das Zitat steht
  unveraendert da oder genau einmal, nur an anderer Stelle.
* ``ambiguous`` und ``missing`` sind es nicht. Mehrdeutig heisst: das Zitat
  kommt mehrfach vor, und auch der Kontext entscheidet nicht. Die Maschine
  waehlt dann NICHT, sie legt die Kandidaten vor.

Dieser Modul schreibt nichts. Er liest die aktuelle Fassung und die
L1-Vorschlaege aus dem Store, setzt jeden Anker neu auf und legt das Ergebnis
vor. Kein Artefakt, kein Beleg, keine ``anchor.checked`` — eine Bindungsevidenz
zu schreiben hiesse, die Wahl doch zu treffen.

Datenschutz: der Bericht nennt Segmentindex, Spannen, Ergebnis und
Hashpraefixe. Das Zitat selbst steht nirgends darin; es ist Transkripttext.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..domain.anchor import Anchor, ReanchorOutcome, reanchor
from ..domain.revision_serialization import RevisionValidationError, verify_revision
from ..project import Workspace

__all__ = ["AnchorFinding", "AnchorReport", "AnchorsError", "reanchor_report"]

REVISION_ARTIFACT = "transcript.revision"
SUGGESTIONS_ARTIFACT = "l1.suggestions"


class AnchorsError(RuntimeError):
    """Der Ankerbericht liess sich nicht bilden. Nichts gelesen, nichts behauptet."""


@dataclass(frozen=True)
class AnchorFinding:
    index: int
    outcome: str
    needs_human: bool
    candidates: tuple[tuple[int, int], ...]
    note: str
    quote_sha256: str

    def to_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "outcome": self.outcome,
            "needs_human": self.needs_human,
            "candidates": [list(spann) for spann in self.candidates],
            "note": self.note,
            "quote_sha256": self.quote_sha256[:12],
        }


@dataclass(frozen=True)
class AnchorReport:
    record_id: str
    revision_sha256: str
    anchored_revision_sha256: str
    findings: tuple[AnchorFinding, ...]

    @property
    def same_revision(self) -> bool:
        """Zeigen die Anker schon auf die aktuelle Fassung? Dann gab es keine Korrektur."""
        return self.revision_sha256 == self.anchored_revision_sha256

    @property
    def offen(self) -> tuple[AnchorFinding, ...]:
        return tuple(f for f in self.findings if f.needs_human)

    def to_json(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "revision_sha256": self.revision_sha256,
            "anchored_revision_sha256": self.anchored_revision_sha256,
            "same_revision": self.same_revision,
            "anchors": len(self.findings),
            "needs_human": len(self.offen),
            "findings": [f.to_json() for f in self.findings],
        }


def _sha(view: Any, name: str, *, historical: bool = False) -> str:
    facts = view.facts.get(name)
    readable_history = (
        historical
        and facts is not None
        and view.enabled
        and not view.findings
        and facts.state().derivation_state.value == "stale"
        and facts.state().decision_state.value not in ("withdrawn", "rejected")
    )
    if name not in view.have and not readable_history:
        raise AnchorsError(f"anchors: {name} ist nicht nutzbar")
    fakten = view.facts.get(name)
    sha = fakten.sha256 if fakten is not None else None
    if not sha:
        raise AnchorsError(f"anchors: fehlende Store-Adresse fuer {name}")
    return sha


def reanchor_report(ws: Workspace, view: Any, record_id: str) -> AnchorReport:
    """Setzt jeden L1-Anker auf die AKTUELLE Fassung neu auf. Schreibfrei.

    Gelesen wird beides inhaltsadressiert und geprueft: die Fassung ueber
    ``verify_revision`` (der Store gibt die Bytes nur unter ihrem eigenen
    Digest heraus), die Vorschlaege als JSON.
    """
    revision_sha = _sha(view, REVISION_ARTIFACT)
    suggestions_sha = _sha(view, SUGGESTIONS_ARTIFACT, historical=True)
    store = ws.store()
    try:
        with store.open_verified(revision_sha) as strom:
            revision = verify_revision(strom.read(), revision_sha)
    except (OSError, ValueError, RuntimeError, RevisionValidationError) as exc:
        raise AnchorsError(f"anchors: Fassung {revision_sha[:12]} nicht lesbar: {exc}") from exc
    try:
        with store.open_verified(suggestions_sha) as strom:
            vorschlaege = json.loads(strom.read())
    except (OSError, ValueError, RuntimeError) as exc:
        raise AnchorsError(
            f"anchors: Vorschlaege {suggestions_sha[:12]} nicht lesbar: {exc}"
        ) from exc

    rohe = vorschlaege.get("suggestions")
    if not isinstance(rohe, list) or not rohe:
        raise AnchorsError("anchors: die Vorschlaege tragen keine Anker")

    befunde: list[AnchorFinding] = []
    verankerte_fassung = ""
    for index, eintrag in enumerate(rohe):
        roh = (eintrag or {}).get("anchor") or {}
        try:
            anker = Anchor(
                transcript_sha256=roh["transcript_sha256"],
                start=int(roh["start"]),
                end=int(roh["end"]),
                quote=roh["quote"],
                quote_sha256=roh["quote_sha256"],
                context_sha256=roh["context_sha256"],
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AnchorsError(f"anchors: Vorschlag {index} traegt keinen lesbaren Anker") from exc
        verankerte_fassung = verankerte_fassung or anker.transcript_sha256
        ergebnis = reanchor(anker, revision)
        befunde.append(
            AnchorFinding(
                index=index,
                outcome=ergebnis.outcome.value,
                needs_human=ergebnis.needs_human,
                candidates=ergebnis.candidates,
                note=ergebnis.note,
                quote_sha256=anker.quote_sha256,
            )
        )
    return AnchorReport(record_id, revision.sha256, verankerte_fassung, tuple(befunde))


def offene_zeile(bericht: AnchorReport) -> str:
    """Ein Satz fuer den Sechszeiler: was offen ist, und was das heisst."""
    offen = bericht.offen
    if not offen:
        return (
            f"{len(bericht.findings)} Anker, alle maschinell geschlossen "
            f"({ReanchorOutcome.EXACT.value}/{ReanchorOutcome.UNIQUE_MOVE.value})."
        )
    arten = sorted({f.outcome for f in offen})
    verb = "braucht" if len(offen) == 1 else "brauchen"
    return (
        f"{len(offen)} von {len(bericht.findings)} Ankern {verb} einen Menschen "
        f"({', '.join(arten)}). Die Maschine legt die Kandidaten vor und waehlt nicht."
    )
