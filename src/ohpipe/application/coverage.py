"""``l1.coverage`` — die deterministische Deckung der L1-Vorschläge, als Gate.

Der Modellschritt schlägt vor; dieser Schritt fragt, ob die Vorschläge das
bestätigte Transkript decken. „Deckung" ist hier keine Kennzahl zum Anschauen,
sondern ein Gate (``policies/gates.py``): Ein Segment gilt als gedeckt, wenn
eine Ankerspanne eines Vorschlags es berührt; die Quote der gedeckten Segmente
wird gegen ``Profile.coverage_threshold`` gehalten. Unterschreitet sie die
Schwelle, trägt der Beleg ein ``REVIEW_REQUIRED`` — kein Abbruch, sondern der
Grund, den der Mensch im nächsten Schritt (``l1.review``) sieht.

Warum ``gates.evaluate`` und keine eigene Aggregation: die Konjunktion (das
schlechteste Gate gewinnt, ein bestandenes hebt kein nicht bestandenes auf)
steht dort geprüft. Eine zweite Kopie derselben Regel wäre genau die
Fehlerklasse, gegen die dieses Repository gebaut ist.

Der Beleg ist deterministisch (``receipt.recorded`` mit ``output_sha256`` gleich
dem Artefakthash und den Eingaben Vorschläge, deklarierter Text und Textmarker):
ändert sich eine Eingabe, wird die Deckung sichtbar ``STALE``, nicht still
falsch. Ohne Bindung (E2-N Nummer 5: eine Zahl hat keine Textanker) und ohne
eigene Entscheidung.

Datenschutz: dieser Schritt nennt Segmentindizes und Quoten, nie ein Zitat.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from typing import Any

from ..domain.events import ARTIFACT_PRODUCED, RECEIPT_RECORDED
from ..domain.hashing import sha256_bytes
from .confirmed_text import ConfirmedTextError, read_confirmed_text
from ..domain.transcript import TranscriptRevision
from ..policies.exit_contract import Report, Status
from ..policies.gates import GateResult, evaluate
from .gate import current_duplicate, receipt_duplicate
from .replay import RecordView

__all__ = [
    "ARTIFACT",
    "CODE_VERSION",
    "SCHEMA",
    "STEP",
    "CoverageError",
    "CoverageResult",
    "coverage_report",
    "covered_segments",
    "run_l1_coverage",
]

STEP = "l1.coverage"
ARTIFACT = "l1.coverage"
SUGGESTIONS_ARTIFACT = "l1.suggestions"
#: Fassung der Deckungslogik. Geht in ``code_version`` des Belegs ein: ändert
#: sich die Regel (Überlappung, Schwellenvergleich), gilt ein alter Beleg als
#: nicht mehr aktuell.
CODE_VERSION = "l1-coverage/3"
SCHEMA = "ohpipe.l1.coverage.v3"
SEGMENT_JOINER = "\n"


class CoverageError(RuntimeError):
    """Die Deckung ließ sich nicht bilden. Nichts geschrieben."""


@dataclass(frozen=True)
class CoverageResult:
    artifact_sha256: str
    covered: int
    total: int
    ratio: float
    threshold: float
    passed: bool
    uncovered: tuple[int, ...]
    written: bool
    changed: tuple[str, ...]


def _segment_spans(rev: TranscriptRevision) -> dict[int, tuple[int, int]]:
    """Zeichenspannen der Segmente im Revisionstext — nachgerechnet, nicht angenommen.

    Dieselbe Rekonstruktion wie in ``l1_suggest``: die Projektion fügt die
    Segmenttexte mit LF zusammen. Stimmt die Rekonstruktion nicht, gibt es keine
    Spannen und keine Deckung.
    """
    spans: dict[int, tuple[int, int]] = {}
    pos = 0
    ordered = sorted(rev.segments, key=lambda s: s.index)
    for n, seg in enumerate(ordered):
        start = pos
        end = start + len(seg.text)
        spans[seg.index] = (start, end)
        pos = end + (len(SEGMENT_JOINER) if n + 1 < len(ordered) else 0)
    if SEGMENT_JOINER.join(s.text for s in ordered) != rev.normalized:
        raise CoverageError(
            "Segmentprojektion und Revisionstext stimmen nicht überein; "
            "Ankerspannen wären nicht adressierbar."
        )
    return spans


def covered_segments(spans: dict[int, tuple[int, int]], anchors: list[tuple[int, int]]) -> set[int]:
    """Welche Segmente eine Ankerspanne berührt. Überlappung, nicht Gleichheit:
    ein Anker, der eine Segmentgrenze schneidet, deckt beide Segmente."""
    getroffen: set[int] = set()
    for a_start, a_end in anchors:
        for index, (s_start, s_end) in spans.items():
            if a_start < s_end and a_end > s_start:
                getroffen.add(index)
    return getroffen


def _anchors(obj: dict[str, Any]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for s in obj.get("suggestions", []):
        anchor = s.get("anchor", {}) if isinstance(s, dict) else {}
        start, end = anchor.get("start"), anchor.get("end")
        if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end:
            raise CoverageError("Ein Vorschlag trägt keine gültige Ankerspanne")
        out.append((start, end))
    return out


def coverage_report(covered: int, total: int, threshold: float) -> Report:
    """Das Gate: Vorschläge vorhanden UND Quote über der Schwelle. Konjunktiv,
    über ``gates.evaluate`` — das schlechteste Ergebnis gewinnt."""
    ratio = covered / total if total else 0.0
    gates = [
        GateResult(
            "l1.coverage.suggestions_present",
            Status.READY if covered else Status.REVIEW_REQUIRED,
            reason="" if covered else "kein Segment trägt einen Vorschlag",
            reason_code="" if covered else "REVIEW_L1_COVERAGE_EMPTY",
        ),
        GateResult(
            "l1.coverage.threshold",
            Status.READY if ratio >= threshold else Status.REVIEW_REQUIRED,
            reason=""
            if ratio >= threshold
            else f"Deckung {covered}/{total} unter der Schwelle {threshold}",
            reason_code="" if ratio >= threshold else "REVIEW_L1_COVERAGE_BELOW_THRESHOLD",
        ),
    ]
    return evaluate(gates)


def _artifact_bytes(
    record_id: str,
    rev: TranscriptRevision,
    covered: int,
    total: int,
    threshold: float,
    uncovered: tuple[int, ...],
    report: Report,
    inputs: dict[str, str],
) -> bytes:
    obj = {
        "schema": SCHEMA,
        "record_id": record_id,
        "revision_sha256": rev.sha256,
        "inputs": inputs,
        "threshold": threshold,
        "covered": covered,
        "total": total,
        "uncovered_segments": list(uncovered),
        "gate": {"status": report.status.value, "reason_code": report.reason_code},
    }
    return (
        json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def check_suggestions_binding(obj, receipt_inputs, bound):
    """Coverage darf Vorschläge nicht nachträglich an einen anderen Text hängen."""
    if (
        not isinstance(obj, dict)
        or obj.get("record_id") != bound.view.record_id
        or obj.get("revision_sha256") != bound.text_sha256
        or not isinstance(receipt_inputs, dict)
        or any(receipt_inputs.get(role) != sha for role, sha in bound.inputs.items())
    ):
        raise CoverageError(
            "l1.coverage: Vorschläge und Beleg gehören zu einer anderen bestätigten Textfassung; l1.suggest erneut ausführen"
        )
    for suggestion in obj.get("suggestions", []):
        anchor = suggestion.get("anchor", {})
        if anchor.get("transcript_sha256") != bound.text_sha256:
            raise CoverageError("l1.coverage: Vorschlagsanker gehört zu einer anderen Textfassung")


def run_l1_coverage(ctx: Any, view: RecordView) -> CoverageResult:
    """Der Lauf: Eingaben aus dem Store lesen, Deckung aus den Ankerspannen
    rechnen, Gate auswerten, Artefakt und deterministischen Beleg schreiben.

    Nichts wird behauptet: die Spannen werden gegen ``rev.normalized``
    nachgerechnet, und die Deckung entsteht aus der Überlappung der Ankerspannen
    mit den Segmentspannen — nicht aus dem selbstgemeldeten ``segment_index``.
    """
    try:
        bound = read_confirmed_text(ctx, view, STEP)
    except ConfirmedTextError as exc:
        raise CoverageError(str(exc)) from exc
    view, rev = bound.view, bound.revision
    if SUGGESTIONS_ARTIFACT not in view.have:
        raise CoverageError(f"{STEP}: {SUGGESTIONS_ARTIFACT} ist nicht nutzbar; keine Deckung")
    sug_fact = view.facts[SUGGESTIONS_ARTIFACT]
    sug_sha = sug_fact.sha256
    store = ctx.ws.store()
    try:
        with store.open_verified(sug_sha) as handle:
            obj = json.load(handle)
    except (OSError, ValueError, RuntimeError) as exc:
        raise CoverageError(f"{STEP}: Vorschlagsbytes nicht verifizierbar") from exc
    check_suggestions_binding(obj, sug_fact.receipt_inputs, bound)

    spans = _segment_spans(rev)
    getroffen = covered_segments(spans, _anchors(obj)) & set(spans)
    total = len(spans)
    covered = len(getroffen)
    uncovered = tuple(sorted(set(spans) - getroffen))
    threshold = float(ctx.ws.profile.coverage_threshold)
    report = coverage_report(covered, total, threshold)
    ratio = covered / total if total else 0.0

    # Die Adresse und der Beleg binden dieselben tatsächlich gelesenen Eingaben.
    inputs = {SUGGESTIONS_ARTIFACT: sug_sha, **bound.inputs}
    data = _artifact_bytes(ctx.record_id, rev, covered, total, threshold, uncovered, report, inputs)
    artifact_sha256 = sha256_bytes(data)
    changed: list[str] = []
    from .finalisation import consumer_publication

    with consumer_publication(ctx, bound) as journal:
        address = store.put(io.BytesIO(data))
        if address != artifact_sha256:
            raise CoverageError(f"{STEP}: Store-Adresse und Artefaktdigest weichen ab")
        changed.append(str(ctx.ws.objects / address))

        rid = ctx.record_id
        written = 0
        if journal.append_once(
            ARTIFACT_PRODUCED,
            {"artifact": ARTIFACT, "sha256": artifact_sha256},
            record_id=rid,
            duplikat=current_duplicate(
                journal, rid, ARTIFACT_PRODUCED, ARTIFACT, {"sha256": artifact_sha256}
            ),
        ):
            written += 1
        if journal.append_once(
            RECEIPT_RECORDED,
            {
                "artifact": ARTIFACT,
                "output_sha256": artifact_sha256,
                "inputs": inputs,
                "code_version": CODE_VERSION,
                "step": STEP,
            },
            record_id=rid,
            duplikat=receipt_duplicate(ctx.ws, journal, rid, ARTIFACT, artifact_sha256, inputs),
        ):
            written += 1
        if written:
            changed.append(str(journal.path))
    return CoverageResult(
        artifact_sha256=artifact_sha256,
        covered=covered,
        total=total,
        ratio=ratio,
        threshold=threshold,
        passed=report.status is Status.READY,
        uncovered=uncovered,
        written=written > 0,
        changed=tuple(changed),
    )
