"""``l1.suggest`` — der erste Modellschritt: Vorschlag, Anker, Beleg.

Drei Regeln, jede vollstreckt und keine davon verhandelbar:

1. **Kein Lauf ohne Gate.** Autorisierung ist die ``ACCEPT``-Entscheidung über
   ``transcript.confirmed`` — nicht ihr Name, sondern das Objekt, gegen das
   ``ModelReceipt.validate`` den Beleg hält. Ein Lauf, der vor dieser
   Entscheidung begann, ist nicht autorisiert (``test_corsia.sh:95``, dort als
   Altzusicherung, hier als Vertrag).
2. **Kein Teilergebnis.** Endet der Lauf nicht sauber (``finish_reason``
   ausserhalb der Allowlist), fällt er VOR dem ersten Byte: kein Store-Eintrag,
   kein Ereignis, kein Anker. Der Vorgänger hat fünf Interviews lang
   abgeschnittene Antworten als Ergebnisse geführt; die Lücke sass am Ende der
   dichtesten Passagen. Deshalb wird der Beleg zuerst geprüft und erst danach
   die Antwort überhaupt gelesen.
3. **Jedes Segment genau einmal, jeder Vorschlag mit Anker.** Eine nichtleere,
   sonst gültige Teilantwort darf genau einmal um die fehlenden Original-IDs
   ergänzt werden. Die Vereinigung muss exakt vollständig sein; sonst fällt
   der ganze Lauf. Die Ankerspanne setzt der Server aus
   dieser Fassung, nicht aus einem Zitat des Modells.

Der Adapter ist austauschbar: aufgezeichnet für synthetische Daten oder
Ollama nach Modellkonfiguration und Profilfreigabe.

Datenschutz: Meldungen dieses Moduls nennen Segmentindizes und Zahlen, nie ein
Zitat. Die Zitate liegen in den Vorschlagsbytes im Store — in der Datenwurzel,
nie im Journal und nie in einer Ausnahme.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Callable, Iterable
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..adapters.models.fixture import (
    FIXTURE_MODEL,
    FixtureAdapter,
    ModelAdapter,
    fixture_params,
)
from ..domain.anchor import Anchor, ReanchorOutcome, reanchor
from ..domain.decision import Decision
from ..domain.events import ANCHOR_CHECKED, ARTIFACT_PRODUCED, RECEIPT_RECORDED
from ..domain.hashing import sha256_bytes, sha256_json, sha256_text
from ..domain.receipt import FINISH_OK, ModelParams, ModelReceipt, TruncatedOutput, UnauthorisedRun
from .confirmed_text import ConfirmedTextError, read_confirmed_text
from ..domain.transcript import Segment, TranscriptRevision
from .codebook import Codebook, load_codebook
from .gate import current_duplicate, receipt_duplicate
from .replay import RecordView

__all__ = [
    "ANSWER_SCHEMA",
    "ANCHOR_SOURCE",
    "ANTWORTFELDER",
    "ARTIFACT",
    "CODE_VERSION",
    "SCHEMA",
    "STEP",
    "SuggestError",
    "SuggestResult",
    "Suggestion",
    "adapter_for",
    "answer_schema",
    "anchor_suggestions",
    "build_prompt",
    "parse_answer",
    "run_l1_suggest",
    "suggestions_bytes",
]

STEP = "l1.suggest"
ARTIFACT = "l1.suggestions"
#: Fassung der Ableitungslogik. Geht in ``code_version`` des Belegs ein: ändert
#: sich die Prompt- oder Ankerregel, gilt ein alter Beleg nicht mehr als aktuell.
CODE_VERSION = "l1-suggest/8"
SCHEMA = "ohpipe.l1.suggestions.v3"
SEGMENT_JOINER = "\n"

#: Die Felder, die ein Ergebniseintrag trägt — genau diese, nicht mehr und nicht
#: weniger. Das Modell nennt das Segment und den Code; die Belegstelle nennt es
#: nicht mehr (06.09.2026).
ANTWORTFELDER = frozenset({"segment", "code"})

#: Ollama erzwingt dieses Schema seit 0.5.0 über das Request-Feld ``format``.
#: https://docs.ollama.com/capabilities/structured-outputs
#: Die konkrete ID-Menge prüft parse_answer zusätzlich gegen die Revision.
ANSWER_SCHEMA = {
    "type": "object",
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "segment": {"type": "integer"},
                    "code": {"type": "string"},
                },
                "required": ["segment", "code"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["results"],
    "additionalProperties": False,
}


#: Woher die Ankerspanne kommt. Steht in jedem Vorschlag und einmal im Kopf des
#: Artefakts, damit „ganzes Segment" nicht als Auswahl des Modells gelesen wird.
ANCHOR_SOURCE = "segment_span"


def answer_schema(codebook: Codebook | None = None) -> dict[str, Any]:
    if codebook is None:
        return ANSWER_SCHEMA
    schema = deepcopy(ANSWER_SCHEMA)
    schema["properties"]["results"]["items"]["properties"]["code"]["enum"] = [
        category["id"] for category in codebook.categories
    ]
    return schema


class SuggestError(RuntimeError):
    """Der Lauf konnte nicht beginnen oder nicht sauber enden. Nichts geschrieben."""


class _IncompleteAnswer(SuggestError):
    """Nur IDs fehlen: JSON, Codes, Eindeutigkeit und Nichtleere sind geprüft."""


@dataclass(frozen=True)
class Suggestion:
    id: str
    segment_index: int
    code: str
    anchor: Anchor

    def to_json(self) -> dict[str, Any]:
        # ``quote`` steht mit im Store — die Datenwurzel ist der Ort für
        # Transkripttext (domain/anchor.py). Ins Journal geht davon nichts.
        #
        # ``source`` sagt, dass diese Spanne SERVERSEITIG aus der Segment-ID
        # gesetzt wurde. Es steht an der Zeile und nicht nur im Kopf des
        # Artefakts, weil eine Zeile den Weg allein geht: wer einen einzelnen
        # Vorschlag ansieht, im Review oder später im Katalog, liest sonst ein
        # vollständiges Segment als Zitat und hält es für die Stelle, die das
        # Modell gewählt hat. Gewählt hat das Modell nur den Code.
        return {
            "id": self.id,
            "segment_index": self.segment_index,
            "code": self.code,
            "anchor": {
                **self.anchor.to_json(),
                "quote": self.anchor.quote,
                "source": ANCHOR_SOURCE,
            },
        }


@dataclass(frozen=True)
class SuggestResult:
    artifact_sha256: str
    suggestions: int
    finish_reason: str
    written: bool
    changed: tuple[str, ...]


def adapter_for(
    ws: Any, options: dict[str, str], *, schema: dict[str, Any] | None = None
) -> ModelAdapter:
    """Welcher Adapter läuft? Die Datenwurzel entscheidet, nicht der Aufruf.

    Zwei Objekte, zwei Orte (Adaptervertrag V3 § 1): Die MENGE der freigegebenen
    Modelle steht im Profil (``model_vocabulary``, eine Projektentscheidung);
    das ELEMENT — dieser Server, dieses Gewicht, diese Größen — steht in
    ``_governance/model.toml`` in der Datenwurzel, weil es zum Korpus gehört
    und nicht zum Quelltext (ADR 0012, ADR 0018).

    Daraus die Reihenfolge, und nichts davon berührt vor dem letzten Schritt
    das Netz:

    1. Keine ``model.toml`` und Produktionsprofil: kein Adapter, benannt — ein
       Aufgezeichneter, der reale Transkripte „kodiert", wäre eine Attrappe mit
       echtem Beleg. Die Meldung nennt den erwarteten Pfad, weil „es gibt
       keinen" ohne ihn nicht handlungsfähig macht.
    2. Keine ``model.toml`` und synthetisch: der aufgezeichnete Adapter, aber
       erst, nachdem sein Modellname gegen die Freigabeliste gehalten wurde.
       Auch die Aufzeichnung ist ein Modell im Beleg.
    3. Mit ``model.toml``: Form prüfen, Fixture-Szenarien ausschließen (sie
       gibt es nur für den Aufgezeichneten), Modell gegen die Freigabeliste
       halten — und ERST DANN den Adapter bauen, der den Server anspricht.
       Ein Modell außerhalb der Liste darf nicht dadurch auffallen, dass es
       schon geladen wurde.
    """
    # Lokal, nicht oben: ``ollama.py`` bezieht seine Fehlerklassen aus diesem
    # Modul. Ein Import auf Modulebene waere ein Zirkel, und die Aufloesung
    # davon (Fehlerklassen anderswo) verteilte den Vertrag auf drei Dateien.
    from ..adapters.models.ollama import OllamaAdapter, load_model_config

    profile = getattr(ws, "profile", ws)
    pfad = getattr(ws, "governance", None)
    pfad = (pfad / "model.toml") if pfad is not None else None

    if pfad is None or not pfad.exists():
        if getattr(profile, "production", False):
            raise SuggestError(
                f"Profil {getattr(profile, 'id', '?')!r} verarbeitet reale Daten; für diese "
                "Strecke gibt es keinen Modelladapter; erwartet wäre "
                f"{pfad if pfad is not None else '<Datenwurzel>/_governance/model.toml'}. "
                "Kein Lauf."
            )
        profile.check_model(FIXTURE_MODEL)
        return FixtureAdapter(options.get("fixture", FINISH_OK))

    cfg = load_model_config(pfad)
    if options.get("fixture", FINISH_OK) != FINISH_OK:
        raise SuggestError(
            "Fixture-Szenarien gibt es nur für den aufgezeichneten Adapter; das Profil "
            "führt einen Modellserver. Kein Lauf."
        )
    profile.check_model(cfg.model)
    return OllamaAdapter(cfg) if schema is None else OllamaAdapter(cfg, answer_schema=schema)


def build_prompt(
    rev: TranscriptRevision,
    segments: Iterable[Segment] | None = None,
    *,
    codebook: Codebook | None = None,
) -> str:
    """Der Prompt: eine Anweisung, dann ein JSON-Block mit den Segmenten.

    Deterministisch je Fassung, damit ``prompt_sha256`` ein Vergleichswert ist
    und nicht ein Zeitstempel in Verkleidung.

    Der Kopftext trägt **keine Leerzeile**. Die Leerzeile trennt Anweisung und
    Datenblock, und beide Leser dieses Prompts trennen an der ERSTEN
    (``adapters/models/fixture.py::_segments`` mit ``partition("\\n\\n")``).
    Eine Leerzeile im Kopftext schöbe die Trennstelle nach vorn; der Datenblock
    wäre dann kein JSON mehr. Einzelne Zeilenumbrüche sind unbedenklich.
    """
    ordered = sorted(rev.segments if segments is None else segments, key=lambda s: s.index)
    anzahl = len(ordered)
    kopf = (
        "Schlage je Sprechersegment einen deskriptiven L1-Inhaltscode vor, der "
        "beschreibt, wovon das Segment handelt.\n"
        "Verwende im Code keinen Sprechernamen, keine Sprecherkennung und keine "
        "Rollenbezeichnung.\n"
        f"Der Datenblock trägt genau {anzahl} Segmente. Liefere für jedes Segment "
        "genau ein Ergebnis, auch für kurze Segmente."
    )
    if codebook is not None:
        kopf += "\n" + codebook.prompt_text
    body = {
        "task": "descriptive_l1",
        "revision_sha256": rev.sha256,
        "projection_version": rev.projection_version,
        "segments": [{"index": s.index, "speaker": s.speaker, "text": s.text} for s in ordered],
    }
    return kopf + "\n\n" + json.dumps(body, ensure_ascii=False, sort_keys=True)


def _segment_spans(rev: TranscriptRevision) -> dict[int, tuple[int, int]]:
    """Zeichenspannen der Segmente im Revisionstext — nachgerechnet, nicht angenommen.

    Die Projektion fügt Segmenttexte mit LF zusammen. Das wird hier nicht
    vorausgesetzt, sondern gegen ``rev.normalized`` geprüft: stimmt die
    Rekonstruktion nicht, gibt es keine Spannen und keinen Lauf.
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
        raise SuggestError(
            "Segmentprojektion und Revisionstext stimmen nicht überein; "
            "Anker wären nicht adressierbar."
        )
    return spans


def _answer_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Doppelte JSON-Schlüssel nicht still durch den letzten Wert ersetzen."""
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Doppelter JSON-Schlüssel")
        obj[key] = value
    return obj


def _invalid_json_constant(value: str) -> None:
    raise ValueError("Keine JSON-Konstante")


def parse_answer(
    text: str,
    expected_segments: Iterable[int],
    allowed_codes: frozenset[str] | None = None,
    *,
    partial: bool = False,
) -> list[dict[str, Any]]:
    """Ein JSON-Dokument; alle erwarteten Segment-IDs genau einmal (O-3).

    Schema und ID-Menge werden vor der ersten Anker- oder Schreiboperation
    geprüft. Es gibt keinen Zeilenparser und keine Formatkorrektur. Meldungen
    tragen nur Positionen und Segment-IDs, niemals Modell- oder Transkripttext.
    ``partial=True`` erlaubt ausschließlich eine nichtleere echte Teilmenge;
    auch eine vollständige Antwort ist in diesem expliziten Modus ein Fehler.
    """
    try:
        obj = json.loads(
            text, object_pairs_hook=_answer_object, parse_constant=_invalid_json_constant
        )
    except ValueError as exc:
        raise SuggestError("Antwort ist kein eindeutiges JSON-Dokument") from exc
    if not isinstance(obj, dict) or set(obj) != {"results"}:
        raise SuggestError("Antwort trägt nicht genau die Ergebnisliste results")
    rows = obj["results"]
    if not isinstance(rows, list):
        raise SuggestError("Antwortfeld results ist keine Liste")
    for n, row in enumerate(rows, start=1):
        if (
            not isinstance(row, dict)
            or set(row) != ANTWORTFELDER
            or type(row.get("segment")) is not int
            or not isinstance(row.get("code"), str)
            or not row["code"].strip()
        ):
            raise SuggestError(f"Ergebniseintrag {n} trägt nicht genau segment und code")
        if allowed_codes is not None:
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,31}", row["code"]):
                # Freitext könnte ein kopierter Interviewausschnitt sein.
                raise SuggestError(
                    f"Segment {row['segment']}: Code ist keine kanonische Codebuch-ID"
                )
            if row["code"] not in allowed_codes:
                raise SuggestError(f"Segment {row['segment']}: unerlaubter Code {row['code']!r}")

    expected = set(expected_segments)
    counts = Counter(row["segment"] for row in rows)
    missing = sorted(expected - counts.keys())
    foreign = sorted(counts.keys() - expected)
    duplicates = sorted(index for index, count in counts.items() if count > 1)
    if missing or foreign or duplicates:
        error = (
            _IncompleteAnswer
            if missing and rows and not foreign and not duplicates and not partial
            else SuggestError
        )
        if partial and rows and missing and not foreign and not duplicates:
            return rows
        raise error(
            f"Segment-IDs stimmen nicht: erwartet {len(expected)}, erhalten {len(rows)}; "
            f"fehlend {missing}, fremd {foreign}, mehrfach {duplicates}. Kein Teilergebnis."
        )
    if partial:
        raise SuggestError("Teilmodus verlangt eine nichtleere echte Segment-Teilmenge")
    return rows


def anchor_suggestions(rev: TranscriptRevision, rows: list[dict[str, Any]]) -> list[Suggestion]:
    """Die Belegstelle ist das genannte Segment — gesetzt hier, nicht gewählt dort.

    Bis 06.09.2026 nannte das Modell ein Zitat, und dieser Schritt suchte es im
    Segment. Das koppelte den Beleg an eine Kopierleistung: Ein Modell, das
    zusammenfasste statt zu kopieren, liess den ganzen Lauf fallen, obwohl sein
    Code richtig sein konnte. Jetzt nennt das Modell nur noch das Segment, und
    die Spanne kommt aus ``_segment_spans`` — also aus der bestätigten Fassung
    selbst, nachgerechnet gegen ``rev.normalized``.

    **Was das für den Betrieb bedeutet.** Der Anker ist gröber: Er deckt das
    ganze Segment. Eine spätere Korrektur IRGENDWO in diesem Segment lässt den
    wörtlichen Rückvergleich in ``anchor.checked`` nicht mehr aufgehen, wo
    früher nur eine Korrektur im zitierten Satzteil ihn traf. Dafür fällt kein
    Lauf mehr an einer Zitierregel, die kein Sprachmodell zuverlässig einhält.

    Ein Segment ohne Text hat keine Spanne, die man ankern könnte
    (``start == end``). Das ist ein Befund und kein Traceback: Die Projektion
    lässt leeren Segmenttext ausdrücklich zu.
    """
    spans = _segment_spans(rev)
    out: list[Suggestion] = []
    for n, row in enumerate(rows, start=1):
        span = spans.get(row["segment"])
        if span is None:
            raise SuggestError(f"Vorschlag {n} nennt Segment {row['segment']}, das es nicht gibt")
        start, end = span
        if start >= end:
            raise SuggestError(
                f"Vorschlag {n} nennt Segment {row['segment']}, das keinen Text trägt; "
                "dort gibt es keine Belegstelle. Kein Teilergebnis."
            )
        out.append(
            Suggestion(
                id=f"S{n:03d}",
                segment_index=row["segment"],
                code=row["code"].strip(),
                anchor=Anchor.create(rev, start, end),
            )
        )
    return out


def suggestions_bytes(
    record_id: str,
    rev: TranscriptRevision,
    suggestions: list[Suggestion],
    params: ModelParams,
    *,
    prompt_plan_sha256: str,
    requests: list[dict[str, Any]],
) -> bytes:
    obj = {
        "schema": SCHEMA,
        "record_id": record_id,
        "revision_sha256": rev.sha256,
        "coding_mode": "descriptive_l1",
        "model": params.to_json(),
        "prompt_plan_sha256": prompt_plan_sha256,
        "execution_plan_sha256": sha256_json(
            [
                {key: request[key] for key in ("kind", "block", "segments", "prompt_sha256")}
                for request in requests
            ]
        ),
        "requests": requests,
        # Die Arbeitsteilung dieses Laufs, einmal im Klartext: Der Code kommt
        # vom Modell, die Ankerspanne kommt von hier. ``model`` sagt WELCHES
        # Modell lief, nicht WOFUER es einsteht -- das steht erst hier.
        "provenance": {"code": "model", "anchor": ANCHOR_SOURCE},
        "suggestions": [s.to_json() for s in suggestions],
    }
    return (
        json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _receipt(
    *,
    decision: Decision,
    output_sha256: str,
    params: ModelParams,
    prompt_sha256: str,
    finish_reason: str,
    output_tokens: int,
    started_at: str,
    codebook_sha256: str | None = None,
    text_inputs: dict[str, str],
) -> ModelReceipt:
    inputs = dict(text_inputs)
    if codebook_sha256 is not None:
        inputs["l1.codebook"] = codebook_sha256
    return ModelReceipt(
        step=STEP,
        inputs=inputs,
        output_sha256=output_sha256,
        code_version=CODE_VERSION,
        params=params,
        prompt_sha256=prompt_sha256,
        finish_reason=finish_reason,
        output_tokens=output_tokens,
        authorisation=decision.id,
        authorisation_subject_sha256=decision.subject_sha256,
        authorised_at=decision.at,
        started_at=started_at,
    )


@dataclass(frozen=True)
class _RequestContext:
    revision: TranscriptRevision
    decision: Decision
    params: ModelParams
    text_inputs: dict[str, str]
    codebook_sha256: str | None
    codebook: Codebook | None


def _block_prompt(
    context: _RequestContext,
    segments: list[Segment],
    block: dict[str, int],
    *,
    parent_prompt: str | None = None,
) -> str:
    head, _, body = build_prompt(context.revision, segments, codebook=context.codebook).partition(
        "\n\n"
    )
    payload = json.loads(body)
    payload["block"] = {
        **block,
        "first": segments[0].index,
        "last": segments[-1].index,
    }
    if parent_prompt is not None:
        payload["supplement"] = {
            "parent_prompt_sha256": parent_prompt,
            "segment_indices": [segment.index for segment in segments],
        }
    return head + "\n\n" + json.dumps(payload, ensure_ascii=False, sort_keys=True)


def _request_record(
    context: _RequestContext,
    segments: list[Segment],
    block: dict[str, int],
    digest: str,
    kind: str,
    *,
    response_text: str,
    finish_reason: str,
    output_tokens: int,
    started_at: str,
) -> dict[str, Any]:
    """Ein eigener geprüfter Beleg, bevor irgendeine Antwort geparst wird.

    Antwortbytes bleiben ausschließlich im verifizierten Vorschlagsobjekt.
    Das Journal trägt weiterhin nur dessen Digest und den Gesamtbeleg.
    """
    if (
        not isinstance(response_text, str)
        or not isinstance(finish_reason, str)
        or type(output_tokens) is not int
        or output_tokens < 0
        or not isinstance(started_at, str)
    ):
        raise SuggestError("Anfragebeleg trägt ungültige Antwortmetadaten")
    probe = _receipt(
        decision=context.decision,
        text_inputs=context.text_inputs,
        output_sha256=sha256_bytes(response_text.encode("utf-8")),
        params=context.params,
        prompt_sha256=digest,
        finish_reason=finish_reason,
        output_tokens=output_tokens,
        started_at=started_at,
        codebook_sha256=context.codebook_sha256,
    )
    try:
        probe.validate(context.decision)
    except TruncatedOutput as exc:
        raise SuggestError(f"Modelllauf endete mit finish_reason={finish_reason!r}") from exc
    except UnauthorisedRun as exc:
        raise SuggestError("Modelllauf nicht autorisiert; Beleg nicht rückwirkend erteilt") from exc
    receipt = probe.to_json()
    # Der geprüfte Anfragestart genügt; keine zusätzliche Wanduhr in den Bytes.
    del receipt["created_at"]
    return {
        "kind": kind,
        "block": block["index"],
        "count": block["count"],
        "first": segments[0].index,
        "last": segments[-1].index,
        "segments": [segment.index for segment in segments],
        "prompt_sha256": digest,
        "finish_reason": finish_reason,
        "output_tokens": output_tokens,
        "started_at": started_at,
        "response_text": response_text,
        "receipt": receipt,
    }


def _parse_original(
    context: _RequestContext, text: str, segments: list[Segment]
) -> tuple[list[dict[str, Any]], list[Segment]]:
    expected = [segment.index for segment in segments]
    codes = context.codebook.ids if context.codebook else None
    try:
        rows = (
            parse_answer(text, expected) if codes is None else parse_answer(text, expected, codes)
        )
    except _IncompleteAnswer:
        # Ausschließlich dieser typisierte Fehler öffnet den Teilmodus.
        rows = parse_answer(text, expected, codes, partial=True)
    present = {row["segment"] for row in rows}
    return rows, [segment for segment in segments if segment.index not in present]


def _complete_block(
    context: _RequestContext, rows: list[dict[str, Any]], segments: list[Segment]
) -> list[Suggestion]:
    # Die unabhängige Endprüfung verwirft auch eine fehlerhaft implementierte
    # Vereinigung (Überschreiben, Überlappung oder weiterhin fehlende IDs).
    if Counter(row["segment"] for row in rows) != Counter(segment.index for segment in segments):
        raise SuggestError("Endvereinigung trägt nicht jedes Originalsegment genau einmal")
    anchored = anchor_suggestions(context.revision, sorted(rows, key=lambda row: row["segment"]))
    if {reanchor(s.anchor, context.revision).outcome for s in anchored} != {ReanchorOutcome.EXACT}:
        raise SuggestError("Anker sind auf der eigenen Fassung nicht exakt")
    return anchored


def _validate_evidence(
    existing: dict[str, Any],
    context: _RequestContext,
    plan: list[tuple[list[Segment], dict[str, int], str, str]],
    record_id: str,
    prompt_plan_sha256: str,
) -> None:
    """Wiederverwendung rekonstruiert auch lückenhafte Zusatzanfragen modellfrei.

    Der Storehash bindet Bytes, diese Prüfung bindet deren Bedeutung: Antwort,
    Fehlmenge, Anfragebeleg, Zusatzprompt und vollständige Vorschläge.
    """
    try:
        requests = existing["requests"]
        if not isinstance(requests, list):
            raise ValueError
        cursor = 0
        suggestions: list[Suggestion] = []

        def take(segments, block, digest, kind):
            nonlocal cursor
            actual = requests[cursor]
            cursor += 1
            expected = _request_record(
                context,
                segments,
                block,
                digest,
                kind,
                **{
                    key: actual[key]
                    for key in ("response_text", "finish_reason", "output_tokens", "started_at")
                },
            )
            if sha256_json(actual) != sha256_json(expected):
                raise ValueError
            return actual["response_text"]

        for segments, block, _, digest in plan:
            text = take(segments, block, digest, "original")
            rows, missing = _parse_original(context, text, segments)
            if missing:
                prompt = _block_prompt(context, missing, block, parent_prompt=digest)
                text = take(missing, block, sha256_text(prompt), "supplement")
                rows += parse_answer(
                    text,
                    [segment.index for segment in missing],
                    context.codebook.ids if context.codebook else None,
                )
            for suggestion in _complete_block(context, rows, segments):
                suggestions.append(replace(suggestion, id=f"S{len(suggestions) + 1:03d}"))
        if cursor != len(requests):
            raise ValueError
        expected_artifact = json.loads(
            suggestions_bytes(
                record_id,
                context.revision,
                suggestions,
                context.params,
                prompt_plan_sha256=prompt_plan_sha256,
                requests=requests,
            )
        )
        if sha256_json(existing) != sha256_json(expected_artifact):
            raise ValueError
    except (IndexError, KeyError, TypeError, ValueError, SuggestError) as exc:
        raise SuggestError(
            f"{STEP}: Anfrage-/Zusatzbelege sind unvollständig oder widersprüchlich. "
            "Keine Wiederverwendung, kein Teilergebnis."
        ) from exc


def run_l1_suggest(
    ctx: Any,
    view: RecordView,
    *,
    adapter: ModelAdapter | None = None,
    clock: Callable[[], str] = _now,
) -> SuggestResult:
    """Der Lauf. ``ctx`` trägt ``ws``, ``journal``, ``record_id`` und ``options``.

    Reihenfolge ist die Zusicherung: Gate, Fassung, Prompt, Lauf, **Beleg
    prüfen**, erst dann Antwort lesen, Anker setzen, Bytes ablegen, Evidenz
    anhängen. Ein aktiviertes Codebuch wird zuvor als Eingabe im Store gesichert;
    Vorschlagsbytes und Journaleinträge entstehen erst nach allen Blöcken.
    """
    try:
        bound = read_confirmed_text(ctx, view, STEP)
    except ConfirmedTextError as exc:
        raise SuggestError(str(exc)) from exc
    decision, rev, view = bound.decision, bound.revision, bound.view

    # Zweite, unabhaengige Bindungsgrenze unmittelbar vor dem Verbraucher:
    # Der Leser hat die geschuetzte Fassung rekonstruiert; hier wird sie gegen
    # seine Replay-Sicht und gegen ihre tatsaechlichen Bytes gehalten. Diese
    # Pruefung liegt bewusst vor Codebuchbeobachtung und Adapterbau, damit ein
    # Widerspruch weder einen Request noch Store-/Journalbytes erzeugen kann.
    try:
        text_fact = bound.view.facts.get(bound.text_artifact)
        gate_fact = bound.view.facts.get(bound.gate_artifact)
        text_bound = (
            text_fact is not None
            and bound.revision.sha256
            == sha256_bytes(bound.revision_bytes)
            == bound.text_sha256
            == bound.inputs.get(bound.text_artifact)
            == text_fact.sha256
        )
        marker_bound = (
            gate_fact is not None
            and bound.marker_sha256 == bound.inputs.get(bound.gate_artifact) == gate_fact.sha256
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        text_bound = marker_bound = False
    if not text_bound or not marker_bound:
        raise SuggestError(f"{STEP}: Textbindung vor Modellaufruf widerspruechlich. Kein Lauf.")

    store = ctx.ws.store()

    options = dict(getattr(ctx, "options", {}) or {})
    codebook = None
    codebook_sha256 = None
    if ctx.ws.profile.codebook:
        profile_arg = str(getattr(ctx, "profile_arg", ctx.ws.profile.id))
        profile_path = (
            Path(profile_arg).expanduser()
            if profile_arg.endswith(".toml")
            else Path(__file__).resolve().parents[1] / "profiles" / profile_arg / "profile.toml"
        )
        try:
            codebook = load_codebook(profile_path.resolve().parent / ctx.ws.profile.codebook)
        except ValueError as exc:
            raise SuggestError(str(exc)) from exc
        from .input_sources import observe

        codebook_sha256 = observe(ctx.ws, ctx.journal, ctx.record_id, "l1.codebook", codebook.raw)
    if adapter is None:
        adapter = (
            adapter_for(ctx.ws, options)
            if codebook is None
            else adapter_for(ctx.ws, options, schema=answer_schema(codebook))
        )
    params = getattr(adapter, "params", None) or fixture_params(options.get("fixture", FINISH_OK))
    block_size = params.extra.get("block_size")
    if type(block_size) is not int or block_size <= 0:
        raise SuggestError(
            f"{STEP}: block_size muss eine ganze Zahl größer null sein. "
            "Kein Teilergebnis, nichts geschrieben."
        )
    ordered = sorted(rev.segments, key=lambda s: s.index)
    if not ordered:
        raise SuggestError(f"{STEP}: keine Segmente. Kein Teilergebnis, nichts geschrieben.")
    blocks = [ordered[start : start + block_size] for start in range(0, len(ordered), block_size)]
    request_context = _RequestContext(
        rev, decision, params, dict(bound.inputs), codebook_sha256, codebook
    )
    plan = []
    for i, segments in enumerate(blocks, start=1):
        block = {
            "index": i,
            "count": len(blocks),
            "first": segments[0].index,
            "last": segments[-1].index,
        }
        prompt = _block_prompt(request_context, segments, block)
        plan.append((segments, block, prompt, sha256_text(prompt)))
    prompt_sha256 = sha256_json({"block_size": block_size, "prompts": [entry[3] for entry in plan]})

    # Zeitpunkte gehören zum tatsächlich ausgeführten Lauf. Ein bereits
    # nutzbarer Beleg für dieselben Eingaben wird deshalb wiederverwendet,
    # statt durch neue Anfragezeitpunkte andere Artefaktbytes zu erzeugen.
    fact = view.facts.get(ARTIFACT)
    if ARTIFACT in view.have and fact is not None:
        for event in ctx.journal:
            p = event.payload
            if (
                event.record_id == ctx.record_id
                and event.kind == RECEIPT_RECORDED
                and p.get("artifact") == ARTIFACT
                and p.get("output_sha256") == fact.sha256
                and p.get("code_version") == CODE_VERSION
                and p.get("params") == params.to_json()
                and p.get("prompt_sha256") == prompt_sha256
                and p.get("inputs")
                == {**bound.inputs, **({"l1.codebook": codebook_sha256} if codebook_sha256 else {})}
                and p.get("authorisation") == decision.id
                and p.get("authorisation_subject_sha256") == decision.subject_sha256
                and p.get("authorised_at") == decision.at
                and p.get("finish_reason") == FINISH_OK
            ):
                try:
                    with store.open_verified(fact.sha256) as handle:
                        existing = json.load(
                            handle,
                            object_pairs_hook=_answer_object,
                            parse_constant=_invalid_json_constant,
                        )
                except (ValueError, TypeError) as exc:
                    raise SuggestError(
                        f"{STEP}: gespeichertes Vorschlagsobjekt ist ungültig"
                    ) from exc
                _validate_evidence(existing, request_context, plan, ctx.record_id, prompt_sha256)
                if p.get("started_at") != existing["requests"][0]["started_at"]:
                    raise SuggestError(f"{STEP}: Gesamtbeleg und Anfragestart widersprechen sich")
                return SuggestResult(
                    fact.sha256, len(existing["suggestions"]), FINISH_OK, False, ()
                )

    suggestions: list[Suggestion] = []
    requests: list[dict[str, Any]] = []

    def execute(segments, block, prompt, kind):
        started_at = clock()
        try:
            response = adapter.run(prompt, params)
        except SuggestError:
            raise
        except Exception as exc:
            raise SuggestError(f"Adapterabbruch ({type(exc).__name__})") from exc
        request = _request_record(
            request_context,
            segments,
            block,
            sha256_text(prompt),
            kind,
            response_text=response.text,
            finish_reason=response.finish_reason,
            output_tokens=response.output_tokens,
            started_at=started_at,
        )
        requests.append(request)
        return response.text

    for segments, block, prompt, digest in plan:
        try:
            text = execute(segments, block, prompt, "original")
            rows, missing = _parse_original(request_context, text, segments)
            if missing:
                supplement_prompt = _block_prompt(
                    request_context, missing, block, parent_prompt=digest
                )
                # Genau ein Zusatzblock; sein Ergebnis wird niemals im Teilmodus gelesen.
                text = execute(missing, block, supplement_prompt, "supplement")
                rows += parse_answer(
                    text,
                    [segment.index for segment in missing],
                    codebook.ids if codebook else None,
                )
            anchored = _complete_block(request_context, rows, segments)
        except (SuggestError, ValueError) as exc:
            reason = str(exc) if isinstance(exc, SuggestError) else "Ankerfehler"
            raise SuggestError(
                f"{STEP}: Block {block['index']}/{block['count']} "
                f"(Segmente {block['first']} bis {block['last']}): {reason}. "
                "Kein Teilergebnis, nichts geschrieben."
            ) from exc
        for suggestion in anchored:
            suggestions.append(replace(suggestion, id=f"S{len(suggestions) + 1:03d}"))
    if [suggestion.segment_index for suggestion in suggestions] != [s.index for s in ordered]:
        raise SuggestError(f"{STEP}: Endvereinigung ist nicht exakt vollständig")

    data = suggestions_bytes(
        ctx.record_id,
        rev,
        suggestions,
        params,
        prompt_plan_sha256=prompt_sha256,
        requests=requests,
    )
    artifact_sha256 = sha256_bytes(data)
    receipt = _receipt(
        decision=decision,
        text_inputs=bound.inputs,
        output_sha256=artifact_sha256,
        params=params,
        prompt_sha256=prompt_sha256,
        finish_reason=FINISH_OK,
        output_tokens=sum(request["output_tokens"] for request in requests),
        started_at=requests[0]["started_at"],
        codebook_sha256=codebook_sha256,
    )
    receipt.validate(decision)

    changed: list[str] = []
    from .finalisation import consumer_publication
    from .l1_publication import l1_object_publication

    with l1_object_publication(store) as publish, consumer_publication(ctx, bound) as journal:
        address = publish(data)
        if address != artifact_sha256:
            raise SuggestError(f"{STEP}: Store-Adresse und Artefaktdigest weichen ab")
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
                "inputs": dict(receipt.inputs),
                "code_version": receipt.code_version,
                "kind": receipt.kind,
                "step": receipt.step,
                "params": params.to_json(),
                "prompt_sha256": receipt.prompt_sha256,
                "finish_reason": receipt.finish_reason,
                "authorisation": receipt.authorisation,
                "authorisation_subject_sha256": receipt.authorisation_subject_sha256,
                "authorised_at": receipt.authorised_at,
                "started_at": receipt.started_at,
            },
            record_id=rid,
            duplikat=receipt_duplicate(
                ctx.ws, journal, rid, ARTIFACT, artifact_sha256, dict(receipt.inputs)
            ),
        ):
            written += 1
        if journal.append_once(
            ANCHOR_CHECKED,
            {"artifact": ARTIFACT, "outcome": ReanchorOutcome.EXACT.value},
            record_id=rid,
            duplikat=lambda e: (
                e.payload.get("artifact") == ARTIFACT
                and e.payload.get("outcome") == ReanchorOutcome.EXACT.value
            ),
        ):
            written += 1
        if written:
            changed.append(str(journal.path))
    return SuggestResult(
        artifact_sha256=artifact_sha256,
        suggestions=len(suggestions),
        finish_reason=FINISH_OK,
        written=written > 0,
        changed=tuple(changed),
    )
