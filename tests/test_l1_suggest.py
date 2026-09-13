"""``l1.suggest`` und der aufgezeichnete Adapter — Demo-Moment 3, vollstreckt.

Drei Zusicherungen, in dieser Reihenfolge, weil die dritte ohne die ersten
beiden nichts beweist:

1. Ein Lauf, der an der Token-Grenze endet, **scheitert**: kein Byte im Store,
   kein Ereignis im Journal, ein ``STOP`` mit dem Wortlaut des Vertrags.
2. Ein Lauf ohne Gate oder vor dem Gate läuft nicht — die Autorisierung ist
   die Entscheidung, nicht ihr Name.
3. Ein sauberer Lauf hinterlässt genau die Belege, die ``replay`` verlangt:
   Bytes, Modellbeleg auf die Gate-Entscheidung, Anker ``exact``. Danach ist
   ``l1.suggestions`` nutzbar, und die Kette steht vor ``l1.coverage``.

Die Fassung im Store ist kanonisch (``canonical_revision_bytes``), nicht
irgendein Byteblock: ``l1.suggest`` liest sie über ``verify_revision`` zurück,
und ein Anker auf eine unkanonische Fassung wäre keiner.
"""

from __future__ import annotations

import io
import json
import shlex
from dataclasses import replace
from pathlib import Path

import pytest

from ohpipe.adapters.models.fixture import (
    FIXTURE_MODEL,
    FixtureAdapter,
    ModelResponse,
    fixture_params,
)
from ohpipe.application import l1_suggest
from ohpipe.application.l1_suggest import SuggestError, run_l1_suggest
from ohpipe.application.replay import replay
from ohpipe.application.steps import REGISTRY, StepContext, continue_record, continue_report
from ohpipe.domain.confirmation import ConfirmationMarker, ConfirmationDecision
from ohpipe.domain.hashing import sha256_json, sha256_text
from ohpipe.domain.revision_serialization import PROJECTION_VERSION, canonical_revision_bytes
from ohpipe.domain.step import build_graph
from ohpipe.domain.transcript import Segment, TranscriptRevision
from ohpipe.journal import Journal
from ohpipe.policies.authority import Authority
from ohpipe.policies.exit_contract import Status
from ohpipe.project import Profile, Workspace

from ._forge import cli_keyed, forge_keyed, journal_path, place_object, report_lines

PROFIL = Path(__file__).resolve().parents[1] / "src" / "ohpipe" / "profiles" / "sandbox"
RECORD = "SANDBOX-001"
ENTSCHIEDEN_AM = "2026-09-01T11:00:00+00:00"

SEGMENTE = (
    Segment(0, 500, 5200, "Wie sah der Schulweg damals aus?", "INTERVIEWER", "deu"),
    Segment(
        1,
        5600,
        13400,
        "Wir sind jeden Morgen zu Fuss gegangen, auch im Winter.",
        "ZEITZEUGIN",
        "deu",
    ),
    Segment(2, 14000, 21800, "Ja.", "ZEITZEUGIN", "deu"),
    Segment(
        3, 22000, 30000, "Das waren gut vierzig Minuten in eine Richtung.", "ZEITZEUGIN", "deu"
    ),
)


def _revision(segmente=SEGMENTE) -> TranscriptRevision:
    return TranscriptRevision.from_segments(
        segmente, projection_version=PROJECTION_VERSION, source_kind="srt"
    )


def _confirmation(ws, rev):
    """P2: echte kanonische Bytes und profil-/graphgebundene Entscheidung."""
    marker = ConfirmationMarker(RECORD, rev.projection_version, rev.sha256)
    decision = ConfirmationDecision.create(
        marker=marker,
        actor="niemand",
        fulltext_origin="segment_projection",
        fulltext_receipt="a" * 64,
        iso6393_release="synthetic",
        iso6393_vocabulary_sha256="b" * 64,
        iso6393_snapshot_receipt="c" * 64,
        profile_id=ws.profile.id,
        graph_sha256=ws.running_graph_sha256(),
    )
    return marker.bytes, replace(decision, at=ENTSCHIEDEN_AM).object()


def _welt(tmp_path: Path, *, bestaetigt: bool = True, segmente=SEGMENTE):
    """Arbeitsbereich mit kanonischer Fassung und — auf Wunsch — bestätigtem Gate."""
    ws = Workspace(tmp_path / "data", Profile.load(PROFIL / "profile.toml"))
    ws.ensure()
    ws.bind_graph_initially()
    journal = Journal(ws.journal_path, key=b"P2-synthetic-unit-journal-key-0001")
    rev = _revision(segmente)
    sha = ws.store().put(io.BytesIO(canonical_revision_bytes(rev)))
    assert sha == rev.sha256
    journal.append(
        "artifact.produced", {"artifact": "transcript.revision", "sha256": sha}, record_id=RECORD
    )
    if bestaetigt:
        marker_bytes, decision = _confirmation(ws, rev)
        marker = ws.store().put(io.BytesIO(marker_bytes))
        journal.append(
            "artifact.produced",
            {"artifact": "transcript.confirmed", "sha256": marker},
            record_id=RECORD,
        )
        journal.append("decision.recorded", decision, record_id=RECORD)
        journal.append(
            "anchor.checked",
            {"artifact": "transcript.confirmed", "outcome": "exact"},
            record_id=RECORD,
        )
    return ws, journal, rev


def _view(ws: Workspace, journal: Journal):
    return replay(journal, graph=build_graph(ws.profile), authority=Authority.AUTHENTICATED)[RECORD]


def _ctx(ws, journal, **options) -> StepContext:
    return StepContext(
        ws=ws,
        journal=journal,
        record_id=RECORD,
        profile_arg="sandbox",
        confirm=True,
        options=options,
    )


def _zustand(ws: Workspace, journal: Journal) -> tuple:
    return journal.head(), sorted(p.name for p in ws.objects.iterdir())


# ------------------------------------------------- der Adapter selbst


def test_the_fixture_answers_one_document_for_every_segment_including_short_text():
    rev = _revision()
    antwort = FixtureAdapter("stop").run(l1_suggest.build_prompt(rev), fixture_params("stop"))
    zeilen = l1_suggest.parse_answer(antwort.text, (s.index for s in rev.segments))
    assert antwort.finish_reason == "stop"
    assert [z["segment"] for z in zeilen] == [0, 1, 2, 3], zeilen
    assert all(set(z) == {"segment", "code"} for z in zeilen), zeilen


def test_the_length_fixture_ends_with_length_and_a_cut_document():
    rev = _revision()
    antwort = FixtureAdapter("length").run(l1_suggest.build_prompt(rev), fixture_params("length"))
    assert antwort.finish_reason == "length"
    assert antwort.output_tokens == fixture_params("length").num_predict
    with pytest.raises(SuggestError):
        l1_suggest.parse_answer(antwort.text, (s.index for s in rev.segments))


def test_the_fixture_refuses_an_unknown_scenario_and_a_foreign_model():
    with pytest.raises(ValueError):
        FixtureAdapter("maybe")
    with pytest.raises(ValueError):
        fixture_params("maybe")
    fremd = fixture_params("stop").__class__(model="gemma4:e4b")
    with pytest.raises(ValueError):
        FixtureAdapter("stop").run("x\n\n{}", fremd)
    assert fixture_params("stop").model == FIXTURE_MODEL


# ------------------------------------------------- der Kopftext des Prompts


def test_the_prompt_head_carries_no_blank_line_so_the_split_stays_where_both_readers_look():
    """Eine Leerzeile im Kopftext zerlegte den Prompt an der falschen Stelle.

    Die Leerzeile ist die Trennung zwischen Anweisung und Datenblock, und
    ``fixture.py::_segments`` trennt an der ERSTEN. Ein Kopftext mit eigener
    Leerzeile machte den Datenblock zu Text hinter Text: kein JSON mehr. Der
    Defekt fiele nicht im Kopftext auf, sondern beim Adapter, und zwar als
    „Fixture-Prompt trägt keinen JSON-Segmentblock" — weit weg von seiner
    Ursache. Deshalb steht die Bedingung hier, wo sie entsteht.
    """
    kopf, trenner, rumpf = l1_suggest.build_prompt(_revision()).partition("\n\n")
    assert trenner == "\n\n", "der Prompt trägt keinen Datenblock"
    assert "\n\n" not in kopf, kopf
    assert json.loads(rumpf)["task"] == "descriptive_l1"


def test_the_prompt_head_keeps_content_speaker_rule_and_segment_count_without_format_example():
    kopf, _, _ = l1_suggest.build_prompt(_revision()).partition("\n\n")
    assert "deskriptiven L1-Inhaltscode" in kopf
    assert "keinen Sprechernamen" in kopf
    assert "genau 4 Segmente" in kopf
    assert "genau ein Ergebnis" in kopf
    assert "kurze Segmente" in kopf
    for obsolete in ("Format", "Zeile", "Platzhalter", "{", "1.", "2.", "3."):
        assert obsolete not in kopf
    anderer_kopf = l1_suggest.build_prompt(_revision(SEGMENTE[:2])).partition("\n\n")[0]
    assert "genau 2 Segmente" in anderer_kopf


# ------------------------------------------------- ein JSON-Dokument, exakte ID-Menge


def _document(ids):
    return json.dumps(
        {"results": [{"segment": i, "code": "Schulweg"} for i in ids]}, ensure_ascii=False
    )


def test_a_formatted_document_preserves_codes_and_checks_actual_ids_without_assuming_order():
    obj = {
        "results": [
            {"segment": 9, "code": 'Ärger über "Arbeit"\nzu Hause'},
            {"segment": 4, "code": "Schulweg"},
        ]
    }
    text = " \n" + json.dumps(obj, ensure_ascii=False, indent=2) + "\n "
    assert l1_suggest.parse_answer(text, [4, 9]) == obj["results"]


@pytest.mark.parametrize(
    "text",
    [
        "",
        " ",
        "{}",
        "[]",
        "null",
        "true",
        '{"results": {}}',
        '{"results": null}',
        '{"results": [], "extra": "GEHEIMWORT"}',
        '{"segment": 0, "code": "Schulweg"}',
        '{"segment": 0, "code": "Schulweg"}\n{"segment": 1, "code": "Arbeit"}',
        '{"segment": 0, "code": "Schulweg"},\n',
        '{"results": [{"segment": 0, "code": "Schulweg"},]}',
        'Vorwort GEHEIMWORT\n{"results": []}',
        '```json\n{"results": []}\n```',
        '{"results": []}\n{"results": []}',
        '{"results": [], "results": []}',
        '{"results": [{"segment": 1, "segment": 0, "code": "Schulweg"}]}',
        '{"results": [{"segment": NaN, "code": "Schulweg"}]}',
    ],
)
def test_only_one_strict_json_document_is_accepted(text):
    with pytest.raises(SuggestError) as error:
        l1_suggest.parse_answer(text, [0])
    assert "GEHEIMWORT" not in str(error.value)


@pytest.mark.parametrize(
    "row",
    [
        None,
        [],
        {},
        {"segment": 0},
        {"code": "Schulweg"},
        {"segment": True, "code": "Schulweg"},
        {"segment": False, "code": "Schulweg"},
        {"segment": 0.0, "code": "Schulweg"},
        {"segment": "0", "code": "Schulweg"},
        {"segment": None, "code": "Schulweg"},
        {"segment": 0, "code": 7},
        {"segment": 0, "code": None},
        {"segment": 0, "code": ""},
        {"segment": 0, "code": " \n"},
        {"segment": 0, "code": "Schulweg", "quote": "GEHEIMWORT"},
    ],
)
def test_result_entries_require_exact_fields_and_types(row):
    with pytest.raises(SuggestError, match="Ergebniseintrag 1") as error:
        l1_suggest.parse_answer(json.dumps({"results": [row]}), [0])
    assert "GEHEIMWORT" not in str(error.value)


@pytest.mark.parametrize(
    "ids, finding",
    [
        ([], "fehlend [0, 1, 2, 3]"),
        ([0, 1, 3], "fehlend [2]"),
        ([0, 1, 2], "fehlend [3]"),
        ([0, 1, 1, 3], "mehrfach [1]"),
        ([0, 1, 2, 3, 3], "mehrfach [3]"),
        ([0, 1, 2, 99], "fremd [99]"),
        ([0, 1, 2, 3, 99], "fremd [99]"),
        ([-1, 1, 2, 3], "fremd [-1]"),
    ],
)
def test_o3_rejects_wrong_ids_before_anchoring_or_writing(tmp_path, monkeypatch, ids, finding):
    ws, journal, _ = _welt(tmp_path)

    class WrongIds:
        name = FIXTURE_MODEL
        params = fixture_params("stop")

        def run(self, prompt, params):
            return ModelResponse(_document(ids), "stop", 20, params.model_digest)

    def no_anchor(*args, **kwargs):
        pytest.fail("Eine ungültige ID-Menge hat die Ankerbildung erreicht")

    monkeypatch.setattr(l1_suggest, "anchor_suggestions", no_anchor)
    before = _zustand(ws, journal)
    with pytest.raises(SuggestError) as error:
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=WrongIds())
    assert finding in str(error.value)
    assert _zustand(ws, journal) == before


def test_64_segments_produce_64_suggestions_in_one_adapter_call(tmp_path):
    segments = tuple(Segment(i, i * 1000, (i + 1) * 1000, "Ja.", "A", "deu") for i in range(64))
    ws, journal, _ = _welt(tmp_path, segmente=segments)
    calls = []

    class CountingFixture(FixtureAdapter):
        def run(self, prompt, params):
            calls.append(prompt)
            return super().run(prompt, params)

    result = run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=CountingFixture())
    assert len(calls) == 1
    assert result.suggestions == 64
    with ws.store().open_verified(result.artifact_sha256) as handle:
        obj = json.load(handle)
    assert [s["segment_index"] for s in obj["suggestions"]] == list(range(64))


@pytest.mark.parametrize("ids", [list(range(63)), list(range(63)) + [62], list(range(63)) + [99]])
def test_64_expected_segments_reject_omission_duplicate_and_substitution(ids):
    with pytest.raises(SuggestError, match="Segment-IDs"):
        l1_suggest.parse_answer(_document(ids), range(64))


# ------------------------------------------------- Zusicherung 1: kein Teilergebnis


def test_a_truncated_run_leaves_no_byte_behind(tmp_path):
    ws, journal, _ = _welt(tmp_path)
    vorher = _zustand(ws, journal)
    with pytest.raises(SuggestError) as exc:
        run_l1_suggest(_ctx(ws, journal, fixture="length"), _view(ws, journal))
    assert "finish_reason='length'" in str(exc.value)
    assert "Teilergebnis" in str(exc.value)
    assert _zustand(ws, journal) == vorher, "ein abgeschnittener Lauf hat geschrieben"


@pytest.mark.parametrize("finish", ["unknown", "load", "unload"])
def test_an_unknown_finish_reason_counts_as_truncated(tmp_path, finish):
    """Die Allowlist gilt: was nicht sauber heisst, ist nicht sauber."""
    ws, journal, _ = _welt(tmp_path)

    class Schweiger:
        name = FIXTURE_MODEL
        params = fixture_params("stop")

        def run(self, prompt, params):
            echt = FixtureAdapter("stop").run(prompt, params)
            return ModelResponse(echt.text, finish, echt.output_tokens, echt.model_digest)

    vorher = _zustand(ws, journal)
    with pytest.raises(SuggestError) as error:
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=Schweiger())
    assert f"finish_reason={finish!r}" in str(error.value)
    assert _zustand(ws, journal) == vorher


# ------------------------------------------------- Zusicherung 2: kein Lauf ohne Gate


def test_without_a_confirmed_transcript_the_adapter_is_never_called(tmp_path):
    ws, journal, _ = _welt(tmp_path, bestaetigt=False)
    aufrufe: list[str] = []

    class Zaehler:
        name = FIXTURE_MODEL
        params = fixture_params("stop")

        def run(self, prompt, params):
            aufrufe.append(prompt)
            return FixtureAdapter("stop").run(prompt, params)

    vorher = _zustand(ws, journal)
    with pytest.raises(SuggestError) as exc:
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=Zaehler())
    assert "transcript.confirmed" in str(exc.value)
    assert aufrufe == [], "der Adapter lief ohne Gate"
    assert _zustand(ws, journal) == vorher


def test_a_run_that_started_before_the_decision_is_not_authorised(tmp_path):
    """Herkunft ``test_corsia.sh:95``: ein vor dem Gate begonnener Lauf wird nicht belegt."""
    ws, journal, _ = _welt(tmp_path)
    vorher = _zustand(ws, journal)
    with pytest.raises(SuggestError) as exc:
        run_l1_suggest(
            _ctx(ws, journal), _view(ws, journal), clock=lambda: "2026-09-01T10:59:59+00:00"
        )
    assert "rückwirkend" in str(exc.value) or "autorisiert" in str(exc.value)
    assert _zustand(ws, journal) == vorher


def test_a_production_profile_without_a_model_toml_gets_no_adapter(tmp_path):
    """Kein Adapter, und die Meldung nennt den erwarteten Pfad.

    Der Name des Falls sagt jetzt die Bedingung mit: Seit dem Ollama-Adapter
    entscheidet die DATENWURZEL, welcher Adapter läuft, und nicht mehr allein
    das Profil. Ohne ``_governance/model.toml`` gibt es für ein
    Produktionsprofil keinen — nicht „noch keinen", sondern keinen, denn ein
    Aufgezeichneter, der reale Transkripte „kodiert", wäre eine Attrappe mit
    echtem Beleg.

    Der Pfad steht in der Meldung, weil „es gibt keinen" ohne ihn nicht
    handlungsfähig macht: Der Operator soll sehen, WO die Entscheidung
    hingehört, nicht raten müssen.
    """
    from dataclasses import replace

    ws, journal, _ = _welt(tmp_path)
    produktiv = Workspace(ws.root, replace(ws.profile, production=True))
    with pytest.raises(SuggestError) as exc:
        l1_suggest.adapter_for(produktiv, {})
    text = str(exc.value)
    assert "keinen Modelladapter" in text, text
    assert str(produktiv.governance / "model.toml") in text, text


# ------------------------------------------------- Zusicherung 3: der saubere Lauf


def test_a_clean_run_writes_bytes_receipt_and_anchor_and_makes_the_artifact_usable(tmp_path):
    ws, journal, rev = _welt(tmp_path)
    ergebnis = run_l1_suggest(_ctx(ws, journal), _view(ws, journal))
    assert ergebnis.written and ergebnis.suggestions == 4 and ergebnis.finish_reason == "stop"

    arten = [e.kind for e in journal][-3:]
    assert arten == ["artifact.produced", "receipt.recorded", "anchor.checked"], arten
    beleg = [e for e in journal if e.kind == "receipt.recorded"][-1].payload
    assert beleg["step"] == "l1.suggest" and beleg["kind"] == "model"
    assert beleg["output_sha256"] == ergebnis.artifact_sha256
    assert beleg["inputs"]["transcript.revision"] == rev.sha256
    assert (
        beleg["authorisation"]
        == _view(ws, journal).effective_decision_by_artifact["transcript.confirmed"].id
    )
    assert beleg["authorised_at"] == ENTSCHIEDEN_AM
    assert beleg["params"]["model"] == FIXTURE_MODEL

    view = _view(ws, journal)
    assert view.findings == []
    assert "l1.suggestions" in view.have
    zustand = view.artifacts["l1.suggestions"].to_json()
    assert (zustand["source_binding"], zustand["derivation_state"]) == ("bound", "current")
    assert [s.name for s in view.graph.next_steps(view.have)] == ["l1.coverage"]


def test_every_suggestion_carries_an_anchor_on_the_confirmed_revision(tmp_path):
    ws, journal, rev = _welt(tmp_path)
    ergebnis = run_l1_suggest(_ctx(ws, journal), _view(ws, journal))
    with ws.store().open_verified(ergebnis.artifact_sha256) as handle:
        obj = json.loads(handle.read())
    assert obj["schema"] == l1_suggest.SCHEMA and obj["revision_sha256"] == rev.sha256
    text = rev.normalized
    for s in obj["suggestions"]:
        anker = s["anchor"]
        assert anker["transcript_sha256"] == rev.sha256
        assert text[anker["start"] : anker["end"]] == anker["quote"]
        assert anker["quote"] == SEGMENTE[s["segment_index"]].text
        assert anker["source"] == l1_suggest.ANCHOR_SOURCE


def test_a_second_clean_run_changes_nothing(tmp_path):
    ws, journal, _ = _welt(tmp_path)
    erster = run_l1_suggest(_ctx(ws, journal), _view(ws, journal))
    zustand = _zustand(ws, journal)
    zweiter = run_l1_suggest(_ctx(ws, journal), _view(ws, journal))
    assert zweiter.artifact_sha256 == erster.artifact_sha256
    assert zweiter.written is False and _zustand(ws, journal) == zustand


def test_an_entry_that_still_carries_a_quote_falls_because_the_contract_has_none(tmp_path):
    """Der alte Vertrag rutscht nicht durch. Er faellt, und zwar auffaellig.

    Ein Modell auf der alten Anweisung schickt weiter ``quote``. Wuerde das
    Feld stillschweigend verworfen, liefe der Record durch, der Beleg truege
    eine serverseitig gesetzte Spanne, und niemand saehe, dass das Modell eine
    ganz andere Stelle gemeint hat. Der Widerspruch soll am Eingang stehen,
    nicht im Katalog.
    """
    ws, journal, _ = _welt(tmp_path)

    class AlterVertrag:
        name = FIXTURE_MODEL
        params = fixture_params("stop")

        def run(self, prompt, params):
            zeile = json.dumps(
                {"results": [{"segment": 1, "code": "L1.01", "quote": SEGMENTE[1].text}]}
            )
            return ModelResponse(zeile + "\n", "stop", 5, "d" * 64)

    vorher = _zustand(ws, journal)
    with pytest.raises(SuggestError) as exc:
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=AlterVertrag())
    assert "genau segment und code" in str(exc.value), exc.value
    assert _zustand(ws, journal) == vorher


def test_an_unknown_extra_field_falls_and_the_message_carries_no_transcript_text(tmp_path):
    """Ein Feld, das der Vertrag nicht kennt, ist keine Zugabe, sondern ein Befund.

    Und die Meldung nennt die Zeilennummer, nicht ihren Inhalt: Fehlertexte
    laufen in Logs und Berichte, Transkripttext gehoert in die Datenwurzel
    (dieselbe Regel wie in ``domain/anchor.py``).
    """
    ws, journal, _ = _welt(tmp_path)

    class Zusatz:
        name = FIXTURE_MODEL
        params = fixture_params("stop")

        def run(self, prompt, params):
            zeile = json.dumps(
                {
                    "results": [
                        {"segment": 3, "code": "L1.01", "confidence": 0.9, "note": "GEHEIMWORT"}
                    ]
                }
            )
            return ModelResponse(zeile + "\n", "stop", 5, "d" * 64)

    vorher = _zustand(ws, journal)
    with pytest.raises(SuggestError) as exc:
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=Zusatz())
    assert "Ergebniseintrag 1" in str(exc.value) and "GEHEIMWORT" not in str(exc.value)
    assert _zustand(ws, journal) == vorher


def test_the_anchor_is_the_segment_span_and_not_something_the_model_chose():
    """Die Spanne kommt aus der Fassung, nicht aus der Antwort.

    Gemessen gegen ``_segment_spans``: Start und Ende jedes Ankers sind genau
    die Grenzen des genannten Segments. Der einzige Beitrag des Modells ist
    die Segmentnummer und der Code -- zwei Zeichenketten, die nichts ueber
    eine Textstelle behaupten koennen.
    """
    rev = _revision()
    spans = l1_suggest._segment_spans(rev)
    vorschlaege = l1_suggest.anchor_suggestions(
        rev, [{"segment": 3, "code": "L1.01"}, {"segment": 0, "code": "L1.02"}]
    )
    assert [v.segment_index for v in vorschlaege] == [3, 0]
    for v in vorschlaege:
        assert (v.anchor.start, v.anchor.end) == spans[v.segment_index]
        assert v.anchor.quote == SEGMENTE[v.segment_index].text


def test_a_segment_that_does_not_exist_still_fails_the_whole_run():
    """Die eine Zusage, die das Modell noch brechen kann, bleibt scharf."""
    with pytest.raises(SuggestError) as exc:
        l1_suggest.anchor_suggestions(_revision(), [{"segment": 99, "code": "L1.01"}])
    assert "Segment 99" in str(exc.value) and "nicht gibt" in str(exc.value)


def test_a_segment_without_text_has_no_place_to_anchor_and_is_a_finding():
    """Leerer Segmenttext ist erlaubt (``revision_serialization``, nichtleer=False).

    Ohne Wache liefe das in einen ``ValueError`` aus ``Anchor.create`` -- ein
    Traceback fuer einen Zustand, den die Projektion ausdruecklich zulaesst.
    Ein Befund mit Segmentnummer ist das, was ein Operator lesen kann.
    """
    leer = (
        SEGMENTE[0],
        Segment(1, 5600, 13400, "", "ZEITZEUGIN", "deu"),
    )
    with pytest.raises(SuggestError) as exc:
        l1_suggest.anchor_suggestions(_revision(leer), [{"segment": 1, "code": "L1.01"}])
    assert "Segment 1" in str(exc.value) and "keinen Text" in str(exc.value)


def test_the_artifact_says_which_half_is_the_models_and_which_is_not(tmp_path):
    """Zwei Stellen, ein Satz: der Code ist vom Modell, die Spanne ist es nicht.

    An der ZEILE, weil eine Zeile den Weg allein geht -- im Review, im
    Katalog, in einem Auszug. Wer dort ein vollstaendiges Segment als Zitat
    liest, haelt es sonst fuer die Stelle, die das Modell gewaehlt hat.
    Und einmal im KOPF, weil die Arbeitsteilung fuer den ganzen Lauf gilt und
    nicht je Vorschlag neu verhandelt wird.
    """
    ws, journal, _ = _welt(tmp_path)
    ergebnis = run_l1_suggest(_ctx(ws, journal), _view(ws, journal))
    with ws.store().open_verified(ergebnis.artifact_sha256) as handle:
        obj = json.loads(handle.read())

    assert obj["provenance"] == {"code": "model", "anchor": l1_suggest.ANCHOR_SOURCE}
    assert obj["suggestions"], obj
    for s in obj["suggestions"]:
        assert s["anchor"]["source"] == l1_suggest.ANCHOR_SOURCE, s


# ------------------------------------------------- über continue, mit und ohne Grenze


def test_continue_reports_the_truncated_run_as_a_stop_with_the_contract_wording(tmp_path):
    ws, journal, _ = _welt(tmp_path)
    ctx = _ctx(ws, journal, fixture="length")
    graph = build_graph(ws.profile)
    outcome = continue_record(
        ctx, graph=graph, registry=REGISTRY, view_of=lambda: _view(ws, journal)
    )
    report = continue_report(outcome, ctx, REGISTRY)
    assert outcome.executed == () and outcome.failure_kind == "SuggestError"
    assert report.status is Status.STOP and report.reason_code == "STOP_CONTINUE_HANDLER"
    assert "finish_reason='length'" in report.reason and report.changed == []
    assert report.details["failure_kind"] == "SuggestError"


def test_continue_runs_the_model_and_coverage_and_halts_at_review(tmp_path):
    ws, journal, _ = _welt(tmp_path)
    ctx = _ctx(ws, journal, fixture="stop")
    graph = build_graph(ws.profile)
    outcome = continue_record(
        ctx, graph=graph, registry=REGISTRY, view_of=lambda: _view(ws, journal)
    )
    report = continue_report(outcome, ctx, REGISTRY)
    assert outcome.executed == ("l1.suggest", "l1.coverage")
    assert [s.name for s in outcome.gates] == ["l1.review"]
    assert report.reason_code == "ACTION_CONTINUE_GATE"
    assert str(journal.path) in report.changed


@pytest.fixture
def welt(tmp_path: Path):
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"

    def run(*args: str):
        return cli_keyed(*args, root=wurzel, key=key)

    assert run("init").returncode == 0
    rev = _revision()
    assert place_object(wurzel, canonical_revision_bytes(rev)) == rev.sha256
    marker_bytes, decision = _confirmation(
        Workspace(wurzel, Profile.load(PROFIL / "profile.toml")), rev
    )
    marker = place_object(wurzel, marker_bytes)
    forge_keyed(
        wurzel,
        key,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "transcript.revision", "sha256": rev.sha256},
            },
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "transcript.confirmed", "sha256": marker},
            },
            {"kind": "decision.recorded", "payload": decision},
            {
                "kind": "anchor.checked",
                "payload": {"artifact": "transcript.confirmed", "outcome": "exact"},
            },
        ],
    )
    return wurzel, key, run


def test_demo_moment_3_over_the_cli_the_run_fails_and_writes_nothing(welt):
    wurzel, _, run = welt
    davor = journal_path(wurzel).read_bytes()
    ergebnis = run("continue", RECORD, "--confirm", "--fixture", "length")
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 1, ergebnis.stdout
    assert zeilen["STATUS"].startswith("STOP") and "finish_reason='length'" in zeilen["STATUS"]
    assert zeilen["CHANGED"] == "keine"
    assert zeilen["CHECK"].endswith(" status")
    assert journal_path(wurzel).read_bytes() == davor


def test_over_the_cli_the_clean_run_carries_the_chain_to_coverage(welt):
    wurzel, _, run = welt
    ergebnis = run("continue", RECORD, "--confirm")
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert "Ausgeführt: l1.suggest" in zeilen["STATUS"] and "l1.coverage" in zeilen["STATUS"]
    assert zeilen["NEXT"].endswith(f"l1 review {RECORD}"), zeilen["NEXT"]
    assert str(journal_path(wurzel)) in zeilen["CHANGED"]
    status = json.loads(run("status", "--json").stdout)["details"]["records"][0]
    assert status["artifacts"]["l1.suggestions"]["status"] == "READY", status["artifacts"]
    assert status["findings"] == []


def test_the_next_after_a_deferred_model_step_runs_as_it_stands(welt):
    wurzel, _, run = welt
    erster = report_lines(run("continue", RECORD).stdout)
    tokens = shlex.split(erster["NEXT"])
    assert tokens[-2:] == [RECORD, "--confirm"], erster
    zweiter = run(*[t for t in tokens[1:] if t not in ("--profile", "sandbox")])
    assert zweiter.returncode == 3, zweiter.stdout
    assert "Ausgeführt: l1.suggest" in report_lines(zweiter.stdout)["STATUS"]


# ------------------------------------------------- Blockvertrag, Regie 07.09.2026


def _many_segments(count):
    return tuple(Segment(i, i * 1000, (i + 1) * 1000, "Ja.", "A", "deu") for i in range(count))


class _BlockFixture(FixtureAdapter):
    def __init__(self, transform=None):
        super().__init__()
        self.calls = []
        self.transform = transform

    def run(self, prompt, params):
        self.calls.append((prompt, params))
        response = super().run(prompt, params)
        return self.transform(len(self.calls), response) if self.transform else response


def test_65_segments_use_two_calls_and_global_ordered_suggestion_ids(tmp_path):
    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(65))

    def reverse_rows(n, response):
        obj = json.loads(response.text)
        obj["results"].reverse()
        return replace(response, text=json.dumps(obj))

    adapter = _BlockFixture(reverse_rows)
    result = run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2 and result.suggestions == 65
    with ws.store().open_verified(result.artifact_sha256) as handle:
        obj = json.load(handle)
    assert [s["segment_index"] for s in obj["suggestions"]] == list(range(65))
    assert [s["id"] for s in obj["suggestions"]] == [f"S{i:03d}" for i in range(1, 66)]
    assert all(s["anchor"]["quote"] == "Ja." for s in obj["suggestions"])


def test_last_block_prompt_has_its_own_count_and_span(tmp_path):
    ws, journal, rev = _welt(tmp_path, segmente=_many_segments(65))
    adapter = _BlockFixture()
    run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    head, _, body = adapter.calls[1][0].partition("\n\n")
    expected_head = l1_suggest.build_prompt(rev).partition("\n\n")[0]
    assert head == expected_head.replace("genau 65 Segmente", "genau 1 Segmente")
    data = json.loads(body)
    assert data["block"] == {"index": 2, "count": 2, "first": 64, "last": 64}
    assert [s["index"] for s in data["segments"]] == [64]
    assert data["revision_sha256"] == rev.sha256
    assert set(data) == {"task", "revision_sha256", "projection_version", "segments", "block"}


def test_an_id_from_another_block_is_foreign_and_nothing_is_written(tmp_path):
    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(65))

    def foreign_id(n, response):
        return replace(response, text=_document([*range(63), 64]))

    adapter = _BlockFixture(foreign_id)
    before = _zustand(ws, journal)
    with pytest.raises(SuggestError, match=r"Block 1/2 .*fremd \[64\]") as error:
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert str(error.value).endswith("Kein Teilergebnis, nichts geschrieben.")
    assert len(adapter.calls) == 1 and _zustand(ws, journal) == before


def test_second_block_length_checks_receipt_before_parsing_and_writes_nothing(
    tmp_path, monkeypatch
):
    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(65))
    parsed = []
    parse = l1_suggest.parse_answer

    def tracked_parse(text, expected):
        parsed.append(text)
        return parse(text, expected)

    def length(n, response):
        return replace(response, finish_reason="length", text="GEHEIMWORT") if n == 2 else response

    monkeypatch.setattr(l1_suggest, "parse_answer", tracked_parse)
    adapter = _BlockFixture(length)
    before = _zustand(ws, journal)
    with pytest.raises(SuggestError, match="Block 2/2 .*Segmente 64 bis 64.*length") as error:
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2 and len(parsed) == 1
    assert "GEHEIMWORT" not in str(error.value)
    assert str(error.value).endswith("Kein Teilergebnis, nichts geschrieben.")
    assert _zustand(ws, journal) == before


def test_block_requests_cover_the_record_and_bind_the_whole_plan(tmp_path, monkeypatch):
    ws, journal, rev = _welt(tmp_path, segmente=_many_segments(130))
    adapter = _BlockFixture()
    receipts = []
    receipt = l1_suggest._receipt

    def tracked_receipt(**kwargs):
        result = receipt(**kwargs)
        receipts.append(result)
        return result

    monkeypatch.setattr(l1_suggest, "_receipt", tracked_receipt)
    times = [f"2026-09-07T12:00:0{i}+00:00" for i in range(3)]
    clock = iter(times)
    before_events = len(list(journal))
    before_objects = len(list(ws.objects.iterdir()))
    result = run_l1_suggest(
        _ctx(ws, journal), _view(ws, journal), adapter=adapter, clock=lambda: next(clock)
    )
    with ws.store().open_verified(result.artifact_sha256) as handle:
        obj = json.load(handle)
    requests = obj["requests"]
    assert obj["schema"] == "ohpipe.l1.suggestions.v3"
    assert len(requests) == len(adapter.calls) == 3
    assert all(params is adapter.calls[0][1] for _, params in adapter.calls)
    assert [i for r in requests for i in range(r["first"], r["last"] + 1)] == list(range(130))
    assert [r["block"] for r in requests] == [1, 2, 3]
    assert [r["count"] for r in requests] == [3, 3, 3]
    assert [r["started_at"] for r in requests] == times
    assert all(
        set(r)
        == {
            "kind",
            "segments",
            "response_text",
            "receipt",
            "block",
            "count",
            "first",
            "last",
            "prompt_sha256",
            "finish_reason",
            "output_tokens",
            "started_at",
        }
        for r in requests
    )
    hashes = [sha256_text(prompt) for prompt, _ in adapter.calls]
    assert [r["prompt_sha256"] for r in requests] == hashes
    expected = sha256_json({"block_size": 64, "prompts": hashes})
    beleg = [e.payload for e in journal if e.kind == "receipt.recorded"][-1]
    assert obj["prompt_plan_sha256"] == beleg["prompt_sha256"] == expected
    assert receipts[-1].output_tokens == sum(r["output_tokens"] for r in requests)
    assert receipts[-1].started_at == times[0]
    assert receipts[-1].inputs["transcript.revision"] == rev.sha256
    assert beleg["code_version"] == "l1-suggest/8" and beleg["finish_reason"] == "stop"
    assert set(beleg) == {
        "artifact",
        "output_sha256",
        "inputs",
        "code_version",
        "kind",
        "step",
        "params",
        "prompt_sha256",
        "finish_reason",
        "authorisation",
        "authorisation_subject_sha256",
        "authorised_at",
        "started_at",
    }
    assert len(list(journal)) == before_events + 3
    assert len(list(ws.objects.iterdir())) == before_objects + 1


def test_second_clean_block_run_is_idempotent_across_different_start_times(tmp_path):
    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(65))
    adapter = _BlockFixture()
    first = run_l1_suggest(
        _ctx(ws, journal),
        _view(ws, journal),
        adapter=adapter,
        clock=lambda: "2026-09-07T12:00:00+00:00",
    )
    before = _zustand(ws, journal)
    second = run_l1_suggest(
        _ctx(ws, journal),
        _view(ws, journal),
        adapter=adapter,
        clock=lambda: "2026-09-07T13:00:00+00:00",
    )
    assert first.artifact_sha256 == second.artifact_sha256
    assert not second.written and second.changed == ()
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == before


@pytest.mark.parametrize("value", [None, 0, -1, True, 1.5, "64"])
def test_invalid_block_size_fails_before_any_adapter_call(tmp_path, value):
    ws, journal, _ = _welt(tmp_path)

    class InvalidParams(_BlockFixture):
        @property
        def params(self):
            extra = {"scenario": "stop"}
            if value is not None:
                extra["block_size"] = value
            return replace(super().params, extra=extra)

    adapter = InvalidParams()
    before = _zustand(ws, journal)
    with pytest.raises(SuggestError, match="block_size"):
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert adapter.calls == [] and _zustand(ws, journal) == before


def test_second_block_adapter_failure_is_private_and_atomic(tmp_path):
    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(65))

    def failure(n, response):
        if n == 2:
            raise RuntimeError("GEHEIMWORT")
        return response

    adapter = _BlockFixture(failure)
    before = _zustand(ws, journal)
    with pytest.raises(SuggestError, match="Block 2/2 .*Adapterabbruch") as error:
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert "GEHEIMWORT" not in str(error.value)
    assert str(error.value).endswith("Kein Teilergebnis, nichts geschrieben.")
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == before


def test_second_block_ollama_error_preserves_message_and_writes_nothing(tmp_path):
    from ohpipe.adapters.models.ollama import OllamaAdapterError

    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(65))
    message = "Laufzeit hat Kontext 4096 statt 8192 geladen. Kein Lauf, nichts geschrieben."

    def failure(n, response):
        if n == 2:
            raise OllamaAdapterError(message)
        return response

    adapter = _BlockFixture(failure)
    before = _zustand(ws, journal)
    with pytest.raises(SuggestError) as error:
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert "Block 2/2" in str(error.value)
    assert message in str(error.value)
    assert str(error.value).endswith("Kein Teilergebnis, nichts geschrieben.")
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == before


def test_second_block_anchor_failure_writes_nothing(tmp_path):
    segments = (*_many_segments(64), Segment(64, 64000, 65000, "", "A", "deu"))
    ws, journal, _ = _welt(tmp_path, segmente=segments)
    adapter = _BlockFixture()
    before = _zustand(ws, journal)
    with pytest.raises(SuggestError, match="Block 2/2 .*keinen Text"):
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == before


def test_second_block_missing_id_writes_nothing(tmp_path):
    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(65))
    adapter = _BlockFixture(lambda n, r: replace(r, text=_document([])) if n == 2 else r)
    before = _zustand(ws, journal)
    with pytest.raises(SuggestError, match=r"Block 2/2 .*fehlend \[64\]"):
        run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == before


@pytest.mark.parametrize("finish", ["end_turn", "eos", "stop_sequence"])
def test_allowlisted_block_finishes_are_preserved_with_aggregate_stop(tmp_path, finish):
    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(65))
    adapter = _BlockFixture(lambda n, r: replace(r, finish_reason=finish))
    result = run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    with ws.store().open_verified(result.artifact_sha256) as handle:
        obj = json.load(handle)
    assert [r["finish_reason"] for r in obj["requests"]] == [finish, finish]
    assert result.finish_reason == "stop"
    assert [e.payload["finish_reason"] for e in journal if e.kind == "receipt.recorded"] == ["stop"]


def test_block_size_comes_from_params_and_spans_follow_actual_indices(tmp_path):
    segments = tuple(Segment(i, i * 1000, (i + 1) * 1000, "Ja.", "A", "deu") for i in range(3))
    ws, journal, _ = _welt(tmp_path, segmente=segments)

    class SmallBlocks(_BlockFixture):
        @property
        def params(self):
            return replace(super().params, extra={"scenario": "stop", "block_size": 2})

    adapter = SmallBlocks()
    result = run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    with ws.store().open_verified(result.artifact_sha256) as handle:
        obj = json.load(handle)
    assert len(adapter.calls) == 2
    assert [s["segment_index"] for s in obj["suggestions"]] == [0, 1, 2]
    assert [(r["first"], r["last"]) for r in obj["requests"]] == [(0, 1), (2, 2)]
    assert obj["prompt_plan_sha256"] == sha256_json(
        {"block_size": 2, "prompts": [sha256_text(p) for p, _ in adapter.calls]}
    )


# ------------------------------------------------- Codebuchvertrag, Regie 07.09.2026


def _codebook_world(tmp_path, count=4):
    from .test_codebook import _write_book

    ws, journal, rev = _welt(tmp_path, segmente=_many_segments(count))
    path = tmp_path / "profile" / "profile.toml"
    book = _write_book(path.parent / "book.toml")
    path.write_text((PROFIL / "profile.toml").read_text() + '\ncodebook = "book.toml"\n')
    ws = replace(ws, profile=Profile.load(path))
    ctx = replace(_ctx(ws, journal), profile_arg=str(path))
    return ws, journal, rev, ctx, book


def _coded_response(n, response):
    obj = json.loads(response.text)
    for row in obj["results"]:
        row["code"] = "UNGEKLAERT" if row["segment"] % 2 else "AA"
    return replace(response, text=json.dumps(obj))


def test_codebook_10_foreign_code_rejects_whole_block_without_l1_writes(tmp_path, monkeypatch):
    ws, journal, _, ctx, book = _codebook_world(tmp_path, count=65)
    # Ungültiges Codebuch hält vor Adapterkonstruktion und vor Store.put.
    valid = book.read_bytes()
    book.write_text("not = [valid")
    before = _zustand(ws, journal)

    def forbidden(*args, **kwargs):
        pytest.fail("Adapter vor Codebuchprüfung berührt")

    monkeypatch.setattr(l1_suggest, "adapter_for", forbidden)
    with pytest.raises(SuggestError, match="TOML"):
        run_l1_suggest(ctx, _view(ws, journal))
    assert _zustand(ws, journal) == before
    book.write_bytes(valid)

    def foreign(n, response):
        response = _coded_response(n, response)
        if n == 2:
            obj = json.loads(response.text)
            obj["results"][0]["code"] = "FREMD"
            return replace(response, text=json.dumps(obj))
        return response

    adapter = _BlockFixture(foreign)
    events = journal.path.read_bytes()
    with pytest.raises(SuggestError, match="Block 2/2 .*Segmente 64 bis 64.*FREMD") as error:
        run_l1_suggest(ctx, _view(ws, journal), adapter=adapter)
    assert str(error.value).endswith("Kein Teilergebnis, nichts geschrieben.")
    assert len(adapter.calls) == 2
    added = journal.path.read_bytes()[len(events) :].splitlines()
    assert len(added) == 1 and json.loads(added[0])["kind"] == "input.observed"
    assert json.loads(added[0])["payload"]["role"] == "l1.codebook"
    # (4f) verlangt das Eingabeobjekt bereits vor Block 1. Kein Vorschlagsobjekt.
    book_sha = l1_suggest.sha256_bytes(valid)
    assert set(p.name for p in ws.objects.iterdir()) == set(before[1]) | {book_sha}
    # Bei bereits gesicherter Eingabe sind Store UND Journal bytegleich.
    before = _zustand(ws, journal)
    with pytest.raises(SuggestError, match="FREMD"):
        run_l1_suggest(ctx, _view(ws, journal), adapter=_BlockFixture(foreign))
    assert _zustand(ws, journal) == before
    # Auch eine vertragswidrige Freitextantwort darf nicht in den Halt gelangen.
    secret = "Synthetischer vertraulicher Testinhalt."
    with pytest.raises(SuggestError, match="keine kanonische Codebuch-ID") as error:
        l1_suggest.parse_answer(
            json.dumps({"results": [{"segment": 0, "code": secret}]}), [0], frozenset({"AA"})
        )
    assert secret not in str(error.value)


def test_codebook_11_ungeklaert_gets_normal_segment_anchor(tmp_path):
    ws, journal, rev, ctx, _ = _codebook_world(tmp_path)
    result = run_l1_suggest(ctx, _view(ws, journal), adapter=_BlockFixture(_coded_response))
    with ws.store().open_verified(result.artifact_sha256) as handle:
        obj = json.load(handle)
    assert obj["schema"] == "ohpipe.l1.suggestions.v3"
    assert "codebook" not in obj and "l1.codebook" not in obj
    for suggestion, segment in zip(obj["suggestions"], rev.segments, strict=True):
        assert suggestion["code"] == ("UNGEKLAERT" if segment.index % 2 else "AA")
        assert suggestion["anchor"]["source"] == "segment_span"
        assert suggestion["anchor"]["quote"] == segment.text
    assert _view(ws, journal).facts["l1.suggestions"].sha256 == result.artifact_sha256


def test_codebook_12_bytes_precede_model_and_digest_is_receipt_input(tmp_path, monkeypatch):
    from ohpipe.application.codebook import load_codebook

    ws, journal, rev, ctx, book = _codebook_world(tmp_path)
    digest = l1_suggest.sha256_bytes(book.read_bytes())
    adapter = _BlockFixture(_coded_response)

    def factory(ws, options, *, schema):
        with ws.store().open_verified(digest) as handle:
            assert handle.read() == book.read_bytes()
        assert schema == l1_suggest.answer_schema(load_codebook(book))
        return adapter

    monkeypatch.setattr(l1_suggest, "adapter_for", factory)
    result = run_l1_suggest(ctx, _view(ws, journal))
    receipt = [e.payload for e in journal if e.kind == "receipt.recorded"][-1]
    assert receipt["inputs"] == {
        "transcript.revision": rev.sha256,
        "transcript.confirmed": _view(ws, journal).facts["transcript.confirmed"].sha256,
        "l1.codebook": digest,
    }
    assert receipt["code_version"] == "l1-suggest/8"
    assert receipt["output_sha256"] == result.artifact_sha256
    assert "codebook" not in receipt and "l1.codebook" not in receipt


def test_codebook_13_open_coding_keeps_two_inputs_and_original_schema(tmp_path):
    ws, journal, rev = _welt(tmp_path)
    schema_bytes = json.dumps(l1_suggest.ANSWER_SCHEMA, sort_keys=True).encode()
    assert l1_suggest.answer_schema() is l1_suggest.ANSWER_SCHEMA
    run_l1_suggest(_ctx(ws, journal), _view(ws, journal))
    receipt = [e.payload for e in journal if e.kind == "receipt.recorded"][-1]
    assert receipt["inputs"] == {
        "transcript.revision": rev.sha256,
        "transcript.confirmed": _view(ws, journal).facts["transcript.confirmed"].sha256,
    }
    assert json.dumps(l1_suggest.answer_schema(), sort_keys=True).encode() == schema_bytes


def test_codebook_14_same_book_same_prompt_digest_changed_book_changes_digest(tmp_path):
    ws, journal, _, ctx, book = _codebook_world(tmp_path, count=65)
    hashes = []
    for n in range(3):
        if n == 2:
            book.write_text(
                book.read_text().replace("Synthetische Definition.", "Andere Definition.")
            )
        adapter = _BlockFixture(_coded_response)
        result = run_l1_suggest(ctx, _view(ws, journal), adapter=adapter)
        with ws.store().open_verified(result.artifact_sha256) as handle:
            obj = json.load(handle)
        # P2 vergleicht alle Belegeingaben einschließlich Codebuch: Lauf 2 ist idempotent.
        assert len(adapter.calls) == (0 if n == 1 else 2)
        for prompt, _ in adapter.calls:
            assert "Codebuch:" in prompt.partition("\n\n")[0]
        receipt = [e.payload for e in journal if e.kind == "receipt.recorded"][-1]
        assert receipt["prompt_sha256"] == obj["prompt_plan_sha256"]
        hashes.append(receipt["prompt_sha256"])
    assert hashes[0] == hashes[1] and hashes[1] != hashes[2]
