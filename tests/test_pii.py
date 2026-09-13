"""Span, SpanSet und bind() im Normalbetrieb.

``test_pseudonymisation_forgery.py`` prüft die Angriffe. Diese Datei prüft die
Verträge — und vor allem die eine Regel, die man an einem Angriffstest nicht
sieht: **Es gibt keine Oberflächenform.** Nicht im Span, nicht im JSON, nicht
in einer Fehlermeldung. Eine Ausnahme, die den abgelehnten Wert ausgibt, hat
ihn in jedes Log geschrieben, das sie aufnimmt.

Nicht geprüft wird hier Erkennungsqualität. Kein Span in dieser Datei stammt
aus einem Modell; sie werden alle von Hand gesetzt.
"""

from __future__ import annotations

import math

import pytest

from ohpipe.domain.cue import CueDocument, CueFormat
from ohpipe.domain.pii import (
    BoundSpan,
    BoundSpanSet,
    EntityType,
    OffsetUnit,
    Span,
    SpanConflict,
    SpanError,
    SpanOutOfRange,
    SpanRevisionMismatch,
    SpanSet,
    mention_id,
)

SRT = (
    "1\n00:00:01,000 --> 00:00:04,000\n"
    "Marie Schmitz kam aus Ettelbruck.\n\n"
    "2\n00:00:04,000 --> 00:00:08,000\n"
    "Sie war die Erzieherin.\n"
)


@pytest.fixture
def doc() -> CueDocument:
    return CueDocument.parse(SRT, CueFormat.SRT)


def span(doc: CueDocument, start: int, end: int, **kw) -> Span:
    felder = {
        "input_sha256": doc.payload_sha256(kw.pop("cue", 0)),
        "unit": OffsetUnit.CODEPOINT,
        "cue_index": 0,
        "start": start,
        "end": end,
        "entity_type": "PERSON",
        "recogniser": "test",
    }
    felder.update(kw)
    return Span(**felder)


# --------------------------------------------------------- strikte Typen


@pytest.mark.parametrize(
    "feld,wert,label",
    [
        ("input_sha256", "zu kurz", "kein Hash"),
        ("input_sha256", "A" * 64, "Grossbuchstaben"),
        ("input_sha256", None, "None"),
        ("cue_index", -1, "negativ"),
        ("cue_index", True, "bool ist kein Index"),
        ("cue_index", None, "None"),
        ("cue_index", 1.0, "float"),
        ("end", "5", "String statt Zahl"),
        ("entity_type", "", "leer"),
        ("entity_type", "   ", "nur Leerzeichen"),
        ("recogniser", "", "leer"),
        ("confidence", 1.5, "ueber 1"),
        ("confidence", -0.1, "unter 0"),
        ("confidence", float("nan"), "NaN"),
        ("confidence", float("inf"), "unendlich"),
        ("confidence", True, "bool ist keine Konfidenz"),
    ],
)
def test_a_malformed_span_is_refused(doc, feld, wert, label):
    felder = {
        "input_sha256": doc.payload_sha256(0),
        "unit": OffsetUnit.CODEPOINT,
        "cue_index": 0,
        "start": 0,
        "end": 5,
        "entity_type": "PERSON",
        "recogniser": "test",
    }
    felder[feld] = wert
    with pytest.raises(SpanError):
        Span(**felder)


@pytest.mark.parametrize("start,end", [(5, 5), (9, 4), (0, 0)])
def test_an_empty_or_reversed_range_is_refused(doc, start, end):
    with pytest.raises(SpanOutOfRange):
        span(doc, start, end)


def test_bool_is_not_an_integer_index(doc):
    """``bool`` ist in Python ein ``int``. ``cue_index=True`` wäre sonst Cue 1,
    und niemand hätte das gewollt."""
    with pytest.raises(SpanError):
        span(doc, 0, 5, cue_index=True)


def test_confidence_defaults_and_is_stored_as_float(doc):
    assert span(doc, 0, 5).confidence == 1.0
    assert isinstance(span(doc, 0, 5, confidence=0).confidence, float)
    assert math.isclose(span(doc, 0, 5, confidence=0.25).confidence, 0.25)


# ------------------------------------------------------ JSON mit Allowlist


def test_json_round_trips(doc):
    s = span(doc, 0, 13)
    assert Span.from_json(s.to_json()) == s
    menge = SpanSet(doc.sha256, (s,))
    assert SpanSet.from_json(menge.to_json()) == menge


@pytest.mark.parametrize("leak", ["surface", "quote", "context", "replacement", "original", "text"])
def test_an_unknown_field_is_refused_without_echoing_anything(doc, leak):
    """Die Allowlist UND die Schweigepflicht.

    Eine erste Fassung nannte den abgelehnten Feldnamen, wenn er einem
    harmlosen Muster entsprach. Das genügt nicht: ``Marie_Schmitz`` und
    ``MarieSchmitz`` passen darauf. Die Regel lautet jetzt schlicht — bekannte
    Konstanten und erlaubte Werte dürfen genannt werden, abgelehnte Eingaben
    nicht.
    """
    payload = span(doc, 0, 13).to_json() | {leak: "Marie Schmitz"}
    with pytest.raises(SpanError) as exc:
        Span.from_json(payload)
    meldung = str(exc.value)
    assert "Marie Schmitz" not in meldung, "die Oberflächenform steht in der Meldung"
    assert "unerlaubte" in meldung or "unerlaubtes" in meldung
    assert "input_sha256" in meldung, "die erlaubten Felder werden nicht genannt"


def test_a_missing_required_field_is_refused(doc):
    payload = span(doc, 0, 13).to_json()
    del payload["entity_type"]
    with pytest.raises(SpanError) as exc:
        Span.from_json(payload)
    assert "entity_type" in str(exc.value)


@pytest.mark.parametrize("murks", [None, [], "text", 42])
def test_json_that_is_not_an_object_is_refused(murks):
    with pytest.raises(SpanError):
        Span.from_json(murks)
    with pytest.raises(SpanError):
        SpanSet.from_json(murks)


def test_a_spanset_only_holds_spans(doc):
    with pytest.raises(SpanError):
        SpanSet(doc.sha256, ({"start": 0},))
    with pytest.raises(SpanError):
        SpanSet("kein hash", ())


# --------------------------------------------------------------- Bindung


def test_bind_returns_canonically_sorted_spans(doc):
    zweiter = span(doc, 0, 3, cue=1, cue_index=1, input_sha256=doc.payload_sha256(1))
    erster = span(doc, 22, 32, entity_type="LOCATION")
    null = span(doc, 0, 13)
    gebunden = SpanSet(doc.sha256, (zweiter, erster, null)).bind(doc)
    assert [s.sort_key for s in gebunden] == sorted(s.sort_key for s in gebunden)
    assert [s.cue_index for s in gebunden] == [0, 0, 1]


def test_bind_checks_the_payload_hash_as_well_as_the_document_hash(doc):
    """Zwei Ebenen, und die strengere ist die äußere.

    Die Spanmenge bindet an den vollständigen Dokumenthash — sie ist eine
    Vollständigkeitsbehauptung über das Dokument. Der Payloadhash kommt
    zusätzlich, damit auch eine Spanmenge mit passendem Dokumenthash nicht auf
    eine andere Payloadfassung zeigen kann. Er ist **keine** Erlaubnis, einen
    alten Erkennungslauf für unveränderte Cues weiterzuverwenden.
    """
    falsch = span(doc, 0, 5, input_sha256=doc.payload_sha256(1))
    with pytest.raises(SpanRevisionMismatch):
        SpanSet(doc.sha256, (falsch,)).bind(doc)


def test_a_cue_that_does_not_exist_is_refused(doc):
    weit = span(doc, 0, 5, cue_index=99)
    with pytest.raises(SpanOutOfRange):
        SpanSet(doc.sha256, (weit,)).bind(doc)


def test_a_range_beyond_the_payload_is_refused(doc):
    zu_weit = span(doc, 0, len(doc.payloads()[0]) + 1)
    with pytest.raises(SpanOutOfRange):
        SpanSet(doc.sha256, (zu_weit,)).bind(doc)


def test_the_exact_end_of_a_payload_is_still_inside(doc):
    """Grenzfall in der harmlosen Richtung: Ein Name am Satzende darf nicht
    an einem Abzählfehler scheitern."""
    genau = span(doc, 0, len(doc.payloads()[0]))
    assert len(SpanSet(doc.sha256, (genau,)).bind(doc)) == 1


def test_byte_offsets_are_canonicalised_once(doc):
    payload = doc.payloads()[0]
    roh = payload.encode("utf-8")
    s = span(doc, 0, len(roh), unit=OffsetUnit.UTF8_BYTE)
    gebunden = SpanSet(doc.sha256, (s,)).bind(doc).spans[0]
    assert (gebunden.start, gebunden.end) == (0, len(payload))


def test_mixed_units_compare_only_after_canonicalisation():
    """Derselbe Textort, zweimal gemeldet — einmal in Bytes, einmal in
    Codepoints. Nach der Bindung ist das EIN Span, kein Konflikt."""
    text = "1\n00:00:01,000 --> 00:00:04,000\nMoien Lëtzebuerg hei.\n"
    d = CueDocument.parse(text, CueFormat.SRT)
    p = d.payloads()[0]
    roh = p.encode("utf-8")
    ab_cp, ab_b = p.index("Lëtzebuerg"), roh.index("Lëtzebuerg".encode())
    # Frueher stand hier `assert ab_cp != ab_b or True` — eine Zusicherung, die
    # NIE fehlschlagen kann. Ruff 0.16 hat sie gefunden (SIM222). Gemeint war,
    # dass die beiden Einheiten sich unterscheiden DUERFEN, aber nicht muessen;
    # das ist keine Zusicherung, sondern eine Voraussetzung des Falls. Also
    # steht sie jetzt als solche da — und prueft dabei etwas Echtes: In UTF-8
    # ist die Byte-Laenge von "Lëtzebuerg" groesser als die Codepoint-Laenge.
    assert len("Lëtzebuerg".encode()) > len("Lëtzebuerg")
    assert ab_cp <= ab_b, (ab_cp, ab_b)
    gemeinsam = dict(
        input_sha256=d.payload_sha256(0),
        cue_index=0,
        entity_type="LOCATION",
    )
    a = Span(
        unit=OffsetUnit.CODEPOINT,
        start=ab_cp,
        end=ab_cp + len("Lëtzebuerg"),
        recogniser="spacy",
        **gemeinsam,
    )
    b = Span(
        unit=OffsetUnit.UTF8_BYTE,
        start=ab_b,
        end=ab_b + len("Lëtzebuerg".encode()),
        recogniser="gliner",
        **gemeinsam,
    )
    gebunden = SpanSet(d.sha256, (a, b)).bind(d)
    assert len(gebunden) == 1, "dieselbe Stelle in zwei Einheiten wurde nicht erkannt"
    assert gebunden.spans[0].recognisers == ("gliner", "spacy")


def test_a_byte_offset_inside_a_character_is_refused():
    text = "1\n00:00:01,000 --> 00:00:04,000\nMoien Lëtzebuerg hei.\n"
    d = CueDocument.parse(text, CueFormat.SRT)
    mitten = d.payloads()[0].encode("utf-8").index("ë".encode()) + 1
    s = Span(
        input_sha256=d.payload_sha256(0),
        unit=OffsetUnit.UTF8_BYTE,
        cue_index=0,
        start=mitten,
        end=mitten + 4,
        entity_type="LOCATION",
        recogniser="test",
    )
    with pytest.raises(SpanOutOfRange):
        SpanSet(d.sha256, (s,)).bind(d)


# -------------------------------------------------------------- Konflikte


def test_identical_spans_of_the_same_type_merge(doc):
    """Zwei Erkenner, die dieselbe Stelle gleich beurteilen, sind eine
    Bestätigung — kein Konflikt und keine doppelte Entität im Bericht."""
    a = span(doc, 0, 13, recogniser="gliner")
    b = span(doc, 0, 13, recogniser="spacy")
    c = span(doc, 0, 13, recogniser="gliner")  # exaktes Duplikat
    gebunden = SpanSet(doc.sha256, (a, b, c)).bind(doc)
    assert len(gebunden) == 1
    assert gebunden.spans[0].recognisers == ("gliner", "spacy")


@pytest.mark.parametrize(
    "a_bereich,b_bereich,label",
    [
        ((0, 13), (5, 20), "teilweise Überlappung"),
        ((0, 20), (5, 10), "vollständig verschachtelt"),
        ((5, 10), (0, 20), "umgekehrt verschachtelt"),
        ((0, 13), (0, 20), "gleicher Beginn"),
    ],
)
def test_any_other_overlap_stops(doc, a_bereich, b_bereich, label):
    a = span(doc, *a_bereich, entity_type="PERSON")
    b = span(doc, *b_bereich, entity_type="LOCATION")
    with pytest.raises(SpanConflict):
        SpanSet(doc.sha256, (a, b)).bind(doc)


def test_adjacent_spans_are_allowed(doc):
    """``end == start`` überlappt nicht. Zwei Namen hintereinander sind der
    Normalfall, kein Konflikt."""
    a = span(doc, 0, 5)
    b = span(doc, 5, 13, entity_type="LOCATION")
    assert len(SpanSet(doc.sha256, (a, b)).bind(doc)) == 2


def test_the_same_range_in_two_cues_is_not_an_overlap(doc):
    """Cue-lokal heißt cue-lokal. Zwei Spans mit gleichen Zahlen in
    verschiedenen Cues haben nichts miteinander zu tun."""
    a = span(doc, 0, 5)
    b = span(doc, 0, 5, cue_index=1, input_sha256=doc.payload_sha256(1))
    assert len(SpanSet(doc.sha256, (a, b)).bind(doc)) == 2


def test_conflict_detection_is_order_independent(doc):
    """Die Adapterreihenfolge hat keinerlei Wirkung — auch nicht darauf,
    WELCHER Konflikt gemeldet wird."""
    a = span(doc, 0, 13, entity_type="PERSON", recogniser="spacy")
    b = span(doc, 5, 20, entity_type="LOCATION", recogniser="flair")
    meldungen = set()
    for reihenfolge in ((a, b), (b, a)):
        with pytest.raises(SpanConflict) as exc:
            SpanSet(doc.sha256, reihenfolge).bind(doc)
        meldungen.add(str(exc.value))
    assert len(meldungen) == 1, meldungen


# ------------------------------------------------------------ mention_id


def test_the_mention_id_is_deterministic_and_opaque(doc):
    a = mention_id(doc.sha256, 0, 0, 13, "PERSON")
    b = mention_id(doc.sha256, 0, 0, 13, "PERSON")
    assert a == b and a.startswith("MEN-")
    assert mention_id(doc.sha256, 0, 0, 13, "LOCATION") != a, "der Typ geht nicht ein"
    assert mention_id(doc.sha256, 1, 0, 13, "PERSON") != a, "das Cue geht nicht ein"


def test_the_same_place_in_two_units_gets_the_same_mention_id():
    """Die ID entsteht aus den KANONISCHEN Offsets. Sonst hinge die Identität
    einer Erwähnung davon ab, in welcher Einheit ein Erkenner meldet."""
    text = "1\n00:00:01,000 --> 00:00:04,000\nMoien Lëtzebuerg hei.\n"
    d = CueDocument.parse(text, CueFormat.SRT)
    p = d.payloads()[0]
    roh = p.encode("utf-8")
    gemeinsam = dict(input_sha256=d.payload_sha256(0), cue_index=0, entity_type="LOCATION")
    cp = Span(
        unit=OffsetUnit.CODEPOINT,
        start=p.index("Lëtzebuerg"),
        end=p.index("Lëtzebuerg") + 10,
        recogniser="spacy",
        **gemeinsam,
    )
    by = Span(
        unit=OffsetUnit.UTF8_BYTE,
        start=roh.index("Lëtzebuerg".encode()),
        end=roh.index("Lëtzebuerg".encode()) + 11,
        recogniser="flair",
        **gemeinsam,
    )
    erste = SpanSet(d.sha256, (cp,)).bind(d).spans[0]
    zweite = SpanSet(d.sha256, (by,)).bind(d).spans[0]
    assert erste.mention_id == zweite.mention_id


def test_a_bound_span_carries_no_surface_form(doc):
    """Die Kernregel, als Zusicherung über das Objekt selbst.

    Wer später ein Feld hinzufügt, in dem ein Klartext landen könnte, bricht
    diesen Test — und das ist der Zweck.
    """
    gebunden = SpanSet(doc.sha256, (span(doc, 0, 13),)).bind(doc)
    felder = set(BoundSpan.__dataclass_fields__) - {"_bound"}
    assert felder == {
        "mention_id",
        "cue_index",
        "start",
        "end",
        "entity_type",
        "recognisers",
    }, felder
    assert "Marie" not in repr(gebunden), repr(gebunden)


# ------------------- Klartextschmuggel über erlaubte Felder (Review 04.08.)


@pytest.mark.parametrize(
    "feld,wert",
    [
        ("entity_type", "Marie Schmitz"),
        ("entity_type", "PERSON Marie Schmitz"),
        ("entity_type", "person"),
        ("recogniser", "Frau Schmitz"),
        ("recogniser", "Marie Schmitz"),
        ("recogniser", "unbekannter-adapter"),
        ("recogniser", "marie.schmitz"),
        ("recogniser", "GLINER"),
    ],
)
def test_plaintext_cannot_be_smuggled_through_an_allowed_field(doc, feld, wert):
    """Die Allowlist verhinderte ZUSÄTZLICHE Felder, nicht Klartext in einem
    erlaubten.

    ``entity_type="Marie Schmitz"`` war ein gültiger, persistierbarer Span.
    Dagegen hilft keine Feldliste, sondern nur ein kontrolliertes Vokabular
    und eine Erkennerkennung statt Freitext.
    """
    with pytest.raises(SpanError):
        span(doc, 0, 5, **{feld: wert})


def test_a_plaintext_json_key_is_not_echoed_back(doc):
    """Auch der SCHLÜSSEL kann Klartext sein.

    ``{"Marie Schmitz": 1}`` hätte den Namen über die Fehlermeldung in jedes
    Log getragen, das sie aufnimmt. Die Allowlist prüft, was erlaubt ist — sie
    schweigt nicht von selbst über das Abgelehnte.
    """
    for schluessel in ("Marie Schmitz", "Marie_Schmitz", "MarieSchmitz", "schmitz"):
        payload = span(doc, 0, 13).to_json() | {schluessel: "Ettelbruck"}
        with pytest.raises(SpanError) as exc:
            Span.from_json(payload)
        meldung = str(exc.value)
        assert "arie" not in meldung, f"{schluessel!r}: der Name steht in der Meldung"
        assert "chmitz" not in meldung, f"{schluessel!r}: der Name steht in der Meldung"
        assert "Ettelbruck" not in meldung, schluessel


def test_a_missing_confidence_is_not_silently_one(doc):
    """Im persistierten Span ist die Konfidenz Pflicht.

    Sie still auf 1.0 zu setzen hieße, eine unsichere Erkennung als sichere zu
    lesen — und genau daran hängt später das typbezogene Leakage-Gate.
    """
    payload = span(doc, 0, 13).to_json()
    del payload["confidence"]
    with pytest.raises(SpanError):
        Span.from_json(payload)
    assert span(doc, 0, 13).confidence == 1.0, "der Konstruktor darf vorbelegen"


# ------------------- Bindung lässt sich nicht umgehen (Review 04.08.)


def test_a_bound_span_cannot_be_built_from_outside(doc):
    """Ein ``BoundSpan`` behauptet, gegen ein Dokument geprüft zu sein.

    Frei konstruierbar wäre das eine Behauptung ohne Deckung: rückwärts
    laufender Bereich, Cue 999, erfundene Mention-ID — und die nächste
    Funktion vertraut genau dieser Behauptung.
    """
    with pytest.raises(SpanError):
        BoundSpan(
            mention_id="MEN-frei-erfunden",
            cue_index=999,
            start=50,
            end=10,
            entity_type=EntityType.PERSON,
            recognisers=("spacy",),
        )
    with pytest.raises(SpanError):
        BoundSpanSet(document_sha256=doc.sha256, spans=())


def test_bind_is_the_only_producer(doc):
    gebunden = SpanSet(doc.sha256, (span(doc, 0, 13),)).bind(doc)
    assert isinstance(gebunden.spans[0], BoundSpan)
    assert gebunden.spans[0].entity_type is EntityType.PERSON


# ------------------------------------------------ UTF-8: die Gegenprobe


def test_a_byte_offset_ending_inside_a_character_is_refused():
    """Die fehlende Hälfte: Nicht nur der Beginn, auch das ENDE muss auf einer
    Zeichengrenze liegen."""
    text = "1\n00:00:01,000 --> 00:00:04,000\nMoien Lëtzebuerg hei.\n"
    d = CueDocument.parse(text, CueFormat.SRT)
    roh = d.payloads()[0].encode("utf-8")
    ab = roh.index("Lëtzebuerg".encode())
    mitten_im_ende = roh.index("ë".encode()) + 1
    s = Span(
        input_sha256=d.payload_sha256(0),
        unit=OffsetUnit.UTF8_BYTE,
        cue_index=0,
        start=ab,
        end=mitten_im_ende,
        entity_type=EntityType.LOCATION,
        recogniser="test",
        confidence=1.0,
    )
    with pytest.raises(SpanOutOfRange):
        SpanSet(d.sha256, (s,)).bind(d)


def test_the_mention_id_is_domain_separated():
    """``ohpipe:mention:v1`` steht im Hash.

    Ohne Domain Separation wäre derselbe Hash über dieselben Felder in einem
    anderen Kontext derselbe Wert — und eine spätere Änderung am Verfahren von
    außen nicht unterscheidbar.
    """
    import hashlib

    from ohpipe.domain.pii import MENTION_ID_DOMAIN

    ohne = "MEN-" + hashlib.sha256(b"a" * 64 + b"|0|0|5|PERSON").hexdigest()[:24]
    assert mention_id("a" * 64, 0, 0, 5, EntityType.PERSON) != ohne
    assert MENTION_ID_DOMAIN == "ohpipe:mention:v1"


def test_a_rejected_recogniser_id_is_not_echoed(doc):
    """``recogniser="marie.schmitz"`` passiert das Muster und stand vorher im
    Klartext in der Meldung. Genannt werden jetzt nur die bekannten Werte."""
    with pytest.raises(SpanError) as exc:
        span(doc, 0, 5, recogniser="marie.schmitz")
    meldung = str(exc.value)
    assert "marie" not in meldung.lower(), meldung
    assert "gliner" in meldung, "die bekannten Kennungen werden nicht genannt"


def test_the_binding_token_is_documented_as_accident_protection_only():
    """Ehrlichkeit über die eigene Schranke.

    ``dataclasses.replace`` übernimmt das Token, und der Wert ist importierbar.
    In Python lässt sich so keine Sicherheitsgrenze bauen — die Grenze liegt
    darin, dass kein öffentliches API ein ``BoundSpanSet`` entgegennimmt.
    Dieser Test hält fest, dass die Umgehung bekannt ist, statt sie als
    geschlossen auszugeben.
    """
    import dataclasses

    from ohpipe.domain.pii import _GEBUNDEN

    d = CueDocument.parse(SRT, CueFormat.SRT)
    echt = SpanSet(d.sha256, (span(d, 0, 13),)).bind(d).spans[0]
    umgangen = dataclasses.replace(echt, cue_index=999, start=50, end=10)
    assert umgangen.cue_index == 999, "replace() traegt das Token nicht mehr - Docstring pruefen"
    assert _GEBUNDEN is not None
