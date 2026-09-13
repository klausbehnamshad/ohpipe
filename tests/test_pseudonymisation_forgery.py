"""Die Fälschungstests zur Pseudonymisierung — vor dem ersten Produktcode.

Herkunft: ``docs/ATTACK-LIST_pseudonymisation.md`` (64 Angriffe in acht
Klassen), verbindlich gemacht durch ADR 0024 und ADR 0015.

**Sechsundzwanzig Fälle**, nicht vierundzwanzig:

    A1 A2 A4 A5 A6 A7 A8 · B1 B2 B3 B4 B5 · C1 C2 C3 C5 C6 C8 C9 ·
    D1 D2 D6 · E1 E2 E4 E6

`A7` und `A8` sind nachgetragen. In der Angriffsliste standen sie **weder**
unter den vierundzwanzig ersten Tests **noch** unter den achtunddreißig
zurückgestellten — 24 + 38 = 62, die Liste hat aber 64 Einträge. Beide sind
nicht harmlos: `A7` ist der Normalisierungsversatz zwischen Spanfassung und
Ankerfassung (derselbe Fehler, der im Vorgängersystem alle Coverage-Zahlen zu
Fiktion gemacht hätte), `A8` der cue-übergreifende Span, der den Zeitanker
zwischen zwei Payloads einschließt.

**Stand 04.08., nach Cue-Parser und Spanmodell: 9 grün, 30 rot.**

Grün: `A1` `A2` `A3` (Cue-Parser), `A7` `A8` `B1` `B3` `B4` (Span und
``bind()``), dazu ``test_d2`` — ein **Wächter**, kein Rotphasentest: Es gibt
keinen Side-by-side-Export, und der Test hält das so.

Rot, nach Ursache: fehlende Module (``adapters.pseudonymisation``,
``graph_for_profile``), fehlende Profilstrenge, und die Fälle, in denen die
CLI die gefälschte Darstellung wortlos annimmt.

Eine erste Fassung dieser Datei war an fünfzehn Stellen grün — weil sie nur
``returncode != 0`` prüfte und heute fast jede erfundene Ereignisart aus
IRGENDEINEM Grund rot wird. Ein Rotphasentest, der aus dem falschen Grund
grün ist, ist schlimmer als keiner. Geprüft wird deshalb der **Wortlaut des
Befunds**, nicht der Exitcode allein.

Der Import steht **in jedem Test** statt am Dateikopf. Am Kopf wäre die ganze
Datei ein einziger Sammelfehler beim Einsammeln, und sechsundzwanzig Fälle
wären ununterscheidbar. So scheitert jeder an seiner eigenen Sache.

**Drei Grenzen, bewusst getrennt:**

  ÜBER DIE CLI     Operatorvertrag betroffen — Exitcode, Sechszeiler, CHANGED:
                   `A4` `C3` `E1` `E2` `E6`
  ÜBER DAS REPLAY  Der Angreifer schreibt die persistierte Darstellung und
                   das Produkt liest sie: `A5` `B1` `B2` `B5` `D1` `D6`
  ÜBER DIE API     Der Angreifer IST der Aufrufer, die CLI kommt nicht vor:
                   `A1` `A2` `A6` `A7` `A8` `B3` `B4` `C1` `C2` `C5` `C6`
                   `C8` `C9` `D2` `E4`

**Was hier NICHT geprüft wird, und das steht auch an den Tests:** Kein Test
hier belegt Erkennungsqualität. Leakage je Entitätstyp (`F1`–`F9`) gehört in
das getrennte Evaluationslabor und braucht einen menschlich annotierten
Prüfkorpus; ein Fixture-Test darüber wäre die „Form stimmt, die Sache nicht"-
Falle. `D3`–`D5` gehören in die Review-UI-Runde, `H4` in Phase 4.

Das API, das diese Datei zum ersten Mal festschreibt::

    ohpipe.domain.cue
        CueDocument.parse(text: str, fmt: CueFormat) -> CueDocument
        .payloads() -> tuple[str, ...]        # NUR gesprochener Text
        .with_payloads(seq) -> CueDocument    # Struktur bleibt dieselbe
        .render() -> str                      # Struktur bytegleich zur Quelle
        CueStructureChanged                   # Ausgabe weicht strukturell ab

    ohpipe.domain.pii
        OffsetUnit.CODEPOINT | OffsetUnit.UTF8_BYTE   # versioniert, nie geraten
        Span(input_sha256, unit, cue_index, start, end, entity_type,
             recogniser, confidence, conflict)        # KEINE Oberflächenform
        SpanSet.from_json(payload) -> SpanSet          # fail-closed
        apply_spans(doc, spans, table) -> tuple[CueDocument, ReplacementReport]
        SpanError · SpanOutOfRange · SpanRevisionMismatch · SpanConflict

    ohpipe.adapters.pseudonymisation.table
        ReplacementTable.open(table_id, path, key_path) -> ReplacementTable
        .pseudonym_for(entity, entity_type) -> str
        .state_sha256 -> str
        TableError · TableInsideDataRoot · TableStateMismatch · TableMissing

Der erste Parameter von ``pseudonym_for`` ist **keine normalisierte
Namenszeichenkette**. Nach ADR 0025 ist er eine adjudizierte, opake
``EntityId``; die Umstellung von `A6`, `C1`, `C2` und `C9` geschieht mit dem
Resolver, vor ``apply_spans()``. Bis dahin stehen dort Platzhalter, und das
ist hier vermerkt statt stillschweigend.

Vokabular, das durchgehend gilt: Eine **Oberflächenform** ist der Klartext aus
dem Quelltranskript. Sie darf in keinem persistierten Artefakt stehen — nicht
in `pii.spans`, nicht im `replacement.report`, nicht in einem `Anchor`.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

from ._forge import REPO, cli, forge

#: Die Rotphase blockiert den Hauptlauf nicht mehr — aber sie wird auch nicht
#: weich. ``strict=True`` ist der Punkt: Der Fall wird ROT in dem Moment, in
#: dem er unerwartet besteht. Damit erzwingt der Marker, dass er beim Landen
#: der Implementierung entfernt wird, statt dass ein Angriff still grün wird
#: und niemand es merkt.
#:
#: Die bereits erfüllten Fälle tragen ihn NICHT (A1 A2 A3 A7 A8 B1 B3 B4 D2);
#: sie sind normale Tests und müssen grün bleiben.
OFFEN = pytest.mark.xfail(
    reason="ADR 0024/0025 — Angriff steht, Implementierung offen",
    strict=True,
)

# --------------------------------------------------------------- Fixtures

#: Ein Cue, dessen Zeitanker wie ein Datum aussieht UND dessen gesprochener
#: Text ein Datum enthält. Genau diese Kombination verlangt ADR 0024 §1: Nur
#: das zweite darf sich ändern.
VTT = """WEBVTT

NOTE Diese Zeile ist Struktur, kein gesprochener Text.

1
00:12:03.000 --> 00:12:09.500
Am 3. Oktober 1978 hat mich Marie Schmitz aus Ettelbruck abgeholt.

2
00:12:09.500 --> 00:12:14.000 align:start position:10%
Sie war die Erzieherin im Heim.
"""

SRT = """1
00:12:03,000 --> 00:12:09,500
Am 3. Oktober 1978 hat mich Marie Schmitz abgeholt.

2
00:12:09,500 --> 00:12:14,000
Sie war die Erzieherin im Heim.
"""


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def cue_module():
    """Der Cue-Parser. Existiert noch nicht."""
    import ohpipe.domain.cue as m

    return m


def pii_module():
    """Das Span-Modell. Existiert noch nicht."""
    import ohpipe.domain.pii as m

    return m


def table_module():
    """Der Tabellenadapter. Existiert noch nicht."""
    import ohpipe.adapters.pseudonymisation.table as m

    return m


def parsed(text: str = VTT, fmt: str = "vtt"):
    m = cue_module()
    return m.CueDocument.parse(text, m.CueFormat(fmt))


def a_table(tmp_path: Path):
    """Eine Tabelle AUSSERHALB der Datenwurzel, Schlüssel getrennt davon."""
    m = table_module()
    store = tmp_path / "secret-store"
    store.mkdir(parents=True, exist_ok=True)
    keys = tmp_path / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    return m.ReplacementTable.open(
        table_id="CHILDLUX-CORPUS-01",
        path=store / "replacements.enc",
        key_path=keys / "table.key",
    )


def findings_for(root: Path, *args: str) -> list[str]:
    """Die Befunde des ersten Records — oder ein aussagekräftiges Scheitern.

    Ein Test, der nur ``returncode != 0`` prüft, ist wertlos: Heute wird fast
    jede erfundene Ereignisart aus IRGENDEINEM Grund rot. Dann steht der Test
    auf grün, ohne die Sache je berührt zu haben. Geprüft wird deshalb der
    WORTLAUT des Befunds.
    """
    r = cli(*args, "status", "--json", root=root)
    assert "Traceback" not in r.stderr, r.stderr[-400:]
    try:
        records = json.loads(r.stdout)["details"]["records"]
    except (json.JSONDecodeError, KeyError):
        return []
    return [f for rec in records for f in rec.get("findings", [])]


def assert_finding(root: Path, needle: str, *args: str) -> None:
    found = findings_for(root, *args)
    assert any(needle.lower() in f.lower() for f in found), (
        f"kein Befund zu {needle!r}; gefunden wurde: {found or 'gar nichts'}"
    )


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "data"
    assert cli("init", root=r).returncode == 0
    return r


# ============================================================ A. Cue-Struktur


def test_a1_a_timecode_never_reaches_the_recogniser(tmp_path):
    """A1 — Der Angriff, wegen dem die Invariante existiert.

    ``private_date`` ist eine erkannte PII-Klasse. Geht ein vollständiger Cue
    in die Erkennung, wird der Zeitanker als Datum erkannt und ersetzt — und
    das Transkript verliert seine Synchronisation zum Audio, ohne dass
    irgendetwas rot wird.

    Die Fixture ist absichtlich gemein: Der Cue enthält BEIDES, einen
    zeitstempelähnlichen Anker und ein echtes Datum im gesprochenen Text.
    """
    doc = parsed()
    payloads = doc.payloads()

    joined = "\n".join(payloads)
    assert "00:12:03" not in joined, "der Zeitanker liegt im Erkennungseingang"
    assert "-->" not in joined, "die Cue-Trennung liegt im Erkennungseingang"
    assert "WEBVTT" not in joined and "NOTE" not in joined, "Struktur im Payload"
    assert "align:start" not in joined, "Cue-Settings im Payload"
    assert "3. Oktober 1978" in joined, "der gesprochene Text fehlt im Payload"


def test_a2_a_numeric_cue_id_is_outside_the_detection_space(tmp_path):
    """A2 — Eine nackte Zahl als Cue-ID sieht für jeden Erkenner aus wie eine
    Telefonnummer oder Kontonummer. Sie darf gar nicht erst hingehen."""
    doc = parsed(SRT, "srt")
    joined = "\n".join(doc.payloads())
    assert not any(line.strip().isdigit() for line in joined.splitlines()), joined


def test_a3_structure_survives_a_full_round_trip_byte_for_byte(tmp_path):
    """Der Vertrag hinter A1–A3, und die Zusicherung, ohne die alles andere
    wertlos ist: Wird nichts ersetzt, ist die Ausgabe die Eingabe."""
    for text, fmt in ((VTT, "vtt"), (SRT, "srt")):
        doc = parsed(text, fmt)
        assert doc.with_payloads(doc.payloads()).render() == text, fmt


@OFFEN
def test_a4_no_anchor_before_the_pseudonymised_revision(root):
    """A4 — Verankern vor der Pseudonymisierung verschiebt später alle Offsets.

    Der Graph muss das verweigern, nicht der Mensch sich merken. Geprüft über
    die CLI, weil es ein Operatorvertrag ist: Ein CHILDLUX-Profil ohne
    ``transcript.pseudonymised.confirmed`` darf keinen Ankerschritt planen.
    """
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "transcript.confirmed", "sha256": "a" * 64},
            },
            {
                "kind": "anchor.checked",
                "payload": {"artifact": "l1.suggestions", "outcome": "exact"},
            },
        ],
    )
    assert_finding(root, "pseudonym", "--profile", "childlux")


@OFFEN
def test_a5_an_anchor_quoting_the_source_transcript_is_refused(root):
    """A5 — ``Anchor.quote`` führt den Transkripttext WÖRTLICH.

    Ein Anker, der vor der Ersetzung entsteht, trägt den Klarnamen in den
    Artefaktbaum — inhaltsadressiert, vom Journal referenziert, exportierbar.
    Das ist eine zweite Kopie des Re-Identifikationsmaterials an einer Stelle,
    die niemand als solche behandelt.
    """
    forge(
        root,
        [
            {
                "kind": "anchor.recorded",
                "payload": {
                    "artifact": "l1.suggestions",
                    "transcript_sha256": sha("quelle"),
                    "start": 12,
                    "end": 25,
                    "quote": "Marie Schmitz",
                },
            }
        ],
    )
    assert_finding(root, "Oberflächenform")
    assert "Marie Schmitz" not in cli("status", "--json", root=root).stdout, (
        "das Werkzeug gibt die Oberflächenform selbst aus"
    )


@OFFEN
def test_a6_re_pseudonymisation_invalidates_old_anchors_visibly(tmp_path):
    """A6 — Neue Tabelle, neue Ersetzung, neue Revision.

    Die erste Fassung dieses Tests war wertlos: Sie benutzte leere SpanSets,
    also konnten beide Tabellen dasselbe Transkript liefern und der Test wäre
    grün geworden, ohne je eine Ersetzung gesehen zu haben. Jetzt wird die
    Verschiedenheit der beiden Ausgaben ERZWUNGEN und danach geprüft, dass ein
    Anker auf die erste Fassung gegen die zweite sichtbar ungültig ist — nicht
    still verschoben.
    """
    from ohpipe.domain.anchor import Anchor, ReanchorOutcome, reanchor
    from ohpipe.domain.transcript import TranscriptRevision

    m = pii_module()
    doc = parsed()
    payload = doc.payloads()[0]
    start = payload.index("Marie Schmitz")
    span = m.Span(
        input_sha256=sha(payload),
        unit=m.OffsetUnit.CODEPOINT,
        cue_index=0,
        start=start,
        end=start + len("Marie Schmitz"),
        entity_type="PERSON",
        recogniser="test",
        confidence=1.0,
    )

    erste = a_table(tmp_path / "korpus-a")
    zweite = a_table(tmp_path / "korpus-b")
    # Die zweite Tabelle hat schon andere Entitäten vergeben; derselbe Mensch
    # bekommt dort deshalb ein anderes Pseudonym. Genau das ist der Fall, den
    # ADR 0024 als „stiller Tabellenneustart" verbietet.
    for i in range(5):
        zweite.pseudonym_for(f"jemand-anders-{i}", "PERSON")

    a = m.apply_spans(doc, m.SpanSet(doc.sha256, (span,)), erste)[0].render()
    b = m.apply_spans(doc, m.SpanSet(doc.sha256, (span,)), zweite)[0].render()
    assert a != b, "beide Tabellen liefern dasselbe Pseudonym - der Test prueft nichts"

    rev_a = TranscriptRevision(text=a, source_kind="vtt")
    rev_b = TranscriptRevision(text=b, source_kind="vtt")
    pseudo_a = erste.pseudonym_for("marie-schmitz", "PERSON")
    at = rev_a.normalized.index(pseudo_a)
    anker = Anchor.create(rev_a, at, at + len(pseudo_a))

    ergebnis = reanchor(anker, rev_b)
    assert ergebnis.outcome is not ReanchorOutcome.EXACT, (
        "der Anker gilt gegen die neue Fassung weiter"
    )
    assert not ergebnis.outcome.machine_closable, (
        f"die Maschine hat den Anker selbst verschoben: {ergebnis.outcome}"
    )


def test_a7_a_span_on_a_differently_normalised_text_is_refused(tmp_path):
    """A7 — Der Fehler, der im Vorgängersystem alle Coverage-Zahlen zu Fiktion
    gemacht hätte, nur eine Ebene früher.

    Spans zeigen auf eine Payloadfassung, Anker auf eine normalisierte Fassung.
    Sind die Normalisierungen verschieden, zeigen dieselben Zahlen auf
    verschiedene Zeichen — und nichts wird rot. Deshalb bindet der Span an den
    Payloadhash, nicht an „das Transkript".
    """
    m = pii_module()
    doc = parsed()
    fremd = m.Span(
        input_sha256=sha("eine andere Normalisierung desselben Textes"),
        unit=m.OffsetUnit.CODEPOINT,
        cue_index=0,
        start=3,
        end=8,
        entity_type="PERSON",
        recogniser="test",
        confidence=1.0,
    )
    with pytest.raises(m.SpanRevisionMismatch):
        m.SpanSet(document_sha256=doc.sha256, spans=(fremd,)).bind(doc)


def test_a8_a_span_crossing_two_cues_is_refused(tmp_path):
    """A8 — Ein Span über zwei Payloads hinweg schließt den Zeitanker ein.

    Wer ihn ersetzt, ersetzt den Zeitcode mit. Spans sind cue-lokal; ein
    cue-übergreifender Span wird abgelehnt und nicht stillschweigend
    zerschnitten — das Zerschneiden ist eine Entscheidung, keine Reparatur.
    """
    m = pii_module()
    doc = parsed()
    with pytest.raises(m.SpanError):
        m.Span(
            input_sha256=sha(doc.payloads()[0]),
            unit=m.OffsetUnit.CODEPOINT,
            cue_index=None,  # „irgendwo im ganzen Dokument"
            start=5,
            end=999,
            entity_type="PERSON",
            recogniser="test",
            confidence=1.0,
        )


# ======================================================== B. Span-Integrität


def test_b1_a_span_naming_another_revision_stops(tmp_path):
    """B1 — Keine heuristische Suche nach „wahrscheinlich derselben Stelle".

    Zwei Ebenen, beide dicht: die Spanmenge gegen den Dokumenthash und jeder
    einzelne Span gegen seinen Payloadhash. Die feinere Bindung ist die
    nützlichere — ein Span über Cue 3 soll nicht ungültig werden, weil Cue 7
    sich geändert hat.
    """
    m = pii_module()
    doc = parsed()
    span = m.Span(
        input_sha256="b" * 64,
        unit=m.OffsetUnit.CODEPOINT,
        cue_index=0,
        start=0,
        end=4,
        entity_type="PERSON",
        recogniser="test",
        confidence=1.0,
    )
    with pytest.raises(m.SpanRevisionMismatch):
        m.SpanSet(document_sha256=doc.sha256, spans=(span,)).bind(doc)
    with pytest.raises(m.SpanRevisionMismatch):
        m.SpanSet(document_sha256="c" * 64, spans=()).bind(doc)


@pytest.mark.parametrize(
    "start,end,label",
    [
        (-1, 4, "negativer Start"),
        (0, 10**6, "Ende hinter dem Payload"),
        (7, 7, "leerer Bereich"),
        (9, 4, "Ende vor Start"),
    ],
)
@OFFEN
def test_b2_a_malformed_span_is_refused_by_the_persisted_representation(root, start, end, label):
    """B2 — Über die persistierte Darstellung, nicht über den Konstruktor.

    Ein Test, der nur ``Span(...)`` aufruft, prüft den Code wie gedacht. Der
    Angriff schreibt in das Journal.
    """
    forge(
        root,
        [
            {
                "kind": "spans.recorded",
                "payload": {
                    "artifact": "pii.spans",
                    "input_sha256": "a" * 64,
                    "unit": "codepoint",
                    "spans": [{"cue_index": 0, "start": start, "end": end, "type": "PERSON"}],
                },
            }
        ],
    )
    assert_finding(root, "Bereich")


def test_b3_overlapping_spans_of_different_types_do_not_resolve_by_list_order(tmp_path):
    """B3 — Die Reihenfolge der Adapterliste ist kein Tie-Break.

    Zwei Erkenner, zwei Typen, derselbe Bereich. Ob aufgelöst oder angehalten
    wird, ist eine dokumentierte Entscheidung — aber sie darf nicht davon
    abhängen, welcher Adapter zuerst in der Konfiguration steht. Geprüft wird
    genau das: Vertauschen der Eingabereihenfolge ändert das Ergebnis nicht.
    """
    m = pii_module()
    doc = parsed()
    h = doc.payload_sha256(0)
    common = dict(input_sha256=h, unit=m.OffsetUnit.CODEPOINT, cue_index=0, confidence=1.0)
    a = m.Span(start=28, end=41, entity_type="PERSON", recogniser="gliner", **common)
    b = m.Span(start=28, end=41, entity_type="LOCATION", recogniser="spacy", **common)

    def ausgang(spans):
        try:
            return sorted(s.sort_key for s in m.SpanSet(doc.sha256, spans).bind(doc))
        except m.SpanConflict:
            return "CONFLICT"

    assert ausgang((a, b)) == "CONFLICT", "verschiedene Typen auf demselben Bereich"
    assert ausgang((a, b)) == ausgang((b, a)), "die Adapterreihenfolge entscheidet"

    # Gegenprobe: identischer Bereich UND identischer Typ ist eine Bestaetigung,
    # kein Konflikt - und die Erkenner werden zusammengefuehrt.
    c = m.Span(start=28, end=41, entity_type="PERSON", recogniser="spacy", **common)
    vereint = m.SpanSet(doc.sha256, (a, c)).bind(doc)
    assert len(vereint) == 1
    assert vereint.spans[0].recognisers == ("gliner", "spacy")


def test_b4_the_offset_unit_is_declared_not_guessed(tmp_path):
    """B4 — ``Lëtzebuerg`` ist als UTF-8 länger als in Codepoints.

    Drei Sachen, nicht nur die Existenz der Enum: Eine unbekannte Einheit wird
    abgelehnt; echte Byteoffsets werden einmalig und korrekt kanonisiert; und
    ein Offset mitten im ``ë`` wird abgelehnt, statt die Kodierung zu
    zerschneiden.
    """
    m = pii_module()
    assert {u.value for u in m.OffsetUnit} >= {"codepoint", "utf8_byte"}

    text = "1\n00:00:01,000 --> 00:00:04,000\nMoien Lëtzebuerg hei.\n"
    doc = parsed(text, "srt")
    payload = doc.payloads()[0]
    roh = payload.encode("utf-8")
    wort = "Lëtzebuerg".encode()
    ab = roh.index(wort)

    def span(start, end, unit=m.OffsetUnit.UTF8_BYTE):
        return m.Span(
            input_sha256=doc.payload_sha256(0),
            unit=unit,
            cue_index=0,
            start=start,
            end=end,
            entity_type="LOCATION",
            recogniser="test",
            confidence=1.0,
        )

    # 1. unbekannte Einheit
    with pytest.raises((m.SpanError, ValueError)):
        span(0, 4, unit="ganz sicher keine Einheit")

    # 2. echte Byteoffsets, korrekt kanonisiert
    gebunden = m.SpanSet(doc.sha256, (span(ab, ab + len(wort)),)).bind(doc).spans[0]
    assert payload[gebunden.start : gebunden.end] == "Lëtzebuerg"
    assert (gebunden.start, gebunden.end) != (ab, ab + len(wort)), (
        "Byte- und Codepointoffsets sind hier zufaellig gleich - die Fixture prueft nichts"
    )

    # 3. Offset mitten im ë
    mitten = roh.index("ë".encode()) + 1
    with pytest.raises(m.SpanOutOfRange):
        m.SpanSet(doc.sha256, (span(mitten, mitten + 4),)).bind(doc)


@pytest.mark.parametrize("leak", ["surface", "quote", "context", "replacement", "original"])
@OFFEN
def test_b5_a_span_carrying_a_surface_form_is_refused(root, leak):
    """B5 — Der Span ist eine Position, kein Zitat.

    Sobald er die Oberflächenform mitführt, ist ``pii.spans`` eine zweite,
    record-lokale Ersetzungstabelle im Datenbaum (ADR 0024).
    """
    forge(
        root,
        [
            {
                "kind": "spans.recorded",
                "payload": {
                    "artifact": "pii.spans",
                    "input_sha256": "a" * 64,
                    "unit": "codepoint",
                    "spans": [
                        {
                            "cue_index": 0,
                            "start": 30,
                            "end": 43,
                            "type": "PERSON",
                            leak: "Marie Schmitz",
                        }
                    ],
                },
            }
        ],
    )
    assert_finding(root, leak)
    assert "Marie Schmitz" not in cli("status", "--json", root=root).stdout, leak


# ============================================ C. Ersetzung und externe Tabelle


@OFFEN
def test_c1_the_same_entity_gets_the_same_pseudonym_across_records(tmp_path):
    """C1 — Korpusweite Konsistenz ist der Zweck der Tabelle.

    Ohne sie ist dieselbe Person in zwei Interviews zwei Personen, und die
    Forschung am Korpus wird falsch.
    """
    table = a_table(tmp_path)
    first = table.pseudonym_for("marie-schmitz", "PERSON")
    second = table.pseudonym_for("marie-schmitz", "PERSON")
    assert first == second


@OFFEN
def test_c2_two_entities_never_collide_on_one_pseudonym(tmp_path):
    """C2 — Eine Kollision führt zwei Menschen zusammen. Das ist kein
    Schönheitsfehler, sondern ein falsches Forschungsergebnis."""
    table = a_table(tmp_path)
    seen = {table.pseudonym_for(f"person-{i:04d}", "PERSON") for i in range(200)}
    assert len(seen) == 200


@OFFEN
def test_c3_a_missing_table_never_starts_an_empty_one(root, tmp_path):
    """C3 — Der gefährlichste Bequemlichkeitsfehler.

    Eine leere Tabelle beginnt die Nummerierung neu. Dieselbe Person bekommt
    dann in Record 8 ein anderes Pseudonym als in Record 7, und niemand merkt
    es, weil beide Läufe „erfolgreich" sind.
    """
    m = table_module()
    with pytest.raises(m.TableMissing):
        m.ReplacementTable.open(
            table_id="CHILDLUX-CORPUS-01",
            path=tmp_path / "gibt-es-nicht" / "replacements.enc",
            key_path=tmp_path / "keys" / "table.key",
        )
    r = cli("--profile", "childlux", "status", root=root)
    assert r.returncode in (1, 2), f"exit {r.returncode}"
    assert "Traceback" not in r.stderr


ALLOCATE_IN_A_SUBPROCESS = """
import sys, time
from pathlib import Path
from ohpipe.adapters.pseudonymisation.table import ReplacementTable

store, keys, startsignal, ab = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
# Die Tabelle EXISTIERT bereits. open() darf sie nicht anlegen (C3).
t = ReplacementTable.open(
    table_id="CHILDLUX-CORPUS-01", path=store / "replacements.enc", key_path=keys / "table.key"
)
(startsignal.parent / f"ready-{ab}").write_text("ready")
while not startsignal.exists():
    time.sleep(0.005)
print("\\n".join(t.pseudonym_for(f"e-{ab + i}", "PERSON") for i in range(8)))
"""


@OFFEN
def test_c5_concurrent_allocation_never_hands_out_a_number_twice(tmp_path):
    """C5 — Acht Prozesse allokieren GLEICHZEITIG.

    Zwei Fassungen waren vorher unbrauchbar. Die erste benutzte
    ``ThreadPoolExecutor`` und behauptete trotzdem Prozesskonkurrenz — eine
    reine ``threading.Lock`` wäre fälschlich grün geworden. Die zweite nahm
    echte Prozesse, aber ohne Barriere: Ohne gemeinsames Startsignal laufen
    sie nacheinander, und der Test prüft wieder nichts. Ausserdem öffneten
    alle eine noch nicht angelegte Tabelle — das kollidiert mit `C3`, wo
    ``open()`` eine fehlende Tabelle gerade **nicht** erzeugen soll.

    Jetzt: Der Elternprozess legt einmal an, acht Kinder öffnen dieselbe
    bestehende Tabelle, melden ``ready`` und warten auf ein gemeinsames Signal.
    """
    m = table_module()
    store = tmp_path / "secret-store"
    store.mkdir(parents=True)
    keys = tmp_path / "keys"
    keys.mkdir(parents=True)
    signal = tmp_path / "los"

    # Provisionierung ist ein EIGENER Schritt, nicht eine Nebenwirkung von open().
    m.ReplacementTable.create(
        table_id="CHILDLUX-CORPUS-01",
        path=store / "replacements.enc",
        key_path=keys / "table.key",
    )

    procs = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                ALLOCATE_IN_A_SUBPROCESS,
                str(store),
                str(keys),
                str(signal),
                str(i * 8),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=REPO,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO / "src")},
        )
        for i in range(8)
    ]
    frist = time.monotonic() + 30
    while len(list(tmp_path.glob("ready-*"))) < 8 and time.monotonic() < frist:
        time.sleep(0.01)
    assert len(list(tmp_path.glob("ready-*"))) == 8, "nicht alle Schreiber sind bereit"
    signal.write_text("los")  # ab hier allokieren alle gleichzeitig

    ergebnisse = [pr.communicate() for pr in procs]
    vergeben: list[str] = []
    for i, (out, err) in enumerate(ergebnisse):
        assert procs[i].returncode == 0, f"Schreiber {i}: {err}"
        vergeben += out.split()

    assert len(vergeben) == 64
    assert len(set(vergeben)) == 64, f"{64 - len(set(vergeben))} Kollisionen ueber Prozesse hinweg"


@OFFEN
def test_c6_the_table_may_not_live_under_the_data_root(root, tmp_path):
    """C6 — Wer den Datenbaum bekommt, bekäme sonst den Schlüssel mit.

    Dieselbe Regel wie beim Journalschlüssel (ADR 0016), und aus demselben
    Grund. Geprüft wird auch das Repository — eine Tabelle dort wäre eine
    Zeile ``git add -A`` von GitLab entfernt.
    """
    m = table_module()
    repo = Path(__file__).resolve().parents[1]
    for verboten in (root / "replacements.enc", repo / "replacements.enc"):
        with pytest.raises(m.TableInsideDataRoot):
            m.ReplacementTable.open(
                table_id="CHILDLUX-CORPUS-01",
                path=verboten,
                key_path=tmp_path / "keys" / "table.key",
            )


@OFFEN
def test_c7_the_key_may_not_live_beside_the_table(tmp_path):
    """Die Trennung ist eine Invariante, kein Hinweis (ADR 0024).

    Steht der Schlüssel neben der Tabelle, ist die Verschlüsselung Dekoration.
    """
    m = table_module()
    store = tmp_path / "secret-store"
    store.mkdir()
    with pytest.raises(m.TableError):
        m.ReplacementTable.open(
            table_id="CHILDLUX-CORPUS-01",
            path=store / "replacements.enc",
            key_path=store / "table.key",
        )


@OFFEN
def test_c8_a_declared_state_that_does_not_match_stops(root, tmp_path):
    """C8 — Das Journal nennt Tabellenstand A, der Adapter öffnet B.

    Ohne Hashprüfung vor der Ersetzung wäre die Zuordnung eines Records
    stillschweigend von einem anderen Tabellenstand abhängig, als die
    Entscheidung behauptet.
    """
    m = table_module()
    table = a_table(tmp_path)
    assert len(table.state_sha256) == 64
    with pytest.raises(m.TableStateMismatch):
        table.require_state("c" * 64)


@OFFEN
def test_c9_bytes_outside_confirmed_spans_are_identical(tmp_path):
    """C9 — Kein generatives Umschreiben.

    Der einzige Weg, das zu prüfen, ist ein Vergleich Zeichen für Zeichen
    ausserhalb der Spans. „Das Modell soll nur ersetzen" ist eine Absicht,
    keine Zusicherung.
    """
    m = pii_module()
    doc = parsed()
    payload = doc.payloads()[0]
    start = payload.index("Marie Schmitz")
    span = m.Span(
        input_sha256=sha(payload),
        unit=m.OffsetUnit.CODEPOINT,
        cue_index=0,
        start=start,
        end=start + len("Marie Schmitz"),
        entity_type="PERSON",
        recogniser="test",
        confidence=1.0,
    )
    out, _report = m.apply_spans(doc, m.SpanSet(doc.sha256, (span,)), a_table(tmp_path))
    after = out.payloads()[0]

    assert payload[:start] == after[: len(payload[:start])], "Bytes VOR dem Span verändert"
    assert after.endswith(payload[start + len("Marie Schmitz") :]), "Bytes NACH dem Span verändert"
    assert "Marie Schmitz" not in after
    assert "3. Oktober 1978" in after, "das Datum im gesprochenen Text blieb unersetzt stehen"


# ================================================ D. Review als Leckagepfad


@OFFEN
def test_d1_a_report_pairing_original_and_pseudonym_is_refused(root):
    """D1 — Der Bericht ist die naheliegendste Stelle für eine zweite Tabelle.

    Er muss den Menschen überzeugen, also möchte man ihm zeigen, was ersetzt
    wurde. Genau das darf nicht persistiert werden.
    """
    forge(
        root,
        [
            {
                "kind": "report.recorded",
                "payload": {
                    "artifact": "replacement.report",
                    "input_sha256": "a" * 64,
                    "output_sha256": "b" * 64,
                    "pairs": [{"original": "Marie Schmitz", "replacement": "PERSON-014"}],
                },
            }
        ],
    )
    assert_finding(root, "Zuordnung")
    assert "Marie Schmitz" not in cli("status", "--json", root=root).stdout


def test_d2_there_is_no_side_by_side_export_adapter(root):
    """D2 — Nicht „der Export ist eingeschränkt", sondern: es gibt ihn nicht.

    Ein Metatest über die tatsächlich registrierten Exportziele. Was nicht
    existiert, kann nicht versehentlich freigeschaltet werden.
    """
    from ohpipe.domain.step import Kind

    from ohpipe.domain.step import DEFAULT_GRAPH  # isort: skip

    egress = {a for s in DEFAULT_GRAPH if s.kind is Kind.EGRESS for a in s.produces}
    verboten = {"pii.spans", "replacement.report", "transcript.confirmed", "review.package"}
    assert not (egress & verboten), f"exportierbar: {egress & verboten}"

    r = cli("--help", root=root)
    for wort in ("side-by-side", "review-package", "export-mapping"):
        assert wort not in r.stdout.lower(), f"{wort} ist aufrufbar"


@OFFEN
def test_d6_the_decision_binds_output_source_spans_and_report_together(root):
    """D6 — Eine Freigabe auf die sichtbare Seite ist keine Freigabe.

    Bindet die Entscheidung nur an die Ausgabebytes, kann hinterher der
    Spanstand oder der Bericht ausgetauscht werden, ohne dass die Freigabe
    sichtbar entwertet wird.
    """
    forge(
        root,
        [
            {
                "kind": "decision.recorded",
                "payload": {
                    "artifact": "transcript.pseudonymised.confirmed",
                    "subject_sha256": "a" * 64,
                    "verdict": "ACCEPT",
                    "reference": "PI-pseudo",
                    "actor": "niemand",
                    "at": "2026-09-01T09:00:00+00:00",
                },
            }
        ],
    )
    assert_finding(root, "Bericht")


# =========================================== E. Profil- und Graphumgehung


@OFFEN
def test_e1_childlux_cannot_reach_l1_from_the_source_transcript(root):
    """E1 — Die Kernzusage der ADR, über den Planner geprüft.

    Ein CHILDLUX-Record mit ausschließlich ``transcript.confirmed`` darf L1
    nicht erreichen. Der nächste Halt ist die Pseudonymisierung.
    """
    from ohpipe.domain.step import graph_for_profile
    from ohpipe.project import Profile

    childlux = Profile.load(
        Path(__file__).resolve().parents[1] / "src/ohpipe/profiles/childlux/profile.toml"
    )
    graph = graph_for_profile(childlux)
    plan = graph.plan({"transcript.revision", "transcript.confirmed"})
    assert "l1.suggest" not in [s.name for s in plan.steps], [s.name for s in plan.steps]
    assert any("pseudonym" in g.name for g in plan.gates), list(plan.gate_names)


def test_e2_a_production_profile_without_the_flag_is_invalid(tmp_path):
    """E2 — Kein sicherheitsrelevanter False-Default.

    Ein fehlendes Feld darf nicht „also nicht erforderlich" heißen. Das ist
    dieselbe Regel wie bei ``key_required`` (ADR 0017), nur teurer, wenn sie
    fehlt.
    """
    from ohpipe.project import Profile, ProfileError

    p = tmp_path / "profile.toml"
    p.write_text(
        '[profile]\nid = "childlux_kopie"\nrecord_prefix = "CHILDLUX"\nproduction = true\n',
        encoding="utf-8",
    )
    with pytest.raises(ProfileError):
        Profile.load(p)


@pytest.mark.parametrize("wert", ['"false"', '"no"', "0", '"maybe"'])
def test_e3_the_flag_is_strictly_typed(tmp_path, wert):
    """Kein ``bool("false")``. Der Wert ist ein TOML-Boolean oder gar nichts."""
    from ohpipe.project import Profile, ProfileError

    p = tmp_path / "profile.toml"
    p.write_text(
        f'[profile]\nid = "x"\nrecord_prefix = "CHILDLUX"\npseudonymisation_required = {wert}\n',
        encoding="utf-8",
    )
    with pytest.raises(ProfileError):
        Profile.load(p)


@OFFEN
def test_e4_no_flag_and_no_record_field_can_switch_the_duty_off(root):
    """E4 — Metatest über Parser und persistiertes Schema.

    Eine Option, die es nicht gibt, kann niemand aus Versehen setzen — und
    keine Dokumentation muss davon abraten.
    """
    from ohpipe.cli.main import build_parser

    parser = build_parser()
    hilfe = parser.format_help()
    for verboten in ("--no-pseudonym", "--skip-pseudonym", "--pseudonymisation"):
        assert verboten not in hilfe, f"{verboten} existiert"

    forge(
        root,
        [
            {
                "kind": "record.configured",
                "payload": {"pseudonymisation_required": False},
            }
        ],
    )
    assert_finding(root, "pseudonymisation_required", "--profile", "childlux")


@OFFEN
def test_e6_a_forged_confirmation_does_not_unlock_l1(root):
    """E6 — Der Angriff, der die ganze Kette wertlos machen würde.

    Ein wohlgeformtes ``transcript.pseudonymised.confirmed`` ohne echte
    Reviewentscheidung darf L1 nicht freischalten. Ohne Schlüssel greift
    zusätzlich die Autoritätskappung (ADR 0017).
    """
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {
                    "artifact": "transcript.pseudonymised.confirmed",
                    "sha256": "a" * 64,
                },
            }
        ],
    )
    r = cli("--profile", "childlux", "status", "--json", root=root)
    assert "Traceback" not in r.stderr, r.stderr[-400:]
    records = json.loads(r.stdout).get("details", {}).get("records")
    assert records, "kein Recordurteil - die Faelschung wurde gar nicht bewertet"
    rec = records[0]
    assert rec["status"] != "READY", rec["explanation"]
    plan = json.dumps(rec.get("next_gates", []))
    assert "pseudonymisation" in plan, f"naechster Halt ist nicht das Review: {plan}"
