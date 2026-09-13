"""Der Cue-Parser im Normalbetrieb — der Verlustfreiheitsvertrag.

``test_pseudonymisation_forgery.py`` prüft die drei Angriffe (`A1`–`A3`).
Diese Datei prüft, dass der Parser überhaupt kann, was er soll — und zwar an
genau den Stellen, an denen ein Parser normalerweise still etwas verliert:
Zeilenenden, BOM, fehlende Schlusszeile, mehrzeilige Payloads.

Die Zusicherung, um die es geht, ist einzeilig und unbedingt:

    Wird nichts ersetzt, ist ``render()`` die Identität.

Nicht „gleichwertig", nicht „normalisiert gleich" — **dieselben Bytes**. Der
vorhandene SRT-Ingest (``adapters/input/srt.py``) erfüllt das ausdrücklich
nicht und soll es auch nicht: Er normalisiert Zeilenenden, entfernt das BOM
und verbindet Textzeilen. Für semantischen Ingest ist das richtig, für einen
Roundtrip ist jede dieser Leistungen ein Datenverlust. Deshalb zwei Parser.
"""

from __future__ import annotations

import pytest

from ohpipe.domain.cue import (
    BOM,
    CueDocument,
    CueFormat,
    CueParseError,
    CueStructureChanged,
    PayloadSpan,
    is_timing_line,
)

SRT = (
    "1\n00:00:01,000 --> 00:00:04,000\nGuten Tag.\n\n2\n00:00:04,000 --> 00:00:08,000\nUnd Ihnen?\n"
)

VTT = (
    "WEBVTT\n"
    "Kind: captions\n"
    "Language: de\n"
    "\n"
    "NOTE Diese Notiz ist Struktur.\n"
    "Sie geht ueber zwei Zeilen.\n"
    "\n"
    "STYLE\n"
    "::cue { color: peachpuff; }\n"
    "\n"
    "einleitung\n"
    "00:00:01.000 --> 00:00:04.000 align:start position:10%\n"
    "Guten Tag.\n"
    "\n"
    "00:00:04.000 --> 00:00:08.000\n"
    "INTERVIEWER: Und Ihnen?\n"
    "Mir geht es gut.\n"
)


def roundtrip(text: str, fmt: str) -> None:
    """Die eine Zusicherung, überall gleich formuliert."""
    doc = CueDocument.parse(text, CueFormat(fmt))
    assert doc.render() == text, "render() ist nicht die Identität"
    assert doc.with_payloads(doc.payloads()).render() == text, "Roundtrip verliert Bytes"


# ------------------------------------------------------ Verlustfreiheit


@pytest.mark.parametrize("fmt,text", [("srt", SRT), ("vtt", VTT)])
def test_an_untouched_document_renders_to_itself(fmt, text):
    roundtrip(text, fmt)


@pytest.mark.parametrize("fmt,text", [("srt", SRT), ("vtt", VTT)])
def test_crlf_survives(fmt, text):
    """Windows-Zeilenenden sind der Normalfall bei Transkriptionswerkzeugen.

    Ein Parser, der ``\\r\\n`` zu ``\\n`` normalisiert, ändert jede einzelne
    Zeile — und der Hash des Dokuments gleich mit.
    """
    roundtrip(text.replace("\n", "\r\n"), fmt)


@pytest.mark.parametrize("fmt,text", [("srt", SRT), ("vtt", VTT)])
def test_a_bom_survives(fmt, text):
    """Das BOM ist Struktur, kein gesprochener Text — und es bleibt stehen."""
    doc = CueDocument.parse(BOM + text, CueFormat(fmt))
    assert doc.render() == BOM + text
    assert BOM not in "".join(doc.payloads()), "das BOM ist im Erkennungseingang"


@pytest.mark.parametrize("fmt,text", [("srt", SRT), ("vtt", VTT)])
def test_a_missing_final_newline_survives(fmt, text):
    """Ein Dokument ohne Schlusszeilenumbruch darf keinen bekommen.

    Der stillste aller Datenverluste: Fast jeder Serialisierer hängt hier
    ungefragt ein ``\\n`` an, und der Dokumenthash ändert sich, ohne dass ein
    Zeichen des Inhalts anders wäre.
    """
    roundtrip(text.rstrip("\n"), fmt)


@pytest.mark.parametrize("fmt,text", [("srt", SRT), ("vtt", VTT)])
def test_trailing_blank_lines_survive(fmt, text):
    roundtrip(text + "\n\n", fmt)


# -------------------------------------------------------- was Payload ist


def test_vtt_structure_never_reaches_the_payload():
    """Kopf, Kopfmetadaten, NOTE, STYLE, Cue-Kennung, Zeitzeile und Settings."""
    doc = CueDocument.parse(VTT, CueFormat.VTT)
    joined = "\n".join(doc.payloads())
    for struktur in (
        "WEBVTT",
        "Kind: captions",
        "Language: de",
        "NOTE",
        "Sie geht ueber zwei Zeilen.",
        "STYLE",
        "peachpuff",
        "einleitung",
        "-->",
        "align:start",
        "position:10%",
    ):
        assert struktur not in joined, f"{struktur!r} liegt im Erkennungseingang"


def test_a_multiline_payload_is_one_span():
    """Zwei Textzeilen eines Cues sind EIN Payload, nicht zwei.

    Sonst könnte ein Span über die Zeilengrenze nicht ausgedrückt werden — und
    ein Name, der über den Zeilenumbruch läuft, entkäme der Ersetzung.
    """
    doc = CueDocument.parse(VTT, CueFormat.VTT)
    assert len(doc.payloads()) == 2
    assert doc.payloads()[1] == "INTERVIEWER: Und Ihnen?\nMir geht es gut."


def test_a_speaker_prefix_stays_in_the_payload():
    """Bewusst KEINE Sonderbehandlung.

    ``INTERVIEWER:`` sieht aus wie Struktur, ist aber gesprochener Text — und
    bei Oral History ist die Sprecherrolle mitunter selbst schutzbedürftig.
    Wer sie hier herausschneidet, entzieht sie der Erkennung.
    """
    doc = CueDocument.parse(VTT, CueFormat.VTT)
    assert doc.payloads()[1].startswith("INTERVIEWER:")


def test_an_optional_cue_id_is_structure_in_both_formats():
    """SRT hat sie fast immer, WebVTT fast nie. Beides ist gültig."""
    ohne = "00:00:01.000 --> 00:00:04.000\nNur Text.\n"
    doc = CueDocument.parse("WEBVTT\n\n" + ohne, CueFormat.VTT)
    assert doc.payloads() == ("Nur Text.",)
    assert doc.render() == "WEBVTT\n\n" + ohne


# ------------------------------------------------------------- Ersetzen


def test_replacing_one_payload_touches_nothing_else():
    doc = CueDocument.parse(SRT, CueFormat.SRT)
    neu = doc.with_payloads(("Moien.", doc.payloads()[1]))
    out = neu.render()

    assert "Moien." in out and "Guten Tag." not in out
    assert "00:00:01,000 --> 00:00:04,000" in out, "die Zeitzeile hat sich geändert"
    assert out.count("-->") == 2 and out.count("\n\n") == 1
    assert out.splitlines()[0] == "1", "die Cue-Kennung hat sich geändert"


def test_a_shorter_replacement_does_not_shift_the_second_cue():
    """Der eigentliche Zweck der Positionslogik.

    Eine kürzere Ersetzung verschiebt alle folgenden Offsets im Text. Von
    hinten nach vorn zu patchen ist deshalb kein Stil, sondern die Bedingung
    dafür, dass Cue 2 unangetastet bleibt.
    """
    doc = CueDocument.parse(SRT, CueFormat.SRT)
    out = doc.with_payloads(("Hm.", "Ja.")).render()
    assert out == "1\n00:00:01,000 --> 00:00:04,000\nHm.\n\n2\n00:00:04,000 --> 00:00:08,000\nJa.\n"


@pytest.mark.parametrize(
    "ersatz,label",
    [
        ("Zeile eins\n\nZeile zwei", "Leerzeile erzeugt eine neue Cue-Grenze"),
        ("Eine Zeile\nund noch eine", "eine Zeile zu viel"),
        (BOM + "Text", "BOM im Ersatztext"),
        ("Text mit\rCR", "alleinstehendes CR"),
        ("Text mit\x0bVT", "zeilentrennendes Steuerzeichen"),
        ("Text mit\u2028LS", "Unicode-Zeilentrenner"),
    ],
)
def test_a_replacement_that_would_change_structure_is_refused(ersatz, label):
    doc = CueDocument.parse(SRT, CueFormat.SRT)
    with pytest.raises(CueStructureChanged):
        doc.with_payloads((ersatz, doc.payloads()[1]))


@pytest.mark.parametrize("falsch", [(), ("nur einer",), ("a", "b", "c"), "eine Zeichenkette"])
def test_a_wrong_payload_count_is_refused(falsch):
    """Zu wenige Ersatztexte hieße: ein Cue behält seinen Klarnamen."""
    doc = CueDocument.parse(SRT, CueFormat.SRT)
    with pytest.raises(CueStructureChanged):
        doc.with_payloads(falsch)


def test_a_crlf_document_keeps_crlf_inside_a_replaced_multiline_payload():
    """Die Zeilenenden im Ersatztext müssen zu denen des Dokuments passen.

    Sonst steht in einer CRLF-Datei plötzlich ein einzelnes ``\\n`` — und der
    Roundtrip ist an einer Stelle kaputt, an der niemand nachsieht.
    """
    doc = CueDocument.parse(VTT.replace("\n", "\r\n"), CueFormat.VTT)
    with pytest.raises(CueStructureChanged):
        doc.with_payloads((doc.payloads()[0], "Erste Zeile\nZweite Zeile"))
    ok = doc.with_payloads((doc.payloads()[0], "Erste Zeile\r\nZweite Zeile"))
    assert "\r\nZweite Zeile" in ok.render()


# ------------------------------------------------------------ fail-closed


@pytest.mark.parametrize(
    "text,fmt,label",
    [
        ("", "srt", "leere Datei"),
        ("", "vtt", "leere VTT-Datei"),
        ("Guten Tag.\n", "srt", "Text ohne Zeitzeile"),
        ("1\n\nGuten Tag.\n", "srt", "Kennung ohne Zeitzeile"),
        ("1\n00:00:01,000 --> 00:00:04,000\n", "srt", "Zeitzeile ohne Text"),
        ("1\n00:00:01,000 --> 00:00:04,000\n\n", "srt", "Zeitzeile, dann Leerzeile"),
        ("Kein Kopf\n\n00:00:01.000 --> 00:00:04.000\nText\n", "vtt", "kein WEBVTT-Kopf"),
        ("WEBVTT\n\nirgendwas\nnoch etwas\n", "vtt", "Kennung ohne Zeitzeile"),
    ],
)
def test_a_malformed_document_is_refused_not_partially_read(text, fmt, label):
    """Fail-closed wie beim SRT-Ingest.

    Ein halb gelesenes Transkript ist die Vorstufe zu einer
    inhaltskorrelierten Lücke — und die kostet später ein ganzes Korpus.
    """
    with pytest.raises(CueParseError):
        CueDocument.parse(text, CueFormat(fmt))


def test_the_document_is_frozen():
    """``with_payloads`` gibt ein neues Dokument zurück und ändert keines."""
    doc = CueDocument.parse(SRT, CueFormat.SRT)
    neu = doc.with_payloads(("Moien.", "Jo."))
    assert doc.payloads() == ("Guten Tag.", "Und Ihnen?")
    assert neu.payloads() == ("Moien.", "Jo.")
    assert doc.render() == SRT


# ------------------------------- Gegenproben aus dem Review vom 04.08.


@pytest.mark.parametrize(
    "zeile,fmt,label",
    [
        ("kein zeitcode --> trotzdem struktur", "srt", "beliebiger Pfeil"),
        ("kein zeitcode --> trotzdem struktur", "vtt", "beliebiger Pfeil, VTT"),
        ("00:99:99,000 --> 00:99:99,000", "srt", "Minuten und Sekunden ausserhalb"),
        ("00:00:10,000 --> 00:00:05,000", "srt", "Ende vor Beginn"),
        ("00:00:01,00 --> 00:00:04,000", "srt", "zweistellige Millisekunden"),
        ("00:00:01,000-->00:00:04,000", "srt", "Pfeil ohne Leerzeichen"),
        ("0:00:01.000 --> 0:00:04.000", "vtt", "einstellige Stunde"),
    ],
)
def test_a_line_that_is_not_a_valid_timing_line_is_not_structure(zeile, fmt, label):
    """P0 — Die Prüfung suchte nur nach ``-->``.

    Der Schaden geht in beide Richtungen, und die zweite ist die schlimmere:
    Gesprochener Text, der zufällig einen Pfeil enthält, wurde als Struktur
    klassifiziert — und damit der Erkennung **vollständig entzogen**. Ein
    Klarname in so einer Zeile käme nie bei einem Erkenner an.
    """
    assert not is_timing_line(zeile, CueFormat(fmt)), label


@pytest.mark.parametrize(
    "zeile,fmt",
    [
        ("00:00:01,000 --> 00:00:04,000", "srt"),
        ("00:00:01.000 --> 00:00:04.000", "srt"),
        ("00:00:01,000 --> 00:00:04,000 X1:100 X2:200", "srt"),
        ("00:00:01.000 --> 00:00:04.000", "vtt"),
        ("00:01.000 --> 00:04.000", "vtt"),
        ("00:00:01.000 --> 00:00:04.000 align:start position:10%", "vtt"),
        ("00:00:01,000 --> 00:00:01,000", "srt"),
    ],
)
def test_a_valid_timing_line_is_still_recognised(zeile, fmt):
    """Die Gegenrichtung. Eine zu strenge Prüfung wäre genauso falsch: Dann
    landete die Zeitzeile im Payload und würde ersetzt."""
    assert is_timing_line(zeile, CueFormat(fmt))


def test_a_bogus_arrow_line_is_refused_as_a_document():
    """Dieselbe Sache eine Ebene höher: Das Dokument wird abgelehnt, nicht
    halb gelesen."""
    with pytest.raises(CueParseError):
        CueDocument.parse("1\nkein zeitcode --> trotzdem struktur\nText\n", CueFormat.SRT)


@pytest.mark.parametrize("kopf", ["WEBVTTevil", "WEBVTT-Kram", "webvtt", " WEBVTT"])
def test_only_a_real_webvtt_header_is_accepted(kopf):
    """P1 — ``startswith("WEBVTT")`` nahm auch ``WEBVTTevil`` an."""
    with pytest.raises(CueParseError):
        CueDocument.parse(kopf + "\n\n00:00:01.000 --> 00:00:04.000\nText\n", CueFormat.VTT)


@pytest.mark.parametrize("kopf", ["WEBVTT", "WEBVTT - Interview 7", "WEBVTT\tmit Tab"])
def test_an_allowed_header_variant_is_accepted(kopf):
    doc = CueDocument.parse(kopf + "\n\n00:00:01.000 --> 00:00:04.000\nText\n", CueFormat.VTT)
    assert doc.payloads() == ("Text",)


def test_a_freely_constructed_structure_span_is_refused():
    """P0 — Der Konstruktor war eine Hintertür.

    Er nahm beliebige ``PayloadSpan``-Positionen. Damit konnte ein Aufrufer
    die Zeitzeile als Payload markieren und ersetzen lassen — genau das, wogegen
    dieses Modul gebaut ist. Der Konstruktor parst jetzt erneut und lehnt jede
    nichtkanonische Spanmenge ab.
    """
    echt = CueDocument.parse(SRT, CueFormat.SRT)
    zeitzeile = PayloadSpan(
        cue_index=0, start=SRT.index("00:00:01"), end=SRT.index("00:00:01") + 29
    )
    with pytest.raises(CueStructureChanged):
        CueDocument(source=SRT, fmt=CueFormat.SRT, spans=(zeitzeile,))
    with pytest.raises(CueStructureChanged):
        CueDocument(source=SRT, fmt=CueFormat.SRT, spans=echt.spans + (zeitzeile,))


def test_a_freely_constructed_payload_passes_the_same_barrier():
    """Auch ``_payloads=`` am Konstruktor vorbei ist keine Hintertür."""
    echt = CueDocument.parse(SRT, CueFormat.SRT)
    with pytest.raises(CueStructureChanged):
        CueDocument(
            source=SRT,
            fmt=CueFormat.SRT,
            spans=echt.spans,
            _payloads=("Zeile\n\nNeues Cue", "Und Ihnen?"),
        )


def test_an_arrow_inside_the_spoken_text_round_trips():
    """P1 — Der Identitätsroundtrip galt nicht für alle gültigen Payloads.

    ``doc.with_payloads(doc.payloads())`` scheiterte an einem Cue, in dem
    jemand „von A --> B" gesagt hatte. Ein Pfeil im Payload erzeugt keine
    Cue-Grenze: Die Grenzen liegen an festen Positionen, und die
    Zeilenstruktur ist unveränderlich.
    """
    text = "1\n00:00:01,000 --> 00:00:04,000\nDer Weg ging von A --> B.\n"
    doc = CueDocument.parse(text, CueFormat.SRT)
    assert doc.payloads() == ("Der Weg ging von A --> B.",)
    assert doc.with_payloads(doc.payloads()).render() == text
    assert doc.with_payloads(("Der Weg ging von X --> Y.",)).render().endswith("X --> Y.\n")


def test_a_lone_cr_in_a_replacement_is_refused():
    """P0 — Die Terminatorprüfung zählte nur ``\n``.

    Ein alleinstehendes ``\r`` kam durch — und der nachgelagerte SRT-Ingest
    macht daraus später eine neue Zeile. Über diesen Umweg wäre doch Struktur
    entstanden.
    """
    doc = CueDocument.parse(SRT, CueFormat.SRT)
    with pytest.raises(CueStructureChanged):
        doc.with_payloads(("Guten\rTag.", doc.payloads()[1]))


# ------------------------------------------------------ Bytes statt Zeichen


@pytest.mark.parametrize("fmt,text", [("srt", SRT), ("vtt", VTT)])
def test_parse_bytes_gives_back_the_same_bytes(fmt, text):
    """Die Zusage heißt jetzt, was sie ist.

    ``parse``/``render`` sichern Zeichenidentität zu. Bytegleichheit gibt es
    nur über ``parse_bytes``/``render_bytes`` — und das ist der Weg, sobald
    gehasht wird.
    """
    roh = (BOM + text).encode("utf-8")
    doc = CueDocument.parse_bytes(roh, CueFormat(fmt))
    assert doc.render_bytes() == roh


def test_non_utf8_input_is_refused_not_repaired():
    """Ein Ersetzungszeichen wäre eine stille Änderung am Transkript — und der
    Hash wäre der eines Dokuments, das so nie existiert hat."""
    with pytest.raises(CueParseError):
        CueDocument.parse_bytes(
            SRT.encode("latin-1").replace(b"Guten", b"Gr\xfc\xdfen"), CueFormat.SRT
        )


# ------------------------- Die Divergenz zum bestehenden SRT-Ingest


#: Zeilen, die ``adapters/input/srt.py`` annimmt und ``cue.py`` ablehnt.
#: Das ist **kein** Fehler in einem der beiden Parser, sondern eine offene
#: Vertragsfrage — und sie hat eine Folge: Eine Datei, die der Ingest annimmt,
#: kann später nicht pseudonymisiert werden. Der Record wäre blockiert.
STRENGER_ALS_INGEST = [
    ("0:00:01,000 --> 0:00:04,000", "einstellige Stunde"),
    ("00:00:01,5 --> 00:00:04,5", "einstellige Millisekunden"),
    ("00:00:01,50 --> 00:00:04,50", "zweistellige Millisekunden"),
    ("00:00:01,000-->00:00:04,000", "Pfeil ohne Leerzeichen"),
    ("00:00:01,000  -->  00:00:04,000", "mehrfache Leerzeichen"),
]


@pytest.mark.parametrize("zeile,label", STRENGER_ALS_INGEST)
def test_the_divergence_from_the_existing_srt_ingest_is_pinned(zeile, label):
    """Festgenagelt über die ECHTEN Parser, nicht über eine private Regex.

    Eine erste Fassung prüfte ``_TIME.match()``. Das ist ein Implementierungs-
    detail des Ingests und nicht seine Zusage. Geprüft wird jetzt, was
    tatsächlich zählt: ``parse_srt()`` nimmt die Datei an, ``CueDocument.parse()``
    lehnt sie ab.

    Der Test behauptet NICHT, dass die strengere Form richtig ist. Er hält
    fest, wo die beiden Parser verschiedener Meinung sind, und scheitert,
    sobald sich einer von beiden bewegt. Die Folge steht dabei: Eine Datei,
    die erfolgreich ingestiert wurde, kann später nicht pseudonymisiert
    werden — der Record wäre blockiert. Die Entscheidung (gemeinsamer
    Zeitzeilenparser oder strengere Form als kanonischer Vertrag) steht aus.
    """
    from ohpipe.adapters.input.srt import parse_srt

    datei = f"1\n{zeile}\nGuten Tag.\n"
    assert parse_srt(datei), f"{label}: der Ingest nimmt das nicht mehr an"

    with pytest.raises(CueParseError):
        CueDocument.parse(datei, CueFormat.SRT)
