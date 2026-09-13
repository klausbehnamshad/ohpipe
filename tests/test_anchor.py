"""Ankerdrift.

Herkunft: DINOH-Coverage-Audit Int1-Int3, Prüfung 4 ("Offset-Drift").
Kategorie: Sicherheitsinvariante -> zwingend portiert.

Der dortige Befund war, dass die Prüfung MANUELL erfolgte und ein negativer
Ausgang alle Coverage-Zahlen zu Fiktion gemacht hätte, ohne dass etwas rot
geworden wäre. Hier ist sie Teil des Typs.
"""

from __future__ import annotations

import pytest

from ohpipe.domain.anchor import Anchor, ReanchorOutcome, reanchor
from ohpipe.domain.revision_serialization import (
    PROJECTION_VERSION,
    InvalidRevisionNormalization,
)
from ohpipe.domain.transcript import Segment, TranscriptRevision

BASE = (
    "Der Interviewer fragt nach der Schule.\n"
    "Wir sind damals jeden Morgen zu Fuss gegangen.\n"
    "Das Essen war knapp, aber es gab immer etwas.\n"
    "Spaeter kam der Bus, das war eine Erleichterung.\n"
)


def rev(text: str = BASE) -> TranscriptRevision:
    """Eine Fassung fuer die Ankertests.

    Seit B3a sind `projection_version` und mindestens ein Segment
    identitaetsbildend (ADR 0028B-S, Teil P und S2). Die Segmente werden hier
    aus den Textzeilen abgeleitet: die Projektion ``seg-join-lf.v1`` verbindet
    genau mit U+000A, sodass der Volltext zeichengleich bleibt und die Zusagen
    dieser Datei unveraendert messbar sind.
    """
    return TranscriptRevision(
        text=text,
        projection_version=PROJECTION_VERSION,
        segments=_segmente_aus(text),
        source_kind="txt",
    )


def _segmente_aus(text: str) -> tuple[Segment, ...]:
    """Ein Segment je Textzeile — die Projektion verbindet genau mit U+000A."""
    return tuple(
        Segment(
            index=i,
            start_ms=i * 1000,
            end_ms=i * 1000 + 900,
            text=zeile,
            speaker="A",
            language="deu",
        )
        for i, zeile in enumerate(text.split(chr(10)))
    )


def revidiert(r: TranscriptRevision, neuer_text: str, note: str = "") -> TranscriptRevision:
    """`revise` mit mitgefuehrten Segmenten.

    Seit B3a sind Volltext und Segmente beide identitaetsbildend und muessen
    das Konsistenztor treffen (ADR 0028B-S, S12); eine Revision mit neuem Text
    und alten Segmenten faellt zu Recht. Die Zusagen dieser Datei bleiben
    unveraendert.
    """
    return r.revise(neuer_text, note=note, segments=_segmente_aus(neuer_text))


def anchor_on(r: TranscriptRevision, needle: str) -> Anchor:
    s = r.normalized.index(needle)
    return Anchor.create(r, s, s + len(needle))


def test_same_revision_is_exact():
    r = rev()
    a = anchor_on(r, "Das Essen war knapp")
    res = reanchor(a, r)
    assert res.outcome is ReanchorOutcome.EXACT
    assert not res.needs_human


def test_edit_after_the_anchor_keeps_offsets_exact():
    r = rev()
    a = anchor_on(r, "Das Essen war knapp")
    r2 = revidiert(r, BASE + "Und dann zogen wir weg.\n", note="Nachtrag am Ende")
    res = reanchor(a, r2)
    assert res.outcome is ReanchorOutcome.EXACT
    assert res.anchor is not None and res.anchor.transcript_sha256 == r2.sha256


def test_edit_before_the_anchor_is_a_unique_move_not_a_silent_shift():
    r = rev()
    a = anchor_on(r, "Das Essen war knapp")
    r2 = revidiert(r, "Vorbemerkung der Bearbeiterin.\n" + BASE, note="Kopf ergaenzt")
    res = reanchor(a, r2)
    assert res.outcome is ReanchorOutcome.UNIQUE_MOVE
    assert res.anchor is not None
    # Die neue Spanne zeigt wieder auf denselben Text - aber es ist ein neuer
    # Anker mit neuem Bezug, keine stille Verschiebung der alten Offsets.
    assert res.anchor.start != a.start
    assert res.anchor.quote == a.quote
    assert res.anchor.transcript_sha256 == r2.sha256


def test_deleted_quote_is_missing_and_never_guessed():
    r = rev()
    a = anchor_on(r, "Das Essen war knapp")
    r2 = revidiert(r, BASE.replace("Das Essen war knapp, aber es gab immer etwas.\n", ""))
    res = reanchor(a, r2)
    assert res.outcome is ReanchorOutcome.MISSING
    assert res.anchor is None
    assert res.needs_human


def test_a_duplicate_elsewhere_does_not_invalidate_an_anchor_that_still_fits():
    """Vorrangregel: Sitzt der Anker noch exakt, ist er exakt - auch wenn das
    Zitat inzwischen ein zweites Mal vorkommt. Eine Kopie an anderer Stelle
    macht eine unveraenderte Stelle nicht mehrdeutig."""
    r = rev()
    a = anchor_on(r, "zu Fuss gegangen")
    doubled = BASE + "Wir sind damals jeden Morgen zu Fuss gegangen.\n"
    assert reanchor(a, revidiert(r, doubled)).outcome is ReanchorOutcome.EXACT


#: Ein Block, dessen Umgebung auf beiden Seiten laenger ist als das
#: Kontextfenster. Kommt er zweimal vor, sind BEIDE Kontexte identisch - dann
#: kann auch der Kontext-Hash nicht mehr trennen.
BLOCK = (
    "Es war eine lange Zeit, und wir erinnern uns heute nur noch bruchstueckhaft daran.\n"
    "Wir sind damals jeden Morgen zu Fuss gegangen.\n"
    "Danach wurde alles anders, was wir aber erst sehr viel spaeter verstanden haben.\n"
)


def test_duplicated_quote_after_a_shift_is_ambiguous_and_the_machine_does_not_choose():
    r = rev(BLOCK)
    a = anchor_on(r, "zu Fuss gegangen")
    # Kopf ergaenzt (Offsets brechen) UND der Block kommt zweimal vor, mit
    # identischem Kontext auf beiden Seiten.
    res = reanchor(a, revidiert(r, "Vorbemerkung der Bearbeiterin.\n" + BLOCK + BLOCK))
    assert res.outcome is ReanchorOutcome.AMBIGUOUS
    assert res.anchor is None
    assert len(res.candidates) == 2
    assert res.needs_human


def test_context_can_disambiguate_but_only_when_it_is_unique():
    r = rev()
    a = anchor_on(r, "war knapp")
    # Kopf ergaenzt (Offsets brechen) UND dieselbe Wortfolge taucht ein zweites
    # Mal auf - aber in klar anderem Kontext. Der Kontext-Hash traegt.
    other = "Vorbemerkung der Bearbeiterin.\n" + BASE + "Der Platz war knapp, das Zimmer klein.\n"
    res = reanchor(a, revidiert(r, other))
    assert res.outcome is ReanchorOutcome.UNIQUE_MOVE
    assert res.anchor is not None
    assert len(res.candidates) == 2  # zwei Treffer, durch Kontext eindeutig


def test_crlf_is_no_longer_absorbed_as_format_noise():
    """Seit B3a faellt U+000D fail-closed, und die Ankersicht ist zeichengenau.

    Die frueher hier gemessene Zusage — CRLF und rechtsseitiger Whitespace
    seien blosses Formatrauschen — traegt die angenommene Norm nicht mehr:
    `docs/adr/0028B-S-revisionsserialisierung-und-P-projektionsvertrag.md`
    Teil P haelt Whitespace zeichengenau und weist U+000D zurueck, statt es
    umzuschreiben. Eine Adresse, die zwei verschiedene Eingaben still auf
    denselben Wert zieht, bindet nicht mehr eindeutig.

    Auch die **anker-sichtbare** Textgestalt zieht nichts mehr zusammen: die
    frueher hier behauptete Gegenprobe, `normalized` schlucke das Rauschen
    weiterhin, ist mit dem Korrekturkandidaten falsch geworden und durch die
    zeichengenaue Zusage ersetzt. Sonst waeren CANON-``fulltext`` und
    anker-sichtbarer Text zwei verschiedene Texte, und eine auf dem
    zeichengenauen Text gesetzte Fundstelle waere ueber den Anker nicht mehr
    vollstaendig adressierbar.
    """
    r = rev()
    noisy = BASE.replace(chr(10), "  " + chr(13) + chr(10))

    with pytest.raises(InvalidRevisionNormalization):
        _ = revidiert(r, noisy).sha256

    # Gegenprobe eins: die Ankersicht ist zeichengenau — sie zieht die beiden
    # Eingaben NICHT mehr auf denselben Wert zusammen.
    verrauscht = TranscriptRevision(
        text=noisy, projection_version=PROJECTION_VERSION, segments=r.segments
    )
    assert verrauscht.normalized == verrauscht.text
    assert verrauscht.normalized != r.normalized

    # Gegenprobe zwei: fuer JEDE Fassung gilt normalized == text und
    # slice(0, len(text)) == text — ohne Trimmen und ohne ergaenztes LF.
    for text in ("abc", "  Rand  ", BASE):
        eine = TranscriptRevision(
            text=text, projection_version=PROJECTION_VERSION, segments=r.segments
        )
        assert eine.normalized == text
        assert eine.slice(0, len(text)) == text

    # Gegenprobe drei: rechtsseitiger Whitespace OHNE U+000D faellt nicht,
    # ist aber identitaetsbildend — er wird getragen, nicht getrimmt.
    mit_rand = BASE.replace(chr(10), "  " + chr(10))
    assert revidiert(r, mit_rand).sha256 != r.sha256


def test_anchor_rejects_impossible_span():
    r = rev()
    with pytest.raises(ValueError):
        Anchor.create(r, 10, 5)
    with pytest.raises(ValueError):
        Anchor.create(r, 0, len(r.normalized) + 1)
