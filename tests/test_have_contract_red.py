"""Rotphase zu C4 — `have` prüft den ganzen Vertrag, nicht die Bytepräsenz.

E4 wörtlich:

    have enthält ein Artefakt genau dann, wenn
    → Bytes existieren
    → ALLE laut ArtifactContract erforderlichen Achsen erfüllt sind
    → es enabled und nicht excluded ist

Heute entscheidet für abgeleitete Artefakte allein ``f.sha256 is not None``
(`src/ohpipe/application/replay.py::RecordView.have`). Ein ausgeschlossenes
Artefakt mit Bytes bleibt darin. Kein Produktivcode in dieser Datei.

**Woran das gemessen wird, und woran ausdrücklich nicht.** Die Zielassertion
liest ``graph.plan(view.have).steps`` — die Verhaltenswirkung, nicht die
Mechanik. Drei Alternativen sind verworfen, jede aus einem gemessenen Grund:

*   **Nicht ``RecordView.have`` selbst.** Eine Zusicherung auf ein internes
    Attribut sichert die Umsetzung und nicht die Folge; sie wäre auch von
    einer Änderung erfüllt, die niemand bemerkt.
*   **Nicht ``next_gates``.** Die erste Fassung dieses Markers tat das und war
    rot — aber die minimale Zielreparatur machte ihn **nicht** grün. Gemessen,
    zweimal: ``have`` verliert das Artefakt, ``next_gates`` bleibt gleich. Ein
    Gate hält, was hinter IHM liegt; die Gateliste bildet die Zugehörigkeit zu
    ``have`` nicht ab. Ein Marker, dessen Grünrichtung nicht nachweisbar ist,
    ist ein Wartemarker auf etwas Unerreichbares — genau der Fehler von T3 in
    Serie 3b, und diesmal war er meiner.
*   **Nicht die ganze Schrittliste.** Sie hängt daran, welche Artefakte die
    Fixture sonst noch trägt. Zugesichert wird die Zugehörigkeit **eines**
    ausgeschriebenen Schrittnamens.

``L1_SCHRITT`` steht von Hand da und wird nicht aus dem Graphen geholt: ein
Test, der den erwarteten Schritt aus ``_producer`` errechnete, prüfte den
Graphen gegen sich selbst.

C4 ändert ausschliesslich die Berechnung von ``have``. Der Reportvertrag und
``next_gates`` bleiben, wie sie sind; ein öffentliches ``next_steps`` ist eine
spätere Scheibe.
"""

from __future__ import annotations

import pytest

from ohpipe.application.replay import ArtifactFacts, LegacyDisposition, RecordView
from ohpipe.domain.anchor import ReanchorOutcome
from ohpipe.domain.step import DEFAULT_GRAPH

#: Bytes, auf die sich die Sicht beruft. Hier genügt ein Platzhalter: geprüft
#: wird der Planer, nicht der Contentstore.
SHA = "a" * 64

#: Das ausgeschlossene Artefakt und der Schritt, der es erzeugt. Beide
#: ausgeschrieben, nicht abgeleitet.
AUSGESCHLOSSEN = "l1.suggestions"
L1_SCHRITT = "l1.suggest"


def _sicht(disposition: LegacyDisposition) -> RecordView:
    """Eine Sicht, in der ``l1.suggestions`` Bytes hat und alles davor steht.

    ``transcript.confirmed`` trägt eine echte Annahme, sonst fiele es schon
    an der bestehenden Regel für menschliche Artefakte aus ``have`` — und der
    Marker wartete dann auf etwas anderes als auf den Ausschluss.
    """
    sicht = RecordView(record_id="R")
    sicht.facts["transcript.revision"] = ArtifactFacts(
        name="transcript.revision",
        contract=DEFAULT_GRAPH.contract_for("transcript.revision"),
        is_egress=False,
        sha256=SHA,
    )
    sicht.facts["transcript.confirmed"] = ArtifactFacts(
        name="transcript.confirmed",
        contract=DEFAULT_GRAPH.contract_for("transcript.confirmed"),
        is_egress=False,
        sha256=SHA,
        # Die echte Annahme braucht einen gepruefen Anker, sonst stuende das
        # Artefakt auf UNKNOWN und faellt aus ``have`` aus einem Grund, den
        # dieser Marker gar nicht meint. Seit C4 gibt es keine is_human-Fahne
        # mehr; die Bindung kommt aus Anker und Vertrag.
        anchor_outcome=ReanchorOutcome.EXACT.value,
        decided_sha=SHA,
        decided_verdict="ACCEPT",
    )
    sicht.facts[AUSGESCHLOSSEN] = ArtifactFacts(
        name=AUSGESCHLOSSEN,
        contract=DEFAULT_GRAPH.contract_for(AUSGESCHLOSSEN),
        is_egress=False,
        sha256=SHA,
        anchor_outcome=ReanchorOutcome.EXACT.value,  # Bindung -> BOUND
        receipt_for=SHA,  # Ableitung -> CURRENT (Beleg auf dieselben Bytes)
        disposition=disposition,
    )
    return sicht


def test_a_usable_artifact_is_not_planned_again():
    """Gegenprobe: was nutzbar vorliegt, wird nicht noch einmal erzeugt.

    Ohne sie wäre der Marker darunter auch dann eingelöst, wenn C4 ``have``
    so verengte, dass gar nichts mehr hineinkommt — dann plante der Planer
    alles immer wieder neu, und ein Rerun überschriebe vorhandene Evidenz.

    Heute grün, und nach C4 muss es grün bleiben.
    """
    sicht = _sicht(LegacyDisposition.OK)
    schritte = [s.name for s in DEFAULT_GRAPH.plan(sicht.have).steps]

    assert L1_SCHRITT not in schritte, (
        f"{AUSGESCHLOSSEN} liegt nutzbar vor, aber {L1_SCHRITT!r} wird trotzdem "
        f"geplant: {schritte!r}"
    )


def test_an_excluded_artifact_with_bytes_leaves_have():
    """Ein ausgeschlossenes Artefakt gilt dem Planer nicht als vorhanden.

    Gemessen, heute — dieselbe Sicht zweimal, einmal mit
    ``disposition = OK`` und einmal mit ``disposition = EXCLUDED``::

        nutzbar    have enthaelt l1.suggestions   steps ohne l1.suggest
        excluded   have enthaelt l1.suggestions   steps ohne l1.suggest   <- gleich

    ``have`` ist in beiden Fällen **identisch**. Der Ausschluss kommt beim
    Planer gar nicht an: das Artefakt ist gleichzeitig ``EXCLUDED`` und
    Vorbedingung des nächsten Schritts — genau der Zustand, den E4 ausschliesst.

    Nach C4 muss ``l1.suggest`` wieder planbar sein, weil sein Ergebnis nicht
    mehr als vorhanden gilt.
    """
    sicht = _sicht(LegacyDisposition.EXCLUDED)

    # Waechter: es IST ausgeschlossen, und die Bytes sind da. Ohne diese Zeilen
    # waere die Zielzeile auch von einer Sicht erfuellt, in der das Artefakt
    # aus einem ganz anderen Grund fehlt.
    fakt = sicht.facts[AUSGESCHLOSSEN]
    assert fakt.disposition is LegacyDisposition.EXCLUDED
    assert fakt.sha256 == SHA

    schritte = [s.name for s in DEFAULT_GRAPH.plan(sicht.have).steps]

    assert L1_SCHRITT in schritte, (
        f"{AUSGESCHLOSSEN} ist ausgeschlossen, wird aber weiter als vorhanden "
        f"geplant — {L1_SCHRITT!r} fehlt in {schritte!r}. Bytepraesenz genuegt nicht."
    )


# ---------------------------------------------------------------- C4 · Waechter
#
# Marker und Gegenrichtung oben decken ``EXCLUDED`` und den positiven
# ``READY``-Fall. Die uebrigen tragenden Bedingungen von ``usable`` sind sonst
# ungepinnt: eine Abschwaechung auf „alles ausser EXCLUDED", das Weglassen der
# Byteklausel und ``usable()`` statt ``usable(self.enabled)`` liessen die Suite
# ohne diese Waechter gruen. Jeder Fakt wird mit seinem Vertrag aus
# ``DEFAULT_GRAPH.contract_for`` konstruiert — nie mit einer zweiten
# Vertragstabelle — und die Zusicherung liest ``usable``/``have`` direkt (die zu
# bauende Einheit selbst, zulaessig wie die C3-Achtfachmatrix direkt auf
# ``status``).


def _fakt(name: str, **evidenz) -> ArtifactFacts:
    return ArtifactFacts(
        name=name,
        contract=DEFAULT_GRAPH.contract_for(name),
        is_egress=DEFAULT_GRAPH.producer_of(name).leaves_system,
        **evidenz,
    )


def test_a_contract_free_artifact_with_bytes_is_usable():
    """Positiv all-N/A — der Ueber-Verengungs-Waechter (Mutant V13).

    ``transcript.revision`` (F,F,F) mit Bytes steht auf allen drei Achsen
    ``NOT_APPLICABLE`` und ist ``READY``. Die bestehende Gegenrichtung faengt
    eine Verengung, die eine KONKRETE Achse verlangt, nicht — dieses
    Ingressartefakt muss nutzbar bleiben, sonst löst es seinen Nachfolger nie aus.
    """
    fakt = _fakt("transcript.revision", sha256=SHA)
    assert fakt.state().status.name == "READY"
    assert fakt.usable() is True

    sicht = RecordView(record_id="R")
    sicht.facts["transcript.revision"] = fakt
    assert "transcript.revision" in sicht.have


def test_bytes_are_a_separate_clause_from_status():
    """Bytes fehlen (Mutant V10) — Status ``READY``, aber keine Bytes.

    Derselbe (F,F,F)-Vertrag OHNE ``sha256``: der Status ist weiter ``READY``
    (drei Achsen ``NOT_APPLICABLE``), aber ohne Bytes ist nichts nutzbar. Ohne
    die eigene Byteklausel gaelte er als vorhanden.
    """
    fakt = _fakt("transcript.revision")
    assert fakt.state().status.name == "READY"
    assert fakt.usable() is False

    sicht = RecordView(record_id="R")
    sicht.facts["transcript.revision"] = fakt
    assert "transcript.revision" not in sicht.have


def _unknown() -> ArtifactFacts:
    # metadata.draft (T,T,F): Beleg CURRENT, aber KEIN Anker -> UNKNOWN -> STOP
    return _fakt("metadata.draft", sha256=SHA, receipt_for=SHA)


def _unverifiable() -> ArtifactFacts:
    # Anker EXACT, aber KEIN Beleg trotz Herkunftspflicht -> UNVERIFIABLE -> STOP
    return _fakt("metadata.draft", sha256=SHA, anchor_outcome=ReanchorOutcome.EXACT.value)


def _stale() -> ArtifactFacts:
    # Anker EXACT, Beleg auf ANDERE Bytes -> STALE
    return _fakt(
        "metadata.draft",
        sha256=SHA,
        anchor_outcome=ReanchorOutcome.EXACT.value,
        receipt_for="b" * 64,
    )


def _drifted() -> ArtifactFacts:
    # Anker nicht schliessbar -> DRIFTED -> REVIEW_REQUIRED
    return _fakt(
        "metadata.draft",
        sha256=SHA,
        anchor_outcome=ReanchorOutcome.AMBIGUOUS.value,
        receipt_for=SHA,
    )


def _undecided() -> ArtifactFacts:
    # transcript.confirmed (T,F,T): Anker EXACT, KEINE Entscheidung -> ACTION_NEEDED
    return _fakt("transcript.confirmed", sha256=SHA, anchor_outcome=ReanchorOutcome.EXACT.value)


@pytest.mark.parametrize(
    ("bauer", "erwarteter_status"),
    [
        (_unknown, "STOP"),
        (_unverifiable, "STOP"),
        (_stale, "STALE"),
        (_drifted, "REVIEW_REQUIRED"),
        (_undecided, "ACTION_NEEDED"),
    ],
)
def test_a_non_ready_artifact_is_not_usable(bauer, erwarteter_status):
    """Jeder Nicht-READY-Zustand ist nicht nutzbar (Mutant V11).

    Eine Abschwaechung auf „alles ausser EXCLUDED" liesse alle fuenf durch;
    genau darum steht hier jeder Zustand einzeln mit ausgeschriebenem Ziel.
    """
    fakt = bauer()
    assert fakt.state().status.name == erwarteter_status
    assert fakt.usable() is False


def test_a_disabled_record_yields_an_empty_have():
    """``enabled`` wird durchgereicht (Mutant V12).

    Ein sonst nutzbarer Fakt: ``usable(True)`` ist wahr, ``usable(False)`` ist
    falsch (``enabled=False`` ergibt ``EXCLUDED``), und ein
    ``RecordView(enabled=False)`` liefert leeres ``have`` — so ist die
    Durchreichung ``usable(self.enabled)`` gepinnt und nicht nur die Methode.
    """
    fakt = _fakt("transcript.revision", sha256=SHA)
    assert fakt.usable(True) is True
    assert fakt.usable(False) is False

    sicht = RecordView(record_id="R", enabled=False)
    sicht.facts["transcript.revision"] = fakt
    assert sicht.have == set()
