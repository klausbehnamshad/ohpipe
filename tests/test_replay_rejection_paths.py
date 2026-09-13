"""Drei Zweige, die das Replay nie erreicht hat — und die die Demo zeigt.

Herkunft: Coverage-Audit 04.08. Nachdem ``COVERAGE_PROCESS_START`` durch
``_forge.cli`` durchgereicht wird, ist ``replay.py`` bei 84 % statt scheinbar
41 %. Die verbleibende Lücke ist **nicht zufällig verteilt**: gemessen ist der
glückliche Pfad, ungemessen sind fast ausschließlich die Ablehnungszweige —
also genau das, wofür ``ohpipe`` gebaut ist.

Diese Datei zieht drei davon vor. Nicht als allgemeine Härtung — die
Modellbeleg-Zweige gehören zum Modelladapter, wo ein gefälschter Beleg ein
realistischer Angriff statt eines synthetischen ist. Sondern weil diese drei
am 23.09. vorgeführt werden und der Weg dorthin unbewiesen war:

* **abgeschnittener Lauf** (``finish_reason``) — die DINOH-Lektion.
  ``ModelReceipt.validate()`` ist als Domänenobjekt gründlich geprüft, aber
  der Weg, auf dem ein abgeschnittener Beleg **durch das Journal** kommt, ist
  nie gelaufen. Die Invariante steht zweimal im Code und war einmal geprüft.
* **``SourceBinding.DRIFTED``** — Demo-Moment 2: Ankerdrift wird sichtbar.
* **``DerivationState.STALE``** — Demo-Moment 4: die Entscheidung wird
  entwertet, weil die Bytes sich unter ihr geändert haben.

Alle drei laufen **mit Schlüssel**. Ohne Schlüssel kappt die Autoritätsregel
(ADR 0017) vorher, und der Test bewiese nur, dass die Kappung greift — die
Zweige hier lägen weiter im Dunkeln.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._forge import cli_keyed, forge_keyed
from .test_forgery import wellformed_chain


@pytest.fixture
def welt(tmp_path: Path):
    """Authentifizierte Welt mit Schlüssel ausserhalb der Datenwurzel."""
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"

    def run(*args: str):
        return cli_keyed(*args, root=wurzel, key=key)

    assert run("init").returncode == 0
    return wurzel, key, run


def _record(run) -> dict:
    ergebnis = run("status", "--json")
    return json.loads(ergebnis.stdout)["details"]["records"][0]


def _gegenprobe_gruen(run) -> None:
    """Die unveränderte Kette MUSS grün sein.

    Ohne diese Zusicherung prüfte jeder Test unten nur, dass irgendetwas rot
    wird — und das wäre auch bei einem kaputten Fixture der Fall.
    """
    rec = _record(run)
    assert rec["findings"] == [], rec["findings"]
    assert rec["status"] == "READY", rec["explanation"]


# ---------------------------------------------------------------- Zeile 384


def test_a_truncated_model_receipt_is_refused_on_the_way_through_the_journal(welt):
    """Der abgeschnittene Lauf — über das Journal, nicht über den Konstruktor.

    ``finish_reason='length'`` heisst: Das Modell hat aufgehört, weil das
    Token-Budget zu Ende war, nicht weil es fertig war. Im Vorgängersystem
    hiess das, dass Themenplätze fehlten und die Coverage-Zahl trotzdem
    gemeldet wurde.

    **Warum hier der WORTLAUT geprüft wird und nicht „irgendetwas mit
    abgeschnitten".** Die erste Fassung dieses Tests prüfte
    ``any("abgeschnittener Lauf" in f)``. Eine Mutationsprobe — ``if r.truncated``
    auf ``if False and r.truncated`` — liess ihn **grün**. Der Grund ist keine
    Lücke, sondern das Gegenteil: Die Invariante ist doppelt abgesichert. Fällt
    die erste Linie weg, fängt die Bindungsprüfung denselben Fall, mit einer
    anderen und ausführlicheren Begründung, in der dieselben Wörter vorkommen.

    Ein Test, der beide Linien nicht unterscheiden kann, prüft keine von
    beiden. Deshalb steht hier die genaue Zeichenkette der ersten Linie.
    """
    wurzel, key, run = welt
    kette = wellformed_chain(wurzel)

    getroffen = 0
    for ereignis in kette:
        p = ereignis["payload"]
        if ereignis["kind"] == "receipt.recorded" and p.get("kind") == "model":
            p["finish_reason"] = "length"
            getroffen += 1
    assert getroffen >= 1, "die Kette enthält keinen Modellbeleg — Fixture geändert?"

    forge_keyed(wurzel, key, kette)
    rec = _record(run)

    assert rec["status"] != "READY", rec["explanation"]
    erwartet = "Modellbeleg mit finish_reason='length' — abgeschnittener Lauf"
    assert erwartet in rec["findings"], rec["findings"]
    # Und die ZWEITE Linie darf hier gerade nicht sprechen: Wenn sie es tut,
    # ist die erste ausgefallen.
    assert not any("nicht an die Entscheidung gebunden" in f for f in rec["findings"]), (
        "die Bindungspruefung hat uebernommen — die erste Linie fehlt"
    )


def test_the_same_chain_with_a_clean_finish_reason_is_ready(welt):
    """Gegenprobe. Ohne sie prüfte der Test darüber nur, dass die Kette
    überhaupt rot werden kann."""
    wurzel, key, run = welt
    forge_keyed(wurzel, key, wellformed_chain(wurzel))
    _gegenprobe_gruen(run)


# ----------------------------------------------------------------- Zeile 95


@pytest.mark.parametrize("ausgang", ["ambiguous", "missing"])
def test_a_non_closable_reanchor_outcome_marks_the_source_binding_as_drifted(welt, ausgang):
    """Demo-Moment 2: Ankerdrift wird sichtbar, statt still zu verschwinden.

    ``ambiguous`` und ``missing`` sind die beiden Ausgänge, die
    ``ReanchorOutcome.machine_closable`` verneint. Genau dafür existiert
    ``SourceBinding.DRIFTED`` — und genau dieser Zweig ist im Replay nie
    gelaufen.
    """
    wurzel, key, run = welt
    kette = wellformed_chain(wurzel)

    getroffen = 0
    for ereignis in kette:
        if ereignis["kind"] == "anchor.checked":
            ereignis["payload"]["outcome"] = ausgang
            getroffen += 1
    assert getroffen >= 1, "die Kette enthält keine Ankerprüfung — Fixture geändert?"

    forge_keyed(wurzel, key, kette)
    rec = _record(run)

    assert rec["status"] != "READY", rec["explanation"]
    bindungen = {a["source_binding"] for a in rec["artifacts"].values()}
    assert bindungen == {"drifted"}, bindungen


def test_a_closable_reanchor_outcome_stays_bound(welt):
    """Gegenprobe: ``exact`` bindet. Sonst prüfte der Test oben nur, dass
    irgendein Ankerwert etwas kaputt macht."""
    wurzel, key, run = welt
    forge_keyed(wurzel, key, wellformed_chain(wurzel))
    rec = _record(run)
    bindungen = {a["source_binding"] for a in rec["artifacts"].values()}
    assert bindungen == {"bound"}, bindungen


# ---------------------------------------------------------------- Zeile 103


def test_regenerating_an_artifact_after_its_receipt_makes_the_derivation_stale(welt):
    """Demo-Moment 4: Die Bytes haben sich unter der Entscheidung geändert.

    Der Beleg lautet auf die alten Bytes, das Artefakt trägt die neuen. Der
    Ableitungszustand ist dann ``stale`` — nicht ``current`` und nicht
    ``unverifiable``. Das ist der Unterschied zwischen „nicht belegt" und
    „belegt, aber für etwas anderes", und nur der zweite Fall ist der
    gefährliche: Er sieht vollständig aus.
    """
    wurzel, key, run = welt
    kette = wellformed_chain(wurzel)

    # Ein neuer Stand DESSELBEN Artefakts, nach Beleg und Entscheidung.
    # Der Beleg wird nicht angefasst — genau das ist der Punkt.
    neue_bytes = "b" * 64
    ziel = "l1.suggestions"
    assert any(
        e["kind"] == "artifact.produced" and e["payload"]["artifact"] == ziel for e in kette
    ), f"{ziel} kommt in der Kette nicht vor — Fixture geändert?"
    kette.append({"kind": "artifact.produced", "payload": {"artifact": ziel, "sha256": neue_bytes}})

    forge_keyed(wurzel, key, kette)
    rec = _record(run)

    assert rec["status"] != "READY", rec["explanation"]
    assert rec["artifacts"][ziel]["derivation_state"] == "stale", rec["artifacts"][ziel]
    # Die ANDEREN Artefakte bleiben unberührt. Ein Zustand, der auf den ganzen
    # Record durchschlägt, wäre nicht diagnostisch.
    andere = {
        n: a["derivation_state"]
        for n, a in rec["artifacts"].items()
        if n != ziel and a["derivation_state"] != "not_applicable"
    }
    assert andere["l1.coverage"] == "stale", andere
    assert andere["metadata.draft"] == "stale", andere
    assert andere["export.bundle"] == "stale", andere
    assert rec["artifacts"]["transcript.confirmed"]["status"] == "READY"


# ------------------------------------------------- drei überlebende Mutanten
#
# Nachgetragen aus einer zweiten Mutationsprobe. Die drei Tests oben fallen bei
# genau der Mutation, für die sie gebaut sind. Drei weitere Mutationen an
# denselben Zweigen überlebten die vollständige Suite jedoch:
#
#   FINISH_CLEAN auf {"stop"} verengt                  -> kein Test fiel
#   UNIQUE_MOVE nicht mehr als gebunden gewertet       -> kein Test fiel
#   unbekanntes Ankerergebnis wird angenommen          -> kein Test fiel
#
# Alle drei brechen in dieselbe Richtung: Sie halten an, wo nichts anzuhalten
# ist. Das ist fail-closed und deshalb kein Schutzfehler — aber es ist ein
# Ablauffehler, und der ist hier nicht das kleinere Übel: Ein Halt, den niemand
# auflösen kann, weil nichts kaputt ist, erzieht dazu, Halte zu umgehen.


CLEAN_FINISH_REASONS = ["stop", "end_turn", "eos", "stop_sequence"]


def test_the_allowlist_of_clean_finish_reasons_is_exactly_this_list():
    """Die Liste steht hier AUSGESCHRIEBEN und wird gegen den Code geprüft.

    Würde die Parametrierung unten aus ``FINISH_CLEAN`` abgeleitet, verschwände
    beim Verengen der Allowlist einfach ein Testfall, und die Suite bliebe
    grün — der Test prüfte den Code gegen sich selbst. Dieselbe Regel wie bei
    ``wellformed_chain``: ein Angriff rechnet nach, er leitet nicht ab.
    """
    from ohpipe.domain.receipt import FINISH_CLEAN

    assert set(CLEAN_FINISH_REASONS) == set(FINISH_CLEAN), (
        "Die Allowlist sauberer Abbruchursachen hat sich geändert. Das ist "
        "keine Kosmetik: Jeder entfernte Wert lässt einen fremden Adapter, der "
        "ihn meldet, als abgeschnittenen Lauf gelten — der Lauf wird abgelehnt, "
        "obwohl er sauber beendet hat."
    )


@pytest.mark.parametrize("grund", CLEAN_FINISH_REASONS)
def test_every_clean_finish_reason_passes_through_the_journal(welt, grund):
    """Nicht nur ``stop``. Ollama meldet ``stop``, andere Adapter melden
    ``eos`` oder ``end_turn`` — und ein Ensemble ist ausdrücklich vorgesehen
    (ADR 0024). Wird die Allowlist verengt, hält der Lauf grundlos an."""
    wurzel, key, run = welt
    kette = wellformed_chain(wurzel)
    getroffen = 0
    for ereignis in kette:
        nutzlast = ereignis["payload"]
        if ereignis["kind"] == "receipt.recorded" and nutzlast.get("kind") == "model":
            nutzlast["finish_reason"] = grund
            getroffen += 1
    assert getroffen >= 1, "die Kette enthält keinen Modellbeleg — Fixture geändert?"

    forge_keyed(wurzel, key, kette)
    _gegenprobe_gruen(run)


@pytest.mark.parametrize("ausgang", ["exact", "unique_move"])
def test_both_machine_closable_outcomes_stay_bound(welt, ausgang):
    """``unique_move`` ist maschinell abschließbar — das ist die halbe Aussage
    des Ankermoduls.

    Die Gegenprobe oben benutzt nur ``exact``. Fiele ``unique_move`` aus der
    Menge der gebundenen Ausgänge, würde jedes eindeutig verschobene Zitat zu
    ``REVIEW_REQUIRED`` — menschliche Arbeit ohne menschliche Frage, und der
    Grund dafür stünde nirgends.
    """
    wurzel, key, run = welt
    kette = wellformed_chain(wurzel)
    for ereignis in kette:
        if ereignis["kind"] == "anchor.checked":
            ereignis["payload"]["outcome"] = ausgang
    forge_keyed(wurzel, key, kette)

    rec = _record(run)
    bindungen = {a["source_binding"] for a in rec["artifacts"].values()}
    assert bindungen == {"bound"}, bindungen


def test_an_unknown_anchor_outcome_says_so_instead_of_quietly_drifting(welt):
    """Der Befund muss die Ursache NENNEN, nicht nur rot färben.

    Ohne die Gültigkeitsprüfung landet ein erfundener Ausgang trotzdem in
    ``anchor_outcome``, fällt dort in den Sonst-Zweig und wird zu ``drifted``.
    Der Record ist dann rot — aus dem falschen Grund, und der Operator sucht
    eine Ankerdrift, die es nicht gibt. Ein Test, der nur ``!= READY`` prüft,
    kann die beiden Fälle nicht unterscheiden und prüft damit keinen von beiden.
    """
    wurzel, key, run = welt
    kette = wellformed_chain(wurzel)
    for ereignis in kette:
        if ereignis["kind"] == "anchor.checked":
            ereignis["payload"]["outcome"] = "wahrscheinlich_schon_richtig"
    forge_keyed(wurzel, key, kette)

    rec = _record(run)
    assert any("unbekanntem Ergebnis" in f for f in rec["findings"]), (
        f"Die Gültigkeitsprüfung hat nicht gesprochen: {rec['findings']}"
    )
    assert rec["status"] == "STOP", rec["explanation"]
