"""Vertragstotalität als eigene Prüfung, in beide Richtungen.

E2‑N Nummer 2: *„Ein Artefakt ohne Vertrag ist ein Befund, kein Default."*
Kein `contracts.get(name, ArtifactContract())`. Diese Datei hat in `R1`
beschrieben, **woran man das erkennt**, bevor jemand es baut; mit `C1` ist es
gebaut und die drei `xfail(strict)`-Marker sind entfernt (E7:
Markerentfernung im Implementierungs-MR). Der Dateiname bleibt, weil ein
prüfsummengesichertes Blatt keine Umbenennung wert ist, die jeden Verweis auf
ihn bricht.

**Die drei sind nur ZUSAMMEN eine Zusicherung.** Gemessen, an der eigenen
Umsetzung: ein absichtlich leeres ``check_contracts(graph) -> []`` macht
`test_the_default_graph_satisfies_contract_totality` grün. Ein No-op erfüllt
ihn. Erst die beiden anderen fangen den No-op ab — 46 → 45 statt 46 → 43.
Deshalb steht in der Abnahme nie „die C1-Marker sind grün", sondern die drei
Namen einzeln.

**Wo die Prüfung wohnt — entschieden als E15/15a.** Die Totalität bekommt eine
eigene Funktion ``check_contracts(graph)``, **nicht** ``StepGraph.__post_init__``
und **nicht** ``check_egress_gates``. Beides ist gemessen begründet:

*   Ein Konstruktorhalt zwänge jeden Testgraphen, sofort vollständig zu sein.
*   Eine Erweiterung von ``check_egress_gates`` bewegt fremde Tests. Gemessen
    an einer Wegwerfprobe: die naive Fassung liess **sechs** Tests in
    ``tests/test_receipt_and_graph.py`` fallen, weil sie auf die exakte
    Ausgabe dieser Funktion zusichern. Die Kerninvariante darf nicht in
    Vertragslärm untergehen.

``check_contracts`` darf Verstösse als Liste liefern; **die Produktionsgrenze
macht daraus einen Fehler**, nicht die Prüffunktion. C1 hängt sie an vier
Stellen ein: eigener Test für ``DEFAULT_GRAPH``, alle ausgelieferten
Profilgraphen im ``invariants``-Job, fail-closed in ``build_graph``, und —
solange ``replay`` beliebige Graphen annimmt — dort vor dem Fold. Ein Tor, das
nur im CI-Job läuft, liesse einen zur Laufzeit gebauten Profilgraphen trotz
verletzter Totalität in den Replay.

**Warum die Voraussetzungszeilen stehen bleiben.** In `R1` brachen alle drei
Marker an ihrer Voraussetzung — ``check_contracts`` gab es nicht — und nicht
an der Zielassertion; ein Test, der die Funktion importierte, wäre ein
``ImportError`` beim Sammeln gewesen, und ein Sammelfehler ist keine
Zusicherung. Die Zusage von damals hat gehalten: unter der C1-Umsetzung
wandert der Bruch auf die Zielassertion, die Voraussetzung war ein Artefakt
jener Woche. Die Zeilen bleiben trotzdem stehen, jetzt in anderer Rolle: sie
melden eine Umbenennung von ``check_contracts`` mit einem benannten Satz statt
mit einem Sammelfehler über die ganze Datei.

Alle Sollmengen stehen von Hand da und werden nicht aus ``steps`` oder
``contracts`` zurückgerechnet.
"""

from __future__ import annotations

import dataclasses

from ohpipe.domain import step as graphmodul
from ohpipe.domain.step import DEFAULT_GRAPH, Kind, Step, StepGraph, check_egress_gates

#: Ein Name, den kein Schritt des Produktionsgraphen erzeugt. Ausgeschrieben:
#: ein Test, der ihn aus ``produces`` errechnete, prüfte den Graphen gegen
#: sich selbst.
FREMD = "erfunden.artefakt"

#: Der Name, den der kleine Probegraph erzeugt — ebenfalls von Hand.
EIGEN = "x.artefakt"

#: Wie die fehlende Prüfung heisst, wenn es sie gibt. Gepinnt wie
#: ``GRAPHBEFUND`` und ``AUFFANGFALL``.
PRUEFUNG = "check_contracts"


def _pruefung():
    return getattr(graphmodul, PRUEFUNG, None)


def test_the_default_graph_has_no_egress_violations():
    """Gegenprobe: die Kerninvariante bleibt, was sie ist.

    Sie steht hier, weil C1 die Versuchung trägt, die Vertragstotalität in
    ``check_egress_gates`` mit hineinzuschreiben. Täte C1 das, meldete diese
    Funktion für jeden unvollständigen Testgraphen etwas — und sechs
    bestehende Zusicherungen in ``tests/test_receipt_and_graph.py``, die auf
    ihre exakte Ausgabe zusichern, fielen mit. Gemessen an einer
    Wegwerfprobe, nicht vermutet.
    """
    assert check_egress_gates(DEFAULT_GRAPH) == []


def test_the_default_graph_satisfies_contract_totality():
    """Der ausgelieferte Graph selbst erfüllt die Totalität.

    Der wichtigste der drei: Ohne ihn liesse sich C1 dadurch einlösen, dass
    ``check_contracts`` existiert und über einen Graphen läuft, dessen Tabelle
    unvollständig ist. Die Prüfung wäre dann da und der Graph trotzdem kaputt.

    Kein Sollwert von Hand nötig — die Sollmenge ist die leere Menge.
    """
    pruefung = _pruefung()
    assert pruefung is not None, (
        f"{PRUEFUNG!r} gibt es in ohpipe.domain.step noch nicht — "
        "die Vertragstotalitaet hat noch keinen Eingang."
    )

    verstoesse = pruefung(DEFAULT_GRAPH)

    assert verstoesse == [], (
        f"Der ausgelieferte Graph verletzt die Vertragstotalitaet: {verstoesse!r}"
    )


def test_a_produced_artifact_without_a_contract_is_a_named_violation():
    """Ein Schritt erzeugt einen Namen, für den kein Vertrag deklariert ist.

    Erwartete Sollmenge, von Hand: genau ``{"erfunden.artefakt"}``. Ein
    Verstoss ohne Namen schickt den Leser suchen; deshalb wird der Name im
    Text des Verstosses verlangt und nicht bloss „irgendein Verstoss".
    """
    pruefung = _pruefung()
    assert pruefung is not None, f"{PRUEFUNG!r} gibt es noch nicht."

    graph = StepGraph(steps=(Step("erzeuge", Kind.DETERMINISTIC, produces=(FREMD,)),))

    verstoesse = pruefung(graph)

    assert any(FREMD in v for v in verstoesse), (
        f"Ein Graph, der {FREMD!r} erzeugt, ohne einen Vertrag dafuer zu "
        f"deklarieren, gilt als sauber. Verstoesse: {verstoesse!r}"
    )


def test_a_contract_for_a_name_no_step_produces_is_a_named_violation():
    """Die andere Richtung: ein Vertrag, zu dem es kein Artefakt gibt.

    Ohne diese Zusicherung liesse sich der Marker davor dadurch einlösen, dass
    C1 für jeden vorkommenden Namen einen Vertrag anlegt — dann wäre die
    Tabelle eine Kopie von ``produces`` und sagte nichts. Erst beide
    Richtungen zusammen machen aus ihr eine Zusicherung.

    Erwartete Sollmenge, von Hand: genau ``{"erfunden.artefakt"}``. Der Graph
    erzeugt ``x.artefakt``; für den existiert hier ein Vertrag, und deshalb
    darf er **nicht** in den Verstössen auftauchen.
    """
    pruefung = _pruefung()
    assert pruefung is not None, f"{PRUEFUNG!r} gibt es noch nicht."

    felder = {f.name for f in dataclasses.fields(StepGraph)}
    assert "contracts" in felder, (
        "StepGraph hat kein Feld 'contracts' — die Vertragstabelle aus E2-N "
        f"Nummer 1 existiert noch nicht. Vorhandene Felder: {sorted(felder)}"
    )

    graph = StepGraph(
        steps=(Step("erzeuge", Kind.DETERMINISTIC, produces=(EIGEN,)),),
        contracts={EIGEN: None, FREMD: None},
    )

    verstoesse = pruefung(graph)

    assert any(FREMD in v for v in verstoesse), (
        f"Ein Vertrag auf {FREMD!r} steht im Graphen, obwohl kein Schritt "
        f"diesen Namen erzeugt. Verstoesse: {verstoesse!r}"
    )
    assert not any(EIGEN in v for v in verstoesse), (
        f"{EIGEN} wird erzeugt UND hat einen Vertrag, darf also nicht "
        f"beanstandet werden. Verstoesse: {verstoesse!r}"
    )
