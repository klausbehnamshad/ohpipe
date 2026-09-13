"""C1 definiert die Hashdomäne; E8 bindet sie an den Arbeitsbereich.

E8 wörtlich: *„Ein ``graph_sha256`` ohne kanonische Hashdomäne ist kein
ausführbarer Vertrag, sondern ein Name für etwas, das noch niemand rechnen
kann. Die Berechnung wird mit dem Commit festgelegt, der ``ArtifactContract``
einführt; Implementierung samt Upgrade- und Kompatibilitätsakt bekommen eine
eigene Serie danach. Unter dem Tag dieser Serie wird kein Fingerprint berechnet
und keiner geprüft."*

Daraus folgen zwei Sorten Zusicherung, und die zweite ist die unangenehmere:

1.  **Was die Domäne enthält** — Semantik ja, Darstellung nein. Geprüft wird
    differentiell: eine Änderung, die etwas bedeutet, bewegt den Wert; eine,
    die nichts bedeutet, bewegt ihn nicht.
2.  **Dass E8 nur an den vorab freigegebenen Stellen bindet und vergleicht.**
    Das ist eine strukturelle Eigenschaft, und strukturelle Eigenschaften
    brauchen strukturelle Wächter (Hausregel 5). Ein Test, der bloss einen
    bekannten Aufrufpfad beobachtet, wäre keiner — deshalb liest der letzte
    Test den ganzen Python-Quellbaum.

Der erste Literalwert steht seit E8 in ``test_e8_graph_binding.py``. Er wird
nicht aus der Produktionsfunktion abgeleitet: sonst prüfte der Test die
Berechnung gegen sich selbst. Eine Änderung braucht den ausdrücklichen
Upgradeakt und eine sichtbare Änderung dieses Pins.
"""

from __future__ import annotations

import dataclasses
from pathlib import Path

from ohpipe.domain import step as graphmodul
from ohpipe.domain.step import (
    DEFAULT_GRAPH,
    ArtifactContract,
    Kind,
    Step,
    StepGraph,
    build_graph,
    graph_contract_fingerprint,
)

#: Zwei winzige Graphen, die sich AUSSCHLIESSLICH im Vertrag unterscheiden.
#: Von Hand gebaut und nicht aus ``DEFAULT_GRAPH`` abgeleitet: ein Test, der
#: seinen Vergleichsfall aus dem Produktionsgraphen holt, prüft den Graphen
#: gegen sich selbst.
_SCHRITT = Step("erzeuge", Kind.DETERMINISTIC, produces=("x.artefakt",))
_STRENG = ArtifactContract(binding_required=True, provenance_required=True, decision_required=True)
_LOCKER = ArtifactContract(binding_required=True, provenance_required=True, decision_required=False)


def test_the_fingerprint_is_stable_across_calls():
    """Zweimal dasselbe Objekt, zweimal derselbe Wert.

    Klingt trivial, ist es nicht: die Domäne enthält Mengen und ein dict, und
    beides hat in Python keine stabile Iterationsreihenfolge über Prozesse
    hinweg, sobald Hashrandomisierung im Spiel ist. Ohne Sortierung wäre der
    Wert innerhalb eines Prozesses stabil und zwischen zwei Läufen nicht —
    die teuerste Sorte Fehler, weil sie in der CI nie auftritt.
    """
    assert graph_contract_fingerprint(DEFAULT_GRAPH) == graph_contract_fingerprint(DEFAULT_GRAPH)


def test_the_profile_graphs_separate_by_contract_and_not_by_name():
    """Der Fingerprint bildet den VERTRAG ab, nicht den Profilnamen.

    Die frühere Fassung schrieb die Profilmenge aus (``{childlux, sandbox}``)
    und las den Unterschied der beiden Werte als „verschiedene Profile,
    verschiedene Werte". Mit ``walz`` fällt das auf: ``walz`` und ``sandbox``
    haben dieselben 16 Artefakte mit denselben Verträgen — also denselben
    Fingerprint. Verschieden sind sie in ``production``, ``key_required`` und
    ``legacy_runtime``, und davon geht nichts in die Hashdomäne ein.

    Das ist die Aussage und nicht der Mangel: ``graph_contract_fingerprint``
    beantwortet „welcher Vertrag läuft hier", nicht „welches Projekt ist das".
    Die zweite Frage beantwortet die Bindungsdatei, die den Profilnamen
    MITFÜHRT — ``Workspace.inspect_graph_binding`` vergleicht beides, und ein
    sandbox-gebundener Arbeitsbereich unter ``--profile walz`` ist deshalb
    MISMATCH und nicht CURRENT (geprüft in
    ``tests/test_profile_walz.py::test_a_sandbox_workspace_is_not_silently_taken_over_by_walz``).
    Ohne diesen Namensvergleich wäre die Gleichheit hier eine Lücke.
    """
    profile = Path("src/ohpipe/profiles")
    from ohpipe.project import Profile

    werte = {}
    for datei in sorted(profile.glob("*/profile.toml")):
        p = Profile.load(datei)
        werte[p.id] = graph_contract_fingerprint(build_graph(p))

    assert set(werte) == {"childlux", "sandbox", "walz", "spur-p-manual", "walz-pilot-pseudo"}, (
        sorted(werte)
    )
    assert werte["spur-p-manual"] not in {werte["childlux"], werte["sandbox"]}, werte
    assert werte["childlux"] != werte["sandbox"], werte
    assert werte["walz"] == werte["sandbox"], werte
    # Der beauftragte Pilot nutzt dieselben manuellen Artefaktverträge;
    # Profil-/Record-/Registerbindung trennt die beiden Arbeitsbereiche.
    assert werte["walz-pilot-pseudo"] == werte["spur-p-manual"], werte


def test_a_changed_contract_boolean_changes_the_fingerprint():
    """Der Vertrag geht ein — nicht nur die Schritte.

    Ohne diese Zusicherung wäre ``graph_contract_fingerprint`` ein
    Schrittfingerprint mit irreführendem Namen. Beide Graphen hier tragen
    denselben Schritt und dasselbe Artefakt; verschieden ist genau ein
    ``bool``.
    """
    streng = StepGraph(steps=(_SCHRITT,), contracts={"x.artefakt": _STRENG})
    locker = StepGraph(steps=(_SCHRITT,), contracts={"x.artefakt": _LOCKER})

    assert graph_contract_fingerprint(streng) != graph_contract_fingerprint(locker)


def test_prose_fields_do_not_change_the_fingerprint():
    """``description`` und ``cost`` sind Darstellung, nicht Semantik.

    Die verworfene erste Fassung nahm den ganzen ``Step`` in die Domäne. Damit
    hätte eine Tippfehlerkorrektur in einer Beschreibung jedes gebundene
    Journal ungültig gemacht. Ein Fingerprint, der auf Kommentare anspricht,
    wird beim ersten Mal umgangen — und ab da ist die Bindung Dekoration.

    ``cost`` steht mit im selben Satz, weil es ein Bedienhinweis für
    ``continue`` ist und keine Aussage über das Artefakt: dass ein Schritt
    teuer ist, ändert nichts daran, wogegen er belegt sein muss.
    """
    vorher = StepGraph(steps=(_SCHRITT,), contracts={"x.artefakt": _STRENG})
    umgeschrieben = dataclasses.replace(
        _SCHRITT, description="andere Prosa, gleiche Semantik", cost="model"
    )
    nachher = StepGraph(steps=(umgeschrieben,), contracts={"x.artefakt": _STRENG})

    assert graph_contract_fingerprint(vorher) == graph_contract_fingerprint(nachher)


def test_the_order_of_steps_does_not_change_the_fingerprint():
    """Die Reihenfolge im Tupel ist laut ``build_graph`` bedeutungslos.

    Sie existiert ausschliesslich, damit der gebaute Graph in Fehlermeldungen
    in der Reihenfolge liest, in der er läuft. Ginge sie in die Domäne ein,
    änderte ein reines Umsortieren im Quelltext den Fingerprint — und damit
    entschiede die Lesbarkeit einer Konstanten über die Gültigkeit von
    Journalen.
    """
    a = Step("a", Kind.DETERMINISTIC, produces=("a.artefakt",))
    b = Step("b", Kind.DETERMINISTIC, requires=("a.artefakt",), produces=("b.artefakt",))
    vertraege = {"a.artefakt": _STRENG, "b.artefakt": _LOCKER}

    vorwaerts = StepGraph(steps=(a, b), contracts=vertraege)
    rueckwaerts = StepGraph(steps=(b, a), contracts=vertraege)

    assert graph_contract_fingerprint(vorwaerts) == graph_contract_fingerprint(rueckwaerts)


def test_domain_and_version_are_part_of_the_hashed_object(monkeypatch):
    """Domänentrenner und Fassungsnummer gehen ein — beide einzeln geprüft.

    Ohne Domänentrenner könnte ein Hash aus einer anderen Domäne desselben
    Systems zufällig gleich aussehen; ohne Fassungsnummer wäre ein Wechsel der
    Berechnung nicht von einem Wechsel des Graphen zu unterscheiden. Genau das
    ist der Unterschied zwischen einem ausführbaren Vertrag und einem Namen
    für etwas, das noch niemand rechnen kann (E8).

    Geprüft wird über ``monkeypatch`` an den Modulglobalen und nicht durch
    Nachbau der Domäne im Test: ein Nachbau prüfte die Testkopie und nicht die
    Berechnung.
    """
    urwert = graph_contract_fingerprint(DEFAULT_GRAPH)

    monkeypatch.setattr(graphmodul, "GRAPH_CONTRACT_VERSION", graphmodul.GRAPH_CONTRACT_VERSION + 1)
    assert graph_contract_fingerprint(DEFAULT_GRAPH) != urwert, (
        "Die Fassungsnummer geht nicht in die Hashdomaene ein."
    )
    monkeypatch.undo()

    monkeypatch.setattr(graphmodul, "GRAPH_CONTRACT_DOMAIN", "ohpipe/etwas-anderes")
    assert graph_contract_fingerprint(DEFAULT_GRAPH) != urwert, (
        "Der Domaenentrenner geht nicht in die Hashdomaene ein."
    )
    monkeypatch.undo()

    assert graph_contract_fingerprint(DEFAULT_GRAPH) == urwert, (
        "monkeypatch.undo hat den Ausgangszustand nicht hergestellt — "
        "die beiden Aussagen oben stehen dann auf einem veraenderten Modul."
    )


def test_e8_uses_the_fingerprint_only_at_the_frozen_sites():
    """Der strukturelle Wächter gegen eine zweite, unbeabsichtigte Wahrheit.

    Die Zweiermenge stammt aus dem gegengezeichneten Design-Freeze vom
    15.08.2026. Sie ist eine Gleichheit, keine Teilmenge: Definition und
    Workspace-Bindung müssen beide vorkommen, jede dritte Textfundstelle unter
    ``src/**/*.py`` stoppt. Auch eine bloße Erwähnung in Prosa würde fallen.

    Die Wegwerfprobe zur Gegenrichtung bleibt Pflicht: eine Fundstelle in
    ``src/ohpipe/journal.py`` muss diesen Test rot machen und wird danach
    vollständig verworfen.
    """
    wurzel = Path(__file__).resolve().parents[1] / "src"
    ERLAUBT = {"ohpipe/domain/step.py", "ohpipe/project.py"}

    treffer = sorted(
        str(datei.relative_to(wurzel)).replace("\\", "/")
        for datei in wurzel.rglob("*.py")
        if "graph_contract_fingerprint" in datei.read_text(encoding="utf-8")
    )

    assert treffer == sorted(ERLAUBT), (
        "graph_contract_fingerprint wird ausserhalb der vorab freigegebenen "
        f"E8-Bindungs-/Vergleichsstellen verwendet: {treffer}; "
        f"erlaubt: {sorted(ERLAUBT)}. Die Allowlist ist im "
        "E8-ALLOWLIST-DESIGNFREEZE_AUTOR_2026-08-15.md gepinnt; "
        "bei Abweichung STOPP statt Anpassung an das Ergebnis."
    )
