"""Das recordgebundene Tor für ``kind`` und ``scope_id`` — vor B2.

`docs/ENTSCHEIDUNGEN_2026-08-05.md § E3 · Receiptvertrag` setzt zwei Grenzen,
die B1 noch nicht vollstreckt: ``ArtifactKey.scope_id`` ist ``workspace_id``
oder ``record_id``, und ``ArtifactKey.kind`` ist eine **kontrollierte**
Artefaktart. B1 prüft beide nur auf nichtleer. Dieses Tor vollstreckt sie am
aktuellen, profilgebundenen Schreibpfad — und nur dort.

**Was hier NICHT entschieden wird.** Der Katalog ist nicht global: er ist der
aktive Graph, den ``build_graph`` aus genau diesem validierten Profil baut.
Gemessen an den beiden mitgelieferten Profilen — sandbox 16 Artefaktarten,
childlux 20, Mengendifferenz zu den Verträgen je 0 — und vier Arten stehen
nur im childlux-Graphen. ``unit_set`` und ``codebook`` nennt ADR 0027 als
Artefakte, aber kein aktueller Graph erzeugt sie. Deshalb sagt ein Fall unter
`KIND_NOT_IN_ACTIVE_GRAPH` **nicht**, die Art sei global ungültig, sondern nur,
dass dieser Pfad sie nicht schreiben darf.

**Warum es kein workspace-Tor gibt.** Die normativ bestimmte Identitätsquelle
``workspace.identity.assigned`` existiert am Sockel nicht im Produktcode. Ein
Pfad, ein Profilname oder ein frisch erzeugter Zufallswert wäre keine
``workspace_id``, sondern eine Erfindung. Der Scope fällt deshalb mit eigener,
benannter Ursache statt in einen Default.

**Warum die Tests das Attribut prüfen und nicht die Prosa.** Ein
``reason_code`` aus einer Substringsuche in einer deutschen Meldung kippt
lautlos, sobald jemand den Satz umformuliert — dieselbe Klasse Fehler, gegen
die `src/ohpipe/project.py::DataRootError` als eigener Typ eingeführt wurde.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ohpipe.application.artifact_identity import (
    ArtifactKeyNotWritable,
    GateReason,
    check_record_scoped_key,
)
from ohpipe.domain.artifact_key import ArtifactKey, InvalidArtifactKey, Scope
from ohpipe.domain.step import DEFAULT_GRAPH, GraphError, StepGraph
from ohpipe.project import Profile

PROFILE_ROOT = Path(__file__).resolve().parents[1] / "src" / "ohpipe" / "profiles"


def _profil(name: str) -> Profile:
    return Profile.load(PROFILE_ROOT / name / "profile.toml")


#: Eine Artefaktart, die BEIDE aktuellen Graphen erzeugen. Ausgeschrieben und
#: nicht aus dem Graphen gezogen: ein Test, der seine Sollwerte aus dem
#: Prüfling holt, prüft den Prüfling gegen sich selbst.
GEMEINSAM = "transcript.revision"

#: Vier Arten, die nur der childlux-Graph erzeugt. Ebenfalls ausgeschrieben.
NUR_CHILDLUX = (
    "pii.spans",
    "replacement.report",
    "transcript.pseudonymised.confirmed",
    "transcript.pseudonymised.draft",
)


def _schluessel(scope_id: str, kind: str = GEMEINSAM, scope: Scope = Scope.RECORD) -> ArtifactKey:
    return ArtifactKey(scope=scope, scope_id=scope_id, kind=kind, instance_id=None)


# --- R1 · Die Artefaktart steht im aktiven Graphen -------------------------


def test_an_unknown_kind_falls_and_a_known_one_passes_in_the_same_graph():
    """R1. Der Katalog ist der aktive Graph, nicht ein kopiertes String-Set."""
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)

    with pytest.raises(ArtifactKeyNotWritable) as exc:
        check_record_scoped_key(_schluessel(aktuell, kind="gibtesnicht.art"), profil, aktuell)

    assert exc.value.reason_code is GateReason.KIND_NOT_IN_ACTIVE_GRAPH
    assert "gibtesnicht.art" in str(exc.value)

    # Gegenprobe in derselben Messung: dieselbe Signatur, zulässige Art.
    key = _schluessel(aktuell)
    assert check_record_scoped_key(key, profil, aktuell) == key


def test_the_gate_error_is_catchable_as_the_b1_exception():
    """Die Anwendungsschicht erfindet keine zweite Fehlerfamilie."""
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)

    with pytest.raises(InvalidArtifactKey) as exc:
        check_record_scoped_key(_schluessel(aktuell, kind="gibtesnicht.art"), profil, aktuell)

    assert isinstance(exc.value, ArtifactKeyNotWritable)
    assert exc.value.reason_code is GateReason.KIND_NOT_IN_ACTIVE_GRAPH


# --- R2 · Profiltrennung ---------------------------------------------------


@pytest.mark.parametrize("kind", NUR_CHILDLUX)
def test_a_childlux_only_kind_falls_under_sandbox_and_passes_under_childlux(kind):
    """R2. Ein stiller DEFAULT_GRAPH oder eine Vereinigungsmenge wird hier sichtbar.

    Dieselbe Artefaktart, zwei Profile, zwei Urteile. Ginge sie unter sandbox
    durch, käme der Katalog nicht aus dem übergebenen Profil.
    """
    sandbox = _profil("sandbox")
    childlux = _profil("childlux")

    with pytest.raises(ArtifactKeyNotWritable) as exc:
        check_record_scoped_key(
            _schluessel(sandbox.record_id(1), kind=kind), sandbox, sandbox.record_id(1)
        )
    assert exc.value.reason_code is GateReason.KIND_NOT_IN_ACTIVE_GRAPH

    # Gegenprobe: derselbe kind, das andere Profil, derselbe Weg.
    aktuell = childlux.record_id(7)
    key = _schluessel(aktuell, kind=kind)
    assert check_record_scoped_key(key, childlux, aktuell) == key


# --- G1 · Form der key.scope_id vor der Kontextgleichheit ------------------


@pytest.mark.parametrize(
    "ungueltig", ["CHILDLUX-0007", "SANDBOX-01", "SANDBOX-0001", "sandbox-001", "", "   ", "7"]
)
def test_a_form_invalid_scope_id_has_its_own_reason_and_claims_no_form_validity(ungueltig):
    """G1. Formungültig und kontextfremd sind zwei Befunde, nicht einer.

    Die Vorfassung gab beiden denselben Code und dieselbe Meldung — und diese
    Meldung sagte „Beide sind für dieses Profil formgültig". Für einen Wert,
    der die Profilform gar nicht erfüllt, behauptete sie damit etwas, das im
    gemessenen Fall falsch war: derselbe Etikettentreuebruch, den PRT am
    B1-Testnamen gefunden hat, nur in einer Fehlermeldung.

    Der leere Wert kommt hier nicht vor: `src/ohpipe/domain/artifact_key.py`
    weist ihn schon beim Bau des Schlüssels zurück. Er steht in der Liste, um
    genau diese Arbeitsteilung sichtbar zu halten.
    """
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)
    assert not profil.is_record_id(ungueltig)

    if not ungueltig.strip() and not ungueltig:
        with pytest.raises(InvalidArtifactKey):
            _schluessel(ungueltig)
        return

    with pytest.raises(ArtifactKeyNotWritable) as exc:
        check_record_scoped_key(_schluessel(ungueltig), profil, aktuell)

    meldung = str(exc.value)
    assert exc.value.reason_code is GateReason.INVALID_SCOPE_ID
    assert repr(ungueltig) in meldung
    assert profil.record_id(7) in meldung, "eine erwartete kanonische Form wird genannt"
    assert "formgültig" not in meldung, "die Meldung behauptet keine Formgueltigkeit"

    # Gegenprobe in derselben Messung: die aktuelle Kennung geht durch.
    key = _schluessel(aktuell)
    assert check_record_scoped_key(key, profil, aktuell) is key


def test_workspace_falls_before_its_scope_id_is_read_as_a_record_id():
    """G1, Reihenfolge: ``Scope.WORKSPACE`` erreicht die Formprüfung nicht.

    Ohne diese Richtung könnte eine workspace-``scope_id`` — die gar keine
    Record-Kennung sein soll — als formungültige Record-Kennung etikettiert
    werden. Der Scope fällt vorher, mit seinem eigenen Grund.
    """
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)

    with pytest.raises(ArtifactKeyNotWritable) as exc:
        check_record_scoped_key(
            _schluessel("kein-record-und-keine-uuid", scope=Scope.WORKSPACE), profil, aktuell
        )

    assert exc.value.reason_code is GateReason.WORKSPACE_IDENTITY_UNAVAILABLE
    assert exc.value.reason_code is not GateReason.INVALID_SCOPE_ID


# --- R3 · Kontextgleichheit statt blosser Form -----------------------------


def test_a_formally_valid_but_different_record_falls():
    """R3. Zwei gültige Kennungen desselben Profils sind nicht derselbe Kontext."""
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)
    fremd = profil.record_id(2)
    assert profil.is_record_id(fremd), "die Gegenkennung muss formal gueltig sein"

    with pytest.raises(ArtifactKeyNotWritable) as exc:
        check_record_scoped_key(_schluessel(fremd), profil, aktuell)

    assert exc.value.reason_code is GateReason.SCOPE_ID_CONTEXT_MISMATCH
    assert fremd in str(exc.value) and aktuell in str(exc.value)
    # Jetzt DARF die Meldung das sagen: das Tor hat es fuer beide Seiten gemessen.
    assert "formgültig" in str(exc.value)

    # Gegenprobe: die aktuelle Kennung geht durch.
    key = _schluessel(aktuell)
    assert check_record_scoped_key(key, profil, aktuell) == key


# --- R4 · Der Kontext selbst wird geprüft ----------------------------------


def test_an_invalid_current_record_id_falls_even_when_both_sides_agree():
    """R4. Gleichheit allein genügt nicht — der Kontext muss zum Profil passen.

    Beide Seiten tragen denselben Wert; ohne diese Richtung wäre eine
    Gleichheitsprüfung mit sich selbst zufriedenzustellen.
    """
    profil = _profil("sandbox")
    ungueltig = "CHILDLUX-0007"
    assert not profil.is_record_id(ungueltig)

    with pytest.raises(ArtifactKeyNotWritable) as exc:
        check_record_scoped_key(_schluessel(ungueltig), profil, ungueltig)

    assert exc.value.reason_code is GateReason.INVALID_CURRENT_RECORD_ID
    assert ungueltig in str(exc.value)

    # Gegenprobe: derselbe Weg mit einer profilgültigen Kennung.
    aktuell = profil.record_id(1)
    key = _schluessel(aktuell)
    assert check_record_scoped_key(key, profil, aktuell) == key


# --- R5 · workspace hat am Sockel keine Identitätsquelle -------------------


def test_workspace_scope_falls_with_its_own_named_cause():
    """R5. Die Lücke wird benannt, nicht in einen Default geschoben."""
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)

    with pytest.raises(ArtifactKeyNotWritable) as exc:
        check_record_scoped_key(_schluessel(aktuell, scope=Scope.WORKSPACE), profil, aktuell)

    assert exc.value.reason_code is GateReason.WORKSPACE_IDENTITY_UNAVAILABLE
    assert "workspace.identity.assigned" in str(exc.value)

    # Gegenprobe: derselbe kind, Scope.RECORD, passende Kennung.
    key = _schluessel(aktuell)
    assert check_record_scoped_key(key, profil, aktuell) == key


# --- G2 · Vertragsdrift am REALEN build_graph-Pfad ------------------------


def test_a_contract_drift_at_the_real_build_graph_path_stays_a_graph_error(monkeypatch):
    """Die Vertragstotalität ist die Grenze von ``build_graph``, nicht des Tors.

    Die Vorfassung dieses Falls ersetzte ``artifact_identity.build_graph`` und
    reichte einen selbst gebauten Graphen mit gekürzter Vertragstabelle ein.
    Damit mass sie einen Graphen, den der reale Bauweg **nie herausgibt**:
    ``build_graph`` ruft `src/ohpipe/domain/step.py::check_contracts` und hält
    bei einem Drift schon dort mit ``GraphError``. Ein Gate-Reason-Code für
    diesen Fall war deshalb unerreichbar — und hätte, wäre er erreichbar
    gewesen, einen systemischen Graphfehler als Aussage über einen
    ``ArtifactKey`` etikettiert.

    Hier wird stattdessen die **Vertragsquelle** angetastet, die der reale
    sandbox-Weg verwendet, und ``build_graph`` im Gate bleibt unersetzt. Die
    Rücknahme besorgt ``monkeypatch`` selbst.
    """
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)
    assert GEMEINSAM in DEFAULT_GRAPH.contracts, "Ausgang: der Vertrag ist da"

    monkeypatch.delitem(DEFAULT_GRAPH.contracts, GEMEINSAM)

    with pytest.raises(GraphError) as exc:
        check_record_scoped_key(_schluessel(aktuell), profil, aktuell)

    assert "Vertragstotalität" in str(exc.value)
    assert GEMEINSAM in str(exc.value)
    assert not isinstance(exc.value, InvalidArtifactKey), (
        "ein Graphfehler ist keine Aussage ueber einen ArtifactKey"
    )

    # Gegenprobe: der unveränderte Weg gibt denselben Schlüssel zurück.
    monkeypatch.undo()
    assert GEMEINSAM in DEFAULT_GRAPH.contracts, "der Zustand ist wiederhergestellt"
    key = _schluessel(aktuell)
    assert check_record_scoped_key(key, profil, aktuell) is key


# --- G3 · Unerwartete Ausnahmen aus contract_for werden nicht maskiert -----

#: Ein Text, der nirgends sonst vorkommt. Nur so ist „dieselbe Ausnahme"
#: gemessen und nicht bloss „irgendeine AttributeError".
SENTINEL = "sentinel-4f2a-contract-for-explodiert"


def test_an_unexpected_exception_from_contract_for_is_not_relabelled(monkeypatch):
    """Ein Programmierfehler bleibt ein Programmierfehler.

    Die Vorfassung fing pauschal mit ``except Exception`` und gab jeder
    Ursache den Reason-Code für einen fehlenden Vertrag. Ein
    maschinenlesbarer Grund, der im Fehlerfall das Falsche behauptet, ist
    schlimmer als keiner: der Aufrufer entscheidet danach.

    ``build_graph`` wird hier **nicht** ersetzt und kein unvollständiger Graph
    eingeschleust — der Graph ist der echte, und nur der Zugriff auf den
    Vertrag explodiert.
    """
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)

    def explodiert(self, artifact):  # noqa: ARG001
        raise AttributeError(SENTINEL)

    monkeypatch.setattr(StepGraph, "contract_for", explodiert)

    with pytest.raises(AttributeError) as exc:
        check_record_scoped_key(_schluessel(aktuell), profil, aktuell)

    assert SENTINEL in str(exc.value)
    assert not isinstance(exc.value, InvalidArtifactKey)
    assert not hasattr(exc.value, "reason_code")

    # Gegenprobe: der gesunde Weg zieht den Vertrag und gibt den Schlüssel zurück.
    monkeypatch.undo()
    key = _schluessel(aktuell)
    assert check_record_scoped_key(key, profil, aktuell) is key
    assert DEFAULT_GRAPH.contract_for(GEMEINSAM) is not None


# --- Die fünf Codes sind fünf ---------------------------------------------


def test_the_five_reason_codes_are_five_distinct_values():
    """Zwei Ursachen dürfen weder denselben Code noch dieselbe Meldung erzeugen.

    Sollmenge ausgeschrieben, nicht aus dem Enum errechnet.
    """
    erwartet = {
        "INVALID_CURRENT_RECORD_ID",
        "INVALID_SCOPE_ID",
        "SCOPE_ID_CONTEXT_MISMATCH",
        "KIND_NOT_IN_ACTIVE_GRAPH",
        "WORKSPACE_IDENTITY_UNAVAILABLE",
    }

    assert {g.value for g in GateReason} == erwartet
    assert len(erwartet) == 5
    assert "KIND_CONTRACT_MISSING" not in {g.value for g in GateReason}, (
        "ein systemischer Graphfehler bekommt keinen Gate-Reason-Code"
    )


def test_no_two_causes_share_a_message():
    """Fünf Ursachen, fünf verschiedene Meldungen — gemessen, nicht behauptet.

    Alle fünf werden über den öffentlichen Aufruf erreicht; keine braucht
    einen gepatchten Graphen. Genau das ist der Unterschied zur Vorfassung:
    dort war eine der fünf nur über einen ersetzten Bauer zu erreichen.
    """
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)
    meldungen: dict[GateReason, str] = {}

    faelle = [
        (_schluessel("CHILDLUX-0007"), "CHILDLUX-0007"),
        (_schluessel("SANDBOX-01"), aktuell),
        (_schluessel(profil.record_id(2)), aktuell),
        (_schluessel(aktuell, kind="gibtesnicht.art"), aktuell),
        (_schluessel(aktuell, scope=Scope.WORKSPACE), aktuell),
    ]
    for key, kontext in faelle:
        with pytest.raises(ArtifactKeyNotWritable) as exc:
            check_record_scoped_key(key, profil, kontext)
        meldungen[exc.value.reason_code] = str(exc.value)

    assert len(meldungen) == 5, f"nicht alle fuenf Ursachen erreicht: {sorted(meldungen)}"
    assert len(set(meldungen.values())) == 5, "zwei Ursachen teilen sich eine Meldung"
    assert set(meldungen) == set(GateReason)


def test_the_gate_returns_the_unchanged_key_and_writes_nothing():
    """Das Tor normalisiert nicht still und ersetzt keinen Wert."""
    profil = _profil("sandbox")
    aktuell = profil.record_id(1)
    key = _schluessel(aktuell)

    zurueck = check_record_scoped_key(key, profil, aktuell)

    assert zurueck is key
    assert zurueck.scope_id == aktuell
    assert zurueck.kind == GEMEINSAM
    assert zurueck.instance_id is None
