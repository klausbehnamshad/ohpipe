"""Scheibe C/2 · was der Vertrag zusichert — und was er ausdrücklich nicht darf.

C2 speist die drei Zustandsachsen aus dem ``ArtifactContract`` statt aus der
Fahne ``is_human_artifact``. Diese Datei ist die Dauerzusicherung dazu. Sie hat
drei Sorten Test, und jede beantwortet eine andere Frage:

    E19   Genau sieben Artefakte wechseln durch diese Vertragswirkung nach
          ``READY`` — und kein achtes.
    E20   ``transcript.revision`` steht auf allen drei Achsen ``not_applicable``
          und ist damit fertig, sobald seine Bytes da sind.
    MENSCH
          Menschlichkeit allein bindet nicht mehr. Bei ``binding_required``
          entscheidet echte Ankerevidenz, in beide Richtungen.

**Die sieben Namen stehen von Hand da.** Sie werden nicht aus
``graph.contracts`` zurückgerechnet. Ein Test, der seine Erwartung aus der
Tabelle holt, die er prüfen soll, ist grün, sobald beide dieselbe Änderung
mitmachen — er prüft den Code gegen sich selbst. Die Tabelle darf hier
ausschliesslich als *Messwert* vorkommen, nie als *Sollwert*.

**Die Menge der Artefakte kommt dagegen sehr wohl aus dem Graphen.** Das ist
kein Widerspruch: Die Frage „wird ein achtes Artefakt grün" hat nur dann eine
Antwort, wenn sie über *alle* Artefakte gestellt wird. Ausgeschrieben wäre die
Grundgesamtheit, nicht die Erwartung — und eine ausgeschriebene Grundgesamtheit
verrottet still, sobald der Graph wächst.

**Bezugsrahmen der Sieben: der Sandbox-Graph.** Das CHILDLUX-Profil bringt mit
``_PSEUDONYMISATION_VERTRAEGE`` drei weitere Artefakte ohne Entscheidungspflicht
mit. „Genau sieben" ist eine Aussage über die Basistabelle und wäre über den
pseudonymisierenden Graphen falsch. Deshalb steht der Graph in jeder Zusicherung
dieser Datei ausdrücklich dabei.
"""

from __future__ import annotations

import json
from pathlib import Path

from ohpipe.domain.step import DEFAULT_GRAPH

from ._forge import cli, place_object
from ._p3_evidence import bindings
from .test_forgery import wellformed_chain
from ._forge import forge as forge_unkeyed

# ---------------------------------------------------------------- die Sieben
#
# Von Hand, nach dem Wortlaut von E19, in zwei Gruppen nach ihrem VORHERIGEN
# Status. Die Vorher-Zustände sind gegen den unveränderten Basisbaum gemessen
# und stehen im Bericht zur Serie; ein Test kann sie nicht mehr sehen, weil er
# gegen den Baum läuft, in dem C2 schon steht.

#: Vor C2 ``STOP``, weil die Bindungsachse ohne Anker auf ``unknown`` fiel und
#: ``UNKNOWN -> STOP`` ganz oben in der Leiter steht.
VON_STOP = ("transcript.revision", "l1.coverage", "release.preview")

#: Vor C2 ``ACTION_NEEDED``, weil die Entscheidungsachse ohne Verdikt auf
#: ``undecided`` fiel — obwohl ihr Vertrag gar keine Entscheidung verlangt.
VON_ACTION_NEEDED = ("metadata.draft", "abstract.draft", "l1.suggestions", "analysis.draft")

DIE_SIEBEN = VON_STOP + VON_ACTION_NEEDED

#: Das menschliche Artefakt, an dem die Bindungsregel gemessen wird. Sein
#: Vertrag verlangt Bindung; ohne Anker ist das ein Mangel, keine
#: Nichtzuständigkeit.
MENSCHLICH = "transcript.confirmed"

#: Die zwei Modellartefakte und ihr jeweiliges Gate. Von Hand: Ein Test, der
#: die Zuordnung aus dem Graphen ableitete, prüfte den Graphen gegen sich
#: selbst — dieselbe Begründung wie in ``tests/test_forgery.py``.
MODELLGATES = {
    "l1.suggestions": ("l1.suggest", "transcript.confirmed"),
    "analysis.draft": ("analysis.summarise", "l1.adjudicated"),
}

ENTSCHIEDEN_UM = "2026-09-01T09:00:00+00:00"
GESTARTET_UM = "2026-09-01T09:30:00+00:00"


# ------------------------------------------------------------------ Werkzeug


def _welt(tmp_path: Path) -> Path:
    wurzel = tmp_path / "daten"
    assert cli("init", root=wurzel).returncode == 0
    return wurzel


def _artefakte(wurzel: Path) -> dict[str, dict]:
    """Alle Artefaktzeilen des einen Records — über die echte Operatorgrenze.

    Gelesen wird ``status --json`` als Unterprozess und nicht ``RecordView``
    im Prozess: Zugesichert ist, was ein Operator sieht.
    """
    ergebnis = cli("status", "--json", root=wurzel)
    rec = json.loads(ergebnis.stdout)["details"]["records"][0]
    assert rec["findings"] == [], rec["findings"]
    return rec["artifacts"]


def _erzeugt(artefakt: str, sha: str) -> dict:
    return {"kind": "artifact.produced", "payload": {"artifact": artefakt, "sha256": sha}}


def _anker(artefakt: str, ergebnis: str = "exact") -> dict:
    return {"kind": "anchor.checked", "payload": {"artifact": artefakt, "outcome": ergebnis}}


def _beleg(artefakt: str, ausgabe: str, eingabe: str) -> dict:
    return {
        "kind": "receipt.recorded",
        "payload": {
            "artifact": artefakt,
            "output_sha256": ausgabe,
            "inputs": {"quelle": eingabe},
            "code_version": "0.1.0",
        },
    }


def _entscheidung(artefakt: str, sha: str, verdikt: str = "ACCEPT") -> dict:
    return {
        "kind": "decision.recorded",
        "payload": {
            "artifact": artefakt,
            "subject_sha256": sha,
            "verdict": verdikt,
            **bindings(artefakt, sha),
            "reference": f"PI-{artefakt}",
            "actor": "kbs",
            "at": ENTSCHIEDEN_UM,
        },
    }


def _modellbeleg(artefakt: str, ausgabe: str, eingabe: str, gate_sha: str) -> dict:
    """Ein Modellbeleg, der sich auf die Entscheidung über SEIN Gate beruft.

    Ein deterministischer Beleg genügt für ein Modellartefakt nicht — dann
    würden Autorisierung, ``finish_reason`` und Parameter nie geprüft, und der
    Test führte eine Evidenzlage vor, die das Produkt gar nicht akzeptiert.
    """
    schritt, gate = MODELLGATES[artefakt]
    return {
        "kind": "receipt.recorded",
        "payload": {
            "artifact": artefakt,
            "output_sha256": ausgabe,
            "inputs": {"quelle": eingabe},
            "code_version": "0.1.0",
            "kind": "model",
            "step": schritt,
            "params": {"model": "gemma4:e4b", "temperature": 0.0, "seed": 7},
            "prompt_sha256": "c" * 64,
            "finish_reason": "stop",
            "authorisation": f"PI-{gate}@{gate_sha[:12]}",
            "authorisation_subject_sha256": gate_sha,
            "authorised_at": ENTSCHIEDEN_UM,
            "started_at": GESTARTET_UM,
        },
    }


# --------------------------------------------------- E19 · die Vertragstabelle


def test_exactly_seven_artifacts_carry_a_contract_without_a_decision():
    """Die Sollmenge von Hand gegen die gemessene Tabelle des Sandbox-Graphen.

    Diese Zeile ist der Grund, warum die Zusicherungen darunter etwas heissen:
    Sie nagelt fest, dass die Vertragswirkung ‚keine Entscheidung nötig' genau
    sieben Artefakte betrifft. Wächst die Tabelle um ein achtes, fällt dieser
    Test — und nicht erst irgendein Statustest, dem eine Zeile mehr nicht
    auffiele.
    """
    gemessen = {n for n, v in DEFAULT_GRAPH.contracts.items() if not v.decision_required}
    assert gemessen == set(DIE_SIEBEN), (
        "Die Artefakte ohne Entscheidungspflicht im Sandbox-Graphen sind nicht mehr "
        f"die sieben aus E19. Erwartet {sorted(DIE_SIEBEN)}, gemessen {sorted(gemessen)}."
    )


def test_the_seven_names_are_seven_distinct_names():
    """Gegenprobe: die Sollmenge ist eine Menge.

    Ohne sie wäre der Test darüber auch mit einem doppelten Namen grün — die
    Mengenbildung bügelte ihn weg, und ``DIE_SIEBEN`` hätte in Wahrheit sechs
    Einträge. Genau so verschwände einer der vier aus der zweiten Gruppe
    unbemerkt.
    """
    assert len(DIE_SIEBEN) == 7, DIE_SIEBEN
    assert len(set(DIE_SIEBEN)) == 7, DIE_SIEBEN
    assert not set(VON_STOP) & set(VON_ACTION_NEEDED), "eine Herkunft je Name"


# ------------------------------------------- E19 · die drei aus ``STOP``


def test_the_three_contract_free_artifacts_are_ready_without_an_anchor(tmp_path: Path):
    """``transcript.revision``, ``l1.coverage``, ``release.preview`` ohne Anker.

    Evidenzlage nach E19, für jedes von Hand gelegt statt aus einer Schleife
    über die Tabelle: Bytes für alle drei, ein aktueller Beleg für die zwei,
    die einen Herkunftsnachweis brauchen, und für keines ein Anker oder eine
    Entscheidung.

    Vor C2 standen alle drei auf ``STOP``, weil die Bindungsachse ohne Anker
    fail-closed auf ``unknown`` fiel.
    """
    wurzel = _welt(tmp_path)
    events = [
        e
        for e in wellformed_chain(wurzel)
        if not (
            e["payload"].get("artifact") in VON_STOP
            and e["kind"] in ("anchor.checked", "decision.recorded")
        )
    ]
    forge_unkeyed(wurzel, events)

    artefakte = _artefakte(wurzel)
    for name in VON_STOP:
        a = artefakte[name]
        assert a["source_binding"] == "not_applicable", (name, a)
        assert a["decision_state"] == "not_applicable", (name, a)
        assert a["status"] == "READY", (name, a)

    # Die Ableitungsachse ist NICHT bei allen dreien gleich, und das ist der
    # Punkt: Der Vertrag steuert sie einzeln. Waere sie ueberall gleich,
    # zeigte der Test nur, dass irgendetwas pauschal N/A wird.
    assert artefakte["transcript.revision"]["derivation_state"] == "not_applicable"
    assert artefakte["l1.coverage"]["derivation_state"] == "current"
    assert artefakte["release.preview"]["derivation_state"] == "current"


# ------------------------------------ E19 · die vier aus ``ACTION_NEEDED``


def test_the_four_undecided_drafts_are_ready_without_a_decision(tmp_path: Path):
    """Die vier Entwürfe mit voller Evidenz, aber ohne Verdikt.

    Evidenzlage nach E19: Bytes, aufgelöster Anker, aktueller Beleg, keine
    Entscheidung. Die zwei Modellartefakte bekommen einen Modellbeleg, der an
    die Entscheidung über sein Gate gebunden ist — mit einem deterministischen
    Beleg wären sie gar nicht erst auswertbar, und der Test führte eine
    Evidenzlage vor, die das Produkt zurückweist.

    Vor C2 standen alle vier auf ``ACTION_NEEDED``: Die Entscheidungsachse
    fiel ohne Verdikt auf ``undecided``, obwohl ihr Vertrag keine Entscheidung
    verlangt.
    """
    wurzel = _welt(tmp_path)
    events = [
        e
        for e in wellformed_chain(wurzel)
        if not (
            e["payload"].get("artifact") in VON_ACTION_NEEDED and e["kind"] == "decision.recorded"
        )
    ]
    forge_unkeyed(wurzel, events)

    artefakte = _artefakte(wurzel)
    for name in VON_ACTION_NEEDED:
        a = artefakte[name]
        assert a["source_binding"] == "bound", (name, a)
        assert a["derivation_state"] == "current", (name, a)
        assert a["decision_state"] == "not_applicable", (name, a)
        assert a["status"] == "READY", (name, a)


# -------------------------------------------------- E19 · und kein achtes


def test_no_eighth_artifact_becomes_ready_from_the_contract_alone(tmp_path: Path):
    """Über ALLE Artefakte des Graphen: ohne Verdikt sind genau die Sieben fertig.

    Die Grundgesamtheit kommt hier aus ``DEFAULT_GRAPH.artifacts``, die
    Erwartung von Hand. Jedes Artefakt bekommt Bytes, einen aufgelösten Anker
    und einen aktuellen Beleg — die bestmögliche Evidenzlage OHNE Entscheidung.
    Wer danach ``not_applicable`` auf der Entscheidungsachse trägt, trägt es
    aus dem Vertrag und aus nichts anderem.

    Die zwei Gate-Entscheidungen sind unvermeidbar: ohne sie ist kein
    Modellbeleg auswertbar. Sie sind deshalb ausdrücklich vom Vergleich
    ausgenommen, und der Test sichert getrennt zu, dass genau sie und sonst
    nichts eine Entscheidung tragen — sonst könnte eine zusätzliche
    Entscheidung die Menge unbemerkt verkleinern.
    """
    wurzel = _welt(tmp_path)
    gates = sorted({gate for _, gate in MODELLGATES.values()})
    ereignisse = [
        e
        for e in wellformed_chain(wurzel)
        if e["kind"] != "decision.recorded" or e["payload"]["artifact"] in gates
    ]
    forge_unkeyed(wurzel, ereignisse)

    artefakte = _artefakte(wurzel)
    mit_entscheidung = {n for n, a in artefakte.items() if a["decision_state"] == "accepted"}
    assert mit_entscheidung == set(gates), (
        "Nur die zwei Gate-Entscheidungen duerfen in dieser Probe stehen, sonst "
        f"misst der Vergleich unten etwas anderes: {sorted(mit_entscheidung)}"
    )

    ohne_pflicht = {n for n, a in artefakte.items() if a["decision_state"] == "not_applicable"}
    assert ohne_pflicht == set(DIE_SIEBEN), (
        "Die Entscheidungsachse steht bei anderen als den sieben Artefakten auf "
        f"not_applicable: {sorted(ohne_pflicht)}"
    )
    fertig_ohne_verdikt = {n for n in ohne_pflicht if artefakte[n]["status"] == "READY"}
    assert fertig_ohne_verdikt == {
        "transcript.revision",
        "l1.suggestions",
        "l1.coverage",
        "metadata.draft",
        "analysis.draft",
    }
    assert artefakte["abstract.draft"]["status"] == "STALE"
    assert artefakte["release.preview"]["status"] == "STALE"


# ------------------------------------------------------------------- E20


def test_transcript_revision_is_ready_on_bytes_alone(tmp_path: Path):
    """E20, einzeln: drei Mal ``not_applicable`` und damit ``READY``.

    ``transcript.revision`` ist das einzige Artefakt, dessen Vertrag auf allen
    drei Achsen nichts verlangt: Es kommt von aussen in das System, hat weder
    Anker noch Beleg noch Entscheidung, und braucht auch keins davon.

    Diese Zusicherung steht getrennt von der Gruppenzusicherung darüber,
    obwohl der Name in beiden vorkommt. Die Gruppe prüft die Vertragswirkung
    über sieben Namen; diese Zeile prüft die eine Kombination, die E20
    namentlich nennt. Fiele sie mit der Gruppe zusammen, wäre nach einer
    Änderung an der Gruppe nicht mehr ablesbar, ob E20 noch gilt.
    """
    wurzel = _welt(tmp_path)
    sha = place_object(wurzel, b"eine Transkriptfassung")
    forge_unkeyed(wurzel, [_erzeugt("transcript.revision", sha)])

    a = _artefakte(wurzel)["transcript.revision"]
    assert a["source_binding"] == "not_applicable", a
    assert a["derivation_state"] == "not_applicable", a
    assert a["decision_state"] == "not_applicable", a
    assert a["status"] == "READY", a


# ------------------------------------------ Menschliche Artefakte, beide Wege


def _menschlich(tmp_path: Path, *anker: dict) -> dict:
    """``transcript.confirmed`` mit Bytes und echter Annahme, Anker nach Wunsch."""
    wurzel = _welt(tmp_path)
    sha = place_object(wurzel, b"die bestaetigte Fassung")
    ereignisse = [_erzeugt("transcript.revision", sha), _erzeugt(MENSCHLICH, sha)]
    ereignisse += list(anker)
    ereignisse.append(_entscheidung(MENSCHLICH, sha))
    forge_unkeyed(wurzel, ereignisse)
    return _artefakte(wurzel)[MENSCHLICH]


def test_a_human_artifact_without_an_anchor_is_unknown_and_stops(tmp_path: Path):
    """Die negative Probe — und der eigentliche Gewinn von C2.

    Vor C2 war dieses Artefakt ``bound``, weil ``is_human_artifact`` wahr ist.
    Das war gespeicherter Zustand mit anderem Namen: Gebunden war es, weil es
    menschlich ist, nicht weil ein Anker geprüft worden wäre. Sein Vertrag sagt
    ``binding_required``; ohne Ankerevidenz ist das ein Mangel, und ein Mangel
    ist fail-closed.

    Die Annahme steht mit im Journal, damit der Test nicht aus der
    Entscheidungsachse rot wird: Zugesichert ist die Bindung.
    """
    a = _menschlich(tmp_path)
    assert a["decision_state"] == "accepted", a
    assert a["source_binding"] == "unknown", a
    assert a["status"] == "STOP", a


def test_a_human_artifact_with_a_checked_anchor_is_bound(tmp_path: Path):
    """Die positive Probe: mit echter Ankerevidenz bindet es wieder.

    Ohne sie wäre die negative Probe darüber auch dann grün, wenn C2 die
    Bindungsachse für menschliche Artefakte pauschal auf ``unknown`` nagelte —
    dann wäre kein bestätigtes Transkript je wieder fertig, und der Pipeline
    fehlte ihr erstes Gate.
    """
    a = _menschlich(tmp_path, _anker(MENSCHLICH))
    assert a["source_binding"] == "bound", a
    assert a["derivation_state"] == "not_applicable", a
    assert a["decision_state"] == "accepted", a
    assert a["status"] == "READY", a


def test_a_human_artifact_with_an_ambiguous_anchor_is_drifted(tmp_path: Path):
    """Und die Gegenrichtung: vorhandene negative Evidenz schlägt den Vertrag.

    Ein Ankerergebnis, das sich nicht schliessen lässt, bleibt ``drifted``.
    Ohne diese Zeile wäre die positive Probe auch von einer Umsetzung erfüllt,
    die JEDES vorhandene ``anchor.checked`` als Bindung liest — und die
    Ankerdrift stillstellte, die im September vorgeführt werden soll.
    """
    a = _menschlich(tmp_path, _anker(MENSCHLICH, "ambiguous"))
    assert a["source_binding"] == "drifted", a
    assert a["status"] == "REVIEW_REQUIRED", a
