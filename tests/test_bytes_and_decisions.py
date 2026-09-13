"""Welche Bytes eine Entscheidung meint — und welche sie nicht mehr meint.

ADR 0027 Punkt 6 trennt zwei Verdikte, die im Code heute gleich behandelt
werden:

* Ein Verdikt, das **aufschließt** (``ACCEPT``), bindet an seine Bytes. Neue
  Bytes entwerten es — das ist seit Anfang an so und ist geprüft.
* Ein Verdikt, das **über die Einwilligung verfügt** (``WITHDRAW``), bindet
  nicht. Ein Widerruf, den man durch Neuerzeugung derselben Datei aufheben
  könnte, wäre kein Widerruf.
* ``REJECT`` steht dazwischen und ist heute auf der falschen Seite: Es klebt
  wie ein Widerruf, obwohl es eine fachliche Beurteilung **dieser** Fassung
  ist.

Diese Datei nagelt den Zustand **vor** der Umsetzung fest. Ohne sie räumt die
Umsetzung von Punkt 6 die Asymmetrie versehentlich mit weg — sie sieht dann
wie eine Inkonsistenz aus, die man beim Aufräumen beseitigt.

Alle Tests laufen **mit Schlüssel**, außer der ausdrücklichen Gegenprobe unten:
ohne Schlüssel kappt die Autoritätsregel (ADR 0017) vorher, und der Test bewiese
nur, dass die Kappung greift.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._forge import cli, cli_keyed, forge, forge_keyed, place_object
from .test_forgery import wellformed_chain
from ._p3_evidence import bindings

#: Ein abgeleitetes Artefakt mit vollständiger Kette — Bindung, Beleg und
#: Entscheidung sind gesetzt, also ist die Entscheidungsachse die einzige, die
#: sich unter den Tests bewegt.
ZIEL = "l1.suggestions"


def _zweite_fassung(wurzel: Path, inhalt: bytes = b"eine zweite Fassung derselben Datei") -> str:
    """Eine neue Fassung des Artefakts — mit BYTES, nicht nur mit einer Adresse.

    Die erste Fassung dieser Datei nahm ``"b" * 64``. Das genügt für die
    Entscheidungsachse, hinterlässt im Record aber den Befund ``Objekt … fehlt``:
    Die Kette beruft sich auf Bytes, die niemand abgelegt hat. Solange die Tests
    nur ``artifacts`` lesen, stört das nicht — wer die Datei je auf eine
    Grün-Gegenprobe umstellt, stolpert darüber. Also echte Bytes.
    """
    return place_object(wurzel, inhalt)


@pytest.fixture
def welt(tmp_path: Path):
    """Authentifizierte Welt mit Schlüssel außerhalb der Datenwurzel."""
    schluessel = tmp_path / "journal.key"
    schluessel.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"

    def run(*args: str):
        return cli_keyed(*args, root=wurzel, key=schluessel)

    assert run("init").returncode == 0
    return wurzel, schluessel, run


def _record(run) -> dict:
    ergebnis = run("status", "--json")
    return json.loads(ergebnis.stdout)["details"]["records"][0]


def _bytes_der_kette(kette: list[dict], artefakt: str) -> str:
    """Die Bytes, auf die sich die Kette für dieses Artefakt beruft.

    Absichtlich aus der Kette gelesen und nicht danebengeschrieben: Eine zweite
    Fassung derselben Byteangabe wäre genau die Doppelwahrheit, gegen die diese
    Datei antritt.
    """
    for e in kette:
        if e["kind"] == "artifact.produced" and e["payload"]["artifact"] == artefakt:
            return e["payload"]["sha256"]
    raise AssertionError(f"{artefakt} kommt in der Kette nicht vor — Fixture geändert?")


def _entscheidung(artefakt: str, bytes_: str, verdikt: str) -> dict:
    return {
        "kind": "decision.recorded",
        "payload": {
            "artifact": artefakt,
            "subject_sha256": bytes_,
            "verdict": verdikt,
            **(bindings(artefakt, bytes_) if verdikt == "ACCEPT" else {}),
            "reference": f"PI-{artefakt}",
            "actor": "niemand",
            "at": "2026-09-01T11:00:00+00:00",
        },
    }


def _eingabe_der_kette(kette: list[dict], artefakt: str) -> str:
    """Die deklarierte Eingabe, auf die sich der Beleg der Kette beruft."""
    for e in kette:
        if e["kind"] == "receipt.recorded" and e["payload"]["artifact"] == artefakt:
            return e["payload"]["inputs"]["transcript.revision"]
    raise AssertionError(f"kein Beleg für {artefakt} in der Kette — Fixture geändert?")


def _modellbeleg(artefakt: str, ausgabe: str, eingabe: str, gate_bytes: str) -> dict:
    """Ein Modellbeleg auf NEUE Ausgabebytes, sonst wie in ``wellformed_chain``.

    Die Autorisierung lautet weiter auf die Entscheidung über das GATE-Artefakt
    (``transcript.confirmed``) und deren Bytes — die hat sich nicht bewegt. Nur
    die Ausgabe ist eine andere.
    """
    return {
        "kind": "receipt.recorded",
        "payload": {
            "artifact": artefakt,
            "output_sha256": ausgabe,
            "inputs": {"transcript.revision": eingabe, "transcript.confirmed": gate_bytes},
            "code_version": "0.1.0",
            "kind": "model",
            "step": "l1.suggest",
            "params": {"model": "gemma4:e4b", "temperature": 0.0, "seed": 7},
            "prompt_sha256": "c" * 64,
            "finish_reason": "stop",
            "authorisation": f"PI-transcript.confirmed@{gate_bytes[:12]}",
            "authorisation_subject_sha256": gate_bytes,
            "authorised_at": "2026-09-01T09:00:00+00:00",
            "started_at": "2026-09-01T09:30:00+00:00",
        },
    }


def _erzeugt(artefakt: str, bytes_: str, at: str | None = None) -> dict:
    ev: dict = {
        "kind": "artifact.produced",
        "payload": {"artifact": artefakt, "sha256": bytes_},
    }
    if at is not None:
        ev["at"] = at
    return ev


def _gegenprobe_gruen(run) -> None:
    """Die unveränderte Kette MUSS grün sein.

    Ohne diese Zusicherung prüfte jeder Test hier nur, dass irgendetwas rot
    wird — und das wäre auch bei einem kaputten Fixture der Fall.
    """
    rec = _record(run)
    assert rec["findings"] == [], rec["findings"]
    assert rec["status"] == "READY", rec["explanation"]


# --------------------------------------------------------------- T1 · WITHDRAW


def test_new_bytes_do_not_lift_a_withdrawal(welt):
    """Ein Widerruf überlebt die Neuerzeugung des Artefakts.

    Wäre es anders, hieße die Bedienungsanleitung für das Umgehen einer
    zurückgezogenen Einwilligung: „Datei neu erzeugen". Das ist der eine Fall,
    in dem Bytegleichheit ausdrücklich **nicht** die Frage ist — die Person hat
    über die Verwendung verfügt, nicht über eine Fassung.
    """
    wurzel, schluessel, run = welt
    kette = wellformed_chain(wurzel)
    alte_bytes = _bytes_der_kette(kette, ZIEL)

    kette.append(_entscheidung(ZIEL, alte_bytes, "WITHDRAW"))
    kette.append(_erzeugt(ZIEL, _zweite_fassung(wurzel)))

    forge_keyed(wurzel, schluessel, kette)
    rec = _record(run)

    assert rec["artifacts"][ZIEL]["decision_state"] == "withdrawn", rec["artifacts"][ZIEL]
    assert rec["artifacts"][ZIEL]["status"] == "EXCLUDED", rec["artifacts"][ZIEL]


def test_an_undo_lifts_the_withdrawal_again(welt):
    """Gegenprobe zu T1: ``EXCLUDED`` klebt nicht pauschal.

    Ohne diesen Test wäre T1 auch dann grün, wenn ein einmal erreichtes
    ``EXCLUDED`` überhaupt nicht mehr verlassen werden könnte — dann prüfte T1
    eine Sackgasse und keine Regel.
    """
    wurzel, schluessel, run = welt
    kette = wellformed_chain(wurzel)
    alte_bytes = _bytes_der_kette(kette, ZIEL)

    kette.append(_entscheidung(ZIEL, alte_bytes, "WITHDRAW"))
    kette.insert(
        0,
        {
            "kind": "instance.registered",
            "record_id": None,
            "payload": {
                "coder_id": "niemand",
                "source": "mensch",
                "label": "synthetic",
                "reference": "SYNTHETIC-REGISTER",
            },
        },
    )
    forge_keyed(wurzel, schluessel, kette)
    from ._forge import journal_path

    withdrawal = json.loads(journal_path(wurzel).read_text().splitlines()[-1])["digest"]
    undo = _entscheidung(ZIEL, alte_bytes, "UNDO")
    undo["payload"]["undo_of"] = withdrawal
    forge_keyed(wurzel, schluessel, [undo])
    rec = _record(run)

    assert rec["artifacts"][ZIEL]["decision_state"] != "withdrawn", rec["artifacts"][ZIEL]
    assert rec["artifacts"][ZIEL]["status"] != "EXCLUDED", rec["artifacts"][ZIEL]


def test_an_unauthenticated_withdrawal_does_not_exclude(tmp_path: Path):
    """Gegenprobe zu T1: Der Ausschluss kommt aus der **Autorität**, nicht aus
    dem Wort ``WITHDRAW``.

    ``Authority.AUTHENTICATED.may_confer_exclusion`` ist ``True``
    (``policies/authority.py``) — genau deshalb landet der Widerruf in T1
    überhaupt. Ohne diese Gegenprobe würde T1 bei einer späteren
    Autoritätsänderung still zum Tautologietest: Es prüfte dann, dass ein
    Widerruf klebt, der nie angekommen ist.
    """
    wurzel = tmp_path / "daten"
    assert cli("init", root=wurzel).returncode == 0

    kette = wellformed_chain(wurzel)
    alte_bytes = _bytes_der_kette(kette, ZIEL)
    kette.append(_entscheidung(ZIEL, alte_bytes, "WITHDRAW"))
    kette.append(_erzeugt(ZIEL, _zweite_fassung(wurzel)))

    forge(wurzel, kette)
    ergebnis = cli("status", "--json", root=wurzel)
    rec = json.loads(ergebnis.stdout)["details"]["records"][0]

    assert rec["artifacts"][ZIEL]["decision_state"] != "withdrawn", rec["artifacts"][ZIEL]
    assert rec["artifacts"][ZIEL]["status"] != "EXCLUDED", rec["artifacts"][ZIEL]
    assert any("WITHDRAW" in p for p in rec["provisional"]), rec["provisional"]


# ---------------------------------------------------- T2 · Journalreihenfolge


@pytest.mark.parametrize(
    ("stelle", "erwartet"),
    [("hinten", "accepted"), ("vorn", "undecided")],
    ids=["annahme-auf-die-hinten-stehenden", "annahme-auf-die-spaeter-datierten"],
)
def test_current_bytes_follow_journal_order(welt, stelle, erwartet):
    """Die Reihenfolge im Journal entscheidet, nicht der Zeitstempel.

    Wächter gegen ein späteres ``max(by ts)``: Wer Zeitstempel setzen kann,
    setzte sonst die Bytes. Die Fassung **vorn** trägt den **späteren**
    Zeitstempel, die Fassung **hinten** den früheren. Nur eine Annahme auf die
    hintere greift.

    **Warum die Assertion an der Entscheidung hängt und nicht an den Bytes.**
    Eine erste Fassung dieses Tests prüfte nur, dass die alte Annahme fällt.
    Sie blieb unter der eingesetzten Mutation (``f.sha256`` nur bei späterem
    ``at`` überschreiben) grün — beide Ordnungen entwerten die alte Annahme.
    Erst die Wirkung auf eine **neue** Annahme unterscheidet die Ordnungen;
    gegen die Mutation gemessen fällt diese Fassung, die erste nicht.
    """
    wurzel, schluessel, run = welt
    kette = wellformed_chain(wurzel)

    vorn = _zweite_fassung(wurzel, b"die vordere Fassung, spaeter datiert")
    hinten = _zweite_fassung(wurzel, b"die hintere Fassung, frueher datiert")
    kette.append(_erzeugt(ZIEL, vorn, at="2026-09-02T10:00:00+00:00"))
    kette.append(_erzeugt(ZIEL, hinten, at="2026-09-01T08:00:00+00:00"))
    kette.append(_entscheidung(ZIEL, {"vorn": vorn, "hinten": hinten}[stelle], "ACCEPT"))

    forge_keyed(wurzel, schluessel, kette)
    rec = _record(run)

    assert rec["artifacts"][ZIEL]["decision_state"] == erwartet, rec["artifacts"][ZIEL]


# ------------------------------------------------------------- T3 · REJECT


def test_rejection_expires_with_its_bytes(welt):
    """Eine Ablehnung gilt der Fassung, die abgelehnt wurde — nicht dem Namen.

    Nach der Neuerzeugung ist die Entscheidungslage **offen**: Niemand hat die
    neuen Bytes beurteilt. Der Zustand ist deshalb ``UNDECIDED`` und
    ``ACTION_NEEDED`` — nicht ``EXCLUDED``.

    Die Zielassertion ist bewusst positiv. ``status ist nicht EXCLUDED`` wäre
    auch bei ``STOP`` erfüllt; unter ``strict=True`` führte ein unerwartetes
    Bestehen dann an das falsche Ende der Suche.

    **Warum die neue Fassung einen zweiten Modellbeleg mitschickt.** Die erste
    Fassung hängte nur die neuen Bytes an. Gemessen mit simuliertem Punkt 6:
    die Entscheidungsachse steht dann richtig auf ``undecided``, der Status
    aber auf ``STALE`` — der Beleg lautete noch auf die alten Bytes, und
    ``STALE`` steht in der Leiter **vor** ``ACTION_NEEDED``
    (``state.py``). Der Test wäre damit ein xfail gewesen, der auch nach der
    Umsetzung nicht grün wird, und zwar aus einem Grund, den er gar nicht
    prüfen will. Mit dem Beleg auf die neuen Bytes ist er der Einachsentest,
    als der er gemeint ist: gemessen liefert er unter simuliertem Punkt 6
    ``current / undecided / ACTION_NEEDED``.
    """
    wurzel, schluessel, run = welt
    kette = wellformed_chain(wurzel)
    alte_bytes = _bytes_der_kette(kette, ZIEL)
    eingabe = _eingabe_der_kette(kette, ZIEL)
    neue_bytes = _zweite_fassung(wurzel)

    kette.append(_entscheidung(ZIEL, alte_bytes, "REJECT"))
    kette.append(_erzeugt(ZIEL, neue_bytes))
    kette.append(_modellbeleg(ZIEL, neue_bytes, eingabe, alte_bytes))

    forge_keyed(wurzel, schluessel, kette)
    rec = _record(run)

    # Die anderen beiden Achsen stehen sauber — sonst prüfte die Zielassertion
    # unten etwas anderes als die Entscheidungsachse.
    assert rec["findings"] == [], rec["findings"]
    assert rec["artifacts"][ZIEL]["derivation_state"] == "current", rec["artifacts"][ZIEL]

    assert rec["artifacts"][ZIEL]["decision_state"] == "undecided", rec["artifacts"][ZIEL]
    assert rec["artifacts"][ZIEL]["status"] == "ACTION_NEEDED", rec["artifacts"][ZIEL]


def test_a_rejection_of_the_current_bytes_keeps_excluding(welt):
    """Gegenprobe zu T3, zwingend.

    Ohne sie wäre T3 nach der Umsetzung auch dann grün, wenn ``REJECT``
    überhaupt nicht mehr wirkte. Hier bleiben die Bytes, auf die die Ablehnung
    lautet, die aktuellen — der Ausschluss muss stehen.
    """
    wurzel, schluessel, run = welt
    kette = wellformed_chain(wurzel)
    alte_bytes = _bytes_der_kette(kette, ZIEL)

    kette.append(_entscheidung(ZIEL, alte_bytes, "REJECT"))

    forge_keyed(wurzel, schluessel, kette)
    rec = _record(run)

    assert rec["artifacts"][ZIEL]["decision_state"] == "rejected", rec["artifacts"][ZIEL]
    assert rec["artifacts"][ZIEL]["status"] == "EXCLUDED", rec["artifacts"][ZIEL]


def test_the_fixture_itself_is_green(welt):
    """Die Kette ohne jede Ergänzung ist grün — sonst misst oben nichts."""
    wurzel, schluessel, run = welt
    forge_keyed(wurzel, schluessel, wellformed_chain(wurzel))
    _gegenprobe_gruen(run)
