"""Rotphase zu Scheibe 4a — das Feld `input_refs` auf `decision.recorded`.

E2 trennt zwei Dinge ausdrücklich: *„befreit von der Receipt-Pflicht, nie vom
Eingabebezug."* `transcript.confirmed` braucht also einen expliziten Bezug auf
den Input, den es bestätigt. Entschieden am 08.08.2026: Träger ist ein neues
Feld `input_refs` auf `decision.recorded`, nicht `receipt.recorded.inputs` —
ein Receipt auf einem Artefakt, dessen Rolle `provenance_required = false`
deklariert, ließe Vertrag und Journal Verschiedenes sagen.

**Die Falle, gemessen.** Heute lehnt die Nutzlastprüfung *jedes* `input_refs`
ab — gültiges, ungültiges, leeres, sogar eine Liste — und immer mit derselben
Begründung:

    gültiger Wert    -> abgelehnt: „nicht erlaubte Felder: ['input_refs']"
    kein sha256      -> abgelehnt: „nicht erlaubte Felder: ['input_refs']"
    unbekannte Rolle -> abgelehnt: „nicht erlaubte Felder: ['input_refs']"

Ein Test, der nur prüft *dass* abgelehnt wird, wäre damit heute grün **und**
nach 4a grün. Er ginge nie rot, bewachte die Rotphase nicht und sähe trotzdem
aus wie ein Test — die Fehlerklasse dieser Woche in Reinform.

**Auflösung: auf den GRUND prüfen, nicht auf die Ablehnung.** Die
Zielassertion lautet: abgelehnt, aber **nicht** wegen des Feldnamens. Damit ist
der Test heute rot, wird mit 4a grün, und er kann nicht dadurch erschlichen
werden, dass das Feld weiterhin ganz verboten bleibt.
"""

from __future__ import annotations

import pytest

from ohpipe.domain.events import (
    DECISION_RECORDED,
    INPUT_REF_ROLES,
    PayloadRejected,
    check_payload,
)

RECORD = "SANDBOX-001"
SHA = "b" * 64

#: Eine gültige Entscheidung ohne Eingabebezug — der heutige Bestand.
BASIS: dict = {
    "artifact": "transcript.confirmed",
    "subject_sha256": "a" * 64,
    "verdict": "ACCEPT",
    "reference": "PI-transcript.confirmed",
    "actor": "niemand",
    "at": "2026-09-01T09:00:00+00:00",
}

#: Der Wortlaut, mit dem die Erlaubnisliste ein unbekanntes FELD abweist. Steht
#: hier ausgeschrieben; wird er umbenannt, fallen die Marker unten auf, statt
#: still ihre Bedeutung zu verlieren.
FELDNAME_ABGEWIESEN = "nicht erlaubte Felder"


def _mit(input_refs) -> dict:
    return {**BASIS, "input_refs": input_refs}


def _ablehnungsgrund(payload: dict) -> str:
    """Die Nutzlast muss abgelehnt werden; zurückgegeben wird der **Grund**."""
    with pytest.raises(PayloadRejected) as fehler:
        check_payload(DECISION_RECORDED, payload, RECORD)
    return str(fehler.value)


# Ein Test, der den heutigen Zustand festnagelt („das Feld wird noch abgewiesen"),
# stand hier und ist wieder heraus: Er wäre heute grün und mit 4a rot — also eine
# Zeile, die der Executor löschen MUSS, damit die Suite grün wird. Ein Test, der
# beim Erfolg gelöscht werden muss, ist eine Falle und kein Wächter. Der heutige
# Zustand steht im Modulkopf und in den Marker-Begründungen; die Marker unten
# sind genau deshalb rot.


def test_a_decision_without_input_refs_stays_valid():
    """Kein Marker: das muss heute grün sein und nach 4a grün bleiben.

    Wäre `input_refs` Pflicht, bräche jeder Bestandsaufruf — und die
    Bestandsjournale, die es schon gibt, wären nachträglich ungültig. Das Feld
    ist optional.
    """
    check_payload(DECISION_RECORDED, dict(BASIS), RECORD)


def test_a_decision_may_carry_input_refs():
    """Eine gültige Nutzlast mit Eingabebezug wird angenommen."""
    check_payload(DECISION_RECORDED, _mit({"transcript": SHA}), RECORD)


@pytest.mark.parametrize(
    ("wert", "was"),
    [
        ({"transcript": "kein-hash"}, "Wert ist kein sha256"),
        ({"transcript": SHA[:32]}, "Wert ist zu kurz"),
        # Kleinhex ist die Hauskonvention: ^[0-9a-f]{64}$ (decision.py, store.py, pii.py).
        ({"transcript": SHA.upper()}, "Wert ist nicht kleingeschrieben"),
        (["b" * 64], "input_refs ist eine Liste statt eines Objekts"),
        ({}, "input_refs ist leer"),
    ],
    ids=["kein-hash", "zu-kurz", "grossbuchstaben", "liste", "leer"],
)
def test_input_refs_is_refused_for_its_content_not_its_name(wert, was):
    """Abgelehnt — aber **nicht** wegen des Feldnamens.

    Das ist die Zielassertion, und sie ist der ganze Grund, warum dieser Test
    so und nicht als schlichtes „wird abgelehnt" geschrieben ist: Letzteres
    wäre heute grün und nach 4a grün.
    """
    grund = _ablehnungsgrund(_mit(wert))
    assert FELDNAME_ABGEWIESEN not in grund, (
        f"{was}: abgelehnt, aber wegen des Feldnamens statt wegen des Inhalts — {grund!r}"
    )


def test_input_refs_refuses_an_unknown_role_for_the_role_not_the_field():
    """Eine unbekannte Rolle wird abgelehnt — wegen der Rolle.

    `transcript.confirmed` bestätigt genau eine Sache. Ein `input_refs` mit
    einem Schlüssel, den der Vertrag nicht kennt, ist kein Eingabebezug,
    sondern ein Freitextfeld im Journal.
    """
    grund = _ablehnungsgrund(_mit({"quatsch": SHA}))
    assert FELDNAME_ABGEWIESEN not in grund, (
        f"unbekannte Rolle: abgelehnt, aber wegen des Feldnamens — {grund!r}"
    )


def test_the_input_ref_role_contract_is_explicit_and_artifact_specific():
    """Die Nutzlastprüfung errät keine Rollen aus einem Laufgraphen."""
    assert {
        "transcript.confirmed": frozenset({"transcript"}),
    } == INPUT_REF_ROLES


def test_an_unknown_input_ref_role_is_not_echoed():
    """Ein geheimer Rollenschlüssel darf nicht über die Logzeile abfließen."""
    geheim = "rolle-geheim-c5-f3-7f0a"

    with pytest.raises(PayloadRejected) as fehler:
        check_payload(DECISION_RECORDED, _mit({geheim: SHA}), RECORD)

    assert geheim not in str(fehler.value)


class _StringifiableHash:
    def __str__(self) -> str:
        return SHA


def test_a_stringifiable_non_string_is_not_an_input_ref_hash():
    """Regex-Eignung nach ``str(wert)`` ist keine Typprüfung."""
    with pytest.raises(PayloadRejected):
        check_payload(
            DECISION_RECORDED,
            _mit({"transcript": _StringifiableHash()}),
            RECORD,
        )


def test_an_invalid_input_ref_value_is_not_echoed():
    """Auch der Wert bleibt aus der Fehlermeldung vollständig heraus."""
    geheim = "wert-geheim-c5-f3-9e1b"

    with pytest.raises(PayloadRejected) as fehler:
        check_payload(DECISION_RECORDED, _mit({"transcript": geheim}), RECORD)

    assert geheim not in str(fehler.value)
