"""Der Vorlauf: ``doctor`` liest die Metadateneingaben, bevor sie zählen.

``metadata.derive`` liest seine Eingabedatei genau einmal (offene Stelle O-2,
``docs/TRACEABILITY.md``). Wer danach etwas ändert, sitzt fest: Der Entwurf
wird nicht neu abgeleitet, und seit dem zweiten Satz der Exportsperre hält der
Export auch noch. Das ist unangenehm, aber ehrlich.

Diese Prüfung ist kein Notausgang daraus. Sie ist der Vorlauf, der verhindert,
dass man dort hineinläuft: Ein Tippfehler im Feldnamen, ein Datum, das keines
ist, ein ``consent_status`` ausserhalb des Profilvokabulars — all das sieht der
Operator jetzt in ``doctor``, an einer Stelle, an der es noch billig ist.

Read-only, wie der ganze Befehl. Und ein Ladefehler ist ein BEFUND, kein
Traceback: ``doctor`` ist der Befehl, den man fährt, wenn etwas nicht stimmt,
und er darf nicht selbst an dem scheitern, was er finden soll.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._forge import cli_keyed, report_lines

RECORD = "SANDBOX-001"

VOLLSTAENDIG = {
    "record_id": RECORD,
    "interview_date": "2026-09-01",
    "interviewer": "Synthetic Interviewer",
    "consent_status": "research-only",
    "accessRights": "restricted",
    "title": "Synthetisches Interview zur Abnahme",
    "language": "deu",
    "consent_reference": "SYNTHETIC-CONSENT-REF",
}


def _toml(werte: dict[str, object]) -> str:
    zeilen = ["[record]"] + [f'{k} = "{v}"' for k, v in werte.items() if v is not None]
    return "\n".join(zeilen) + "\n"


@pytest.fixture
def welt(tmp_path: Path):
    """Ein frisch angelegter Arbeitsbereich. Mehr braucht ``doctor`` nicht.

    Kein Record, keine Kette, kein Modelllauf: Der Vorlauf soll gerade DANN
    etwas sagen, wenn noch nichts passiert ist.
    """
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"

    def run(*args: str):
        return cli_keyed(*args, root=wurzel, key=key)

    assert run("init").returncode == 0
    return wurzel, run


def _schreibe(wurzel: Path, name: str, inhalt: str) -> Path:
    verzeichnis = wurzel / "_governance" / "metadata"
    verzeichnis.mkdir(parents=True, exist_ok=True)
    pfad = verzeichnis / name
    pfad.write_text(inhalt, encoding="utf-8")
    return pfad


def _doctor(run) -> tuple[int, dict]:
    ergebnis = run("doctor", "--json")
    return ergebnis.returncode, json.loads(ergebnis.stdout)


def test_without_the_directory_doctor_is_unchanged(welt):
    """Keine Dateien ist kein Befund und kein Halt.

    Ein Arbeitsbereich ohne Erschliessung ist ein normaler Zustand. Ein
    Vorlauf, der ihn bemängelt, wäre eine Prüfung, die den Regelfall für einen
    Mangel hält — und der Operator lernte, sie zu übergehen.
    """
    wurzel, run = welt
    assert not (wurzel / "_governance" / "metadata").exists()
    code, bericht = _doctor(run)
    assert code == 0, bericht
    assert bericht["status"] == "READY", bericht
    assert "metadata_input_findings" not in bericht["details"], bericht["details"]


def test_a_clean_file_produces_no_finding(welt):
    """Die Gegenprobe: Eine richtige Datei bewegt nichts.

    Ohne sie prüften die drei folgenden Fälle nur, dass der Vorlauf überhaupt
    anschlägt, und nicht, dass er im Normalfall schweigt.
    """
    wurzel, run = welt
    _schreibe(wurzel, f"{RECORD}.toml", _toml(VOLLSTAENDIG))
    code, bericht = _doctor(run)
    assert code == 0, bericht
    assert bericht["status"] == "READY", bericht
    assert "metadata_input_findings" not in bericht["details"], bericht["details"]


def test_a_missing_mandatory_key_is_named(welt):
    """Der Schlüssel steht in der Meldung, nicht seine Anzahl.

    Wer den Befund liest, soll wissen, was er eintragen muss, und nicht erst
    eine zweite Abfrage brauchen. Der Loader nennt Pfad, Schlüssel und Grund;
    der Vorlauf reicht diesen Wortlaut durch, statt ihn in einen zweiten
    Rahmen zu setzen.
    """
    wurzel, run = welt
    ohne = {k: v for k, v in VOLLSTAENDIG.items() if k != "interviewer"}
    _schreibe(wurzel, f"{RECORD}.toml", _toml(ohne))

    code, bericht = _doctor(run)
    assert code == 3, bericht
    assert bericht["status"] == "ACTION_NEEDED", bericht
    assert bericht["reason_code"] == "ACTION_METADATA_INPUT", bericht
    befunde = bericht["details"]["metadata_input_findings"]
    assert len(befunde) == 1 and "interviewer" in befunde[0], befunde


def test_a_consent_status_outside_the_profile_vocabulary_is_a_finding(welt):
    """Die Form stimmt, die Aussage nicht — und genau das soll man vorher sehen.

    ``teaching`` ist ein gültiger Wert des Metadata Models und steht trotzdem
    nicht im Vokabular des Sandboxprofils. Der Loader lässt ihn durch, weil er
    Form prüft; ``check_record`` meldet ihn, weil es das Profil kennt. Zwei
    Prüfungen, zwei Orte, und der Vorlauf zeigt beide.
    """
    wurzel, run = welt
    _schreibe(wurzel, f"{RECORD}.toml", _toml(dict(VOLLSTAENDIG) | {"consent_status": "teaching"}))

    code, bericht = _doctor(run)
    assert code == 3, bericht
    assert bericht["reason_code"] == "ACTION_METADATA_INPUT", bericht
    befunde = bericht["details"]["metadata_input_findings"]
    assert any("Profilvokabular" in b for b in befunde), befunde
    assert any(f"{RECORD}.toml" in b for b in befunde), befunde


def test_a_broken_toml_is_a_finding_and_not_a_traceback(welt):
    """``doctor`` fährt man, WEIL etwas nicht stimmt.

    Ein Befehl, der an dem scheitert, was er finden soll, ist an der einen
    Stelle unbrauchbar, an der man ihn braucht. Geprüft wird deshalb beides:
    dass ein Exitcode nach Vertrag herauskommt, und dass in der Ausgabe kein
    Traceback steht.
    """
    wurzel, run = welt
    _schreibe(wurzel, f"{RECORD}.toml", "[record\nrecord_id = kaputt")

    ergebnis = run("doctor", "--json")
    assert ergebnis.returncode == 3, ergebnis.stdout + ergebnis.stderr
    assert "Traceback" not in ergebnis.stderr, ergebnis.stderr
    bericht = json.loads(ergebnis.stdout)
    assert bericht["reason_code"] == "ACTION_METADATA_INPUT", bericht
    befunde = bericht["details"]["metadata_input_findings"]
    assert len(befunde) == 1 and "nicht lesbar" in befunde[0], befunde


def test_a_file_named_after_another_record_is_a_finding(welt):
    """Der Dateiname ist die Zuordnung, und der Inhalt muss sie bestätigen.

    Die Prüfung ist dieselbe wie in ``metadata.derive``, nur früher: Dort hält
    sie den Lauf an, hier zeigt sie den Fehler, bevor jemand den Lauf startet.
    Eine kopierte Eingabedatei ist der Fall, für den beide da sind.
    """
    wurzel, run = welt
    _schreibe(wurzel, "SANDBOX-002.toml", _toml(VOLLSTAENDIG))

    code, bericht = _doctor(run)
    assert code == 3, bericht
    befunde = bericht["details"]["metadata_input_findings"]
    assert any("SANDBOX-002" in b and RECORD in b for b in befunde), befunde


def test_the_next_command_points_at_the_files_and_not_at_doctor(welt):
    """Ein read-only Befund, dessen NEXT derselbe read-only Befehl ist, ist eine Schleife.

    Und ``init`` wäre ebenso falsch: Es legt keine Metadateneingabe an. Der
    NEXT nennt deshalb das Verzeichnis — dieselbe Überlegung wie beim
    Storehinweis, der auf die liegengebliebene Datei zeigt.
    """
    wurzel, run = welt
    _schreibe(wurzel, f"{RECORD}.toml", _toml(dict(VOLLSTAENDIG) | {"interview_date": "gestern"}))

    ergebnis = run("doctor")
    zeilen = report_lines(ergebnis.stdout)
    assert "doctor" not in zeilen["NEXT"], zeilen["NEXT"]
    assert "init" not in zeilen["NEXT"], zeilen["NEXT"]
    assert str(wurzel / "_governance" / "metadata") in zeilen["NEXT"], zeilen["NEXT"]


def test_the_findings_are_visible_even_when_another_branch_returns_first(welt):
    """Systemintegrität geht vor Erschliessung — aber sie verdeckt sie nicht.

    Die Zweige von ``doctor`` kehren einzeln zurück; ein Storehinweis käme vor
    dem Metadatenbefund. Deshalb steht der Vorlauf VOR den Storezweigen und
    schreibt seine Befunde in ``details``, auch wenn ein anderer Zweig antwortet.
    Sonst sähe der Operator abwechselnd die eine Hälfte seines Problems.
    """
    wurzel, run = welt
    _schreibe(wurzel, f"{RECORD}.toml", _toml(dict(VOLLSTAENDIG) | {"consent_status": "teaching"}))
    # Ein Objekt unter einem Namen, der keine Adresse ist: der Storezweig, der
    # frueher zurueckkehrt als der Metadatenzweig — und zwar mit STOP, also so
    # frueh wie irgend moeglich. Genau der Fall, der die Metadatenbefunde
    # verdecken wuerde, wenn sie erst im eigenen Zweig entstuenden.
    objekte = wurzel / "objects"
    objekte.mkdir(parents=True, exist_ok=True)
    (objekte / ".tmp-abgebrochen").write_bytes(b"halb")

    code, bericht = _doctor(run)
    assert code == 1, bericht
    assert bericht["reason_code"] == "STOP_STORE_UNSOUND", bericht
    assert bericht["details"]["metadata_input_findings"], bericht["details"]
    assert any(
        "Profilvokabular" in b for b in bericht["details"]["metadata_input_findings"]
    ), bericht["details"]
