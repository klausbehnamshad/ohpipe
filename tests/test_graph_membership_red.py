"""Rotphase zu Punkt 10 · ein Name, den der Graph nicht erzeugt, ist kein Artefakt.

Gemessen, heute: Ein Journal mit einem einzigen Ereignis auf
``erfunden.artefakt`` legt diesen Namen in der Zustandstabelle an — **still**,
ohne Befund, für **jede** Ereignisart mit einem ``artifact``-Feld.

Der Defekt sitzt nicht in einer der Ereignisarten, sondern **vor** der
Fallunterscheidung:

    src/ohpipe/application/replay.py::replay
    f = v.facts.setdefault(name, ArtifactFacts(name=name, …))

Ein Marker, der nur auf ``anchor.checked`` zeigte, würde nach einer engen
Reparatur grün, während ``receipt.recorded`` weiter Phantomzeilen anlegt.
Deshalb ist die Zusicherung über alle vier Arten parametrisiert.

**Warum ``anchor.checked`` trotzdem der auffälligste Fall ist** — und warum er
hier nur im Docstring steht und nicht als eigene Zusicherung: Er ist der
einzige, der die Bindungsachse zusätzlich auf ``bound`` setzt. Nach der
Reparatur gibt es für ihn keine Zeile mehr, an der man das prüfen könnte; eine
Zusicherung darauf wäre nach der Reparatur unerreichbar — genau der Fehler, den
T3 in Serie 3b hatte.

Gemessen mit **gültigen** Nutzlasten und **abgelegten** Bytes. Das ist keine
Formalie: Mit ``"a" * 64`` ohne ``place_object`` meldet der Record den Befund
*„Objekt … fehlt"*, und dann misst man den Contentstore statt der Phantomzeile.

Beide Richtungen sind vor der Auslieferung gemessen — heute rot an der
Zielassertion, nach der Reparatur grün, und die Gegenrichtung unten hält in
beiden Fällen.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._forge import cli, forge, place_object

#: Ein Name, den kein Schritt eines Profils erzeugt.
ERFUNDEN = "erfunden.artefakt"

#: Ein Name, den der Sandbox-Graph erzeugt — die Gegenrichtung.
ECHT = "transcript.revision"

#: Der Kern des Befunds, den die Graphprüfung erzeugt. Er steht hier
#: AUSGESCHRIEBEN und wird nicht aus ``replay.py`` importiert — sonst prüfte
#: der Test den Code gegen sich selbst und zöge bei einer Umbenennung
#: stillschweigend mit (dasselbe Muster wie ``AUFFANGFALL`` in
#: ``test_status_ladder_totality.py``).
#:
#: Beide Tests unten hängen daran, und zwar in entgegengesetzter Richtung: der
#: Marker verlangt ihn, die Gegenrichtung verbietet ihn. Wer den Wortlaut
#: ändert, ohne diese Zeile nachzuziehen, bekommt einen roten Marker — nicht
#: eine stille Gegenrichtung, die über nichts mehr wacht.
GRAPHBEFUND = "kein Schritt des Graphen erzeugt"


def _nutzlast(kind: str, sha: str) -> dict:
    """Eine je Art **gültige** Nutzlast, damit der Nutzlastprüfer nicht mitmisst."""
    return {
        "anchor.checked": {"outcome": "exact"},
        "artifact.produced": {"sha256": sha},
        "receipt.recorded": {
            "output_sha256": sha,
            "inputs": {"src": sha},
            "code_version": "0.1.0",
        },
        "decision.recorded": {
            "subject_sha256": sha,
            "verdict": "ACCEPT",
            "reference": "PI-erfunden",
            "actor": "niemand",
            "at": "2026-09-01T09:00:00+00:00",
        },
    }[kind]


def _record_mit_einem_ereignis(tmp_path: Path, kind: str, artefakt: str) -> dict:
    wurzel = tmp_path / "daten"
    assert cli("init", root=wurzel).returncode == 0
    sha = place_object(wurzel, b"echte Bytes, damit keine Referenz ins Leere zeigt")
    forge(wurzel, [{"kind": kind, "payload": {"artifact": artefakt, **_nutzlast(kind, sha)}}])
    return json.loads(cli("status", "--json", root=wurzel).stdout)["details"]["records"][0]


ARTEN = ["anchor.checked", "artifact.produced", "receipt.recorded", "decision.recorded"]


@pytest.mark.parametrize("kind", ARTEN)
def test_an_event_on_a_name_no_step_produces_gets_no_row(tmp_path: Path, kind: str):
    """Ein erfundener Name bekommt keine Zeile, sondern einen benannten Befund.

    Die Zielzeile ist die **Abwesenheit der Zeile**, nicht die Anwesenheit des
    Befunds: Eine Reparatur, die den Namen weiter einträgt und nur zusätzlich
    warnt, hätte den Angriff nicht geschlossen — die Zeile ist es, die in
    ``have`` und in den Planer läuft. Der Befund steht als zweite Zusicherung
    daneben, damit die Ablehnung nicht stumm ist.
    """
    rec = _record_mit_einem_ereignis(tmp_path, kind, ERFUNDEN)

    # Wächter: der Record ist überhaupt gelesen worden.
    assert rec["events"] >= 1, rec

    assert ERFUNDEN not in rec["artifacts"], (
        f"{kind} auf {ERFUNDEN!r} hat eine Zeile in der Zustandstabelle angelegt: "
        f"{rec['artifacts'].get(ERFUNDEN)}. Kein Schritt des Graphen erzeugt diesen Namen."
    )
    assert any(ERFUNDEN in b and GRAPHBEFUND in b for b in rec["findings"]), (
        f"{kind} auf {ERFUNDEN!r} wurde stillschweigend verworfen — kein Befund nennt "
        f"den Namen UND den Grund {GRAPHBEFUND!r}: {rec['findings']}"
    )


@pytest.mark.parametrize("kind", ARTEN)
def test_an_event_on_a_graph_artifact_keeps_its_row(tmp_path: Path, kind: str):
    """Gegenrichtung, muss heute grün sein und grün bleiben.

    Ohne sie wäre der Marker oben auch dann erfüllt, wenn die Reparatur
    **jedem** Ereignis die Zeile verweigerte — dann wäre die Zustandstabelle
    dauerhaft leer und alles rot. Geprüft wird deshalb an einem Namen, den der
    Sandbox-Graph wirklich erzeugt.

    **Warum die zweite Zusicherung auf den Graphzugehörigkeits-Befund verengt
    ist und nicht ``findings == []`` lautet.** Die erste Fassung sicherte zu,
    dass an dieser Journallage überhaupt nichts auffällt — mehr, als dieser
    Test behauptet. Gemessen: Unter der (bereits als ``xfail`` markierten)
    Reparatur des Dauerbefunds *„anchor.checked ohne erzeugte Bytes"* fällt
    genau diese Zeile, und zwar für die Parametrisierung ``anchor.checked``,
    weil die Gegenprobe absichtlich **ein einziges** Ereignis schreibt — also
    ein Ankerergebnis ohne vorherige Bytes, exakt die Lage, die jener Marker
    als Defekt festhält.

    Die Zeile wäre damit eine Falle gewesen: Wer den Dauerbefund repariert,
    sähe einen Test aus einer fremden Scheibe fallen und wüsste nicht, ob er
    etwas kaputt gemacht hat. Der Test meint nicht *„hier ist nichts
    auffällig"*, sondern *„die Graphprüfung hat einen echten Namen nicht
    zurückgewiesen"* — und genau das steht jetzt da. Andere Befunde gehen ihn
    nichts an; sie haben ihre eigenen Zusicherungen.

    **Verworfen: die Zusicherung ganz zu streichen.** Die Zeile darüber
    (``ECHT in rec["artifacts"]``) deckt die Eigenschaft schon ab — eine
    zurückgewiesene Zeile gibt es nicht. Sie deckt aber den halbfertigen
    Fall nicht ab: eine Reparatur, die die Zeile behält **und** trotzdem den
    Graphbefund meldet. Genau dafür steht sie, und deshalb nennt sie den
    Befund beim Namen statt zu zählen.
    """
    rec = _record_mit_einem_ereignis(tmp_path, kind, ECHT)

    assert ECHT in rec["artifacts"], (
        f"{kind} auf {ECHT!r} hat keine Zeile bekommen — der Name steht in "
        f"produces des Schritts 'ingest'. artifacts={list(rec['artifacts'])}"
    )
    assert not [b for b in rec["findings"] if GRAPHBEFUND in b], (
        f"{kind} auf {ECHT!r} wurde von der Graphprüfung zurückgewiesen, obwohl "
        f"ein Schritt den Namen erzeugt: {rec['findings']}"
    )
