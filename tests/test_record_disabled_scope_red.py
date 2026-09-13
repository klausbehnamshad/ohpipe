"""Regression: record.disabled prüft vor dem Ausschluss die Graphzugehörigkeit.

Der frühere Rotmarker ist seit der Replay-Korrektur vom 13.09.2026 ein
regulärer Regressionstest. Die historische Begründung folgt zur Einordnung.

Scheibe A hat zugesichert: ein Ereignis auf einem Namen, den kein Schritt des
Graphen erzeugt, legt keine Zustandszeile an, sondern einen benannten Befund
(`src/ohpipe/application/replay.py::replay`). Für **vier** Ereignisarten ist
das gemessen und grün.

`record.disabled` ist die fünfte, und sie wird **vor** der Namensprüfung
behandelt — der Zweig steht früher im Fold als die Prüfung auf
Graphzugehörigkeit. Sein ``artifact``-Feld prüft damit gar nichts, während
seine Wirkung die grösste im System ist: der ganze Record verschwindet aus
jeder Auswertung.

**Dieser Marker bleibt während der ganzen Scheibe C rot.** Er gehört in
dieselbe Familie wie die zwei Dauerbefunde D1 und D2 und wird mit ihnen
zusammen in einer späteren Replay-Härtung repariert, nicht hier. Wer ihn beim
Bau von C grün werden sieht, hat etwas anderes gebaut als C —
`docs/PLAN_SCHEIBE-C.md`, Abschnitt 2.

Die Autorität muss echt sein, nicht behauptet: ein Ausschluss aus einer
unauthentifizierten Kette wäre ohnehin ``provisional`` (ADR 0017) und
verschwände aus einem Grund, der mit dem Geltungsbereich nichts zu tun hat.
Der Marker wäre dann grün, während die Sache kaputt ist.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ._forge import cli_keyed, forge_keyed, place_object

#: Ein Name, den kein Schritt des Graphen erzeugt — von Hand, nicht abgeleitet.
FREMD = "erfunden.artefakt"

#: Der Halbsatz, den Scheibe A für genau diesen Fall eingeführt hat. Gepinnt
#: wie ``GRAPHBEFUND``: ein Marker, der irgendeinen Befund akzeptierte, wäre
#: auch von einer fremden Meldung erfüllt.
GRAPHBEFUND = "kein Schritt des Graphen erzeugt"


@pytest.fixture
def authentifiziert(tmp_path: Path):
    schluessel = tmp_path / "journal.key"
    schluessel.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "keyed-data"

    def lauf(*args: str):
        return cli_keyed(*args, root=wurzel, key=schluessel)

    assert lauf("init").returncode == 0
    return wurzel, schluessel, lauf


def _ausschluss(artefakt: str, sha: str) -> dict:
    return {
        "kind": "record.disabled",
        "payload": {
            "artifact": artefakt,
            "subject_sha256": sha,
            "verdict": "WITHDRAW",
            "reference": f"PI-{artefakt}",
            "actor": "kbs",
            "at": "2026-09-01T09:00:00+00:00",
        },
    }


def _record(lauf) -> dict:
    return json.loads(lauf("status", "--json").stdout)["details"]["records"][0]


def test_record_disabled_on_a_graph_artifact_still_excludes(authentifiziert):
    """Gegenprobe: auf einem echten Artefaktnamen bleibt der Ausschluss wirksam.

    Ohne sie wäre der Marker darunter auch dann eingelöst, wenn jemand
    ``record.disabled`` schlicht nicht mehr auswertete. Dann verschwände mit
    dem ungeprüften Weg auch der geprüfte, und ein Interview liesse sich gar
    nicht mehr aus dem Betrieb nehmen.
    """
    wurzel, schluessel, lauf = authentifiziert
    sha = place_object(wurzel, b"eine Transkriptfassung")
    forge_keyed(
        wurzel,
        schluessel,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "transcript.revision", "sha256": sha},
            },
            _ausschluss("transcript.revision", sha),
        ],
    )
    rec = _record(lauf)
    assert rec["status"] == "EXCLUDED", rec["status"]


def test_record_disabled_on_a_name_no_step_produces_does_not_exclude(authentifiziert):
    """Ein Ausschluss auf einem erfundenen Namen nimmt keinen Record aus dem Betrieb.

    Gemessen, heute — eine authentifizierte Kette mit genau einem
    ``record.disabled`` auf ``erfunden.artefakt``: der Record steht auf
    ``status = EXCLUDED``, seine Artefaktliste ist **leer**, und es gibt
    **keinen** Befund. Für dieselbe Nutzlast
    unter ``artifact.produced``, ``receipt.recorded``, ``decision.recorded``
    oder ``anchor.checked`` meldet Scheibe A dagegen den Graphbefund.

    Die Wirkung ist die grösste im System: ein ausgeschlossener Record
    verschwindet aus jeder Auswertung. Ausgerechnet dort prüft das
    ``artifact``-Feld nichts.

    **Warum die Zielassertion den Befund verlangt und nicht den Recordstatus.**
    Beide Reparaturen sind denkbar — den Ausschluss verweigern oder ihn
    weiterhin zulassen und einen Befund schreiben. Eine Zusicherung auf
    ``status`` legte den Weg fest, bevor er entschieden ist; eine auf den
    benannten Befund hält in beiden Fällen. Dieselbe Lehre wie aus der
    Kollision, wegen der Scheibe A neu ausgegeben werden musste.
    """
    wurzel, schluessel, lauf = authentifiziert
    sha = place_object(wurzel, b"Bytes, damit keine Referenz ins Leere zeigt")
    forge_keyed(wurzel, schluessel, [_ausschluss(FREMD, sha)])

    rec = _record(lauf)

    assert rec["status"] != "EXCLUDED", "Ein unbekannter Name darf nicht ausschließen"
    assert any(GRAPHBEFUND in b for b in rec["findings"]), (
        f"record.disabled auf {FREMD!r} hinterlaesst keinen Graphbefund. "
        f"Recordstatus={rec['status']!r}, Artefakte={sorted(rec['artifacts'])}, "
        f"findings={rec['findings']!r}"
    )
