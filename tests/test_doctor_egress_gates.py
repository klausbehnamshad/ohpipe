"""Die Egressinvariante im Betrieb, nicht nur im Build.

``src/ohpipe/domain/step.py::check_egress_gates`` steht seit ADR 0013 als
pruefbare Funktion da und war gruen — gerufen aber nur von Tests. Das ist
dieselbe Klasse wie A-1 (``build_graph`` gebaut, nicht angeschlossen): eine
Zusicherung, die der laufende Arbeitsbereich nie erfaehrt, ist eine Zusicherung
ueber ein anderes Objekt. Am Ausgang ist das die teuerste Variante davon, weil
genau dort Modellausgaben das System verlassen.

``doctor`` ist die richtige Stelle: read-only, vom Operator jederzeit aufrufbar,
und im Vorfuehrskript der Punkt, an dem man die Aussage zeigen kann. Geprueft
wird der PROFILGEBUNDENE Graph, nicht die Modulkonstante.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ohpipe.cli import main as cli_main
from ohpipe.cli.main import build_parser

from ._forge import cli


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "data"
    assert cli("init", root=r).returncode == 0
    return r


def _args(root: Path):
    return build_parser().parse_args(["--profile", "sandbox", "--root", str(root), "doctor"])


def test_doctor_reports_the_egress_gates_as_closed(root):
    """Der gruene Weg, ueber die echte CLI-Grenze: ``doctor`` sagt es.

    Nicht nur „wirft keinen Fehler": die Auskunft steht im Bericht. Ohne ein
    ausgewiesenes Feld waere die Pruefung wieder unsichtbar — nur eben zur
    Laufzeit statt im Build.
    """
    lauf = cli("doctor", "--json", root=root)
    bericht = json.loads(lauf.stdout)
    assert bericht["details"]["egress_gates"] == "geschlossen", bericht["details"]
    assert "egress_violations" not in bericht["details"], bericht["details"]


def test_doctor_stops_when_a_model_path_reaches_the_exit_without_a_gate(root, monkeypatch):
    """Der rote Weg. Ein offener Ausgang ist ein STOP, keine Randnotiz.

    Der Verstoss wird eingesetzt statt nachgebaut: ob
    ``check_egress_gates`` einen offenen Pfad FINDET, ist in
    ``tests/test_receipt_and_graph.py`` an gebauten Graphen gemessen. Hier steht
    die andere Haelfte — dass ``doctor`` das Ergebnis nicht verschluckt.
    """
    monkeypatch.setattr(
        cli_main,
        "check_egress_gates",
        lambda graph: ["export.bundle: kein human_gate zwischen l1.suggest und dem Ausgang"],
    )
    bericht = cli_main.cmd_doctor(_args(root))
    assert bericht.status.value == "STOP", bericht
    assert bericht.reason_code == "STOP_EGRESS_GATE_OPEN", bericht
    assert bericht.details["egress_gates"] == "verletzt", bericht.details
    assert bericht.details["egress_violations"], bericht.details
    # Und der Befund steht im Satz, nicht nur im Anhang.
    assert "human_gate" in bericht.reason, bericht.reason
