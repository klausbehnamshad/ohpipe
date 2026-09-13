"""Testumgebung gegen die Entwickler-Shell abschirmen.

src/ohpipe/journal.py::load_key liest den Journalschluessel aus
$OHPIPE_JOURNAL_KEY, src/ohpipe/project.py::Workspace.resolve die Datenwurzel
aus $OHPIPE_DATA_ROOT. Sind diese in der Shell gesetzt, laufen in-Prozess
gefahrene Tests gegen eine andere Umgebung als CI. Konkret: bei gesetztem
OHPIPE_JOURNAL_KEY baut src/ohpipe/cli/main.py::_journal_or_stop das Journal mit
Schluessel, die in-Prozess-CLI verifiziert also per HMAC, waehrend
In-Prozess-Helfer wie tests/test_b3b_ux.py::_prepare_confirmation es keyless
schreiben; src/ohpipe/journal.py::Journal.verify bricht dann bei seq=1 mit
STOP_JOURNAL_BROKEN, der Report traegt kein 'preview', und
tests/test_b3b_ux.py::_invoke faellt am KeyError. Tests, die Schluessel oder
Wurzel brauchen, setzen sie selbst in einer sauberen Subprozessumgebung
(tests/_forge.py::cli). Darum beide ambienten Variablen je Test entfernen:
deterministisch gegen CI.

Zeilennummern stehen hier bewusst nicht mehr: docs/ROADMAP.md § 13 Regel 7
verlangt pfad::symbol, und eine Nummer ueberlebt keinen Einschub.
"""
import pytest


@pytest.fixture(autouse=True)
def _abschirmung_umgebung(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OHPIPE_JOURNAL_KEY", raising=False)
    monkeypatch.delenv("OHPIPE_DATA_ROOT", raising=False)
