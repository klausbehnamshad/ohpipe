"""Kein Zustand ohne Ausweg — geprüft an jeder Stelle, die einen Bericht baut.

B9 verlangt: *Jeder nichtterminale Zustand besitzt einen konkreten
Auflösungsweg.* Mit dem Sechszeiler (E6) heißt das mechanisch: Ein Bericht, der
nicht ``READY`` meldet, trägt **mindestens eines** von ``NEXT``, ``CHECK``,
``RECOVERY``. Ein Halt, den niemand auflösen kann, erzieht dazu, Halte zu
umgehen — das ist die teuerste Art von Vertragslücke, weil sie nicht auffällt.

**Warum über den Quelltext und nicht über die Laufzeit.** Es gibt heute keine
Aufzählung der ``reason_code``-Werte: zwanzig verschiedene stehen als
Zeichenketten an achtundzwanzig Stellen. Eine Testschleife „über die
``reason_code``-Menge" hätte deshalb nur eine handgepflegte Liste sein können —
und eine handgepflegte Liste übersieht genau den Fall, der neu dazukommt. Der
Syntaxbaum kennt dagegen jede Konstruktion, auch die von morgen.

**Die Datei prüft sich zuerst selbst.** Ein Prüfer, der nichts findet, weil er
nichts sieht, ist schlimmer als keiner: Er meldet Grün. Deshalb steht vor der
Zielassertion die Zusicherung, dass der Sucher überhaupt Berichte findet, dass
er einen künstlich eingebauten Verstoß erkennt und dass er einen künstlich
eingebauten Ausweg **nicht** als Verstoß meldet.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

QUELLE = Path(__file__).resolve().parents[1] / "src" / "ohpipe"

#: Die drei Felder des Sechszeilers, die einen Ausweg tragen können. ``NEXT``
#: und ``RECOVERY`` schließen sich gegenseitig aus (``Report.__post_init__``);
#: ``CHECK`` ist unabhängig von beiden.
AUSWEGFELDER = ("next_command", "check", "recovery_code")

#: ``READY`` ist der einzige terminale Zustand — es gibt nichts aufzulösen.
#: Ausdrücklich benannt, nicht stillschweigend übersprungen. Alle anderen
#: Zustände, auch die zur Laufzeit berechneten, brauchen einen Ausweg.
TERMINAL = ("Status.READY",)


class _Fund:
    __slots__ = ("datei", "zeile", "status", "auswege")

    def __init__(self, datei: str, zeile: int, status: str, auswege: list[str]) -> None:
        self.datei, self.zeile, self.status, self.auswege = datei, zeile, status, auswege

    def __repr__(self) -> str:  # pragma: no cover - nur für die Fehlermeldung
        return f"{self.datei}:{self.zeile} status={self.status} auswege={self.auswege}"


def _berichte(baum: ast.AST, datei: str) -> list[_Fund]:
    """Jede ``Report(...)``-Konstruktion mit Status und gesetzten Auswegfeldern."""
    gefunden: list[_Fund] = []
    for knoten in ast.walk(baum):
        if not (isinstance(knoten, ast.Call) and getattr(knoten.func, "id", None) == "Report"):
            continue
        if knoten.args or any(k.arg is None for k in knoten.keywords):
            # Positionsargumente oder `**kwargs` machen die Zuordnung unsicher.
            # Der Sucher rät hier nicht — er meldet den Fall als Fund ohne
            # Ausweg, damit er auffällt, statt still durchzurutschen.
            gefunden.append(_Fund(datei, knoten.lineno, "UNBESTIMMT", []))
            continue
        felder = {k.arg: k.value for k in knoten.keywords}
        status = ast.unparse(felder["status"]) if "status" in felder else "UNBESTIMMT"
        auswege = [f for f in AUSWEGFELDER if f in felder]
        gefunden.append(_Fund(datei, knoten.lineno, status, auswege))
    return gefunden


def _alle_berichte() -> list[_Fund]:
    alle: list[_Fund] = []
    for pfad in sorted(QUELLE.rglob("*.py")):
        alle += _berichte(
            ast.parse(pfad.read_text(encoding="utf-8")), str(pfad.relative_to(QUELLE))
        )
    return alle


def _ohne_ausweg(funde: list[_Fund]) -> list[_Fund]:
    return [f for f in funde if f.status not in TERMINAL and not f.auswege]


# ------------------------------------------------- der Sucher prüft sich selbst


def test_the_scanner_finds_the_report_constructions_at_all():
    """Ohne diese Zusicherung wäre die Zielassertion nach jeder Umbenennung grün.

    Die Zahl ist eine untere Schranke und kein Halt: Sie soll wachsen dürfen,
    ohne dass jemand hier nachpflegt — aber nicht auf null fallen, ohne dass es
    auffällt.
    """
    funde = _alle_berichte()
    assert len(funde) >= 30, f"nur {len(funde)} Report-Konstruktionen gefunden"
    assert {f.datei for f in funde} >= {"cli/main.py", "policies/gates.py"}, {
        f.datei for f in funde
    }


def test_the_scanner_flags_a_report_without_an_exit():
    quelle = "Report(status=Status.STOP, reason='x', reason_code='STOP_X')"
    funde = _berichte(ast.parse(quelle), "kunstgriff.py")
    assert _ohne_ausweg(funde) != [], funde


@pytest.mark.parametrize("feld", AUSWEGFELDER)
def test_the_scanner_accepts_a_report_with_any_one_exit(feld):
    quelle = f"Report(status=Status.STOP, reason='x', {feld}='y')"
    funde = _berichte(ast.parse(quelle), "kunstgriff.py")
    assert _ohne_ausweg(funde) == [], funde


def test_the_scanner_treats_ready_as_terminal():
    quelle = "Report(status=Status.READY, reason='fertig')"
    funde = _berichte(ast.parse(quelle), "kunstgriff.py")
    assert _ohne_ausweg(funde) == [], funde


def test_the_scanner_does_not_guess_at_positional_arguments():
    """Ein Bericht mit Positionsargumenten wird gemeldet, nicht ausgelegt."""
    quelle = "Report(Status.STOP, 'x')"
    funde = _berichte(ast.parse(quelle), "kunstgriff.py")
    assert _ohne_ausweg(funde) != [], funde


# ------------------------------------------------------------ die Zielassertion


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="B9 — drei Berichte ohne Ausweg, gemessen auf baseline-adr0027: "
    "cli/main.py STOP_LEDGER_INVALID, STOP_OWNERSHIP, ACTION_INTERRUPTED. "
    "Marker fällt, sobald die drei einen NEXT, CHECK oder RECOVERY tragen.",
)
def test_every_non_terminal_report_offers_a_way_out():
    ohne = _ohne_ausweg(_alle_berichte())
    assert ohne == [], "Berichte ohne NEXT, CHECK und RECOVERY: " + "; ".join(map(repr, ohne))


def test_the_known_gap_is_exactly_these_three():
    """Der heutige Befund, festgenagelt — damit die Lücke nicht **wächst**.

    Der ``xfail`` oben sagt nur „nicht null". Er bliebe auch bei zehn Lücken
    erwartet-rot. Diese Zusicherung ist die Gegenrichtung: Eine vierte Stelle
    ohne Ausweg macht die Suite sofort rot, und zwar an einer Zeile, die den
    Grund nennt.

    Die Liste steht AUSGESCHRIEBEN und wird nicht aus dem Code abgeleitet —
    sonst prüfte sie den Code gegen sich selbst.
    """
    bekannt = {
        ("cli/main.py", "Status.STOP"),
        ("cli/main.py", "Status.ACTION_NEEDED"),
    }
    ohne = _ohne_ausweg(_alle_berichte())
    assert len(ohne) == 3, "; ".join(map(repr, ohne))
    assert {(f.datei, f.status) for f in ohne} == bekannt, "; ".join(map(repr, ohne))
