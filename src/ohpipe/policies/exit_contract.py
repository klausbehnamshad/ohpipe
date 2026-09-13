"""Der Exitcode-Vertrag und der Sechszeiler.

Übernommen aus DINOH (ROADMAP v3, §2). Der Grund, warum das nicht optional ist:
dort landeten ein Namensfund und ein fehlendes Pflichtfeld beide auf Exit 1 —
ununterscheidbar. Ein `continue`, das automatisch weiterlaufen soll, muss
"Mensch ist dran" von "Sicherheitsventil hat ausgelöst" trennen können.
Diese Unterscheidung IST seine Existenzberechtigung.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, TextIO

__all__ = ["STATUS_EXIT", "Exit", "Report", "Status"]


class Exit(int, Enum):
    READY = 0
    STOP = 1
    CONFIG = 2
    ACTION_NEEDED = 3


class Status(str, Enum):
    """Sichtbarer Workflowstatus. Wird berechnet, nie gespeichert (ADR 003)."""

    READY = "READY"
    ACTION_NEEDED = "ACTION_NEEDED"
    STALE = "STALE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    EXCLUDED = "EXCLUDED"
    GRAPH_CONTRACT_UNBOUND = "GRAPH_CONTRACT_UNBOUND"
    GRAPH_CONTRACT_MISMATCH = "GRAPH_CONTRACT_MISMATCH"
    STOP = "STOP"
    CONFIG = "CONFIG"


#: Nur READY ist grün. Alles Erwartbare ist gelb (3). Nur Ventile sind rot (1).
STATUS_EXIT: dict[Status, Exit] = {
    Status.READY: Exit.READY,
    Status.ACTION_NEEDED: Exit.ACTION_NEEDED,
    Status.STALE: Exit.ACTION_NEEDED,
    Status.REVIEW_REQUIRED: Exit.ACTION_NEEDED,
    Status.EXCLUDED: Exit.ACTION_NEEDED,
    Status.GRAPH_CONTRACT_UNBOUND: Exit.ACTION_NEEDED,
    Status.GRAPH_CONTRACT_MISMATCH: Exit.ACTION_NEEDED,
    Status.STOP: Exit.STOP,
    Status.CONFIG: Exit.CONFIG,
}

_COLOR = {
    Status.READY: "\033[32m",
    Status.ACTION_NEEDED: "\033[33m",
    Status.STALE: "\033[33m",
    Status.REVIEW_REQUIRED: "\033[33m",
    Status.EXCLUDED: "\033[33m",
    Status.GRAPH_CONTRACT_UNBOUND: "\033[33m",
    Status.GRAPH_CONTRACT_MISMATCH: "\033[33m",
    Status.STOP: "\033[31m",
    Status.CONFIG: "\033[31m",
}
_RESET = "\033[0m"


@dataclass
class Report:
    """Das Ergebnis genau eines Operator-Befehls.

    Der Sechszeiler ist verbindlich (STATUS/CHANGED/SAFE/NEXT/CHECK/RECOVERY,
    in dieser Reihenfolge, alle immer). Er beantwortet, was ein Operator nach
    jedem Befehl braucht: Stand, Änderung, Quellsicherheit, den einen sicheren
    nächsten Befehl, die read-only-Diagnose und — für bewusst nicht automatisch
    reparierte Zustände — den benannten manuellen Wiederherstellungsweg.
    """

    status: Status
    reason: str = ""
    reason_code: str = ""
    #: Konkret veränderte Pfade. Leer heißt: nichts geschrieben. Das ist eine
    #: Zusage, kein Hinweis — `check` und `status` müssen hier leer bleiben.
    changed: list[str] = field(default_factory=list)
    #: GENAU EIN ausführbarer nächster Befehl. Keine Ellipsen, keine Auswahl.
    next_command: str | None = None
    #: Read-only-Diagnosebefehl (genau einer) oder None. Unabhängig von NEXT;
    #: darf den ursprünglichen Diagnosebefehl nennen — er läuft NACH ihm.
    check: str | None = None
    #: Manuelle Wiederherstellung für bewusst NICHT automatisch reparierte
    #: Zustände (beschädigter Store, gebrochene Journalintegrität). Code (stabile
    #: Identität) und Text (kanonischer Wortlaut) sind gemeinsam gesetzt oder
    #: gemeinsam None; höchstens eines von NEXT und Recovery ist gesetzt;
    #: Recovery ist NIE ein ausführbarer Befehl.
    recovery_code: str | None = None
    recovery_text: str | None = None
    upload_safe: bool = False
    #: Wurden QUELLDATEN angefasst? Eigenes Feld, nicht aus ``changed``
    #: abgeleitet. ``init`` legt Governance-Verzeichnisse an und meldete
    #: deshalb „Quelldaten verändert" — an Quelldaten war nichts. Der README
    #: bewirbt diese Zeile als Zusage; ein Operator, der nach `init` das liest,
    #: lernt in genau der falschen Richtung.
    source_data_touched: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        has_code = self.recovery_code is not None
        has_text = self.recovery_text is not None
        if has_code != has_text:
            raise ValueError(
                "recovery_code und recovery_text sind ein untrennbares Paar — "
                "beide oder keines (recovery)."
            )
        if has_code and self.next_command is not None:
            raise ValueError(
                "NEXT und Recovery schließen sich aus — höchstens eines ist gesetzt (recovery)."
            )
        # Kein Feldwert darf den festen Sechszeiler heimlich um eine Zeile
        # erweitern. `str.splitlines()` erkennt CR, LF, CRLF, VT, FF, FS/GS/RS,
        # NEL (U+0085) sowie U+2028/U+2029 — das Argument gilt für JEDES der vier
        # Textfelder, nicht nur für Recovery.
        for feld, wert in (
            ("next_command", self.next_command),
            ("check", self.check),
            ("recovery_code", self.recovery_code),
            ("recovery_text", self.recovery_text),
        ):
            if wert and wert.splitlines() != [wert]:
                raise ValueError(f"{feld}: eingebetteter Zeilenumbruch verboten (Zeilenumbruch).")
        # CHECK ist GENAU EIN read-only-Befehl: keine Verkettung, shlex-parsebar.
        # Ein `#`-Kommentar bleibt erlaubt (dieselbe Konvention wie bei NEXT).
        if self.check is not None:
            if any(z in self.check for z in (";", "|", "&")):
                raise ValueError("check: genau ein Befehl — keine Verkettung mit ; | & (check).")
            try:
                shlex.split(re.split(r"\s{2,}#", self.check, maxsplit=1)[0])
            except ValueError as exc:
                raise ValueError(f"check: nicht shlex-parsebar (check): {exc}") from exc

    @property
    def exit_code(self) -> int:
        return int(STATUS_EXIT[self.status])

    def to_json(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "reason": self.reason,
            "reason_code": self.reason_code,
            "changed": list(self.changed),
            "next": self.next_command,
            "check": self.check,
            "recovery_code": self.recovery_code,
            "recovery_text": self.recovery_text,
            "upload_safe": self.upload_safe,
            "source_data_touched": self.source_data_touched,
            "details": self.details,
        }

    def render(self, stream: TextIO | None = None, color: bool | None = None) -> None:
        stream = stream or sys.stdout
        english = (
            os.environ.get("OHPIPE_UI_LANG", "de")
            .strip()
            .lower()
            .replace("_", "-")
            .startswith("en")
        )
        if color is None:
            color = stream.isatty()
        head = self.status.value
        if color:
            head = f"{_COLOR[self.status]}{head}{_RESET}"
        changed = ", ".join(self.changed) if self.changed else ("none" if english else "keine")
        if english:
            safe = "Source data changed" if self.source_data_touched else "Source data unchanged"
            safe += f"; Upload {'yes' if self.upload_safe else 'no'}"
        else:
            safe = "Quelldaten verändert" if self.source_data_touched else "Quelldaten unverändert"
            safe += f"; Upload {'ja' if self.upload_safe else 'nein'}"
        recovery = (
            f"{self.recovery_code} — {self.recovery_text}"
            if self.recovery_code is not None
            else "—"
        )
        lines = [
            f"STATUS : {head}" + (f"  — {self.reason}" if self.reason else ""),
            f"CHANGED: {changed}",
            f"SAFE   : {safe}",
            f"NEXT   : {self.next_command or '—'}",
            f"CHECK  : {self.check or '—'}",
            f"RECOVERY: {recovery}",
        ]
        print("\n".join(lines), file=stream)

    def emit(self, as_json: bool = False, stream: TextIO | None = None) -> int:
        stream = stream or sys.stdout
        if as_json:
            print(json.dumps(self.to_json(), ensure_ascii=False, indent=2), file=stream)
        else:
            self.render(stream)
        return self.exit_code
