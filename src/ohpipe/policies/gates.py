"""Gates sind konjunktiv.

Herkunft: ``test_corsia.sh:165`` — „gültiges Corsia-GATE überstimmt den
Namensscan nicht". Ein bestandenes Gate ist keine Vollmacht. Gates addieren
sich nicht zu einer Erlaubnis, sie multiplizieren sich zu einer Bedingung:
**alle** müssen bestehen, und ein einzelnes Nein ist abschließend.

Das ist der Unterschied zwischen „wir haben eine Freigabe" und „nichts spricht
dagegen". Nur das Zweite trägt.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .exit_contract import Report, Status

__all__ = ["GateResult", "evaluate"]


@dataclass(frozen=True)
class GateResult:
    name: str
    status: Status
    reason: str = ""
    reason_code: str = ""

    @property
    def passed(self) -> bool:
        return self.status is Status.READY


def evaluate(results: Sequence[GateResult], *, next_command: str | None = None) -> Report:
    """Fasst Gate-Ergebnisse zusammen. Das schlechteste Ergebnis gewinnt.

    Rangfolge: STOP schlägt CONFIG schlägt jeden erwartbaren Halt schlägt READY.
    Ein bestandenes Gate kann ein nicht bestandenes nicht aufheben — dafür gibt
    es keinen Parameter und keinen Aufrufweg.
    """
    if not results:
        # Kein Gate ausgewertet heißt nicht "alles frei".
        return Report(
            status=Status.STOP,
            reason="Keine Gates ausgewertet — fail-closed",
            reason_code="STOP_NO_GATES",
            next_command=next_command,
        )

    order = [
        Status.STOP,
        Status.CONFIG,
        Status.REVIEW_REQUIRED,
        Status.STALE,
        Status.EXCLUDED,
        Status.ACTION_NEEDED,
        Status.READY,
    ]
    worst = min(results, key=lambda r: order.index(r.status))

    if worst.passed:
        return Report(
            status=Status.READY,
            reason=f"{len(results)} Gate(s) bestanden",
            next_command=next_command,
            details={"gates": [g.name for g in results]},
        )

    failed = [g for g in results if not g.passed]
    return Report(
        status=worst.status,
        reason=f"{worst.name}: {worst.reason}",
        reason_code=worst.reason_code,
        next_command=next_command,
        details={
            "failed": [
                {
                    "name": g.name,
                    "status": g.status.value,
                    "reason": g.reason,
                    "reason_code": g.reason_code,
                }
                for g in failed
            ],
            "passed": [g.name for g in results if g.passed],
        },
    )
