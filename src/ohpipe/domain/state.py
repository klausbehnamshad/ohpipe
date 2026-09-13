"""Die drei unabhängigen Zustände und der daraus berechnete Workflowstatus.

Kernentscheidung (ADR 003): ``READY`` wird BERECHNET, nie gespeichert. Ein
gespeicherter Workflowstatus ist ein Zustandsautomat, der repariert werden
muss — und im Vorgängerprojekt genau das getan hat.

Die drei Achsen sind unabhängig, weil sie verschiedene Fragen beantworten:

    source_binding    Gehören Transkript, Lauf und Annotationen noch zusammen?
    derivation_state  Sind die deklarierten Eingaben der Ableitung unverändert?
    decision_state    Hat ein Mensch GENAU DIESE Bytes verantwortet?

Die zweite und dritte Achse zu vermischen war der Fehler, den ein Review im
Vorgängerprojekt gefunden hat: ein Record war technisch aktuell, inhaltlich nie
akzeptiert — und wäre beim nächsten Build veröffentlicht worden.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..policies.exit_contract import Status

__all__ = [
    "ArtifactState",
    "DecisionState",
    "DerivationState",
    "LegacyDisposition",
    "SourceBinding",
]


class SourceBinding(str, Enum):
    BOUND = "bound"  # alle Anker sitzen auf der aktuellen Transkriptfassung
    DRIFTED = "drifted"  # mindestens ein Anker braucht menschliche Klärung
    UNKNOWN = "unknown"  # keine Bindung feststellbar -> fail-closed
    NOT_APPLICABLE = "not_applicable"  # der Vertrag verlangt keine Bindung


class DerivationState(str, Enum):
    CURRENT = "current"  # deklarierte Eingaben unverändert (Receipt passt)
    STALE = "stale"  # Eingaben haben sich geändert
    UNVERIFIABLE = "unverifiable"  # kein Beleg vorhanden -> fail-closed
    NOT_APPLICABLE = "not_applicable"  # rein menschliches Artefakt


class DecisionState(str, Enum):
    ACCEPTED = "accepted"  # Beleg auf genau diese Bytes
    REJECTED = "rejected"
    WITHDRAWN = "withdrawn"
    UNDECIDED = "undecided"
    NOT_APPLICABLE = "not_applicable"  # der Vertrag verlangt keine Entscheidung


class LegacyDisposition(str, Enum):
    """Was operativ gilt — unabhängig davon, was die heutige Regel sagt.

    Aus DINOH übernommen: ein Altlauf unter der heutigen Schwelle wird nicht
    rückwirkend hingerichtet. Er bleibt lesbar, trägt einen Caveat und ist für
    interviewübergreifende Aussagen gesperrt.
    """

    OK = "ok"
    LEGACY_BELOW_CURRENT_THRESHOLD = "legacy_below_current_threshold"
    EXCLUDED = "excluded"


@dataclass(frozen=True)
class ArtifactState:
    source_binding: SourceBinding
    derivation_state: DerivationState
    decision_state: DecisionState
    enabled: bool = True
    disposition: LegacyDisposition = LegacyDisposition.OK
    harness_era: str = "current"
    reason: str = ""

    @property
    def cross_record_claims_allowed(self) -> bool:
        return self.disposition is LegacyDisposition.OK

    @property
    def status(self) -> Status:
        """Die einzige Stelle, an der ein sichtbarer Status entsteht.

        Reihenfolge ist normativ: Ventile vor Erwartbarem, Erwartbares vor
        Grün. Ein nicht abgedeckter Fall fällt auf STOP, nicht auf READY.
        """
        if not self.enabled or self.disposition is LegacyDisposition.EXCLUDED:
            return Status.EXCLUDED

        # Fail-closed: Was wir nicht feststellen können, ist kein "wahrscheinlich ok".
        if self.source_binding is SourceBinding.UNKNOWN:
            return Status.STOP
        if self.derivation_state is DerivationState.UNVERIFIABLE:
            return Status.STOP

        if self.decision_state in (DecisionState.REJECTED, DecisionState.WITHDRAWN):
            return Status.EXCLUDED

        # Ankerdrift schlägt Staleness: erst muss geklärt sein, worauf sich die
        # Annotation überhaupt bezieht, bevor ihre Aktualität eine Frage ist.
        if self.source_binding is SourceBinding.DRIFTED:
            return Status.REVIEW_REQUIRED

        if self.derivation_state is DerivationState.STALE:
            return Status.STALE

        if self.decision_state is DecisionState.UNDECIDED:
            return Status.ACTION_NEEDED

        if (
            self.source_binding in (SourceBinding.BOUND, SourceBinding.NOT_APPLICABLE)
            and self.derivation_state in (DerivationState.CURRENT, DerivationState.NOT_APPLICABLE)
            and self.decision_state in (DecisionState.ACCEPTED, DecisionState.NOT_APPLICABLE)
        ):
            return Status.READY

        return Status.STOP  # unerreichbar bei vollständiger Abdeckung — absichtlich rot

    @property
    def explanation(self) -> str:
        s = self.status
        if self.reason and s is not Status.READY:
            return self.reason
        if s is Status.READY:
            teile: list[str] = []
            if self.source_binding is SourceBinding.BOUND:
                teile.append("aktuell gebunden")
            if self.derivation_state is DerivationState.CURRENT:
                teile.append("Eingaben unverändert")
            if self.decision_state is DecisionState.ACCEPTED:
                teile.append("von einem Menschen verantwortet")
            if not teile:
                return (
                    "keine Bindung, kein Ableitungsbeleg und keine menschliche "
                    "Entscheidung erforderlich"
                )
            return ", ".join(teile)
        if s is Status.EXCLUDED:
            if not self.enabled:
                return "bewusst deaktiviert"
            if self.decision_state is DecisionState.REJECTED:
                return "verworfen"
            if self.decision_state is DecisionState.WITHDRAWN:
                return "zurückgezogen"
            return "aus dem Betrieb genommen"
        if s is Status.REVIEW_REQUIRED:
            return "Ankerdrift: Annotationen zeigen nicht mehr eindeutig auf den Text"
        if s is Status.STALE:
            return "Eingaben der Ableitung haben sich geändert"
        if s is Status.ACTION_NEEDED:
            return "keine menschliche Entscheidung zu genau diesen Bytes"
        if self.source_binding is SourceBinding.UNKNOWN:
            return "Bindung an eine Transkriptfassung nicht feststellbar"
        if self.derivation_state is DerivationState.UNVERIFIABLE:
            return "kein Beleg für die Ableitung vorhanden"
        return self.reason or "nicht abgedeckter Zustand"

    def to_json(self) -> dict[str, Any]:
        return {
            "source_binding": self.source_binding.value,
            "derivation_state": self.derivation_state.value,
            "decision_state": self.decision_state.value,
            "enabled": self.enabled,
            "disposition": self.disposition.value,
            "harness_era": self.harness_era,
            "status": self.status.value,
            "explanation": self.explanation,
            "cross_record_claims_allowed": self.cross_record_claims_allowed,
        }
