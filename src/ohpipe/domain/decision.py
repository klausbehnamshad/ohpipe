"""Menschliche Entscheidungen, gebunden an Bytes.

Eine Entscheidung gilt für die Fassung, die der Mensch gesehen hat — nicht für
"den Record". Ändern sich die Bytes, passt der Beleg nicht mehr, und das System
sagt Nein.

``UNDO`` ist ausdrücklich KEINE Annahme: Ein Rücknahme-Akt verschafft einer
zurückgeholten Fassung keine Legitimität, die sie nie hatte.

Alle Pflichtfelder werden bei der Konstruktion geprüft. Eine leere Entscheidung
darf nicht konstruierbar sein — sonst deckt sie den leeren Hash, und „gebunden
an Bytes" ist eine Behauptung ohne Prüfung.
"""

from __future__ import annotations

from ohpipe.domain import manual_context

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any

__all__ = ["ACCEPTING", "SHA256_RE", "Decision", "InvalidDecision", "Verdict"]

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
#: Ein Token ohne Whitespace. Herkunft: ``test_simple.sh:165`` (mehrwortige
#: Referenz -> CONFIG) und ``:169`` (Tab in der Referenz).
REFERENCE_RE = re.compile(r"^[\w.:@/+-]{3,64}$")


class InvalidDecision(ValueError):
    pass


class Verdict(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    WITHDRAW = "WITHDRAW"
    UNDO = "UNDO"


#: Nur diese Verdikte machen aus einer technischen Fassung eine verantwortete.
ACCEPTING = frozenset({Verdict.ACCEPT})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_aware_iso(value: str) -> datetime | None:
    """Ein Zeitpunkt zählt nur mit Zeitzone. Siehe receipt._parse_iso."""
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo is not None else None


@dataclass(frozen=True)
class Decision:
    record_id: str
    artifact: str
    subject_sha256: str
    verdict: Verdict
    reference: str
    actor: str
    at: str = field(default_factory=_now)
    note: str = ""
    reason_code: str = ""
    input_refs: Mapping[str, str] = field(default_factory=dict)
    input_refs_version: int = 1
    profile_id: str | None = None
    graph_sha256: str | None = None

    def __post_init__(self) -> None:
        if type(self.input_refs_version) is not int or self.input_refs_version not in (1, 2, 3, 4):
            raise InvalidDecision("Unbekannte input_refs-Version")
        roles = {"transcript"} if self.input_refs_version == 1 else {"text"}
        if not isinstance(self.input_refs, Mapping) or (
            self.input_refs_version not in (3, 4)
            and self.input_refs
            and set(self.input_refs) != roles
        ):
            raise InvalidDecision("input_refs hat nicht den deklarierten Rollensatz")
        if any(
            not isinstance(v, str) or not SHA256_RE.fullmatch(v) for v in self.input_refs.values()
        ):
            raise InvalidDecision("input_refs enthält keinen gültigen sha256")
        if self.input_refs_version == 4:
            from .p4c_events import REVIEW_INPUTS

            if (
                self.artifact != "transcript.pseudonymised.confirmed"
                or not manual_context.record(self.record_id, self.profile_id)
                or set(self.input_refs) != REVIEW_INPUTS
            ):
                raise InvalidDecision("P4c-Referenzen außerhalb ihres geschlossenen Vertrags")
        object.__setattr__(self, "input_refs", MappingProxyType(dict(self.input_refs)))
        if (self.profile_id is None) != (self.graph_sha256 is None):
            raise InvalidDecision("Profil- und Graphkontext müssen gemeinsam vorliegen")
        if self.profile_id is not None and (
            not isinstance(self.profile_id, str)
            or not self.profile_id.strip()
            or not isinstance(self.graph_sha256, str)
            or not SHA256_RE.fullmatch(self.graph_sha256)
        ):
            raise InvalidDecision("Ungültiger Profil-/Graphkontext")
        if self.input_refs_version in (2, 3, 4) and (
            not self.input_refs or self.profile_id is None
        ):
            raise InvalidDecision("input_refs v2 verlangt Textreferenz und Profil-/Graphkontext")
        if not self.record_id.strip():
            raise InvalidDecision("record_id fehlt")
        if not self.artifact.strip():
            raise InvalidDecision("artifact fehlt")
        if not SHA256_RE.match(self.subject_sha256):
            raise InvalidDecision(
                f"subject_sha256 ist kein sha256: {self.subject_sha256!r}. "
                "Eine Entscheidung ohne Bezugsbytes gibt es nicht."
            )
        if not REFERENCE_RE.match(self.reference):
            raise InvalidDecision(
                f"reference {self.reference!r} ist kein Token (3-64 Zeichen, kein Whitespace)."
            )
        if not self.actor.strip():
            raise InvalidDecision("actor fehlt — eine Entscheidung hat immer jemanden")
        if parse_aware_iso(self.at) is None:
            raise InvalidDecision(
                f"at {self.at!r} ist kein zeitzonenbehafteter ISO-8601-Zeitpunkt. "
                "Ohne Zone ist die Reihenfolge gegenüber einem Beleg nicht prüfbar."
            )

    @property
    def is_accepting(self) -> bool:
        return self.verdict in ACCEPTING

    @property
    def id(self) -> str:
        """Stabile Kennung dieser Entscheidung, an die ein Beleg binden kann."""
        return f"{self.reference}@{self.subject_sha256[:12]}"

    def covers(self, sha256: str) -> bool:
        """Deckt diese Entscheidung genau diese Bytes?"""
        if not SHA256_RE.match(sha256 or ""):
            return False
        return self.is_accepting and self.subject_sha256 == sha256

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "record_id": self.record_id,
            "artifact": self.artifact,
            "subject_sha256": self.subject_sha256,
            "verdict": self.verdict.value,
            "reference": self.reference,
            "actor": self.actor,
            "at": self.at,
            "note": self.note,
            "reason_code": self.reason_code,
            **({"input_refs": dict(self.input_refs)} if self.input_refs else {}),
            **(
                {"input_refs_version": self.input_refs_version}
                if self.input_refs_version != 1
                else {}
            ),
            **(
                {"profile_id": self.profile_id, "graph_sha256": self.graph_sha256}
                if self.profile_id is not None
                else {}
            ),
        }
