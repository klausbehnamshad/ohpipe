"""Kanonischer transcript.confirmed-Marker und seine Decision."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .operation import canonical_json_bytes
from .token import validate_token

__all__ = ["ConfirmationDecision", "ConfirmationMarker", "TextConfirmationMarker"]


@dataclass(frozen=True)
class ConfirmationMarker:
    record_id: str
    projection_version: str
    revision_sha256: str

    def object(self) -> dict[str, Any]:
        return {
            "artifact_key": {
                "scope": "record",
                "scope_id": self.record_id,
                "kind": "transcript.confirmed",
                "instance_id": None,
            },
            "domain": "transcript_confirmation",
            "projection_version": self.projection_version,
            "revision_sha256": self.revision_sha256,
            "v": 1,
        }

    @property
    def bytes(self) -> bytes:
        return canonical_json_bytes(self.object())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.bytes).hexdigest()


@dataclass(frozen=True)
class ConfirmationDecision:
    marker: ConfirmationMarker
    actor: str
    fulltext_origin: str
    fulltext_receipt: str
    iso6393_release: str
    iso6393_vocabulary_sha256: str
    iso6393_snapshot_receipt: str
    activation_id: str
    at: str
    profile_id: str | None = None
    graph_sha256: str | None = None

    @classmethod
    def create(
        cls,
        *,
        marker: ConfirmationMarker,
        actor: str,
        fulltext_origin: str,
        fulltext_receipt: str,
        iso6393_release: str,
        iso6393_vocabulary_sha256: str,
        iso6393_snapshot_receipt: str,
        profile_id: str | None = None,
        graph_sha256: str | None = None,
    ) -> ConfirmationDecision:
        return cls(
            marker=marker,
            profile_id=profile_id,
            graph_sha256=graph_sha256,
            actor=validate_token(actor, field="actor"),
            fulltext_origin=fulltext_origin,
            fulltext_receipt=fulltext_receipt,
            iso6393_release=iso6393_release,
            iso6393_vocabulary_sha256=iso6393_vocabulary_sha256,
            iso6393_snapshot_receipt=iso6393_snapshot_receipt,
            activation_id=secrets.token_hex(32),
            at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    def object_without_id(self) -> dict[str, Any]:
        return {
            "domain": "transcript_confirmation_decision",
            "v": 2 if self.profile_id is not None else 1,
            **(
                {"profile_id": self.profile_id, "graph_sha256": self.graph_sha256}
                if self.profile_id is not None
                else {}
            ),
            "record_id": self.marker.record_id,
            "artifact": "transcript.confirmed",
            "subject_sha256": self.marker.sha256,
            "verdict": "ACCEPT",
            "reference": self.marker.sha256,
            "activation_id": self.activation_id,
            "actor": self.actor,
            "at": self.at,
            "note": "",
            "reason_code": "",
            "input_refs": {"transcript": self.marker.revision_sha256},
            "source": "mensch",
            "fulltext_origin": self.fulltext_origin,
            "fulltext_receipt": self.fulltext_receipt,
            "iso6393_release": self.iso6393_release,
            "iso6393_vocabulary_sha256": self.iso6393_vocabulary_sha256,
            "iso6393_snapshot_receipt": self.iso6393_snapshot_receipt,
        }

    @property
    def decision_id(self) -> str:
        return hashlib.sha256(canonical_json_bytes(self.object_without_id())).hexdigest()

    def object(self) -> dict[str, Any]:
        return {**self.object_without_id(), "decision_id": self.decision_id}


@dataclass(frozen=True)
class TextConfirmationMarker:
    """V2 für deklarierte Textgates; definiert keinen Pseudonymisierungswriter."""

    record_id: str
    gate_artifact: str
    text_artifact: str
    revision_sha256: str
    projection_version: str
    profile_id: str
    graph_sha256: str

    def object(self):
        return {
            "domain": "text_confirmation",
            "v": 2,
            "record_id": self.record_id,
            "gate_artifact": self.gate_artifact,
            "text_artifact": self.text_artifact,
            "revision_sha256": self.revision_sha256,
            "projection_version": self.projection_version,
            "profile_id": self.profile_id,
            "graph_sha256": self.graph_sha256,
        }

    @property
    def bytes(self):
        return canonical_json_bytes(self.object())

    @property
    def sha256(self):
        return hashlib.sha256(self.bytes).hexdigest()
