"""Kanonischer B3b-v2-RetryIntent und Matrix-A-bis-G-Klassifikation."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any
from collections.abc import Mapping

__all__ = [
    "B3B_COMMANDS",
    "EVENT_CATALOG_VERSION",
    "RETRY_INTENT_VERSION",
    "MatrixState",
    "OperationError",
    "OperationTrace",
    "RetryIntent",
    "canonical_json_bytes",
    "classify_recovery",
]

EVENT_CATALOG_VERSION = "b3b-event-catalog-v2"
RETRY_INTENT_VERSION = "b3b-operation-retry-intent-v2"
B3B_COMMANDS = frozenset(
    {
        "ingest_srt",
        "transcript_confirm",
        "transcript_fulltext_prepare",
        "transcript_language_prepare",
        "iso6393_prepare",
        "instance_register",
        "instance_retire",
    }
)
CAUSAL_PRESTATE_ROLES = {
    "ingest_srt": {
        "current_language_assignment_sha256",
        "current_language_assignment_event_digest",
        "current_revision_sha256",
        "current_revision_event_digest",
    },
    "transcript_confirm": {
        "current_revision_sha256",
        "current_revision_event_digest",
        "actor_state_sha256",
        "actor_state_event_digest",
        "current_confirmation_sha256",
        "current_confirmation_event_digest",
    },
    "transcript_fulltext_prepare": {
        "current_revision_sha256",
        "current_revision_event_digest",
        "current_fulltext_receipt_sha256",
        "current_fulltext_receipt_event_digest",
    },
    "transcript_language_prepare": {
        "current_language_assignment_sha256",
        "current_language_assignment_event_digest",
        "actor_state_sha256",
        "actor_state_event_digest",
        "iso_binding_sha256",
        "iso_binding_event_digest",
        "prepared_candidate_sha256",
        "prepared_candidate_event_digest",
    },
    "iso6393_prepare": {
        "iso_binding_sha256",
        "iso_binding_event_digest",
        "prepared_candidate_sha256",
        "prepared_candidate_event_digest",
    },
    "instance_register": {"coder_state_sha256", "coder_state_event_digest"},
    "instance_retire": {"coder_state_sha256", "coder_state_event_digest"},
}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class OperationError(ValueError):
    pass


class MatrixState(str, Enum):
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    E = "E"
    F = "F"
    G = "G"


def canonical_json_bytes(value: Any) -> bytes:
    def validate(item: Any) -> None:
        if isinstance(item, (bool, float)):
            raise OperationError("kanonische B3b-Bytes verbieten bool und float")
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                raise OperationError("Zeichenkette ist nicht NFC")
            if any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise OperationError("Zeichenkette enthaelt einen Surrogat")
        elif isinstance(item, Mapping):
            if any(not isinstance(key, str) for key in item):
                raise OperationError("Objektschluessel muessen Zeichenketten sein")
            for key, child in item.items():
                validate(key)
                validate(child)
        elif isinstance(item, (list, tuple)):
            for child in item:
                validate(child)
        elif item is not None and not isinstance(item, int):
            raise OperationError(f"nichtkanonischer Typ {type(item).__name__}")

    validate(value)
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


@dataclass(frozen=True)
class RetryIntent:
    workspace_id: str
    command: str
    target_key: dict[str, Any]
    inputs: dict[str, Any]
    store_bindings: dict[str, Any]
    causal_prestate: dict[str, Any]
    rule_versions: dict[str, str]
    idempotency_keys: dict[str, Any]
    routing_keys: dict[str, Any]
    desired_effect: dict[str, Any]
    domain: str = "b3b_operation_retry_intent"
    v: int = 2

    FIELDS = frozenset(
        {
            "domain",
            "v",
            "workspace_id",
            "command",
            "target_key",
            "inputs",
            "store_bindings",
            "causal_prestate",
            "rule_versions",
            "idempotency_keys",
            "routing_keys",
            "desired_effect",
        }
    )

    def __post_init__(self) -> None:
        if self.domain != "b3b_operation_retry_intent" or type(self.v) is not int or self.v != 2:
            raise OperationError("RetryIntent braucht domain b3b_operation_retry_intent und v 2")
        if SHA256_RE.fullmatch(self.workspace_id) is None:
            raise OperationError("workspace_id muss ein voller ASCII-Kleinhex-sha256 sein")
        if self.command not in B3B_COMMANDS:
            raise OperationError("RetryIntent.command ist nicht im geschlossenen v2-Katalog")
        required_roles = CAUSAL_PRESTATE_ROLES[self.command]
        if set(self.causal_prestate) != required_roles:
            raise OperationError("causal_prestate hat nicht den geschlossenen Rollensatz")
        if self.rule_versions.get("event_catalog") != EVENT_CATALOG_VERSION:
            raise OperationError("rule_versions.event_catalog weicht vom v2-Katalog ab")
        if self.rule_versions.get("retry_intent") != RETRY_INTENT_VERSION:
            raise OperationError("rule_versions.retry_intent weicht von v2 ab")
        if set(self.desired_effect) != {"event_sequence", "store_outputs", "system_bindings"}:
            raise OperationError("desired_effect hat nicht den geschlossenen Dreifeldsatz")

    def object(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "v": self.v,
            "workspace_id": self.workspace_id,
            "command": self.command,
            "target_key": self.target_key,
            "inputs": self.inputs,
            "store_bindings": self.store_bindings,
            "causal_prestate": self.causal_prestate,
            "rule_versions": self.rule_versions,
            "idempotency_keys": self.idempotency_keys,
            "routing_keys": self.routing_keys,
            "desired_effect": self.desired_effect,
        }

    @property
    def bytes(self) -> bytes:
        return canonical_json_bytes(self.object())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.bytes).hexdigest()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> RetryIntent:
        if set(raw) != cls.FIELDS:
            raise OperationError("RetryIntent hat fehlende oder fremde Top-Level-Felder")
        return cls(**dict(raw))


@dataclass(frozen=True)
class OperationTrace:
    intent_present: bool
    intent_valid: bool
    causal_prestate_equal: bool
    expected_effects: tuple[str, ...]
    actual_effects: tuple[str, ...]
    foreign_relevant_in_window: bool = False
    foreign_relevant_after_window: bool = False


def classify_recovery(trace: OperationTrace) -> MatrixState:
    if not trace.intent_present:
        return MatrixState.A
    if not trace.intent_valid:
        return MatrixState.B
    expected = trace.expected_effects
    actual = trace.actual_effects
    if actual == expected:
        if not trace.causal_prestate_equal or trace.foreign_relevant_in_window:
            return MatrixState.G
        return MatrixState.D
    if not trace.causal_prestate_equal or trace.foreign_relevant_in_window:
        return MatrixState.C
    if not actual:
        return MatrixState.F
    if expected[: len(actual)] == actual and len(actual) < len(expected):
        return MatrixState.E
    return MatrixState.G
