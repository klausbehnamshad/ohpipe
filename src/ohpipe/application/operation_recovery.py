"""Gemeinsame v2-Intentpersistenz, Recoveryklassifikation und Reportprojektion."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from io import BytesIO
from typing import Any

from ..domain.events import OPERATION_INTENT_RECORDED
from ..domain.operation import MatrixState, OperationTrace, RetryIntent, classify_recovery
from ..journal import Event, Journal
from ..policies.exit_contract import Report, Status
from ..project import Workspace
from ..workspace_lock import workspace_write_lock

__all__ = [
    "Effect",
    "b3b_report",
    "execute_intent",
    "operation_events",
    "recovery_report",
]


@dataclass(frozen=True)
class Effect:
    kind: str
    payload: dict[str, Any]
    record_id: str | None


def b3b_report(
    status: Status,
    reason_code: str,
    reason: str,
    *,
    changed: Iterable[str] = (),
    next_command: str | None = None,
    operation_result: str = "NONE",
    details: dict[str, Any] | None = None,
) -> Report:
    return Report(
        status=status,
        reason=reason,
        reason_code=reason_code,
        changed=list(changed),
        next_command=next_command,
        source_data_touched=False,
        details={"operation_result": operation_result, **(details or {})},
    )


def operation_events(events: Iterable[Event], intent_sha256: str) -> list[Event]:
    return [event for event in events if event.operation_intent_sha256 == intent_sha256]


def execute_intent(
    ws: Workspace,
    journal: Journal,
    intent_factory: Callable[[], RetryIntent],
    effect_factory: Callable[[RetryIntent], Iterable[Effect]],
    *,
    pre_intent_objects: Iterable[bytes] = (),
    current_effects: bool = False,
    renew_effects: bool = False,
) -> tuple[RetryIntent, tuple[Event, ...]]:
    """Persistiert Intent vor jeder fachlichen Wirkung unter der gemeinsamen Sperre."""
    with workspace_write_lock(ws.root):
        intent = intent_factory()
        store = ws.store()
        for body in pre_intent_objects:
            store.put(BytesIO(body))
        address = store.put(BytesIO(intent.bytes))
        if address != intent.sha256:
            raise RuntimeError("RetryIntent-Storeadresse weicht vom Bytehash ab")
        intent_event = journal.append_once(
            OPERATION_INTENT_RECORDED,
            {
                "domain": "b3b_operation_intent_recorded",
                "v": 1,
                "workspace_id": intent.workspace_id,
                "command": intent.command,
                "target_key": intent.target_key,
                "intent_sha256": intent.sha256,
            },
            duplikat=lambda event: event.payload.get("intent_sha256") == intent.sha256,
        )
        written: list[Event] = []
        for effect in effect_factory(intent):
            latest = next(
                (
                    e
                    for e in reversed(list(journal))
                    if e.kind == effect.kind
                    and e.record_id == effect.record_id
                    and e.payload.get("artifact") == effect.payload.get("artifact")
                    and e.payload.get("kind") == effect.payload.get("kind")
                    and e.payload.get("target_record_id") == effect.payload.get("target_record_id")
                ),
                None,
            )
            event = journal.append_once(
                effect.kind,
                effect.payload,
                record_id=effect.record_id,
                operation_intent_sha256=intent.sha256,
                duplikat=lambda existing, candidate=effect, last=latest: (
                    not renew_effects
                    and existing.payload == candidate.payload
                    and (not current_effects or (last is not None and existing.seq == last.seq))
                ),
            )
            if event is not None:
                written.append(event)
        journal.verify()
        store.verify(intent.sha256)
        if intent_event is not None:
            written.insert(0, intent_event)
        return intent, tuple(written)


def recovery_report(trace: OperationTrace, *, retry_command: str) -> Report:
    matrix = classify_recovery(trace)
    details = {"matrix_state": matrix.value, "operation_result": "NONE"}
    if matrix is MatrixState.A:
        return b3b_report(
            Status.STOP,
            "STOP_B3B_INTENT_ABSENT",
            "Kein gueltiger persistierter Intentbeleg.",
            details=details,
        )
    if matrix is MatrixState.B:
        return b3b_report(
            Status.STOP,
            "STOP_B3B_INTENT_INVALID",
            "Der Intentbeleg ist ungueltig oder widerspruechlich.",
            details=details,
        )
    if matrix is MatrixState.C:
        return b3b_report(
            Status.ACTION_NEEDED,
            "ACTION_B3B_NEW_NORMAL_ACT_REQUIRED",
            "Der kausale Vorzustand hat sich bewegt; ein neuer Normalakt ist erforderlich.",
            details=details,
        )
    if matrix is MatrixState.G:
        return b3b_report(
            Status.STOP,
            "STOP_B3B_RECOVERY_STATE_INVALID",
            "Der persistierte Wirkungszustand ist widerspruechlich.",
            details=details,
        )
    if matrix is MatrixState.D:
        return b3b_report(
            Status.READY,
            "READY_B3B_NULLDURCHGANG",
            "Die vollstaendige Wirkung ist bereits deckungsgleich vorhanden.",
            operation_result="NULLDURCHGANG",
            details=details,
        )
    return b3b_report(
        Status.ACTION_NEEDED,
        "ACTION_B3B_STATUS_FINDING",
        "Die verankerte Operation ist objektgleich fortsetzbar.",
        next_command=retry_command,
        operation_result="VIEW",
        details={**details, "recovery": retry_command},
    )
