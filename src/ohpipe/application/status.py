"""Fluechtiger ReadSnapshot und deterministische B3b-Operationssicht."""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.events import OPERATION_INTENT_RECORDED
from ..journal import Event, Journal
from ..policies.exit_contract import Report, Status
from .operation_recovery import b3b_report

__all__ = ["ReadSnapshot", "read_snapshot", "status_report"]


@dataclass(frozen=True)
class ReadSnapshot:
    head_seq: int
    head_digest: str
    events: tuple[Event, ...]
    attempts: int


def read_snapshot(journal: Journal, *, max_attempts: int = 3) -> ReadSnapshot:
    if max_attempts != 3:
        raise ValueError("ReadSnapshot ist fest auf hoechstens drei Versuche gebunden")
    for attempt in range(1, max_attempts + 1):
        before = journal.head()
        events = tuple(journal)
        after = journal.head()
        if before == after and (not events or (events[-1].seq, events[-1].digest) == after):
            return ReadSnapshot(after[0], after[1], events, attempt)
    raise RuntimeError("Journal bewegte sich waehrend aller drei ReadSnapshot-Versuche")


def status_report(snapshot: ReadSnapshot) -> Report:
    intents = [event for event in snapshot.events if event.kind == OPERATION_INTENT_RECORDED]
    uncertain = [
        event
        for event in intents
        if not any(
            candidate.operation_intent_sha256 == event.payload["intent_sha256"]
            for candidate in snapshot.events
        )
    ]
    if uncertain:
        first = uncertain[0]
        command = first.payload["command"].replace("_", " ")
        return b3b_report(
            Status.ACTION_NEEDED,
            "ACTION_B3B_STATUS_FINDING",
            "Mindestens eine intentgebundene Wirkung ist noch nicht vollstaendig belegt.",
            next_command=f"ohpipe {command} --retry-intent {first.payload['intent_sha256']}",
            operation_result="VIEW",
            details={
                "head_seq": snapshot.head_seq,
                "head_digest": snapshot.head_digest,
                "snapshot_attempts": snapshot.attempts,
                "operation_intents": [event.payload["intent_sha256"] for event in intents],
                "wirkung_ungewiss": [event.payload["intent_sha256"] for event in uncertain],
            },
        )
    return b3b_report(
        Status.READY,
        "READY_B3B_STATUS_VIEW",
        "Der fluechtige B3b-Status wurde ohne zweite Wahrheit aus Replay berechnet.",
        operation_result="VIEW",
        details={
            "head_seq": snapshot.head_seq,
            "head_digest": snapshot.head_digest,
            "snapshot_attempts": snapshot.attempts,
            "operation_intents": [event.payload["intent_sha256"] for event in intents],
        },
    )
