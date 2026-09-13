"""Schreibfreier ISO-Plan und autorisierter v2-Snapshotwriter."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..domain.events import ISO6393_SNAPSHOT_PREPARED
from ..domain.iso6393 import IsoSnapshot, parse_iso6393_snapshot
from ..domain.operation import EVENT_CATALOG_VERSION, RETRY_INTENT_VERSION, RetryIntent
from ..journal import Journal
from ..policies.exit_contract import Report, Status
from ..project import Workspace
from .operation_recovery import Effect, b3b_report, execute_intent

__all__ = ["IsoPreparePlan", "plan_iso_prepare", "write_iso_prepare"]


@dataclass(frozen=True)
class IsoPreparePlan:
    snapshot: IsoSnapshot
    source_path: Path


def plan_iso_prepare(path: Path, *, release_id: str, reference: str) -> IsoPreparePlan:
    source = Path(path)
    raw = source.read_bytes()
    return IsoPreparePlan(
        snapshot=parse_iso6393_snapshot(raw, release_id=release_id, reference=reference),
        source_path=source,
    )


def _intent(ws: Workspace, plan: IsoPreparePlan) -> RetryIntent:
    snapshot = plan.snapshot
    workspace = ws.running_graph_sha256()
    return RetryIntent(
        workspace_id=workspace,
        command="iso6393_prepare",
        target_key={"workspace_id": workspace, "release_id": snapshot.release_id},
        inputs={
            "snapshot_raw_sha256": snapshot.source_sha256,
            "vocabulary_canonical_sha256": snapshot.vocabulary_sha256,
        },
        store_bindings={
            "raw_snapshot_store": {
                "address": snapshot.source_sha256,
                "sha256": snapshot.source_sha256,
            },
            "canonical_vocabulary_store": {
                "address": snapshot.vocabulary_sha256,
                "sha256": snapshot.vocabulary_sha256,
            },
        },
        causal_prestate={
            "iso_binding_sha256": None,
            "iso_binding_event_digest": None,
            "prepared_candidate_sha256": None,
            "prepared_candidate_event_digest": None,
        },
        rule_versions={
            "event_catalog": EVENT_CATALOG_VERSION,
            "retry_intent": RETRY_INTENT_VERSION,
            "iso_snapshot_schema": "iso6393-snapshot-prepared-v1",
        },
        idempotency_keys={
            "snapshot_prepared_key": [
                snapshot.release_id,
                snapshot.source_sha256,
                snapshot.vocabulary_sha256,
            ]
        },
        routing_keys={"workspace_iso_key": workspace},
        desired_effect={
            "event_sequence": ["operation.intent.recorded", ISO6393_SNAPSHOT_PREPARED],
            "store_outputs": {
                "retry_intent_store": "SELF_OPERATION_INTENT_SHA256",
                "raw_snapshot_store": snapshot.source_sha256,
                "canonical_vocabulary_store": snapshot.vocabulary_sha256,
            },
            "system_bindings": {"operation_intent_sha256": "SELF_OPERATION_INTENT_SHA256"},
        },
    )


def write_iso_prepare(ws: Workspace, journal: Journal, plan: IsoPreparePlan) -> Report:
    snapshot = plan.snapshot
    payload = {
        "release_id": snapshot.release_id,
        "source_sha256": snapshot.source_sha256,
        "vocabulary_sha256": snapshot.vocabulary_sha256,
        "reference": snapshot.reference,
        "raw_store": snapshot.source_sha256,
        "canonical_store": snapshot.vocabulary_sha256,
    }
    existing = [
        event
        for event in journal
        if event.kind == ISO6393_SNAPSHOT_PREPARED and event.payload == payload
    ]
    if existing:
        return b3b_report(
            Status.READY,
            "READY_B3B_NULLDURCHGANG",
            "Der ISO-Snapshot ist bereits bytegleich vorbereitet.",
            operation_result="NULLDURCHGANG",
        )
    intent, written = execute_intent(
        ws,
        journal,
        lambda: _intent(ws, plan),
        lambda _intent_value: [Effect(ISO6393_SNAPSHOT_PREPARED, payload, None)],
        pre_intent_objects=(snapshot.raw_bytes, snapshot.canonical_bytes),
    )
    return b3b_report(
        Status.READY,
        "READY_B3B_WRITTEN",
        "Der ISO-Snapshot ist vorbereitet und aus Originalbytes replaygeprueft.",
        changed=[str(ws.journal_path), str(ws.objects / intent.sha256)],
        operation_result="WRITTEN",
        details={
            "events": [event.kind for event in written],
            "intent_sha256": intent.sha256,
            "vocabulary_sha256": snapshot.vocabulary_sha256,
        },
    )
