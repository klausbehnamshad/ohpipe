"""Einmal gelesener FulltextPreparePlan und intentgebundener Writer."""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from ..domain.events import RECEIPT_RECORDED, SOURCE_INGESTED
from ..domain.operation import EVENT_CATALOG_VERSION, RETRY_INTENT_VERSION, RetryIntent
from ..journal import Journal
from ..policies.exit_contract import Report, Status
from ..project import Workspace
from .operation_recovery import Effect, b3b_report, execute_intent

__all__ = ["FulltextPreparePlan", "plan_fulltext_prepare", "write_fulltext_prepare"]


@dataclass(frozen=True)
class FulltextPreparePlan:
    source_path: Path
    record_id: str
    revision_sha256: str
    raw_bytes: bytes
    fulltext: str
    source_sha256: str
    source_filename: str
    reference: str


def plan_fulltext_prepare(
    path: Path,
    *,
    record_id: str,
    revision_sha256: str,
    reference: str,
) -> FulltextPreparePlan:
    raw = Path(path).read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("getrennter Volltext ist nicht UTF-8") from exc
    if not raw or "\r" in text or unicodedata.normalize("NFC", text) != text:
        raise ValueError("getrennter Volltext muss nichtleer, NFC und CR-frei sein")
    filename = f"fulltext-{hashlib.sha256(Path(path).name.encode()).hexdigest()[:16]}.txt"
    return FulltextPreparePlan(
        source_path=Path(path),
        record_id=record_id,
        revision_sha256=revision_sha256,
        raw_bytes=raw,
        fulltext=text,
        source_sha256=hashlib.sha256(raw).hexdigest(),
        source_filename=filename,
        reference=reference,
    )


def _intent(ws: Workspace, plan: FulltextPreparePlan) -> RetryIntent:
    workspace = ws.running_graph_sha256()
    receipt_key = hashlib.sha256(
        f"{plan.record_id}:{plan.revision_sha256}:{plan.source_sha256}".encode("ascii")
    ).hexdigest()
    return RetryIntent(
        workspace_id=workspace,
        command="transcript_fulltext_prepare",
        target_key={"workspace_id": workspace, "record_id": plan.record_id},
        inputs={
            "revision_sha256": plan.revision_sha256,
            "fulltext_source_sha256": plan.source_sha256,
        },
        store_bindings={
            "fulltext_source_store": {
                "address": plan.source_sha256,
                "sha256": plan.source_sha256,
            }
        },
        causal_prestate={
            "current_revision_sha256": plan.revision_sha256,
            "current_revision_event_digest": None,
            "current_fulltext_receipt_sha256": None,
            "current_fulltext_receipt_event_digest": None,
        },
        rule_versions={
            "event_catalog": EVENT_CATALOG_VERSION,
            "retry_intent": RETRY_INTENT_VERSION,
            "fulltext_prepare": "transcript-fulltext-separate-input-v1",
        },
        idempotency_keys={"fulltext_receipt_key": receipt_key},
        routing_keys={"fulltext_routing_key": [workspace, plan.record_id, plan.revision_sha256]},
        desired_effect={
            "event_sequence": [
                "operation.intent.recorded",
                SOURCE_INGESTED,
                RECEIPT_RECORDED,
            ],
            "store_outputs": {
                "retry_intent_store": "SELF_OPERATION_INTENT_SHA256",
                "fulltext_source_store": plan.source_sha256,
            },
            "system_bindings": {"operation_intent_sha256": "SELF_OPERATION_INTENT_SHA256"},
        },
    )


def write_fulltext_prepare(ws: Workspace, journal: Journal, plan: FulltextPreparePlan) -> Report:
    source = {
        "record_id": plan.record_id,
        "sha256": plan.source_sha256,
        "media_type": "text/plain;charset=utf-8",
        "filename": plan.source_filename,
        "bytes": len(plan.raw_bytes),
    }
    source_receipt = hashlib.sha256(
        f"{plan.source_sha256}:{plan.source_filename}:{len(plan.raw_bytes)}".encode("ascii")
    ).hexdigest()
    receipt = {
        # Graphname (siehe application/ingest.py::write_b3b_ingest_srt), Spezifik
        # in `kind`.
        "artifact": "transcript.revision",
        # Der Beleg sagt: DIESE Fassung hat ihren Volltext aus einer getrennten
        # Eingabe. Ausgabe ist damit die Fassung, Eingabe die Quelldatei.
        # Vorher stand die Quelle auf beiden Seiten: als Ausgabe UND als
        # Eingabe. Fuer `replay` heisst eine Ausgabe, die nicht die Bytes des
        # Artefakts sind, `STALE` — die Fassung waere durch ihren eigenen
        # Herkunftsbeleg entwertet worden, und die Kette haette hier gehalten.
        "output_sha256": plan.revision_sha256,
        "inputs": {
            "source": plan.source_sha256,
        },
        "code_version": "transcript-fulltext-separate-input-v1",
        "kind": "transcript.fulltext.separate_input.v1",
        "fulltext_origin": "separate_input",
        "reference": plan.reference,
        "fulltext_source_receipt": source_receipt,
    }
    if any(event.kind == RECEIPT_RECORDED and event.payload == receipt for event in journal):
        return b3b_report(
            Status.READY,
            "READY_B3B_NULLDURCHGANG",
            "Die getrennte Volltextherkunft ist bereits bytegleich wirksam.",
            operation_result="NULLDURCHGANG",
        )
    intent, events = execute_intent(
        ws,
        journal,
        lambda: _intent(ws, plan),
        lambda _intent_value: [
            Effect(SOURCE_INGESTED, source, plan.record_id),
            Effect(RECEIPT_RECORDED, receipt, plan.record_id),
        ],
        pre_intent_objects=(plan.raw_bytes,),
    )
    return b3b_report(
        Status.READY,
        "READY_B3B_WRITTEN",
        "Getrennter Volltext und Attestation sind intentgebunden geschrieben.",
        changed=[str(ws.journal_path), str(ws.objects / plan.source_sha256)],
        operation_result="WRITTEN",
        details={"intent_sha256": intent.sha256, "events": [event.kind for event in events]},
    )
