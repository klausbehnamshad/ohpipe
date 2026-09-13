"""Lokaler Templateexport sowie Plan und Writer der Segmentsprachzuordnung."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..domain.events import RECEIPT_RECORDED
from ..domain.instance import InstanceRegistry
from ..domain.iso6393 import IsoSnapshot
from ..domain.language_assignment import (
    ASSIGNMENT_CODE_VERSION,
    DRAFT_PARSER_VERSION,
    LanguageAssignment,
    SrtDraft,
    assign_languages,
    build_srt_draft,
    LanguageAssignmentError,
    mapping_template_bytes,
)
from ..domain.operation import EVENT_CATALOG_VERSION, RETRY_INTENT_VERSION, RetryIntent
from ..domain.token import validate_token
from ..journal import Journal
from ..policies.exit_contract import Report, Status
from ..project import Workspace
from .local_publish import check_target, publish_bytes
from .operation_recovery import Effect, b3b_report, execute_intent

__all__ = [
    "LanguagePreparePlan",
    "export_language_template",
    "plan_language_prepare",
    "write_language_prepare",
]


@dataclass(frozen=True)
class LanguagePreparePlan:
    target_record_id: str
    draft: SrtDraft
    mapping_path: Path
    assignment: LanguageAssignment
    actor: str
    reference: str
    vocabulary: IsoSnapshot
    iso_snapshot_receipt: str


def _template_report(
    status: Status,
    code: str,
    reason: str,
    *,
    changed: list[str] | None = None,
    operation_result: str = "NONE",
    local_write_state: str = "NONE",
) -> Report:
    return b3b_report(
        status,
        code,
        reason,
        changed=changed or [],
        operation_result=operation_result,
        details={"local_write_state": local_write_state},
    )


def export_language_template(
    source: Path,
    output: Path,
    *,
    managed_roots: tuple[Path, ...] = (),
) -> Report:
    """Liest die SRT einmal und publiziert die Vorlage per linkat ohne Overwrite.

    Der sichere lokale Schreibvorgang steht seit dem Katalogexport in
    ``local_publish.py`` und wird geteilt, nicht kopiert. Hier bleibt, was
    diesen Aufrufer ausmacht: die Reihenfolge — erst die Lage, dann der Inhalt,
    dann der Schreibvorgang — und seine eigenen Meldungsbausteine.
    """
    output = Path(output)
    parent, art, grund = check_target(output, managed_roots)
    if art == "PARTS":
        return _template_report(
            Status.CONFIG,
            "CONFIG_B3B_LANGUAGE_TEMPLATE_OUTPUT",
            "Der Ausgabepfad enthaelt eine leere, Punkt- oder Elternkomponente.",
        )
    if art == "UNSAFE":
        return _template_report(
            Status.CONFIG,
            "CONFIG_B3B_LANGUAGE_TEMPLATE_OUTPUT",
            f"Sichere Ausgabelage nicht beweisbar: {grund}",
        )
    try:
        source_bytes = Path(source).read_bytes()
    except OSError as exc:
        return _template_report(
            Status.CONFIG,
            "CONFIG_B3B_LANGUAGE_TEMPLATE_OUTPUT",
            f"Sichere Ausgabelage nicht beweisbar: {exc}",
        )
    try:
        draft = build_srt_draft(source_bytes)
    except LanguageAssignmentError as exc:
        return _template_report(
            Status.ACTION_NEEDED,
            "ACTION_B3B_DRAFT_OTHER_IDENTITY_REQUIRED",
            str(exc),
        )

    assert parent is not None  # art == "" heisst: die Lage ist aufgeloest
    ergebnis = publish_bytes(
        mapping_template_bytes(draft),
        output,
        parent=parent,
        temp_prefix=".ohpipe-language-template.",
    )
    if ergebnis.state == "TARGET_EXISTS":
        return _template_report(
            Status.STOP,
            "STOP_B3B_LANGUAGE_TEMPLATE_TARGET_EXISTS",
            "Der Zielname erschien konkurrierend; nichts wurde ueberschrieben."
            if ergebnis.raced
            else "Der lokale Templatezielname ist bereits belegt.",
        )
    if ergebnis.state != "WRITTEN":
        return _template_report(
            Status.STOP,
            "STOP_B3B_LANGUAGE_TEMPLATE_PERSISTENCE_UNCERTAIN"
            if ergebnis.published
            else "STOP_B3B_LANGUAGE_TEMPLATE_WRITE_FAILED",
            f"Lokale Templateablage fehlgeschlagen: {ergebnis.detail}",
            changed=[str(output)] if ergebnis.published else [],
            operation_result="UNKNOWN" if ergebnis.published else "NONE",
            local_write_state="TARGET_VISIBLE_FULL" if ergebnis.published else "NONE",
        )
    return _template_report(
        Status.ACTION_NEEDED,
        "ACTION_B3B_LANGUAGE_MAPPING_EDIT_REQUIRED",
        "Die Mappingvorlage ist vollstaendig angelegt; jede Sprachzelle ist auszufuellen.",
        changed=[str(output)],
        operation_result="WRITTEN",
        local_write_state="TARGET_VISIBLE_FULL",
    )


def plan_language_prepare(
    *,
    record_id: str,
    srt_path: Path,
    mapping_path: Path,
    actor: str,
    reference: str,
    vocabulary: IsoSnapshot,
    iso_snapshot_receipt: str,
    profile_normalize: Callable[[str], str],
    profile_check: Callable[[str], bool],
    events: list[object],
) -> LanguagePreparePlan:
    canonical_record = profile_normalize(record_id)
    if not profile_check(canonical_record) or canonical_record != record_id:
        raise ValueError("target_record_id ist nicht profilkanonisch")
    registry = InstanceRegistry.from_events(events)
    registry.get(actor, active=True)
    draft = build_srt_draft(Path(srt_path).read_bytes())
    mapping = Path(mapping_path).read_bytes()
    assignment = assign_languages(
        draft,
        mapping,
        target_record_id=canonical_record,
        vocabulary=vocabulary,
    )
    return LanguagePreparePlan(
        target_record_id=canonical_record,
        draft=draft,
        mapping_path=Path(mapping_path),
        assignment=assignment,
        actor=validate_token(actor, field="actor"),
        reference=validate_token(reference, field="reference"),
        vocabulary=vocabulary,
        iso_snapshot_receipt=iso_snapshot_receipt,
    )


def _intent(ws: Workspace, plan: LanguagePreparePlan) -> RetryIntent:
    assignment = plan.assignment
    workspace = ws.running_graph_sha256()
    actor_state_sha256 = hashlib.sha256(plan.actor.encode("ascii")).hexdigest()
    actor_event_digest = hashlib.sha256(f"active-instance:{plan.actor}".encode("ascii")).hexdigest()
    return RetryIntent(
        workspace_id=workspace,
        command="transcript_language_prepare",
        target_key={
            "workspace_id": workspace,
            "target_record_id": plan.target_record_id,
            "srt_bytes_sha256": plan.draft.srt_bytes_sha256,
            "draft_segments_sha256": plan.draft.draft_segments_sha256,
        },
        inputs={
            "srt_bytes_sha256": plan.draft.srt_bytes_sha256,
            "draft_segments_sha256": plan.draft.draft_segments_sha256,
            "mapping_bytes_sha256": hashlib.sha256(assignment.mapping_bytes).hexdigest(),
            "language_assignment_sha256": assignment.sha256,
            "iso6393_vocabulary_sha256": plan.vocabulary.vocabulary_sha256,
        },
        store_bindings={
            "language_assignment_store": {
                "address": assignment.sha256,
                "sha256": assignment.sha256,
            },
            "iso6393_vocabulary_store": {
                "address": plan.vocabulary.vocabulary_sha256,
                "sha256": plan.vocabulary.vocabulary_sha256,
            },
        },
        causal_prestate={
            "current_language_assignment_sha256": None,
            "current_language_assignment_event_digest": None,
            "actor_state_sha256": actor_state_sha256,
            "actor_state_event_digest": actor_event_digest,
            "iso_binding_sha256": None,
            "iso_binding_event_digest": None,
            "prepared_candidate_sha256": plan.vocabulary.vocabulary_sha256,
            "prepared_candidate_event_digest": plan.iso_snapshot_receipt,
        },
        rule_versions={
            "event_catalog": EVENT_CATALOG_VERSION,
            "retry_intent": RETRY_INTENT_VERSION,
            "srt_draft_schema": "transcript-srt-draft-v1",
            "language_assignment_schema": "transcript-segment-language-assignment-v1",
            "language_assignment_receipt": "transcript-segment-languages-prepared-v1",
        },
        idempotency_keys={"language_assignment_receipt_key": assignment.sha256},
        routing_keys={
            "language_assignment_routing_key": [
                workspace,
                plan.target_record_id,
                plan.draft.srt_bytes_sha256,
                DRAFT_PARSER_VERSION,
                plan.draft.draft_segments_sha256,
            ]
        },
        desired_effect={
            "event_sequence": ["operation.intent.recorded", RECEIPT_RECORDED],
            "store_outputs": {
                "retry_intent_store": "SELF_OPERATION_INTENT_SHA256",
                "language_assignment_store": assignment.sha256,
            },
            "system_bindings": {"operation_intent_sha256": "SELF_OPERATION_INTENT_SHA256"},
        },
    )


def write_language_prepare(ws: Workspace, journal: Journal, plan: LanguagePreparePlan) -> Report:
    assignment = plan.assignment
    payload = {
        # Graphname wie bei den beiden anderen B3b-Belegen; die Spezifik steht
        # in `kind`. Dieses Ereignis traegt keine record_id in der Huelle
        # (workspaceweit, siehe domain/events.py::check_payload). P3 liest
        # daraus den aktuellen SRT-/Sprachzuordnungsstand des Zielrecords;
        # der Workspacebeleg wird dadurch kein fachliches Revisionsartefakt.
        "artifact": "transcript.revision",
        "output_sha256": assignment.sha256,
        "inputs": {
            "srt": plan.draft.srt_bytes_sha256,
            "draft_segments": plan.draft.draft_segments_sha256,
            "mapping": hashlib.sha256(assignment.mapping_bytes).hexdigest(),
        },
        "code_version": ASSIGNMENT_CODE_VERSION,
        "kind": "transcript.segment_languages.prepared.v1",
        "target_record_id": plan.target_record_id,
        "actor": plan.actor,
        "reference": plan.reference,
        "iso6393_release": plan.vocabulary.release_id,
        "iso6393_vocabulary_sha256": plan.vocabulary.vocabulary_sha256,
        "iso6393_snapshot_receipt": plan.iso_snapshot_receipt,
    }
    latest = next(
        (
            event
            for event in reversed(list(journal))
            if event.kind == RECEIPT_RECORDED
            and event.payload.get("kind") == payload["kind"]
            and event.payload.get("target_record_id") == plan.target_record_id
        ),
        None,
    )
    if latest is not None and latest.payload == payload:
        return b3b_report(
            Status.READY,
            "READY_B3B_NULLDURCHGANG",
            "Die Sprachzuordnung ist bereits aktuell und bytegleich.",
            operation_result="NULLDURCHGANG",
        )
    intent, written = execute_intent(
        ws,
        journal,
        lambda: _intent(ws, plan),
        lambda _intent_value: [Effect(RECEIPT_RECORDED, payload, None)],
        pre_intent_objects=(assignment.bytes,),
        current_effects=True,
    )
    return b3b_report(
        Status.READY,
        "READY_B3B_WRITTEN",
        "Die Segmentsprachzuordnung ist intentgebunden und replaygeprueft.",
        changed=[str(ws.journal_path), str(ws.objects / assignment.sha256)],
        next_command=None,
        operation_result="WRITTEN",
        details={"intent_sha256": intent.sha256, "events": [event.kind for event in written]},
    )
