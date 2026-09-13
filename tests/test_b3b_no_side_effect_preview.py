import hashlib
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

import ohpipe.application.operation_recovery as operation_recovery
import ohpipe.journal as journal_module
from ohpipe.application.fulltext import plan_fulltext_prepare, write_fulltext_prepare
from ohpipe.application.ingest import (
    IngestError,
    language_prepare_required,
    plan_b3b_ingest_srt,
    write_b3b_ingest_srt,
)
from ohpipe.application.iso6393 import plan_iso_prepare, write_iso_prepare
from ohpipe.application.replay import replay
from ohpipe.application.status import ReadSnapshot, status_report
from ohpipe.application.transcript_language import plan_language_prepare, write_language_prepare
from ohpipe.cli.main import build_parser, cmd_b3b
from ohpipe.domain.confirmation import ConfirmationDecision, ConfirmationMarker
from ohpipe.domain.decision import Decision, Verdict
from ohpipe.domain.events import RECEIPT_RECORDED, check_payload
from ohpipe.domain.instance import InstanceRegistry, InstanceRegistryError
from ohpipe.domain.iso6393 import parse_iso6393_snapshot
from ohpipe.domain.language_assignment import (
    LanguageAssignmentError,
    assign_languages,
    build_srt_draft,
    mapping_template_bytes,
    parse_mapping,
)
from ohpipe.domain.operation import MatrixState, OperationTrace, RetryIntent, classify_recovery
from ohpipe.domain.step import DEFAULT_GRAPH
from ohpipe.domain.token import InvalidToken, validate_token
from ohpipe.journal import Journal
from ohpipe.policies.authority import Authority
from ohpipe.project import Profile, Workspace
from ohpipe.store import ContentStore


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-028"])
def test_language_missing_preview_has_no_changed(_case):
    report = language_prepare_required("SANDBOX-001", next_command="ohpipe status")
    assert report.changed == []
    assert report.details["operation_result"] == "NONE"


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-029"])
def test_mapping_template_does_not_change_draft(_case):
    raw = b"1\n00:00:00,000 --> 00:00:01,000\nSPK: Text\n"
    draft = build_srt_draft(raw)
    before = hashlib.sha256(draft.raw_bytes).hexdigest()
    mapping_template_bytes(draft)
    assert hashlib.sha256(draft.raw_bytes).hexdigest() == before


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-030"])
def test_template_is_visibly_incomplete(_case):
    draft = build_srt_draft(b"1\n00:00:00,000 --> 00:00:01,000\nSPK: Text\n")
    assert mapping_template_bytes(draft).endswith(b"\t\n")


def _assignment(record_id="SANDBOX-001"):
    draft = build_srt_draft(b"1\n00:00:00,000 --> 00:00:01,000\nSPK: Text\n")
    vocabulary = parse_iso6393_snapshot(
        b"deu\nund\nzxx\n", release_id="iso.2025", reference="ref.001"
    )
    mapping = f"index\tsegment_sha256\tlanguage\n0\t{draft.segments[0].sha256}\tdeu\n".encode()
    return assign_languages(draft, mapping, target_record_id=record_id, vocabulary=vocabulary)


def _workspace(tmp_path):
    profile = Profile.load(
        Path(__file__).parents[1] / "src" / "ohpipe" / "profiles" / "sandbox" / "profile.toml"
    )
    ws = Workspace(tmp_path / "data", profile)
    ws.ensure()
    ws.bind_graph_initially()
    return ws, Journal(ws.journal_path)


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-031"])
def test_unicode_word_character_never_enters_an_ascii_token(_case):
    with pytest.raises(InvalidToken):
        validate_token("coeder.ö")


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-032"])
def test_token_end_anchor_rejects_a_final_lf(_case):
    with pytest.raises(InvalidToken):
        validate_token("coder.001\n")


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-033"])
def test_new_event_envelope_refuses_a_foreign_payload_field(_case):
    payload = {
        "artifact": "transcript.revision",
        "output_sha256": "a" * 64,
        "inputs": {"srt": "b" * 64},
        "code_version": "b3b-test",
        "kind": "transcript.fulltext.segment_projection.v1",
        "fulltext_origin": "from_segments",
        "step": "must-not-pass-specialised-envelope",
    }
    with pytest.raises(ValueError):
        check_payload(RECEIPT_RECORDED, payload, "SANDBOX-001")


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-034"])
def test_invalid_newest_decision_blocks_fallback_to_an_older_one(_case):
    decision = Decision(
        record_id="SANDBOX-001",
        artifact="transcript.revision",
        subject_sha256="a" * 64,
        verdict=Verdict.ACCEPT,
        reference="ref.001",
        actor="coder.001",
    ).to_json()
    broken = {**decision, "actor": ""}
    events = [
        SimpleNamespace(
            kind="artifact.produced",
            record_id="SANDBOX-001",
            payload={"artifact": "transcript.revision", "sha256": "a" * 64},
            at=decision["at"],
        ),
        SimpleNamespace(
            kind="decision.recorded",
            record_id="SANDBOX-001",
            payload=decision,
            at=decision["at"],
        ),
        SimpleNamespace(
            kind="decision.recorded",
            record_id="SANDBOX-001",
            payload=broken,
            at=decision["at"],
        ),
    ]
    view = replay(events, DEFAULT_GRAPH, Authority.AUTHENTICATED)["SANDBOX-001"]
    assert view.status.value == "STOP"
    assert "transcript.revision" not in view.effective_decision_by_artifact


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-035"])
def test_decision_payload_record_is_checked_before_routing(_case):
    decision = Decision(
        record_id="SANDBOX-002",
        artifact="transcript.revision",
        subject_sha256="a" * 64,
        verdict=Verdict.ACCEPT,
        reference="ref.001",
        actor="coder.001",
    ).to_json()
    event = SimpleNamespace(
        kind="decision.recorded",
        record_id="SANDBOX-001",
        payload=decision,
        at=decision["at"],
    )
    view = replay([event], DEFAULT_GRAPH, Authority.AUTHENTICATED)["SANDBOX-001"]
    assert view.status.value == "STOP"
    assert "weicht" in view.findings[0]


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-036"])
def test_produced_without_intent_bound_receipt_is_not_backfilled(_case, tmp_path):
    ws, journal = _workspace(tmp_path)
    plan = plan_b3b_ingest_srt(
        record_id="SANDBOX-001",
        assignment=_assignment(),
        language_receipt_digest="a" * 64,
    )
    journal.append(
        "artifact.produced",
        {"artifact": "transcript.revision", "sha256": plan.revision_sha256},
        record_id="SANDBOX-001",
    )
    before = journal.head()
    report = write_b3b_ingest_srt(ws, journal, plan)
    assert report.reason_code == "STOP_B3B_RECOVERY_STATE_INVALID"
    assert journal.head() == before


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-037"])
def test_ingest_effect_order_is_receipt_before_produced(_case, tmp_path):
    ws, journal = _workspace(tmp_path)
    plan = plan_b3b_ingest_srt(
        record_id="SANDBOX-001", assignment=_assignment(), language_receipt_digest="a" * 64
    )
    report = write_b3b_ingest_srt(ws, journal, plan)
    assert report.details["events"] == [
        "operation.intent.recorded",
        "receipt.recorded",
        "artifact.produced",
    ]


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-038"])
def test_ingest_retry_intent_keeps_all_mutable_causal_roles(_case, tmp_path):
    ws, journal = _workspace(tmp_path)
    plan = plan_b3b_ingest_srt(
        record_id="SANDBOX-001", assignment=_assignment(), language_receipt_digest="a" * 64
    )
    report = write_b3b_ingest_srt(ws, journal, plan)
    with ws.store().open_verified(report.details["intent_sha256"]) as handle:
        intent = RetryIntent.from_mapping(__import__("json").loads(handle.read()))
    assert set(intent.causal_prestate) == {
        "current_language_assignment_sha256",
        "current_language_assignment_event_digest",
        "current_revision_sha256",
        "current_revision_event_digest",
    }


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-039"])
def test_retry_digest_without_persisted_intent_is_a_stop(_case):
    args = build_parser().parse_args(["instance", "retire", "--retry-intent", "a" * 64])
    report = cmd_b3b(args)
    assert report.reason_code == "STOP_B3B_INTENT_ABSENT"


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-040"])
def test_partial_effect_with_foreign_window_movement_is_matrix_c(_case):
    trace = OperationTrace(True, True, True, ("intent", "effect"), ("intent",), True)
    assert classify_recovery(trace) is MatrixState.C


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-041"])
def test_complete_effect_stays_matrix_d_after_later_foreign_append(_case):
    trace = OperationTrace(
        True, True, True, ("intent", "effect"), ("intent", "effect"), False, True
    )
    assert classify_recovery(trace) is MatrixState.D


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-042"])
def test_new_store_object_fsyncs_its_directory(_case, tmp_path, monkeypatch):
    store = ContentStore(tmp_path)
    calls = []
    original = ContentStore._fsync_dir

    def observed(fd):
        calls.append(fd)
        return original(fd)

    monkeypatch.setattr(ContentStore, "_fsync_dir", staticmethod(observed))
    store.put(BytesIO(b"durable"))
    assert len(calls) == 1


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-043"])
def test_journal_fsync_precedes_effect_return(_case, tmp_path, monkeypatch):
    journal = Journal(tmp_path / "journal.jsonl")
    calls = []
    original = journal_module.os.fsync

    def observed(fd):
        calls.append(fd)
        return original(fd)

    monkeypatch.setattr(journal_module.os, "fsync", observed)
    journal.append(
        "anchor.checked",
        {"artifact": "transcript.revision", "outcome": "STILL_BOUND"},
        record_id="SANDBOX-001",
    )
    assert calls


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-044"])
def test_fulltext_writer_uses_once_read_plan_bytes(_case, tmp_path):
    source = tmp_path / "fulltext.txt"
    source.write_bytes(b"first\n")
    plan = plan_fulltext_prepare(
        source, record_id="SANDBOX-001", revision_sha256="a" * 64, reference="ref.001"
    )
    source.write_bytes(b"second\n")
    ws, journal = _workspace(tmp_path / "workspace")
    write_fulltext_prepare(ws, journal, plan)
    with ws.store().open_verified(plan.source_sha256) as handle:
        assert handle.read() == b"first\n"


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-045"])
def test_every_writer_enters_the_common_workspace_lock(_case, tmp_path, monkeypatch):
    ws, journal = _workspace(tmp_path)
    entered = []

    @contextmanager
    def observed(root):
        entered.append(root)
        yield -1

    monkeypatch.setattr(operation_recovery, "workspace_write_lock", observed)
    plan = plan_b3b_ingest_srt(
        record_id="SANDBOX-001", assignment=_assignment(), language_receipt_digest="a" * 64
    )
    write_b3b_ingest_srt(ws, journal, plan)
    assert entered == [ws.root]


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-046"])
def test_retry_intent_and_confirm_are_rejected_together(_case):
    args = build_parser().parse_args(
        ["instance", "retire", "--retry-intent", "a" * 64, "--confirm"]
    )
    assert cmd_b3b(args).reason_code == "CONFIG_B3B_ARGUMENTS"


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-047"])
def test_status_surfaces_uncertain_intent_with_retry_next(_case):
    intent = SimpleNamespace(
        kind="operation.intent.recorded",
        payload={"intent_sha256": "a" * 64, "command": "instance_register"},
        operation_intent_sha256=None,
    )
    report = status_report(ReadSnapshot(1, "b" * 64, (intent,), 1))
    assert report.status.value == "ACTION_NEEDED"
    assert report.reason_code == "ACTION_B3B_STATUS_FINDING"
    assert report.next_command == f"ohpipe instance register --retry-intent {'a' * 64}"


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-048"])
def test_iso_writer_never_rereads_path_after_preview(_case, tmp_path):
    source = tmp_path / "iso.txt"
    source.write_bytes(b"deu\nund\nzxx\n")
    plan = plan_iso_prepare(source, release_id="iso.2025", reference="ref.001")
    source.write_bytes(b"eng\nund\nzxx\n")
    ws, journal = _workspace(tmp_path / "workspace")
    write_iso_prepare(ws, journal, plan)
    assert plan.snapshot.contains("deu") and not plan.snapshot.contains("eng")
    with ws.store().open_verified(plan.snapshot.source_sha256) as handle:
        assert handle.read() == b"deu\nund\nzxx\n"
    assert write_iso_prepare(ws, journal, plan).details["operation_result"] == "NULLDURCHGANG"


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-049"])
def test_registry_rejects_at_order_in_place_of_journal_seq(_case):
    payload = InstanceRegistry.registration_payload(
        "coder.001", source="mensch", label="Coder Eins", reference="ref.001"
    )
    first = SimpleNamespace(
        seq=1,
        at="2026-01-02T00:00:00+00:00",
        kind="instance.registered",
        payload=payload,
        digest="a",
    )
    second = SimpleNamespace(
        seq=2,
        at="2026-01-01T00:00:00+00:00",
        kind="instance.retired",
        payload={"coder_id": "coder.001", "reference": "ref.002"},
        digest="b",
    )
    assert InstanceRegistry.from_events([first, second]).get("coder.001").retired
    with pytest.raises(InstanceRegistryError):
        InstanceRegistry.from_events([second, first])


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-050"])
def test_new_confirmation_gets_a_fresh_activation_identity(_case):
    marker = ConfirmationMarker("SANDBOX-001", "projection.v1", "a" * 64)
    values = dict(
        marker=marker,
        actor="coder.001",
        fulltext_origin="from_segments",
        fulltext_receipt="b" * 64,
        iso6393_release="iso.2025",
        iso6393_vocabulary_sha256="c" * 64,
        iso6393_snapshot_receipt="d" * 64,
    )
    assert (
        ConfirmationDecision.create(**values).activation_id
        != ConfirmationDecision.create(**values).activation_id
    )


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-051"])
def test_missing_language_is_never_defaulted_to_und(_case):
    draft = _assignment().draft
    vocabulary = parse_iso6393_snapshot(
        b"deu\nund\nzxx\n", release_id="iso.2025", reference="ref.001"
    )
    mapping = f"index\tsegment_sha256\tlanguage\n0\t{draft.segments[0].sha256}\t\n".encode()
    with pytest.raises(LanguageAssignmentError):
        parse_mapping(mapping, draft, vocabulary)


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-052"])
def test_mapping_segment_digest_is_not_ignored(_case):
    assignment = _assignment()
    mapping = b"index\tsegment_sha256\tlanguage\n0\t" + b"f" * 64 + b"\tdeu\n"
    vocabulary = parse_iso6393_snapshot(
        b"deu\nund\nzxx\n", release_id="iso.2025", reference="ref.001"
    )
    with pytest.raises(LanguageAssignmentError):
        parse_mapping(mapping, assignment.draft, vocabulary)


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-053"])
def test_ingest_requires_a_full_current_language_receipt_digest(_case):
    with pytest.raises(IngestError):
        plan_b3b_ingest_srt(
            record_id="SANDBOX-001", assignment=_assignment(), language_receipt_digest="old"
        )


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-054"])
def test_language_prepare_writer_is_intent_bound(_case, tmp_path):
    ws, journal = _workspace(tmp_path)
    registration = InstanceRegistry.registration_payload(
        "coder.001", source="mensch", label="Coder Eins", reference="ref.001"
    )
    journal.append("instance.registered", registration)
    srt = tmp_path / "source.srt"
    srt.write_bytes(b"1\n00:00:00,000 --> 00:00:01,000\nSPK: Text\n")
    draft = build_srt_draft(srt.read_bytes())
    mapping = tmp_path / "mapping.tsv"
    mapping.write_bytes(
        f"index\tsegment_sha256\tlanguage\n0\t{draft.segments[0].sha256}\tdeu\n".encode()
    )
    vocabulary = parse_iso6393_snapshot(
        b"deu\nund\nzxx\n", release_id="iso.2025", reference="ref.001"
    )
    plan = plan_language_prepare(
        record_id="SANDBOX-001",
        srt_path=srt,
        mapping_path=mapping,
        actor="coder.001",
        reference="ref.001",
        vocabulary=vocabulary,
        iso_snapshot_receipt="e" * 64,
        profile_normalize=ws.profile.normalize_record_id,
        profile_check=ws.profile.is_record_id,
        events=list(journal),
    )
    report = write_language_prepare(ws, journal, plan)
    assert report.details["events"] == ["operation.intent.recorded", "receipt.recorded"]
