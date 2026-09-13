from pathlib import Path

import pytest

from ohpipe.application.ingest import (
    IngestError,
    language_prepare_required,
    plan_b3b_ingest_srt,
    write_b3b_ingest_srt,
)
from ohpipe.domain.iso6393 import parse_iso6393_snapshot
from ohpipe.domain.language_assignment import assign_languages, build_srt_draft
from ohpipe.journal import Journal
from ohpipe.project import Profile, Workspace


def _assignment():
    draft = build_srt_draft(b"1\n00:00:00,000 --> 00:00:01,000\nSPK: Text\n")
    vocabulary = parse_iso6393_snapshot(
        b"deu\nund\nzxx\n", release_id="iso.2025", reference="ref.001"
    )
    mapping = f"index\tsegment_sha256\tlanguage\n0\t{draft.segments[0].sha256}\tdeu\n".encode()
    return assign_languages(draft, mapping, target_record_id="SANDBOX-001", vocabulary=vocabulary)


def _workspace(tmp_path):
    profile = Profile.load(
        Path(__file__).parents[1] / "src" / "ohpipe" / "profiles" / "sandbox" / "profile.toml"
    )
    ws = Workspace(tmp_path / "data", profile)
    ws.ensure()
    ws.bind_graph_initially()
    from hashlib import sha256

    assignment = _assignment()
    journal = Journal(ws.journal_path)
    journal.append(
        "receipt.recorded",
        {
            "artifact": "transcript.revision",
            "output_sha256": assignment.sha256,
            "inputs": {
                "srt": assignment.draft.srt_bytes_sha256,
                "draft_segments": assignment.draft.draft_segments_sha256,
                "mapping": sha256(assignment.mapping_bytes).hexdigest(),
            },
            "code_version": "P3-synthetic-language-preparation",
            "kind": "transcript.segment_languages.prepared.v1",
            "target_record_id": "SANDBOX-001",
            "actor": "SYNTHETIC",
            "reference": "P3-PREPARED",
            "iso6393_release": "iso.2025",
            "iso6393_vocabulary_sha256": "a" * 64,
            "iso6393_snapshot_receipt": "a" * 64,
        },
    )
    return ws, journal


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-001"])
def test_missing_assignment_is_action_without_effect(_case):
    report = language_prepare_required(
        "SANDBOX-001",
        next_command="ohpipe transcript language template source.srt --output mapping.tsv",
    )
    assert report.to_json()["status"] == "ACTION_NEEDED"
    assert report.reason_code == "ACTION_B3B_LANGUAGE_PREPARE_REQUIRED"
    assert report.changed == [] and report.source_data_touched is False


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-002"])
def test_assignment_enters_revision_identity(_case):
    plan = plan_b3b_ingest_srt(
        record_id="SANDBOX-001",
        assignment=_assignment(),
        language_receipt_digest="a" * 64,
    )
    assert b'"language":"deu"' in plan.revision_bytes
    assert len(plan.revision_sha256) == 64


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-003"])
def test_ingest_writes_intent_receipt_produced_in_order(_case, tmp_path):
    ws, journal = _workspace(tmp_path)
    plan = plan_b3b_ingest_srt(
        record_id="SANDBOX-001",
        assignment=_assignment(),
        language_receipt_digest="a" * 64,
    )
    report = write_b3b_ingest_srt(ws, journal, plan)
    assert report.reason_code == "READY_B3B_WRITTEN"
    assert [event.kind for event in journal][-3:] == [
        "operation.intent.recorded",
        "receipt.recorded",
        "artifact.produced",
    ]


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-004"])
def test_ingest_second_run_is_null(_case, tmp_path):
    ws, journal = _workspace(tmp_path)
    plan = plan_b3b_ingest_srt(
        record_id="SANDBOX-001",
        assignment=_assignment(),
        language_receipt_digest="a" * 64,
    )
    write_b3b_ingest_srt(ws, journal, plan)
    before = journal.head()
    report = write_b3b_ingest_srt(ws, journal, plan)
    assert report.reason_code == "READY_B3B_NULLDURCHGANG"
    assert journal.head() == before


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-005"])
def test_assignment_for_other_record_is_rejected(_case):
    with pytest.raises(IngestError):
        plan_b3b_ingest_srt(
            record_id="SANDBOX-002",
            assignment=_assignment(),
            language_receipt_digest="a" * 64,
        )


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-006"])
def test_ingest_stores_exact_revision_bytes(_case, tmp_path):
    ws, journal = _workspace(tmp_path)
    plan = plan_b3b_ingest_srt(
        record_id="SANDBOX-001",
        assignment=_assignment(),
        language_receipt_digest="a" * 64,
    )
    write_b3b_ingest_srt(ws, journal, plan)
    with ws.store().open_verified(plan.revision_sha256) as handle:
        assert handle.read() == plan.revision_bytes
