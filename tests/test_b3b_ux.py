import fcntl
import hashlib
import io
import json
import os
import shutil
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest

import ohpipe.cli.main as cli_module
from ohpipe.application.ingest import plan_b3b_ingest_srt, write_b3b_ingest_srt
from ohpipe.application.instance_registry import plan_register, write_instance_plan
from ohpipe.application.iso6393 import IsoPreparePlan, write_iso_prepare
from ohpipe.application.transcript_language import plan_language_prepare, write_language_prepare
from ohpipe.domain.iso6393 import parse_iso6393_snapshot
from ohpipe.domain.language_assignment import build_srt_draft
from ohpipe.journal import Journal
from ohpipe.policies.exit_contract import Report
from ohpipe.project import Profile, Workspace

from ._b3b import assert_case, load_cases

CASES = load_cases("UX")
PROFILE = Path(__file__).parents[1] / "src" / "ohpipe" / "profiles" / "sandbox" / "profile.toml"
CHOICE = "[b] Bestaetigen / [a] Abbrechen"
ORIGINAL_EMIT = Report.emit
ORIGINAL_FSYNC = os.fsync


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _files(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _lock_state(ws: Workspace) -> dict[str, bool]:
    path = ws.root / "_governance" / ".b3b-workspace-write.lock"
    if not path.exists():
        return {"path_present": False, "held": False}
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    held = False
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        except BlockingIOError:
            held = True
    finally:
        os.close(fd)
    return {"path_present": True, "held": held}


def _effect_state(ws: Workspace) -> dict[str, Any]:
    files = _files(ws.root)
    events = list(Journal(ws.journal_path)) if ws.journal_path.exists() else []
    store = {name: digest for name, digest in files.items() if "/objects/" in f"/{name}"}
    intents = [event.digest for event in events if event.kind == "operation.intent.recorded"]
    return {
        "files": files,
        "store_digest": _digest(store),
        "journal_digest": hashlib.sha256(
            ws.journal_path.read_bytes() if ws.journal_path.exists() else b""
        ).hexdigest(),
        "intent_digest": _digest(intents),
        "lock_state": _lock_state(ws),
        "event_count": len(events),
    }


class _Visible(io.StringIO):
    def __init__(self) -> None:
        super().__init__()
        self.flush_count = 0

    def flush(self) -> None:
        self.flush_count += 1
        super().flush()


class _DecisionInput(io.StringIO):
    def __init__(
        self,
        text: str,
        *,
        tty: bool,
        fail_on_read: bool,
        before_read: Any,
    ) -> None:
        super().__init__(text)
        self.tty = tty
        self.fail_on_read = fail_on_read
        self.before_read = before_read
        self.consumed: list[str] = []
        self.read_count = 0

    def isatty(self) -> bool:
        return self.tty

    def readline(self, *args: Any, **kwargs: Any) -> str:
        if self.fail_on_read:
            raise AssertionError("non-TTY/--confirm attempted to read stdin")
        self.before_read()
        self.read_count += 1
        value = super().readline(*args, **kwargs)
        self.consumed.append(value.encode("ascii").hex())
        return value


def _workspace(root: Path) -> Workspace:
    ws = Workspace(root, Profile.load(PROFILE))
    ws.ensure()
    ws.bind_graph_initially()
    return ws


def _canonical_paths(value: Any, ws: Workspace) -> Any:
    if isinstance(value, str):
        return value.replace(str(ws.root), "{root}")
    if isinstance(value, list):
        return [_canonical_paths(item, ws) for item in value]
    if isinstance(value, dict):
        return {key: _canonical_paths(item, ws) for key, item in value.items()}
    return value


def _plan_value(plan: Any) -> dict[str, Any]:
    if hasattr(plan, "marker") and hasattr(plan, "decision"):
        return {
            "marker": plan.marker.object(),
            "actor": plan.decision.actor,
            "fulltext_origin": plan.decision.fulltext_origin,
            "fulltext_receipt": plan.decision.fulltext_receipt,
            "iso6393_release": plan.decision.iso6393_release,
            "iso6393_vocabulary_sha256": plan.decision.iso6393_vocabulary_sha256,
            "iso6393_snapshot_receipt": plan.decision.iso6393_snapshot_receipt,
            "actor_state_sha256": plan.actor_state_sha256,
            "actor_event_digest": plan.actor_event_digest,
        }
    return {"action": plan.action, "payload": dict(plan.payload)}


def _invoke(
    ws: Workspace,
    argv: list[str],
    monkeypatch: pytest.MonkeyPatch,
    *,
    tty: bool,
    input_text: str,
    writer_name: str,
    fail_on_read: bool = False,
) -> dict[str, Any]:
    before = _effect_state(ws)
    stdout = _Visible()
    stderr = _Visible()
    fsync_calls: list[int] = []
    read_snapshots: list[dict[str, Any]] = []
    emitted: list[Report] = []
    writer_calls: list[dict[str, Any]] = []

    def before_read() -> None:
        state = _effect_state(ws)
        text = stderr.getvalue()
        read_snapshots.append(
            {
                **state,
                "fsync_count": len(fsync_calls),
                "preview_fully_emitted": text.startswith("B3B-VORSCHAU ") and "\n" in text,
                "choice_fully_emitted": text.endswith(CHOICE + "\n"),
                "visible_stream_flushed": stderr.flush_count > 0,
                "flush_count": stderr.flush_count,
            }
        )

    decision_input = _DecisionInput(
        input_text,
        tty=tty,
        fail_on_read=fail_on_read,
        before_read=before_read,
    )

    with monkeypatch.context() as patch:
        original_writer = getattr(cli_module, writer_name)

        def observed_writer(*args: Any, **kwargs: Any) -> Report:
            writer_calls.append(_plan_value(args[-1]))
            return original_writer(*args, **kwargs)

        def measured_fsync(fd: int) -> None:
            fsync_calls.append(fd)
            ORIGINAL_FSYNC(fd)

        def measured_emit(report: Report, as_json: bool = False, stream: Any = None) -> int:
            emitted.append(report)
            return ORIGINAL_EMIT(report, as_json=as_json, stream=stream)

        patch.setattr(cli_module, writer_name, observed_writer)
        patch.setattr(os, "fsync", measured_fsync)
        patch.setattr(Report, "emit", measured_emit)
        patch.setattr(cli_module.sys, "stdin", decision_input)
        with redirect_stdout(stdout), redirect_stderr(stderr):
            process_exit = cli_module.main(argv)

    assert len(emitted) == 1
    report = emitted[0]
    after = _effect_state(ws)
    preview = report.details["preview"]
    first_read = read_snapshots[0] if read_snapshots else {**before, "fsync_count": 0}
    differences = [
        key
        for key in ("files", "store_digest", "journal_digest", "intent_digest", "lock_state")
        if before[key] != after[key]
    ]
    return {
        "resolved_argv": _canonical_paths(argv, ws),
        "plan_fingerprint": _digest(writer_calls[0] if writer_calls else preview),
        "preview_fingerprint": _digest(preview),
        "stdin_isatty": tty,
        "input_bytes_sequence": decision_input.consumed,
        "input_read_count": decision_input.read_count,
        "prompt_count": stderr.getvalue().count(CHOICE + "\n"),
        "prompt_bytes": (CHOICE + "\n").encode("ascii").hex(),
        "flush_count_before_read": first_read.get("flush_count", stderr.flush_count),
        "pre_read_store_digest": first_read["store_digest"],
        "pre_read_journal_digest": first_read["journal_digest"],
        "pre_read_intent_digest": first_read["intent_digest"],
        "pre_read_lock_state": first_read["lock_state"],
        "pre_read_fsync_count": first_read["fsync_count"],
        "preview_fully_emitted": first_read.get("preview_fully_emitted", True),
        "choice_fully_emitted": first_read.get("choice_fully_emitted", True),
        "visible_stream_flushed": first_read.get("visible_stream_flushed", True),
        "read_snapshots": read_snapshots,
        "writer_call_count": len(writer_calls),
        "writer_plan": writer_calls[0] if writer_calls else None,
        "report": _canonical_paths(report.to_json(), ws),
        "exit_code": process_exit,
        "post_store_digest": after["store_digest"],
        "post_journal_digest": after["journal_digest"],
        "post_intent_digest": after["intent_digest"],
        "post_lock_state": after["lock_state"],
        "post_fsync_count": len(fsync_calls),
        "full_difference_list": differences,
        "stderr": _canonical_paths(stderr.getvalue(), ws),
        "stdout": _canonical_paths(stdout.getvalue(), ws),
    }


def _instance_argv(ws: Workspace, *, confirm: bool = False, as_json: bool = False) -> list[str]:
    argv = ["--profile", "sandbox", "--root", str(ws.root)]
    if as_json:
        argv.append("--json")
    argv.extend(
        [
            "instance",
            "register",
            "coder.focus",
            "--source",
            "mensch",
            "--label",
            "Focus Coder",
            "--reference",
            "ref.focus",
        ]
    )
    if confirm:
        argv.append("--confirm")
    return argv


def _prepare_confirmation(root: Path) -> Workspace:
    ws = _workspace(root)
    journal = Journal(ws.journal_path)
    actor = plan_register(
        list(journal),
        "coder.focus",
        source="mensch",
        label="Focus Coder",
        reference="ref.actor",
    )
    write_instance_plan(ws, journal, actor)

    vocabulary = parse_iso6393_snapshot(
        b"deu\nund\nzxx\n", release_id="iso.2025", reference="ref.iso"
    )
    write_iso_prepare(ws, journal, IsoPreparePlan(vocabulary, root / "iso.txt"))
    iso_receipt = [event for event in journal if event.kind == "iso6393.snapshot.prepared"][-1]

    srt = root / "focus.srt"
    srt.write_bytes(b"1\n00:00:00,000 --> 00:00:01,000\nSPK: Text\n")
    draft = build_srt_draft(srt.read_bytes())
    mapping = root / "focus.tsv"
    mapping.write_bytes(
        f"index\tsegment_sha256\tlanguage\n0\t{draft.segments[0].sha256}\tdeu\n".encode("ascii")
    )
    language = plan_language_prepare(
        record_id="SANDBOX-001",
        srt_path=srt,
        mapping_path=mapping,
        actor="coder.focus",
        reference="ref.language",
        vocabulary=vocabulary,
        iso_snapshot_receipt=iso_receipt.digest,
        profile_normalize=ws.profile.normalize_record_id,
        profile_check=ws.profile.is_record_id,
        events=list(journal),
    )
    write_language_prepare(ws, journal, language)
    language_receipt = [
        event
        for event in journal
        if event.kind == "receipt.recorded"
        and event.payload.get("kind") == "transcript.segment_languages.prepared.v1"
    ][-1]
    ingest = plan_b3b_ingest_srt(
        record_id="SANDBOX-001",
        assignment=language.assignment,
        language_receipt_digest=language_receipt.digest,
    )
    write_b3b_ingest_srt(ws, journal, ingest)
    return ws


def _confirmation_argv(ws: Workspace, *, confirm: bool = False) -> list[str]:
    argv = [
        "--profile",
        "sandbox",
        "--root",
        str(ws.root),
        "transcript",
        "confirm",
        "SANDBOX-001",
        "--actor",
        "coder.focus",
    ]
    if confirm:
        argv.append("--confirm")
    return argv


def _assert_zero_effect(record: dict[str, Any]) -> None:
    assert record["pre_read_store_digest"] == record["post_store_digest"]
    assert record["pre_read_journal_digest"] == record["post_journal_digest"]
    assert record["pre_read_intent_digest"] == record["post_intent_digest"]
    assert record["pre_read_lock_state"] == record["post_lock_state"]
    assert record["pre_read_fsync_count"] == record["post_fsync_count"] == 0
    assert record["full_difference_list"] == []


def test_ux_01_and_ux_15_share_the_real_tty_abort_stimulus(tmp_path, monkeypatch):
    ws = _workspace(tmp_path / "shared" / "workspace")
    record = _invoke(
        ws,
        _instance_argv(ws),
        monkeypatch,
        tty=True,
        input_text="a\n",
        writer_name="write_instance_plan",
    )
    assert record["input_bytes_sequence"] == ["610a"]
    assert record["input_read_count"] == record["prompt_count"] == 1
    assert record["preview_fully_emitted"]
    assert record["choice_fully_emitted"]
    assert record["visible_stream_flushed"]
    assert record["writer_call_count"] == 0
    assert record["report"]["status"] == "ACTION_NEEDED"
    assert record["report"]["reason_code"] == "ACTION_B3B_USER_ABORTED"
    assert record["report"]["changed"] == []
    assert record["report"]["details"]["operation_result"] == "NONE"
    assert record["exit_code"] == 3
    _assert_zero_effect(record)
    equivalence = {
        "equivalence_id": "UX-TTY-ABORT-A-01-15",
        "members": ["UX-01", "UX-15"],
        "shared_stimulus_fingerprint": _digest(
            {
                "argv": record["resolved_argv"],
                "plan": record["plan_fingerprint"],
                "preview": record["preview_fingerprint"],
                "stdin_isatty": record["stdin_isatty"],
                "input_bytes_sequence": record["input_bytes_sequence"],
                "pre_read_store_digest": record["pre_read_store_digest"],
                "pre_read_journal_digest": record["pre_read_journal_digest"],
            }
        ),
    }
    assert equivalence["members"] == ["UX-01", "UX-15"]


def test_ux_03_eof_is_a_consumed_safe_abort(tmp_path, monkeypatch):
    ws = _workspace(tmp_path / "eof" / "workspace")
    record = _invoke(
        ws,
        _instance_argv(ws),
        monkeypatch,
        tty=True,
        input_text="",
        writer_name="write_instance_plan",
    )
    assert record["input_bytes_sequence"] == [""]
    assert record["input_read_count"] == record["prompt_count"] == 1
    assert record["report"]["reason_code"] == "ACTION_B3B_USER_ABORTED"
    assert record["exit_code"] == 3 and record["writer_call_count"] == 0
    _assert_zero_effect(record)


def test_ux_13_non_tty_never_reads_and_requires_confirm(tmp_path, monkeypatch):
    ws = _workspace(tmp_path / "non-tty" / "workspace")
    record = _invoke(
        ws,
        _instance_argv(ws),
        monkeypatch,
        tty=False,
        input_text="must-not-read",
        writer_name="write_instance_plan",
        fail_on_read=True,
    )
    assert record["input_read_count"] == record["prompt_count"] == 0
    assert record["writer_call_count"] == 0
    assert record["report"]["reason_code"] == "ACTION_B3B_CONFIRM_REQUIRED"
    assert record["exit_code"] == 3
    _assert_zero_effect(record)


@pytest.mark.parametrize(
    ("input_text", "prompts", "reason_code", "writer_calls"),
    [
        pytest.param("x\na\n", 2, "ACTION_B3B_USER_ABORTED", 0, id="invalid-then-a"),
        pytest.param(" \t\na\n", 2, "ACTION_B3B_USER_ABORTED", 0, id="empty-then-a"),
        pytest.param("A\n", 1, "ACTION_B3B_USER_ABORTED", 0, id="uppercase-a"),
        pytest.param("B\n", 1, "READY_B3B_WRITTEN", 1, id="uppercase-b"),
    ],
)
def test_invalid_and_ascii_case_choices_are_consumed(
    input_text, prompts, reason_code, writer_calls, tmp_path, monkeypatch
):
    ws = _workspace(tmp_path / reason_code / str(prompts) / "workspace")
    record = _invoke(
        ws,
        _instance_argv(ws),
        monkeypatch,
        tty=True,
        input_text=input_text,
        writer_name="write_instance_plan",
    )
    assert record["prompt_count"] == prompts
    assert record["input_read_count"] == prompts
    assert record["writer_call_count"] == writer_calls
    assert record["report"]["reason_code"] == reason_code
    if writer_calls == 0:
        _assert_zero_effect(record)
    if prompts == 2:
        assert record["read_snapshots"][1]["store_digest"] == record["pre_read_store_digest"]
        assert record["read_snapshots"][1]["journal_digest"] == record["pre_read_journal_digest"]
        assert record["read_snapshots"][1]["fsync_count"] == 0


def test_ux_05_b_and_ux_14_confirm_use_the_same_real_confirm_plan(tmp_path, monkeypatch):
    source = _prepare_confirmation(tmp_path / "prepared" / "workspace")
    b_root = tmp_path / "tty-b" / "workspace"
    confirm_root = tmp_path / "confirm" / "workspace"
    b_root.parent.mkdir(parents=True)
    confirm_root.parent.mkdir(parents=True)
    shutil.copytree(source.root, b_root)
    shutil.copytree(source.root, confirm_root)
    b_ws = Workspace(b_root, source.profile)
    confirm_ws = Workspace(confirm_root, source.profile)

    by_b = _invoke(
        b_ws,
        _confirmation_argv(b_ws),
        monkeypatch,
        tty=True,
        input_text="b\n",
        writer_name="write_confirmation",
    )
    by_flag = _invoke(
        confirm_ws,
        _confirmation_argv(confirm_ws, confirm=True),
        monkeypatch,
        tty=False,
        input_text="must-not-read",
        writer_name="write_confirmation",
        fail_on_read=True,
    )
    assert by_b["preview_fingerprint"] == by_flag["preview_fingerprint"]
    assert by_b["plan_fingerprint"] == by_flag["plan_fingerprint"]
    assert by_b["writer_plan"] == by_flag["writer_plan"]
    assert by_b["input_bytes_sequence"] == ["620a"]
    assert by_b["prompt_count"] == by_b["input_read_count"] == 1
    assert by_flag["prompt_count"] == by_flag["input_read_count"] == 0
    for record in (by_b, by_flag):
        assert record["writer_call_count"] == 1
        assert record["report"]["status"] == "READY"
        assert record["report"]["reason_code"] == "READY_B3B_WRITTEN"
        assert record["report"]["details"]["operation_result"] == "WRITTEN"
        assert record["exit_code"] == 0
        assert record["pre_read_store_digest"] != record["post_store_digest"]
        assert record["pre_read_journal_digest"] != record["post_journal_digest"]
        assert record["pre_read_intent_digest"] != record["post_intent_digest"]
        events = record["report"]["details"]["events"]
        assert events == [
            "operation.intent.recorded",
            "artifact.produced",
            "decision.recorded",
        ]


@pytest.mark.parametrize("case", CASES, ids=[case["norm_id"] for case in CASES])
def test_b3b_norm_contract(case, tmp_path, monkeypatch):
    assert_case(case, tmp_path, monkeypatch)
