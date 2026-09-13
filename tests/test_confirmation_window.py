"""Confirmation must recheck the displayed selection before writing its effects.

All material, identities and keys are synthetic. Interleavings happen either
at the visible prompt or after acquiring the common writer lock. The latter
distinguishes a protected check from an earlier, race-prone check.
"""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

import ohpipe.cli.main as cli
from ohpipe.application import operation_recovery
from ohpipe.application.confirmation import write_confirmation
from ohpipe.application.instance_registry import plan_register, plan_retire
from ohpipe.journal import Journal

from . import test_b3b_ux as helpers


def _files(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def prepared(tmp_path, monkeypatch):
    key = os.urandom(32)
    path = tmp_path / "journal.key"
    path.write_bytes(key)
    path.chmod(0o600)
    monkeypatch.setenv("OHPIPE_JOURNAL_KEY", str(path))
    monkeypatch.setattr(helpers, "Journal", lambda path: Journal(path, key=key))
    ws = helpers._prepare_confirmation(tmp_path / "workspace")
    return ws, Journal(ws.journal_path, key=key)


CASES = (
    ("unchanged", False, False),
    ("unchanged", True, False),
    ("retired", False, True),
    ("human_added", True, True),
    ("human_added_then_retired", True, True),
    ("human_added", False, False),
    ("machine_added", True, False),
    ("revision_changed", False, True),
    ("revision_changed_then_restored", False, True),
)


@pytest.mark.parametrize("boundary", ["prompt", "writer_lock"])
@pytest.mark.parametrize("change,automatic,blocked", CASES)
def test_confirmation_rechecks_its_basis(
    prepared, monkeypatch, boundary, change, automatic, blocked
):
    ws, journal = prepared
    snapshots = []

    def interleave():
        assert not snapshots
        if change == "retired":
            payload = plan_retire(
                list(journal), "coder.focus", reference="synthetic.retire"
            ).payload
            journal.append("instance.retired", payload)
        elif change in {"human_added", "human_added_then_retired", "machine_added"}:
            machine = change == "machine_added"
            plan = plan_register(
                list(journal),
                "coder.synthetic.other",
                source="maschine" if machine else "mensch",
                label="Synthetic Other",
                reference="synthetic.register",
                **(
                    {"model": "fixture-model", "parametersatz": "synthetic.parameters"}
                    if machine
                    else {}
                ),
            )
            journal.append("instance.registered", plan.payload)
            if change == "human_added_then_retired":
                plan = plan_retire(
                    list(journal), "coder.synthetic.other", reference="synthetic.retire"
                )
                journal.append("instance.retired", plan.payload)
        elif change.startswith("revision_changed"):
            old = next(
                e.payload["sha256"]
                for e in reversed(list(journal))
                if e.kind == "artifact.produced"
                and e.payload.get("artifact") == "transcript.revision"
            )
            journal.append(
                "artifact.produced",
                {"artifact": "transcript.revision", "sha256": "f" * 64},
                record_id="SANDBOX-001",
            )
            if change == "revision_changed_then_restored":
                journal.append(
                    "artifact.produced",
                    {"artifact": "transcript.revision", "sha256": old},
                    record_id="SANDBOX-001",
                )
        snapshots.append((_files(ws.root), len(list(journal))))

    original_lock = operation_recovery.workspace_write_lock

    @contextmanager
    def writer_lock(root):
        with original_lock(root) as fd:
            if boundary == "writer_lock":
                interleave()
            yield fd

    class Input(io.StringIO):
        def isatty(self):
            return True

        def readline(self, *args, **kwargs):
            if boundary == "prompt":
                interleave()
            return super().readline(*args, **kwargs)

    monkeypatch.setattr(operation_recovery, "workspace_write_lock", writer_lock)
    monkeypatch.setattr(cli.sys, "stdin", Input("b\n"))
    argv = helpers._confirmation_argv(ws)
    if automatic:
        argv = argv[:-2]
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli.main(["--json", *argv])
    report = json.loads(stdout.getvalue())
    assert len(snapshots) == 1
    before, event_count = snapshots[0]
    if blocked:
        assert (code, report["status"], report["reason_code"]) == (
            3,
            "ACTION_NEEDED",
            "ACTION_B3B_CONFIRMATION_STALE",
        )
        assert report["changed"] == [] and report["details"]["operation_result"] == "NONE"
        assert _files(ws.root) == before
        assert len(list(journal)) == event_count
    else:
        assert code == 0 and report["reason_code"] == "READY_B3B_WRITTEN"
        assert [e.kind for e in list(journal)[event_count:]] == [
            "operation.intent.recorded",
            "artifact.produced",
            "decision.recorded",
            "anchor.checked",
        ]
    journal.verify()
    with (ws.governance / ".b3b-workspace-write.lock").open("rb") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fcntl.flock(handle, fcntl.LOCK_UN)


def test_another_process_can_retire_during_preview_but_cannot_authorize_the_old_plan(
    prepared, monkeypatch
):
    ws, journal = prepared
    snapshots = []

    class Input(io.StringIO):
        def isatty(self):
            return True

        def readline(self, *args, **kwargs):
            env = {**os.environ, "PYTHONPATH": str(Path(cli.__file__).resolve().parents[2])}
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "ohpipe.cli.main",
                    "--profile",
                    "sandbox",
                    "--root",
                    str(ws.root),
                    "instance",
                    "retire",
                    "coder.focus",
                    "--reference",
                    "synthetic.retire",
                    "--confirm",
                ],
                env=env,
                capture_output=True,
                timeout=20,
            )
            assert result.returncode == 0
            snapshots.append(_files(ws.root))
            return super().readline(*args, **kwargs)

    monkeypatch.setattr(cli.sys, "stdin", Input("b\n"))
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        code = cli.main(["--json", *helpers._confirmation_argv(ws)])
    report = json.loads(stdout.getvalue())
    assert code == 3 and report["reason_code"] == "ACTION_B3B_CONFIRMATION_STALE"
    assert _files(ws.root) == snapshots[0]
    journal.verify()


def test_competing_confirmation_is_stale_but_exact_retry_and_fresh_preview_work(prepared):
    ws, journal = prepared
    args = cli.build_parser().parse_args(helpers._confirmation_argv(ws))
    first, _ = cli._transcript_confirmation_plan(ws, list(journal), args)
    second, _ = cli._transcript_confirmation_plan(ws, list(journal), args)
    assert first.decision.decision_id != second.decision.decision_id
    assert write_confirmation(ws, journal, first).status.value == "READY"
    before = _files(ws.root)
    result = write_confirmation(ws, journal, second)
    assert result.reason_code == "ACTION_B3B_CONFIRMATION_STALE"
    assert _files(ws.root) == before
    assert write_confirmation(ws, journal, first).reason_code == "READY_B3B_NULLDURCHGANG"
    assert _files(ws.root) == before
    fresh, _ = cli._transcript_confirmation_plan(ws, list(journal), args)
    assert write_confirmation(ws, journal, fresh).reason_code == "READY_B3B_WRITTEN"
    journal.verify()
