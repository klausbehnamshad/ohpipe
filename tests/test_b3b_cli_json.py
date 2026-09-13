import io
import json

import pytest

from ohpipe.application.operation_recovery import b3b_report
from ohpipe.cli.main import build_parser
from ohpipe.policies.exit_contract import Status

from .test_b3b_ux import _instance_argv, _invoke, _workspace


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-021"])
def test_nested_language_template_grammar(_case):
    args = build_parser().parse_args(
        ["transcript", "language", "template", "a.srt", "--output", "a.tsv"]
    )
    assert args.b3b_action == "language_template"


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-022"])
def test_retry_and_confirm_are_representable_for_config_rejection(_case):
    args = build_parser().parse_args(
        ["instance", "retire", "--retry-intent", "a" * 64, "--confirm"]
    )
    assert args.retry_intent == "a" * 64 and args.confirm is True


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-023"])
def test_report_json_is_parseable_and_complete(_case):
    report = b3b_report(
        Status.READY,
        "READY_B3B_STATUS_VIEW",
        "sicht",
        operation_result="VIEW",
    )
    stream = io.StringIO()
    assert report.emit(as_json=True, stream=stream) == 0
    actual = json.loads(stream.getvalue())
    assert actual["details"]["operation_result"] == "VIEW"
    assert actual["source_data_touched"] is False


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-024"])
def test_unknown_nested_option_fails_argparse(_case):
    with pytest.raises(SystemExit) as error:
        build_parser().parse_args(
            ["iso6393", "prepare", "codes", "--release", "iso.1", "--unknown"]
        )
    assert error.value.code == 2


def test_json_keeps_preview_and_choice_on_stderr(tmp_path, monkeypatch):
    ws = _workspace(tmp_path / "json" / "workspace")
    record = _invoke(
        ws,
        _instance_argv(ws, as_json=True),
        monkeypatch,
        tty=True,
        input_text="a\n",
        writer_name="write_instance_plan",
    )
    output = json.loads(record["stdout"])
    assert output == record["report"]
    assert output["details"]["preview"]
    assert record["stderr"].startswith("B3B-VORSCHAU ")
    assert record["stderr"].endswith("[b] Bestaetigen / [a] Abbrechen\n")
