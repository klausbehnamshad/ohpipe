"""Rote Vertragstests für Serie 3a.

Diese Datei beschreibt nur den gewünschten Rand. Produktivcode gehört erst in
die anschließende Grünphase.
"""

from __future__ import annotations

import io
import json
import shlex
from pathlib import Path

import pytest

from ohpipe.policies.exit_contract import Report, Status

from ._forge import REPORT_LABELS, cli, journal_path, report_lines


#: Eine Wahrheit, nicht zwei: dieselbe Labelfolge, die `report_lines` liest.
SIX_LINES = REPORT_LABELS
OHPIPE_COMMANDS = {"doctor", "init", "status", "ingest"}
RECOVERY_CODE = "RECOVER_STORE_FROM_BACKUP"
RECOVERY_TEXT = "Store aus dem geprüften Backup wiederherstellen."


def _labels(output: str) -> list[str]:
    return [line.split(":", 1)[0].strip() for line in output.strip().splitlines()]


def _values(output: str) -> dict[str, str]:
    return {
        line.split(":", 1)[0].strip(): line.split(":", 1)[1].strip()
        for line in output.strip().splitlines()
        if ":" in line and line.split(":", 1)[0].strip() in SIX_LINES
    }


def _command_identity(command: str) -> str:
    """Vergleicht Handlungen, nicht kosmetische CLI-Varianten."""
    tokens = shlex.split(command.split("#", 1)[0])
    if not tokens:
        return ""
    if tokens[0] != "ohpipe":
        return tokens[0]
    return next((token for token in tokens[1:] if token in OHPIPE_COMMANDS), "ohpipe")


def _render(report: Report) -> str:
    stream = io.StringIO()
    report.render(stream, color=False)
    return stream.getvalue()


def test_report_renders_the_six_lines_in_contract_order():
    report = Report(
        status=Status.READY,
        next_command="ohpipe init",
        check="ohpipe doctor",
    )

    rendered = _render(report)

    assert _labels(rendered) == list(SIX_LINES)
    assert _values(rendered)["CHECK"] == "ohpipe doctor"
    assert _values(rendered)["RECOVERY"] == "—"


def test_json_adds_three_fields_without_renaming_existing_fields():
    report = Report(
        status=Status.STOP,
        check="ohpipe doctor",
        recovery_code=RECOVERY_CODE,
        recovery_text=RECOVERY_TEXT,
    )

    payload = report.to_json()

    assert payload["next"] is None
    assert payload["check"] == "ohpipe doctor"
    assert payload["recovery_code"] == RECOVERY_CODE
    assert payload["recovery_text"] == RECOVERY_TEXT
    assert {
        "status",
        "exit_code",
        "reason",
        "reason_code",
        "changed",
        "next",
        "check",
        "recovery_code",
        "recovery_text",
        "upload_safe",
        "source_data_touched",
        "details",
    } <= payload.keys()
    assert "recovery" not in payload


def test_cli_json_always_exposes_the_three_additive_fields(tmp_path: Path):
    result = cli("doctor", "--json", root=tmp_path / "missing")

    payload = json.loads(result.stdout)

    assert "check" in payload
    assert "recovery_code" in payload
    assert "recovery_text" in payload
    assert "recovery" not in payload


def test_recovery_has_one_canonical_text_representation():
    report = Report(
        status=Status.STOP,
        check="ohpipe doctor",
        recovery_code=RECOVERY_CODE,
        recovery_text=RECOVERY_TEXT,
    )

    assert _render(report).splitlines()[-1] == f"RECOVERY: {RECOVERY_CODE} — {RECOVERY_TEXT}"


def test_absent_recovery_has_the_explicit_placeholder():
    report = Report(status=Status.READY, next_command="ohpipe init", check="ohpipe doctor")

    assert _render(report).splitlines()[-1] == "RECOVERY: —"
    assert report.to_json()["recovery_code"] is None
    assert report.to_json()["recovery_text"] is None


@pytest.mark.parametrize(
    ("recovery_code", "recovery_text"),
    [(RECOVERY_CODE, None), (None, RECOVERY_TEXT)],
)
def test_recovery_code_and_text_are_an_indivisible_pair(recovery_code, recovery_text):
    with pytest.raises(ValueError, match="recovery"):
        Report(
            status=Status.STOP,
            recovery_code=recovery_code,
            recovery_text=recovery_text,
        )


def test_next_without_recovery_is_valid():
    report = Report(status=Status.ACTION_NEEDED, next_command="ohpipe init")

    assert _values(_render(report))["NEXT"] == "ohpipe init"
    assert _values(_render(report))["RECOVERY"] == "—"


def test_recovery_without_next_is_valid():
    report = Report(
        status=Status.STOP,
        recovery_code=RECOVERY_CODE,
        recovery_text=RECOVERY_TEXT,
    )

    assert _values(_render(report))["NEXT"] == "—"
    assert _values(_render(report))["RECOVERY"] == f"{RECOVERY_CODE} — {RECOVERY_TEXT}"


def test_next_and_recovery_are_mutually_exclusive():
    with pytest.raises(ValueError, match="NEXT|Recovery|recovery"):
        Report(
            status=Status.STOP,
            next_command="ohpipe init",
            recovery_code=RECOVERY_CODE,
            recovery_text=RECOVERY_TEXT,
        )


@pytest.mark.parametrize("line_break", ["\n", "\r", "\x85", "\u2028", "\u2029"])
@pytest.mark.parametrize("field", ["next_command", "check", "recovery_code", "recovery_text"])
def test_no_report_field_may_embed_a_line_break(field: str, line_break: str):
    """Ein einzelner Feldwert darf den festen Sechszeiler nicht um eine Zeile
    erweitern \u2014 das Integrit\u00e4tsargument gilt f\u00fcr ALLE vier Textfelder, nicht
    nur f\u00fcr Recovery."""
    payload: dict[str, str] = {}
    if field in ("recovery_code", "recovery_text"):
        payload = {"recovery_code": RECOVERY_CODE, "recovery_text": RECOVERY_TEXT}
    payload[field] = f"vorher{line_break}nachher"

    with pytest.raises(ValueError, match="Zeilenumbruch|line break"):
        Report(status=Status.STOP, **payload)


def test_failed_doctor_never_recommends_doctor_as_next(tmp_path: Path):
    """Optionen und Kommentare machen aus der Schleife keinen Fortschritt."""
    root = tmp_path / "data"
    assert cli("init", root=root).returncode == 0
    journal_path(root).write_text("{kaputt\n", encoding="utf-8")

    result = cli("doctor", root=root)
    values = _values(result.stdout)

    assert result.returncode == 1
    assert _command_identity(values["NEXT"]) != "doctor"


def test_caught_cli_error_offers_a_read_only_resolution_path(tmp_path: Path):
    """Ein unbekanntes Profil hat keinen sicheren, zustandsändernden Resolver:
    die mitgelieferten Profile stehen in der Meldung, die korrigierte
    Wiederholung ist read-only. Der Auflösungsweg steht daher in CHECK, nicht in
    NEXT (Adjudikation Ausgang b) — NEXT bleibt der ausdrückliche Platzhalter."""
    result = cli("status", "--profile", "does-not-exist", root=tmp_path / "data")

    values = _values(result.stdout)

    assert result.returncode == 2
    assert values["NEXT"] == "—"
    assert values["CHECK"] != "—"


@pytest.mark.parametrize("status", [Status.READY, Status.ACTION_NEEDED, Status.CONFIG, Status.STOP])
def test_the_six_lines_keep_their_order_for_every_status(status: Status):
    """Die feste Reihenfolge gilt in JEDEM Status, nicht nur im Happy Path."""
    assert _labels(_render(Report(status=status))) == list(SIX_LINES)


@pytest.mark.parametrize(
    "verkettet",
    ["ohpipe doctor; rm -rf x", "ohpipe doctor | tee log", "a && b", 'ohpipe "offen'],
)
def test_check_must_be_exactly_one_command(verkettet: str):
    """CHECK ist genau ein Befehl: keine Verkettung, shlex-parsebar."""
    with pytest.raises(ValueError, match="check"):
        Report(status=Status.STOP, check=verkettet)


def test_check_allows_a_single_command_with_a_trailing_comment():
    """Ein `#`-Kommentar bleibt erlaubt — dieselbe Konvention wie bei NEXT."""
    report = Report(status=Status.READY, check="ohpipe --json doctor   # Befund sichern")

    assert "ohpipe --json doctor" in _values(_render(report))["CHECK"]


# --------------------------------------------- der Leser prüft sich selbst
#
# `report_lines` ersetzt seit dieser Serie `four_lines`. Ein Leser, der die
# Reihenfolge zusichert, ohne dass jemand die Zusicherung geprüft hat, ist
# dieselbe Sorte Zusage wie der Vierzeiler, den er ablöst.


def test_the_report_reader_accepts_a_correct_six_line_block():
    ausgabe = _render(Report(status=Status.READY, next_command="ohpipe status"))
    gelesen = report_lines(ausgabe)
    assert list(gelesen) == list(REPORT_LABELS)
    assert gelesen["NEXT"] == "ohpipe status"


def test_the_report_reader_rejects_a_shuffled_report():
    """Ein geschütteltes Protokoll bestand bei ``four_lines`` — hier fällt es."""
    zeilen = _render(Report(status=Status.READY, next_command="ohpipe status")).strip().split("\n")
    geschuettelt = "\n".join([zeilen[0], zeilen[2], zeilen[1], *zeilen[3:]])
    with pytest.raises(AssertionError, match="Reihenfolge"):
        report_lines(geschuettelt)


def test_the_report_reader_rejects_a_truncated_report():
    zeilen = _render(Report(status=Status.READY, next_command="ohpipe status")).strip().split("\n")
    with pytest.raises(AssertionError, match="bricht nach"):
        report_lines("\n".join(zeilen[:4]))


def test_the_report_reader_rejects_output_without_a_report():
    with pytest.raises(AssertionError, match="kein Bericht"):
        report_lines("irgendetwas anderes\nzweite Zeile\n")
