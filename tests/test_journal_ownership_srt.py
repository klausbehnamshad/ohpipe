"""Evidenzkette, Ownership/Cutover und strenger SRT-Ingest.

Herkunft:
  - Journal: Ersatz fuer den reparaturanfaelligen BUILDER_STATE
  - Ownership: ZUSAMMENFASSUNG 2026-07-14 ("lief noch - mit seinem EIGENEN
    Manifest und seinem EIGENEN BUILDER_STATE")
  - SRT: RUNBOOK_neues-interview ("Ein leerer Lauf darf nicht wie Erfolg aussehen")
"""

from __future__ import annotations

import json

import pytest

from ohpipe.adapters.input.srt import SrtParseError, parse_srt
from ohpipe.journal import Journal, JournalBroken
from ohpipe.policies.ownership import (
    LEGACY_RUNTIME,
    THIS_RUNTIME,
    CutoverLedger,
    OwnershipError,
)

# Seit der Nutzlast-Allowlist (domain/events.py) gibt es keine
# Platzhalterarten mehr. Diese Tests pruefen Kettenmechanik, nicht
# Semantik — sie brauchen irgendeine ECHTE Art mit stabiler Nutzlast.
KIND = "anchor.checked"
REC = "SANDBOX-001"


# ---------------------------------------------------------------- journal


def test_journal_chain_verifies(tmp_path):
    j = Journal(tmp_path / "journal.jsonl")
    j.append("workspace.initialised", {"profile": "sandbox", "root": str(tmp_path), "version": "0"})
    j.append(
        "source.ingested",
        {
            "record_id": "SANDBOX-001",
            "sha256": "a" * 64,
            "media_type": "text/srt",
            "filename": "SANDBOX-001.srt",
            "bytes": 42,
        },
        record_id="SANDBOX-001",
    )
    j.verify()
    assert j.head()[0] == 2


def test_tampering_with_a_line_breaks_the_chain(tmp_path):
    p = tmp_path / "journal.jsonl"
    j = Journal(p)
    j.append("anchor.checked", {"artifact": "erste", "outcome": "exact"}, record_id=REC)
    j.append("anchor.checked", {"artifact": "zweite", "outcome": "exact"}, record_id=REC)
    lines = p.read_text(encoding="utf-8").strip().split("\n")
    row = json.loads(lines[0])
    row["payload"]["outcome"] = "missing"
    lines[0] = json.dumps(row, ensure_ascii=False, sort_keys=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(JournalBroken, match="nachträglich verändert"):
        j.verify()


def test_removing_a_line_breaks_the_chain(tmp_path):
    p = tmp_path / "journal.jsonl"
    j = Journal(p)
    for i in range(3):
        j.append("anchor.checked", {"artifact": f"a{i}", "outcome": "exact"}, record_id=REC)
    lines = p.read_text(encoding="utf-8").strip().split("\n")
    p.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    with pytest.raises(JournalBroken):
        j.verify()


def test_journal_has_no_update_or_delete_path():
    assert not hasattr(Journal, "update")
    assert not hasattr(Journal, "delete")


# -------------------------------------------------------------- ownership


def test_unknown_records_belong_to_the_legacy_runtime(tmp_path):
    """Der Default ist nicht 'niemand', sondern 'der Zustand vor dem Cutover'.
    Damit blockiert ohpipe von sich aus - ohne dass DINOH etwas tun muss."""
    led = CutoverLedger()
    assert led.owner_of("CHILDLUX-0003") == LEGACY_RUNTIME
    assert not led.may_write("CHILDLUX-0003")


def test_writing_a_foreign_record_is_refused():
    led = CutoverLedger()
    with pytest.raises(OwnershipError, match="Kein Dual-Write"):
        led.require_write("CHILDLUX-0003")


def test_adoption_needs_a_decision_reference():
    led = CutoverLedger()
    with pytest.raises(ValueError):
        led.adopt("CHILDLUX-0007", reference="")


def test_adoption_transfers_and_is_logged():
    led = CutoverLedger()
    t = led.adopt(
        "CHILDLUX-0007", reference="PI-2026-09-01-0007", artifact_hashes={"transcript": "a" * 64}
    )
    assert led.may_write("CHILDLUX-0007")
    assert t.from_runtime == LEGACY_RUNTIME and t.to_runtime == THIS_RUNTIME
    assert len(led.transfers) == 1
    led.require_write("CHILDLUX-0007")  # wirft nicht


def test_double_adoption_is_refused():
    led = CutoverLedger()
    led.adopt("CHILDLUX-0007", reference="r1")
    with pytest.raises(OwnershipError, match="bereits"):
        led.adopt("CHILDLUX-0007", reference="r2")


def test_retirement_is_derived_not_a_switch():
    led = CutoverLedger()
    active = {"CHILDLUX-0006", "CHILDLUX-0007"}
    led.adopt("CHILDLUX-0007", reference="r")
    assert not led.retired(LEGACY_RUNTIME, active)  # 0006 gehoert noch dem Altsystem
    led.adopt("CHILDLUX-0006", reference="r2")
    assert led.retired(LEGACY_RUNTIME, active)


def test_ledger_roundtrip(tmp_path):
    led = CutoverLedger()
    led.adopt("CHILDLUX-0007", reference="PI-1", artifact_hashes={"t": "x" * 64})
    p = tmp_path / "cutover.json"
    led.save(p)
    back = CutoverLedger.load(p)
    assert back.owner_of("CHILDLUX-0007") == THIS_RUNTIME
    assert back.transfers[0].reference == "PI-1"
    assert not back.may_write("CHILDLUX-0001")


# -------------------------------------------------------------------- srt

GOOD = """1
00:00:01,000 --> 00:00:04,000
INTERVIEWER: Erzaehlen Sie mir von der Schule.

2
00:00:04,500 --> 00:00:09,000
Wir sind jeden Morgen zu Fuss gegangen,
auch im Winter.
"""


def test_good_srt_parses_with_speaker_and_timecodes():
    segs = parse_srt(GOOD)
    assert len(segs) == 2
    assert segs[0].speaker == "INTERVIEWER"
    assert segs[0].start_ms == 1000 and segs[0].end_ms == 4000
    assert "auch im Winter" in segs[1].text


def test_broken_block_is_rejected_not_partially_read():
    bad = GOOD + "\n3\nkein zeitcode hier\nText.\n"
    with pytest.raises(SrtParseError, match="unlesbare"):
        parse_srt(bad)


def test_empty_input_never_looks_like_success():
    with pytest.raises(SrtParseError):
        parse_srt("\n\n   \n")


def test_backwards_timecodes_are_rejected():
    rev = """1
00:00:10,000 --> 00:00:12,000
Zweitens.

2
00:00:01,000 --> 00:00:03,000
Erstens.
"""
    with pytest.raises(SrtParseError, match="rückwärts"):
        parse_srt(rev)


def test_end_before_start_is_rejected():
    with pytest.raises(SrtParseError):
        parse_srt("1\n00:00:09,000 --> 00:00:04,000\nText.\n")
