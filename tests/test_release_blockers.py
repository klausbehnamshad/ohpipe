"""Regressionstests zu den Release-Blockern des ersten Reviews (03.08.2026).

Jeder Test hier reproduziert einen Befund, der am gebauten Stand vorführbar
war. Sie stehen bewusst in einer eigenen Datei: Es sind keine portierten
Altzusicherungen, sondern Fehler dieses Repositories.
"""

from __future__ import annotations

import concurrent.futures as cf
import hashlib
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from ohpipe.adapters.input.srt import SrtParseError, parse_srt
from ohpipe.application.replay import replay
from ohpipe.domain.revision_serialization import PROJECTION_VERSION
from ohpipe.domain.transcript import Segment, TranscriptRevision
from ohpipe.journal import Journal
from ohpipe.policies.authority import Authority
from ohpipe.policies.exit_contract import Status
from ohpipe.policies.ownership import CutoverLedger, OwnershipError

# Seit der Nutzlast-Allowlist (domain/events.py) gibt es keine
# Platzhalterarten mehr. Diese Tests pruefen Kettenmechanik, nicht
# Semantik — sie brauchen irgendeine ECHTE Art mit stabiler Nutzlast.
KIND = "anchor.checked"
REC = "SANDBOX-001"

REPO = Path(__file__).resolve().parents[1]


def _cli(*args: str, root: Path | None = None) -> subprocess.CompletedProcess:
    env = {"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO / "src")}
    if root is not None:
        env["OHPIPE_DATA_ROOT"] = str(root)
    return subprocess.run(
        [sys.executable, "-m", "ohpipe.cli.main", *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=REPO,
        check=False,
    )


# ------------------------------------------------------------------- B1


def test_status_never_reports_ready_for_a_broken_journal(tmp_path):
    """Der schlimmste Befund: `status` meldete Exit 0, wo `doctor` Exit 1 gab.
    Grün ohne Prüfung verletzt „0 = vollständig geprüft" in der gefährlichen
    Richtung."""
    root = tmp_path / "data"
    assert _cli("--profile", "sandbox", "init", root=root).returncode == 0

    p = root / "_governance" / "journal.jsonl"
    lines = p.read_text(encoding="utf-8").strip().split("\n")
    row = json.loads(lines[0])
    row["payload"]["profile"] = "MANIPULIERT"
    lines[0] = json.dumps(row, ensure_ascii=False, sort_keys=True)
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")

    st = _cli("--profile", "sandbox", "status", root=root)
    dr = _cli("--profile", "sandbox", "doctor", root=root)
    assert st.returncode == 1, "status muss fail-closed stoppen"
    assert st.returncode == dr.returncode, "status und doctor dürfen nicht divergieren"
    assert "STOP" in st.stdout


def test_a_bare_event_does_not_make_a_record_ready():
    """Es genügte irgendein Ereignis mit record_id, damit ein Record als READY
    erschien."""
    j = [
        type(
            "E",
            (),
            {
                "record_id": "SANDBOX-001",
                "kind": "irgendwas",
                "payload": {},
                "at": "2026-09-01T10:00:00+00:00",
            },
        )(),
    ]
    view = replay(j)["SANDBOX-001"]
    assert view.status is not Status.READY
    assert view.status is Status.ACTION_NEEDED


# ------------------------------------------------------------------- B4


def test_the_journal_survives_concurrent_writers(tmp_path):
    """30 gleichzeitige Schreiber brachen die Kette in 5 von 5 Läufen:
    O_APPEND schützt das Schreiben, nicht die Vergabe der Sequenznummer."""
    j = Journal(tmp_path / "j.jsonl")
    with cf.ThreadPoolExecutor(30) as ex:
        list(
            ex.map(
                lambda i: j.append(KIND, {"artifact": f"a{i}", "outcome": "exact"}, record_id=REC),
                range(30),
            )
        )
    j.verify()
    assert j.head()[0] == 30


def test_the_lock_file_is_not_part_of_the_evidence(tmp_path):
    j = Journal(tmp_path / "j.jsonl")
    j.append(KIND, {"artifact": "a", "outcome": "exact"}, record_id=REC)
    assert (tmp_path / "j.jsonl.lock").exists()
    assert len(list(j)) == 1


# ------------------------------------------------------------------- B5


def test_default_runtime_cannot_be_declared_in_the_file(tmp_path):
    """Eine Zeile in einer JSON-Datei darf einen nicht zum Eigentümer aller
    unbekannten Records machen."""
    p = tmp_path / "cutover.json"
    p.write_text(
        json.dumps({"version": 1, "default_runtime": "ohpipe", "owners": {}, "transfers": []})
    )
    with pytest.raises(OwnershipError, match="default_runtime"):
        CutoverLedger.load(p)


def test_retirement_cannot_be_claimed_from_an_empty_ledger():
    """Aus Unwissen folgt nicht Stilllegung, sondern ihr Gegenteil."""
    assert CutoverLedger().retired("dinoh") is False
    assert CutoverLedger().retired("dinoh", set()) is False
    assert CutoverLedger().retired("dinoh", {"CHILDLUX-0001"}) is False


def test_ownership_must_be_bound_to_the_journal(tmp_path):
    """Eine Uebergabe braucht ein Journalereignis UND eine echte Entscheidung.

    Runde 6: Eine erfundene Referenz reichte in einer korrekt HMAC-signierten
    Kette. HMAC beweist, dass ein Schluesselinhaber geschrieben hat - nicht,
    dass die behauptete menschliche Entscheidung existiert.
    """
    led = CutoverLedger()
    led.adopt("CHILDLUX-0007", reference="PI-1")
    j = Journal(tmp_path / "j.jsonl")
    assert led.verify_against(j), "unprotokollierte Uebergabe muss auffallen"

    sha = "a" * 64
    ok = Journal(tmp_path / "ok.jsonl")
    ok.append(
        "decision.recorded",
        {
            "record_id": "CHILDLUX-0007",
            "artifact": "cutover",
            "subject_sha256": sha,
            "verdict": "ACCEPT",
            "reference": "PI-1",
            "actor": "operator",
            "at": "2026-09-01T09:00:00+00:00",
        },
        record_id="CHILDLUX-0007",
    )
    ok.append(
        "record.adopted",
        {
            "record_id": "CHILDLUX-0007",
            "from": "dinoh",
            "to": "ohpipe",
            "reference": "PI-1",
            "decision_id": f"PI-1@{sha[:12]}",
        },
        record_id="CHILDLUX-0007",
    )
    assert led.verify_against(ok, authority=Authority.AUTHENTICATED) == []

    # Dieselbe Uebergabe OHNE die Entscheidung wird nicht wirksam.
    bad = Journal(tmp_path / "bad.jsonl")
    bad.append(
        "record.adopted",
        {
            "record_id": "CHILDLUX-0007",
            "from": "dinoh",
            "to": "ohpipe",
            "reference": "ERFUNDEN",
            "decision_id": "ERFUNDEN@" + "f" * 12,
        },
        record_id="CHILDLUX-0007",
    )
    truth = CutoverLedger.from_journal(bad, strict=False, authority=Authority.AUTHENTICATED)
    assert truth.owner_of("CHILDLUX-0007") == "dinoh"
    assert truth.problems


# ------------------------------------------------------- Transkriptidentität


def test_the_same_words_with_swapped_speakers_are_a_different_revision():
    """Für Oral History ist die Sprecherzuordnung nicht Beiwerk. Eine
    Bestätigung, die nur den Text bindet, würde beide Fassungen decken."""
    # Seit B3a sind `projection_version` und je Segment `language` Pflicht
    # (ADR 0028B-S, Teil P und S2); die Zusage des Tests bleibt unveraendert.
    a = TranscriptRevision.from_segments(
        [
            Segment(0, 0, 1000, "Ja.", speaker="A", language="deu"),
            Segment(1, 1000, 2000, "Nein.", speaker="B", language="deu"),
        ],
        projection_version=PROJECTION_VERSION,
    )
    b = TranscriptRevision.from_segments(
        [
            Segment(0, 0, 1000, "Ja.", speaker="B", language="deu"),
            Segment(1, 1000, 2000, "Nein.", speaker="A", language="deu"),
        ],
        projection_version=PROJECTION_VERSION,
    )
    assert a.text_sha256 == b.text_sha256
    assert a.sha256 != b.sha256


def test_shifted_timecodes_are_a_different_revision():
    a = TranscriptRevision.from_segments(
        [Segment(0, 0, 1000, "Ja.", speaker="A", language="deu")],
        projection_version=PROJECTION_VERSION,
    )
    b = TranscriptRevision.from_segments(
        [Segment(0, 500, 1500, "Ja.", speaker="A", language="deu")],
        projection_version=PROJECTION_VERSION,
    )
    assert a.sha256 != b.sha256


# ------------------------------------------------------------- SRT-Strenge


@pytest.mark.parametrize(
    "name,src",
    [
        ("ungültige Minuten/Sekunden", "1\n00:99:99,999 --> 00:99:99,999\nText.\n"),
        ("Müll um den Zeitcode", "1\nxx 00:00:01,000 --> 00:00:04,000 yy\nText.\n"),
        ("leer nach Sprecherpräfix", "1\n00:00:01,000 --> 00:00:04,000\nINTERVIEWER:\n"),
    ],
)
def test_the_strict_parser_is_actually_strict(name, src):
    with pytest.raises(SrtParseError):
        parse_srt(src)


def test_overlapping_segments_are_rejected():
    """Überlappung zählt dieselbe Zeit doppelt — jede spätere Coverage-Zahl
    misst dann etwas anderes, als sie behauptet."""
    src = "1\n00:00:01,000 --> 00:00:09,000\nA.\n\n2\n00:00:04,000 --> 00:00:12,000\nB.\n"
    with pytest.raises(SrtParseError, match="überlappen"):
        parse_srt(src)


# ------------------------------------------------- Operatorvertrag / Paket


def test_every_next_command_is_actually_callable(tmp_path):
    """Ein NEXT, das argparse ablehnt, ist schlimmer als keines."""
    root = tmp_path / "data"
    seen: set[str] = set()
    for args in (["--profile", "sandbox", "doctor"], ["doctor", "--profile", "sandbox"]):
        r = _cli(*args, "--json", root=root)
        nxt = json.loads(r.stdout)["next"]
        assert nxt, "jeder Report nennt genau einen nächsten Befehl"
        seen.add(nxt)
    for nxt in seen:
        if nxt.startswith("ohpipe") and "#" not in nxt and "export" not in nxt:
            argv = nxt.split()[1:]
            out = _cli(*argv, root=root)
            assert out.returncode in (0, 1, 2, 3)
            assert "unrecognized arguments" not in out.stderr, f"{nxt!r} ist nicht aufrufbar"


def test_both_argument_orders_work():
    a = _cli("--profile", "sandbox", "doctor")
    b = _cli("doctor", "--profile", "sandbox")
    assert "unrecognized arguments" not in (a.stderr + b.stderr)
    assert a.returncode == b.returncode == 2  # ohne Datenwurzel: CONFIG


def test_a_data_root_inside_the_repository_is_refused(tmp_path):
    r = _cli("--profile", "sandbox", "--root", str(REPO), "doctor")
    assert r.returncode == 2 and "im Repository" in r.stdout


@pytest.mark.skipif(not (REPO / "pyproject.toml").exists(), reason="kein Repo")
def test_the_wheel_contains_the_profiles(tmp_path):
    """Ein isoliert installiertes Wheel scheiterte mit FileNotFoundError,
    weil PROFILE_DIR einen Repository-Pfad annahm."""
    # Zwei Versuche: mit und ohne Build-Isolation. Ein stiller Skip waere hier
    # besonders schlecht — es ist der EINZIGE Test, der das Packaging prueft,
    # und genau er ist beim ersten Mal unbemerkt uebersprungen worden.
    # Der Quellbaum wird kopiert: pip legt build/ IM Quellverzeichnis an, und
    # auf einem nur eingeschraenkt beschreibbaren Mount scheitert das — der
    # Test wuerde dann die Verpackung anklagen statt das Dateisystem.
    src = tmp_path / "src-copy"
    shutil.copytree(
        REPO,
        src,
        ignore=shutil.ignore_patterns(
            ".git", "build", "*.egg-info", "__pycache__", ".pytest_cache", "_incoming", "_to_delete"
        ),
    )
    attempts = []
    for extra in ([], ["--no-build-isolation"]):
        out = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "-q",
                "-w",
                str(tmp_path),
                *extra,
                str(src),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        attempts.append(out)
        if out.returncode == 0:
            break
    else:
        if all("No module named pip" in a.stderr for a in attempts):
            pytest.skip("pip nicht verfügbar")
        pytest.fail("Wheel-Build fehlgeschlagen:\n" + attempts[-1].stderr[-400:])
    wheels = list(tmp_path.glob("ohpipe-*.whl"))
    assert wheels, "kein Wheel gebaut"
    names = zipfile.ZipFile(wheels[0]).namelist()
    assert any(n.endswith("profiles/sandbox/profile.toml") for n in names)
    assert any(n.endswith("profiles/childlux/profile.toml") for n in names)


# ------------------------------------------------ B3b-Vorcommitblocker


def test_b3b_norm_coverage_is_exactly_the_closed_522_sequence():
    path = REPO / "docs" / "b3b-norm-coverage.json"
    raw = path.read_bytes()
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    raw.decode("ascii")
    rows = json.loads(raw)
    counts = (
        ("E10", 48),
        ("REG", 23),
        ("ACT", 25),
        ("DEC", 70),
        ("ISO", 28),
        ("UX", 211),
        ("TOK", 31),
        ("LNG", 86),
    )
    expected = [
        f"{prefix}-{number:02d}" for prefix, count in counts for number in range(1, count + 1)
    ]
    assert len(rows) == 522
    assert [row["norm_id"] for row in rows] == expected


def test_b3b_norm_runner_has_no_arithmetic_case_reduction():
    source = (REPO / "tests" / "_b3b.py").read_text(encoding="utf-8")
    assert "case %" not in source
    assert "norm_id %" not in source
    assert "unknown" not in source.casefold() or "unbekannte stimulus.operation" in source


def test_b3b_keeps_both_data_root_followup_hints_byteequal():
    lines = [
        line
        for line in (REPO / "src" / "ohpipe" / "cli" / "main.py")
        .read_text(encoding="utf-8")
        .splitlines(keepends=True)
        if "~/ohpipe-data" in line
    ]
    assert len(lines) == 2
    assert hashlib.sha256("".join(lines).encode()).hexdigest() == (
        "87745be1ae983ee04cdbb8fd153c82522cfb22e29bb64802b4622f0d24984822"
    )


def test_b3b_norm_nodes_are_real_entrypoint_calls_not_assert_only_placeholders():
    source = (REPO / "tests" / "_b3b.py").read_text(encoding="utf-8")
    for call in (
        "check_payload(",
        "registry.register(",
        "parse_iso6393_snapshot(",
        "validate_token(",
        "parse_mapping(",
        "recovery_report(",
        "report.emit(",
    ):
        assert call in source
