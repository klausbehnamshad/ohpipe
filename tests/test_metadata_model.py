"""Das Metadata Model — vendorte Fassung, Drift und erzwingbare Invarianten.

Quelle: IMM-Core v1.0, DOI 10.5281/zenodo.20507329. Die DCTAP ist die
maßgebliche Fassung; der JSON-Spiegel ist abgeleitet.
"""

from __future__ import annotations

import json
from importlib.resources import files

import pytest

from ohpipe.cli.main import PROFILE_DIR
from ohpipe.policies.metadata import REQUIRED_FIELDS, check_record, load_tap
from ohpipe.project import Profile

SCHEMA = files("ohpipe").joinpath("schemas", "metadata", "core.schema.json")


def test_the_vendored_mirror_has_not_drifted_from_the_tap():
    """Eine vendorte Kopie, die still driftet, war im Vorgängersystem ein
    realer Defekt: ein publiziertes Schema lag als Kopie im Repo, und niemand
    verglich."""
    tap = load_tap()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    assert set(schema["properties"]) == set(tap), "Felder weichen ab"
    assert set(schema["required"]) == {k for k, v in tap.items() if v.mandatory}
    assert set(schema["properties"]["accessRights"]["enum"]) == set(tap["accessRights"].enum)


def test_the_core_has_thirteen_fields_in_blocks():
    tap = load_tap()
    assert len(tap) == 13
    assert {v.block for v in tap.values()} == {"A", "B", "C"}  # D ist Phase 2


def test_required_fields_are_the_seven_from_block_a_and_b():
    assert set(REQUIRED_FIELDS) == {
        "record_id",
        "interview_date",
        "interviewer",
        "consent_status",
        "accessRights",
        "title",
        "language",
    }


def valid() -> dict:
    return {
        "record_id": "2026-09-01_C2DH_0007",
        "interview_date": "2026-09-01",
        "interviewer": "Operator",
        "consent_status": "research-only",
        "accessRights": "restricted",
        "title": "Synthetisches Testinterview",
        "language": "deu",
    }


def test_a_valid_record_passes():
    assert check_record(valid()) == []


@pytest.mark.parametrize("missing", REQUIRED_FIELDS)
def test_every_required_field_is_actually_required(missing):
    rec = valid()
    del rec[missing]
    assert any(missing in p for p in check_record(rec))


def test_access_rights_is_a_closed_vocabulary():
    rec = valid() | {"accessRights": "halboffen"}
    assert any("Wertebereich" in p for p in check_record(rec))


# -- die Invariante aus dem Vokabular -------------------------------------


def test_withdrawn_forces_closed_access():
    """Aus vocabs/consent_status.md: `withdrawn` MUSS accessRights='closed'
    setzen. Erzwingbar, also erzwungen."""
    rec = valid() | {"consent_status": "withdrawn", "accessRights": "restricted"}
    problems = check_record(rec)
    assert any("closed" in p for p in problems)
    assert check_record(valid() | {"consent_status": "withdrawn", "accessRights": "closed"}) == []


def test_withdrawn_stays_valid_even_when_a_profile_restricts_the_vocabulary():
    """Invariante: `withdrawn` bleibt in JEDEM Profil gültig."""
    rec = valid() | {"consent_status": "withdrawn", "accessRights": "closed"}
    assert check_record(rec, consent_vocabulary=("research-only", "public")) == []


def test_a_value_outside_the_profile_vocabulary_is_refused():
    rec = valid() | {"consent_status": "broad-research"}
    assert any(
        "Profilvokabular" in p for p in check_record(rec, consent_vocabulary=("research-only",))
    )


# -- Profilkopplung --------------------------------------------------------


def test_every_shipped_profile_declares_a_consent_vocabulary():
    for d in sorted(p for p in PROFILE_DIR.iterdir() if p.is_dir()):
        prof = Profile.load(d / "profile.toml")
        assert prof.consent_vocabulary, f"{prof.id} ohne consent_vocabulary"


def test_the_childlux_profile_matches_the_registered_luxoh_profile():
    """IMM-Profile-LuxOH führt: research-only | teaching | public | embargoed."""
    prof = Profile.load(PROFILE_DIR / "childlux" / "profile.toml")
    assert set(prof.consent_vocabulary) == {"research-only", "teaching", "public", "embargoed"}


# -- ADR 0020: deskriptiv/analytisch wird getrennt, nicht geprüft ----------


def test_the_core_has_no_descriptiveness_check():
    """Kein Klassifikator, keine Heuristik, kein Regelwerk entscheidet, ob ein
    Text deskriptiv ist. Das Positionspapier sagt es mit Charmaz selbst: auch
    eine deskriptive Zusammenfassung ist ein theoretischer Akt."""
    import ohpipe.policies.metadata as m

    verboten = ("descriptive", "analytic", "is_analytic", "classify", "score")
    namen = [n for n in dir(m) if not n.startswith("_")]
    for v in verboten:
        assert not any(v in n.lower() and n != "is_descriptive" for n in namen), v
    # `FieldSpec.is_descriptive` gibt es — aber es liest den BLOCK aus der
    # DCTAP, es beurteilt keinen Text.
    assert m.load_tap()["abstract"].is_descriptive
    assert not m.load_tap()["timecoded_segments"].is_descriptive


def test_the_abstract_is_not_a_hard_gate_field():
    """`abstract` ist im Modell optional. Eine Freigabe darf nicht daran
    scheitern, dass eine Heuristik den Text für zu analytisch hält."""
    assert "abstract" not in REQUIRED_FIELDS
    assert load_tap()["abstract"].mandatory is False


def test_advisory_is_separate_from_findings():
    """Hinweise färben nichts rot. Befunde schon."""
    from ohpipe.application.replay import RecordView
    from ohpipe.policies.exit_contract import Status

    v = RecordView(record_id="R-1")
    v.advisory.append("Der Abstract enthält Codebezeichner aus der Analyse")
    assert v.status is not Status.STOP
    v.findings.append("etwas wirklich Kaputtes")
    assert v.status is Status.STOP
