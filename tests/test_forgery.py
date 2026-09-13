"""Fälschungstests — die Invarianten über die PERSISTENZ und die CLI angreifen.

Diese Datei existiert wegen eines Musters aus vier Reviewrunden, und sie ist
selbst schon einmal daran gescheitert.

Runde 1–3: Die übrigen Tests prüfen den Code *wie gedacht*. Alle gefundenen
Blocker waren von der anderen Sorte — jemand schreibt an der API vorbei in die
persistierte Darstellung.

Runde 4: Die erste Fassung dieser Datei benutzte ``FakeEvent``-Objekte im
Speicher. Das war derselbe Fehler eine Ebene tiefer: wieder der Code wie
gedacht, nur mit anderem Vorzeichen.

**Regel (ADR 0015, verschärft):** Ein Fälschungstest schreibt den persistierten
Zustand tatsächlich und führt anschließend das Produkt von außen aus — über
dieselbe CLI-Grenze, die ein Operator benutzt. Geprüft werden Exitcode und
Sechszeiler, nicht ein Rückgabewert.

Drei getrennte Bedrohungsmodelle:

  KORRUPTION   Bytes sind kaputt (Absturz, Dateisystem, halber Schreibvorgang).
  UNBEFUGTER   Jemand hängt plausible Ereignisse an, ohne die API zu benutzen —
               und rechnet die Hashkette selbstverständlich nach.
  VOLLZUGRIFF  Jemand darf die ganze Datei schreiben. Dagegen schützt eine
               unkeyed Kette NICHT; sie ist Integritätsschutz, keine
               Authentifizierung. Siehe ADR 0016.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from ohpipe.cli.main import build_parser

from ._forge import (
    REPORT_LABELS,
    cli,
    cli_keyed,
    forge,
    forge_keyed,
    journal_path,
    place_object,
    report_lines,
)


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "data"
    assert cli("init", root=r).returncode == 0
    return r


@pytest.fixture
def keyed(tmp_path: Path):
    """Eine authentifizierte Welt: Schlüssel AUSSERHALB der Datenwurzel."""
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    r = tmp_path / "keyed-data"

    def run(*args: str):
        return cli_keyed(*args, root=r, key=key)

    assert run("init").returncode == 0
    return r, key, run


# ------------------------------------------------- KORRUPTION -> D-1-Pfad


@pytest.mark.parametrize(
    "content,label",
    [
        ("{kaputt\n", "kein JSON"),
        ('{"seq":1}\n', "Pflichtfeld fehlt"),
        ("[1,2,3]\n", "Zeile ist kein Objekt"),
        ('"nur ein string"\n', "Zeile ist ein String"),
        (
            (
                '{"seq":"eins","at":"x","kind":"k","record_id":null,"payload":{},'
                '"prev":"0","digest":"d"}\n'
            ),
            "seq ist ein String",
        ),
        (
            (
                '{"seq":1,"at":"x","kind":"k","record_id":null,"payload":[1],'
                '"prev":"0","digest":"d"}\n'
            ),
            "payload ist eine Liste",
        ),
        (
            '{"seq":1,"at":"x","kind":"k","record_id":7,"payload":{},"prev":"0","digest":"d"}\n',
            "record_id ist eine Zahl",
        ),
    ],
)
def test_every_corruption_reaches_the_d1_wording_via_the_cli(root, content, label):
    """Ein Traceback statt des Sechszeilers ist die Sorte Fehlermeldung, die man
    nachts um elf nicht deuten kann."""
    journal_path(root).write_text(content, encoding="utf-8")
    for cmd in ("status", "doctor"):
        r = cli(cmd, root=root)
        assert r.returncode == 1, f"{label}/{cmd}: exit {r.returncode}"
        assert "Traceback" not in r.stderr, f"{label}/{cmd}: Traceback statt Report"
        lines = report_lines(r.stdout)
        assert set(lines) == set(REPORT_LABELS), label
        assert "STOP" in lines["STATUS"]
        assert "Integritätsprüfung" in r.stdout, f"{label}: D-1-Wortlaut fehlt"


def test_a_truncated_last_line_is_a_finding_not_a_crash(root):
    p = journal_path(root)
    p.write_text(p.read_text(encoding="utf-8").rstrip()[:-20], encoding="utf-8")
    r = cli("status", root=root)
    assert r.returncode == 1 and "Traceback" not in r.stderr


def test_status_and_doctor_never_disagree_on_a_broken_journal(root):
    p = journal_path(root)
    p.write_text(p.read_text(encoding="utf-8").replace('"sandbox"', '"MANIPULIERT"'), "utf-8")
    assert cli("status", root=root).returncode == cli("doctor", root=root).returncode == 1


# ------------------------------------- UNBEFUGTER -> plausible Ereignisse


ARTIFACTS = [
    # Von Hand gefuehrt, mit Absicht: ein Angriff rechnet die Artefaktmenge
    # nach, er leitet sie nicht aus dem Graphen ab. Wuerde diese Liste
    # `build_graph` befragen, pruefte der Test den Graphen gegen sich selbst.
    # Seit ADR 0027 Punkt 8 fehlen l1.receipt und analysis.receipt — sie sind
    # keine Artefakte mehr, und `replay` weist sie seit derselben Serie als
    # nicht erzeugbare Namen zurueck.
    "transcript.revision",
    "transcript.confirmed",
    "l1.suggestions",
    "l1.coverage",
    "l1.adjudicated",
    "metadata.draft",
    "metadata.confirmed",
    "abstract.draft",
    "abstract.confirmed",
    "analysis.draft",
    "analysis.confirmed",
    "release.preview",
    "release.approved",
    "export.bundle",
    "analysis.approved",
    "analysis.bundle",
]


def wellformed_chain(root: Path) -> list[dict]:
    """Eine Fälschung, an der nach ALLEN eigenen Regeln nichts auszusetzen ist.

    Die erste Fassung dieser Kette benutzte für Modellartefakte deterministische
    Belege — nach den eigenen Regeln also gar nicht wohlgeformt. Der Test bewies
    dann nur, dass die Nutzlastprüfung greift, und nicht, dass die
    Autoritätsregel trägt.

    Diese Fassung enthält: echte Entscheidungen vor den Belegen, die sich darauf
    berufen; Modellbelege mit Parametersatz, Prompt-Hash, sauberem
    finish_reason und Autorisierung auf die zugehörige Gate-Entscheidung;
    Zeitpunkte in richtiger Reihenfolge. Formal ist das echte Evidenz — nur
    ohne Schlüssel geschrieben.

    Seit es den Content Store gibt, legt diese Kette auch die BYTES ab, auf die
    sie sich beruft. Sonst prüfte der Test nur noch, dass eine Referenz ins
    Leere zeigt — ein Angreifer, der eine Hashkette nachrechnet, schreibt auch
    zwei Dateien. Der Angriff wird dadurch stärker, nicht schwächer.
    """
    sha = place_object(root, b"die Bytes, auf die sich diese Kette beruft")
    from ._p3_evidence import INPUTS, bindings

    # Der Modellbeleg muss sich auf die Entscheidung ueber DAS GATE-ARTEFAKT
    # berufen, nicht auf die ueber sich selbst — und seit ADR 0020 gibt es
    # zwei Modellschritte mit ZWEI verschiedenen Gates. Die Zuordnung steht
    # hier von Hand: ein Angriff rechnet sie nach, er leitet sie nicht aus dem
    # Graphen ab. Wuerde der Test sie ableiten, prueft er den Graphen gegen
    # sich selbst.
    model_made = {
        "l1.suggestions": ("l1.suggest", "transcript.confirmed"),
        "analysis.draft": ("analysis.summarise", "l1.adjudicated"),
    }
    egress_upstream = {
        "export.bundle": "release.approved",
        "analysis.bundle": "analysis.approved",
    }
    evs: list[dict] = []
    for a in ARTIFACTS:
        evs.append({"kind": "artifact.produced", "payload": {"artifact": a, "sha256": sha}})
        # Erst die Entscheidung, dann der Beleg, der sich auf sie beruft.
        evs.append(
            {
                "kind": "decision.recorded",
                "payload": {
                    "artifact": a,
                    "subject_sha256": sha,
                    **bindings(a, sha),
                    "verdict": "ACCEPT",
                    "reference": f"PI-{a}",
                    "actor": "niemand",
                    "at": "2026-09-01T09:00:00+00:00",
                },
            }
        )
        if a == "transcript.revision":
            evs.append({"kind": "anchor.checked", "payload": {"artifact": a, "outcome": "exact"}})
            continue  # Ingress hat keinen Ableitungsbeleg.
        if a in model_made:
            step, gate_artifact = model_made[a]
            evs.append(
                {
                    "kind": "receipt.recorded",
                    "payload": {
                        "artifact": a,
                        "output_sha256": sha,
                        "inputs": {role: sha for role in INPUTS[a]},
                        "code_version": "0.1.0",
                        "kind": "model",
                        "step": step,
                        "params": {"model": "gemma4:e4b", "temperature": 0.0, "seed": 7},
                        "prompt_sha256": "c" * 64,
                        "finish_reason": "stop",
                        "authorisation": f"PI-{gate_artifact}@{sha[:12]}",
                        "authorisation_subject_sha256": sha,
                        "authorised_at": "2026-09-01T09:00:00+00:00",
                        "started_at": "2026-09-01T09:30:00+00:00",
                    },
                }
            )
        else:
            evs.append(
                {
                    "kind": "receipt.recorded",
                    "payload": {
                        "artifact": a,
                        "output_sha256": sha,
                        "inputs": (
                            {egress_upstream[a]: sha}
                            if a in egress_upstream
                            else {role: sha for role in INPUTS[a]}
                        ),
                        "code_version": "0.1.0",
                    },
                }
            )
        evs.append({"kind": "anchor.checked", "payload": {"artifact": a, "outcome": "exact"}})
    return evs


def test_a_wellformed_forgery_is_capped_exactly_and_for_the_right_reason(root):
    """DER Angriff — und der Test prüft jetzt den GENAUEN Ausgang.

    Vorher genügte "irgendetwas ausser READY"; damit hätte auch ein zufälliges
    STOP als Erfolg gezählt. Erwartet wird: sauber gekappt, keine Befunde, mit
    der Autoritätsbegründung.
    """
    from ohpipe.policies.authority import CAP_REASON

    forge(root, wellformed_chain(root))
    r = cli("status", "--json", root=root)
    data = json.loads(r.stdout)
    rec = data["details"]["records"][0]
    assert rec["findings"] == [], f"unerwartete Befunde: {rec['findings']}"
    assert rec["status"] == "ACTION_NEEDED", rec["status"]
    assert rec["explanation"] == CAP_REASON
    assert data["details"]["authority"] == "unauthenticated"
    assert r.returncode == 3


def test_the_same_chain_written_with_the_key_is_ready(keyed):
    """Gegenprobe zur Kappung: Dieselbe Kette, mit Schlüssel geschrieben, ist
    grün. Sonst prüfte der Test nur, dass irgendetwas rot wird."""
    r, key, run = keyed
    forge_keyed(r, key, wellformed_chain(r))
    out = run("status", "--json")
    rec = json.loads(out.stdout)["details"]["records"][0]
    assert rec["findings"] == [], rec["findings"]
    assert rec["status"] == "READY", rec["explanation"]


def test_incomplete_payloads_still_fail_fast(root):
    """Die Nutzlastprüfung bleibt — sie ist nur nicht mehr die Verteidigung."""
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "l1.suggestions", "sha256": "a" * 64},
            },
            {
                "kind": "receipt.recorded",
                "payload": {"artifact": "l1.suggestions", "output_sha256": "a" * 64},
            },
        ],
    )
    assert cli("status", root=root).returncode == 1


def test_a_decision_payload_without_actor_or_reference_is_not_a_decision(root):
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "metadata.draft", "sha256": "a" * 64},
            },
            {
                "kind": "decision.recorded",
                "payload": {
                    "artifact": "metadata.draft",
                    "subject_sha256": "a" * 64,
                    "verdict": "ACCEPT",
                },
            },
        ],
    )
    r = cli("status", "--json", root=root)
    findings = json.loads(r.stdout)["details"]["records"][0]["findings"]
    assert findings and "keine gültige Entscheidung" in findings[0]


def test_a_receipt_payload_without_declared_inputs_is_not_a_receipt(root):
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "l1.suggestions", "sha256": "a" * 64},
            },
            {
                "kind": "receipt.recorded",
                "payload": {"artifact": "l1.suggestions", "output_sha256": "a" * 64},
            },
        ],
    )
    findings = json.loads(cli("status", "--json", root=root).stdout)["details"]["records"][0][
        "findings"
    ]
    assert findings and "Eingaben" in findings[0]


@pytest.mark.parametrize("kind", ["artifact.state", "record.state", "status.set"])
def test_state_asserting_events_are_refused_through_the_cli(root, kind):
    forge(
        root,
        [{"kind": kind, "payload": {"artifact": "release.approved", "decision_state": "accepted"}}],
    )
    r = cli("status", root=root)
    assert r.returncode == 1
    assert "behauptet einen Zustand" in r.stdout


def test_an_anchor_outcome_that_does_not_exist_is_a_finding(root):
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "l1.suggestions", "sha256": "a" * 64},
            },
            {
                "kind": "anchor.checked",
                "payload": {"artifact": "l1.suggestions", "outcome": "natuerlich_alles_gut"},
            },
        ],
    )
    assert cli("status", root=root).returncode == 1


def test_an_artifact_hash_that_is_not_a_hash_is_a_finding(root):
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "l1.suggestions", "sha256": "vertrau_mir"},
            }
        ],
    )
    assert cli("status", root=root).returncode == 1


# --------------------------------------------------- UNBEFUGTER: Ownership


def test_record_disabled_needs_a_real_decision(root):
    """`record.disabled` mit leerer Nutzlast blendete einen Record aus — ohne
    Akteur, ohne Referenz, ohne Entscheidung. Auch Deaktivieren ist ein
    menschlicher Akt."""
    forge(root, [{"kind": "record.disabled", "payload": {}}])
    r = cli("status", root=root)
    assert r.returncode == 1
    assert "ohne gültige Entscheidung" in r.stdout


def test_record_disabled_with_an_accepting_verdict_is_refused(root):
    forge(
        root,
        [
            {
                "kind": "record.disabled",
                "payload": {
                    "artifact": "record",
                    "subject_sha256": "a" * 64,
                    "verdict": "ACCEPT",
                    "reference": "PI-1",
                    "actor": "op",
                    "at": "2026-09-01T10:00:00+00:00",
                },
            }
        ],
    )
    assert cli("status", root=root).returncode == 1


def test_a_decision_payload_may_not_name_another_record(root):
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "metadata.draft", "sha256": "a" * 64},
            },
            {
                "kind": "decision.recorded",
                "payload": {
                    "record_id": "EIN-ANDERER",
                    "artifact": "metadata.draft",
                    "subject_sha256": "a" * 64,
                    "verdict": "ACCEPT",
                    "reference": "PI-1",
                    "actor": "op",
                    "at": "2026-09-01T10:00:00+00:00",
                },
            },
        ],
    )
    assert cli("status", root=root).returncode == 1


def test_a_model_artifact_needs_a_model_receipt(root):
    """Sonst wird ein Modellartefakt durch einen deterministischen Beleg
    aktuell, und Autorisierung, finish_reason und Parameter werden nie
    geprüft."""
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "l1.suggestions", "sha256": "a" * 64},
            },
            {
                "kind": "receipt.recorded",
                "payload": {
                    "artifact": "l1.suggestions",
                    "output_sha256": "a" * 64,
                    "inputs": {"src": "b" * 64},
                    "code_version": "0.1.0",
                },
            },
        ],
    )
    r = cli("status", root=root)
    assert r.returncode == 1
    assert "deterministischem Beleg" in r.stdout


def test_ownership_is_ineffective_without_authentication(root):
    """Eine Übergabe aus einer nicht authentifizierten Kette wäre ein
    Schreibrecht, das man sich selbst ausstellt."""
    forge(
        root,
        [
            {
                "kind": "record.adopted",
                "record_id": "CHILDLUX-0007",
                "payload": {
                    "record_id": "CHILDLUX-0007",
                    "from": "dinoh",
                    "to": "ohpipe",
                    "reference": "PI-1",
                },
            }
        ],
    )
    d = json.loads(cli("doctor", "--json", root=root).stdout)["details"]
    # `adopted_records`, nicht `owned_by_ohpipe`: Seit `legacy_runtime` eine
    # Profileigenschaft ist, gehören unbekannte Records unter `sandbox` ohpipe
    # — die abgeleitete Zahl kann eine unwirksame Übergabe nicht mehr von der
    # Voreinstellung unterscheiden. Geprüft wird, was der Test meint: dass die
    # Übergabe KEINEN Eintrag erzeugt hat.
    assert d.get("adopted_records") == []
    assert d["authority"] == "unauthenticated"


def test_a_minimal_adoption_event_does_not_grant_ownership(root):
    """Der Befund aus Runde 4: ein Ereignis nur mit record_id machte ohpipe zum
    Eigentümer. Seit Runde 5 greift davor schon die Autoritätsregel — die
    Übergabe wird gar nicht erst wirksam."""
    forge(
        root,
        [
            {
                "kind": "record.adopted",
                "record_id": "CHILDLUX-0001",
                "payload": {"record_id": "CHILDLUX-0001"},
            }
        ],
    )
    d = json.loads(cli("doctor", "--json", root=root).stdout)["details"]
    assert d.get("adopted_records") == []
    assert d["authority"] == "unauthenticated"


# -- Nutzlastprüfung: bewusst auf Modulebene ------------------------------
#
# Diese Fälle laufen NICHT über die CLI, und das ist kein Rückfall. Eine von
# Hand angehängte Übergabe scheitert in der authentifizierten Welt bereits an
# der Kettenprüfung — sie wurde ohne Schlüssel geschrieben. Der Weg über die
# CLI kann die Nutzlastprüfung deshalb gar nicht erreichen.
#
# Geprüft wird hier also die zweite Verteidigungslinie: Ein Schlüsselinhaber
# kann sich irren, und dann soll die Übergabe trotzdem auffallen.


GATE_SHA = "a" * 64
GATE_REF = "PI-2026-09-01-0007"
GATE_ID = f"{GATE_REF}@{GATE_SHA[:12]}"


class _Ev:
    def __init__(self, payload, at="2026-09-01T10:00:00+00:00", kind="record.adopted"):
        self.kind = kind
        self.payload = payload
        self.at = at
        self.record_id = payload.get("record_id")


def _gate(record_id: str = "CHILDLUX-0007") -> _Ev:
    """Die Entscheidung, auf die sich eine Übergabe berufen muss."""
    return _Ev(
        {
            "record_id": record_id,
            "artifact": "cutover",
            "subject_sha256": GATE_SHA,
            "verdict": "ACCEPT",
            "reference": GATE_REF,
            "actor": "operator",
            "at": "2026-09-01T09:00:00+00:00",
        },
        kind="decision.recorded",
    )


@pytest.mark.parametrize(
    "payload,why",
    [
        ({"record_id": "CHILDLUX-0001", "from": "dinoh", "to": "ohpipe"}, "ohne Referenz"),
        (
            {
                "record_id": "CHILDLUX-0001",
                "from": "dinoh",
                "to": "ohpipe",
                "reference": "zwei woerter",
            },
            "Referenz mit Leerzeichen",
        ),
        (
            {
                "record_id": "CHILDLUX-0001",
                "from": "wer_auch_immer",
                "to": "ohpipe",
                "reference": "PI-1",
            },
            "unbekannter Runtime",
        ),
        (
            {"record_id": "CHILDLUX-0001", "from": "ohpipe", "to": "ohpipe", "reference": "PI-1"},
            "kein Eigentuemerwechsel",
        ),
        (
            {"record_id": "CHILDLUX-0001", "from": "ohpipe", "to": "dinoh", "reference": "PI-1"},
            "falsche Herkunft",
        ),
    ],
)
def test_every_malformed_adoption_is_refused_even_with_the_key(payload, why):
    from ohpipe.policies.authority import Authority
    from ohpipe.policies.ownership import CutoverLedger, OwnershipError

    with pytest.raises(OwnershipError):
        CutoverLedger.from_journal([_Ev(payload)], authority=Authority.AUTHENTICATED)


def test_the_envelope_id_must_match_the_payload_id():
    from ohpipe.policies.authority import Authority
    from ohpipe.policies.ownership import CutoverLedger

    ev = _Ev(
        {
            "record_id": "CHILDLUX-0007",
            "from": "dinoh",
            "to": "ohpipe",
            "reference": GATE_REF,
            "decision_id": GATE_ID,
        }
    )
    ev.record_id = "EIN-ANDERER"
    led = CutoverLedger.from_journal([_gate(), ev], strict=False, authority=Authority.AUTHENTICATED)
    assert led.problems and "Ereignishülle" in led.problems[0]


def test_a_wellformed_adoption_with_the_key_is_accepted():
    """Gegenprobe: Die Strenge darf den legitimen Weg nicht mitverbieten."""
    from ohpipe.policies.authority import Authority
    from ohpipe.policies.ownership import CutoverLedger

    ev = _Ev(
        {
            "record_id": "CHILDLUX-0007",
            "from": "dinoh",
            "to": "ohpipe",
            "reference": GATE_REF,
            "decision_id": GATE_ID,
        }
    )
    led = CutoverLedger.from_journal([_gate(), ev], authority=Authority.AUTHENTICATED)
    assert led.owner_of("CHILDLUX-0007") == "ohpipe"


def test_the_same_adoption_is_ineffective_without_the_key():
    from ohpipe.policies.authority import Authority
    from ohpipe.policies.ownership import CutoverLedger

    ev = _Ev(
        {
            "record_id": "CHILDLUX-0007",
            "from": "dinoh",
            "to": "ohpipe",
            "reference": "PI-2026-09-01-0007",
        }
    )
    led = CutoverLedger.from_journal([ev], strict=False, authority=Authority.UNAUTHENTICATED)
    assert led.owner_of("CHILDLUX-0007") == "dinoh"
    assert led.problems


# ---------------------------------------------- VOLLZUGRIFF -> Grenze zeigen


def test_a_full_rewrite_is_not_detected_and_the_tool_says_so(root):
    """Ehrlichkeit über die eigene Grenze (ADR 0016).

    Wer die ganze Datei schreiben darf, rechnet die Kette neu — und die Prüfung
    besteht. Eine unkeyed Hashkette ist Integritätsschutz, keine
    Authentifizierung. Dieser Test hält fest, dass das so ist UND dass das
    Produkt es an der Oberfläche sagt, statt Sicherheit zu suggerieren.
    """
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "transcript.revision", "sha256": "a" * 64},
            }
        ],
    )
    d = json.loads(cli("doctor", "--json", root=root).stdout)["details"]
    assert d["journal_integrity"] == "unkeyed"
    assert "authentifiziert" in d["journal_integrity_note"]
    assert len(d["journal_head"]) == 64  # Kopf ausgewiesen -> extern verankerbar


def test_a_keyed_journal_detects_the_full_rewrite(root, tmp_path):
    """Mit Schlüssel außerhalb der Datenwurzel wird aus Integrität auch
    Authentizität — und genau dieselbe Fälschung fliegt auf."""
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")

    def keyed(*args):
        return cli_keyed(*args, root=tmp_path / "keyed", key=key)

    assert keyed("init").returncode == 0
    d = json.loads(keyed("doctor", "--json").stdout)["details"]
    assert d["journal_integrity"] == "keyed"
    forge(
        tmp_path / "keyed",
        [{"kind": "artifact.produced", "payload": {"artifact": "x", "sha256": "a" * 64}}],
    )
    r = keyed("doctor")
    assert r.returncode == 1 and "Integritätsprüfung" in r.stdout


# ------------------------------------------------------------- kein Bypass

FORBIDDEN_OPTIONS = {
    "--yes",
    "-y",
    "--force",
    "-f",
    "--skip-gate",
    "--allow-stale",
    "--model",
    "--no-verify",
    "--no-gate",
    "--override",
    "--unsafe",
}
FORBIDDEN_COMMANDS = {"evidence", "write-evidence", "set-state", "approve-raw", "unlock"}


def _walk(parser: argparse.ArgumentParser, prefix=""):
    for a in parser._actions:
        for s in a.option_strings:
            yield "option", s, prefix
        if isinstance(a, argparse._SubParsersAction):
            for name, sub in a.choices.items():
                yield "command", name, prefix
                yield from _walk(sub, prefix=f"{prefix}{name} ")


def test_no_bypass_option_anywhere_including_subcommands():
    for kind, name, where in _walk(build_parser()):
        target = FORBIDDEN_OPTIONS if kind == "option" else FORBIDDEN_COMMANDS
        assert name not in target, f"{where}{name} ist ein Umgehungspfad"


def test_the_walker_actually_descends():
    """Ein Test, der nichts findet, weil er nicht sucht, ist kein Test."""
    items = list(_walk(build_parser()))
    cmds = {n for k, n, _ in items if k == "command"}
    assert {"doctor", "init", "status"} <= cmds
    assert any(k == "option" and w for k, _, w in items), "keine Unterbefehlsoptionen gesehen"


def test_a_forged_l1_adjudication_pointing_at_other_bytes_is_red(root):
    """ADR 0015: eine von Hand geschriebene Entscheidung, die auf ANDERE Bytes
    zeigt als das Artefakt traegt, macht die Adjudikation nicht wirksam.

    Bindung (anchor.checked) und Ableitung (deterministischer Beleg) sind gruen;
    allein die Entscheidungsachse faellt, weil ``subject_sha256`` nicht die Bytes
    des Artefakts sind. Muss rot werden, nicht gruen.
    """
    echt = place_object(root, b'{"schema":"ohpipe.l1.adjudicated.v1","record_id":"SANDBOX-001"}\n')
    quelle = place_object(root, b'{"schema":"ohpipe.l1.suggestions.v1"}\n')
    fremd = place_object(root, b'{"schema":"ohpipe.l1.adjudicated.v1","manipuliert":true}\n')
    assert fremd != echt
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "l1.adjudicated", "sha256": echt},
            },
            {
                "kind": "anchor.checked",
                "payload": {"artifact": "l1.adjudicated", "outcome": "exact"},
            },
            {
                "kind": "receipt.recorded",
                "payload": {
                    "artifact": "l1.adjudicated",
                    "output_sha256": echt,
                    "inputs": {"l1.suggestions": quelle},
                    "code_version": "l1-review/1",
                },
            },
            {
                "kind": "decision.recorded",
                "payload": {
                    "artifact": "l1.adjudicated",
                    "subject_sha256": fremd,
                    "verdict": "ACCEPT",
                    "reference": "l1.review",
                    "actor": "KLAUS",
                    "at": "2026-09-01T10:00:00+00:00",
                },
            },
        ],
    )
    rec = json.loads(cli("status", "--json", root=root).stdout)["details"]["records"][0]
    adj = rec["artifacts"]["l1.adjudicated"]
    assert adj["decision_state"] == "undecided", adj
    assert adj["status"] != "READY", adj


@pytest.mark.parametrize(
    "artifact,reference",
    [
        ("metadata.confirmed", "metadata.confirm"),
        ("abstract.confirmed", "abstract.confirm"),
        ("release.approved", "release.approve"),
    ],
)
def test_a_forged_catalog_confirmation_pointing_at_other_bytes_is_red(root, artifact, reference):
    """ADR 0015, EINE Invariante ueber die drei Katalog-Bestaetigungen.

    ``metadata.confirmed``, ``abstract.confirmed`` und ``release.approved`` tragen
    denselben Vertrag (binding_required=True, provenance_required=False,
    decision_required=True) und schreiben ueber DIESELBE Mechanik
    (``application/gate.py``). Deshalb EIN parametrisierter Test, nicht drei
    Kopien: eine von Hand geschriebene Entscheidung, die auf ANDERE Bytes zeigt
    als das Artefakt traegt, macht die Bestaetigung nicht wirksam. Die Bindung
    (anchor.checked) ist gruen; allein die Entscheidungsachse faellt, weil
    ``subject_sha256`` nicht die Bytes des Artefakts sind.
    """
    echt = place_object(
        root, ('{"schema":"ohpipe.' + artifact + '.v1","record_id":"SANDBOX-001"}\n').encode()
    )
    fremd = place_object(
        root, ('{"schema":"ohpipe.' + artifact + '.v1","manipuliert":true}\n').encode()
    )
    assert fremd != echt
    forge(
        root,
        [
            {"kind": "artifact.produced", "payload": {"artifact": artifact, "sha256": echt}},
            {"kind": "anchor.checked", "payload": {"artifact": artifact, "outcome": "exact"}},
            {
                "kind": "decision.recorded",
                "payload": {
                    "artifact": artifact,
                    "subject_sha256": fremd,
                    "verdict": "ACCEPT",
                    "reference": reference,
                    "actor": "KLAUS",
                    "at": "2026-09-01T11:00:00+00:00",
                },
            },
        ],
    )
    rec = json.loads(cli("status", "--json", root=root).stdout)["details"]["records"][0]
    st = rec["artifacts"][artifact]
    assert st["source_binding"] == "bound", st
    assert st["decision_state"] == "undecided", st
    assert st["status"] != "READY", st


@pytest.mark.parametrize(
    "manipulation",
    ["andere_bytes", "zusaetzliche_eingabe"],
)
def test_a_forged_export_bundle_does_not_inherit_a_decision_it_does_not_hang_on(root, manipulation):
    """ADR 0015 am Ausgang: das Erbe ist kein Freibrief.

    ``export.bundle`` traegt selbst keine ``decision.recorded`` — es erbt die
    wirksame ACCEPT-Entscheidung seiner Vorbedingung
    (``src/ohpipe/application/replay.py::_inherit_egress_decision``). Genau das ist die Stelle, an der
    ein Angreifer ansetzen wuerde: ein Beleg, der irgendetwas als Eingabe
    nennt, und die Zustimmung kommt gratis dazu.

    Zwei Wege, ein Verdikt. Nennt der Beleg ANDERE Bytes als die wirksame
    Freigabe, haengt der Ausgang nicht an ihr. Nennt er die Freigabe UND
    zusaetzlich etwas anderes, deckt die geerbte Zustimmung nicht mehr, was
    tatsaechlich eingeflossen ist — beides faellt, und zwar unabhaengig davon,
    dass Bindung und Ableitungsbeleg formal in Ordnung sind.
    """
    freigabe = place_object(
        root, b'{"schema":"ohpipe.release.approved.v1","record_id":"SANDBOX-001"}\n'
    )
    fremd = place_object(root, b'{"schema":"ohpipe.release.approved.v1","manipuliert":true}\n')
    bundle = place_object(root, b'{"schema":"ohpipe.export.bundle.v1","record_id":"SANDBOX-001"}\n')
    assert len({freigabe, fremd, bundle}) == 3

    eingaben = (
        {"release.approved": fremd}
        if manipulation == "andere_bytes"
        else {"release.approved": freigabe, "l1.adjudicated": fremd}
    )
    forge(
        root,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "release.approved", "sha256": freigabe},
            },
            {
                "kind": "anchor.checked",
                "payload": {"artifact": "release.approved", "outcome": "exact"},
            },
            {
                "kind": "decision.recorded",
                "payload": {
                    "artifact": "release.approved",
                    "subject_sha256": freigabe,
                    "verdict": "ACCEPT",
                    "reference": "release.approve",
                    "actor": "KLAUS",
                    "at": "2026-09-05T12:00:00+00:00",
                },
            },
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "export.bundle", "sha256": bundle},
            },
            {
                "kind": "anchor.checked",
                "payload": {"artifact": "export.bundle", "outcome": "exact"},
            },
            {
                "kind": "receipt.recorded",
                "payload": {
                    "artifact": "export.bundle",
                    "output_sha256": bundle,
                    "inputs": eingaben,
                    "code_version": "export-bundle/1",
                    "step": "export",
                },
            },
        ],
    )
    rec = json.loads(cli("status", "--json", root=root).stdout)["details"]["records"][0]
    st = rec["artifacts"]["export.bundle"]
    assert st["source_binding"] == "bound", st
    assert st["decision_state"] == "undecided", st
    assert st["status"] != "READY", st
