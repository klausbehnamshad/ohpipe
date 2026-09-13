"""Schritt-Registry und ``continue`` — die vier Invarianten, vollstreckt.

Der ROADMAP-Entwurf verlangt, bevor ein Schritt als ausführbar gelten darf:
ein Handler je Schritt, Outputs exakt gleich ``produces``, jeder erzeugbare
NEXT von argparse angenommen, jeder Handler erzeugt die behaupteten Belege.
Diese Datei prüft alle vier — die ersten drei am echten Graphen und am echten
Parser, die vierte an einem kleinen Graphen mit Handlern, die lügen dürfen.

**Zwei Ebenen, absichtlich beide.** Die Mechanik (was läuft, was hält, was
fällt) wird an einem Vierschrittgraphen geprüft, weil der Sandbox-Graph heute
nur zwei registrierte Schritte hat und keinen, den ``continue`` selbst
ausführen könnte. Der Operatorvertrag (Sechszeiler, Exitcodes, ein NEXT, das so
läuft, wie es dasteht) wird über die echte Grenze geprüft — als Unterprozess,
wie jeder andere CLI-Akzeptanztest hier.
"""

from __future__ import annotations

import io
import shlex
from pathlib import Path

import pytest

from ohpipe.application.replay import replay
from ohpipe.application.steps import (
    REGISTRY,
    Handler,
    HandlerOutcome,
    Mode,
    RegistryError,
    StepContext,
    check_registry,
    continue_record,
    continue_report,
)
from ohpipe.cli.main import build_parser
from ohpipe.domain.step import DEFAULT_GRAPH, ArtifactContract, Kind, Step, StepGraph
from ohpipe.journal import Journal
from ohpipe.policies.authority import Authority
from ohpipe.policies.exit_contract import Status
from ohpipe.project import Profile, Workspace

from ._forge import cli_keyed, forge_keyed, journal_path, place_object, report_lines

PROFIL = Path(__file__).resolve().parents[1] / "src" / "ohpipe" / "profiles" / "sandbox"
RECORD = "SANDBOX-001"


def _argparse_accepts(command: str) -> bool:
    """Nimmt der echte Parser den Befehl so an, wie er dasteht?

    ``--help`` beendet argparse mit Code 0 — das ist Annahme, kein Fehler. Jeder
    andere ``SystemExit`` ist eine Ablehnung.
    """
    tokens = shlex.split(command)
    assert tokens[0] == "ohpipe", command
    try:
        build_parser().parse_args(tokens[1:])
    except SystemExit as exc:
        return exc.code == 0
    return True


# ------------------------------------------------- Registry gegen Graph


def test_every_handler_names_a_step_and_produces_exactly_what_the_graph_says():
    assert check_registry(DEFAULT_GRAPH, REGISTRY) == []


def test_every_registry_command_is_accepted_by_argparse(tmp_path):
    ws = Workspace(tmp_path / "data", Profile.load(PROFIL / "profile.toml"))
    ctx = StepContext(
        ws=ws, journal=Journal(ws.journal_path), record_id=RECORD, profile_arg="sandbox"
    )
    # RUN-Handler tragen keinen eigenen Befehl; ihr NEXT ist der Aufruf von
    # continue mit --confirm, den continue_report für teure Schritte nennt.
    befehle = {
        name: (h.next_command or h.check_command)(ctx)  # type: ignore[misc]
        if h.mode is not Mode.RUN
        else ctx.command("continue", RECORD, "--confirm")
        for name, h in REGISTRY.items()
    }
    assert befehle, "Registry ohne Befehl — es gibt nichts zu prüfen"
    abgelehnt = {name: cmd for name, cmd in befehle.items() if not _argparse_accepts(cmd)}
    assert abgelehnt == {}, abgelehnt


def test_the_registry_checker_flags_forged_handlers():
    """Der Prüfer prüft sich zuerst selbst: vier gepflanzte Verstöße, vier Funde."""
    gepflanzt = {
        "nirgends": Handler(
            step="nirgends", mode=Mode.GATE, produces=("x",), next_command=lambda c: "ohpipe"
        ),
        "ingest": Handler(
            step="ingest", mode=Mode.INPUT, produces=("falsch",), check_command=lambda c: "ohpipe"
        ),
        "transcript.confirm": Handler(
            step="transcript.confirm",
            mode=Mode.INPUT,
            produces=("transcript.confirmed",),
            check_command=lambda c: "ohpipe",
        ),
        "l1.coverage": Handler(
            step="l1.coverage",
            mode=Mode.INPUT,
            produces=("l1.coverage",),
            check_command=lambda c: "x",
        ),
    }
    funde = check_registry(DEFAULT_GRAPH, gepflanzt)
    assert any("kein Schritt" in f for f in funde), funde
    assert any("Outputs entsprechen exakt produces" in f for f in funde), funde
    assert any("Ein Gate ist ein Gate" in f for f in funde), funde
    assert any("keine Eingabe" in f for f in funde), funde
    assert check_registry(DEFAULT_GRAPH, {}) == []


@pytest.mark.parametrize(
    ("mode", "felder"),
    [
        (Mode.RUN, {}),
        (Mode.RUN, {"run": lambda c: HandlerOutcome(), "next_command": lambda c: "x"}),
        (Mode.GATE, {}),
        (Mode.GATE, {"next_command": lambda c: "x", "run": lambda c: HandlerOutcome()}),
        (Mode.INPUT, {}),
    ],
)
def test_a_handler_that_does_not_fit_its_mode_is_refused_at_construction(mode, felder):
    with pytest.raises(RegistryError):
        Handler(step="ingest", mode=mode, produces=("transcript.revision",), **felder)


# ------------------------------------------------- Mechanik am kleinen Graphen

_FREI = ArtifactContract(binding_required=False, provenance_required=False, decision_required=False)
_GRAPH = StepGraph(
    steps=(
        Step("quelle", Kind.DETERMINISTIC, produces=("a",)),
        Step("ableiten", Kind.DETERMINISTIC, requires=("a",), produces=("b",)),
        Step("modell", Kind.MODEL, requires=("b",), produces=("m",), cost="model"),
        Step("pruefen", Kind.HUMAN, requires=("m",), produces=("c",), human_gate=True),
    ),
    contracts={name: _FREI for name in ("a", "b", "m", "c")},
)


def _welt(tmp_path: Path) -> tuple[StepContext, str]:
    ws = Workspace(tmp_path / "data", Profile.load(PROFIL / "profile.toml"))
    ws.ensure()
    journal = Journal(ws.journal_path)
    sha = ws.store().put(io.BytesIO(b"a"))
    journal.append("artifact.produced", {"artifact": "a", "sha256": sha}, record_id=RECORD)
    return StepContext(ws=ws, journal=journal, record_id=RECORD, profile_arg="sandbox"), sha


def _schreiber(artefakt: str):
    def run(ctx: StepContext, _view) -> HandlerOutcome:
        sha = ctx.ws.store().put(io.BytesIO(artefakt.encode()))
        ctx.journal.append(
            "artifact.produced", {"artifact": artefakt, "sha256": sha}, record_id=RECORD
        )
        return HandlerOutcome(changed=(str(ctx.journal.path),))

    return run


def _registry(**ersatz) -> dict[str, Handler]:
    basis = {
        "quelle": Handler(
            step="quelle",
            mode=Mode.INPUT,
            produces=("a",),
            check_command=lambda c: c.command("doctor"),
        ),
        "ableiten": Handler(step="ableiten", mode=Mode.RUN, produces=("b",), run=_schreiber("b")),
        "modell": Handler(step="modell", mode=Mode.RUN, produces=("m",), run=_schreiber("m")),
        "pruefen": Handler(
            step="pruefen",
            mode=Mode.GATE,
            produces=("c",),
            next_command=lambda c: c.command("transcript", "confirm", c.record_id),
        ),
    }
    basis.update(ersatz)
    return {k: v for k, v in basis.items() if v is not None}


def _lauf(ctx: StepContext, registry: dict[str, Handler]):
    def view_of():
        return replay(ctx.journal, graph=_GRAPH, authority=Authority.UNAUTHENTICATED).get(RECORD)

    outcome = continue_record(ctx, graph=_GRAPH, registry=registry, view_of=view_of)
    return outcome, continue_report(outcome, ctx, registry)


def test_continue_runs_the_cheap_handler_and_waits_before_the_costly_one(tmp_path):
    ctx, _ = _welt(tmp_path)
    assert check_registry(_GRAPH, _registry()) == []
    outcome, report = _lauf(ctx, _registry())
    assert outcome.executed == ("ableiten",)
    assert [s.name for s in outcome.deferred] == ["modell"]
    assert outcome.gates == ()
    assert report.status is Status.ACTION_NEEDED
    assert report.reason_code == "ACTION_CONTINUE_CONFIRM_REQUIRED"
    assert report.next_command == ctx.command("continue", RECORD, "--confirm")
    assert report.changed == [str(ctx.journal.path)]


def test_with_confirm_the_costly_handler_runs_and_continue_halts_at_the_gate(tmp_path):
    ctx, _ = _welt(tmp_path)
    ctx = StepContext(
        ws=ctx.ws, journal=ctx.journal, record_id=RECORD, profile_arg="sandbox", confirm=True
    )
    outcome, report = _lauf(ctx, _registry())
    assert outcome.executed == ("ableiten", "modell")
    assert [g.name for g in outcome.gates] == ["pruefen"]
    assert report.reason_code == "ACTION_CONTINUE_GATE"
    assert report.next_command == ctx.command("transcript", "confirm", RECORD)
    assert "hält vor pruefen" in report.reason


def test_a_handler_that_claims_without_evidence_is_a_stop(tmp_path):
    """Invariante 4: gezählt wird, was danach im Journal steht — nicht die Behauptung."""
    ctx, _ = _welt(tmp_path)
    luegner = Handler(
        step="ableiten",
        mode=Mode.RUN,
        produces=("b",),
        run=lambda c, v: HandlerOutcome(changed=("erfunden",)),
    )
    outcome, report = _lauf(ctx, _registry(ableiten=luegner))
    assert outcome.executed == ("ableiten",)
    assert outcome.failure is not None and "behauptet ['b']" in outcome.failure
    assert report.status is Status.STOP
    assert report.reason_code == "STOP_CONTINUE_HANDLER"
    assert report.check is not None and report.next_command is None


def test_a_failing_handler_is_a_stop_and_stops_the_run(tmp_path):
    ctx, _ = _welt(tmp_path)

    def kaputt(_ctx: StepContext, _view) -> HandlerOutcome:
        raise RuntimeError("Adapter nicht erreichbar")

    outcome, report = _lauf(
        ctx,
        _registry(ableiten=Handler(step="ableiten", mode=Mode.RUN, produces=("b",), run=kaputt)),
    )
    assert outcome.executed == ()
    assert report.status is Status.STOP and "Adapter nicht erreichbar" in report.reason
    assert report.check is not None
    assert (
        outcome.failure_kind == "RuntimeError" and report.details["failure_kind"] == "RuntimeError"
    )


def test_an_unbuilt_step_is_named_and_never_recommended(tmp_path):
    ctx, _ = _welt(tmp_path)
    outcome, report = _lauf(ctx, _registry(ableiten=None))
    assert [s.name for s in outcome.unbuilt] == ["ableiten"]
    assert report.reason_code == "ACTION_CONTINUE_NOT_BUILT"
    assert report.next_command is None
    assert report.check == ctx.command("status")
    assert "ableiten" in report.reason and "noch nicht gebaut" in report.reason


def test_an_input_step_carries_a_check_and_no_next(tmp_path):
    ws = Workspace(tmp_path / "data", Profile.load(PROFIL / "profile.toml"))
    ws.ensure()
    journal = Journal(ws.journal_path)
    journal.append(
        "record.registered", {"record_id": RECORD, "profile": "sandbox"}, record_id=RECORD
    )
    ctx = StepContext(ws=ws, journal=journal, record_id=RECORD, profile_arg="sandbox")
    outcome, report = _lauf(ctx, _registry())
    assert [s.name for s in outcome.inputs] == ["quelle"]
    assert report.reason_code == "ACTION_CONTINUE_INPUT_REQUIRED"
    assert report.next_command is None and report.check == ctx.command("doctor")


def test_findings_stop_the_run_before_the_first_handler(tmp_path):
    ctx, sha = _welt(tmp_path)
    ctx.journal.append("artifact.produced", {"artifact": "unsinn", "sha256": sha}, record_id=RECORD)
    outcome, report = _lauf(ctx, _registry())
    assert outcome.executed == () and outcome.findings
    assert report.status is Status.STOP and report.reason_code == "STOP_CONTINUE_FINDINGS"


def test_a_complete_graph_is_ready(tmp_path):
    ctx, sha = _welt(tmp_path)
    for name in ("b", "m", "c"):
        ctx.journal.append("artifact.produced", {"artifact": name, "sha256": sha}, record_id=RECORD)
    outcome, report = _lauf(ctx, _registry())
    assert outcome.complete
    assert report.status is Status.READY and report.exit_code == 0


# ------------------------------------------------- Operatorvertrag über die echte Grenze


@pytest.fixture
def welt(tmp_path: Path):
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"

    def run(*args: str):
        return cli_keyed(*args, root=wurzel, key=key)

    assert run("init").returncode == 0
    return wurzel, key, run


def _revision(wurzel: Path) -> list[dict]:
    sha = place_object(wurzel, b"die Fassung, auf die Anker zeigen werden")
    return [
        {"kind": "artifact.produced", "payload": {"artifact": "transcript.revision", "sha256": sha}}
    ]


def test_continue_on_an_empty_workspace_points_to_ingest(welt):
    wurzel, _, run = welt
    ergebnis = run("continue")
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert zeilen["STATUS"].startswith("ACTION_NEEDED")
    # Ausdruecklich `transcript ingest`: das einfache `ingest` registriert den
    # Record und legt die Quelle ab, es erzeugt keine transcript.revision.
    assert zeilen["CHECK"].endswith("transcript ingest --help"), zeilen


def test_continue_halts_before_transcript_confirm_with_a_next_that_runs_as_it_stands(welt):
    """Demo-Moment 1: läuft von selbst, hält, nennt Grund und nächsten Befehl."""
    wurzel, key, run = welt
    forge_keyed(wurzel, key, _revision(wurzel))
    davor = journal_path(wurzel).read_bytes()

    ergebnis = run("continue", RECORD)
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert "hält vor transcript.confirm" in zeilen["STATUS"], zeilen
    assert zeilen["CHANGED"] == "keine"
    assert zeilen["NEXT"] == shlex.join(
        ["ohpipe", "--profile", "sandbox", "--root", str(wurzel), "transcript", "confirm", RECORD]
    )
    assert journal_path(wurzel).read_bytes() == davor, (
        "continue hat geschrieben, ohne etwas auszuführen"
    )

    # Der NEXT läuft so, wie er dasteht: argparse nimmt ihn an, und der Befehl
    # antwortet mit seinem eigenen Sechszeiler (hier: fehlende Vorbedingung,
    # kein Parserfehler mit Exit 2).
    tokens = shlex.split(zeilen["NEXT"])[1:]
    ohne_profil = [
        t for i, t in enumerate(tokens) if t != "sandbox" or tokens[i - 1] != "--profile"
    ]
    ohne_profil = [t for t in ohne_profil if t != "--profile"]
    folge = run(*ohne_profil)
    assert folge.returncode == 3, folge.stdout + folge.stderr
    assert report_lines(folge.stdout)["STATUS"].startswith("ACTION_NEEDED")


def test_after_a_confirmed_transcript_continue_asks_before_the_model_step(welt):
    """Der Modellschritt ist gebaut (P2), aber teuer: ohne --confirm läuft er nicht."""
    wurzel, key, run = welt
    kette = _revision(wurzel)
    sha = place_object(wurzel, b"die bestaetigte Fassung")
    kette += [
        {
            "kind": "artifact.produced",
            "payload": {"artifact": "transcript.confirmed", "sha256": sha},
        },
        {
            "kind": "decision.recorded",
            "payload": {
                "artifact": "transcript.confirmed",
                "subject_sha256": sha,
                "input_refs": {"transcript": kette[0]["payload"]["sha256"]},
                "verdict": "ACCEPT",
                "reference": "PI-transcript.confirmed",
                "actor": "niemand",
                "at": "2026-09-01T11:00:00+00:00",
            },
        },
        {
            "kind": "anchor.checked",
            "payload": {"artifact": "transcript.confirmed", "outcome": "exact"},
        },
    ]
    forge_keyed(wurzel, key, kette)
    ergebnis = run("continue", RECORD)
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert "l1.suggest" in zeilen["STATUS"] and "Bestätigung" in zeilen["STATUS"], zeilen
    assert zeilen["NEXT"] == shlex.join(
        ["ohpipe", "--profile", "sandbox", "--root", str(wurzel), "continue", RECORD, "--confirm"]
    ), zeilen
    assert zeilen["CHANGED"] == "keine"


def test_continue_without_a_record_among_several_is_config(welt):
    wurzel, key, run = welt
    kette = _revision(wurzel)
    kette.append({**kette[0], "record_id": "SANDBOX-002"})
    forge_keyed(wurzel, key, kette)
    ergebnis = run("continue")
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 2, ergebnis.stdout
    assert "SANDBOX-001" in zeilen["STATUS"] and "SANDBOX-002" in zeilen["STATUS"]
    assert zeilen["CHECK"].endswith(" status")


def test_continue_on_an_unknown_record_is_config(welt):
    wurzel, key, run = welt
    forge_keyed(wurzel, key, _revision(wurzel))
    ergebnis = run("continue", "SANDBOX-999")
    assert ergebnis.returncode == 2, ergebnis.stdout
    assert report_lines(ergebnis.stdout)["CHECK"].endswith(" status")


def test_continue_stops_on_a_record_with_findings(welt):
    wurzel, key, run = welt
    kette = _revision(wurzel)
    kette.append(
        {"kind": "artifact.produced", "payload": {"artifact": "unsinn", "sha256": "a" * 64}}
    )
    forge_keyed(wurzel, key, kette)
    ergebnis = run("continue", RECORD)
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 1, ergebnis.stdout
    assert zeilen["STATUS"].startswith("STOP") and zeilen["CHECK"].endswith(" status")


def test_continue_stops_when_claimed_bytes_are_missing_from_the_store(welt):
    """Store- UND Journalbeleg: ein Artefakt ohne Bytes ist ein Befund, kein Fortschritt."""
    wurzel, key, run = welt
    forge_keyed(
        wurzel,
        key,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "transcript.revision", "sha256": "b" * 64},
            }
        ],
    )
    ergebnis = run("continue", RECORD)
    assert ergebnis.returncode == 1, ergebnis.stdout
    assert report_lines(ergebnis.stdout)["STATUS"].startswith("STOP")
