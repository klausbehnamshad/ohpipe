"""Truncation-Guard und Egress-Invariante.

Herkunft:
  - HIL-NOTE Coverage-Audit Int1-Int3 (num_predict=1280, Q4-Befund 5/5)
  - HIL-NOTE Abstract-Verzerrung (Int6-Gegenlauf, 5 von 6 Themenplaetzen)
Kategorie: Sicherheitsinvariante -> zwingend portiert.

Diese beiden Tests sind der Grund, warum es dieses Repository gibt.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from ohpipe.domain.decision import Decision, InvalidDecision, Verdict
from ohpipe.domain.receipt import (
    FINISH_LENGTH,
    FINISH_OK,
    FINISH_UNKNOWN,
    ModelParams,
    ModelReceipt,
    Receipt,
    TruncatedOutput,
    UnauthorisedRun,
)
from ohpipe.domain.step import DEFAULT_GRAPH, GraphError, Kind, Step, StepGraph, check_egress_gates

PARAMS = ModelParams(model="gemma4:e4b", temperature=0.0, seed=7, num_ctx=8192, num_predict=1280)
SUBJECT = "d" * 64
PROMPT = "c" * 64

GATE = Decision(
    record_id="SANDBOX-001",
    artifact="transcript.confirmed",
    subject_sha256=SUBJECT,
    verdict=Verdict.ACCEPT,
    reference="PI-2026-09-01-0007",
    actor="operator",
    at="2026-09-01T10:00:00+00:00",
)


def receipt(finish: str, **kw) -> ModelReceipt:
    return ModelReceipt(
        step="l1.suggest",
        inputs={"transcript": "a" * 64},
        output_sha256="b" * 64,
        code_version="0.1.0",
        params=PARAMS,
        prompt_sha256=PROMPT,
        finish_reason=finish,
        **{
            "authorisation": GATE.id,
            "authorisation_subject_sha256": SUBJECT,
            "authorised_at": GATE.at,
            "started_at": "2026-09-01T10:05:00+00:00",
            **kw,
        },
    )


def test_clean_finish_validates():
    receipt(FINISH_OK).validate(GATE)
    assert not receipt(FINISH_OK).truncated


def test_length_finish_is_a_failure_not_a_partial_result():
    r = receipt(FINISH_LENGTH, chunk_index=3, chunk_count=9)
    assert r.truncated
    with pytest.raises(TruncatedOutput) as exc:
        r.validate(GATE)
    assert "Chunk 4/9" in str(exc.value)


def test_unknown_finish_reason_counts_as_truncated():
    """Ein Adapter, der die Abbruchursache nicht meldet, darf nicht wie einer
    aussehen, der sauber beendet hat. Default = fehlgeschlagen."""
    assert receipt(FINISH_UNKNOWN).truncated
    assert receipt("weird_new_value").truncated
    with pytest.raises(TruncatedOutput):
        receipt(FINISH_UNKNOWN).validate(GATE)


def test_truncated_receipt_never_counts_as_current():
    r = receipt(FINISH_LENGTH)
    assert not r.matches({"transcript": "a" * 64}, "0.1.0", params=PARAMS, prompt_sha256=PROMPT)


def test_matches_covers_params_and_prompt_not_only_inputs():
    """Zu den Eingaben eines generativen Schritts gehoeren Modell, Parameter
    und Prompt. Sonst gilt ein Lauf als aktuell, dessen num_predict verdoppelt
    wurde - genau die Korpusvergleichbarkeit, die ADR 0012 schuetzt."""
    r = receipt(FINISH_OK)
    args = ({"transcript": "a" * 64}, "0.1.0")
    out = "b" * 64
    assert r.matches(*args, params=PARAMS, prompt_sha256=PROMPT, output_sha256=out)
    other = ModelParams(**{**PARAMS.__dict__, "num_predict": 4096})
    assert not r.matches(*args, params=other, prompt_sha256=PROMPT, output_sha256=out)
    assert not r.matches(*args, params=PARAMS, prompt_sha256="e" * 64, output_sha256=out)
    # Andere Ausgabebytes: der Beleg gilt fuer die alten, nicht fuer diese.
    assert not r.matches(*args, params=PARAMS, prompt_sha256=PROMPT, output_sha256="f" * 64)
    # Unvollstaendiger Vergleich ist fail-closed, nicht "vermutlich gleich".
    assert not r.matches(*args)
    assert not r.matches(*args, params=PARAMS, prompt_sha256=PROMPT)


def test_to_json_keeps_every_authorisation_field():
    j = receipt(FINISH_OK).to_json()
    for k in ("authorisation", "authorisation_subject_sha256", "authorised_at", "started_at"):
        assert j.get(k), f"{k} geht beim Serialisieren verloren"


def test_receipt_binds_to_the_actual_decision():
    r = receipt(FINISH_OK)
    assert r.bound_to(GATE)
    other = Decision(
        record_id="SANDBOX-001",
        artifact="transcript.confirmed",
        subject_sha256="e" * 64,
        verdict=Verdict.ACCEPT,
        reference="PI-2026-09-01-0007",
        actor="operator",
    )
    assert not r.bound_to(other)
    rejected = Decision(
        record_id="SANDBOX-001",
        artifact="transcript.confirmed",
        subject_sha256=SUBJECT,
        verdict=Verdict.REJECT,
        reference="PI-2026-09-01-0007",
        actor="operator",
    )
    assert not r.bound_to(rejected)


def test_receipt_matching_is_input_comparison_not_regeneration():
    r = Receipt(
        step="metadata.derive",
        inputs={"l1": "x" * 64},
        output_sha256="y" * 64,
        code_version="0.1.0",
    )
    assert r.matches({"l1": "x" * 64}, "0.1.0")
    assert not r.matches({"l1": "z" * 64}, "0.1.0")
    assert not r.matches({"l1": "x" * 64}, "0.2.0")


def test_param_fingerprint_is_order_independent():
    a = ModelParams(model="m", extra={"a": 1, "b": 2})
    b = ModelParams(model="m", extra={"b": 2, "a": 1})
    assert a.fingerprint == b.fingerprint


def test_param_change_changes_the_fingerprint():
    assert PARAMS.fingerprint != ModelParams(**{**PARAMS.__dict__, "num_predict": 4096}).fingerprint


# ------------------------------------------------------------------ graph


def test_default_graph_has_no_ungated_egress():
    assert check_egress_gates(DEFAULT_GRAPH) == []


def test_an_ungated_model_to_export_path_is_caught():
    """Genau der Pfad, der im Vorgaengersystem offen war: zwischen Modell-
    statistik und oeffentlichem Record sass keine menschliche Stufe."""
    bad = StepGraph(
        steps=(
            Step("ingest", Kind.DETERMINISTIC, produces=("t",)),
            Step("suggest", Kind.MODEL, requires=("t",), produces=("s",)),
            Step("abstract", Kind.DETERMINISTIC, requires=("s",), produces=("a",)),
            Step("publish", Kind.EGRESS, requires=("a",), produces=("bundle",), leaves_system=True),
        )
    )
    violations = check_egress_gates(bad)
    assert len(violations) == 1
    assert "publish" in violations[0] and "suggest" in violations[0]


def test_two_writers_for_one_artifact_is_rejected():
    """Ein Generator, der in die Quelle schreibt, die er validiert, war der
    Builder-Defekt. Hier ist er ein Konstruktionsfehler."""
    with pytest.raises(GraphError, match="zwei Schritten"):
        StepGraph(
            steps=(
                Step("a", Kind.DETERMINISTIC, produces=("metadata",)),
                Step("b", Kind.DETERMINISTIC, produces=("metadata",)),
            )
        )


def test_continue_stops_at_the_first_human_gate():
    plan = DEFAULT_GRAPH.plan(set())
    assert [s.name for s in plan.steps] == ["ingest"]
    assert plan.gate_names == ("transcript.confirm",)


def test_continue_resumes_after_a_gate_was_satisfied():
    have = {"transcript.revision", "transcript.confirmed"}
    plan = DEFAULT_GRAPH.plan(have)
    assert [s.name for s in plan.steps] == ["l1.suggest", "l1.coverage"]
    assert plan.gate_names == ("l1.review",)


def test_repeating_a_finished_step_plans_nothing():
    have = {"transcript.revision"}
    assert DEFAULT_GRAPH.plan(have).steps == ()


L1_DONE = {
    "transcript.revision",
    "transcript.confirmed",
    "l1.suggestions",
    "l1.receipt",
    "l1.coverage",
    "l1.adjudicated",
}


def test_the_analysis_path_is_not_queued_behind_the_catalogue_path():
    """ADR 0021 — der Befund, der diese Änderung ausgelöst hat.

    ``analysis.summarise`` verlangt nur ``l1.adjudicated``. Trotzdem kam der
    alte Planner nie dort an: Er kehrte beim ersten Gate zurück, also bei
    ``metadata.confirm``, und danach bei ``abstract.confirm``. Die Analyse
    lief damit praktisch erst nach dem gesamten Katalogpfad — eine
    Abhängigkeit, die **keine Kante des Graphen behauptet**.

    Der Test prüft die Sache selbst und nicht die Formulierung: Wird ein
    Schritt geplant, dessen Voraussetzungen erfüllt sind?
    """
    plan = DEFAULT_GRAPH.plan(L1_DONE)
    planned = [s.name for s in plan.steps]
    assert "analysis.summarise" in planned, f"Analyse nicht geplant, geplant wurde: {planned}"
    assert "metadata.derive" in planned, planned
    assert set(plan.gate_names) == {"metadata.confirm", "analysis.confirm"}


def test_a_gate_still_blocks_what_lies_behind_it():
    """Die Gegenprobe. Verzweigt planen heißt nicht: Gates umgehen.

    Ohne diese Zusicherung wäre die Änderung ein Loch statt einer Korrektur —
    ``abstract.derive`` hängt an ``metadata.confirmed``, und das entsteht erst
    durch eine menschliche Entscheidung.
    """
    planned = [s.name for s in DEFAULT_GRAPH.plan(L1_DONE).steps]
    for behind_a_gate in ("abstract.derive", "release.preview", "export", "analysis.export"):
        assert behind_a_gate not in planned, f"{behind_a_gate} wurde am Gate vorbei geplant"


def test_every_reported_gate_is_actually_reachable():
    """Ein gemeldeter Halt, an dem man gar nicht steht, ist eine Falschaussage.

    „Erreichbar" heißt nicht „die Voraussetzungen liegen jetzt vor", sondern
    „liegen vor, wenn der geplante Lauf durch ist". Die erste Fassung dieses
    Tests prüfte gegen ``have`` und fiel prompt über ``transcript.confirm``:
    Dessen Voraussetzung entsteht durch ``ingest`` — also durch genau den
    Lauf, den der Plan beschreibt.
    """
    for have in (set(), {"transcript.revision"}, L1_DONE):
        plan = DEFAULT_GRAPH.plan(have)
        after = set(have) | {a for s in plan.steps for a in s.produces}
        for gate in plan.gates:
            assert all(a in after for a in gate.requires), f"{gate.name} ist nicht erreichbar"


def test_human_kind_requires_a_gate():
    with pytest.raises(GraphError):
        Step("x", Kind.HUMAN, human_gate=False)


def test_graph_is_acyclic_and_complete():
    order = [s.name for s in DEFAULT_GRAPH.topological()]
    assert order[0] == "ingest" and order[-1] == "export"
    assert len(order) == len(DEFAULT_GRAPH.steps)


# ------------------------------------------------- Autorisierung (corsia:95)


@pytest.mark.parametrize(
    "kw,match",
    [
        ({"authorisation": ""}, "ohne gültige Autorisierungsreferenz"),
        ({"authorisation": "irgendwas"}, "ohne gültige Autorisierungsreferenz"),
        ({"authorisation": "REF@zzz"}, "keine Decision.id"),
        ({"authorisation_subject_sha256": ""}, "nicht benannt"),
        ({"authorisation_subject_sha256": "f" * 64}, "passen nicht zusammen"),
        ({"authorised_at": ""}, "ISO-8601"),
        ({"started_at": ""}, "ISO-8601"),
        ({"authorised_at": "a", "started_at": "z"}, "ISO-8601"),
    ],
)
def test_a_run_without_real_authorisation_is_refused(kw, match):
    """Eine beliebige nichtleere Zeichenkette ist keine Autorisierung."""
    with pytest.raises(UnauthorisedRun, match=match):
        receipt(FINISH_OK, **kw).validate(GATE)


def test_a_run_started_before_the_gate_is_never_backdated():
    """test_corsia.sh:95 - vor dem GATE begonnener Pass 1 wird nicht
    rueckwirkend belegt. Sonst waere die Freigabe eine Formalie."""
    with pytest.raises(UnauthorisedRun, match="nicht rückwirkend"):
        receipt(FINISH_OK, started_at="2026-09-01T09:59:00+00:00").validate(GATE)


def test_a_run_started_after_the_gate_validates():
    receipt(FINISH_OK).validate(GATE)


def test_a_wellformed_but_invented_reference_is_not_a_proof():
    """PI-1@aaaaaaaaaaaa ist wohlgeformt und frei erfunden. validate() ohne die
    tatsaechliche Entscheidung darf nicht durchgehen."""
    with pytest.raises(UnauthorisedRun, match="braucht die Entscheidung"):
        receipt(FINISH_OK).validate()
    other = Decision(
        record_id="SANDBOX-001",
        artifact="transcript.confirmed",
        subject_sha256="e" * 64,
        verdict=Verdict.ACCEPT,
        reference="PI-2026-09-01-0007",
        actor="operator",
    )
    with pytest.raises(UnauthorisedRun, match="passt nicht zu dieser"):
        receipt(FINISH_OK).validate(other)


def test_a_receipt_is_structurally_not_an_acceptance():
    """test_corsia.sh:56 und :114 - technische Belege sind keine Annahme.
    Im Modell sind das verschiedene Typen; ein Receipt hat kein Verdikt."""
    from ohpipe.domain.decision import Decision

    r = receipt(FINISH_OK)
    assert not hasattr(r, "verdict")
    assert not isinstance(r, Decision)
    assert not any("accept" in f.lower() for f in r.to_json())


# ------------------------------------------------------ Gates (corsia:165)


def test_a_passing_gate_cannot_override_a_failing_one():
    """Ein bestandenes Gate ist keine Vollmacht."""
    from ohpipe.policies.exit_contract import Status
    from ohpipe.policies.gates import GateResult, evaluate

    rep = evaluate(
        [
            GateResult("consent", Status.READY),
            GateResult("processing_route", Status.READY),
            GateResult("name_scan", Status.STOP, "Treffer in der Beilage", "STOP_NAME_FOUND"),
        ]
    )
    assert rep.status is Status.STOP
    assert rep.exit_code == 1
    assert "name_scan" in rep.reason


def test_no_gates_evaluated_is_not_all_clear():
    from ohpipe.policies.exit_contract import Status
    from ohpipe.policies.gates import evaluate

    assert evaluate([]).status is Status.STOP


def test_worst_status_wins_and_expected_halts_stay_yellow():
    from ohpipe.policies.exit_contract import Status
    from ohpipe.policies.gates import GateResult, evaluate

    rep = evaluate(
        [
            GateResult("a", Status.READY),
            GateResult("b", Status.ACTION_NEEDED, "Feld fehlt"),
        ]
    )
    assert rep.status is Status.ACTION_NEEDED and rep.exit_code == 3


def test_the_cli_has_no_bypass_or_free_model_channel():
    """test_simple.sh:151 - `--yes` bleibt CONFIG; test_corsia.sh:184/186 - es
    gibt keinen freien --model-Kanal und keinen generischen Evidence-Schreiber.
    Hier ist die staerkere Fassung: die Optionen existieren gar nicht."""
    from ohpipe.cli.main import build_parser

    opts = {s for a in build_parser()._actions for s in a.option_strings}
    for forbidden in (
        "--yes",
        "-y",
        "--force",
        "--skip-gate",
        "--allow-stale",
        "--model",
        "--no-verify",
    ):
        assert forbidden not in opts, f"{forbidden} ist ein Umgehungspfad"


# ------------------------------------------------ Egress: Pfad UND Reihenfolge


def test_a_gate_only_before_the_model_does_not_protect_the_export():
    """Der Befund: eine fruehere Fassung akzeptierte diesen Graphen als sicher.
    Das ist genau die Konstellation des Vorgaengersystems - der Mensch
    bestaetigt das Transkript, danach laeuft die Modellstatistik ungeprueft
    nach aussen."""
    g = StepGraph(
        steps=(
            Step("ingest", Kind.DETERMINISTIC, produces=("t",)),
            Step("confirm", Kind.HUMAN, requires=("t",), produces=("tc",), human_gate=True),
            Step("suggest", Kind.MODEL, requires=("tc",), produces=("s",)),
            Step("publish", Kind.EGRESS, requires=("s",), produces=("b",), leaves_system=True),
        )
    )
    v = check_egress_gates(g)
    assert len(v) == 1 and "hinter dem Modellschritt" in v[0]


def test_every_path_is_checked_not_just_one():
    """Ein Umgehungspfad neben einem gesicherten bleibt ein Umgehungspfad."""
    g = StepGraph(
        steps=(
            Step("ingest", Kind.DETERMINISTIC, produces=("t",)),
            Step("suggest", Kind.MODEL, requires=("t",), produces=("s",)),
            Step("review", Kind.HUMAN, requires=("s",), produces=("adj",), human_gate=True),
            Step("safe", Kind.DETERMINISTIC, requires=("adj",), produces=("bundle_a",)),
            Step("shortcut", Kind.DETERMINISTIC, requires=("s",), produces=("bundle_b",)),
            Step(
                "publish",
                Kind.EGRESS,
                requires=("bundle_a", "bundle_b"),
                produces=("out",),
                leaves_system=True,
            ),
        )
    )
    v = check_egress_gates(g)
    assert len(v) == 1 and "shortcut" in v[0]


# ------------------------------------------------------- Decision-Pflichten


def test_an_empty_decision_cannot_be_constructed():
    """Sonst deckt sie den leeren Hash, und 'gebunden an Bytes' ist eine
    Behauptung ohne Pruefung."""
    with pytest.raises(InvalidDecision):
        Decision(
            record_id="",
            artifact="",
            subject_sha256="",
            verdict=Verdict.ACCEPT,
            reference="",
            actor="",
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("record_id", ""),
        ("artifact", ""),
        ("actor", ""),
        ("subject_sha256", "nichthex"),
        ("subject_sha256", "ab"),
        ("reference", "zwei woerter"),
        ("reference", "mit\ttab"),
        ("reference", "ab"),
    ],
)
def test_decision_requires_every_field(field, value):
    base = {
        "record_id": "R-1",
        "artifact": "a",
        "subject_sha256": "a" * 64,
        "verdict": Verdict.ACCEPT,
        "reference": "PI-1",
        "actor": "operator",
    }
    with pytest.raises(InvalidDecision):
        Decision(**{**base, field: value})


def test_covers_rejects_a_non_sha_subject():
    d = Decision(
        record_id="R-1",
        artifact="a",
        subject_sha256="a" * 64,
        verdict=Verdict.ACCEPT,
        reference="PI-1",
        actor="operator",
    )
    assert d.covers("a" * 64)
    assert not d.covers("")
    assert not d.covers("nichthex")


# ------------------------- Die Egress-Luecke (Review 04.08., P0-1)


def test_a_step_may_not_be_model_and_leave_the_system_at_once():
    """P0-1 — Die Kerninvariante hatte ein Loch, und zwar das einzige, das zählt.

    ``check_egress_gates`` prüfte nur Modelle **upstream** des Ausgangs.
    ``graph.upstream(egress)`` enthält den Ausgang selbst nicht — ein Schritt,
    der zugleich ``Kind.MODEL`` und ``leaves_system=True`` ist, wurde nie
    geprüft, und der CI-Job meldete „kein Modellpfad ohne menschliches Gate".

    Das ist genau die Konstellation, die im Vorgängersystem offen war, nur
    einen Schritt kürzer — und es ist die eine Zusage, mit der das Projekt in
    die Präsentation geht.
    """
    with pytest.raises(GraphError) as exc:
        Step(
            "model_export",
            Kind.MODEL,
            requires=("t",),
            produces=("bundle",),
            leaves_system=True,
        )
    assert "egress" in str(exc.value)


def test_the_checker_catches_it_even_without_the_constructor():
    """Die Gegenprobe auf einer Ebene tiefer.

    Eine Invariante, die sich darauf verlässt, dass ein Konstruktor an anderer
    Stelle schon aufgepasst hat, ist keine Invariante. Der Schritt wird hier
    unter Umgehung von ``__post_init__`` gebaut — der Prüfer muss ihn trotzdem
    finden.
    """
    schmuggel = Step(
        "model_export", Kind.EGRESS, requires=("t",), produces=("b",), leaves_system=True
    )
    object.__setattr__(schmuggel, "kind", Kind.MODEL)
    g = StepGraph(steps=(Step("ingest", Kind.DETERMINISTIC, produces=("t",)), schmuggel))

    verstoesse = check_egress_gates(g)
    assert verstoesse, "der Prüfer sieht den Ausgang selbst nicht an"
    assert "model_export" in verstoesse[0]


def test_every_shipped_profile_builds_a_graph_that_holds_the_invariant():
    """A-1 — Die CI bewies die Invariante über einen Graphen, den die
    Produktion nicht verwendet.

    ``DEFAULT_GRAPH`` war eine Modulkonstante; ADR 0024 verlangt den Graphen
    aus dem validierten Profil. Ein grüner Job über den Standardgraphen sagt
    etwas Wahres über etwas Unbenutztes — die gefährlichste Sorte grün.
    """
    from ohpipe.domain.step import build_graph
    from ohpipe.project import Profile

    wurzel = Path(__file__).resolve().parents[1] / "src/ohpipe/profiles"
    profile = sorted(wurzel.glob("*/profile.toml"))
    assert profile, "keine mitgelieferten Profile gefunden"
    for datei in profile:
        p = Profile.load(datei)
        g = build_graph(p)
        assert check_egress_gates(g) == [], f"{p.id}: Egress-Invariante verletzt"


def test_a_profile_requiring_pseudonymisation_has_no_direct_edge_to_l1():
    """ADR 0024: „enthält nur die gewählte Kante".

    Kein Laufzeit-Flag, kein Per-Record-Override, kein Fallback. Verlangt das
    Profil den Schritt, existiert die direkte Kante im gebauten Graphen nicht.
    """
    from ohpipe.domain.step import build_graph
    from ohpipe.project import Profile

    wurzel = Path(__file__).resolve().parents[1] / "src/ohpipe/profiles"
    childlux = build_graph(Profile.load(wurzel / "childlux/profile.toml"))
    sandbox = build_graph(Profile.load(wurzel / "sandbox/profile.toml"))

    assert childlux.get("l1.suggest").requires == ("transcript.pseudonymised.confirmed",)
    assert sandbox.get("l1.suggest").requires == ("transcript.confirmed",)

    nach_transkript = {"transcript.revision", "transcript.confirmed"}
    geplant = [s.name for s in childlux.plan(nach_transkript).steps]
    assert "l1.suggest" not in geplant, geplant
    assert "pii.detect" in geplant, geplant
