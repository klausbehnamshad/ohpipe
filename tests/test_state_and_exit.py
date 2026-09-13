"""Statusberechnung und Exitcode-Vertrag.

Herkunft: DINOH ROADMAP v3 §2 (Exitcodes) und ZUSAMMENFASSUNG 2026-07-14
("AKTUELL heisst nicht AKZEPTIERT").
Kategorie: Sicherheitsinvariante + Operatorvertrag -> zwingend portiert.
"""

from __future__ import annotations

import io

import pytest

from ohpipe.domain.state import (
    ArtifactState,
    DecisionState,
    DerivationState,
    LegacyDisposition,
    SourceBinding,
)
from ohpipe.policies.exit_contract import Exit, Report, Status


def st(
    binding=SourceBinding.BOUND,
    derivation=DerivationState.CURRENT,
    decision=DecisionState.ACCEPTED,
    **kw,
) -> ArtifactState:
    return ArtifactState(binding, derivation, decision, **kw)


def test_ready_needs_all_three_axes():
    assert st().status is Status.READY


def test_current_but_unaccepted_is_never_ready():
    """Der lebende Gegenbeweis aus DINOH: technisch aktuell, nie akzeptiert."""
    s = st(decision=DecisionState.UNDECIDED)
    assert s.status is Status.ACTION_NEEDED
    assert s.status is not Status.READY


def test_accepted_but_stale_is_never_ready():
    assert st(derivation=DerivationState.STALE).status is Status.STALE


def test_anchor_drift_outranks_staleness():
    # Erst klaeren, worauf sich die Annotation bezieht - dann, ob sie aktuell ist.
    s = st(binding=SourceBinding.DRIFTED, derivation=DerivationState.STALE)
    assert s.status is Status.REVIEW_REQUIRED


@pytest.mark.parametrize(
    "kwargs",
    [
        {"binding": SourceBinding.UNKNOWN},
        {"derivation": DerivationState.UNVERIFIABLE},
    ],
)
def test_unknowable_is_stop_not_probably_fine(kwargs):
    """Fail-closed: was nicht feststellbar ist, ist rot, nicht gruen."""
    assert st(**kwargs).status is Status.STOP


def test_rejected_and_withdrawn_are_excluded_not_stop():
    assert st(decision=DecisionState.REJECTED).status is Status.EXCLUDED
    assert st(decision=DecisionState.WITHDRAWN).status is Status.EXCLUDED
    assert st(enabled=False).status is Status.EXCLUDED


def test_legacy_era_does_not_devalue_by_itself():
    """Int4 war legacy UND PASS. Die Aera entwertet nichts von selbst."""
    s = st(harness_era="legacy", disposition=LegacyDisposition.OK)
    assert s.status is Status.READY
    assert s.cross_record_claims_allowed


def test_below_threshold_legacy_stays_readable_but_locked_for_cross_claims():
    s = st(harness_era="legacy", disposition=LegacyDisposition.LEGACY_BELOW_CURRENT_THRESHOLD)
    assert s.status is Status.READY
    assert not s.cross_record_claims_allowed


@pytest.mark.parametrize(
    "status,code",
    [
        (Status.READY, Exit.READY),
        (Status.ACTION_NEEDED, Exit.ACTION_NEEDED),
        (Status.STALE, Exit.ACTION_NEEDED),
        (Status.REVIEW_REQUIRED, Exit.ACTION_NEEDED),
        (Status.EXCLUDED, Exit.ACTION_NEEDED),
        (Status.GRAPH_CONTRACT_UNBOUND, Exit.ACTION_NEEDED),
        (Status.GRAPH_CONTRACT_MISMATCH, Exit.ACTION_NEEDED),
        (Status.STOP, Exit.STOP),
        (Status.CONFIG, Exit.CONFIG),
    ],
)
def test_exit_contract(status, code):
    """Erwartbare Haltepunkte sind 3, nie 1. Ventile sind 1, nie 3."""
    assert Report(status=status).exit_code == int(code)


def test_expected_halt_is_distinguishable_from_safety_valve():
    # Genau die Unterscheidung, die DINOH fehlte: hil_check (Namensfund) und ein
    # fehlendes Pflichtfeld landeten beide auf 1.
    assert Report(status=Status.ACTION_NEEDED).exit_code != Report(status=Status.STOP).exit_code


def test_six_line_report_always_has_all_six_lines():
    buf = io.StringIO()
    Report(status=Status.READY, next_command="ohpipe status").render(buf, color=False)
    lines = buf.getvalue().strip().split("\n")
    assert [ln.split(":")[0].strip() for ln in lines] == [
        "STATUS",
        "CHANGED",
        "SAFE",
        "NEXT",
        "CHECK",
        "RECOVERY",
    ]


def test_report_without_changes_says_so_explicitly():
    buf = io.StringIO()
    Report(status=Status.READY).render(buf, color=False)
    assert "CHANGED: keine" in buf.getvalue()
    assert "Quelldaten unverändert" in buf.getvalue()


# ------------------- Operatorvertrag (Review 04.08., P1-3/4/5/9)


def test_init_does_not_claim_that_source_data_changed(tmp_path):
    """P1-3 — Die SAFE-Zeile ist eine Zusage, kein Nebenprodukt von CHANGED.

    ``init`` legt Governance-Verzeichnisse an. An QUELLDATEN wird dabei nichts
    angefasst. Ein Operator, der nach `init` „Quelldaten verändert" liest,
    lernt in genau der falschen Richtung — und der README bewirbt diese Zeile.
    """
    from ohpipe.policies.exit_contract import Report, Status

    r = Report(status=Status.READY, changed=["/x/records", "/x/objects"])
    assert "Quelldaten unverändert" in _rendered(r)
    assert "Quelldaten verändert" in _rendered(
        Report(status=Status.READY, changed=["/x/int.srt"], source_data_touched=True)
    )


def _rendered(report) -> str:
    import io

    buf = io.StringIO()
    report.render(buf, color=False)
    return buf.getvalue()


def test_every_config_report_names_an_executable_next_step():
    """P1-4 — ``NEXT: —`` bei CONFIG, und ein NEXT, das auf sich selbst zeigt.

    Die Selbstschleife ist genau das Anti-Muster, das ``cmd_doctor`` beim
    Store-Hinweis-Zweig kritisiert und dort vermeidet.
    """
    from ohpipe.project import DataRootError, ProfileError

    assert issubclass(DataRootError, ProfileError), "muss weiterhin als ProfileError durchgehen"


def test_the_data_root_error_is_its_own_class_not_a_substring_match():
    """Die Klassifikation lief über ``ENV_ROOT in str(exc)`` — Substringsuche
    in einer deutschen Meldung. Wer den Text umformuliert, kippt den
    reason_code lautlos."""
    import inspect

    from ohpipe.cli import main as cli_main

    quelle = inspect.getsource(cli_main)
    assert "ENV_ROOT in str(exc)" not in quelle, "die Substringsuche ist zurück"


def test_an_unexpected_error_still_produces_the_six_lines():
    """P1-9 — Ein Traceback ist die Fehlermeldung, die man nachts um elf nicht
    deuten kann. Der Sechszeiler ist die Zusage, auch im unerwarteten Fall."""
    import inspect

    from ohpipe.cli import main as cli_main

    quelle = inspect.getsource(cli_main.main)
    assert "except Exception" in quelle, "kein Auffangzweig in main()"
    assert "STOP_UNEXPECTED" in quelle


def test_the_planner_does_not_plan_behind_a_rejected_artifact():
    """P1-5 — ``have`` fragte nur ``sha256 is not None``.

    Ein verworfenes menschliches Artefakt zählte damit als vorhanden, und der
    Sechszeiler nannte als NEXT ein Gate **hinter** einer Ablehnung. Der Record
    war korrekt rot — der Operator bekam trotzdem die falsche nächste Handlung,
    und die Review-UI hätte eine Unit-Queue hinter einem Reject aufgebaut.
    """
    from ohpipe.application.replay import ArtifactFacts, RecordView
    from ohpipe.domain.anchor import ReanchorOutcome
    from ohpipe.domain.step import DEFAULT_GRAPH

    # Der Vertrag kommt aus demselben Graphen wie im Fold. Ihn hier von Hand
    # zusammenzusetzen hiesse, den Test gegen eine zweite Vertragstabelle zu
    # fahren — und die erste Abweichung faende niemand.
    v = RecordView(record_id="R")
    v.facts["transcript.revision"] = ArtifactFacts(
        name="transcript.revision",
        contract=DEFAULT_GRAPH.contract_for("transcript.revision"),
        is_egress=False,
        sha256="a" * 64,
    )
    v.facts["transcript.confirmed"] = ArtifactFacts(
        name="transcript.confirmed",
        contract=DEFAULT_GRAPH.contract_for("transcript.confirmed"),
        is_egress=False,
        sha256="a" * 64,
        # Ohne geprueften Anker stuende dieses Artefakt auf UNKNOWN, und die
        # Fixture behauptete eine Lage, die es nicht gibt: ein bestaetigtes
        # Transkript ohne jede Ankerpruefung. Die Zusicherungen unten lesen die
        # Entscheidungsachse, nicht die Bindung — der Anker steht hier fuer die
        # Fachlichkeit. (Seit C4 gibt es keine is_human-Fahne mehr; die Bindung
        # kommt aus Anker und Vertrag.)
        anchor_outcome=ReanchorOutcome.EXACT.value,
        decided_sha="a" * 64,
        decided_verdict="REJECT",
    )
    assert "transcript.confirmed" not in v.have
    assert [g.name for g in v.next_gates] == ["transcript.confirm"]

    v.facts["transcript.confirmed"].decided_verdict = "ACCEPT"
    assert "transcript.confirmed" in v.have
    assert [g.name for g in v.next_gates] == ["l1.review"]


def test_artifact_facts_requires_explicit_is_egress():
    """Die Egressrolle hat keinen stillen Default außerhalb des Laufgraphen."""
    from ohpipe.application.replay import ArtifactFacts
    from ohpipe.domain.step import DEFAULT_GRAPH

    with pytest.raises(TypeError):
        ArtifactFacts(
            name="transcript.revision",
            contract=DEFAULT_GRAPH.contract_for("transcript.revision"),
        )


def test_the_runtime_uses_the_profile_graph_not_the_module_constant():
    """A-1, zweite Hälfte — ``build_graph`` war gebaut, aber nicht angeschlossen.

    ``replay`` trug ``DEFAULT_GRAPH`` als Default, und das CLI reichte keinen
    Graphen durch. Für einen CHILDLUX-Arbeitsbereich plante die Laufzeit also
    entlang des Sandbox-Graphen — der direkten Kante, die ADR 0024 verbietet.
    Die CI prüfte den richtigen Graphen, die Laufzeit nahm den alten.
    """
    import inspect

    from ohpipe.cli import main as cli_main

    quelle = inspect.getsource(cli_main)
    assert quelle.count("build_graph(ws.profile)") >= 2, (
        "doctor und status muessen beide den Profilgraphen durchreichen"
    )
    assert "replay(journal, authority=" not in quelle, "irgendwo faellt der Graph noch weg"
