"""C2-Nachtrag: die zwei Profilvertrag-Zusagen mit messbaren Zaehnen.

Der C2-Produktcode war korrekt, aber zwei unabhaengige Gegenmutationen
ueberlebten die gesamte Suite: Der Provenienzvertrag konnte wirkungslos
werden, und der Fold konnte den uebergebenen Profilgraphen durch den
Sandbox-Graphen ersetzen. Diese Tests sichern beide Gegenrichtungen direkt
am Replay und asserten ihre Voraussetzungen, bevor sie den Zustand lesen.
"""

from __future__ import annotations

from pathlib import Path

from ohpipe.application.replay import replay
from ohpipe.domain.events import ARTIFACT_PRODUCED
from ohpipe.domain.state import DecisionState, DerivationState, SourceBinding
from ohpipe.domain.step import DEFAULT_GRAPH, build_graph
from ohpipe.journal import Event
from ohpipe.policies.exit_contract import Status
from ohpipe.project import Profile

PROFILE_ROOT = Path(__file__).resolve().parents[1] / "src/ohpipe/profiles"
RECORD = "CHILDLUX-0007"


def _produced(artifact: str) -> Event:
    return Event(
        seq=1,
        at="2026-09-01T10:00:00+00:00",
        kind=ARTIFACT_PRODUCED,
        record_id=RECORD,
        payload={"artifact": artifact, "sha256": "a" * 64},
        prev="0" * 64,
    )


def test_provenance_required_without_a_receipt_stays_unverifiable_and_stops():
    """Bytes allein duerfen einen provenance-pflichtigen Vertrag nie erfuellen."""
    artifact = "l1.coverage"
    assert artifact in DEFAULT_GRAPH.artifacts
    contract = DEFAULT_GRAPH.contract_for(artifact)
    assert contract.binding_required is False
    assert contract.provenance_required is True
    assert contract.decision_required is False

    view = replay([_produced(artifact)], graph=DEFAULT_GRAPH)[RECORD]
    assert view.findings == []
    assert view.facts[artifact].contract == contract

    state = view.artifacts[artifact]
    assert state.source_binding is SourceBinding.NOT_APPLICABLE
    assert state.derivation_state is DerivationState.UNVERIFIABLE
    assert state.decision_state is DecisionState.NOT_APPLICABLE
    assert state.status is Status.STOP


def test_replay_uses_the_childlux_graph_contract_for_pii_spans():
    """Der Fold nimmt den Vertrag aus dem uebergebenen CHILDLUX-Graphen."""
    artifact = "pii.spans"
    childlux = build_graph(Profile.load(PROFILE_ROOT / "childlux/profile.toml"))
    assert artifact in childlux.artifacts
    assert artifact not in DEFAULT_GRAPH.artifacts
    contract = childlux.contract_for(artifact)
    assert contract.binding_required is True
    assert contract.provenance_required is True
    assert contract.decision_required is False

    view = replay([_produced(artifact)], graph=childlux)[RECORD]
    assert view.findings == []
    assert view.facts[artifact].contract == contract

    state = view.artifacts[artifact]
    assert state.source_binding is SourceBinding.UNKNOWN
    assert state.derivation_state is DerivationState.UNVERIFIABLE
    assert state.decision_state is DecisionState.NOT_APPLICABLE
    assert state.status is Status.STOP
