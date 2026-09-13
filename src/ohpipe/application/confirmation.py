"""ConfirmPlan und transcript.confirm-Writer ohne CLI-Sachlogik."""

from __future__ import annotations

from dataclasses import dataclass

from ..domain.confirmation import ConfirmationDecision, ConfirmationMarker
from ..domain.anchor import ReanchorOutcome
from ..domain.events import ANCHOR_CHECKED, ARTIFACT_PRODUCED, DECISION_RECORDED
from ..domain.instance import InstanceRegistry
from ..domain.operation import EVENT_CATALOG_VERSION, RETRY_INTENT_VERSION, RetryIntent
from ..journal import Journal
from ..policies.exit_contract import Report, Status
from ..project import Workspace
from .operation_recovery import Effect, b3b_report, execute_intent

__all__ = ["ConfirmPlan", "plan_confirmation", "write_confirmation"]


@dataclass(frozen=True)
class ConfirmPlan:
    marker: ConfirmationMarker
    decision: ConfirmationDecision
    actor_state_sha256: str
    actor_event_digest: str | None
    human_registry_events: tuple[str, ...] | None = None
    revision_event_digest: str | None = None
    confirmation_events: tuple[str | None, str | None] = (None, None)
    previous_confirmation_sha256: str | None = None


def _human_registry_events(events: list[object]) -> tuple[str, ...]:
    """Keep human-registry history, including an A -> A+B -> A change."""
    humans: set[str] = set()
    history = []
    for event in events:
        if event.kind == "instance.registered" and event.payload.get("source") == "mensch":
            humans.add(event.payload["coder_id"])
            history.append(event.digest)
        elif event.kind == "instance.retired" and event.payload.get("coder_id") in humans:
            history.append(event.digest)
    return tuple(history)


def _latest_revision(events: list[object], record_id: str):
    return next(
        (
            event
            for event in reversed(events)
            if event.kind == ARTIFACT_PRODUCED
            and event.record_id == record_id
            and event.payload.get("artifact") == "transcript.revision"
        ),
        None,
    )


def _confirmation_events(events: list[object], record_id: str):
    return tuple(
        next(
            (
                event
                for event in reversed(events)
                if event.kind == kind
                and event.record_id == record_id
                and event.payload.get("artifact") == "transcript.confirmed"
            ),
            None,
        )
        for kind in (ARTIFACT_PRODUCED, DECISION_RECORDED)
    )


def plan_confirmation(
    *,
    record_id: str,
    projection_version: str,
    revision_sha256: str,
    actor: str,
    fulltext_origin: str,
    fulltext_receipt: str,
    iso6393_release: str,
    iso6393_vocabulary_sha256: str,
    iso6393_snapshot_receipt: str,
    events: list[object],
    profile_id: str | None = None,
    graph_sha256: str | None = None,
    automatic_actor: bool = False,
) -> ConfirmPlan:
    registry = InstanceRegistry.from_events(events)
    instance = registry.get(actor, active=True)
    if instance.source != "mensch":
        raise ValueError("transcript.confirm verlangt eine aktive menschliche Instanz")
    if automatic_actor and registry.active_humans() != (instance,):
        raise ValueError("Automatische Auswahl verlangt genau eine aktive menschliche Instanz")
    marker = ConfirmationMarker(
        record_id=record_id,
        projection_version=projection_version,
        revision_sha256=revision_sha256,
    )
    decision = ConfirmationDecision.create(
        marker=marker,
        profile_id=profile_id,
        graph_sha256=graph_sha256,
        actor=actor,
        fulltext_origin=fulltext_origin,
        fulltext_receipt=fulltext_receipt,
        iso6393_release=iso6393_release,
        iso6393_vocabulary_sha256=iso6393_vocabulary_sha256,
        iso6393_snapshot_receipt=iso6393_snapshot_receipt,
    )
    revision = _latest_revision(events, record_id)
    confirmation, prior_decision = _confirmation_events(events, record_id)
    return ConfirmPlan(
        marker,
        decision,
        instance.state_sha256,
        instance.event_digest,
        _human_registry_events(events) if automatic_actor else None,
        revision.digest if revision is not None else None,
        (
            confirmation.digest if confirmation else None,
            prior_decision.digest if prior_decision else None,
        ),
        confirmation.payload["sha256"] if confirmation else None,
    )


class _StaleConfirmation(ValueError):
    pass


def _checked_intent(ws: Workspace, journal: Journal, plan: ConfirmPlan) -> RetryIntent:
    """Called by execute_intent under the shared writer lock, before any effect."""
    events = journal.verified_events()
    registry = InstanceRegistry.from_events(events)
    try:
        actor = registry.get(plan.decision.actor, active=True)
    except ValueError as exc:
        raise _StaleConfirmation from exc
    revision = _latest_revision(events, plan.marker.record_id)
    confirmation, decision = _confirmation_events(events, plan.marker.record_id)
    current_confirmation_events = (
        confirmation.digest if confirmation else None,
        decision.digest if decision else None,
    )
    own_retry = (
        confirmation is not None
        and confirmation.payload.get("sha256") == plan.marker.sha256
        and decision is not None
        and decision.payload == plan.decision.object()
    )
    if (
        actor.source != "mensch"
        or actor.state_sha256 != plan.actor_state_sha256
        or actor.event_digest != plan.actor_event_digest
        or (
            plan.human_registry_events is not None
            and _human_registry_events(events) != plan.human_registry_events
        )
        or revision is None
        or revision.payload.get("sha256") != plan.marker.revision_sha256
        or (
            plan.revision_event_digest is not None and revision.digest != plan.revision_event_digest
        )
        or (current_confirmation_events != plan.confirmation_events and not own_retry)
    ):
        raise _StaleConfirmation
    return _intent(ws, plan)


def _intent(ws: Workspace, plan: ConfirmPlan) -> RetryIntent:
    workspace = ws.running_graph_sha256()
    return RetryIntent(
        workspace_id=workspace,
        command="transcript_confirm",
        target_key={
            "workspace_id": workspace,
            "record_id": plan.marker.record_id,
            "marker_sha256": plan.marker.sha256,
        },
        inputs={
            "revision_sha256": plan.marker.revision_sha256,
            "marker_sha256": plan.marker.sha256,
            "decision_id": plan.decision.decision_id,
        },
        store_bindings={
            "confirmation_marker_store": {
                "address": plan.marker.sha256,
                "sha256": plan.marker.sha256,
            }
        },
        causal_prestate={
            "current_revision_sha256": plan.marker.revision_sha256,
            "current_revision_event_digest": plan.revision_event_digest,
            "actor_state_sha256": plan.actor_state_sha256,
            "actor_state_event_digest": plan.actor_event_digest,
            "current_confirmation_sha256": plan.previous_confirmation_sha256,
            "current_confirmation_event_digest": plan.confirmation_events[1],
        },
        rule_versions={
            "event_catalog": EVENT_CATALOG_VERSION,
            "retry_intent": RETRY_INTENT_VERSION,
            "confirmation_marker": "transcript-confirmation-marker-v1",
            "confirmation_decision": (
                "transcript-confirmation-decision-v2"
                if plan.decision.profile_id is not None
                else "transcript-confirmation-decision-v1"
            ),
        },
        idempotency_keys={
            "marker_key": plan.marker.sha256,
            "decision_key": plan.decision.decision_id,
        },
        routing_keys={
            "decision_routing_key": [
                workspace,
                plan.marker.record_id,
                "transcript.confirmed",
            ]
        },
        desired_effect={
            "event_sequence": [
                "operation.intent.recorded",
                ARTIFACT_PRODUCED,
                DECISION_RECORDED,
            ],
            "store_outputs": {
                "retry_intent_store": "SELF_OPERATION_INTENT_SHA256",
                "confirmation_marker_store": plan.marker.sha256,
            },
            "system_bindings": {"operation_intent_sha256": "SELF_OPERATION_INTENT_SHA256"},
        },
    )


def _anchor_confirmed(journal: Journal, record_id: str) -> bool:
    """Die Bindungsevidenz zur Bestaetigung — der Satz, den nur dieser Akt sagen kann.

    ``transcript.confirmed`` traegt ``binding_required=True``
    (`src/ohpipe/domain/step.py::_BASISVERTRAEGE`). Evidenz der Bindungsachse
    ist ausschliesslich ein ``anchor.checked``; ohne eines steht die Achse auf
    ``UNKNOWN``, und ``UNKNOWN`` ist fail-closed ``STOP``. Ohne diese Zeile war
    ein bestaetigtes Transkript deshalb rot, obwohl der Mensch genau die
    Fassung bestaetigt hatte, an die gebunden wird.

    ``exact`` ist hier keine Messung, sondern der Sachverhalt: der Marker
    bindet ``revision_sha256``, die Entscheidung fuehrt dieselbe Fassung in
    ``input_refs``. Ein Re-Anchoring gaebe es erst, wenn sich die Fassung
    bewegt — und dann schreibt es der Korrekturpfad, nicht dieser Akt.

    NICHT im Intent, sondern danach und idempotent: der Intent von
    ``transcript_confirm`` ist mit seiner Ereignisfolge gebunden, und eine
    dritte Wirkung darin waere ein anderer Aktdigest. Der Preis ist ein
    schmales Fenster zwischen Entscheidung und Bindung; er wird bezahlt, indem
    derselbe Befehl die fehlende Zeile beim naechsten Lauf nachtraegt — auch
    im Nulldurchgang.
    """
    return (
        journal.append_once(
            ANCHOR_CHECKED,
            {"artifact": "transcript.confirmed", "outcome": ReanchorOutcome.EXACT.value},
            record_id=record_id,
            duplikat=lambda e: (
                e.payload.get("artifact") == "transcript.confirmed"
                and e.payload.get("outcome") == ReanchorOutcome.EXACT.value
            ),
        )
        is not None
    )


def write_confirmation(ws: Workspace, journal: Journal, plan: ConfirmPlan) -> Report:
    decision_payload = plan.decision.object()
    try:
        intent, events = execute_intent(
            ws,
            journal,
            lambda: _checked_intent(ws, journal, plan),
            lambda _intent_value: [
                Effect(
                    ARTIFACT_PRODUCED,
                    {"artifact": "transcript.confirmed", "sha256": plan.marker.sha256},
                    plan.marker.record_id,
                ),
                Effect(DECISION_RECORDED, decision_payload, plan.marker.record_id),
            ],
            pre_intent_objects=(plan.marker.bytes,),
        )
    except _StaleConfirmation:
        return b3b_report(
            Status.ACTION_NEEDED,
            "ACTION_B3B_CONFIRMATION_STALE",
            "Personenauswahl, Transkriptfassung oder Bestätigungsstand haben sich seit der Vorschau geändert. "
            "Die Bestätigung wurde nicht geschrieben; eine neue Vorschau ist erforderlich.",
            next_command="ohpipe --json status",
        )
    if not events:
        nachgetragen = _anchor_confirmed(journal, plan.marker.record_id)
        return b3b_report(
            Status.READY,
            "READY_B3B_NULLDURCHGANG",
            "Exakt diese Aktivierung ist bereits wirksam."
            + (" Die fehlende Bindungsevidenz wurde nachgetragen." if nachgetragen else ""),
            changed=[str(ws.journal_path)] if nachgetragen else [],
            operation_result="NULLDURCHGANG",
        )
    _anchor_confirmed(journal, plan.marker.record_id)
    return b3b_report(
        Status.READY,
        "READY_B3B_WRITTEN",
        "Marker, Aktivierungsdecision und Bindungsevidenz sind geschrieben.",
        changed=[str(ws.journal_path), str(ws.objects / plan.marker.sha256)],
        operation_result="WRITTEN",
        details={
            "intent_sha256": intent.sha256,
            "events": [event.kind for event in events],
            "anchor_outcome": ReanchorOutcome.EXACT.value,
        },
    )
