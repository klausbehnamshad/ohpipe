"""Ein Leser für deklarierte Textgates: Marker ist Evidenz, Revision ist Inhalt.

V1-Marker bleiben bytegleich. Ihre Rolle transcript wird über Step.confirms
aufgelöst; neue Bestätigungsentscheidungen binden zusätzlich Profil und Graph.
V2-Marker erlauben andere Gate-/Textnamen, ohne einen Erzeuger zu implementieren.
"""

from __future__ import annotations

from ohpipe.domain import manual_context

import json
import hashlib
from dataclasses import dataclass
from typing import Any

from ..domain.confirmation import ConfirmationMarker, TextConfirmationMarker
from ..domain.decision import Decision
from ..domain.operation import canonical_json_bytes
from ..domain.revision_serialization import verify_revision
from ..domain.step import build_graph, confirmed_text_role
from ..domain.transcript import TranscriptRevision
from ..policies.authority import Authority
from ..project import GraphBindingState
from .replay import RecordView, replay


class ConfirmedTextError(RuntimeError):
    """Keine Textverwendung; Meldung nennt das aufgelöste Gate und seinen Folgeweg."""


@dataclass(frozen=True)
class ConfirmedText:
    gate_artifact: str
    text_artifact: str
    marker_sha256: str
    text_sha256: str
    revision: TranscriptRevision
    revision_bytes: bytes
    decision: Decision
    view: RecordView
    events: tuple[Any, ...]

    @property
    def inputs(self) -> dict[str, str]:
        return {self.gate_artifact: self.marker_sha256, self.text_artifact: self.text_sha256}


def confirmation_command(ctx, gate) -> str:
    # Lokaler Import vermeidet einen Zyklus mit den registrierten Verbrauchern.
    from .steps import registry_for

    handler = registry_for(ctx.ws.profile).get(gate.name)
    if handler is not None and handler.next_command is not None:
        return handler.next_command(ctx)
    return ctx.command("continue", ctx.record_id) + f" # Gate {gate.name}: noch kein Handler"


def read_confirmed_text(ctx, supplied_view: RecordView, step_name: str) -> ConfirmedText:
    graph = build_graph(ctx.ws.profile)
    gate_artifact, gate, text_artifact = confirmed_text_role(graph, step_name)
    command = confirmation_command(ctx, gate)

    def halt(reason):
        raise ConfirmedTextError(
            f"{step_name}: {reason}; Gate {gate.name} ({gate_artifact}). NEXT: {command}"
        )

    if supplied_view.record_id != ctx.record_id or supplied_view.graph != graph:
        halt("Record-/Graphkontext der Eingabesicht passt nicht")
    state, _, graph_sha = ctx.ws.inspect_graph_binding()
    if state is not GraphBindingState.CURRENT:
        halt("Graphvertrag fehlt oder wurde geändert; explizites graph-upgrade erforderlich")
    if not ctx.journal.key:
        halt("authentifiziertes Journal erforderlich")
    events = ctx.journal.verified_events()
    view = replay(events, graph=graph, authority=Authority.AUTHENTICATED).get(ctx.record_id)
    if view is None or view.findings or not view.enabled:
        halt("Record fehlt, ist deaktiviert oder trägt Befunde")
    if (
        gate_artifact in view.have
        and gate_artifact == "transcript.pseudonymised.confirmed"
        and manual_context.enabled(ctx.ws.profile)
        and ctx.ws.profile.pii_detection == "manual"
    ):
        from .finalisation import refresh
        from ..protected_store import ProtectionError

        try:
            refresh(ctx)
        except (ProtectionError, RuntimeError, ValueError, OSError) as exc:
            halt(f"P4c-Registerprüfung gesperrt ({type(exc).__name__})")
        events = ctx.journal.verified_events()
        view = replay(events, graph=graph, authority=Authority.AUTHENTICATED).get(ctx.record_id)
        if view is None or view.findings or not view.enabled:
            halt("Record nach Registerprüfung gesperrt")
    decision = view.effective_decision_by_artifact.get(gate_artifact)
    gate_fact = view.facts.get(gate_artifact)
    marker_sha = gate_fact.sha256 if gate_fact else None
    if gate_artifact not in view.have or decision is None or not decision.covers(marker_sha):
        halt("keine nutzbare akzeptierende Textbestätigung")
    if decision.record_id != ctx.record_id or decision.artifact != gate_artifact:
        halt("Entscheidung gehört zu einem anderen Record oder Gate")
    if decision.profile_id != ctx.ws.profile.id or decision.graph_sha256 != graph_sha:
        halt("Bestätigung ohne passenden Profil-/Graphkontext; erneut bestätigen")
    if decision.input_refs_version == 4:
        from .finalisation import published, verify_package, basis
        from ..registry_store import RegistryStore, GATE, FINAL
        from ..protected_store import canonical

        if gate_artifact != GATE or text_artifact != FINAL:
            halt("P4c-Gate-/Textrolle passt nicht")
        p = published(ctx, events, "review")
        expected = basis(view, "review")
        if (
            p is None
            or p["basis"] != expected
            or p["marker"]["volltext_gelesen"] is not True
            or dict(decision.input_refs) != {k: v[0] for k, v in expected.items()}
        ):
            halt("P4c-Mehrfachbindung nicht aktuell")
        with ctx.ws.store().open_verified(marker_sha) as handle:
            if handle.read() != canonical(p["marker"]):
                halt("P4c-Marker widerspricht dem abgeschlossenen Volltextakt")
        raw, report = verify_package(
            ctx,
            RegistryStore(ctx.ws, ctx.journal.key),
            events,
            published(ctx, events, "finalise"),
            view,
        )
        if p["marker"]["counts"] != report["counts"]:
            halt("P4c-Fallbilanz stimmt nicht")
        sha = expected[FINAL][0]
        revision = verify_revision(raw, sha)
        return ConfirmedText(
            gate_artifact,
            text_artifact,
            marker_sha,
            sha,
            revision,
            raw,
            decision,
            view,
            tuple(events),
        )
    # Bei kanonischen Bestätigungsentscheidungen ist auch die inhaltliche ID Evidenz.
    event = next(
        e
        for e in reversed(events)
        if e.kind == "decision.recorded"
        and e.record_id == ctx.record_id
        and e.payload.get("artifact") == gate_artifact
    )
    if event.payload.get("domain") == "transcript_confirmation_decision":
        payload = dict(event.payload)
        decision_id = payload.pop("decision_id", None)
        if hashlib.sha256(canonical_json_bytes(payload)).hexdigest() != decision_id:
            halt("kanonischer Entscheidungsdigest passt nicht")
    role = "transcript" if decision.input_refs_version == 1 else "text"
    if set(decision.input_refs) != {role}:
        halt("Entscheidung enthält nicht die deklarierte Textreferenz")
    reference_sha = decision.input_refs[role]
    text_fact = view.facts.get(text_artifact)
    text_sha = text_fact.sha256 if text_fact else None
    if text_artifact not in view.have or text_sha != reference_sha:
        halt("aktuelle Textrolle und bestätigte Fassung weichen ab")

    store = ctx.ws.store()
    try:
        with store.open_verified(marker_sha) as handle:
            marker_bytes = handle.read()
        marker_object = json.loads(marker_bytes)
        if marker_object.get("domain") == "transcript_confirmation":
            marker = ConfirmationMarker(
                ctx.record_id, marker_object["projection_version"], reference_sha
            )
            if (
                decision.input_refs_version != 1
                or marker.object()["artifact_key"]["kind"] != gate_artifact
            ):
                halt("V1-Marker passt nicht zur deklarierten Gaterolle")
        elif marker_object.get("domain") == "text_confirmation":
            marker = TextConfirmationMarker(
                ctx.record_id,
                gate_artifact,
                text_artifact,
                reference_sha,
                marker_object["projection_version"],
                ctx.ws.profile.id,
                graph_sha,
            )
            if decision.input_refs_version != 2:
                halt("V2-Marker verlangt die Textreferenzrolle v2")
        else:
            halt("unbekannte Markerdomäne")
        if marker.bytes != marker_bytes or marker.sha256 != marker_sha:
            halt("Marker ist nicht kanonisch oder bindet andere Eingaben")
        # Ausschließlich die bestätigte Adresse lesen; niemals die aktuelle als Ersatz.
        with store.open_verified(reference_sha) as handle:
            revision_bytes = handle.read()
        revision = verify_revision(revision_bytes, reference_sha)
        if revision.projection_version != marker.projection_version:
            halt("Marker und Revision tragen verschiedene Projektionen")
        if revision.profile_id != graph.contract_for(text_artifact).text_profile:
            halt("Normalisierungsprofil der Revision passt nicht zur Textrolle")
    except ConfirmedTextError:
        raise
    except (OSError, ValueError, RuntimeError, KeyError, TypeError, AttributeError) as exc:
        # Fremde Parser-/Storefehler können Inhalte tragen; nur ihre Klasse nennen.
        halt(f"Bestätigungsbytes nicht verifizierbar ({type(exc).__name__})")
    return ConfirmedText(
        gate_artifact,
        text_artifact,
        marker_sha,
        reference_sha,
        revision,
        revision_bytes,
        decision,
        view,
        tuple(events),
    )
