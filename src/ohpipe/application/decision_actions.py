"""Getrennte menschliche Widerrufs-/UNDO-Akte unter der Journalsperre."""

from ..domain.decision import Decision, Verdict
from ..domain.instance import InstanceRegistry
from ..domain.step import build_graph
from ..policies.authority import Authority
from ..policies.ownership import THIS_RUNTIME, CutoverLedger
from ..workspace_lock import workspace_write_lock
from .gate import GateError, resolve_active_human
from .replay import replay


def write_action(ws, journal, record_id, artifact, verdict, actor, reference, *, undo_of=None):
    if verdict not in (Verdict.WITHDRAW, Verdict.UNDO):
        raise GateError("Hier sind ausschließlich WITHDRAW und UNDO zulässig")
    with workspace_write_lock(ws.root), journal.transaction() as transaction:
        if not transaction.key:
            raise GateError("Authentifiziertes Journal erforderlich")
        events = list(transaction)
        CutoverLedger.from_journal(
            events,
            authority=Authority.AUTHENTICATED,
            default_runtime=ws.profile.legacy_runtime or THIS_RUNTIME,
        ).require_write(record_id)
        resolve_active_human(InstanceRegistry.from_events(events), actor)
        view = replay(events, graph=build_graph(ws.profile), authority=Authority.AUTHENTICATED).get(
            record_id
        )
        if view is None or view.findings or artifact not in view.facts:
            raise GateError("Kein belegtes Entscheidungsartefakt")
        facts = view.facts[artifact]
        if verdict is Verdict.UNDO and (not facts.withdrawal or undo_of != facts.withdrawal):
            raise GateError("UNDO verlangt den genau benannten wirksamen Widerruf")
        decision = Decision(record_id, artifact, facts.sha256, verdict, reference, actor)
        payload = {
            k: v
            for k, v in decision.to_json().items()
            if k in {"artifact", "subject_sha256", "verdict", "reference", "actor", "at"}
        }
        if verdict is Verdict.UNDO:
            payload["undo_of"] = undo_of
        return transaction.append_once(
            "decision.recorded", payload, record_id=record_id, duplikat=lambda e: False
        )
