"""``l1.review`` -> ``l1.adjudicated``: die menschliche Entscheidung, an Bytes gebunden.

Der Reviewschritt ist ein menschliches Gate. Er baut nichts Neues: er zeigt die
offenen Faelle (die L1-Vorschlaege) und schreibt EINE Entscheidung, die an den
sha256 der adjudizierten Bytes gebunden ist. Das Schreiben selbst besorgt die
gemeinsame Bestaetigungsmechanik :func:`ohpipe.application.gate.write_gate` —
dieselbe, die ``metadata.confirm``, ``abstract.confirm`` und ``release.approve``
benutzen. Was ``l1.review`` von jenen unterscheidet, steht in :data:`_SPEC` und
in den hier gebauten Bytes; die Mechanik teilt es.

Die Entwertung ist NICHT hier gebaut, sie ist im Replay: der deterministische
Beleg (``receipt.recorded``, ``output_sha256`` = Artefakthash) laesst das
Artefakt sichtbar ``STALE`` werden, sobald sich die gebundenen Bytes aendern
(``replay.py`` Zeile 160, ``receipt_for != sha256``). Eine von Hand geschriebene
Entscheidung, die auf ANDERE Bytes zeigt als das Artefakt traegt, faellt auf der
Entscheidungsachse (``decided_sha != sha256`` -> UNDECIDED). Beides ist rot, kein
Teilkredit.

Schmale Fassung (Streichungsvermerk V2, Abschnitt 4): der Review nimmt die
Vorschlaege als Ganzes an. Editieren, Stapel, Filter und der Zustand DEFERRED
sind verschoben.

Datenschutz: Meldungen dieses Moduls nennen Vorschlags-IDs, Segmentindizes und
Codes, nie ein Zitat.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..domain.decision import Verdict
from ..domain.hashing import sha256_bytes
from ..domain.instance import InstanceRegistry
from ..journal import Journal
from ..policies.authority import Authority
from ..policies.exit_contract import Report
from ..project import Workspace
from .gate import ConfirmationSpec, GateError, current_inputs, resolve_active_human, write_gate

__all__ = [
    "ARTIFACT",
    "CODE_VERSION",
    "REFERENCE",
    "SCHEMA",
    "STEP",
    "ReviewError",
    "ReviewPlan",
    "plan_l1_review",
    "write_l1_review",
]

STEP = "l1.review"
ARTIFACT = "l1.adjudicated"
SUGGESTIONS_ARTIFACT = "l1.suggestions"
COVERAGE_ARTIFACT = "l1.coverage"
CODE_VERSION = "l1-review/1"
SCHEMA = "ohpipe.l1.adjudicated.v1"
#: Referenz der Reviewentscheidung. Token nach ``decision.REFERENCE_RE``.
REFERENCE = "l1.review"

#: Was ``l1.review`` von den anderen Gates unterscheidet — die Mechanik in
#: :func:`ohpipe.application.gate.write_gate` teilt der Rest.
_SPEC = ConfirmationSpec(
    artifact=ARTIFACT,
    reference=REFERENCE,
    code_version=CODE_VERSION,
    step=STEP,
    reason_written="READY_L1_REVIEW_WRITTEN",
    message_written="L1-Adjudikation, Entscheidung und Bindungsevidenz sind geschrieben.",
    reason_null="READY_L1_REVIEW_NULLDURCHGANG",
    message_null="Exakt diese Adjudikation ist bereits wirksam.",
)


class ReviewError(GateError):
    """Der Review liess sich nicht planen. Nichts geschrieben."""


@dataclass(frozen=True)
class ReviewPlan:
    record_id: str
    actor: str
    suggestions_sha256: str
    coverage_sha256: str
    adjudicated_sha256: str
    adjudicated_bytes: bytes
    preview: dict[str, Any]


def _adjudicated_bytes(
    record_id: str,
    suggestions_sha: str,
    coverage_sha: str,
    actor: str,
    suggestions: list[dict[str, Any]],
) -> bytes:
    obj = {
        "schema": SCHEMA,
        "record_id": record_id,
        "reviewed_suggestions": suggestions_sha,
        "coverage": coverage_sha,
        "actor": actor,
        "decisions": [
            {
                "id": s["id"],
                "segment_index": s["segment_index"],
                "code": s["code"],
                "verdict": Verdict.ACCEPT.value,
            }
            for s in suggestions
        ],
    }
    return (
        json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def plan_l1_review(
    ws: Workspace,
    events: list[Any],
    *,
    record_id: str,
    actor_arg: str | None,
    authority: Authority = Authority.UNAUTHENTICATED,
) -> ReviewPlan:
    inputs = current_inputs(
        ws, events, record_id, (SUGGESTIONS_ARTIFACT, COVERAGE_ARTIFACT), authority=authority
    )
    registry = InstanceRegistry.from_events(events)
    try:
        actor = resolve_active_human(registry, actor_arg)
    except GateError as exc:
        raise ReviewError(str(exc)) from exc
    suggestions_sha = inputs[SUGGESTIONS_ARTIFACT]
    coverage_sha = inputs[COVERAGE_ARTIFACT]
    store = ws.store()
    with store.open_verified(suggestions_sha) as handle:
        try:
            obj = json.loads(handle.read().decode("utf-8"))
        except ValueError as exc:
            raise ReviewError(f"{SUGGESTIONS_ARTIFACT} ist kein gueltiges JSON") from exc
    suggestions = obj.get("suggestions", [])
    if not suggestions:
        raise ReviewError(f"{SUGGESTIONS_ARTIFACT} traegt keinen Vorschlag")
    data = _adjudicated_bytes(record_id, suggestions_sha, coverage_sha, actor, suggestions)
    adjudicated_sha = sha256_bytes(data)
    preview = {
        "action": "l1 review",
        "record": record_id,
        "actor": actor,
        "reviewed_suggestions": suggestions_sha,
        "coverage": coverage_sha,
        "planned_registry_effect": ARTIFACT,
        "open_cases": [
            {"id": s["id"], "segment_index": s["segment_index"], "code": s["code"]}
            for s in suggestions
        ],
    }
    return ReviewPlan(
        record_id, actor, suggestions_sha, coverage_sha, adjudicated_sha, data, preview
    )


def write_l1_review(ws: Workspace, journal: Journal, plan: ReviewPlan) -> Report:
    """Schreibt ueber die gemeinsame Mechanik — dieselbe wie die drei Katalog-Gates."""
    return write_gate(
        ws,
        journal,
        spec=_SPEC,
        record_id=plan.record_id,
        actor=plan.actor,
        subject_bytes=plan.adjudicated_bytes,
        subject_sha256=plan.adjudicated_sha256,
        receipt_inputs={
            SUGGESTIONS_ARTIFACT: plan.suggestions_sha256,
            COVERAGE_ARTIFACT: plan.coverage_sha256,
        },
        details_written={
            "artifact_sha256": plan.adjudicated_sha256,
            "decisions": len(plan.preview["open_cases"]),
        },
    )
