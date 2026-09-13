"""Plaene und Writer fuer das gemeinsame Instanzregister."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ..domain.events import INSTANCE_REGISTERED, INSTANCE_RETIRED
from ..domain.instance import InstanceRegistry
from ..domain.operation import EVENT_CATALOG_VERSION, RETRY_INTENT_VERSION, RetryIntent
from ..journal import Journal
from ..policies.exit_contract import Report, Status
from ..project import Workspace
from .operation_recovery import Effect, b3b_report, execute_intent

__all__ = ["InstancePlan", "plan_register", "plan_retire", "write_instance_plan"]


@dataclass(frozen=True)
class InstancePlan:
    action: str
    payload: dict[str, str]
    registry_before: InstanceRegistry


def plan_register(
    events: list[Any],
    coder_id: str,
    *,
    source: str,
    label: str,
    reference: str,
    model: str | None = None,
    parametersatz: str | None = None,
) -> InstancePlan:
    registry = InstanceRegistry.from_events(events)
    payload = registry.registration_payload(
        coder_id,
        source=source,
        label=label,
        reference=reference,
        model=model,
        parametersatz=parametersatz,
    )
    return InstancePlan("register", payload, registry)


def plan_retire(events: list[Any], coder_id: str, *, reference: str) -> InstancePlan:
    registry = InstanceRegistry.from_events(events)
    registry.get(coder_id, active=True)
    return InstancePlan(
        "retire", registry.retirement_payload(coder_id, reference=reference), registry
    )


def _intent(ws: Workspace, plan: InstancePlan) -> RetryIntent:
    command = f"instance_{plan.action}"
    payload_sha = hashlib.sha256(repr(sorted(plan.payload.items())).encode("utf-8")).hexdigest()
    effect_kind = INSTANCE_REGISTERED if plan.action == "register" else INSTANCE_RETIRED
    input_name = (
        "registration_payload_sha256" if plan.action == "register" else "retirement_payload_sha256"
    )
    return RetryIntent(
        workspace_id=ws.running_graph_sha256(),
        command=command,
        target_key={
            "workspace_id": ws.running_graph_sha256(),
            "coder_id": plan.payload["coder_id"],
        },
        inputs={input_name: payload_sha},
        store_bindings={},
        causal_prestate={"coder_state_sha256": None, "coder_state_event_digest": None},
        rule_versions={
            "event_catalog": EVENT_CATALOG_VERSION,
            "retry_intent": RETRY_INTENT_VERSION,
        },
        idempotency_keys={f"instance_{plan.action}ed_key": plan.payload["coder_id"]},
        routing_keys={"workspace_register_key": ws.running_graph_sha256()},
        desired_effect={
            "event_sequence": ["operation.intent.recorded", effect_kind],
            "store_outputs": {"retry_intent_store": "SELF_OPERATION_INTENT_SHA256"},
            "system_bindings": {"operation_intent_sha256": "SELF_OPERATION_INTENT_SHA256"},
        },
    )


def write_instance_plan(ws: Workspace, journal: Journal, plan: InstancePlan) -> Report:
    current = InstanceRegistry.from_events(list(journal))
    if plan.action == "register":
        changed = current.register(plan.payload)
        kind = INSTANCE_REGISTERED
    else:
        changed = current.retire(plan.payload)
        kind = INSTANCE_RETIRED
    if not changed:
        return b3b_report(
            Status.READY,
            "READY_B3B_NULLDURCHGANG",
            "Der Registerzustand ist bereits bytegleich wirksam.",
            operation_result="NULLDURCHGANG",
        )
    intent, events = execute_intent(
        ws,
        journal,
        lambda: _intent(ws, plan),
        lambda _intent_value: [Effect(kind, plan.payload, None)],
    )
    return b3b_report(
        Status.READY,
        "READY_B3B_WRITTEN",
        "Der Registerakt wurde nach Vollreplay wirksam.",
        changed=[str(ws.journal_path), str(ws.objects / intent.sha256)],
        operation_result="WRITTEN",
        details={"events": [event.kind for event in events], "intent_sha256": intent.sha256},
    )
