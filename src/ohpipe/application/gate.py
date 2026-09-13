"""Die gemeinsame Bestaetigungsmechanik — EIN Schreiber fuer die menschlichen Gates.

Vier B3b-Gates schreiben dieselbe Form: ``l1.review`` und die drei
Katalog-Bestaetigungen ``metadata.confirm``, ``abstract.confirm`` und
``release.approve``. Jeder Akt bindet eine Entscheidung an den sha256 GENAU der
Bytes, die er freigibt, legt das Artefakt ab, traegt Bindungsevidenz
(``anchor.checked``) und einen deterministischen Beleg (``receipt.recorded``).
Vier Kopien dieser Form waeren vier Stellen, an denen eine still abweichen
koennte — deshalb steht sie hier einmal, und die vier Aufrufer reichen nur das
durch, was sie unterscheidet (:class:`ConfirmationSpec`).

``write_confirmation`` (``transcript.confirm``) teilt die FORM, aber nicht die
Bytes: es schreibt eine aktivierungsgebundene ``ConfirmationDecision`` ueber den
vollen RetryIntent-Weg (``execute_intent``, Marker, ``activation_id``), ohne
deterministischen Beleg. Diese Bytes sind von den ACT-Normkontrakten
eingefroren (``test_b3b_norm_coverage.py``: P0-INTENT-FINAL-07 liest die
Aufrufstelle, A0-INTENT-08 liest ``intent_sha256`` in ``confirmation.py``). Es
bleibt deshalb unangetastet und ist die eine benannte Ausnahme zu dieser
Mechanik — nicht ihr fuenfter Aufrufer.

Jeder Aufruf schreibt GENAU EIN Artefakt (ADR 0005): eine ``artifact.produced``,
eine ``decision.recorded``, eine ``anchor.checked``, eine ``receipt.recorded``,
alle auf denselben Artefaktnamen und alle idempotent (``append_once``).

Datenschutz: Meldungen dieses Moduls nennen Artefaktnamen, Referenzen und
Hashpraefixe, nie ein Zitat.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..domain.anchor import ReanchorOutcome
from ..domain.decision import Decision, Verdict
from ..domain.events import ANCHOR_CHECKED, ARTIFACT_PRODUCED, DECISION_RECORDED, RECEIPT_RECORDED
from ..domain.hashing import sha256_bytes
from ..domain.instance import InstanceRegistry
from ..domain.step import build_graph
from ..journal import Journal
from ..policies.authority import Authority
from ..policies.exit_contract import Report, Status
from ..project import Workspace
from ..workspace_lock import workspace_write_lock
from .operation_recovery import b3b_report
from .replay import replay

__all__ = [
    "ConfirmationSpec",
    "GateError",
    "GateBlocked",
    "current_inputs",
    "check_planned_inputs",
    "canonical_bytes",
    "input_sha",
    "latest_produced",
    "resolve_active_human",
    "write_derivation",
    "write_gate",
]


class GateError(RuntimeError):
    """Der Akt liess sich nicht ausfuehren. Nichts geschrieben."""


class GateBlocked(GateError):
    """Befund im aktuellen Replay: STOP statt fehlender Voraussetzung."""


def current_inputs(ws, events, record_id, names, *, authority):
    """Eingaben aus dem authentifizierten Replay des betroffenen Records."""
    views = replay(events, graph=build_graph(ws.profile), authority=authority)
    view = views.get(record_id)
    if view is not None and view.findings:
        raise GateBlocked("Aktueller Replay enthaelt Befunde; kein Gate und kein Ausgang")
    if authority is not Authority.AUTHENTICATED:
        raise GateError("Authentifiziertes Journal erforderlich")
    if view is None or not view.enabled:
        raise GateError("Record fehlt oder ist deaktiviert; kein Gate und kein Ausgang")
    actual = {name: input_sha(view, name, "Gate/Ausgang") for name in names}
    from .storage_integrity import check_referenced

    missing = check_referenced(ws, view)
    if missing:
        raise GateBlocked(
            "Belegte Eingabe im Store fehlt oder ist beschädigt; kein Gate und kein Ausgang"
        )
    return actual


def check_planned_inputs(ws, transaction, record_id, expected):
    authority = Authority.AUTHENTICATED if transaction.key else Authority.UNAUTHENTICATED
    actual = current_inputs(ws, list(transaction), record_id, expected, authority=authority)
    if actual != expected:
        raise GateError("Eingabe seit der Vorschau geaendert; erneut anzeigen und bestaetigen")


def canonical_bytes(obj: dict[str, Any]) -> bytes:
    """Die Bytefassung, in der die B3b-Ableitungen und Bestaetigungen abgelegt werden.

    Sortierte Schluessel, kein ueberfluessiges Leerzeichen, ein Abschlussbyte.
    Ausdruecklich NICHT die an ADR 0028B delegierte kanonische Serialisierung
    der Transkriptrevision: das ist eine andere, offene Frage, und diese
    Funktion beantwortet sie nicht.
    """
    return (
        json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def input_sha(view: Any, name: str, step: str) -> str:
    """Der Store-Hash einer NUTZBAREN Eingabe — oder ein Fehler, nie ein Rateschritt."""
    if name not in view.have:
        fact = view.facts.get(name)
        reason = fact.state().explanation if fact else "Quelle fehlt"
        raise GateError(f"{step}: {name} ist nicht nutzbar; {reason}; keine Ableitung")
    fact = view.facts.get(name)
    sha = fact.sha256 if fact is not None else None
    if not sha:
        raise GateError(f"{step}: fehlende Store-Adresse fuer {name}")
    return sha


def current_event(journal, record_id, kind, artifact):
    return next(
        (
            e
            for e in reversed(list(journal))
            if e.record_id == record_id and e.kind == kind and e.payload.get("artifact") == artifact
        ),
        None,
    )


def current_duplicate(journal, record_id, kind, artifact, payload):
    last = current_event(journal, record_id, kind, artifact)
    return lambda e: (
        last is not None
        and e.seq == last.seq
        and all(e.payload.get(k) == value for k, value in payload.items())
    )


def write_derivation(
    ws: Workspace,
    journal: Journal,
    *,
    record_id: str,
    artifact: str,
    step: str,
    code_version: str,
    data: bytes,
    inputs: dict[str, str],
    bind: bool,
) -> tuple[str, tuple[str, ...]]:
    """Legt Ableitungsbytes ab und schreibt ``artifact.produced``, bei ``bind``
    eine ``anchor.checked`` (binding_required) und einen deterministischen
    Beleg. Genau ein Artefakt je Aufruf (ADR 0005), alles idempotent.

    Das Gegenstueck zu :func:`write_gate`: dieselbe Disziplin, aber ohne
    ``decision.recorded`` — eine Ableitung entscheidet nichts. Der Katalogpfad
    und der Egress teilen sie; eine zweite Kopie waere die Stelle, an der eine
    von beiden die ``anchor.checked`` vergisst.
    """
    store = ws.store()
    sha = sha256_bytes(data)
    address = store.put(io.BytesIO(data))
    if address != sha:
        raise GateError(f"{step}: Store-Adresse und Artefaktdigest weichen ab")
    rid = record_id
    changed = [str(ws.objects / address)]
    written = 0
    if journal.append_once(
        ARTIFACT_PRODUCED,
        {"artifact": artifact, "sha256": sha},
        record_id=rid,
        duplikat=current_duplicate(journal, rid, ARTIFACT_PRODUCED, artifact, {"sha256": sha}),
    ):
        written += 1
    if bind and journal.append_once(
        ANCHOR_CHECKED,
        {"artifact": artifact, "outcome": ReanchorOutcome.EXACT.value},
        record_id=rid,
        duplikat=lambda e: (
            e.payload.get("artifact") == artifact
            and e.payload.get("outcome") == ReanchorOutcome.EXACT.value
        ),
    ):
        written += 1
    if journal.append_once(
        RECEIPT_RECORDED,
        {
            "artifact": artifact,
            "output_sha256": sha,
            "inputs": dict(inputs),
            "code_version": code_version,
            "step": step,
        },
        record_id=rid,
        duplikat=receipt_duplicate(ws, journal, rid, artifact, sha, inputs),
    ):
        written += 1
    if written:
        changed.append(str(journal.path))
    return sha, tuple(changed)


@dataclass(frozen=True)
class ConfirmationSpec:
    """Was einen Bestaetigungsakt von den anderen unterscheidet — sonst nichts.

    Der Artefaktname, die Entscheidungsreferenz (Token nach ``REFERENCE_RE``),
    die Belegfassung (``code_version``, ``step``) und die vier Meldungsbausteine.
    Die MECHANIK darueber ist fuer alle Aufrufer gleich und steht in
    :func:`write_gate`.
    """

    artifact: str
    reference: str
    code_version: str
    step: str
    reason_written: str
    message_written: str
    reason_null: str
    message_null: str


def latest_produced(events: list[Any], name: str) -> str | None:
    """Der zuletzt fuer ``name`` belegte Artefakthash, oder ``None``."""
    sha = None
    for event in events:
        if event.kind == ARTIFACT_PRODUCED and event.payload.get("artifact") == name:
            sha = event.payload.get("sha256")
    return sha


def resolve_active_human(registry: InstanceRegistry, actor_arg: str | None) -> str:
    """Die aktive menschliche Instanz — benannt oder die einzige aufgeloeste.

    Ein Gate ist ein menschlicher Akt (``domain/step.py``, ``Kind.HUMAN``). Ohne
    aufgeloesten Menschen gibt es niemanden, der verantwortet — das ist ein
    Fehler, kein Default.
    """
    if actor_arg is not None:
        instance = registry.get(actor_arg, active=True)
        if instance.source != "mensch":
            raise GateError("Ein Gate verlangt eine aktive menschliche Instanz")
        return instance.coder_id
    humans = registry.active_humans()
    if len(humans) != 1:
        raise GateError("Ein Gate verlangt genau eine aufgeloeste menschliche Instanz")
    return humans[0].coder_id


def write_gate(
    ws: Workspace,
    journal: Journal,
    *,
    spec: ConfirmationSpec,
    record_id: str,
    actor: str,
    subject_bytes: bytes,
    subject_sha256: str,
    receipt_inputs: dict[str, str],
    details_written: dict[str, Any],
    validate: Callable[[Any], None] | None = None,
) -> Report:
    """Legt die freizugebenden Bytes ab und schreibt die vier Belege dazu.

    Reihenfolge und Idempotenz sind Teil der Zusicherung: ``append_once`` mit
    einem ``duplikat``-Praedikat je Ereignis macht den Akt zum Nulldurchgang,
    wenn er schon wirksam ist — kein zweiter Beleg, keine zweite Entscheidung.

    Die Entscheidung wird als :class:`Decision` gebaut (Referenzformat, Akteur
    und Zeitpunkt werden dabei geprueft) und dann auf die erlaubten
    Huellenfelder reduziert: ``Decision.to_json()`` traegt zusaetzlich
    ``id``/``note``/``reason_code``, die ``check_payload`` ablehnt.
    """
    with workspace_write_lock(ws.root), journal.transaction() as transaction:
        check_planned_inputs(ws, transaction, record_id, receipt_inputs)
        resolve_active_human(InstanceRegistry.from_events(list(transaction)), actor)
        view = replay(
            list(transaction), graph=build_graph(ws.profile), authority=Authority.AUTHENTICATED
        )[record_id]
        if spec.artifact in view.facts and view.facts[spec.artifact].withdrawal:
            raise GateError(
                "WITHDRAW bleibt wirksam; zuerst getrennten autorisierten UNDO ausführen"
            )
        if validate is not None:
            validate(transaction)
        return _write_gate_locked(
            ws,
            transaction,
            spec=spec,
            record_id=record_id,
            actor=actor,
            subject_bytes=subject_bytes,
            subject_sha256=subject_sha256,
            receipt_inputs=receipt_inputs,
            details_written=details_written,
        )


def _write_gate_locked(
    ws,
    journal,
    *,
    spec,
    record_id,
    actor,
    subject_bytes,
    subject_sha256,
    receipt_inputs,
    details_written,
):
    store = ws.store()
    address = store.put(io.BytesIO(subject_bytes))
    if address != subject_sha256:
        raise GateError(f"{spec.step}: Store-Adresse und Artefaktdigest weichen ab")
    artifact = spec.artifact
    a = subject_sha256
    written = 0
    if journal.append_once(
        ARTIFACT_PRODUCED,
        {"artifact": artifact, "sha256": a},
        record_id=record_id,
        duplikat=current_duplicate(journal, record_id, ARTIFACT_PRODUCED, artifact, {"sha256": a}),
    ):
        written += 1
    decision = Decision(
        record_id=record_id,
        artifact=artifact,
        subject_sha256=a,
        verdict=Verdict.ACCEPT,
        reference=spec.reference,
        actor=actor,
        input_refs=receipt_inputs,
        input_refs_version=3,
        profile_id=ws.profile.id,
        graph_sha256=ws.inspect_graph_binding()[2],
    )
    decision_payload = {
        "artifact": artifact,
        "subject_sha256": a,
        "verdict": decision.verdict.value,
        "reference": decision.reference,
        "actor": decision.actor,
        "at": decision.at,
        "input_refs": dict(decision.input_refs),
        "input_refs_version": 3,
        "profile_id": decision.profile_id,
        "graph_sha256": decision.graph_sha256,
    }
    if journal.append_once(
        DECISION_RECORDED,
        decision_payload,
        record_id=record_id,
        duplikat=decision_duplicate(ws, journal, record_id, artifact, decision_payload),
    ):
        written += 1
    if journal.append_once(
        ANCHOR_CHECKED,
        {"artifact": artifact, "outcome": ReanchorOutcome.EXACT.value},
        record_id=record_id,
        duplikat=lambda e: (
            e.payload.get("artifact") == artifact
            and e.payload.get("outcome") == ReanchorOutcome.EXACT.value
        ),
    ):
        written += 1
    if journal.append_once(
        RECEIPT_RECORDED,
        {
            "artifact": artifact,
            "output_sha256": a,
            "inputs": dict(receipt_inputs),
            "code_version": spec.code_version,
            "step": spec.step,
        },
        record_id=record_id,
        duplikat=receipt_duplicate(ws, journal, record_id, artifact, a, receipt_inputs),
    ):
        written += 1
    if written == 0:
        return b3b_report(
            Status.READY, spec.reason_null, spec.message_null, operation_result="NULLDURCHGANG"
        )
    return b3b_report(
        Status.READY,
        spec.reason_written,
        spec.message_written,
        changed=[str(journal.path), str(ws.objects / a)],
        operation_result="WRITTEN",
        details=details_written,
    )


def receipt_duplicate(ws, journal, rid, artifact, sha, inputs):
    view = replay(
        list(journal), graph=build_graph(ws.profile), authority=Authority.AUTHENTICATED
    ).get(rid)
    facts = view.facts.get(artifact) if view else None
    if facts is None or facts.freshness is not None:
        return lambda e: False
    return current_duplicate(
        journal, rid, RECEIPT_RECORDED, artifact, {"output_sha256": sha, "inputs": inputs}
    )


def decision_duplicate(ws, journal, rid, artifact, payload):
    view = replay(
        list(journal), graph=build_graph(ws.profile), authority=Authority.AUTHENTICATED
    ).get(rid)
    facts = view.facts.get(artifact) if view else None
    if facts is None or facts.freshness is not None:
        return lambda e: False
    return current_duplicate(
        journal, rid, DECISION_RECORDED, artifact, {k: v for k, v in payload.items() if k != "at"}
    )
