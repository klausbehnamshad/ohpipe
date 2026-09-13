"""Der Katalogpfad: drei duenne Ableitungen und ihre drei Bestaetigungen.

Nach ``l1.adjudicated`` teilt sich die Kette in einen Katalog- und einen
Analysepfad (ADR 0020). Dieser Modul baut den Katalogpfad:

* **metadata.derive** rechnet die kontrollierten deskriptiven Felder gegen das
  Metadata Model (``policies/metadata.py``: ``load_tap``, ``check_record``,
  ``REQUIRED_FIELDS``) und legt einen Entwurf ab, der die noch offenen
  Pflichtfelder benennt. Es fuellt keine Werte, die es nicht deterministisch
  kennt — die setzt der Mensch am Gate.
* **abstract.derive** legt einen deskriptiven Katalogabstract nach einer
  DEKLARIERTEN Schablonenversion (:data:`ABSTRACT_TEMPLATE_VERSION`) an; die
  Abschnitte sind die Block-B-Felder, die das Modell nennt — nicht geraten.
* **release.preview** setzt Metadaten, Abstract und Adjudikation zusammen. Die
  Analyse ist ausdruecklich NICHT enthalten (eigener Pfad, ADR 0020).

Die drei Bestaetigungen ``metadata.confirm``, ``abstract.confirm`` und
``release.approve`` schreiben ueber die gemeinsame Mechanik
(:func:`ohpipe.application.gate.write_gate`) — dieselbe, die ``l1.review``
benutzt. Sie unterscheiden sich nur in ihrer :class:`ConfirmationSpec` und im
bestaetigten Entwurf.

**ADR 0020, woertlich befolgt:** Kein Klassifikator, keine Heuristik, kein Gate
auf „deskriptiv gegen analytisch". Die Konfiguration nennt Artefaktnamen und
Pflichtfelder, sonst nichts. Was auffaellt, ohne dass eine Maschine darueber
entscheiden duerfte, gehoert in den ``advisory``-Kanal des Replays — getrennt
von den ``findings`` — und wird hier nicht erzeugt.

Datenschutz: Meldungen dieses Moduls nennen Artefaktnamen, Feldnamen und
Hashpraefixe, nie ein Zitat und keinen Feldwert.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..domain.hashing import sha256_bytes
from ..domain.instance import InstanceRegistry
from ..journal import Journal
from ..policies.authority import Authority
from ..policies.exit_contract import Report
from ..policies.metadata import (
    REQUIRED_FIELDS,
    RecordMetadataError,
    check_record,
    load_record_metadata,
    load_tap,
)
from ..project import Workspace
from .gate import (
    ConfirmationSpec,
    GateError,
    canonical_bytes,
    input_sha,
    current_inputs,
    resolve_active_human,
    write_derivation,
    write_gate,
)
from .replay import RecordView

__all__ = [
    "ABSTRACT_TEMPLATE_VERSION",
    "CONFIRM_GATES",
    "ConfirmGatePlan",
    "DeriveError",
    "DerivationResult",
    "plan_confirm",
    "run_abstract_derive",
    "run_metadata_derive",
    "run_release_preview",
    "write_confirm",
]

#: Die deklarierte Schablonenversion des Katalogabstracts. Sie steht in den
#: Entwurfsbytes: aendert sie sich, aendert sich der Artefakthash, und der
#: deterministische Beleg zeigt sichtbar auf die alte Fassung (STALE).
ABSTRACT_TEMPLATE_VERSION = "catalog-abstract/1"


class DeriveError(GateError):
    """Eine Ableitung liess sich nicht bilden. Nichts geschrieben."""


@dataclass(frozen=True)
class DerivationResult:
    artifact_sha256: str
    changed: tuple[str, ...]
    details: dict[str, Any]


# ------------------------------------------------- die drei Ableitungen (RUN)


#: Wo die Eingabe eines Records liegt. Unter ``_governance``, weil sie zur
#: Datenwurzel gehoert und nicht in den Quelltext (ADR 0006, ADR 0012); in
#: einem eigenen Unterverzeichnis, weil ``_governance`` sonst vier wurzelweite
#: Dinge und eine mit dem Bestand wachsende Menge Recorddateien mischte.
METADATA_INPUT_DIR = "metadata"


def metadata_input_path(ws: Workspace, record_id: str) -> Path:
    """Der Pfad der Eingabedatei. Eine Funktion, damit die Meldung ihn nennen kann."""
    return ws.governance / METADATA_INPUT_DIR / f"{record_id}.toml"


def run_metadata_derive(ctx: Any, view: RecordView) -> DerivationResult:
    """``metadata.derive``: kontrollierte deskriptive Felder gegen das Metadata Model.

    Zwei Quellen, klar getrennt. Der ``record_id`` kommt aus dem Aufruf. Alles
    andere kommt aus einer Datei, die der Operator einmal je Interview
    schreibt: ``_governance/metadata/<RECORD_ID>.toml``. Das Modul FUELLT
    weiterhin nichts, was es nicht hat — es liest, was jemand eingetragen hat,
    und benennt, was dann noch offen ist (``check_record``, kein
    Klassifikator, ADR 0020).

    **Die Rohbytes der Eingabe gehen in den Store**, und ihr Digest steht als
    ``metadata.input`` in den Belegeingaben. Damit laesst sich ein
    Katalogeintrag auf die Bytes zurueckfuehren, die ein Mensch getippt hat,
    und diese Bytes liegen unter ihrer Adresse. Kanonisiert wird dabei nichts:
    Was der Operator geschrieben hat, IST die Aussage; eine zweite, geglaettete
    Fassung waere ein Objekt, dessen Verhaeltnis zur ersten niemand belegt.

    **Die Herkunft der Rechtezusage steht im Entwurf.** ``consent_status`` wird
    nicht beim Eintragen entschieden, sondern vom Controller ausserhalb dieses
    Systems; was hier passiert, ist eine Uebertragung. Der Beleg soll deshalb
    sagen, WORAUF die Zusage beruht, und nicht nur, wer sie getippt hat. Sie
    steht neben ``fields`` und nicht darin: Das Metadata Model beschreibt das
    Interview, nicht den Verwaltungsakt, auf dem seine Freigabe beruht.

    **Ohne Datei** bleibt es bei einem Profil ohne Produktion beim alten Stand
    (nur ``record_id``, alle uebrigen Pflichtfelder offen, die Kette laeuft
    weiter bis zum Bundle). Unter einem PRODUKTIVEN Profil haelt der Schritt
    an: Fuer reale Daten ist ein Katalogentwurf ohne Einwilligungs- und
    Rechteangabe kein Entwurf, sondern eine leere Form mit einem Recordnamen.
    """
    adj = input_sha(view, "l1.adjudicated", "metadata.derive")
    pfad = metadata_input_path(ctx.ws, ctx.record_id)

    fields: dict[str, Any] = {"record_id": ctx.record_id}
    consent_reference: str | None = None
    inputs = {"l1.adjudicated": adj}

    if pfad.exists():
        eingabe = load_record_metadata(pfad, record_id=ctx.record_id)
        fields = dict(eingabe.fields)
        consent_reference = eingabe.consent_reference
        from .input_sources import observe

        adresse = observe(ctx.ws, ctx.journal, ctx.record_id, "metadata.input", eingabe.raw)
        inputs["metadata.input"] = adresse
    elif ctx.ws.profile.production:
        raise RecordMetadataError(
            f"metadata.derive: Profil {ctx.ws.profile.id!r} verarbeitet reale Daten, und die "
            f"Metadateneingabe fehlt; erwartet wäre {pfad}. Ein Katalogentwurf ohne "
            "Einwilligungs- und Rechteangabe ist kein Entwurf. Kein Lauf, nichts geschrieben."
        )

    open_requirements = sorted(
        check_record(fields, consent_vocabulary=tuple(ctx.ws.profile.consent_vocabulary))
    )
    data = canonical_bytes(
        {
            "schema": "ohpipe.metadata.draft.v1",
            "record_id": ctx.record_id,
            "adjudicated": adj,
            "metadata_input": inputs.get("metadata.input"),
            "consent_reference": consent_reference,
            "required_fields": list(REQUIRED_FIELDS),
            "fields": fields,
            "open_requirements": open_requirements,
        }
    )
    sha, changed = write_derivation(
        ctx.ws,
        ctx.journal,
        record_id=ctx.record_id,
        artifact="metadata.draft",
        step="metadata.derive",
        code_version="metadata-derive/2",
        data=data,
        inputs=inputs,
        bind=True,
    )
    return DerivationResult(
        sha, changed, {"artifact_sha256": sha, "open_requirements": len(open_requirements)}
    )


def _block_b_sections() -> list[str]:
    """Die Block-B-Abschnitte des Modells — genannt, nicht geraten (ADR 0020)."""
    return sorted(pid for pid, spec in load_tap().items() if spec.block == "B")


def run_abstract_derive(ctx: Any, view: RecordView) -> DerivationResult:
    """``abstract.derive``: deskriptiver Katalogabstract nach deklarierter Schablone."""
    adj = input_sha(view, "l1.adjudicated", "abstract.derive")
    meta = input_sha(view, "metadata.confirmed", "abstract.derive")
    data = canonical_bytes(
        {
            "schema": "ohpipe.abstract.draft.v1",
            "record_id": ctx.record_id,
            "adjudicated": adj,
            "metadata": meta,
            "template_version": ABSTRACT_TEMPLATE_VERSION,
            "block": "B",
            "sections": _block_b_sections(),
        }
    )
    sha, changed = write_derivation(
        ctx.ws,
        ctx.journal,
        record_id=ctx.record_id,
        artifact="abstract.draft",
        step="abstract.derive",
        code_version="abstract-derive/1",
        data=data,
        inputs={"l1.adjudicated": adj, "metadata.confirmed": meta},
        bind=True,
    )
    return DerivationResult(
        sha, changed, {"artifact_sha256": sha, "template_version": ABSTRACT_TEMPLATE_VERSION}
    )


def run_release_preview(ctx: Any, view: RecordView) -> DerivationResult:
    """``release.preview``: setzt das Katalogartefakt zusammen. Ohne Analyse, ohne Bindung."""
    meta = input_sha(view, "metadata.confirmed", "release.preview")
    abstract = input_sha(view, "abstract.confirmed", "release.preview")
    adj = input_sha(view, "l1.adjudicated", "release.preview")
    data = canonical_bytes(
        {
            "schema": "ohpipe.release.preview.v1",
            "record_id": ctx.record_id,
            "metadata": meta,
            "abstract": abstract,
            "adjudicated": adj,
            "analysis_included": False,
        }
    )
    sha, changed = write_derivation(
        ctx.ws,
        ctx.journal,
        record_id=ctx.record_id,
        artifact="release.preview",
        step="release.preview",
        code_version="release-preview/1",
        data=data,
        inputs={"metadata.confirmed": meta, "abstract.confirmed": abstract, "l1.adjudicated": adj},
        bind=False,
    )
    return DerivationResult(sha, changed, {"artifact_sha256": sha, "analysis_included": False})


# ------------------------------------------------- die drei Bestaetigungen (GATE)

METADATA_CONFIRM_SPEC = ConfirmationSpec(
    artifact="metadata.confirmed",
    reference="metadata.confirm",
    code_version="metadata-confirm/1",
    step="metadata.confirm",
    reason_written="READY_METADATA_CONFIRM_WRITTEN",
    message_written="Die kontrollierten Metadatenfelder sind bestaetigt und an ihre Bytes gebunden.",
    reason_null="READY_METADATA_CONFIRM_NULLDURCHGANG",
    message_null="Exakt diese Metadatenbestaetigung ist bereits wirksam.",
)
ABSTRACT_CONFIRM_SPEC = ConfirmationSpec(
    artifact="abstract.confirmed",
    reference="abstract.confirm",
    code_version="abstract-confirm/1",
    step="abstract.confirm",
    reason_written="READY_ABSTRACT_CONFIRM_WRITTEN",
    message_written="Der Katalogabstract ist bestaetigt und an seine Bytes gebunden.",
    reason_null="READY_ABSTRACT_CONFIRM_NULLDURCHGANG",
    message_null="Exakt diese Abstractbestaetigung ist bereits wirksam.",
)
RELEASE_APPROVE_SPEC = ConfirmationSpec(
    artifact="release.approved",
    reference="release.approve",
    code_version="release-approve/1",
    step="release.approve",
    reason_written="READY_RELEASE_APPROVE_WRITTEN",
    message_written="Die Katalogfreigabe ist erteilt und an genau die freizugebenden Bytes gebunden.",
    reason_null="READY_RELEASE_APPROVE_NULLDURCHGANG",
    message_null="Exakt diese Freigabe ist bereits wirksam.",
)

#: Aktion (b3b_action) -> (Spec, bestaetigter Entwurf, Schema der Bestaetigungsbytes).
#: EINE Tabelle statt drei fast gleicher CLI-Zweige.
CONFIRM_GATES: dict[str, tuple[ConfirmationSpec, str, str]] = {
    "metadata_confirm": (METADATA_CONFIRM_SPEC, "metadata.draft", "ohpipe.metadata.confirmed.v1"),
    "abstract_confirm": (ABSTRACT_CONFIRM_SPEC, "abstract.draft", "ohpipe.abstract.confirmed.v1"),
    "release_approve": (RELEASE_APPROVE_SPEC, "release.preview", "ohpipe.release.approved.v1"),
}


@dataclass(frozen=True)
class ConfirmGatePlan:
    record_id: str
    actor: str
    spec: ConfirmationSpec
    draft_artifact: str
    draft_sha256: str
    subject_sha256: str
    subject_bytes: bytes
    preview: dict[str, Any]
    terminal_fields: tuple[tuple[str, str], ...] | None = None
    fields_sha256: str | None = None
    display_inputs: tuple[tuple[str, str], ...] = ()


RELEASE_FIELDS = (
    "record_id",
    "interview_date",
    "interviewer",
    "consent_status",
    "accessRights",
    "title",
    "language",
)


def release_fields_bytes(fields: dict[str, str]) -> bytes:
    """Deklarierte Kanonisierung: UTF-8, JSON sortiert/kompakt, LF, Domain/version."""
    return canonical_bytes({"domain": "ohpipe.release.fields", "version": 1, "fields": fields})


def _release_fields(ws, events, record_id, preview_sha, authority):
    def read(sha):
        try:
            with ws.store().open_verified(sha) as handle:
                obj = json.load(handle)
            if not isinstance(obj, dict) or obj.get("record_id") != record_id:
                raise ValueError("Recordbindung")
            return obj
        except (OSError, ValueError, RuntimeError) as exc:
            raise GateError("Freigabefelder nicht verifizierbar; kein Schreibakt") from exc

    preview = read(preview_sha)
    current = current_inputs(
        ws, events, record_id, ("metadata.confirmed", "metadata.draft"), authority=authority
    )
    if preview.get("metadata") != current["metadata.confirmed"]:
        raise GateError("Freigabevorlage bindet andere Metadaten; neue Vorschau erforderlich")
    metadata = read(current["metadata.confirmed"])
    if metadata.get("confirmed") != current["metadata.draft"]:
        raise GateError("Metadatenentwurf geaendert; neue Bestaetigung erforderlich")
    draft = read(current["metadata.draft"])
    fields = draft.get("fields")
    if not isinstance(fields, dict) or any(
        not isinstance(fields.get(k), str) for k in RELEASE_FIELDS
    ):
        raise GateError("Die sieben Freigabefelder sind nicht vollstaendig")
    fields = {key: fields[key] for key in RELEASE_FIELDS}
    if (
        fields["record_id"] != record_id
        or draft.get("open_requirements")
        or check_record(fields, consent_vocabulary=tuple(ws.profile.consent_vocabulary))
    ):
        raise GateError("Die sieben Freigabefelder sind nicht freigabefaehig")
    try:
        actual = sha256_bytes(metadata_input_path(ws, record_id).read_bytes())
    except OSError as exc:
        raise GateError("Metadateneingabe nicht lesbar; neue Vorschau erforderlich") from exc
    if actual != draft.get("metadata_input"):
        raise GateError("Metadateneingabe geaendert; neu ableiten, anzeigen und bestaetigen")
    return tuple(fields.items()), sha256_bytes(release_fields_bytes(fields)), tuple(current.items())


def _confirmed_bytes(schema: str, record_id: str, draft_sha: str, actor: str) -> bytes:
    return canonical_bytes(
        {"schema": schema, "record_id": record_id, "confirmed": draft_sha, "actor": actor}
    )


def plan_confirm(
    ws: Workspace,
    events: list[Any],
    *,
    spec: ConfirmationSpec,
    draft_artifact: str,
    confirmed_schema: str,
    record_id: str,
    actor_arg: str | None,
    authority: Authority = Authority.UNAUTHENTICATED,
) -> ConfirmGatePlan:
    """Plant eine Katalogbestaetigung schreibfrei: aktive Instanz aufloesen, den
    zu bestaetigenden Entwurf finden, die Bestaetigungsbytes und ihren Hash bilden."""
    draft_sha = current_inputs(ws, events, record_id, (draft_artifact,), authority=authority)[
        draft_artifact
    ]
    registry = InstanceRegistry.from_events(events)
    actor = resolve_active_human(registry, actor_arg)
    terminal_fields, fields_sha, display_inputs = None, None, ()
    data = _confirmed_bytes(confirmed_schema, record_id, draft_sha, actor)
    if spec.artifact == "release.approved" and ws.profile.production:
        terminal_fields, fields_sha, display_inputs = _release_fields(
            ws, events, record_id, draft_sha, authority
        )
        data = canonical_bytes({**json.loads(data), "fields_sha256": fields_sha})
    subject_sha = sha256_bytes(data)
    preview = {
        "action": spec.step,
        "record": record_id,
        "actor": actor,
        "confirms": draft_artifact,
        "draft_sha256": draft_sha,
        "planned_registry_effect": spec.artifact,
    }
    return ConfirmGatePlan(
        record_id,
        actor,
        spec,
        draft_artifact,
        draft_sha,
        subject_sha,
        data,
        preview,
        terminal_fields,
        fields_sha,
        display_inputs,
    )


def write_confirm(ws: Workspace, journal: Journal, plan: ConfirmGatePlan) -> Report:
    """Schreibt den angezeigten Plan; Feldänderungen verlangen einen neuen Akt."""

    def validate(transaction):
        if plan.spec.artifact == "release.approved" and ws.profile.production:
            authority = Authority.AUTHENTICATED if transaction.key else Authority.UNAUTHENTICATED
            fields, digest, inputs = _release_fields(
                ws, list(transaction), plan.record_id, plan.draft_sha256, authority
            )
            if (fields, digest, inputs) != (
                plan.terminal_fields,
                plan.fields_sha256,
                plan.display_inputs,
            ):
                raise GateError(
                    "Angezeigte Freigabefelder geaendert; erneut anzeigen und bestaetigen"
                )
            subject = json.loads(plan.subject_bytes)
            if (
                subject.get("fields_sha256") != digest
                or subject.get("confirmed") != plan.draft_sha256
            ):
                raise GateError("Freigabeplan bindet die angezeigten Felder nicht")

    return write_gate(
        ws,
        journal,
        spec=plan.spec,
        record_id=plan.record_id,
        actor=plan.actor,
        subject_bytes=plan.subject_bytes,
        subject_sha256=plan.subject_sha256,
        receipt_inputs={plan.draft_artifact: plan.draft_sha256},
        details_written={"artifact_sha256": plan.subject_sha256, "confirms": plan.draft_artifact},
        validate=validate,
    )
