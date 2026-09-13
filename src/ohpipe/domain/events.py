"""Die Ereignisarten und ihre Nutzlasten — an genau einer Stelle.

Vorher standen dieselben Feldnamen an drei Orten: im Schreibpfad, der sie
zusammensetzt; in ``Event.from_json``, das die Hülle von Hand rekonstruiert;
und in ``replay``, das sie einzeln wieder herausliest. Drei Kopien einer
Vereinbarung, von denen keine die anderen kennt. Genau das ist die Sorte
Duplikat, bei der eine Kopie still verrottet und die Tests dieser Kopie grün
bleiben, weil sie gegen ein Format prüfen, das es nicht mehr gibt.

**Die Allowlist ist eine Schreibbedingung, keine Lesehilfe.** Das Journal ist
append-only: Was einmal darinsteht, bleibt darin. Ein Feld, das beim Schreiben
durchrutscht, ist dauerhaft — und wenn es eine Oberflächenform trägt, ist es
dauerhaft eine Klartextspur in der kanonischen Evidenz (D1, D4). Deshalb wird
hier nicht gefiltert, sondern **abgelehnt**: Ein unbekanntes Feld ist ein
Programmierfehler des Aufrufers, und ihn stillschweigend wegzuwerfen hiesse,
den Aufrufer im Glauben zu lassen, sein Wert sei angekommen.

Umgekehrt gilt: **Diese Prüfung ist keine Autorisierung** (ADR 0017). Eine
wohlgeformte Nutzlast ist eine wohlgeformte Nutzlast. Ob sie etwas bewirken
darf, entscheidet die Autoritätsregel, nicht dieses Modul.

Was hier NICHT steht, ist Absicht: die Semantik. Ob ein ``sha256`` zu den
Bytes im Store passt, ob eine Entscheidung eine echte ``Decision`` ergibt, ob
ein Beleg an sein Gate gebunden ist — das prüft ``replay`` gegen den
Gesamtzustand. Dieses Modul beantwortet nur: Ist das überhaupt ein Ereignis
dieser Art?
"""

from __future__ import annotations

from ohpipe.domain import manual_context

from dataclasses import dataclass
from typing import Any

from .decision import SHA256_RE

__all__ = [
    "ANCHOR_CHECKED",
    "ARTIFACT_PRODUCED",
    "DECISION_RECORDED",
    "ENVELOPE_FIELDS",
    "FORBIDDEN_KINDS",
    "INSTANCE_REGISTERED",
    "INSTANCE_RETIRED",
    "INPUT_REF_ROLES",
    "ISO6393_SNAPSHOT_PREPARED",
    "KINDS",
    "OPERATION_INTENT_RECORDED",
    "RECEIPT_RECORDED",
    "RECORD_ADOPTED",
    "RECORD_DISABLED",
    "RECORD_REGISTERED",
    "SOURCE_INGESTED",
    "WORKSPACE_INITIALISED",
    "PayloadRejected",
    "check_payload",
    "known",
]


class PayloadRejected(ValueError):
    """Die Nutzlast passt nicht zu ihrer Ereignisart."""


# -- Ereignisarten ---------------------------------------------------------

WORKSPACE_INITIALISED = "workspace.initialised"
RECORD_REGISTERED = "record.registered"
SOURCE_INGESTED = "source.ingested"
ARTIFACT_PRODUCED = "artifact.produced"
RECEIPT_RECORDED = "receipt.recorded"
DECISION_RECORDED = "decision.recorded"
ANCHOR_CHECKED = "anchor.checked"
RECORD_DISABLED = "record.disabled"
RECORD_ADOPTED = "record.adopted"
OPERATION_INTENT_RECORDED = "operation.intent.recorded"
INSTANCE_REGISTERED = "instance.registered"
INSTANCE_RETIRED = "instance.retired"
ISO6393_SNAPSHOT_PREPARED = "iso6393.snapshot.prepared"

#: Ereignisarten, die einen Zustand BEHAUPTEN statt Evidenz einzutragen.
#: Sie existieren nicht mehr; taucht eine im Journal auf, ist das ein Befund.
FORBIDDEN_KINDS = frozenset({"artifact.state", "record.state", "status.set"})

#: Erlaubte Eingabebezüge je Entscheidungsartefakt. Bewusst ausgeschrieben
#: statt aus dem Graphen abgeleitet: ``check_payload`` prüft Syntax, nicht
#: Zustand oder Autorität, und besitzt deshalb keinen Laufgraphen.
INPUT_REF_ROLES: dict[str, frozenset[str]] = {
    "transcript.confirmed": frozenset({"transcript"}),
}

#: Die Felder der Hülle. Sie stehen hier, damit ``Event.to_json`` und
#: ``Event.from_json`` nicht zwei Listen pflegen, die auseinanderlaufen können.
#: Wert ist (Typ, optional).
ENVELOPE_FIELDS: dict[str, tuple[type, bool]] = {
    "seq": (int, False),
    "at": (str, False),
    "kind": (str, False),
    "record_id": (str, True),
    "payload": (dict, False),
    "prev": (str, False),
    "digest": (str, False),
}


@dataclass(frozen=True)
class Kind:
    name: str
    pflicht: frozenset[str]
    optional: frozenset[str] = frozenset()
    braucht_record: bool = True
    """Ob ``record_id`` in der Hülle gesetzt sein muss."""

    @property
    def erlaubt(self) -> frozenset[str]:
        return self.pflicht | self.optional


def _k(
    name: str, pflicht: str, optional: str = "", *, braucht_record: bool = True
) -> tuple[str, Kind]:
    return name, Kind(
        name=name,
        pflicht=frozenset(pflicht.split()),
        optional=frozenset(optional.split()),
        braucht_record=braucht_record,
    )


KINDS: dict[str, Kind] = dict(
    (
        _k(WORKSPACE_INITIALISED, "profile root version", braucht_record=False),
        # Ein Record entsteht als Ereignis, nicht als Verzeichnis. Wer ein
        # Verzeichnis anlegt, hat noch keinen Record — er hat einen Ordner.
        _k(RECORD_REGISTERED, "record_id profile", "note"),
        # Die Quelle wird mit ihrem Hash festgehalten, NICHT mit ihrem Pfad
        # jenseits des Dateinamens: Ein absoluter Pfad im Journal verrät die
        # Ablagestruktur der Datenwurzel und oft den Namen der Person im
        # Ordnernamen. `filename` ist der Basename, sonst nichts.
        _k(SOURCE_INGESTED, "record_id sha256 media_type filename bytes", "cues note"),
        _k("input.observed", "role sha256"),
        _k("p4c.init.prepared", "v ref at", braucht_record=False),
        _k("p4c.initialised", "v ref at", braucht_record=False),
        _k(
            "p4c.prepared",
            "v phase operation actor actor_state at basis registry_before registry_after refs marker",
        ),
        _k("p4c.completed", "v prepared_sha256"),
        _k("p4c.aborted", "v prepared_sha256"),
        _k("p4b.policy", "v profile graph sha256"),
        _k("p4b.checkpoint", "v ref basis actor actor_state previous"),
        _k("p4b.prepared", "v ref plan basis actor actor_state checkpoint at"),
        _k("p4b.completed", "v prepared_sha256"),
        _k(ARTIFACT_PRODUCED, "artifact sha256", "disposition harness_era"),
        _k(
            RECEIPT_RECORDED,
            "artifact output_sha256 inputs code_version",
            "kind step params prompt_sha256 finish_reason "
            "authorisation authorisation_subject_sha256 authorised_at started_at",
        ),
        _k(
            DECISION_RECORDED,
            "artifact subject_sha256 verdict reference actor at",
            "note record_id input_refs input_refs_version profile_id graph_sha256 undo_of",
        ),
        _k(ANCHOR_CHECKED, "artifact outcome", "note"),
        _k(
            RECORD_DISABLED,
            "artifact subject_sha256 verdict reference actor at",
            "note record_id",
        ),
        _k(RECORD_ADOPTED, "record_id from to reference", "decision_id artifact_hashes note"),
        _k(
            OPERATION_INTENT_RECORDED,
            "domain v workspace_id command target_key intent_sha256",
            braucht_record=False,
        ),
        _k(
            INSTANCE_REGISTERED,
            "coder_id source label reference",
            "model parametersatz",
            braucht_record=False,
        ),
        _k(INSTANCE_RETIRED, "coder_id reference", braucht_record=False),
        _k(
            ISO6393_SNAPSHOT_PREPARED,
            "release_id source_sha256 vocabulary_sha256 reference raw_store canonical_store",
            braucht_record=False,
        ),
    )
)


def known(kind: str) -> bool:
    return kind in KINDS


#: Feldnamen, die eine Oberflächenform tragen KÖNNTEN und in keiner Nutzlast
#: vorkommen dürfen. Sie stehen in keiner ``erlaubt``-Menge und wären daher
#: ohnehin abgelehnt — aber mit einer Begründung, die nach Tippfehler klingt.
#: Diese Liste macht aus „unbekanntes Feld" einen benannten Befund.
KLARTEXTVERDACHT = frozenset(
    {"surface", "quote", "context", "replacement", "text", "name", "original", "value"}
)


def check_payload(kind: str, payload: Any, record_id: str | None) -> None:
    """Wirft ``PayloadRejected``, wenn die Nutzlast nicht zur Art passt.

    Die Meldungen nennen **niemals einen abgelehnten Wert**, nur Feldnamen und
    Zahlen. Ein Fehlertext ist eine Logzeile, und eine Logzeile mit einer
    Oberflächenform darin ist genau der Re-Identifikationspfad, den D4
    beschreibt.
    """
    if kind.startswith("p4c."):
        spec = KINDS.get(kind)
        if spec is not None and isinstance(payload, dict) and spec.pflicht - set(payload):
            raise PayloadRejected(
                "Pflichtfelder fehlen: " + ", ".join(sorted(spec.pflicht - set(payload)))
            )
        from .p4c_events import check

        try:
            check(kind, payload, record_id)
        except ValueError:
            raise PayloadRejected("Ungültiger P4c-Metadatenvertrag") from None
        return
    if kind.startswith("p4b."):
        spec = KINDS.get(kind)
        if spec is not None and isinstance(payload, dict) and spec.pflicht - set(payload):
            raise PayloadRejected(
                "Pflichtfelder fehlen: " + ", ".join(sorted(spec.pflicht - set(payload)))
            )
        from .p4b_events import check

        try:
            check(kind, payload, record_id)
        except ValueError:
            raise PayloadRejected("Ungültiger P4b-Metadatenvertrag") from None
        return
    if kind in FORBIDDEN_KINDS:
        raise PayloadRejected(
            f"{kind!r} behauptet einen Zustand, statt Evidenz einzutragen. "
            "Zustand wird abgeleitet, nicht geschrieben (ADR 0003)."
        )
    spec = KINDS.get(kind)
    if spec is None:
        raise PayloadRejected(
            f"unbekannte Ereignisart {kind!r}. Bekannt sind: {', '.join(sorted(KINDS))}"
        )
    if not isinstance(payload, dict):
        raise PayloadRejected(f"{kind}: Nutzlast ist {type(payload).__name__}, erwartet dict")

    specialised = _specialised_fields(kind, payload)
    if specialised is not None:
        fehlend = sorted(specialised - set(payload))
        fremd = sorted(set(payload) - specialised)
        if fehlend or fremd:
            raise PayloadRejected(
                f"{kind}: spezialisierter Feldsatz weicht ab; fehlt={fehlend}, fremd={fremd}"
            )

    schluessel = set(payload)
    verdaechtig = sorted(schluessel & KLARTEXTVERDACHT)
    if verdaechtig:
        raise PayloadRejected(
            f"{kind}: die Felder {verdaechtig} dürfen in keiner Nutzlast stehen. "
            "Sie tragen typischerweise eine Oberflächenform, und das Journal ist "
            "append-only — eine Klartextspur darin ist dauerhaft."
        )
    if specialised is None:
        fehlend = sorted(spec.pflicht - schluessel)
        if fehlend:
            raise PayloadRejected(f"{kind}: Pflichtfelder fehlen: {fehlend}")
        fremd = sorted(schluessel - spec.erlaubt)
        if fremd:
            raise PayloadRejected(
                f"{kind}: nicht erlaubte Felder: {fremd}. "
                f"Erlaubt sind: {sorted(spec.erlaubt)}. Ein unbekanntes Feld wird nicht "
                "stillschweigend verworfen — es wäre sonst dauerhaft im Journal."
            )
    braucht_record = spec.braucht_record
    if (
        specialised is not None
        and kind == RECEIPT_RECORDED
        and payload.get("kind") == "transcript.segment_languages.prepared.v1"
    ):
        braucht_record = False
    if braucht_record and not record_id:
        raise PayloadRejected(f"{kind}: record_id fehlt in der Hülle")
    if not braucht_record and record_id:
        raise PayloadRejected(f"{kind}: record_id gehört nicht zu dieser Ereignisart")

    # Einige Arten tragen `record_id` zusätzlich in der Nutzlast, weil ein
    # Übergabebeleg exportierbar sein muss und dann für sich stehen soll. Zwei
    # Orte für dieselbe Angabe sind aber ein Angriffsweg: Die Hülle bestimmt,
    # welchem Record ein Ereignis zugeordnet wird — die Nutzlast bestimmt, was
    # `ownership` daraus liest. Weichen sie ab, liest jede Schicht einen
    # anderen Record, und beide sind für sich stimmig.
    innen = payload.get("record_id")
    if innen is not None and record_id is not None and innen != record_id:
        raise PayloadRejected(
            f"{kind}: record_id in Hülle und Nutzlast widersprechen sich. "
            "Ein Ereignis gehört zu genau einem Record."
        )

    if kind == "input.observed" and (
        payload.get("role") not in ("l1.codebook", "metadata.input")
        or (
            payload.get("sha256") is not None
            and (
                not isinstance(payload["sha256"], str) or not SHA256_RE.fullmatch(payload["sha256"])
            )
        )
    ):
        raise PayloadRejected("input.observed: ungültige Rolle oder SHA256-Adresse")

    if kind == DECISION_RECORDED:
        if "input_refs_version" in payload and "input_refs" not in payload:
            raise PayloadRejected(f"{kind}: input_refs-Version ohne Eingabereferenzen")
        if ("profile_id" in payload or "graph_sha256" in payload) and (
            not isinstance(payload.get("profile_id"), str)
            or not payload["profile_id"].strip()
            or not isinstance(payload.get("graph_sha256"), str)
            or not SHA256_RE.fullmatch(payload["graph_sha256"])
        ):
            raise PayloadRejected(f"{kind}: ungültiger Profil-/Graphkontext")
        if payload.get("domain") == "transcript_confirmation_decision" and (
            type(payload.get("v")) is not int or payload["v"] not in (1, 2)
        ):
            raise PayloadRejected(f"{kind}: unbekannte Bestätigungsentscheidungsversion")

    refs = payload.get("input_refs")
    if "input_refs" in payload:
        if not isinstance(refs, dict) or not refs:
            raise PayloadRejected(
                f"{kind}: input_refs ist {type(refs).__name__} oder leer — "
                "erwartet ein nichtleeres Objekt."
            )
        version = payload.get("input_refs_version", 1)
        if type(version) is not int or version not in (1, 2, 3, 4):
            raise PayloadRejected(f"{kind}: unbekannte input_refs-Version")
        erlaubte_rollen = (
            frozenset({"text"})
            if version == 2
            else INPUT_REF_ROLES.get(payload.get("artifact"), frozenset())
        )
        if version == 4:
            from .p4c_events import REVIEW_INPUTS

            if payload.get(
                "artifact"
            ) != "transcript.pseudonymised.confirmed" or not manual_context.known(
                payload.get("profile_id")
            ):
                raise PayloadRejected("P4c-Referenzen außerhalb ihres Vertrags")
            erlaubte_rollen = frozenset(REVIEW_INPUTS)
        if version == 3:
            erlaubte_rollen = frozenset(refs)  # Semantik prüft Replay gegen den Laufgraphen.
        if set(refs) != erlaubte_rollen:
            raise PayloadRejected(
                f"{kind}: input_refs enthält eine nicht deklarierte Rolle oder eine deklarierte Rolle fehlt"
            )
        if version in (2, 3, 4) and (
            not isinstance(payload.get("profile_id"), str)
            or not payload["profile_id"]
            or not SHA256_RE.fullmatch(payload.get("graph_sha256") or "")
        ):
            raise PayloadRejected(f"{kind}: input_refs v2 braucht Profil-/Graphkontext")
        for rolle, wert in refs.items():
            if rolle not in erlaubte_rollen:
                raise PayloadRejected(
                    f"{kind}: input_refs enthält eine nicht deklarierte Rolle. "
                    f"Deklariert sind: {sorted(erlaubte_rollen)}."
                )
            if not isinstance(wert, str):
                raise PayloadRejected(
                    f"{kind}: ein input_refs-Wert ist keine Zeichenkette im sha256-Format."
                )
            if not SHA256_RE.fullmatch(wert):
                raise PayloadRejected(
                    f"{kind}: ein input_refs-Wert ist kein sha256 (^[0-9a-f]{{64}}$)."
                )


def _specialised_fields(kind: str, payload: dict[str, Any]) -> frozenset[str] | None:
    """Geschlossene B3b-v2-Spezialisierungen bestehender Ereignisarten."""
    if kind == SOURCE_INGESTED and payload.get("media_type") == "text/plain;charset=utf-8":
        return frozenset({"record_id", "sha256", "media_type", "filename", "bytes"})
    if kind == RECEIPT_RECORDED:
        receipt_kind = payload.get("kind")
        if receipt_kind == "transcript.fulltext.separate_input.v1":
            return frozenset(
                {
                    "artifact",
                    "output_sha256",
                    "inputs",
                    "code_version",
                    "kind",
                    "fulltext_origin",
                    "reference",
                    "fulltext_source_receipt",
                }
            )
        if receipt_kind == "transcript.fulltext.segment_projection.v1":
            return frozenset(
                {
                    "artifact",
                    "output_sha256",
                    "inputs",
                    "code_version",
                    "kind",
                    "fulltext_origin",
                }
            )
        if receipt_kind == "transcript.segment_languages.prepared.v1":
            return frozenset(
                {
                    "artifact",
                    "output_sha256",
                    "inputs",
                    "code_version",
                    "kind",
                    "target_record_id",
                    "actor",
                    "reference",
                    "iso6393_release",
                    "iso6393_vocabulary_sha256",
                    "iso6393_snapshot_receipt",
                }
            )
    b3b_decision_sentinels = {
        "domain",
        "v",
        "activation_id",
        "decision_id",
        "reason_code",
        "fulltext_origin",
        "fulltext_receipt",
        "iso6393_release",
        "iso6393_vocabulary_sha256",
        "iso6393_snapshot_receipt",
    }
    if (
        kind == DECISION_RECORDED
        and payload.get("artifact") == "transcript.confirmed"
        and set(payload) & b3b_decision_sentinels
    ):
        return frozenset(
            {
                "domain",
                "v",
                "record_id",
                "artifact",
                "subject_sha256",
                "verdict",
                "reference",
                "activation_id",
                "decision_id",
                "actor",
                "at",
                "note",
                "reason_code",
                "input_refs",
                "source",
                "fulltext_origin",
                "fulltext_receipt",
                "iso6393_release",
                "iso6393_vocabulary_sha256",
                "iso6393_snapshot_receipt",
            }
            | ({"profile_id", "graph_sha256"} if payload.get("v") == 2 else set())
        )
    return None
