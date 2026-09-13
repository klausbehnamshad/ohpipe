"""Der erste echte Schreibpfad — und damit die erste Stelle, an der die
Schreibwache tatsächlich steht.

``CutoverLedger.require_write`` existierte seit dem ersten Tag und hatte
**null Aufrufer**. Eine Wache, die nie gestanden hat, ist keine Wache; sie ist
ein Kommentar in Funktionsform. Rund fünfzehn Zusagen der Form „das System
würde X ablehnen" waren Aussagen über einen Pfad, den es nicht gab. Dieses
Modul ist der Pfad.

Der Ablauf hat genau eine Reihenfolge, und sie ist nicht verhandelbar:

1. **Erst fragen, ob geschrieben werden darf.** ``require_write`` vor jedem
   Byte. Nicht danach, nicht parallel.
2. **Dann die Quelle prüfen.** Ein Transkript, das der Parser nicht
   verlustfrei wiedergeben kann, wird nicht aufgenommen.
3. **Dann die Bytes ablegen.** Inhaltsadressiert; der Name trägt keine
   Information.
4. **Zuletzt das Ereignis.** Es beschreibt, was bereits liegt — nie, was
   gleich geschehen soll.

Schritt 4 zuletzt, weil das Journal die kanonische Evidenz ist: Ein Ereignis,
das vor der Ablage geschrieben wird, behauptet bei einem Abbruch etwas, das
nicht existiert. Umgekehrt ist ein Objekt ohne Ereignis nur unbenutzter
Speicher — es behauptet nichts. Von den beiden möglichen Halbzuständen ist
das der harmlose.

**Kein Realdatenpfad vor der Freigabe.** ``ingest`` prüft das Profil nicht auf
Realdatentauglichkeit und kann das auch nicht: Ob eine Datei synthetisch ist,
weiß nur ein Mensch. Die Trennung ist organisatorisch (ADR 0024), und dieses
Modul behauptet nichts anderes.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from ..domain.cue import CueDocument, CueFormat, CueParseError
from ..domain.events import ARTIFACT_PRODUCED, RECEIPT_RECORDED, RECORD_REGISTERED, SOURCE_INGESTED
from ..domain.language_assignment import LanguageAssignment, revision_from_assignment
from ..domain.operation import EVENT_CATALOG_VERSION, RETRY_INTENT_VERSION, RetryIntent
from ..domain.revision_serialization import PROJECTION_VERSION, canonical_revision_bytes
from ..journal import Journal
from ..policies.exit_contract import Report, Status
from ..policies.authority import Authority
from ..policies.ownership import THIS_RUNTIME, CutoverLedger
from ..project import Workspace
from .operation_recovery import Effect, b3b_report, execute_intent

__all__ = [
    "B3bIngestPlan",
    "IngestError",
    "IngestResult",
    "ingest",
    "language_prepare_required",
    "plan_b3b_ingest_srt",
    "write_b3b_ingest_srt",
]

#: Was ``ingest`` annimmt — und wie es geparst wird. Ein unbekanntes Suffix
#: wird abgelehnt statt geraten: Ein als SRT gelesenes VTT verliert seinen
#: Kopf, und der Verlust fiele erst beim Export auf.
FORMATE: dict[str, tuple[CueFormat, str]] = {
    ".srt": (CueFormat.SRT, "application/x-subrip"),
    ".vtt": (CueFormat.VTT, "text/vtt"),
}

#: Obergrenze für eine einzelne Quelldatei. Kein Sicherheitsmerkmal, sondern
#: ein Bedienungsschutz: Wer versehentlich ein Audiofile übergibt, soll einen
#: Satz lesen und nicht auf einen Parser warten.
MAX_BYTES = 32 * 1024 * 1024


class IngestError(RuntimeError):
    """Die Quelle kann nicht aufgenommen werden."""


@dataclass(frozen=True)
class IngestResult:
    record_id: str
    address: str
    cues: int
    bytes: int
    geschrieben: list[str]
    """Was sich geändert hat — für die CHANGED-Zeile, konkret und vollständig."""

    neu: bool
    """Ob der Record durch diesen Lauf entstanden ist."""

    bereits_vorhanden: bool = False
    """Diese Bytes lagen schon unter diesem Record.

    Heisst NICHT "nichts wurde angehängt": Derselbe Aufruf kann soeben
    ``record.registered`` geschrieben haben. Was tatsächlich geschrieben wurde,
    sagt ``geschrieben`` — und nur das.
    """


@dataclass(frozen=True)
class B3bIngestPlan:
    record_id: str
    assignment: LanguageAssignment
    language_receipt_digest: str
    revision_bytes: bytes
    revision_sha256: str


def language_prepare_required(record_id: str, *, next_command: str) -> Report:
    """Geschlossener LNG-01-Ausgang ohne Store-, Journal- oder Sperrwirkung."""
    return b3b_report(
        Status.ACTION_NEEDED,
        "ACTION_B3B_LANGUAGE_PREPARE_REQUIRED",
        f"Fuer den exakten Sprach-Routingkey von {record_id} fehlt eine aktuelle Zuordnung.",
        next_command=next_command,
        operation_result="NONE",
    )


def plan_b3b_ingest_srt(
    *,
    record_id: str,
    assignment: LanguageAssignment,
    language_receipt_digest: str,
) -> B3bIngestPlan:
    if assignment.target_record_id != record_id:
        raise IngestError("Sprachzuordnung bindet einen fremden Record")
    if re.fullmatch(r"[0-9a-f]{64}", language_receipt_digest) is None:
        raise IngestError("Sprachzuordnung braucht den vollen aktuellen Receipt-Ereignisdigest")
    revision = revision_from_assignment(assignment.draft, assignment)
    revision_bytes = canonical_revision_bytes(revision)
    return B3bIngestPlan(
        record_id=record_id,
        assignment=assignment,
        language_receipt_digest=language_receipt_digest,
        revision_bytes=revision_bytes,
        revision_sha256=revision.revision_sha256,
    )


def _b3b_intent(ws: Workspace, plan: B3bIngestPlan) -> RetryIntent:
    workspace = ws.running_graph_sha256()
    assignment = plan.assignment
    return RetryIntent(
        workspace_id=workspace,
        command="ingest_srt",
        target_key={
            "workspace_id": workspace,
            "record_id": plan.record_id,
            "srt_bytes_sha256": assignment.draft.srt_bytes_sha256,
        },
        inputs={
            "srt_bytes_sha256": assignment.draft.srt_bytes_sha256,
            "language_assignment_sha256": assignment.sha256,
            "language_receipt_event_digest": plan.language_receipt_digest,
            "revision_sha256": plan.revision_sha256,
        },
        store_bindings={
            "language_assignment_store": {
                "address": assignment.sha256,
                "sha256": assignment.sha256,
            },
            "revision_store": {
                "address": plan.revision_sha256,
                "sha256": plan.revision_sha256,
            },
        },
        causal_prestate={
            "current_language_assignment_sha256": assignment.sha256,
            "current_language_assignment_event_digest": plan.language_receipt_digest,
            "current_revision_sha256": None,
            "current_revision_event_digest": None,
        },
        rule_versions={
            "event_catalog": EVENT_CATALOG_VERSION,
            "retry_intent": RETRY_INTENT_VERSION,
            "projection_code": PROJECTION_VERSION,
        },
        idempotency_keys={"produced_key": plan.revision_sha256},
        routing_keys={
            "language_assignment_routing_key": [
                workspace,
                plan.record_id,
                assignment.draft.srt_bytes_sha256,
            ]
        },
        desired_effect={
            "event_sequence": [
                "operation.intent.recorded",
                RECEIPT_RECORDED,
                ARTIFACT_PRODUCED,
            ],
            "store_outputs": {
                "retry_intent_store": "SELF_OPERATION_INTENT_SHA256",
                "revision_store": plan.revision_sha256,
            },
            "system_bindings": {"operation_intent_sha256": "SELF_OPERATION_INTENT_SHA256"},
        },
    )


def write_b3b_ingest_srt(ws: Workspace, journal: Journal, plan: B3bIngestPlan) -> Report:
    # (1) Schreibrecht ZUERST — derselbe Satz wie in :func:`ingest`, und aus
    # demselben Grund. Die Wache steht in der ANWENDUNGSSCHICHT und nicht im
    # CLI: seit ADR 0013 ruft die Reviewoberflaeche dieselbe Schicht, und eine
    # Wache, die nur an der Fronttuer haengt, schuetzt genau einen Eingang.
    # Der Ledger wird hier gebaut und nicht durchgereicht, damit kein Aufrufer
    # ihn weglassen kann.
    CutoverLedger.from_journal(
        journal,
        strict=False,
        authority=Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED,
        default_runtime=ws.profile.legacy_runtime or THIS_RUNTIME,
    ).require_write(plan.record_id)
    receipt = {
        # Der Graphname, nicht der Belegname. `replay` legt eine Zeile nur fuer
        # Namen an, die ein Schritt des Graphen ERZEUGT; alles andere ist ein
        # Befund und faerbt den Record rot. Welcher Beleg das hier ist, sagt
        # `kind` — und nur `kind`: die Spezialisierung des Feldsatzes in
        # `src/ohpipe/domain/events.py::_specialised_fields` haengt ohnehin daran.
        "artifact": "transcript.revision",
        "output_sha256": plan.revision_sha256,
        "inputs": {
            "srt": plan.assignment.draft.srt_bytes_sha256,
            "language_assignment": plan.assignment.sha256,
        },
        "code_version": PROJECTION_VERSION,
        "kind": "transcript.fulltext.segment_projection.v1",
        "fulltext_origin": "from_segments",
    }
    produced = {"artifact": "transcript.revision", "sha256": plan.revision_sha256}
    from .replay import replay
    from ..domain.step import build_graph

    view = replay(journal, graph=build_graph(ws.profile), authority=Authority.AUTHENTICATED).get(
        plan.record_id
    )
    facts = view.facts.get("transcript.revision") if view else None
    renew = facts is not None and facts.freshness is not None
    if facts is not None and facts.sha256 == plan.revision_sha256 and not renew:
        if not any(
            event.kind == RECEIPT_RECORDED and event.payload == receipt for event in journal
        ):
            return b3b_report(
                Status.STOP,
                "STOP_B3B_RECOVERY_STATE_INVALID",
                "Produced ohne journalfrueheren segment_projection-Receipt ist Matrix G.",
                operation_result="NONE",
            )
        return b3b_report(
            Status.READY,
            "READY_B3B_NULLDURCHGANG",
            "Revision und Projektionsbeleg sind bereits bytegleich wirksam.",
            operation_result="NULLDURCHGANG",
        )
    intent, events = execute_intent(
        ws,
        journal,
        lambda: _b3b_intent(ws, plan),
        lambda _intent_value: [
            Effect(RECEIPT_RECORDED, receipt, plan.record_id),
            Effect(ARTIFACT_PRODUCED, produced, plan.record_id),
        ],
        current_effects=True,
        renew_effects=renew,
        # Auch die SRT-Rohbytes. Der Beleg fuehrt sie als Eingabe `srt`; eine
        # Eingabe, deren Bytes nirgends liegen, ist eine Referenz ins Leere —
        # und genau das meldet `ContentStore.check_referenced` dem Operator als
        # Befund, sobald `status` oder `continue` den Record ansieht. Gemessen:
        # ohne diese Zeile faellt ein frisch aufgenommener Record auf STOP,
        # obwohl jeder Schritt sauber gelaufen ist.
        pre_intent_objects=(
            plan.assignment.draft.raw_bytes,
            plan.assignment.bytes,
            plan.revision_bytes,
        ),
    )
    return b3b_report(
        Status.READY,
        "READY_B3B_WRITTEN",
        "SRT-Ingest schrieb Intent, Projektionsbeleg und Produced in fester Reihenfolge.",
        changed=[str(ws.journal_path), str(ws.objects / plan.revision_sha256)],
        operation_result="WRITTEN",
        details={"intent_sha256": intent.sha256, "events": [event.kind for event in events]},
    )


def _sicherer_dateiname(p: Path) -> str:
    """Nur der Basename, normalisiert, ohne Pfadanteile.

    Ein absoluter Pfad im Journal verrät die Ablagestruktur — und in der Praxis
    steht der Name der interviewten Person oft im Ordnernamen, nicht in der
    Datei. Das Journal ist append-only; eine solche Spur ist dauerhaft.
    """
    name = unicodedata.normalize("NFC", p.name)
    if "/" in name or "\\" in name or name in ("", ".", ".."):
        raise IngestError("Dateiname ist unbrauchbar.")
    return name


def ingest(
    ws: Workspace,
    journal: Journal,
    ledger: CutoverLedger,
    quelle: Path,
    record_id: str,
) -> IngestResult:
    """Nimmt EINE Quelldatei als Record auf.

    Wirft ``OwnershipError``, ``IngestError``, ``StoreError`` oder
    ``PayloadRejected`` — jedes davon hat oben eine eigene Antwort im
    Vierzeiler. Nichts davon wird hier in einen Rückgabewert übersetzt: Ein
    Fehler, der als Wert zurückkommt, wird irgendwann nicht geprüft.
    """
    rid = ws.profile.normalize_record_id(record_id)
    if not ws.profile.is_record_id(rid):
        raise IngestError(
            f"{record_id!r} ist keine gültige Record-ID für Profil {ws.profile.id!r}. "
            f"Erwartet wird {ws.profile.record_prefix}-"
            f"{'N' * ws.profile.record_digits}."
        )

    # (1) Schreibrecht ZUERST. Der einzige Aufrufpunkt der Wache.
    ledger.require_write(rid)

    # (2) Quelle prüfen, bevor irgendetwas abgelegt wird.
    quelle = Path(quelle).expanduser()
    try:
        roh = quelle.read_bytes()
    except OSError as exc:
        raise IngestError(f"Quelldatei nicht lesbar: {exc}") from exc
    if not roh:
        raise IngestError("Quelldatei ist leer.")
    if len(roh) > MAX_BYTES:
        raise IngestError(
            f"Quelldatei ist {len(roh) // 1024 // 1024} MB groß, erlaubt sind "
            f"{MAX_BYTES // 1024 // 1024} MB. Ist das wirklich ein Transkript?"
        )

    suffix = quelle.suffix.lower()
    if suffix not in FORMATE:
        raise IngestError(
            f"Unbekannte Endung {suffix!r}. Aufgenommen werden: {', '.join(sorted(FORMATE))}. "
            "Das Format wird nicht geraten — ein als SRT gelesenes VTT verliert seinen Kopf."
        )
    fmt, media_type = FORMATE[suffix]

    try:
        dok = CueDocument.parse_bytes(roh, fmt)
    except CueParseError as exc:
        raise IngestError(f"{quelle.name} ist kein lesbares {fmt.value}: {exc}") from exc

    # Verlustfreiheit ist eine Aufnahmebedingung, keine Zusicherung im
    # Nachhinein: Was wir nicht byteweise zurückgeben können, nehmen wir nicht
    # auf. Sonst hätte der spätere Export eine Herkunft, die er nicht einlösen
    # kann (INTEROP §1).
    #
    # EHRLICH DAZUGESAGT: Dieser Vergleich ist heute nicht auslösbar. Der
    # Cue-Parser lehnt ab, was er nicht verlustfrei wiedergeben kann, schon
    # beim Parsen — acht konstruierte Kandidaten (fehlendes Zeilenende, CRLF,
    # BOM, doppelte Leerzeilen, Lücken in den Cue-IDs, Tabs) kommen entweder
    # bytegleich zurück oder gar nicht durch. Die Mutationsprobe hat das
    # aufgedeckt: `if False:` an dieser Stelle überlebte die Suite.
    #
    # Er bleibt trotzdem stehen, aber mit richtigem Namen: Er ist ein
    # STOLPERDRAHT gegen eine künftige Parseränderung, kein Eingangsfilter.
    # Wer den Parser toleranter macht, bekommt hier einen Halt statt eines
    # stillen Verlusts. In der Mutantenliste steht er deshalb NICHT — eine
    # Zusage, die niemand auslösen kann, wird nicht als geprüft geführt.
    if dok.render_bytes() != roh:
        raise IngestError(
            f"{quelle.name} lässt sich nicht bytegleich wiedergeben. Die Datei wird "
            "nicht aufgenommen — ein Transkript, dessen Struktur wir verlieren, "
            "kann später keinen belegbaren Export tragen."
        )
    if not dok.payloads():
        raise IngestError(f"{quelle.name} enthält keinen einzigen Cue.")

    # (3) Bytes ablegen.
    store = ws.store()
    with quelle.open("rb") as fh:
        address = store.put(fh)

    geschrieben: list[str] = [f"{ws.objects}/<{address[:12]}…>"]

    # (4) Erst jetzt die Evidenz.
    #
    # Idempotent. "Hat das geklappt? Nochmal." ist die normalste
    # Operatorhandlung, die es gibt — und bei append-only ist das erzeugte
    # Rauschen nicht mehr entfernbar. Beide Ereignisarten hingen frueher blank
    # an, hinter einem ungesperrten Lesen — derselbe Befehl zweimal ergab zwei
    # Ereignisse, gleiche Meldung, kein Hinweis.
    #
    # Beide Prüfungen liegen jetzt IN der Sperre (`append_once`). Die
    # Vorgängerfassung las das Journal als Listenausdruck davor und hängte
    # danach an — sequenziell idempotent, nebenläufig nicht: acht gleichzeitige
    # Aufrufe auf denselben Record schrieben acht `record.registered` und acht
    # `source.ingested`. Die Kette blieb heil, `doctor` meldete READY, und bei
    # append-only bleibt das drin.
    registriert = journal.append_once(
        RECORD_REGISTERED,
        {"record_id": rid, "profile": ws.profile.id},
        record_id=rid,
    )
    neu = registriert is not None

    eingetragen = journal.append_once(
        SOURCE_INGESTED,
        {
            "record_id": rid,
            "sha256": address,
            "media_type": media_type,
            "filename": _sicherer_dateiname(quelle),
            "bytes": len(roh),
            "cues": len(dok.payloads()),
        },
        record_id=rid,
        # Massgeblich ist der HASH, nicht der Dateiname: Dieselben Bytes unter
        # anderem Namen sind dieselbe Quelle. Andere Bytes sind eine neue
        # Fassung und werden angehängt — das ist kein Duplikat, sondern
        # Geschichte.
        duplikat=lambda e: e.payload.get("sha256") == address,
    )
    if eingetragen is None:
        # Nichts MEHR anzuhaengen — aber vielleicht hat genau dieser Aufruf
        # eben den Record angelegt. Die Vorgaengerfassung setzte hier hart
        # `neu=False` und `geschrieben=[]` und warf damit das Ergebnis des
        # ERSTEN `append_once` weg.
        #
        # Nebenlaeufig war das eine Luecke im CHANGED-Vertrag: Gewinnt A
        # `record.registered` und B `source.ingested`, meldete B
        # `neu=False` (es hat den Record nicht angelegt) und A ebenfalls
        # `neu=False` (weil hart gesetzt). Kein Aufruf behauptete die
        # Anlage, die nachweislich stattgefunden hat — und der Schreiber
        # meldete "nichts angehaengt". Ein Vierzeiler, der eine echte
        # Aenderung verschweigt, ist schlimmer als einer, der zu viel meldet:
        # Der Operator glaubt, nichts getan zu haben.
        #
        # Jetzt meldet jeder Aufruf genau das, was seine eigenen
        # `append_once`-Ergebnisse belegen. Zwei Sperrabschnitte bleiben
        # zwei Sperrabschnitte — die Zusage ist nicht, dass beide Ereignisse
        # gemeinsam fallen, sondern dass jede Aenderung von genau einem
        # Aufrufer behauptet wird.
        if registriert is not None:
            geschrieben.append(str(journal.path))
        else:
            # Nichts angehaengt UND nichts abgelegt: `geschrieben` wurde oben
            # mit dem Objekteintrag initialisiert, bevor ueberhaupt feststand,
            # ob etwas geschrieben wird. Steht hier ein passendes
            # `source.ingested` im Journal, lag GENAU DIESE Adresse schon vor —
            # `store.put` war ein Nulldurchgang, und der Eintrag waere eine
            # behauptete Aenderung, die nicht stattgefunden hat.
            #
            # Die erste Fassung dieser Reparatur uebersah das und liess den
            # Objektpfad stehen; der echte Wiederholungsfall meldete dann
            # `changed=[Objekt]` statt `[]`. Gefunden hat es die Gegenprobe,
            # die genau dafuer danebensteht — nicht der neue Test.
            #
            # Bewusst in Kauf genommen: Fehlt das Objekt im Store, obwohl das
            # Ereignis existiert, legt `store.put` es bytegleich neu an und wir
            # melden es hier nicht. Dieser Zustand ist ein Store-Befund und
            # gehoert zu `doctor` (`check_referenced`), nicht in die
            # CHANGED-Zeile eines Ingest, der fachlich nichts getan hat.
            geschrieben = []
        return IngestResult(
            record_id=rid,
            address=address,
            cues=len(dok.payloads()),
            bytes=len(roh),
            geschrieben=geschrieben,
            neu=neu,
            bereits_vorhanden=True,
        )

    geschrieben.append(str(journal.path))

    return IngestResult(
        record_id=rid,
        address=address,
        cues=len(dok.payloads()),
        bytes=len(roh),
        geschrieben=geschrieben,
        neu=neu,
    )
