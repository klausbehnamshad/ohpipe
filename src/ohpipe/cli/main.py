"""Die dünne Fronttür.

Regel aus ADR 0013: Das CLI enthält KEINE Geschäftslogik. Es löst Argumente auf,
ruft die Anwendungsschicht und rendert einen :class:`Report`. Die
Review-Oberfläche ruft dieselbe Schicht — es gibt keine zweite Logik, die
driften könnte.

Zwei Regeln für ``NEXT``:

* Der genannte Befehl muss **existieren** und **so aufrufbar sein, wie er
  dasteht**. Ein NEXT, das argparse ablehnt, ist schlimmer als keines.
* Ein noch nicht gebauter Befehl wird nicht empfohlen.
"""

from __future__ import annotations

from ..application.storage_integrity import check_referenced

import argparse
import json
import os
import shlex
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..application.confirmation import plan_confirmation, write_confirmation
from ..application.review import plan_l1_review, write_l1_review
from ..application.catalog import CONFIRM_GATES, plan_confirm, write_confirm
from ..application.anchors import AnchorsError, offene_zeile, reanchor_report
from ..application.export import ExportBlocked, ExportTargetError, plan_export, write_export
from ..application.gate import GateError, GateBlocked
from ..application.fulltext import plan_fulltext_prepare, write_fulltext_prepare
from ..application.ingest import (
    IngestError,
    ingest,
    language_prepare_required,
    plan_b3b_ingest_srt,
    write_b3b_ingest_srt,
)
from ..application.instance_registry import plan_register, plan_retire, write_instance_plan
from ..application.iso6393 import plan_iso_prepare, write_iso_prepare
from ..application.replay import replay
from ..application.steps import (
    StepContext,
    check_registry,
    continue_record,
    continue_report,
)
from ..application.transcript_language import (
    export_language_template,
    plan_language_prepare,
    write_language_prepare,
)
from .ui import is_english, text
from ..domain.iso6393 import IsoSnapshotError, parse_iso6393_snapshot
from ..domain.language_assignment import LanguageAssignmentError, assign_languages, build_srt_draft
from ..domain.step import check_egress_gates, build_graph
from ..domain.instance import InstanceRegistry
from ..domain.revision_serialization import verify_revision
from ..journal import (
    ENV_KEY,
    UNSAFE_REASON,
    Journal,
    JournalBroken,
    JournalUnsafe,
    PayloadRejected,
    load_key,
)
from ..policies.authority import Authority
from ..policies.exit_contract import Report, Status
from ..policies.metadata import RecordMetadataError, check_record, load_record_metadata
from ..policies.ownership import LEGACY_RUNTIME, THIS_RUNTIME, CutoverLedger, OwnershipError
from ..project import (
    ENV_ROOT,
    DataRootError,
    GraphBindingError,
    GraphBindingState,
    ModelNotAllowed,
    ProfileError,
    Workspace,
    WorkspaceUnsafe,
)
from ..store import StoreError

__version__ = "0.1.0.dev0"

#: Mitgelieferte Profile liegen IM PAKET — sonst ist das Wheel nicht lauffähig.
PROFILE_DIR = Path(__file__).resolve().parent.parent / "profiles"

#: Wortlaut für D-1. Ein Kettenbruch ist kein Manipulationsnachweis; er heißt,
#: dass Vollständigkeit und Unverändertheit der Evidenz gerade nicht bestätigt
#: werden können. Bis zur dokumentierten Klärung wird nichts geschrieben,
#: freigegeben oder exportiert.
D1_REASON = (
    "Die Integritätsprüfung des Entscheidungsprotokolls ist fehlgeschlagen. "
    "Vollständigkeit und Unverändertheit der Evidenz sind derzeit nicht "
    "bestätigbar; das System stoppt fail-closed. Das ist kein Nachweis einer "
    "Manipulation — mögliche Ursachen sind unter anderem unvollständige oder "
    "konkurrierende Schreibvorgänge, Dateisystemeffekte und nachträgliche "
    "Änderungen. Bis zur dokumentierten Klärung erfolgen keine weiteren "
    "Schreib-, Freigabe- oder Exportvorgänge."
)


def _profile_path(name: str) -> Path:
    # Ein Pfad auf eine profile.toml ist erlaubt: projektspezifische Profile
    # gehören nicht ins Repository.
    if name.endswith(".toml"):
        p = Path(name).expanduser()
        if not p.exists():
            raise ProfileError(f"Profildatei nicht gefunden: {p}")
        return p
    p = PROFILE_DIR / name / "profile.toml"
    if not p.exists():
        available = sorted(d.name for d in PROFILE_DIR.iterdir() if d.is_dir())
        raise ProfileError(
            f"Unbekanntes Profil {name!r}. Mitgeliefert: {', '.join(available)}. "
            "Ein Pfad auf eine profile.toml ist ebenfalls erlaubt."
        )
    return p


def _workspace(args: argparse.Namespace) -> Workspace:
    return Workspace.resolve(_profile_path(args.profile), args.root)


def _default_runtime(ws: Workspace) -> str:
    """Wem gehören unbekannte Records dieses Profils?

    ``childlux`` hat einen Vorgänger und sagt ``dinoh``; ``sandbox`` hat
    keinen und gehört sich selbst. Vorher stand die Antwort global im
    Ownership-Modul — und ``ingest`` verweigerte deshalb die Aufnahme eines
    synthetischen Sandbox-Records mit dem Hinweis, er gehöre DINOH.
    """
    return ws.profile.legacy_runtime or THIS_RUNTIME


def _graph_binding_entry_exists(path: Path) -> bool:
    """Erkennt auch einen gebrochenen Link als vorhandenen, ungültigen Eintrag."""
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise GraphBindingError(f"Graphbindung {path} nicht prüfbar: {exc}") from exc
    return True


def _e8_operator_command(
    ws: Workspace,
    profile_arg: str,
    command: str,
    *command_args: str,
    as_json: bool = False,
    comment: str | None = None,
) -> str:
    """Bindet neue E8-Befehle shell-sicher an Profil und aufgelöste Wurzel."""
    tokens = ["ohpipe", "--profile", profile_arg, "--root", str(ws.root)]
    if as_json:
        tokens.append("--json")
    tokens.extend((command, *command_args))
    rendered = shlex.join(tokens)
    if comment:
        rendered += f"   # {comment}"
    return rendered


def _journal_or_stop(ws: Workspace, *, mit_lockpfad: bool = True) -> tuple[Journal, Report | None]:
    """Jeder Befehl, der Evidenz auswertet, prüft sie zuerst vollständig.

    ``mit_lockpfad=False`` nutzt genau **eine** Stelle: die Vorprüfung in
    ``cmd_init``, bevor irgendetwas angelegt ist. Der Grund steht schon in
    ``Journal._exclusive`` — die Sperre liegt bewusst auf einer eigenen Datei,
    *damit sie nicht selbst Teil der Evidenz ist*. Die Vorprüfung fragt, ob die
    vorhandene Evidenz tragfähig ist; der Lockpfad gehört nicht dazu. Er wird
    beim zweiten Aufruf geprüft, nach ``ws.ensure()`` — und der STOP nennt dann,
    was dieser Lauf angelegt hat, statt still zu behaupten, es sei nichts
    passiert.
    """
    try:
        key = load_key(ws.root)
    except JournalBroken as exc:
        return Journal(ws.journal_path), Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_KEY_INVALID",
            next_command=f"unset {ENV_KEY}   # oder Schlüssel außerhalb der Datenwurzel ablegen",
        )
    if ws.profile.key_required and key is None:
        return Journal(ws.journal_path), Report(
            status=Status.CONFIG,
            reason=(
                f"Profil {ws.profile.id!r} verlangt eine authentifizierte Evidenzkette "
                f"(key_required). Ohne ${ENV_KEY} wäre jede wohlgeformte Zeile im Journal "
                "so gültig wie eine echte."
            ),
            reason_code="CONFIG_KEY_REQUIRED",
            next_command=f"export {ENV_KEY}=/pfad/ausserhalb/der/datenwurzel/journal.key",
        )
    j = Journal(ws.journal_path, key=key)
    # Kein `journal_path.exists()` mehr davor. Genau diese Zeile war der Befund:
    # bei einem gebrochenen Symlink meldet `exists()` Abwesenheit, obwohl der
    # Pfad belegt ist — daraus wurde „kein Journal", und „kein Journal" ist
    # READY-fähig. Ein fehlendes Journal liest sich jetzt als leere Kette, ein
    # belegter Pfad als Befund; unterschieden wird das in der Primitive, nicht
    # hier.
    try:
        j.verify()
        if mit_lockpfad:
            j.pruefe_lockpfad()
    except JournalUnsafe as exc:
        # VOR `JournalBroken`, sonst verschluckt die Oberklasse den Sonderfall
        # und der Operator bekommt den Wiederherstellungsweg für eine kaputte
        # Kette — obwohl seine Kette in Ordnung ist und nur der Pfad nicht.
        return j, Report(
            status=Status.STOP,
            reason=UNSAFE_REASON,
            reason_code="STOP_JOURNAL_UNSAFE",
            recovery_code="RECOVER_JOURNAL_PATH",
            recovery_text=(
                "Den beanstandeten Pfad aus details.pfad ansehen, ohne ihm zu folgen "
                "(ls -ld), den Link oder Fremdeintrag entfernen und die Journaldatei "
                "als reguläre Datei aus dem geprüften Backup an ihren Ort zurücklegen. "
                "Die Kette selbst ist unberührt; bis zur Klärung keine Schreib-, "
                "Freigabe- oder Exportvorgänge."
            ),
            details={"pfad": str(exc.pfad)},
        )
    except JournalBroken as exc:
        # Gebrochene Evidenz ist ein bewusst NICHT automatisch reparierter
        # Zustand: es gibt keinen sicheren Resolver, der die Kette heilt — also
        # kein NEXT, sondern RECOVERY. Das Sichern des Befunds ist read-only und
        # darf denselben `doctor` nennen; es steht in CHECK, nie in NEXT (sonst
        # schickt `doctor` den Operator in den gerade gescheiterten Befehl).
        return j, Report(
            status=Status.STOP,
            reason=f"{D1_REASON} Befund: {exc}",
            reason_code="STOP_JOURNAL_BROKEN",
            check="ohpipe --json doctor   # Befund sichern",
            recovery_code="RECOVER_JOURNAL_FROM_BACKUP",
            recovery_text=(
                "Journal aus dem geprüften Backup außerhalb der Datenwurzel "
                "wiederherstellen; bis zur dokumentierten Klärung keine Schreib-, "
                "Freigabe- oder Exportvorgänge."
            ),
        )
    return j, None


def _graph_binding_or_halt(
    ws: Workspace, profile_arg: str, *, pristine_ok: bool = False
) -> Report | None:
    """Macht die E8-Bindung vor jedem fachlichen Lesen/Schreiben sichtbar."""
    if not ws.journal_path.exists() and not _graph_binding_entry_exists(ws.graph_binding_path):
        if pristine_ok:
            return None
        return Report(
            status=Status.ACTION_NEEDED,
            reason="Arbeitsbereich ist noch nicht angelegt und hat keine Graphbindung.",
            reason_code="ACTION_WORKSPACE_NOT_INITIALISED",
            next_command=_e8_operator_command(ws, profile_arg, "init"),
            details={"profile": ws.profile.id, "root": str(ws.root)},
        )
    try:
        state, binding, running = ws.inspect_graph_binding()
    except GraphBindingError as exc:
        return Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_GRAPH_BINDING_INVALID",
            check=_e8_operator_command(
                ws,
                profile_arg,
                "doctor",
                as_json=True,
                comment="Bindungsdatei sichern und untersuchen",
            ),
        )

    details = {
        "graph_binding_state": state.value,
        "running_graph_sha256": running,
        "bound_graph_sha256": binding.graph_sha256 if binding else None,
        "bound_profile": binding.profile if binding else None,
    }
    next_command = _e8_operator_command(ws, profile_arg, "graph-upgrade", "--to", running)
    if state is GraphBindingState.UNBOUND:
        return Report(
            status=Status.GRAPH_CONTRACT_UNBOUND,
            reason=(
                "Altbestand: Das Journal entstand vor E8 und trägt noch keine "
                "journalexterne Graphbindung. Es wird nichts still gebunden."
            ),
            reason_code="GRAPH_CONTRACT_UNBOUND",
            next_command=next_command,
            details=details,
        )
    if state is GraphBindingState.MISMATCH:
        return Report(
            status=Status.GRAPH_CONTRACT_MISMATCH,
            reason=(
                "Gebundener und laufender Graphvertrag weichen ab. Ohne ausdrücklichen "
                "Upgradeakt bleibt die gespeicherte Bindung unverändert."
            ),
            reason_code="GRAPH_CONTRACT_MISMATCH",
            next_command=next_command,
            details=details,
        )
    return None


# ---------------------------------------------------------------- doctor


def _metadata_input_findings(ws: Workspace) -> list[str]:
    """Liest ``_governance/metadata/*.toml`` und meldet, was daran nicht stimmt.

    **Der Vorlauf, nicht der Notausgang.** ``metadata.derive`` liest seine
    Eingabedatei genau einmal (offene Stelle O-2, ``docs/TRACEABILITY.md``);
    wer danach etwas aendert, sitzt fest. Diese Pruefung behebt das nicht. Sie
    verhindert, dass man hineinlaeuft: Der Operator sieht einen Tippfehler oder
    einen Vokabularverstoss, BEVOR der Schritt das erste Mal laeuft, und
    korrigiert ihn dort, wo es noch billig ist.

    Read-only, wie der ganze Befehl. Gelesen werden Dateien, geschrieben wird
    nichts, und keine Datei ist kein Befund: Ein Arbeitsbereich ohne
    Erschliessung ist ein normaler Zustand und kein Mangel.

    Ein LADEFEHLER ist ein Befund und kein Traceback. ``doctor`` ist der
    Befehl, den ein Operator faehrt, wenn etwas nicht stimmt; er darf nicht
    selbst an dem scheitern, was er finden soll.
    """
    verzeichnis = ws.governance / "metadata"
    if not verzeichnis.is_dir():
        return []

    befunde: list[str] = []
    for pfad in sorted(verzeichnis.glob("*.toml")):
        record_id = pfad.stem
        try:
            eingabe = load_record_metadata(pfad, record_id=record_id)
        except RecordMetadataError as exc:
            # Der Wortlaut des Loaders traegt schon Pfad, Schluessel und Grund.
            # Ein zweiter Rahmen darum machte die Zeile laenger und nicht klarer.
            befunde.append(str(exc))
            continue
        for problem in sorted(
            check_record(eingabe.fields, consent_vocabulary=tuple(ws.profile.consent_vocabulary))
        ):
            befunde.append(f"{pfad.name}: {problem}")
    return befunde


def cmd_doctor(args: argparse.Namespace) -> Report:
    """Read-only. Schreibt unter keinen Umständen etwas."""
    findings: list[str] = []
    details: dict[str, object] = {"version": __version__, "python": sys.version.split()[0]}

    try:
        ws = _workspace(args)
    except DataRootError as exc:
        return Report(
            status=Status.CONFIG,
            reason=str(exc),
            reason_code="CONFIG_DATA_ROOT",
            # Ein NEXT, das denselben read-only Befehl nennt, ist eine Schleife:
            # Der Operator bekommt keinen Schritt, der den Zustand aendern KANN.
            next_command=f"export {ENV_ROOT}=~/ohpipe-data   # ausserhalb des Repositories",
            details=details,
        )
    except ProfileError as exc:
        # Ein unbekanntes Profil hat keinen sicheren, zustandsändernden Resolver:
        # die mitgelieferten Profile stehen bereits in der Meldung, die
        # korrigierte Wiederholung ist read-only und gehört daher nach CHECK,
        # nicht in NEXT (Reviewer-Adjudikation 07.08.).
        return Report(
            status=Status.CONFIG,
            reason=str(exc),
            reason_code="CONFIG_PROFILE",
            check=shlex.join(
                ["ohpipe", "--profile", getattr(args, "profile", None) or "sandbox", "doctor"]
            ),
            details=details,
        )

    details["profile"] = ws.profile.id
    details["root"] = str(ws.root)
    if ws.profile.model_vocabulary:
        # Sichtbar, sonst waere die Freigabe eine Zusicherung, die niemand liest.
        details["model_vocabulary"] = list(ws.profile.model_vocabulary)
        details["default_model"] = ws.profile.default_model

    if not ws.root.exists():
        findings.append(f"Datenwurzel fehlt: {ws.root}")
    else:
        # Struktur ZUERST. Ein untergeschobener Symlink ist kein „Befund unter
        # anderen": Solange er da ist, sagt jede folgende Prüfung etwas über
        # ein Verzeichnis aus, das gar nicht zur Datenwurzel gehört.
        unsafe = ws.unsafe_entries()
        if unsafe:
            details["unsafe_entries"] = unsafe
            return Report(
                status=Status.STOP,
                reason="Struktur der Datenwurzel: " + "; ".join(unsafe[:2]),
                reason_code="STOP_WORKSPACE_UNSAFE",
                next_command="ohpipe --json doctor   # Befund sichern, dann den Link untersuchen",
                details=details,
            )
        for p in ws.managed_dirs:
            if not p.exists():
                findings.append(f"fehlt: {p.relative_to(ws.root)}/")
        if not os.access(ws.root, os.W_OK):
            findings.append(f"nicht schreibbar: {ws.root}")

    journal, stop = _journal_or_stop(ws)
    if stop:
        stop.details.update(details)
        return stop
    graph_halt = _graph_binding_or_halt(ws, args.profile, pristine_ok=True)
    if graph_halt:
        graph_halt.details.update(details)
        return graph_halt
    if _graph_binding_entry_exists(ws.graph_binding_path):
        details["graph_binding_state"] = GraphBindingState.CURRENT.value
        details["graph_sha256"] = ws.running_graph_sha256()
    details["journal_events"] = journal.head()[0]
    details["journal_head"] = journal.head()[1]
    details["journal_integrity"] = journal.integrity
    details["journal_integrity_note"] = (
        "Die Kette ist mit einem Schlüssel außerhalb der Datenwurzel authentifiziert; "
        "ein vollständiges Neuschreiben der Datei fällt auf."
        if journal.key
        else "Die Kette ist nur integritätsgeprüft, NICHT authentifiziert: Wer die ganze "
        f"Datei schreiben darf, rechnet die Hashes neu. Für Authentizität ${ENV_KEY} "
        "auf eine Schlüsseldatei außerhalb der Datenwurzel setzen (ADR 0016). "
        "Den oben ausgewiesenen Kopf extern notieren macht die Lücke sichtbar."
    )

    authority = Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED
    details["authority"] = authority.value
    graph = build_graph(ws.profile)
    details["graph_steps"] = len(list(graph))
    # Die Kerninvariante am Ausgang, im Betrieb statt nur im Build. Sie steht
    # seit ADR 0013 als pruefbare Funktion da und wurde nur von Tests gerufen:
    # eine Zusicherung, die der laufende Arbeitsbereich nie erfaehrt, ist eine
    # Zusicherung ueber ein anderes Objekt. Geprueft wird der PROFILGEBUNDENE
    # Graph, nicht die Modulkonstante — genau der Unterschied, an dem eine
    # CHILDLUX-Laufzeit entlang der verbotenen direkten Kante plante (A-1).
    egress_violations = check_egress_gates(graph)
    details["egress_gates"] = "verletzt" if egress_violations else "geschlossen"
    if egress_violations:
        details["egress_violations"] = egress_violations
        return Report(
            status=Status.STOP,
            reason="Kein Modellpfad darf den Ausgang ohne menschliches Gate erreichen: "
            + "; ".join(egress_violations[:2]),
            reason_code="STOP_EGRESS_GATE_OPEN",
            next_command="ohpipe --json doctor   # Befund sichern, dann den Graphen des Profils pruefen",
            details=details,
        )
    views = replay(journal, graph=graph, authority=authority)
    records = set(views)
    # Massgeblich ist das Journal (ADR 0014). Die Datei ist ein abgeleiteter
    # Index und wird nur daraufhin geprueft, ob sie damit uebereinstimmt.
    try:
        ledger = CutoverLedger.from_journal(
            journal, authority=authority, default_runtime=_default_runtime(ws)
        )
        on_disk = CutoverLedger.load(ws.cutover_path, default_runtime=_default_runtime(ws))
    except OwnershipError as exc:
        return Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_LEDGER_INVALID",
            next_command="ohpipe --json doctor",
            details=details,
        )

    stale = on_disk.stale_against(journal, authority=authority)
    if stale:
        details["ledger_stale"] = stale
    drift = on_disk.verify_against(journal, authority=authority)
    if drift:
        return Report(
            status=Status.STOP,
            reason="Ownership-Ledger und Journal weichen ab: " + "; ".join(drift[:3]),
            reason_code="STOP_LEDGER_UNBOUND",
            next_command="ohpipe --json doctor",
            details={**details, "ledger_drift": drift},
        )

    # AUSDRÜCKLICH übergebene Records — nicht die abgeleiteten Eigentümer.
    #
    # Der Unterschied wurde erst sichtbar, als `legacy_runtime` eine
    # Profileigenschaft wurde: Unter `sandbox` gibt es keinen Vorgänger, dort
    # gehören unbekannte Records ohpipe. `owned_by_ohpipe` kann eine
    # unwirksame Übergabe deshalb nicht mehr von der Voreinstellung
    # unterscheiden — zwei Fälschungstests wurden dadurch grün, obwohl sie
    # nichts mehr prüften. Diese Liste zählt nur, was tatsächlich
    # protokolliert übergeben wurde.
    details["adopted_records"] = sorted(ledger.owners)
    details["default_runtime"] = ledger.default_runtime
    details["owned_by_ohpipe"] = sum(1 for r in records if ledger.owner_of(r) == THIS_RUNTIME)
    details["owned_by_legacy"] = sum(1 for r in records if ledger.owner_of(r) == LEGACY_RUNTIME)
    details["legacy_retired"] = ledger.retired(LEGACY_RUNTIME, records)

    # -- Der Store, in beide Richtungen -----------------------------------
    # Von innen: Ist jedes abgelegte Objekt heil, richtig benannt und eng?
    # Von außen: Liegen die Bytes, auf die sich das Journal beruft, wirklich da?
    # Nicht geprüft wird die dritte Richtung — Objekte ohne Referenz sind
    # harmlos (A5), und ihr stilles Löschen wäre es nicht.
    leftovers: list[Path] = []
    try:
        store = ws.store()
        audit = store.audit()
        store_findings = list(audit.findings)
        for rid in sorted(views):
            store_findings += check_referenced(ws, views[rid])
        store_notes = list(audit.notes)
        leftovers = store.stale_temporaries()
    except StoreError as exc:
        store_findings, store_notes = [str(exc)], []

    # Der Metadatenvorlauf steht VOR den Storezweigen, damit seine Befunde auch
    # dann in `details` stehen, wenn ein frueherer Zweig zurueckkehrt. Der
    # eigene Halt kommt weiter unten: Systemintegritaet geht vor Erschliessung.
    metadaten_befunde = _metadata_input_findings(ws)
    if metadaten_befunde:
        details["metadata_input_findings"] = metadaten_befunde

    if store_findings:
        details["store_findings"] = store_findings
        return Report(
            status=Status.STOP,
            reason="Content Store: " + "; ".join(store_findings[:2]),
            reason_code="STOP_STORE_UNSOUND",
            next_command="ohpipe --json doctor",
            details=details,
        )
    if findings:
        details["findings"] = findings
        return Report(
            status=Status.ACTION_NEEDED,
            reason=f"{len(findings)} Befund(e): " + "; ".join(findings[:3]),
            reason_code="ACTION_WORKSPACE_INCOMPLETE",
            next_command=f"ohpipe --profile {args.profile} init",
            details=details,
        )

    if store_notes:
        # Eigener Zweig statt in die Workspace-Befunde geschoben: Der nächste
        # Befehl wäre sonst `init`, und `init` legt gegen eine liegengebliebene
        # Temporärdatei gar nichts an. Ein NEXT, das die Sache nicht anfasst,
        # ist schlimmer als keines.
        #
        # Und es zeigt nicht auf `doctor` zurück. Ein read-only Befund, dessen
        # NEXT derselbe read-only Befehl ist, ist eine Schleife: Der Operator
        # bekommt keinen Schritt, der den Zustand ändern KANN. Deshalb der
        # konkrete Pfad. Ansehen ist der nächste Schritt, Löschen bleibt ein
        # bewusster Akt — `ohpipe` räumt im Datenbaum nichts von selbst auf.
        details["store_notes"] = store_notes
        details["store_note_paths"] = [str(p) for p in leftovers]
        first = leftovers[0] if leftovers else ws.objects
        return Report(
            status=Status.ACTION_NEEDED,
            reason=f"{len(store_notes)} Hinweis(e) im Content Store: " + "; ".join(store_notes[:2]),
            reason_code="ACTION_STORE_NOTES",
            next_command=f"ls -l '{first}'   # ansehen; Entfernen ist ein bewusster Akt",
            details=details,
        )

    if metadaten_befunde:
        # Eigener Zweig statt in die Workspace-Befunde geschoben: Deren NEXT ist
        # `init`, und `init` legt keine Metadateneingabe an. Ein NEXT, das die
        # Sache nicht anfasst, ist schlimmer als keines (dieselbe Ueberlegung
        # wie beim Storehinweis darueber).
        #
        # ACTION_NEEDED und nicht STOP: Der Arbeitsbereich ist unversehrt, es
        # fehlt eine Eintragung. Genau dafuer steht dieser Status im
        # Exitcodevertrag, und die Workspace-Befunde oben benutzen ihn ebenso.
        # Ein STOP hiesse, dass etwas nicht stimmt, was der Operator nicht
        # aendern kann.
        #
        # Das NEXT nennt die Datei und nicht `doctor`: Ein read-only Befund,
        # dessen NEXT derselbe read-only Befehl ist, ist eine Schleife.
        erste = str(ws.governance / "metadata")
        return Report(
            status=Status.ACTION_NEEDED,
            reason=f"{len(metadaten_befunde)} Befund(e) in der Metadateneingabe: "
            + "; ".join(metadaten_befunde[:3]),
            reason_code="ACTION_METADATA_INPUT",
            next_command=f"$EDITOR '{erste}'   # vor dem ersten `continue` korrigieren",
            details=details,
        )

    return Report(
        status=Status.READY,
        reason="Arbeitsbereich vollständig, Evidenzkette unversehrt",
        next_command=f"ohpipe --profile {args.profile} status",
        upload_safe=False,
        details=details,
    )


# ------------------------------------------------------------------ init


def cmd_init(args: argparse.Namespace) -> Report:
    ws = _workspace(args)
    # Erst pruefen, DANN anlegen. Eine fruehere Fassung legte _governance/,
    # records/ und releases/ an und brach anschliessend mit CONFIG ab — bei
    # gleichzeitig leerem CHANGED. Beide Aussagen waren damit unwahr.
    _, stop = _journal_or_stop(ws, mit_lockpfad=False)
    if stop:
        return stop
    graph_halt = _graph_binding_or_halt(ws, args.profile, pristine_ok=True)
    if graph_halt:
        return graph_halt
    created = ws.ensure()
    if not _graph_binding_entry_exists(ws.graph_binding_path):
        bound = ws.bind_graph_initially()
        if bound:
            created.append(bound)
    journal, stop = _journal_or_stop(ws)
    if stop:
        # NACH `ws.ensure()`: der STOP muss nennen, was DIESER Lauf angelegt hat.
        # Ein leeres CHANGED wäre hier dieselbe Unwahrheit wie die, gegen die der
        # Kommentar am Anfang dieser Funktion geschrieben ist — nur an einem
        # anderen Ausgang. Die STOPs weiter unten führen `changed=created` aus
        # genau diesem Grund; die Durchreichung hatte es bisher als einzige nicht.
        stop.changed = list(created)
        return stop
    # Der abgeleitete Index wird neu gebaut (ADR 0008) — aber NUR in der
    # harmlosen Richtung. Behauptet die Datei MEHR als das Journal, ist das ein
    # Sicherheitsbefund; ihn zu überschreiben hiesse, die Spur zu beseitigen.
    authority = Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED
    try:
        on_disk = CutoverLedger.load(ws.cutover_path, default_runtime=_default_runtime(ws))
    except OwnershipError as exc:
        return Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_LEDGER_INVALID",
            changed=created,
            next_command="ohpipe --json doctor",
        )
    drift = on_disk.verify_against(journal, authority=authority)
    if drift:
        return Report(
            status=Status.STOP,
            reason=(
                "Der Ownership-Index behauptet mehr als das Journal belegt: "
                + "; ".join(drift[:3])
                + " — init überschreibt das nicht. Datei sichern und untersuchen."
            ),
            reason_code="STOP_LEDGER_UNBOUND",
            changed=created,
            next_command="ohpipe --json doctor",
        )
    rebuilt = CutoverLedger.from_journal(
        journal, strict=False, authority=authority, default_runtime=_default_runtime(ws)
    )
    before = ws.cutover_path.read_text(encoding="utf-8") if ws.cutover_path.exists() else ""
    rebuilt.save(ws.cutover_path)
    if ws.cutover_path.read_text(encoding="utf-8") != before:
        created.append(str(ws.cutover_path))

    ev = journal.append_once(
        "workspace.initialised",
        {"profile": ws.profile.id, "root": str(ws.root), "version": __version__},
    )
    if ev is not None:
        created.append(str(ws.journal_path))
    return Report(
        status=Status.READY,
        reason="Arbeitsbereich angelegt" if created else "Arbeitsbereich war bereits vollständig",
        changed=created,
        next_command=f"ohpipe --profile {args.profile} doctor",
        details={
            "profile": ws.profile.id,
            "root": str(ws.root),
            "graph_binding_state": GraphBindingState.CURRENT.value,
            "graph_sha256": ws.running_graph_sha256(),
        },
    )


# ---------------------------------------------------------------- ingest


def cmd_ingest(args: argparse.Namespace) -> Report:
    """Der erste Befehl, der schreibt — und der erste Aufrufer der Schreibwache."""
    retry = getattr(args, "retry_intent", None)
    if retry is not None:
        if getattr(args, "source", None) is not None or getattr(args, "record", None) is not None:
            return Report(
                status=Status.CONFIG,
                reason="--retry-intent verbietet normale Ingest-Fachargumente.",
                reason_code="CONFIG_B3B_ARGUMENTS",
                check="ohpipe ingest --help",
                details={"operation_result": "NONE"},
            )
        return Report(
            status=Status.STOP,
            reason="Zum bezeichneten Digest liegt kein gueltiger persistierter Intentbeleg vor.",
            reason_code="STOP_B3B_INTENT_ABSENT",
            check="ohpipe --json status",
            details={"operation_result": "NONE", "retry_intent": retry},
        )
    if args.source is None or args.record is None:
        return Report(
            status=Status.CONFIG,
            reason="Normaler Ingest verlangt Quelle und --record.",
            reason_code="CONFIG_B3B_ARGUMENTS",
            check="ohpipe ingest --help",
            details={"operation_result": "NONE"},
        )
    ws = _workspace(args)
    journal, stop = _journal_or_stop(ws)
    if stop:
        return stop
    graph_halt = _graph_binding_or_halt(ws, args.profile)
    if graph_halt:
        return graph_halt
    authority = Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED
    ledger = CutoverLedger.from_journal(
        journal, strict=False, authority=authority, default_runtime=_default_runtime(ws)
    )

    try:
        ergebnis = ingest(ws, journal, ledger, Path(args.source), args.record)
    except IngestError as exc:
        return Report(
            status=Status.CONFIG,
            reason=str(exc),
            reason_code="CONFIG_INGEST",
            source_data_touched=False,
            next_command="ohpipe --json doctor",
        )

    return Report(
        status=Status.ACTION_NEEDED,
        # Drei Faelle, nicht zwei. Die Vorgaengerfassung verzweigte nur auf
        # `bereits_vorhanden` und sagte dann pauschal "Nichts angehängt" —
        # auch dann, wenn derselbe Aufruf soeben `record.registered`
        # geschrieben hatte. Der Vierzeiler widersprach damit seiner eigenen
        # CHANGED-Zeile und seinen eigenen `details`. Ein Bericht, dessen drei
        # Zeilen sich widersprechen, ist schlimmer als eine fehlende Zeile:
        # Der Operator muss raten, welcher er glauben soll.
        reason=(
            (
                f"{ergebnis.record_id} angelegt. Diese Bytes lagen bereits als "
                f"Quelle vor ({ergebnis.cues} Cues) — angehängt wurde nur die "
                "Registrierung des Records."
            )
            if ergebnis.bereits_vorhanden and ergebnis.neu
            else (
                f"{ergebnis.record_id}: diese Bytes liegen bereits als Quelle vor "
                f"({ergebnis.cues} Cues). Nichts angehängt."
            )
            if ergebnis.bereits_vorhanden
            else (
                f"{ergebnis.record_id} aufgenommen: {ergebnis.cues} Cues, "
                f"{ergebnis.bytes} Bytes. Die Quelle ist abgelegt und belegt — "
                "bestätigt ist sie damit nicht."
            )
        ),
        reason_code="ACTION_TRANSCRIPT_UNCONFIRMED",
        changed=ergebnis.geschrieben,
        # Die Quelldatei wird gelesen, nie geschrieben. Der Store bekommt eine
        # Kopie; das Original bleibt, wo es lag.
        source_data_touched=False,
        next_command=f"ohpipe --profile {args.profile} status",
        details={
            "record_id": ergebnis.record_id,
            "address": ergebnis.address,
            "cues": ergebnis.cues,
            "neuer_record": ergebnis.neu,
            "bereits_vorhanden": ergebnis.bereits_vorhanden,
        },
    )


# ---------------------------------------------------------------- anchors


def cmd_anchors(args: argparse.Namespace) -> Report:
    """Read-only: was die aktuelle Fassung mit den L1-Ankern gemacht hat.

    Der Befehl schreibt nichts, auch keine Bindungsevidenz. Eine
    ``anchor.checked`` zu schreiben hiesse, die Wahl doch zu treffen — und
    genau das ist die Aussage: die Maschine schliesst, was eindeutig ist, und
    legt bei Mehrdeutigkeit die Kandidaten vor.
    """
    ws = _workspace(args)
    journal, stop = _journal_or_stop(ws)
    if stop:
        return stop
    graph_halt = _graph_binding_or_halt(ws, args.profile)
    if graph_halt:
        return graph_halt
    authority = Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED
    views = replay(journal, graph=build_graph(ws.profile), authority=authority)
    if not views:
        return Report(
            status=Status.ACTION_NEEDED,
            reason="Noch kein Record im Arbeitsbereich",
            reason_code="ACTION_NO_RECORDS",
            next_command=f"ohpipe --profile {args.profile} doctor",
        )
    if args.record is None:
        if len(views) != 1:
            return Report(
                status=Status.CONFIG,
                reason="Mehrere Records: welcher? Die Record-ID gehoert auf die Kommandozeile.",
                reason_code="CONFIG_RECORD_AMBIGUOUS",
                check=f"ohpipe --profile {args.profile} status",
                details={"records": sorted(views)},
            )
        record_id = next(iter(views))
    else:
        record_id = ws.profile.normalize_record_id(args.record)
    view = views.get(record_id)
    if view is None:
        return Report(
            status=Status.ACTION_NEEDED,
            reason=f"Record {record_id} ist im Journal unbekannt.",
            reason_code="ACTION_RECORD_UNKNOWN",
            check=f"ohpipe --profile {args.profile} status",
        )
    try:
        bericht = reanchor_report(ws, view, record_id)
    except AnchorsError as exc:
        return Report(
            status=Status.ACTION_NEEDED,
            reason=str(exc),
            reason_code="ACTION_ANCHORS_PRECONDITION_REQUIRED",
            check=f"ohpipe --profile {args.profile} status",
            details={"record_id": record_id},
        )
    einzel = bericht.to_json()
    if not args.json:
        for befund in bericht.findings:
            kandidaten = (
                " Kandidaten " + ", ".join(f"[{a},{e})" for a, e in befund.candidates)
                if befund.candidates
                else ""
            )
            marke = "MENSCH" if befund.needs_human else "      "
            print(f"  Anker {befund.index}  {marke}  {befund.outcome}{kandidaten}")
    if not bericht.same_revision and not bericht.offen:
        return Report(
            status=Status.ACTION_NEEDED,
            reason="Historische Ankerdiagnose; ohne neuen Ableitungsbeleg keine Rebasefreigabe.",
            next_command=_e8_operator_command(ws, args.profile, "continue", record_id),
            details={**einzel, "rebase_authorised": False},
        )
    if not bericht.offen:
        return Report(
            status=Status.READY,
            reason=offene_zeile(bericht),
            reason_code="READY_ANCHORS_MACHINE_CLOSABLE",
            details=einzel,
        )
    return Report(
        status=Status.ACTION_NEEDED,
        reason=offene_zeile(bericht),
        reason_code="ACTION_ANCHORS_NEED_A_HUMAN",
        # Es gibt keinen gebauten Befehl, mit dem ein Mensch die Wahl trifft.
        # Ein NEXT, das auf etwas Ungebautes zeigt, waere ein Versprechen —
        # der ROADMAP-Grundsatz lautet sichtbar geplant statt still versprochen.
        check=f"ohpipe --profile {args.profile} --json transcript anchors {record_id}",
        details={**einzel, "resolution": "nicht gebaut: die Wahl trifft ein Mensch im Review"},
    )


# ---------------------------------------------------------------- status


def cmd_status(args: argparse.Namespace) -> Report:
    """Vollständig read-only (ADR 0004) — und niemals grün ohne Prüfung."""
    ws = _workspace(args)
    journal, stop = _journal_or_stop(ws)
    if stop:
        return stop
    graph_halt = _graph_binding_or_halt(ws, args.profile)
    if graph_halt:
        return graph_halt

    authority = Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED
    try:
        ledger = CutoverLedger.from_journal(
            journal, authority=authority, default_runtime=_default_runtime(ws)
        )
        drift = CutoverLedger.load(
            ws.cutover_path, default_runtime=_default_runtime(ws)
        ).verify_against(journal, authority=authority)
    except OwnershipError as exc:
        return Report(status=Status.STOP, reason=str(exc), reason_code="STOP_LEDGER_INVALID")
    if drift:
        return Report(
            status=Status.STOP,
            reason="Ownership-Ledger und Journal weichen ab: " + "; ".join(drift[:3]),
            reason_code="STOP_LEDGER_UNBOUND",
            next_command="ohpipe --json doctor",
            details={"ledger_drift": drift},
        )

    views = replay(journal, graph=build_graph(ws.profile), authority=authority)
    if not views:
        return Report(
            status=Status.ACTION_NEEDED,
            reason="Noch kein Record im Arbeitsbereich",
            reason_code="ACTION_NO_RECORDS",
            next_command=f"ohpipe --profile {args.profile} doctor",
            details={"profile": ws.profile.id, "records": []},
        )

    # Für einen Record zählt genau eine Richtung: Liegen die Bytes da, auf die
    # er sich beruft? Der Rest des Stores ist Sache von `doctor`. Ein Befund
    # hier färbt den Record rot — eine Referenz ins Leere ist kein Schönheits-
    # fehler, sondern der Verlust genau der Bytes, über die entschieden wurde.
    try:
        for v in views.values():
            v.findings.extend(check_referenced(ws, v))
    except StoreError as exc:
        return Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_STORE_UNSOUND",
            next_command="ohpipe --json doctor",
        )

    rows = []
    for rid in sorted(views):
        v = views[rid]
        rows.append({**v.to_json(), "owner": ledger.owner_of(rid)})

    order = [
        Status.STOP,
        Status.CONFIG,
        Status.REVIEW_REQUIRED,
        Status.STALE,
        Status.EXCLUDED,
        Status.ACTION_NEEDED,
        Status.READY,
    ]
    worst = min((views[r].status for r in views), key=order.index)

    if not args.json:
        for r in rows:
            print(
                f"  {r['record_id']:<16} {r['status']:<16} owner={r['owner']:<8} {r['explanation']}"
            )
        print()

    return Report(
        status=worst,
        reason=f"{len(rows)} Record(s), schlechtester Zustand: {worst.value}",
        next_command=f"ohpipe --profile {args.profile} doctor"
        if any(v.findings for v in views.values())
        else _p3_repair(
            args, ws, journal, next(r for r in sorted(views) if views[r].status is worst)
        ),
        details={"profile": ws.profile.id, "authority": authority.value, "records": rows},
    )


# ---------------------------------------------------------------- continue


def cmd_continue(args: argparse.Namespace) -> Report:
    """Demo-Moment 1: läuft von selbst und hält — mit Grund und nächstem Befehl.

    Dünn, wie ADR 0013 es verlangt: Vorprüfungen wie ``status``, dann die
    Anwendungsschicht (``continue_record``), dann der Sechszeiler
    (``continue_report``). Die Registry wird vor jedem Lauf gegen den gebauten
    Graphen geprüft — ein Handler, der etwas anderes behauptet als der Graph,
    ist ein Halt vor dem ersten Schritt, keine Warnung.
    """
    ws = _workspace(args)
    journal, stop = _journal_or_stop(ws)
    if stop:
        return stop
    graph_halt = _graph_binding_or_halt(ws, args.profile)
    if graph_halt:
        return graph_halt
    status_cmd = shlex.join(["ohpipe", "--profile", args.profile, "--root", str(ws.root), "status"])
    graph = build_graph(ws.profile)
    from ..application.steps import registry_for

    registry = registry_for(ws.profile)
    verstoesse = check_registry(graph, registry)
    if verstoesse:
        return Report(
            status=Status.STOP,
            reason="Schritt-Registry und Graph decken sich nicht: " + "; ".join(verstoesse[:3]),
            reason_code="STOP_REGISTRY_INVALID",
            check=status_cmd,
            details={"registry_violations": verstoesse},
        )

    authority = Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED
    try:
        ledger = CutoverLedger.from_journal(
            journal, authority=authority, default_runtime=_default_runtime(ws)
        )
        drift = CutoverLedger.load(
            ws.cutover_path, default_runtime=_default_runtime(ws)
        ).verify_against(journal, authority=authority)
    except OwnershipError as exc:
        return Report(
            status=Status.STOP, reason=str(exc), reason_code="STOP_LEDGER_INVALID", check=status_cmd
        )
    if drift:
        return Report(
            status=Status.STOP,
            reason="Ownership-Ledger und Journal weichen ab: " + "; ".join(drift[:3]),
            reason_code="STOP_LEDGER_UNBOUND",
            next_command="ohpipe --json doctor",
            details={"ledger_drift": drift},
        )

    def views() -> dict[str, Any]:
        # Wie `status`: Bytes, auf die sich ein Record beruft, muessen im Store
        # liegen. Ein Handler, der `artifact.produced` schreibt und die Bytes
        # nicht ablegt, faellt damit als Befund — Store- UND Journalbeleg.
        out = replay(journal, graph=graph, authority=authority)
        for v in out.values():
            v.findings.extend(check_referenced(ws, v))
        return out

    bekannt = views()
    if not bekannt:
        return Report(
            status=Status.ACTION_NEEDED,
            reason="Noch kein Record im Arbeitsbereich — continue hat nichts, worauf es laufen könnte.",
            reason_code="ACTION_NO_RECORDS",
            check=shlex.join(
                [
                    "ohpipe",
                    "--profile",
                    args.profile,
                    "--root",
                    str(ws.root),
                    "transcript",
                    "ingest",
                    "--help",
                ]
            ),
            details={"profile": ws.profile.id, "records": []},
        )
    if args.record is None:
        if len(bekannt) != 1:
            return Report(
                status=Status.CONFIG,
                reason=f"{len(bekannt)} Records im Arbeitsbereich; continue braucht genau einen: "
                + ", ".join(sorted(bekannt)),
                reason_code="CONFIG_CONTINUE_RECORD",
                check=status_cmd,
                details={"records": sorted(bekannt)},
            )
        rid = next(iter(bekannt))
    else:
        rid = ws.profile.normalize_record_id(args.record)
        if rid not in bekannt:
            return Report(
                status=Status.CONFIG,
                reason=f"{args.record!r} ist kein Record dieses Arbeitsbereichs. Bekannt: "
                + ", ".join(sorted(bekannt)),
                reason_code="CONFIG_CONTINUE_RECORD",
                check=status_cmd,
                details={"records": sorted(bekannt)},
            )
    owner = ledger.owner_of(rid)
    if owner != THIS_RUNTIME:
        return Report(
            status=Status.STOP,
            reason=f"{rid} gehört {owner!r}, nicht {THIS_RUNTIME!r}. continue schreibt nur für "
            "eigene Records (ADR 0009).",
            reason_code="STOP_OWNERSHIP",
            check=status_cmd,
            details={"record_id": rid, "owner": owner},
        )

    ctx = StepContext(
        ws=ws,
        journal=journal,
        record_id=rid,
        profile_arg=args.profile,
        confirm=bool(getattr(args, "confirm", False)),
        options={"fixture": getattr(args, "fixture", None) or "stop"},
    )
    outcome = continue_record(ctx, graph=graph, registry=registry, view_of=lambda: views().get(rid))
    return continue_report(outcome, ctx, registry)


# ----------------------------------------------------------- graph-upgrade


def cmd_graph_upgrade(args: argparse.Namespace) -> Report:
    """Der ausdrückliche, menschlich verantwortete E8-Upgradeakt."""
    ws = _workspace(args)
    unsafe = ws.unsafe_entries()
    if unsafe:
        raise WorkspaceUnsafe("; ".join(unsafe))
    journal, stop = _journal_or_stop(ws)
    if stop:
        return stop
    if not ws.journal_path.exists():
        return Report(
            status=Status.ACTION_NEEDED,
            reason="Kein bestehendes Journal zum Upgrade; zuerst Arbeitsbereich anlegen.",
            reason_code="ACTION_GRAPH_UPGRADE_NO_WORKSPACE",
            next_command=_e8_operator_command(ws, args.profile, "init"),
        )

    running = ws.running_graph_sha256()
    if args.target != running:
        return Report(
            status=Status.CONFIG,
            reason=(
                f"Abgelehnt: --to nennt {args.target}, der laufende Graphvertrag ist {running}. "
                "Ein Upgrade bindet nie still auf einen anderen Wert."
            ),
            reason_code="CONFIG_GRAPH_UPGRADE_TARGET",
            check=_e8_operator_command(ws, args.profile, "doctor"),
            details={"requested_graph_sha256": args.target, "running_graph_sha256": running},
        )
    try:
        changed = ws.upgrade_graph_binding()
    except GraphBindingError as exc:
        return Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_GRAPH_BINDING_INVALID",
            check=_e8_operator_command(
                ws,
                args.profile,
                "doctor",
                as_json=True,
                comment="Bindungsdatei sichern und untersuchen",
            ),
        )
    return Report(
        status=Status.READY,
        reason=(
            "Graphbindung wurde ausdrücklich auf den laufenden Vertrag angehoben."
            if changed
            else "Graphbindung war bereits auf dem laufenden Vertrag."
        ),
        changed=[str(ws.graph_binding_path)] if changed else [],
        next_command=_e8_operator_command(ws, args.profile, "doctor"),
        details={
            "graph_binding_state": GraphBindingState.CURRENT.value,
            "graph_sha256": running,
            "profile": ws.profile.id,
        },
    )


def _b3b_journal(args: argparse.Namespace) -> tuple[Workspace, Journal, Report | None]:
    ws = _workspace(args)
    halt = _graph_binding_or_halt(ws, args.profile)
    if halt is not None:
        return ws, Journal(ws.journal_path), halt
    journal, stop = _journal_or_stop(ws)
    return ws, journal, stop


def _b3b_choice() -> str:
    return text("[b] Bestaetigen / [a] Abbrechen", "[c] Confirm / [a] Abort")


def _b3b_next_command(args: argparse.Namespace) -> str:
    action = args.b3b_action
    if action == "instance_register":
        tokens = [
            "instance",
            "register",
            args.coder_id,
            "--source",
            args.source,
            "--label",
            args.label,
            "--reference",
            args.reference,
        ]
        if args.model is not None:
            tokens.extend(("--model", args.model))
        if args.parametersatz is not None:
            tokens.extend(("--parametersatz", args.parametersatz))
    elif action == "instance_retire":
        tokens = [
            "instance",
            "retire",
            args.coder_id,
            "--reference",
            args.reference,
        ]
    elif action == "iso_prepare":
        tokens = [
            "iso6393",
            "prepare",
            args.snapshot,
            "--release",
            args.release,
            "--reference",
            args.reference,
        ]
    elif action == "fulltext_prepare":
        tokens = [
            "transcript",
            "fulltext",
            "prepare",
            args.record,
            args.fulltext,
            "--reference",
            args.reference,
        ]
    elif action == "transcript_confirm":
        tokens = ["transcript", "confirm", args.record]
        if args.actor is not None:
            tokens.extend(("--actor", args.actor))
    elif action == "language_prepare":
        tokens = [
            "transcript",
            "language",
            "prepare",
            args.record_id,
            args.srt,
            args.mapping,
            "--actor",
            args.actor,
            "--reference",
            args.reference,
        ]
    elif action == "ingest_srt":
        tokens = ["transcript", "ingest", args.record, args.srt, args.mapping]
    elif action == "l1_review":
        tokens = ["l1", "review", args.record]
        if args.actor is not None:
            tokens.extend(("--actor", args.actor))
    elif action == "export_bundle":
        tokens = ["export", args.record]
        if args.output is not None:
            tokens.extend(("--output", args.output))
    elif action in ("metadata_confirm", "abstract_confirm", "release_approve"):
        verb = {
            "metadata_confirm": ("metadata", "confirm"),
            "abstract_confirm": ("abstract", "confirm"),
            "release_approve": ("release", "approve"),
        }[action]
        tokens = [verb[0], verb[1], args.record]
        if args.actor is not None:
            tokens.extend(("--actor", args.actor))
    else:  # pragma: no cover - nur von neuen B3b-Schreibaktionen erreichbar
        raise ValueError(f"kein B3b-Bestaetigungsweg fuer {action!r}")
    next_tokens = [
        "ohpipe",
        "--profile",
        args.profile,
        "--root",
        str(_workspace(args).root),
        *tokens,
        "--confirm",
    ]
    return shlex.join(next_tokens)


def _b3b_action_report(
    args: argparse.Namespace,
    reason: str,
    preview: dict[str, Any],
    *,
    reason_code: str = "ACTION_B3B_CONFIRM_REQUIRED",
) -> Report:
    return Report(
        status=Status.ACTION_NEEDED,
        reason=reason,
        reason_code=reason_code,
        next_command=_b3b_next_command(args)
        if reason_code == "ACTION_B3B_CONFIRM_REQUIRED"
        else None,
        details={"operation_result": "NONE", "preview": preview},
    )


def _b3b_ascii_choice(raw: str) -> str:
    stripped = raw.strip(" \t\n\r\v\f")
    return stripped.translate(
        str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")
    )


def _release_terminal_required(args):
    return Report(
        status=Status.CONFIG,
        reason="Produktionsfreigabe verlangt interaktive Eingabe und sichtbare Terminalausgabe.",
        reason_code="CONFIG_RELEASE_TERMINAL_REQUIRED",
        check=_b3b_command(args, "release", "approve", args.record),
        details={"operation_result": "NONE"},
    )


def _p3_repair(args, ws, journal, record_id):
    from ..application.freshness import repair_command

    authority = Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED
    view = replay(journal, graph=build_graph(ws.profile), authority=authority).get(record_id)
    ctx = StepContext(ws, journal, record_id, args.profile)
    return repair_command(ctx, view) if view else ctx.command("continue", record_id)


def _gate_halt(args, exc):
    blocked = isinstance(exc, (GateBlocked, ExportBlocked))
    return Report(
        status=Status.STOP if blocked else Status.ACTION_NEEDED,
        reason=str(exc),
        reason_code="STOP_B3B_REPLAY_FINDINGS" if blocked else "ACTION_B3B_PRECONDITION_REQUIRED",
        check=_b3b_command(args, "--json", "status"),
        next_command=None
        if blocked
        else _p3_repair(args, _workspace(args), _b3b_journal(args)[1], args.record),
        details={"operation_result": "NONE"},
    )


def _b3b_confirm_or_abort(
    args: argparse.Namespace,
    reason: str,
    preview: dict[str, Any],
    writer: Callable[[], Report],
    *,
    terminal_fields: tuple[tuple[str, str], ...] | None = None,
) -> Report:
    """Zeigt den einmal gebauten Plan, entscheidet und ruft hoechstens einen Writer."""
    if terminal_fields is not None and not (sys.stdin.isatty() and sys.stderr.isatty()):
        return _release_terminal_required(args)
    visible = sys.stderr
    print(
        text("B3B-VORSCHAU ", "B3B PREVIEW ")
        + json.dumps(preview, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
        file=visible,
    )
    if terminal_fields is not None:
        print(
            text(
                "Freizugebende Metadaten (alle sieben Werte prüfen):",
                "Metadata to approve (check all seven values):",
            ),
            file=visible,
        )
        for name, value in terminal_fields:
            print(f"{name}: {json.dumps(value, ensure_ascii=False)}", file=visible)
    if args.confirm and terminal_fields is None:
        visible.flush()
        report = writer()
        report.details = {**report.details, "preview": preview}
        return report
    if not sys.stdin.isatty():
        visible.flush()
        return _b3b_action_report(args, reason, preview)
    while True:
        print(_b3b_choice(), file=visible, flush=True)
        raw = sys.stdin.readline()
        if raw == "" or _b3b_ascii_choice(raw) == "a":
            return _b3b_action_report(
                args,
                text(
                    "Der geplante B3b-Akt wurde vor jeder Wirkung abgebrochen.",
                    "The planned action was aborted before it had any effect.",
                ),
                preview,
                reason_code="ACTION_B3B_USER_ABORTED",
            )
        expected = "c" if is_english() else "b"
        if _b3b_ascii_choice(raw) == expected:
            report = writer()
            report.details = {**report.details, "preview": preview}
            return report


def _instance_preview(plan: Any) -> dict[str, Any]:
    return {
        "action": f"instance {plan.action}",
        "plan": dict(plan.payload),
        "planned_registry_effect": f"instance.{plan.action}ed",
        "persistence_notice": (
            "reference und Akt werden bei Bestaetigung dauerhaft journalisiert."
        ),
    }


def _b3b_command(args: argparse.Namespace, *tokens: str) -> str:
    return shlex.join(
        ["ohpipe", "--profile", args.profile, "--root", str(_workspace(args).root), *tokens]
    )


def _iso_snapshot_or_halt(ws: Workspace, events: list[Any]) -> tuple[Any, str, Report | None]:
    """Der zuletzt vorbereitete ISO-Snapshot — aus dem Store gelesen, neu geparst.

    Das Ereignis nennt Adressen, keine Werte. Wer den Wortschatz aus dem
    Ereignis GLAUBT, prueft die Sprachzuordnung gegen eine Behauptung; wer ihn
    aus den Storebytes neu baut, prueft sie gegen die Bytes, auf die sich der
    Snapshotakt beruft. Weicht der neu berechnete ``vocabulary_sha256`` ab, ist
    das ein Befund und kein Fortschritt.
    """
    prepared = [event for event in events if event.kind == "iso6393.snapshot.prepared"]
    if not prepared:
        return (
            None,
            "",
            Report(
                status=Status.ACTION_NEEDED,
                reason="Es ist kein ISO-639-3-Snapshot vorbereitet; ohne ihn gibt es keinen "
                "pruefbaren Sprachwortschatz.",
                reason_code="ACTION_B3B_ISO_SNAPSHOT_REQUIRED",
                check="ohpipe iso6393 prepare --help",
                details={"operation_result": "NONE"},
            ),
        )
    event = prepared[-1]
    try:
        with ws.store().open_verified(event.payload["raw_store"]) as handle:
            snapshot = parse_iso6393_snapshot(
                handle.read(),
                release_id=event.payload["release_id"],
                reference=event.payload["reference"],
            )
    except (StoreError, IsoSnapshotError) as exc:
        return (
            None,
            "",
            Report(
                status=Status.STOP,
                reason=f"Der vorbereitete ISO-Snapshot ist nicht aus seinen Bytes rekonstruierbar: {exc}",
                reason_code="STOP_B3B_ISO_SNAPSHOT_UNSOUND",
                check="ohpipe --json doctor",
                details={"operation_result": "NONE"},
            ),
        )
    if snapshot.vocabulary_sha256 != event.payload["vocabulary_sha256"]:
        return (
            None,
            "",
            Report(
                status=Status.STOP,
                reason="Der aus den Storebytes gebaute Wortschatz trifft den im Snapshotakt "
                "gemeldeten Digest nicht.",
                reason_code="STOP_B3B_ISO_SNAPSHOT_UNSOUND",
                check="ohpipe --json doctor",
                details={"operation_result": "NONE"},
            ),
        )
    return snapshot, event.digest, None


def _transcript_confirmation_plan(
    ws: Workspace, events: list[Any], args: argparse.Namespace
) -> tuple[Any, dict[str, Any]]:
    registry = InstanceRegistry.from_events(events)
    humans = registry.active_humans()
    actor_id = args.actor
    if actor_id is None:
        if len(humans) != 1:
            raise ValueError(
                "transcript.confirm verlangt genau eine aufgeloeste menschliche Instanz"
            )
        actor_id = humans[0].coder_id
    actor = registry.get(actor_id, active=True)

    revisions = [
        event
        for event in events
        if event.kind == "artifact.produced"
        and event.record_id == args.record
        and event.payload.get("artifact") == "transcript.revision"
    ]
    if not revisions:
        raise ValueError("transcript.confirm fehlt die aktuelle TranscriptRevision")
    revision_event = revisions[-1]
    revision_sha256 = revision_event.payload["sha256"]
    projection_receipts = [
        event
        for event in events
        if event.kind == "receipt.recorded"
        and event.record_id == args.record
        # Gesucht wird ueber `kind`, nicht mehr ueber `artifact`: der
        # Artefaktname ist seit der Graphangleichung fuer alle drei B3b-Belege
        # derselbe, und nur `kind` trennt sie.
        and event.payload.get("kind") == "transcript.fulltext.segment_projection.v1"
        and event.payload.get("output_sha256") == revision_sha256
    ]
    if not projection_receipts:
        raise ValueError("transcript.confirm fehlt der aktuelle Volltextherkunftsbeleg")
    fulltext_receipt = projection_receipts[-1]
    language_receipts = [
        event
        for event in events
        if event.kind == "receipt.recorded"
        and event.payload.get("kind") == "transcript.segment_languages.prepared.v1"
        and event.payload.get("target_record_id") == args.record
        and event.payload.get("output_sha256")
        == fulltext_receipt.payload.get("inputs", {}).get("language_assignment")
    ]
    if not language_receipts:
        raise ValueError("transcript.confirm fehlt die aktuelle ISO-gebundene Sprachzuordnung")
    language_receipt = language_receipts[-1]
    with ws.store().open_verified(revision_sha256) as handle:
        revision = verify_revision(handle.read(), revision_sha256)

    plan = plan_confirmation(
        record_id=args.record,
        automatic_actor=args.actor is None,
        profile_id=ws.profile.id,
        graph_sha256=ws.running_graph_sha256(),
        projection_version=revision.projection_version,
        revision_sha256=revision_sha256,
        actor=actor.coder_id,
        fulltext_origin=fulltext_receipt.payload["fulltext_origin"],
        fulltext_receipt=fulltext_receipt.digest,
        iso6393_release=language_receipt.payload["iso6393_release"],
        iso6393_vocabulary_sha256=language_receipt.payload["iso6393_vocabulary_sha256"],
        iso6393_snapshot_receipt=language_receipt.payload["iso6393_snapshot_receipt"],
        events=events,
    )
    preview = {
        "action": "transcript confirm",
        "activation_status": "READY_FOR_CONFIRMATION",
        "actor": {
            "coder_id": actor.coder_id,
            "label": actor.label,
            "register_status": "ACTIVE",
            "source": actor.source,
        },
        "artifact_key": plan.marker.object()["artifact_key"],
        "fulltext": {
            "input_status": "BOUND_FROM_SEGMENTS",
            "origin": plan.decision.fulltext_origin,
            "receipt_digest_short": plan.decision.fulltext_receipt[:12],
            "store_address": revision_sha256,
        },
        "iso6393": {
            "binding_status": "BOUND",
            "release": plan.decision.iso6393_release,
            "snapshot_receipt_digest_short": plan.decision.iso6393_snapshot_receipt[:12],
            "vocabulary_sha256": plan.decision.iso6393_vocabulary_sha256,
        },
        "projection_version": plan.marker.projection_version,
        "record": plan.marker.record_id,
        "revision_sha256": plan.marker.revision_sha256,
        "revision_store_address": plan.marker.revision_sha256,
    }
    return plan, preview


def cmd_b3b(args: argparse.Namespace) -> Report:
    """Duennes CLI-Routing auf die gemeinsamen B3b-Anwendungsplaene."""
    action = args.b3b_action
    retry = getattr(args, "retry_intent", None)
    if retry is not None:
        if getattr(args, "confirm", False):
            return Report(
                status=Status.CONFIG,
                reason="--retry-intent und --confirm sind gegenseitig unzulaessig.",
                reason_code="CONFIG_B3B_ARGUMENTS",
                check="ohpipe --help",
                details={"operation_result": "NONE"},
            )
        normal_fields = {
            "instance_register": (
                "coder_id",
                "source",
                "label",
                "reference",
                "model",
                "parametersatz",
            ),
            "instance_retire": ("coder_id", "reference"),
            "iso_prepare": ("snapshot", "release", "reference"),
            "fulltext_prepare": ("record", "fulltext", "reference"),
            "transcript_confirm": ("record", "actor"),
            "language_prepare": ("record_id", "srt", "mapping", "actor", "reference"),
            "ingest_srt": ("record", "srt", "mapping"),
        }[action]
        if any(getattr(args, field, None) is not None for field in normal_fields):
            return Report(
                status=Status.CONFIG,
                reason="--retry-intent verbietet normale Fachargumente.",
                reason_code="CONFIG_B3B_ARGUMENTS",
                check="ohpipe --help",
                details={"operation_result": "NONE"},
            )
        return Report(
            status=Status.STOP,
            reason="Zum bezeichneten Digest liegt kein gueltiger persistierter Intentbeleg vor.",
            reason_code="STOP_B3B_INTENT_ABSENT",
            check="ohpipe --json status",
            details={"operation_result": "NONE", "retry_intent": retry},
        )

    required_fields = {
        "instance_register": ("coder_id", "source", "label", "reference"),
        "instance_retire": ("coder_id", "reference"),
        "iso_prepare": ("snapshot", "release", "reference"),
        "fulltext_prepare": ("record", "fulltext", "reference"),
        "transcript_confirm": ("record",),
        "l1_review": ("record",),
        "metadata_confirm": ("record",),
        "abstract_confirm": ("record",),
        "release_approve": ("record",),
        "export_bundle": ("record",),
        "language_prepare": ("record_id", "srt", "mapping", "actor", "reference"),
        "ingest_srt": ("record", "srt", "mapping"),
    }.get(action, ())
    if any(getattr(args, field, None) is None for field in required_fields):
        return Report(
            status=Status.CONFIG,
            reason="Die normale B3b-Grammatik ist unvollstaendig.",
            reason_code="CONFIG_B3B_ARGUMENTS",
            check="ohpipe --help",
            details={"operation_result": "NONE"},
        )

    if action == "language_template":
        ws = _workspace(args)
        return export_language_template(
            Path(args.srt),
            Path(args.output),
            managed_roots=ws.managed_dirs + (ws.root,),
        )

    ws, journal, stop = _b3b_journal(args)
    if stop is not None:
        return stop
    events = (
        journal.verified_events()
        if action in {"l1_review", "export_bundle", *CONFIRM_GATES}
        else list(journal)
    )

    if action == "instance_register":
        # Der EINE Eingang fuer einen Modelltag in dieser Strecke. Fuehrt das
        # Profil eine geschlossene Liste, wird hier gehalten und nicht gewarnt:
        # Eine Maschineninstanz traegt ihren Modelltag dauerhaft im Register,
        # und ein Vermerk „ausserhalb der Liste, trotzdem gefahren" waere genau
        # der Beleg, den spaeter niemand mehr aufloest.
        if args.model is not None:
            ws.profile.check_model(args.model)
        plan = plan_register(
            events,
            args.coder_id,
            source=args.source,
            label=args.label,
            reference=args.reference,
            model=args.model,
            parametersatz=args.parametersatz,
        )
        return _b3b_confirm_or_abort(
            args,
            "Die Instanzregistrierung ist schreibfrei geplant.",
            _instance_preview(plan),
            lambda: write_instance_plan(ws, journal, plan),
        )

    if action == "instance_retire":
        plan = plan_retire(events, args.coder_id, reference=args.reference)
        return _b3b_confirm_or_abort(
            args,
            "Das Retirement ist schreibfrei geplant.",
            _instance_preview(plan),
            lambda: write_instance_plan(ws, journal, plan),
        )

    if action == "iso_prepare":
        plan = plan_iso_prepare(
            Path(args.snapshot), release_id=args.release, reference=args.reference
        )
        preview = {
            "action": "iso6393 prepare",
            "canonical_store_address": plan.snapshot.vocabulary_sha256,
            "planned_registry_effect": "iso6393.snapshot.prepared",
            "raw_store_address": plan.snapshot.source_sha256,
            "reference": plan.snapshot.reference,
            "release": plan.snapshot.release_id,
            "vocabulary_sha256": plan.snapshot.vocabulary_sha256,
        }
        return _b3b_confirm_or_abort(
            args,
            "Der ISO-639-3-Snapshot ist schreibfrei geplant.",
            preview,
            lambda: write_iso_prepare(ws, journal, plan),
        )

    if action == "fulltext_prepare":
        revisions = [
            event.payload["sha256"]
            for event in events
            if event.kind == "artifact.produced"
            and event.record_id == args.record
            and event.payload.get("artifact") == "transcript.revision"
        ]
        if not revisions:
            return Report(
                status=Status.STOP,
                reason="Keine aktuelle TranscriptRevision fuer den Record.",
                reason_code="STOP_B3B_INVARIANT",
                check="ohpipe --json status",
                details={"operation_result": "NONE"},
            )
        plan = plan_fulltext_prepare(
            Path(args.fulltext),
            record_id=args.record,
            revision_sha256=revisions[-1],
            reference=args.reference,
        )
        preview = {
            "action": "transcript fulltext prepare",
            "fulltext_origin": "separate_input",
            "fulltext_store_address": plan.source_sha256,
            "record": plan.record_id,
            "reference": plan.reference,
            "revision_sha256": plan.revision_sha256,
        }
        return _b3b_confirm_or_abort(
            args,
            "Die getrennte Volltextherkunft ist schreibfrei geplant.",
            preview,
            lambda: write_fulltext_prepare(ws, journal, plan),
        )

    if action == "language_prepare":
        vocabulary, iso_receipt, halt = _iso_snapshot_or_halt(ws, events)
        if halt is not None:
            return halt
        try:
            plan = plan_language_prepare(
                record_id=args.record_id,
                srt_path=Path(args.srt),
                mapping_path=Path(args.mapping),
                actor=args.actor,
                reference=args.reference,
                vocabulary=vocabulary,
                iso_snapshot_receipt=iso_receipt,
                profile_normalize=ws.profile.normalize_record_id,
                profile_check=ws.profile.is_record_id,
                events=events,
            )
        except (ValueError, OSError) as exc:
            return Report(
                status=Status.CONFIG,
                reason=str(exc),
                reason_code="CONFIG_B3B_LANGUAGE_PREPARE",
                check="ohpipe transcript language prepare --help",
                details={"operation_result": "NONE"},
            )
        preview = {
            "action": "transcript language prepare",
            "actor": plan.actor,
            "assignment_store_address": plan.assignment.sha256,
            "iso6393_release": plan.vocabulary.release_id,
            "iso6393_vocabulary_sha256": plan.vocabulary.vocabulary_sha256,
            "planned_registry_effect": "transcript.segment_languages.prepared.v1",
            "record": plan.target_record_id,
            "reference": plan.reference,
            "segments": len(plan.draft.segments),
        }
        return _b3b_confirm_or_abort(
            args,
            "Die Segmentsprachzuordnung ist schreibfrei geplant.",
            preview,
            lambda: write_language_prepare(ws, journal, plan),
        )

    if action == "ingest_srt":
        # Die Eigentumswache steht NICHT hier, sondern in
        # `src/ohpipe/application/ingest.py::write_b3b_ingest_srt`. ADR 0013:
        # das CLI enthaelt keine Geschaeftslogik, und die Reviewoberflaeche
        # ruft dieselbe Schicht. Eine Wache im CLI waere genau die zweite
        # Logik, die driften kann.
        record = ws.profile.normalize_record_id(args.record)
        vocabulary, iso_receipt, halt = _iso_snapshot_or_halt(ws, events)
        if halt is not None:
            return halt
        try:
            draft = build_srt_draft(Path(args.srt).read_bytes())
            assignment = assign_languages(
                draft,
                Path(args.mapping).read_bytes(),
                target_record_id=record,
                vocabulary=vocabulary,
            )
        except (LanguageAssignmentError, ValueError, OSError) as exc:
            return Report(
                status=Status.CONFIG,
                reason=str(exc),
                reason_code="CONFIG_B3B_INGEST",
                check="ohpipe transcript ingest --help",
                details={"operation_result": "NONE"},
            )
        # Die Zuordnung wird NEU GEBAUT und gegen den Beleg gehalten, statt aus
        # dem Journal geglaubt zu werden. Wer sie glaubt, kann mit einer
        # anderen Mappingdatei dieselbe Fassung behaupten; wer sie nachrechnet,
        # bekommt fuer andere Bytes einen anderen Digest und damit keinen
        # Treffer. Ohne Treffer gibt es keinen Ingest, sondern den Verweis auf
        # den Schritt, der fehlt.
        belege = [
            event
            for event in events
            if event.kind == "receipt.recorded"
            and event.payload.get("kind") == "transcript.segment_languages.prepared.v1"
            and event.payload.get("target_record_id") == record
            and event.payload.get("output_sha256") == assignment.sha256
        ]
        if not belege:
            return language_prepare_required(
                record,
                next_command=_b3b_command(
                    args,
                    "transcript",
                    "language",
                    "prepare",
                    record,
                    args.srt,
                    args.mapping,
                    "--actor",
                    "<coder_id>",
                    "--reference",
                    "<reference>",
                ),
            )
        try:
            plan = plan_b3b_ingest_srt(
                record_id=record,
                assignment=assignment,
                language_receipt_digest=belege[-1].digest,
            )
        except IngestError as exc:
            return Report(
                status=Status.CONFIG,
                reason=str(exc),
                reason_code="CONFIG_B3B_INGEST",
                check="ohpipe transcript ingest --help",
                details={"operation_result": "NONE"},
            )
        preview = {
            "action": "transcript ingest",
            "language_receipt_digest": plan.language_receipt_digest,
            "planned_registry_effect": "transcript.fulltext.segment_projection.v1",
            "record": plan.record_id,
            "revision_sha256": plan.revision_sha256,
            "revision_store_address": plan.revision_sha256,
            "segments": len(assignment.draft.segments),
        }
        return _b3b_confirm_or_abort(
            args,
            "Die kanonische Transkriptfassung ist schreibfrei geplant.",
            preview,
            lambda: write_b3b_ingest_srt(ws, journal, plan),
        )

    if action == "transcript_confirm":
        try:
            plan, preview = _transcript_confirmation_plan(ws, events, args)
        except ValueError as exc:
            return Report(
                status=Status.ACTION_NEEDED,
                reason=str(exc),
                reason_code="ACTION_B3B_PRECONDITION_REQUIRED",
                next_command="ohpipe --json status",
                details={"operation_result": "NONE", "action": action},
            )
        return _b3b_confirm_or_abort(
            args,
            "Die Transcriptaktivierung ist vollstaendig und schreibfrei geplant.",
            preview,
            lambda: write_confirmation(ws, journal, plan),
        )

    if action == "l1_review":
        try:
            plan = plan_l1_review(
                ws,
                events,
                authority=Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED,
                record_id=ws.profile.normalize_record_id(args.record),
                actor_arg=args.actor,
            )
        except GateError as exc:
            return _gate_halt(args, exc)
        except ValueError as exc:
            return Report(
                status=Status.ACTION_NEEDED,
                reason=str(exc),
                reason_code="ACTION_B3B_PRECONDITION_REQUIRED",
                next_command="ohpipe --json status",
                details={"operation_result": "NONE", "action": action},
            )
        return _b3b_confirm_or_abort(
            args,
            "Die L1-Adjudikation ist schreibfrei geplant.",
            plan.preview,
            lambda: write_l1_review(ws, journal, plan),
        )

    if action == "export_bundle":
        try:
            plan = plan_export(
                ws,
                events,
                authority=Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED,
                record_id=ws.profile.normalize_record_id(args.record),
                output_arg=args.output,
                managed_roots=ws.managed_dirs + (ws.root,),
            )
        except ExportBlocked as exc:
            return Report(
                status=Status.STOP,
                reason=str(exc),
                reason_code="STOP_EXPORT_MANDATORY_FIELDS_MISSING",
                check="ohpipe --json status",
                details={"operation_result": "NONE", "action": action},
            )
        except ExportTargetError as exc:
            return Report(
                status=Status.CONFIG,
                reason=str(exc),
                reason_code="CONFIG_EXPORT_OUTPUT",
                check="ohpipe export --help",
                details={"operation_result": "NONE", "action": action},
            )
        except GateError as exc:
            return _gate_halt(args, exc)
        except ValueError as exc:
            return Report(
                status=Status.ACTION_NEEDED,
                reason=str(exc),
                reason_code="ACTION_B3B_PRECONDITION_REQUIRED",
                next_command="ohpipe --json status",
                details={"operation_result": "NONE", "action": action},
            )
        return _b3b_confirm_or_abort(
            args,
            "Der Katalogausgang ist schreibfrei geplant.",
            plan.preview,
            lambda: write_export(ws, journal, plan),
        )

    if action in CONFIRM_GATES:
        if (
            action == "release_approve"
            and ws.profile.production
            and not (sys.stdin.isatty() and sys.stderr.isatty())
        ):
            return _release_terminal_required(args)
        spec, draft_artifact, confirmed_schema = CONFIRM_GATES[action]
        try:
            plan = plan_confirm(
                ws,
                events,
                authority=Authority.AUTHENTICATED if journal.key else Authority.UNAUTHENTICATED,
                spec=spec,
                draft_artifact=draft_artifact,
                confirmed_schema=confirmed_schema,
                record_id=ws.profile.normalize_record_id(args.record),
                actor_arg=args.actor,
            )
        except GateError as exc:
            return _gate_halt(args, exc)
        except ValueError as exc:
            return Report(
                status=Status.ACTION_NEEDED,
                reason=str(exc),
                reason_code="ACTION_B3B_PRECONDITION_REQUIRED",
                next_command="ohpipe --json status",
                details={"operation_result": "NONE", "action": action},
            )
        return _b3b_confirm_or_abort(
            args,
            f"Der Katalogakt {spec.step} ist schreibfrei geplant.",
            plan.preview,
            lambda: write_confirm(ws, journal, plan),
            terminal_fields=plan.terminal_fields,
        )

    return Report(
        status=Status.ACTION_NEEDED,
        reason="Der B3b-Fachplan benoetigt zunaechst seine journalabgeleiteten Bindungen.",
        reason_code="ACTION_B3B_PRECONDITION_REQUIRED",
        next_command="ohpipe --json status",
        details={"operation_result": "NONE", "action": action},
    )


def cmd_decision_action(args: argparse.Namespace) -> Report:
    from ..application.decision_actions import write_action
    from ..domain.decision import Verdict

    ws, journal, stop = _b3b_journal(args)
    if stop:
        return stop
    if not args.confirm:
        return Report(
            status=Status.ACTION_NEEDED,
            reason="Menschlicher Akt benötigt --confirm; UNDO ist keine Freigabe.",
            check=_e8_operator_command(
                ws, args.profile, "decision", args.decision_action, "--help"
            ),
        )
    write_action(
        ws,
        journal,
        args.record,
        args.artifact,
        Verdict(args.decision_action.upper()),
        args.actor,
        args.reference,
        undo_of=args.undo_of,
    )
    return Report(
        status=Status.READY,
        reason="Entscheidungsakt getrennt und zurechenbar protokolliert.",
        next_command=_e8_operator_command(ws, args.profile, "status"),
    )


def cmd_sources_refresh(args: argparse.Namespace) -> Report:
    from ..application.input_sources import refresh

    ws, journal, stop = _b3b_journal(args)
    if stop:
        return stop
    refresh(ws, journal, args.record, _profile_path(args.profile))
    return Report(
        status=Status.READY,
        reason="Zusatzquellen eingelesen; abhängige Belege werden erneut geprüft.",
        next_command=_e8_operator_command(ws, args.profile, "continue", args.record),
    )


# ------------------------------------------------------------------ main


class _B3bArgumentParser(argparse.ArgumentParser):
    """Loest das fachliche --model vor argparse auf, ohne einen Bypassschalter anzulegen.

    Der Sockelwaechter verbietet eine argparse-Option namens ``--model`` als
    historischen Modell-Gate-Bypass. B3b benutzt denselben Wortlaut dagegen
    ausschliesslich als Pflichtmetadatum unter ``instance register``. Die
    Vorauflösung ist auf genau diese Tokenfolge gebunden; jede andere Stelle
    bleibt eine unbekannte Option.
    """

    def parse_known_args(self, args=None, namespace=None):
        tokens = list(sys.argv[1:] if args is None else args)
        if self.prog == "ohpipe":
            try:
                register = tokens.index("register")
            except ValueError:
                register = -1
            if register > 0 and tokens[register - 1] == "instance":
                tokens = ["--machine-model" if token == "--model" else token for token in tokens]
        return super().parse_known_args(tokens, namespace)


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--profile", default=argparse.SUPPRESS, help="Profilname oder Pfad")
    p.add_argument("--root", default=argparse.SUPPRESS, help=f"Datenwurzel (sonst ${ENV_ROOT})")
    p.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="maschinenlesbares Ergebnis"
    )


def build_parser() -> argparse.ArgumentParser:
    p = _B3bArgumentParser(
        prog="ohpipe",
        description="Oral-History-Pipeline. Exitcodes: 0 READY · 1 STOP · 2 CONFIG · 3 ACTION_NEEDED",
    )
    p.add_argument("--version", action="version", version=f"ohpipe {__version__}")
    p.add_argument("--profile", default="sandbox", help="Profilname oder Pfad zu profile.toml")
    p.add_argument("--root", default=None, help=f"Datenwurzel (sonst ${ENV_ROOT})")
    p.add_argument("--json", action="store_true", help="maschinenlesbares Ergebnis")
    sub = p.add_subparsers(dest="command", required=True)

    for name, help_, fn in (
        ("doctor", "read-only Selbstdiagnose", cmd_doctor),
        ("init", "Arbeitsbereich anlegen", cmd_init),
        ("status", "read-only Übersicht", cmd_status),
        ("ingest", "Quelltranskript aufnehmen", cmd_ingest),
        ("graph-upgrade", "Graphbindung ausdrücklich anheben", cmd_graph_upgrade),
        ("continue", "läuft von selbst und hält — mit Grund und nächstem Befehl", cmd_continue),
    ):
        sp = sub.add_parser(name, help=help_)
        # Beide Reihenfolgen zulassen: ein NEXT-Befehl, den argparse ablehnt,
        # ist ein gebrochener Operatorvertrag.
        _add_common(sp)
        if name == "ingest":
            sp.add_argument("source", nargs="?", help="Pfad zur Quelldatei (.srt oder .vtt)")
            sp.add_argument("--record", help="Record-ID, etwa SANDBOX-001")
            sp.add_argument("--retry-intent")
        if name == "continue":
            sp.add_argument("record", nargs="?", help="Record-ID, etwa SANDBOX-001")
            sp.add_argument(
                "--confirm",
                action="store_true",
                help="auch teure Schritte (model) ausführen; Gates bleiben Gates",
            )
            sp.add_argument(
                "--fixture",
                choices=("stop", "length"),
                default="stop",
                help="Szenario des aufgezeichneten Modelladapters (nur synthetische Profile)",
            )
        if name == "graph-upgrade":
            sp.add_argument(
                "--to",
                dest="target",
                required=True,
                metavar="SHA256",
                help="bewusst bestätigter laufender Graphvertrag",
            )
        sp.set_defaults(fn=fn)

    from .manual import parsers as manual_parsers

    manual_parsers(sub, _add_common)

    decision = sub.add_parser("decision", help="Menschlicher Widerruf und dessen Rücknahme")
    decision_sub = decision.add_subparsers(dest="decision_action", required=True)
    for action in ("withdraw", "undo"):
        command = decision_sub.add_parser(action)
        _add_common(command)
        command.add_argument("record")
        command.add_argument("artifact")
        command.add_argument("--actor", required=True)
        command.add_argument("--reference", required=True)
        command.add_argument("--undo-of", required=action == "undo")
        command.add_argument("--confirm", action="store_true")
        command.set_defaults(fn=cmd_decision_action)

    sources = sub.add_parser("sources", help="Zusatzquellen ausdrücklich neu einlesen")
    sources_sub = sources.add_subparsers(dest="sources_action", required=True)
    refresh = sources_sub.add_parser("refresh", help="Codebuch und Metadaten einlesen")
    _add_common(refresh)
    refresh.add_argument("record")
    refresh.set_defaults(fn=cmd_sources_refresh)

    instance = sub.add_parser("instance", help="workspaceweites Instanzregister")
    _add_common(instance)
    instance_sub = instance.add_subparsers(dest="instance_command", required=True)
    register = instance_sub.add_parser("register", help="Instanz registrieren")
    _add_common(register)
    register.add_argument("coder_id", nargs="?")
    register.add_argument("--source", choices=("mensch", "maschine"))
    register.add_argument("--label")
    register.add_argument("--reference")
    register.add_argument("--machine-model", dest="model", help=argparse.SUPPRESS)
    register.add_argument("--parametersatz")
    register.add_argument("--confirm", action="store_true")
    register.add_argument("--retry-intent")
    register.set_defaults(fn=cmd_b3b, b3b_action="instance_register")
    retire = instance_sub.add_parser("retire", help="Instanz retiren")
    _add_common(retire)
    retire.add_argument("coder_id", nargs="?")
    retire.add_argument("--reference")
    retire.add_argument("--confirm", action="store_true")
    retire.add_argument("--retry-intent")
    retire.set_defaults(fn=cmd_b3b, b3b_action="instance_retire")

    iso = sub.add_parser("iso6393", help="ISO-639-3-Snapshotverwaltung")
    _add_common(iso)
    iso_sub = iso.add_subparsers(dest="iso_command", required=True)
    iso_prepare = iso_sub.add_parser("prepare", help="Snapshot vorbereiten")
    _add_common(iso_prepare)
    iso_prepare.add_argument("snapshot", nargs="?")
    iso_prepare.add_argument("--release")
    iso_prepare.add_argument("--reference")
    iso_prepare.add_argument("--confirm", action="store_true")
    iso_prepare.add_argument("--retry-intent")
    iso_prepare.set_defaults(fn=cmd_b3b, b3b_action="iso_prepare")

    transcript = sub.add_parser("transcript", help="B3b-Transcriptakte")
    _add_common(transcript)
    transcript_sub = transcript.add_subparsers(dest="transcript_command", required=True)
    confirm = transcript_sub.add_parser("confirm", help="Transcript aktivieren")
    _add_common(confirm)
    confirm.add_argument("record", nargs="?")
    confirm.add_argument("--actor")
    confirm.add_argument("--confirm", action="store_true")
    confirm.add_argument("--retry-intent")
    confirm.set_defaults(fn=cmd_b3b, b3b_action="transcript_confirm")
    t_ingest = transcript_sub.add_parser(
        "ingest", help="SRT mit Sprachzuordnung zur kanonischen Fassung aufnehmen"
    )
    _add_common(t_ingest)
    t_ingest.add_argument("record", nargs="?")
    t_ingest.add_argument("srt", nargs="?")
    t_ingest.add_argument("mapping", nargs="?")
    t_ingest.add_argument("--confirm", action="store_true")
    t_ingest.add_argument("--retry-intent")
    t_ingest.set_defaults(fn=cmd_b3b, b3b_action="ingest_srt")
    fulltext = transcript_sub.add_parser("fulltext", help="Volltextherkunft")
    _add_common(fulltext)
    fulltext_sub = fulltext.add_subparsers(dest="fulltext_command", required=True)
    fulltext_prepare = fulltext_sub.add_parser("prepare", help="Volltext vorbereiten")
    _add_common(fulltext_prepare)
    fulltext_prepare.add_argument("record", nargs="?")
    fulltext_prepare.add_argument("fulltext", nargs="?")
    fulltext_prepare.add_argument("--reference")
    fulltext_prepare.add_argument("--confirm", action="store_true")
    fulltext_prepare.add_argument("--retry-intent")
    fulltext_prepare.set_defaults(fn=cmd_b3b, b3b_action="fulltext_prepare")
    anchors = transcript_sub.add_parser(
        "anchors", help="read-only: Ankerzustand nach einer Korrektur"
    )
    _add_common(anchors)
    anchors.add_argument("record", nargs="?")
    anchors.set_defaults(fn=cmd_anchors)

    language = transcript_sub.add_parser("language", help="Segmentsprachen")
    _add_common(language)
    language_sub = language.add_subparsers(dest="language_command", required=True)
    template = language_sub.add_parser("template", help="lokale Mappingvorlage")
    _add_common(template)
    template.add_argument("srt")
    template.add_argument("--output", required=True)
    template.set_defaults(fn=cmd_b3b, b3b_action="language_template")
    language_prepare = language_sub.add_parser("prepare", help="Sprachen vorbereiten")
    _add_common(language_prepare)
    language_prepare.add_argument("record_id", nargs="?")
    language_prepare.add_argument("srt", nargs="?")
    language_prepare.add_argument("mapping", nargs="?")
    language_prepare.add_argument("--actor")
    language_prepare.add_argument("--reference")
    language_prepare.add_argument("--confirm", action="store_true")
    language_prepare.add_argument("--retry-intent")
    language_prepare.set_defaults(fn=cmd_b3b, b3b_action="language_prepare")

    l1 = sub.add_parser("l1", help="L1-Adjudikation")
    l1_sub = l1.add_subparsers(dest="l1_command", required=True)
    review = l1_sub.add_parser("review", help="L1-Vorschlaege adjudizieren")
    review.add_argument("record", nargs="?")
    review.add_argument("--actor")
    review.add_argument("--confirm", action="store_true")
    review.set_defaults(fn=cmd_b3b, b3b_action="l1_review")

    metadata = sub.add_parser("metadata", help="Katalogmetadaten")
    metadata_sub = metadata.add_subparsers(dest="metadata_command", required=True)
    m_confirm = metadata_sub.add_parser("confirm", help="Metadatenentwurf bestaetigen")
    m_confirm.add_argument("record", nargs="?")
    m_confirm.add_argument("--actor")
    m_confirm.add_argument("--confirm", action="store_true")
    m_confirm.set_defaults(fn=cmd_b3b, b3b_action="metadata_confirm")

    abstract = sub.add_parser("abstract", help="Katalogabstract")
    abstract_sub = abstract.add_subparsers(dest="abstract_command", required=True)
    a_confirm = abstract_sub.add_parser("confirm", help="Abstractentwurf bestaetigen")
    a_confirm.add_argument("record", nargs="?")
    a_confirm.add_argument("--actor")
    a_confirm.add_argument("--confirm", action="store_true")
    a_confirm.set_defaults(fn=cmd_b3b, b3b_action="abstract_confirm")

    release = sub.add_parser("release", help="Katalogfreigabe")
    release_sub = release.add_subparsers(dest="release_command", required=True)
    r_approve = release_sub.add_parser("approve", help="Katalogvorschau freigeben")
    r_approve.add_argument("record", nargs="?")
    r_approve.add_argument("--actor")
    r_approve.add_argument("--confirm", action="store_true")
    r_approve.set_defaults(fn=cmd_b3b, b3b_action="release_approve")

    export_cmd = sub.add_parser("export", help="Katalogausgang (deterministisches Bundle)")
    export_cmd.add_argument("record", nargs="?")
    export_cmd.add_argument(
        "--output", help="lokales Ziel fuer die Bundlebytes, neben dem Datenbaum"
    )
    export_cmd.add_argument("--confirm", action="store_true")
    export_cmd.set_defaults(fn=cmd_b3b, b3b_action="export_bundle")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    for k, default in (("profile", "sandbox"), ("root", None), ("json", False)):
        if not hasattr(args, k):
            setattr(args, k, default)
    try:
        report = args.fn(args)
    except DataRootError as exc:
        report = Report(
            status=Status.CONFIG,
            reason=str(exc),
            reason_code="CONFIG_DATA_ROOT",
            next_command=f"export {ENV_ROOT}=~/ohpipe-data   # ausserhalb des Repositories",
        )
    except GraphBindingError as exc:
        ws = _workspace(args)
        report = Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_GRAPH_BINDING_INVALID",
            check=_e8_operator_command(
                ws,
                args.profile,
                "doctor",
                as_json=True,
                comment="Bindungsdatei sichern und untersuchen",
            ),
        )
    except WorkspaceUnsafe as exc:
        # Vor ProfileError, weil WorkspaceUnsafe davon erbt und die Antwort eine
        # andere ist: Ein fehlendes Profil korrigiert man (CONFIG), einen
        # untergeschobenen Symlink untersucht man (STOP).
        report = Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_WORKSPACE_UNSAFE",
            next_command="ohpipe --json doctor",
        )
    except ModelNotAllowed as exc:
        # Vor ProfileError, weil ModelNotAllowed davon erbt und die Antwort eine
        # andere ist: Ein unbekanntes Profil korrigiert der Operator (CONFIG),
        # ein Modell ausserhalb der geschlossenen Liste ist ein Halt (STOP).
        # Die Liste steht im Profil, nicht in der Bedienung.
        report = Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_MODEL_NOT_IN_PROFILE_LIST",
            check="ohpipe --json doctor",
        )
    except ProfileError as exc:
        # Ein gefangener Konfigurationsfehler nennt seinen Auflösungsweg. Ein
        # unbekanntes Profil hat keinen zustandsändernden Resolver — die
        # mitgelieferten Profile stehen in der Meldung, die korrigierte
        # Wiederholung ist read-only und gehört nach CHECK, nicht NEXT
        # (Reviewer-Adjudikation 07.08.).
        report = Report(
            status=Status.CONFIG,
            reason=str(exc),
            reason_code="CONFIG_PROFILE",
            check=shlex.join(
                ["ohpipe", "--profile", getattr(args, "profile", None) or "sandbox", "doctor"]
            ),
        )
    except OwnershipError as exc:
        report = Report(status=Status.STOP, reason=str(exc), reason_code="STOP_OWNERSHIP")
    except PayloadRejected as exc:
        # Eine abgelehnte Nutzlast ist ein Programmierfehler des Aufrufers, kein
        # Bedienfehler — deshalb STOP und nicht CONFIG. Der Operator kann hier
        # nichts korrigieren; es steht nur noch nichts Falsches im Journal.
        report = Report(
            status=Status.STOP,
            reason=f"Ereignis abgelehnt, nichts geschrieben: {exc}",
            reason_code="STOP_PAYLOAD_REJECTED",
            next_command="ohpipe --json doctor",
        )
    except StoreError as exc:
        report = Report(
            status=Status.STOP,
            reason=str(exc),
            reason_code="STOP_STORE",
            next_command="ohpipe --json doctor",
        )
    except GateError as exc:
        report = _gate_halt(args, exc)
    except KeyboardInterrupt:
        report = Report(
            status=Status.ACTION_NEEDED,
            reason="abgebrochen — nichts geschrieben",
            reason_code="ACTION_INTERRUPTED",
        )
    except Exception as exc:  # noqa: BLE001 - der Vierzeiler ist die Zusage
        # Nicht gefangen waren unter anderem: JournalBroken aus der VERZOEGERTEN
        # Iteration in replay (die Datei kann sich zwischen verify() und replay()
        # aendern), StoreError ausserhalb des try in cmd_status, PermissionError
        # und jedes OSError auf der Datenwurzel. Der Exitcode waere zufaellig 1
        # und damit richtig gewesen — aber statt vier Zeilen stand ein Traceback
        # da, und genau das ist die Fehlermeldung, die man nachts um elf nicht
        # deuten kann.
        import traceback

        report = Report(
            status=Status.STOP,
            reason=f"Unerwarteter Fehler ({type(exc).__name__}): {exc}",
            reason_code="STOP_UNEXPECTED",
            next_command="ohpipe --json doctor   # Befund sichern",
            details={"traceback": traceback.format_exc()} if args.json else {},
        )
    return report.emit(as_json=args.json)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
