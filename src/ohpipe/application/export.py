"""Der Katalogausgang: aus der Freigabe wird ein Bundle, die Entscheidung wird geerbt.

Der letzte Schritt der Kette und der einzige, der ``leaves_system`` traegt
(``domain/step.py``, ``Kind.EGRESS``). Drei Dinge machen ihn aus:

* **Genau eine Eingabe.** Der Beleg nennt ``release.approved`` und sonst
  nichts. Alles Weitere im Bundle haengt an dieser einen Adresse: die Freigabe
  nennt die Vorschau, die Vorschau nennt Metadaten, Abstract und Adjudikation,
  und jede dieser Bytequellen wird inhaltsadressiert aus dem Store gelesen. Wer
  eine der Zwischenstufen austauscht, aendert ihren Hash und damit die
  Freigabe, die auf ihn zeigt.
* **Keine neue Entscheidung.** ``export.bundle`` verlangt vertraglich eine
  Entscheidung (``decision_required``, E2-N Nummer 8), und sie wird GEERBT:
  ``src/ohpipe/application/replay.py::_inherit_egress_decision`` bindet den Beleg an die wirksame
  ACCEPT-Entscheidung auf ``release.approved``. Der Export fragt keinen
  Menschen ein zweites Mal, und er erfindet auch keine Zustimmung. Faellt die
  Freigabe weg oder aendern sich ihre Bytes, faellt das Erbe mit.
* **Zwei getrennte Vorgaenge.** Das Bundle ENTSTEHT im Content Store (das tut
  ``continue`` von selbst, der Schritt ist billig). Es VERLAESST das System
  erst, wenn jemand ein Ziel nennt: ``--output`` schreibt die Bytes neben den
  Datenbaum, ueber den gemeinsamen sicheren Schreiber (``local_publish.py``).
  Ohne Ziel entsteht kein Datenausgang.

Bewusst NICHT hier: WebVTT, OHMS, Dublin Core und jedes andere Zielformat,
mehrere Records in einem Bundle, jede Form von Rendering. Das Bundle ist der
deterministische JSON-Ausgang, auf dem Formatadapter spaeter aufsetzen.

Ebenfalls nicht enthalten: die Transkriptidentitaet. Sie liegt hinter
``l1.adjudicated`` und waere ein zweiter Kettengang; das Bundle nennt die
Adjudikation mit ihrer Adresse und ueberlaesst den Rest dem, der sie aufloest.

Datenschutz: das Bundle traegt Artefaktnamen, Adressen, die kontrollierten
Metadatenfelder und die Abschnittsnamen der Schablone — keinen Transkripttext
und kein Zitat.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..domain.hashing import sha256_bytes
from ..journal import Journal
from ..policies.authority import Authority
from ..workspace_lock import workspace_write_lock
from ..policies.exit_contract import Report, Status
from ..project import Workspace
from .gate import GateError, canonical_bytes, current_inputs, check_planned_inputs, write_derivation
from .local_publish import check_target, publish_bytes
from .operation_recovery import b3b_report

__all__ = [
    "BUNDLE_CODE_VERSION",
    "BUNDLE_SCHEMA",
    "ExportBlocked",
    "ExportError",
    "ExportPlan",
    "ExportTargetError",
    "build_bundle",
    "plan_export",
    "run_export",
    "write_export",
]

#: Das Schema der Bundlebytes und die Fassung, die im Beleg steht. Aendert sich
#: eine von beiden, aendert sich der Artefakthash — und der Beleg zeigt
#: sichtbar auf die alte Fassung (STALE), statt still weiterzugelten.
BUNDLE_SCHEMA = "ohpipe.export.bundle.v1"
BUNDLE_CODE_VERSION = "export-bundle/1"

#: Die eine Eingabe des Ausgangs. Sie MUSS die Vorbedingung des Graphschritts
#: sein, sonst kann ``_inherit_egress_decision`` nicht erben: es vergleicht die
#: Belegeingaben zeichengenau mit ``Step.requires``.
UPSTREAM = "release.approved"


class ExportError(GateError):
    """Der Ausgang liess sich nicht bilden. Nichts abgelegt, nichts geschrieben."""


class ExportBlocked(ExportError):
    """Ein produktives Profil laesst diesen Katalogeintrag nicht hinaus.

    Getrennt von :class:`ExportError`, damit das CLI sie als STOP melden kann
    und nicht als fehlende Vorbedingung: ein fehlendes Pflichtfeld ist kein
    Schritt, der noch laeuft, sondern eine Grenze, an der nichts passiert.
    """


class ExportTargetError(ExportError):
    """Die genannte Ausgabelage taugt nicht. Eine Bedienfrage, keine Vorbedingung.

    Getrennt von :class:`ExportError`, damit das CLI sie als CONFIG melden kann
    und nicht als fehlende Vorbedingung: ein Ziel im Datenbaum ist kein Schritt,
    der noch fehlt, sondern ein falsch genannter Pfad.
    """


@dataclass(frozen=True)
class ExportPlan:
    """Der schreibfrei gebaute Ausgang — Bytes, Adresse, Ziel."""

    record_id: str
    upstream_sha256: str
    bundle_sha256: str
    bundle_bytes: bytes
    output: Path | None
    output_parent: Path | None
    preview: dict[str, Any]


def _feld(obj: dict[str, Any], schluessel: str, herkunft: str) -> str:
    wert = obj.get(schluessel)
    if not isinstance(wert, str) or not wert:
        raise ExportError(f"export: {herkunft} nennt kein brauchbares {schluessel!r}")
    return wert


def _lies(ws: Workspace, sha: str, herkunft: str) -> dict[str, Any]:
    """Liest ein Artefakt inhaltsadressiert und geprueft aus dem Store.

    ``open_verified`` und nicht ``open``: der Store rechnet den Digest gegen
    den Namen, bevor er die Bytes herausgibt. Ein Objekt, das unter seiner
    Adresse etwas anderes traegt, faellt hier und nicht im Bundle auf.
    """
    try:
        with ws.store().open_verified(sha) as strom:
            roh = strom.read()
    except (OSError, ValueError, RuntimeError) as exc:
        raise ExportError(f"export: {herkunft} ({sha[:12]}) ist nicht lesbar: {exc}") from exc
    try:
        geladen = json.loads(roh)
    except json.JSONDecodeError as exc:
        raise ExportError(f"export: {herkunft} ({sha[:12]}) ist kein JSON: {exc}") from exc
    if not isinstance(geladen, dict):
        raise ExportError(f"export: {herkunft} ({sha[:12]}) ist kein Objekt")
    return geladen


def _halt_wenn_eingabe_gewandert(
    ws: Workspace, record_id: str, metadaten_entwurf: dict[str, Any]
) -> None:
    """Der zweite Satz der Sperre: haelt die Eingabedatei gegen ihren Digest im Entwurf.

    **Was hier NICHT gebaut wird.** Die offene Stelle O-2 (`TRACEABILITY.md`)
    bleibt offen: ``metadata.derive`` liest seine Eingabedatei genau einmal, und
    eine spaetere Aenderung wirkt nicht. Das zu beheben hiesse zu entscheiden,
    wann eine Ableitung ihre Eingaben erneut liest, und das ist eine
    Regie-Entscheidung fuer Oktober. Was hier gebaut wird, ist nicht die
    Behebung, sondern die SICHTBARKEIT: Der Katalogeintrag darf nicht
    hinausgehen, ohne dass jemand gesehen hat, dass die Eingabe daneben eine
    andere geworden ist.

    **Warum an dieser Stelle.** Der Egress ist heute ohnehin der einzige Ort,
    der eine Belegeingabe gegen die aktuellen Bytes haelt
    (``src/ohpipe/application/replay.py::_inherit_egress_decision`` vergleicht ``receipt_inputs``
    gegen ``upstream_facts.sha256``). Dieser Satz erweitert dieses Muster um
    einen Fall und erfindet keins: Wieder wird eine Eingabe, die ein Beleg
    nennt, gegen das gehalten, was heute dasteht.

    **Warum der Digest aus dem ENTWURF und nicht aus dem Beleg.** Der Auftrag
    nennt ``inputs["metadata.input"]`` aus dem Beleg von ``metadata.draft``.
    ``build_bundle`` hat kein Journal und bekaeme es nur ueber eine geaenderte
    Signatur, die drei Aufrufer beruehrte. Der Entwurf traegt seit
    ``metadata-derive/2`` denselben Digest als ``metadata_input``, und er wird
    inhaltsadressiert und geprueft gelesen (``_lies`` ueber
    ``open_verified``). Die Quelle ist damit dieselbe Aussage, nur naeher am
    Gegenstand: die Bytes, auf die sich der ganze Katalogeintrag beruft.

    Wirkt AUSSCHLIESSLICH bei ``production = true``, wie die vorhandene Sperre.
    Im Sandboxprofil aendert sich nichts, und das Vorfuehrskript laeuft
    unveraendert.
    """
    erwartet = metadaten_entwurf.get("metadata_input")
    if not erwartet:
        # Ein Entwurf aus `metadata-derive/1` kennt das Feld nicht. Er hat nie
        # eine Eingabedatei gesehen, also fehlen ihm die Pflichtfelder, und der
        # erste Satz der Sperre feuert ohnehin. Hier gibt es nichts zu
        # vergleichen; eine Behauptung waere schlimmer als keine.
        return

    pfad = ws.governance / "metadata" / f"{record_id}.toml"
    if not pfad.exists():
        raise ExportBlocked(
            f"export gesperrt: der Katalogeintrag beruht auf der Metadateneingabe "
            f"{erwartet[:12]}…, und unter {pfad} liegt keine Datei mehr. Ob die Zusage im "
            "Eintrag noch die des Operators ist, laesst sich damit nicht mehr feststellen. "
            "Ohne diese Feststellung verlaesst nichts das System (offene Stelle O-2)."
        )

    jetzt = sha256_bytes(pfad.read_bytes())
    if jetzt != erwartet:
        raise ExportBlocked(
            f"export gesperrt: die Metadateneingabe unter {pfad} wurde nach dem Entwurf "
            f"geaendert (heute {jetzt[:12]}…, im Entwurf {erwartet[:12]}…). Der "
            "Katalogeintrag beruht auf der ALTEN Fassung: `metadata.derive` liest seine "
            "Eingabe genau einmal, und die Aenderung ist nirgends eingegangen. Entweder "
            "der Eintrag stimmt und die Datei ist zurueckzunehmen, oder die Datei stimmt "
            "und der Eintrag ist neu abzuleiten (offene Stelle O-2)."
        )


def build_bundle(ws: Workspace, record_id: str, upstream_sha: str) -> tuple[bytes, dict[str, Any]]:
    """Baut die Bundlebytes aus der Freigabe heraus. Schreibfrei.

    Der Gang durch die Kette ist die Aussage des Exports: von
    ``release.approved`` ueber ``release.preview`` zu den drei bestaetigten
    Teilen. Jede Stufe wird gelesen, nicht geglaubt; fehlt ein Feld, bricht der
    Export ab, statt ein halbes Bundle abzulegen.
    """
    freigabe = _lies(ws, upstream_sha, "release.approved")
    if freigabe.get("record_id") != record_id:
        raise ExportError("export: die Freigabe gehoert zu einem anderen Record")
    vorschau_sha = _feld(freigabe, "confirmed", "release.approved")
    vorschau = _lies(ws, vorschau_sha, "release.preview")

    metadaten_sha = _feld(vorschau, "metadata", "release.preview")
    abstract_sha = _feld(vorschau, "abstract", "release.preview")
    adjudiziert = _feld(vorschau, "adjudicated", "release.preview")

    metadaten = _lies(ws, metadaten_sha, "metadata.confirmed")
    metadaten_entwurf_sha = _feld(metadaten, "confirmed", "metadata.confirmed")
    metadaten_entwurf = _lies(ws, metadaten_entwurf_sha, "metadata.draft")

    abstract = _lies(ws, abstract_sha, "abstract.confirmed")
    abstract_entwurf_sha = _feld(abstract, "confirmed", "abstract.confirmed")
    abstract_entwurf = _lies(ws, abstract_entwurf_sha, "abstract.draft")

    # Die Sperre. Sie wirkt AUSSCHLIESSLICH in produktiven Profilen
    # (``profile.toml``: ``production = true``, heute nur childlux). Im
    # Sandboxprofil aendert sich nichts, und das ist Absicht: die synthetische
    # Uebungswelt soll die ganze Kette zeigen duerfen, gerade weil ihr Record
    # keine Erschliessung hat.
    #
    # Der Grund fuer die Sperre ist nicht Vollstaendigkeit um ihrer selbst
    # willen. Unter den Pflichtfeldern des Metadata Model stehen
    # ``consent_status`` und ``accessRights``: ein Katalogpaket ohne sie sagt
    # nicht, unter welcher Einwilligung und mit welchen Rechten es hinausgeht.
    # Das Bundle hat diese Luecke bisher MITGETEILT (``open_requirements``) und
    # nicht verhindert. Mitteilen reicht an der Systemgrenze nicht.
    if ws.profile.production:
        _halt_wenn_eingabe_gewandert(ws, record_id, metadaten_entwurf)

    offen = list(metadaten_entwurf.get("open_requirements") or [])
    if ws.profile.production and offen:
        fehlend = [
            feld
            for feld in metadaten_entwurf.get("required_fields") or []
            if feld not in (metadaten_entwurf.get("fields") or {})
        ]
        # Namentlich, nicht als Zahl. Wer den Halt liest, soll wissen, was er
        # eintragen muss, und nicht erst eine zweite Abfrage brauchen.
        benannt = ", ".join(fehlend) if fehlend else "; ".join(offen)
        raise ExportBlocked(
            f"export gesperrt: das Profil {ws.profile.id!r} ist produktiv, und dem "
            f"Katalogeintrag fehlen Pflichtfelder des Metadata Models: {benannt}. "
            "Ohne sie verlaesst nichts das System."
        )

    daten = canonical_bytes(
        {
            "schema": BUNDLE_SCHEMA,
            "bundle_version": BUNDLE_CODE_VERSION,
            "record_id": record_id,
            "release": {
                "approved": upstream_sha,
                "preview": vorschau_sha,
                "actor": _feld(freigabe, "actor", "release.approved"),
            },
            "catalog": {
                "adjudicated": adjudiziert,
                "metadata": {
                    "confirmed": metadaten_sha,
                    "draft": metadaten_entwurf_sha,
                    "fields": metadaten_entwurf.get("fields", {}),
                    "open_requirements": metadaten_entwurf.get("open_requirements", []),
                },
                "abstract": {
                    "confirmed": abstract_sha,
                    "draft": abstract_entwurf_sha,
                    "template_version": abstract_entwurf.get("template_version"),
                    "sections": abstract_entwurf.get("sections", []),
                },
            },
            # ADR 0020: der Analysepfad hat einen eigenen Ausgang. Das Feld
            # steht hier, damit ein Empfaenger es nicht raten muss.
            "analysis_included": False,
        }
    )
    zusammenfassung = {
        "inherits_decision_from": UPSTREAM,
        "open_requirements": len(metadaten_entwurf.get("open_requirements", []) or []),
        "analysis_included": False,
    }
    return daten, zusammenfassung


@dataclass(frozen=True)
class ExportResult:
    artifact_sha256: str
    changed: tuple[str, ...]
    details: dict[str, Any]


def run_export(ctx: Any, view: Any) -> ExportResult:
    """``export``: legt das Bundle ab und belegt es. Der Schritt fuer ``continue``.

    Kein Dateiausgang — dieser Weg erzeugt das Artefakt, mehr nicht. Wer die
    Bytes neben den Datenbaum haben will, nennt ein Ziel (``ohpipe export
    RECORD --output PFAD``).
    """
    plan = plan_export(
        ctx.ws,
        ctx.journal.verified_events(),
        record_id=ctx.record_id,
        output_arg=None,
        authority=Authority.AUTHENTICATED if ctx.journal.key else Authority.UNAUTHENTICATED,
    )
    report = write_export(ctx.ws, ctx.journal, plan)
    return ExportResult(plan.bundle_sha256, tuple(report.changed), report.details)


def plan_export(
    ws: Workspace,
    events: list[Any],
    *,
    record_id: str,
    output_arg: str | None,
    managed_roots: tuple[Path, ...] = (),
    authority: Authority = Authority.UNAUTHENTICATED,
) -> ExportPlan:
    """Plant den Ausgang schreibfrei: Bundlebytes bilden, Ziellage pruefen.

    Die Lage des Ziels wird VOR dem Schreiben geprueft und nicht erst beim
    Schreiben: eine Vorschau, die ein Ziel nennt, das nicht beschreibbar ist,
    waere eine Zusage, die der naechste Schritt bricht.
    """
    upstream_sha = current_inputs(ws, events, record_id, (UPSTREAM,), authority=authority)[UPSTREAM]
    daten, zusammenfassung = build_bundle(ws, record_id, upstream_sha)
    bundle_sha = sha256_bytes(daten)

    ziel: Path | None = None
    parent: Path | None = None
    if output_arg is not None:
        ziel = Path(output_arg)
        parent, art, grund = check_target(ziel, managed_roots)
        if art == "PARTS":
            raise ExportTargetError(
                "Der Ausgabepfad enthaelt eine leere, Punkt- oder Elternkomponente."
            )
        if art == "UNSAFE":
            raise ExportTargetError(f"Sichere Ausgabelage nicht beweisbar: {grund}")

    preview = {
        "action": "export",
        "record": record_id,
        "inherits_decision_from": UPSTREAM,
        "release_approved_sha256": upstream_sha,
        "bundle_sha256": bundle_sha,
        "bundle_bytes": len(daten),
        "planned_registry_effect": "export.bundle",
        "local_output": str(ziel) if ziel is not None else None,
        **zusammenfassung,
    }
    return ExportPlan(record_id, upstream_sha, bundle_sha, daten, ziel, parent, preview)


def write_export(ws: Workspace, journal: Journal, plan: ExportPlan) -> Report:
    """Prüfung, Beleg und Veröffentlichung unter Workspace -> Journalsperre.

    Die Bundlebytes sind vorab geplant. Erst nach Veröffentlichung kann ein
    konkurrierender Journal-Schreiber seinen WITHDRAW wirksam anhängen.
    """
    with workspace_write_lock(ws.root), journal.transaction() as transaction:
        check_planned_inputs(ws, transaction, plan.record_id, {UPSTREAM: plan.upstream_sha256})
        if sha256_bytes(plan.bundle_bytes) != plan.bundle_sha256:
            raise ExportError("Bundleplan wurde veraendert; erneut planen")
        if ws.profile.production:
            bundle = json.loads(plan.bundle_bytes)
            draft = _lies(ws, bundle["catalog"]["metadata"]["draft"], "metadata.draft")
            _halt_wenn_eingabe_gewandert(ws, plan.record_id, draft)
        return _write_export_locked(ws, transaction, plan)


def _write_export_locked(ws, journal, plan):
    evidence_exists = any(
        e.kind == "receipt.recorded"
        and e.record_id == plan.record_id
        and e.payload.get("artifact") == "export.bundle"
        and e.payload.get("output_sha256") == plan.bundle_sha256
        for e in journal
    )
    object_exists = (ws.objects / plan.bundle_sha256).is_file()
    sha, changed = write_derivation(
        ws,
        journal,
        record_id=plan.record_id,
        artifact="export.bundle",
        step="export",
        code_version=BUNDLE_CODE_VERSION,
        data=plan.bundle_bytes,
        inputs={UPSTREAM: plan.upstream_sha256},
        bind=True,
    )
    if object_exists:
        changed = tuple(path for path in changed if path != str(ws.objects / sha))
    details = {
        "bundle_evidence_state": "ALREADY_RECORDED" if evidence_exists else "RECORDED",
        "artifact_sha256": sha,
        "inherits_decision_from": UPSTREAM,
        "local_write_state": "NONE",
    }
    if plan.output is None:
        return b3b_report(
            Status.READY,
            "READY_EXPORT_BUNDLE_WRITTEN" if changed else "READY_EXPORT_BUNDLE_NULLDURCHGANG",
            "Das Katalogbundle liegt im Store und erbt die Freigabeentscheidung."
            if changed
            else "Exakt dieses Katalogbundle ist bereits abgelegt.",
            changed=list(changed),
            operation_result="WRITTEN" if changed else "NULLDURCHGANG",
            details=details,
        )

    assert plan.output_parent is not None  # plan_export hat die Lage aufgeloest
    ergebnis = publish_bytes(
        plan.bundle_bytes,
        plan.output,
        parent=plan.output_parent,
        temp_prefix=".ohpipe-export-bundle.",
    )
    if ergebnis.state == "TARGET_EXISTS":
        return b3b_report(
            Status.STOP,
            "STOP_EXPORT_TARGET_EXISTS",
            "Der Zielname erschien konkurrierend; nichts wurde ueberschrieben."
            if ergebnis.raced
            else "Der lokale Zielname ist bereits belegt.",
            changed=list(changed),
            operation_result="WRITTEN" if changed else "NULLDURCHGANG",
            details={
                **details,
                "local_write_state": "TARGET_VISIBLE_FULL"
                if ergebnis.existing_matches
                else "TARGET_EXISTS",
            },
        )
    if ergebnis.state != "WRITTEN":
        return b3b_report(
            Status.STOP,
            "STOP_EXPORT_PERSISTENCE_UNCERTAIN"
            if ergebnis.published
            else "STOP_EXPORT_WRITE_FAILED",
            f"Lokale Bundleablage fehlgeschlagen: {ergebnis.detail}",
            changed=[*changed, str(plan.output)] if ergebnis.published else list(changed),
            operation_result="UNKNOWN" if ergebnis.published else "NONE",
            details={
                **details,
                "local_write_state": "TARGET_VISIBLE_FULL" if ergebnis.published else "NONE",
            },
        )
    return b3b_report(
        Status.READY,
        "READY_EXPORT_BUNDLE_PUBLISHED",
        "Das Katalogbundle ist abgelegt, belegt und am genannten Ziel sichtbar.",
        changed=[*changed, str(plan.output)],
        operation_result="WRITTEN",
        details={**details, "local_write_state": "TARGET_VISIBLE_FULL"},
    )
