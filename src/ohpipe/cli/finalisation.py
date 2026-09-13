"""Bewusste lokale P4c-Akte; keine Schutzinhalte in Argumenten oder JSON."""

from ohpipe.domain import manual_context

import sys
import shlex

from ..application.steps import StepContext
from ..application import finalisation as work
from ..application.gate import GateError, GateBlocked
from ..application.confirmed_text import ConfirmedTextError
from ..registry_store import REPORT
from ..protected_store import ProtectionError, ProtectionConfig, canonical, digest
from ..policies.exit_contract import Report, Status
from ..domain.revision_serialization import verify_revision
from .ui import confirmed, is_english, text


def _resolution_answer(value: str) -> str:
    if not is_english():
        return value
    return {"new": "neu", "close": "schließen"}.get(value.lower(), value)


def command(args):
    from .main import _workspace, _journal_or_stop, _graph_binding_or_halt

    check = shlex.join(
        [
            "ohpipe",
            "--profile",
            str(args.profile),
            *(["--root", str(args.root)] if args.root else []),
            "--json",
            "doctor",
        ]
    )
    try:
        ws = _workspace(args)
        journal, halt = _journal_or_stop(ws)
        if halt:
            return halt
        halt = _graph_binding_or_halt(ws, args.profile)
        if halt:
            return halt
        if not manual_context.enabled(ws.profile):
            raise ProtectionConfig("Finalisierung ist für dieses Profil nicht gebaut")
        phase = args.p4c_phase
        if phase in ("resolve", "review") and (
            args.json or not all(s.isatty() for s in (sys.stdin, sys.stdout, sys.stderr))
        ):
            raise ProtectionConfig(
                "P4c-Ansicht verlangt einen bewusst geöffneten lokalen Terminaldialog"
            )
        ctx = StepContext(
            ws=ws,
            journal=journal,
            record_id=ws.profile.normalize_record_id(args.record)
            if getattr(args, "record", None)
            else "",
            profile_arg=args.profile,
        )
        if phase == "init":
            work.initialise(ctx)
        elif phase == "recovery":
            work.recover(ctx, args.actor)
        else:
            session = work.Work(ctx, args.actor)
            if phase == "resolve":
                print(
                    text(
                        "IDENTITÄTSRESOLUTION — KEINE FINALE TEXTFREIGABE",
                        "IDENTITY RESOLUTION — NOT FINAL TEXT APPROVAL",
                    )
                )
                print(session.source.text)
                for gid, group in sorted(session.capsule["groups"].items()):
                    print(
                        text("Gruppe", "Group"),
                        gid,
                        group["type"],
                        "Mentions",
                        ",".join(group["mentions"]),
                    )
                    print(
                        text(
                            "Kandidaten (niemals automatisch übernommen):",
                            "Candidates (never selected automatically):",
                        ),
                        ",".join(session.candidates(gid)) or text("keine", "none"),
                    )
                    answer = input(
                        text(
                            "Explizit neu oder vorhandene Entity-ID; schließen: ",
                            "Enter new or an existing entity ID; close: ",
                        )
                    ).strip()
                    answer = _resolution_answer(answer)
                    if answer == "schließen":
                        raise GateError(
                            text(
                                "Resolution abgebrochen; kein bestätigter Akt",
                                "Resolution aborted; no action confirmed",
                            )
                        )
                    session.choose(gid, None if answer == "neu" else answer)
                print(
                    text("Gewählte Zuordnungen:", "Selected assignments:"),
                    canonical(session.resolution["assignments"]).decode(),
                )
                if not confirmed(
                    input(
                        text(
                            "Diese vollständige Identitätszuordnung bestätigen? BESTÄTIGEN: ",
                            "Confirm this complete identity assignment? CONFIRM: ",
                        )
                    )
                ):
                    raise GateError(text("Resolution nicht bestätigt", "Resolution not confirmed"))
                session.accept_resolution(digest(canonical(session.resolution)))
            elif phase == "finalise":
                session.finalise()
            elif phase == "review":
                inputs, raw, report = session.review_material()
                print(text("FINALISIERT — NICHT FREIGEGEBEN", "FINALISED — NOT APPROVED"))
                print(text("Originalbezug:", "Original reference:"), session.source.sha256)
                final_revision = verify_revision(raw, digest(raw))
                print(final_revision.text)
                for segment in final_revision.segments:
                    print(
                        text(
                            f"Segment {segment.index} / Sprecherkennung: {segment.speaker} / Sprache: {segment.language}",
                            f"Segment {segment.index} / speaker: {segment.speaker} / language: {segment.language}",
                        )
                    )
                print(
                    text("Fallbilanz:", "Case totals:"),
                    report["counts"],
                    text("Aktionsbilanz:", "Action totals:"),
                    report["sums"],
                )
                print(
                    text(
                        "Automatische Trennung: nicht anwendbar; ausschließlich manuelle Markierungen.",
                        "Automatic separation: not applicable; only manual markings are used.",
                    )
                )
                if not confirmed(
                    input(
                        text(
                            "Ich habe den vollständigen Text gelesen und die markierten Stellen geprüft. BESTÄTIGEN: ",
                            "I have read the complete text and checked the marked passages. CONFIRM: ",
                        )
                    )
                ):
                    raise GateError(
                        text("Finaler Text nicht bestätigt", "Final text not confirmed")
                    )
                displayed = digest(
                    canonical({"final": digest(raw), "report": inputs[REPORT][0], "basis": inputs})
                )
                session.accept_text(displayed, inputs)
        return Report(
            status=Status.READY,
            reason="P4c-Akt abgeschlossen",
            reason_code="READY_P4C_ACT",
            details={"phase": phase},
        )
    except (ProtectionError, GateError, ConfirmedTextError) as exc:
        code = (
            exc.code
            if isinstance(exc, ProtectionError)
            else 1
            if isinstance(exc, GateBlocked)
            else 3
        )
        return Report(
            status={1: Status.STOP, 2: Status.CONFIG, 3: Status.ACTION_NEEDED}[code],
            reason=str(exc),
            reason_code={1: "STOP_P4C", 2: "CONFIG_P4C", 3: "ACTION_P4C"}[code],
            check=check,
            next_command=ctx.command(*exc.command)
            if isinstance(exc, work.FinalisationAction)
            else None,
        )
    except (EOFError, KeyboardInterrupt):
        return Report(
            status=Status.ACTION_NEEDED,
            reason="P4c-Akt abgebrochen; kein neuer ACCEPT",
            reason_code="ACTION_P4C_ABORT",
            check=check,
        )
    except (OSError, ValueError, KeyError, TypeError):
        return Report(
            status=Status.STOP,
            reason="P4c-Akt oder Schutzvertrag nicht prüfbar",
            reason_code="STOP_P4C_IO",
            check=check,
        )


def parsers(nested, common):
    for name in ("resolve", "review", "recovery"):
        p = nested.add_parser(name)
        common(p)
        p.add_argument("record")
        p.add_argument("--actor")
        p.set_defaults(fn=command, p4c_phase=name)
    registry = nested.add_parser("registry").add_subparsers(required=True)
    p = registry.add_parser("init")
    common(p)
    p.set_defaults(fn=command, p4c_phase="init")
