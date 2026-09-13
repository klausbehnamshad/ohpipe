"""Bewusst geöffneter lokaler P4b-Dialog; keine Nutzlast in argv oder JSON."""

from ohpipe.domain import manual_context

import json
import sys
import shlex

from ..project import ProfileError
from ..policies.ownership import OwnershipError

from ..application.manual_work import Session, recover
from ..application.gate import GateError, GateBlocked
from ..application.confirmed_text import ConfirmedTextError
from ..application.steps import StepContext
from ..domain.manual_pseudonymisation import ManualError, counts, render, bound
from ..domain.pii import SpanError
from ..policies.exit_contract import Report, Status
from ..protected_store import ProtectionError, ProtectionConfig, canonical, digest
from .ui import confirmed, is_english, text


def _session_choice(value: str) -> str:
    if not is_english():
        return value
    return {"new": "neu", "resume": "fortsetzen", "close": "schließen"}.get(value.lower(), value)


def _action(value: str) -> str:
    if not is_english():
        return value
    return {
        "mark": "markieren",
        "exclude": "ausschließen",
        "save": "speichern",
        "confirm": "bestätigen",
        "close": "schließen",
        "defer": "zurückstellen",
        "resolve": "auflösen",
        "correct": "korrigieren",
        "context": "kontext",
    }.get(value.lower(), value)


def show(session):
    print(text("ENTWURF — NICHT FREIGEGEBEN", "DRAFT — NOT APPROVED"))
    print(
        text(
            "Cue und Codepointgrenzen [start,end); Codepoints sind keine Bildschirmspalten.",
            "Cue and code-point bounds [start,end); code points are not screen columns.",
        )
    )
    for i, segment in enumerate(session.source.segments):
        print(f"Cue {i} / Segment {segment.index}: {segment.text}")
        for span in bound(session.source, session.capsule["spans"]).for_cue(i):
            print(
                f"  {span.mention_id} [{span.start},{span.end}) {span.entity_type.value}: {segment.text[span.start : span.end]}"
            )
    print(
        text(
            "Provisorische Gruppen (keine stabile Registerresolution):",
            "Provisional groups (no stable registry resolution):",
        )
    )
    for gid, group in sorted(session.capsule["groups"].items()):
        print(gid, group["type"], group["state"], " ".join(group["mentions"]))
    print(
        text("Gesichert:", "Saved:"),
        session.revision,
        text("Zählungen:", "Counts:"),
        json.dumps(counts(session.capsule)),
    )
    if session.phase == "pseudonymisation.cases":
        from ..domain.revision_serialization import verify_revision

        raw = render(session.source, session.capsule, session.policy)
        preview = verify_revision(raw, digest(raw))
        print(text("ENTWURF — NICHT FREIGEGEBEN\n", "DRAFT — NOT APPROVED\n") + preview.text)
        print(text("Sitzungskontext:", "Session context:"), session.capsule["context"])


def dialog(ctx, phase, actor):
    choice = input(
        text(
            "Sitzung: neu / fortsetzen / recovery / schließen: ",
            "Session: new / resume / recovery / close: ",
        )
    ).strip()
    choice = _session_choice(choice)
    if choice == "schließen":
        return text("Geschlossen; nichts gespeichert", "Closed; nothing saved")
    if choice == "recovery":
        recover(ctx, actor)
        return text("Belegte unterbrochene Akte geprüft", "Recorded interrupted action checked")
    if choice not in ("neu", "fortsetzen"):
        raise GateError(text("Sitzungsakt nicht gewählt", "No session action selected"))
    session = Session(ctx, phase, actor, resume=choice == "fortsetzen")
    while True:
        show(session)
        print(
            text(
                "Aktionen: markieren Cue Start Ende Typ | ausschließen Mention | speichern | bestätigen | schließen",
                "Actions: mark Cue Start End Type | exclude Mention | save | confirm | close",
            )
        )
        if phase == "pseudonymisation.cases":
            print(
                text(
                    "Fälle: merge Gruppe Gruppe… | split Gruppe Mention,Mention;Mention… | zurückstellen Gruppe | auflösen Gruppe | korrigieren Mention Cue Start Ende Typ | kontext",
                    "Cases: merge Group Group… | split Group Mention,Mention;Mention… | defer Group | resolve Group | correct Mention Cue Start End Type | context",
                )
            )
        command = input(text("Aktion: ", "Action: ")).split()
        if command:
            command[0] = _action(command[0])
        if not command or command[0] == "schließen":
            return text(
                "Geschlossen; letzter gesicherter Stand bleibt erhalten",
                "Closed; the last saved state remains available",
            )
        try:
            action, *args = command
            if action == "markieren" and len(args) == 4:
                session.add(*map(int, args[:3]), args[3])
            elif action == "ausschließen" and len(args) == 1:
                session.exclude(args[0])
            elif action == "speichern" and not args:
                session.save()
                print(
                    text(
                        "Editorstand dauerhaft gesichert; keine Decision.",
                        "Editor state saved; no decision recorded.",
                    )
                )
            elif action == "bestätigen" and not args:
                # Erst sichern, dann genau DIESE gespeicherte Fassung anzeigen.
                if session.saved_bytes != canonical(session.capsule):
                    session.save()
                show(session)
                displayed = digest(canonical(session.capsule))
                if confirmed(
                    input(
                        text(
                            "Diese angezeigte Sitzungsfassung dokumentieren? BESTÄTIGEN: ",
                            "Record this displayed session version? CONFIRM: ",
                        )
                    )
                ):
                    session.publish(displayed=displayed)
                    return text(
                        "Sitzung dokumentiert; keine finale Textfreigabe",
                        "Session recorded; this is not final text approval",
                    )
            elif phase == "pseudonymisation.cases" and action == "merge":
                session.merge(args)
            elif phase == "pseudonymisation.cases" and action == "split" and len(args) == 2:
                session.split(args[0], [part.split(",") for part in args[1].split(";")])
            elif (
                phase == "pseudonymisation.cases"
                and action in ("zurückstellen", "auflösen")
                and len(args) == 1
            ):
                session.state(args[0], "DEFERRED" if action == "zurückstellen" else "RESOLVED")
            elif phase == "pseudonymisation.cases" and action == "korrigieren" and len(args) == 5:
                session.add(*map(int, args[1:4]), args[4], old=args[0])
            elif phase == "pseudonymisation.cases" and action == "kontext" and not args:
                session.capsule["context"] = input(
                    text(
                        "Lokaler geschützter Sitzungskontext: ", "Protected local session context: "
                    )
                )
            else:
                print(text("Aktion nicht erkannt; keine Änderung.", "Unknown action; no change."))
        except (ManualError, SpanError, KeyError, ValueError):
            print(
                text(
                    "Aktion verletzt den Positions-/Fallvertrag; keine gültige neue Fassung.",
                    "Action violates the position or case rules; no valid new version.",
                )
            )


def command(args):
    from .main import _workspace, _journal_or_stop, _graph_binding_or_halt

    check = shlex.join(
        [
            "ohpipe",
            "--profile",
            args.profile,
            *(["--root", str(args.root)] if args.root else []),
            "--json",
            "doctor",
        ]
    )
    if args.p4b_phase == "pseudonymise" and (
        (args.record == "finalise") != bool(args.final_record)
    ):
        return Report(
            status=Status.CONFIG,
            reason="Syntax: pseudonymise RECORD oder pseudonymise finalise RECORD",
            reason_code="CONFIG_P4C_ARGUMENTS",
            check=check,
        )
    if args.p4b_phase == "pseudonymise" and args.record == "finalise":
        from .finalisation import command as final_command

        args.record = args.final_record
        args.p4c_phase = "finalise"
        return final_command(args)
    try:
        ws = _workspace(args)
        journal, stop = _journal_or_stop(ws)
        if stop:
            return stop
        halt = _graph_binding_or_halt(ws, args.profile)
        if halt:
            return halt
        if not manual_context.enabled(ws.profile):
            raise ProtectionConfig("Manualpfad ist für dieses Profil nicht gebaut")
        ctx = StepContext(
            ws=ws,
            journal=journal,
            record_id=ws.profile.normalize_record_id(args.record),
            profile_arg=args.profile,
        )
        phase = args.p4b_phase
        if phase != "pseudonymise":
            if args.json or not all(s.isatty() for s in (sys.stdin, sys.stdout, sys.stderr)):
                raise ProtectionConfig(
                    "Markierungs-/Fallansicht verlangt einen bewusst geöffneten lokalen Terminaldialog"
                )
            reason = dialog(ctx, phase, args.actor)
        else:
            s = Session(ctx, phase, args.actor)
            role = "transcript.pseudonymised.draft"
            if role in s.view.have:
                from ..application.manual_work import reference

                old = s.store.open(reference(s.view, role), ctx.record_id)
                if old != render(s.source, s.capsule, s.policy):
                    raise ProtectionError("Draft widerspricht gebundenem Plan")
            else:
                s.publish()
            reason = "Provisorischer Draft geschützt abgelegt; keine finale Textfreigabe"
        return Report(
            status=Status.READY,
            reason=reason,
            reason_code="READY_P4B_ACT",
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
        status = {1: Status.STOP, 2: Status.CONFIG, 3: Status.ACTION_NEEDED}[code]
        return Report(
            status=status,
            reason=str(exc),
            reason_code={1: "STOP_P4B", 2: "CONFIG_P4B", 3: "ACTION_P4B"}[code],
            check=check,
        )
    except (ProfileError, OwnershipError):
        raise
    except (OSError, ValueError, KeyError, EOFError, KeyboardInterrupt):
        return Report(
            status=Status.STOP,
            reason="P4b-Akt abgebrochen; letzten dauerhaft belegten Stand prüfen",
            reason_code="STOP_P4B_IO",
            check=check,
        )


def parsers(sub, common):
    for name, action, phase in (
        ("pii", "mark", "pii.mark"),
        ("pseudonymisation", "cases", "pseudonymisation.cases"),
        ("pseudonymise", None, "pseudonymise"),
    ):
        parent = sub.add_parser(name, help="Lokale synthetische P4b-Arbeit")
        if action:
            nested = parent.add_subparsers(required=True)
            parser = nested.add_parser(action)
            if name == "pseudonymisation":
                from .finalisation import parsers as final_parsers

                final_parsers(nested, common)
        else:
            parser = parent
        common(parser)
        parser.add_argument("record")
        if name == "pseudonymise":
            parser.add_argument("final_record", nargs="?")
        parser.add_argument("--actor")
        parser.set_defaults(fn=command, p4b_phase=phase)
