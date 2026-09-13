"""Die Schritt-Registry und der ``continue``-Lauf.

Der Graph sagt, was gilt; die Registry sagt, was gebaut ist. Beides in einer
Tabelle zu führen wäre bequem und falsch: Ein Schritt stünde dann als
ausführbar da, sobald ihn jemand in den Graphen schreibt — und ``continue``
liefe in eine Funktion, die es nicht gibt, oder schlimmer, in eine, die es fast
gibt. Die Registry ist deshalb ein eigenes Objekt mit eigener Prüfung.

Vier Invarianten, aus dem ROADMAP-Entwurf übernommen und hier vollstreckt:

1. **Ein Handler je ausführbarem Schritt.** Ein Schritt ohne Handler ist im
   Graphen, aber nicht gebaut. ``continue`` nennt ihn und empfiehlt ihn nicht.
2. **Outputs entsprechen exakt ``produces``.** Geprüft in
   :func:`check_registry`, in beide Richtungen.
3. **Jeder erzeugbare NEXT existiert und wird von argparse angenommen.** Das
   prüft die Testsuite über den echten Parser; hier steht nur, wie der Befehl
   gebaut wird.
4. **Jeder Handler erzeugt die behaupteten Belege.** Nicht dem Handler
   geglaubt, sondern nach seinem Lauf am Journal nachgelesen: Was er zu
   erzeugen behauptet, muss danach im ``have`` des Records stehen. Sonst hält
   ``continue`` mit ``STOP`` — ein Handler, der behauptet und nicht belegt, ist
   genau die Klasse Fehler, gegen die dieses Repository gebaut ist.

Drei Handlerarten, weil es drei Arten von Schritten gibt, die ``continue``
antrifft: solche, die es selbst ausführen darf (``RUN``), solche, an denen ein
Mensch entscheidet (``GATE``), und solche, die eine Eingabe von aussen brauchen
(``INPUT``). Ein Gate trägt den Befehl, mit dem der Mensch weitermacht; eine
Eingabe trägt die read-only-Diagnose, die sagt, was fehlt. Beides sind
Zeichenketten für den Sechszeiler, keine Aufrufe.

Was ``continue`` NICHT tut: es überspringt kein Gate, es rät keine Eingabe, und
es führt einen teuren Schritt (``cost != "cheap"``) nur nach ausdrücklicher
Bestätigung aus. Der Lauf ist ein Fixpunkt über dem Graphen: nach jedem
ausgeführten Schritt wird der Record neu aus dem Journal abgeleitet, und der
Plan wird neu gerechnet. Es gibt keinen zweiten Zustand neben dem Journal.
"""

from __future__ import annotations

from ohpipe.domain import manual_context

import shlex
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..domain.step import Kind, Step, StepGraph
from ..journal import Journal
from ..policies.exit_contract import Report, Status
from ..project import Workspace
from .replay import RecordView

__all__ = [
    "REGISTRY",
    "ContinueOutcome",
    "Handler",
    "HandlerOutcome",
    "Mode",
    "RegistryError",
    "StepContext",
    "check_registry",
    "continue_record",
    "continue_report",
    "default_registry",
]


class Mode(str, Enum):
    RUN = "run"  # continue führt aus
    GATE = "gate"  # ein Mensch entscheidet; continue nennt den Befehl
    INPUT = "input"  # braucht eine Eingabe von aussen; continue nennt die Diagnose


class RegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class StepContext:
    """Was ein Handler bekommt — und alles, was er bekommt."""

    ws: Workspace
    journal: Journal
    record_id: str
    profile_arg: str
    confirm: bool = False
    #: Bedienoptionen für Handler, die welche kennen (heute: ``fixture`` für
    #: den aufgezeichneten Modelladapter). Zeichenketten, keine Objekte — was
    #: hier steht, muss auch auf einer Kommandozeile stehen können.
    options: dict[str, str] = field(default_factory=dict)

    def command(self, *tokens: str) -> str:
        """Ein Operatorbefehl in der Form, die der Sechszeiler verlangt.

        Dieselbe Form wie die B3b-Bestätigungswege: ``--profile`` und
        ``--root`` ausgeschrieben, damit der Befehl aus jedem Verzeichnis und
        jeder Shell so läuft, wie er dasteht.
        """
        return shlex.join(
            ["ohpipe", "--profile", self.profile_arg, "--root", str(self.ws.root), *tokens]
        )


@dataclass(frozen=True)
class HandlerOutcome:
    changed: tuple[str, ...] = ()
    details: dict[str, Any] = field(default_factory=dict)
    halt: Report | None = None


@dataclass(frozen=True, kw_only=True)
class Handler:
    """Ein Eintrag der Registry. ``kw_only``, weil drei Felder positionell
    vertauschbar wären und die Prüfung im Konstruktor sonst zu spät käme."""

    step: str
    mode: Mode
    produces: tuple[str, ...]
    run: Callable[[StepContext, RecordView], HandlerOutcome] | None = None
    next_command: Callable[[StepContext], str] | None = None
    check_command: Callable[[StepContext], str] | None = None

    def __post_init__(self) -> None:
        if self.mode is Mode.RUN and (self.run is None or self.next_command is not None):
            raise RegistryError(f"{self.step}: RUN verlangt run und verbietet next_command")
        if self.mode is Mode.GATE and (self.next_command is None or self.run is not None):
            raise RegistryError(f"{self.step}: GATE verlangt next_command und verbietet run")
        if self.mode is Mode.INPUT and (self.check_command is None or self.run is not None):
            raise RegistryError(f"{self.step}: INPUT verlangt check_command und verbietet run")


def check_registry(graph: StepGraph, registry: Mapping[str, Handler]) -> list[str]:
    """Registry gegen Graph, in beide Richtungen, als Liste — wie ``check_contracts``.

    Eine Liste und kein Fehler, damit die Prüfung an jeder Stelle brauchbar
    ist: im Test als Zusicherung, im CLI als Halt. Leere Liste = grün.
    """
    verstoesse: list[str] = []
    for name, h in sorted(registry.items()):
        if name != h.step:
            verstoesse.append(f"Schlüssel {name!r} führt einen Handler für {h.step!r}")
        if name not in {s.name for s in graph}:
            verstoesse.append(f"{name!r} ist kein Schritt dieses Graphen")
            continue
        step = graph.get(name)
        if set(h.produces) != set(step.produces):
            verstoesse.append(
                f"{name!r} behauptet {sorted(h.produces)}, der Graph erzeugt "
                f"{sorted(step.produces)}. Outputs entsprechen exakt produces."
            )
        if step.human_gate != (h.mode is Mode.GATE):
            verstoesse.append(
                f"{name!r}: human_gate={step.human_gate}, Handlerart {h.mode.value}. "
                "Ein Gate ist ein Gate und nichts anderes ist eines."
            )
        if h.mode is Mode.INPUT and step.requires:
            verstoesse.append(f"{name!r} braucht {sorted(step.requires)} und ist keine Eingabe")
        if h.mode is Mode.RUN and step.kind is Kind.HUMAN:
            verstoesse.append(f"{name!r} ist menschlich und wird nicht von continue ausgeführt")
    return verstoesse


def default_registry() -> dict[str, Handler]:
    """Was heute gebaut ist. Bewusst kurz — die Liste wächst je Punkt der Strecke.

    ``ingest`` ist eine Eingabe: die Quelldatei kommt von aussen, ``continue``
    kann sie nicht erraten und nennt deshalb keinen NEXT mit Platzhalter, sondern
    die Hilfe des Befehls als CHECK. Genannt wird ``transcript ingest`` und
    nicht das einfache ``ingest``: der Graphschritt ``ingest`` erzeugt
    ``transcript.revision``, und das tut allein der B3b-Weg. Das einfache
    ``ingest`` registriert den Record und legt die Quelle ab — beides
    notwendig, keins davon dieser Schritt. ``transcript.confirm`` ist das erste Gate;
    sein Befehl löst die Instanz und die Vorbedingungen selbst auf und meldet,
    was fehlt — ``continue`` wiederholt diese Prüfung nicht.
    """
    from . import catalog, coverage, export, l1_suggest

    def suggest(ctx: StepContext, view: RecordView) -> HandlerOutcome:
        result = l1_suggest.run_l1_suggest(ctx, view)
        return HandlerOutcome(
            changed=result.changed,
            details={
                "artifact_sha256": result.artifact_sha256,
                "suggestions": result.suggestions,
                "finish_reason": result.finish_reason,
            },
        )

    def cover(ctx: StepContext, view: RecordView) -> HandlerOutcome:
        result = coverage.run_l1_coverage(ctx, view)
        return HandlerOutcome(
            changed=result.changed,
            details={
                "artifact_sha256": result.artifact_sha256,
                "covered": result.covered,
                "total": result.total,
                "passed": result.passed,
                "uncovered": list(result.uncovered),
            },
        )

    def _derivation_handler(runner):
        def run(ctx: StepContext, view: RecordView) -> HandlerOutcome:
            result = runner(ctx, view)
            return HandlerOutcome(changed=result.changed, details=result.details)

        return run

    return {
        "ingest": Handler(
            step="ingest",
            mode=Mode.INPUT,
            produces=("transcript.revision",),
            check_command=lambda ctx: ctx.command("transcript", "ingest", "--help"),
        ),
        "transcript.confirm": Handler(
            step="transcript.confirm",
            mode=Mode.GATE,
            produces=("transcript.confirmed",),
            next_command=lambda ctx: ctx.command("transcript", "confirm", ctx.record_id),
        ),
        # cost="model" im Graphen: continue führt ihn nur mit --confirm aus.
        "l1.suggest": Handler(
            step="l1.suggest",
            mode=Mode.RUN,
            produces=("l1.suggestions",),
            run=suggest,
        ),
        "l1.coverage": Handler(
            step="l1.coverage",
            mode=Mode.RUN,
            produces=("l1.coverage",),
            run=cover,
        ),
        "l1.review": Handler(
            step="l1.review",
            mode=Mode.GATE,
            produces=("l1.adjudicated",),
            next_command=lambda ctx: ctx.command("l1", "review", ctx.record_id),
        ),
        "metadata.derive": Handler(
            step="metadata.derive",
            mode=Mode.RUN,
            produces=("metadata.draft",),
            run=_derivation_handler(catalog.run_metadata_derive),
        ),
        "metadata.confirm": Handler(
            step="metadata.confirm",
            mode=Mode.GATE,
            produces=("metadata.confirmed",),
            next_command=lambda ctx: ctx.command("metadata", "confirm", ctx.record_id),
        ),
        "abstract.derive": Handler(
            step="abstract.derive",
            mode=Mode.RUN,
            produces=("abstract.draft",),
            run=_derivation_handler(catalog.run_abstract_derive),
        ),
        "abstract.confirm": Handler(
            step="abstract.confirm",
            mode=Mode.GATE,
            produces=("abstract.confirmed",),
            next_command=lambda ctx: ctx.command("abstract", "confirm", ctx.record_id),
        ),
        "release.preview": Handler(
            step="release.preview",
            mode=Mode.RUN,
            produces=("release.preview",),
            run=_derivation_handler(catalog.run_release_preview),
        ),
        "release.approve": Handler(
            step="release.approve",
            mode=Mode.GATE,
            produces=("release.approved",),
            next_command=lambda ctx: ctx.command("release", "approve", ctx.record_id),
        ),
        # Billig und ohne eigenes Tor: die Entscheidung ist die der Freigabe
        # und wird geerbt (``export.py``). ``continue`` legt das Bundle deshalb
        # von selbst ab. Nach draussen geht dabei nichts — dafuer braucht es
        # ein genanntes Ziel (``ohpipe export RECORD --output PFAD``).
        "export": Handler(
            step="export",
            mode=Mode.RUN,
            produces=("export.bundle",),
            run=_derivation_handler(export.run_export),
        ),
    }


REGISTRY: dict[str, Handler] = default_registry()


@dataclass(frozen=True)
class ContinueOutcome:
    record_id: str
    executed: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    gates: tuple[Step, ...] = ()
    inputs: tuple[Step, ...] = ()
    deferred: tuple[Step, ...] = ()
    unbuilt: tuple[Step, ...] = ()
    findings: tuple[str, ...] = ()
    failure: str | None = None
    #: Klassenname der Ausnahme hinter ``failure`` — ``TruncatedOutput``,
    #: ``UnauthorisedRun``, ``SuggestError`` — damit ein Leser des JSON den
    #: Grund sortieren kann, ohne den Text zu parsen.
    failure_kind: str | None = None
    halt: Report | None = None

    @property
    def complete(self) -> bool:
        return not (
            self.gates
            or self.inputs
            or self.deferred
            or self.unbuilt
            or self.findings
            or self.failure
            or self.halt
        )


def continue_record(
    ctx: StepContext,
    *,
    graph: StepGraph,
    registry: Mapping[str, Handler],
    view_of: Callable[[], RecordView | None],
) -> ContinueOutcome:
    """Der Lauf: ausführen, was billig und gebaut ist; alles andere benennen.

    ``view_of`` liefert den Record neu aus dem Journal — vor dem ersten Schritt
    und nach jedem weiteren. Der Handler bekommt keine Gelegenheit, seinen
    Erfolg selbst zu melden: gezählt wird, was danach im ``have`` steht.
    """
    executed: list[str] = []
    changed: list[str] = []
    attempted: set[str] = set()
    while True:
        view = view_of()
        if view is None:
            return ContinueOutcome(ctx.record_id, failure="Record ist nach dem Lauf unbekannt")
        from .storage_integrity import ProtectionConfigurationFinding

        config_only = bool(view.findings) and all(
            isinstance(f, ProtectionConfigurationFinding) for f in view.findings
        )
        if config_only:
            return ContinueOutcome(
                ctx.record_id,
                tuple(executed),
                tuple(changed),
                halt=Report(
                    status=Status.CONFIG,
                    reason=str(view.findings[0]),
                    reason_code="CONFIG_P4B",
                    check=ctx.command("--json", "doctor"),
                    details={"failure_kind": "ProtectionConfig"},
                ),
            )
        if view.findings:
            return ContinueOutcome(
                ctx.record_id, tuple(executed), tuple(changed), findings=tuple(view.findings)
            )
        candidate = next(
            (
                (s, registry[s.name])
                for s in graph.next_steps(view.have)
                if s.name not in attempted
                and s.name in registry
                and registry[s.name].mode is Mode.RUN
                and (s.cost == "cheap" or ctx.confirm)
            ),
            None,
        )
        if candidate is None:
            break
        step, handler = candidate
        attempted.add(step.name)
        try:
            outcome = handler.run(ctx, view)  # type: ignore[misc]  # RUN garantiert run
        except (RuntimeError, ValueError, OSError) as exc:
            return ContinueOutcome(
                ctx.record_id,
                tuple(executed),
                tuple(changed),
                failure=f"{step.name} ist gescheitert ({type(exc).__name__}): {exc}",
                failure_kind=type(exc).__name__,
            )
        if outcome.halt is not None:
            return ContinueOutcome(
                ctx.record_id, tuple(executed), tuple(changed), halt=outcome.halt
            )
        executed.append(step.name)
        changed.extend(outcome.changed)
        after = view_of()
        missing = sorted(set(handler.produces) - (after.have if after else set()))
        if missing:
            return ContinueOutcome(
                ctx.record_id,
                tuple(executed),
                tuple(changed),
                failure=(
                    f"{step.name} behauptet {missing}, das Journal belegt es nicht. "
                    "Ein Handler, der behauptet und nicht belegt, hält den Lauf an."
                ),
            )

    # ``next_steps`` und nicht ``plan().gates``: der Plan trägt JEDEN erreichbaren
    # Halt ein, auch einen hinter einem Schritt, der erst noch laufen müsste
    # (ADR 0021 — richtig für die Statusanzeige). Hier zählt nur, was JETZT an
    # der Tür steht: ein Gate, dessen Voraussetzungen im ``have`` liegen. Sonst
    # meldete ``continue`` für einen leeren Record „hält vor transcript.confirm"
    # und verschwiege, dass zuerst die Eingabe fehlt — gemessen an einem Record
    # mit ``record.registered`` und ``source.ingested``, aber ohne Artefakt.
    pending = graph.next_steps(view.have)
    return ContinueOutcome(
        ctx.record_id,
        tuple(executed),
        tuple(changed),
        gates=tuple(s for s in pending if s.human_gate and s.name in registry),
        inputs=tuple(
            s for s in pending if s.name in registry and registry[s.name].mode is Mode.INPUT
        ),
        deferred=tuple(
            s
            for s in pending
            if s.name in registry and registry[s.name].mode is Mode.RUN and s.cost != "cheap"
        ),
        unbuilt=tuple(s for s in pending if s.name not in registry),
    )


def _done(outcome: ContinueOutcome) -> str:
    if not outcome.executed:
        return "Nichts auszuführen"
    return f"Ausgeführt: {', '.join(outcome.executed)}"


def continue_report(
    outcome: ContinueOutcome, ctx: StepContext, registry: Mapping[str, Handler]
) -> Report:
    """Der Sechszeiler zum Lauf. Rangfolge: Befund, Fehlschlag, Gate, Eingabe,
    Bestätigung, nicht gebaut, fertig — vom Ventil zum Menschen zum Grün."""
    status_cmd = ctx.command("status")
    common: dict[str, Any] = {
        "record_id": outcome.record_id,
        "executed": list(outcome.executed),
        "gates": [g.name for g in outcome.gates],
        "inputs": [s.name for s in outcome.inputs],
        "deferred": [s.name for s in outcome.deferred],
        "unbuilt": [s.name for s in outcome.unbuilt],
        "failure_kind": outcome.failure_kind,
    }
    if outcome.findings:
        return Report(
            status=Status.STOP,
            reason=f"{outcome.record_id} trägt Befunde; continue führt nichts aus: "
            + outcome.findings[0],
            reason_code="STOP_CONTINUE_FINDINGS",
            changed=list(outcome.changed),
            check=status_cmd,
            details={**common, "findings": list(outcome.findings)},
        )
    if outcome.halt is not None:
        from dataclasses import replace

        return replace(
            outcome.halt,
            changed=[*outcome.changed, *outcome.halt.changed],
            details={**common, **outcome.halt.details},
        )
    if outcome.failure is not None:
        return Report(
            status=Status.STOP,
            reason=f"{_done(outcome)}; {outcome.failure}",
            reason_code="STOP_CONTINUE_HANDLER",
            changed=list(outcome.changed),
            check=status_cmd,
            details=common,
        )
    if outcome.gates:
        gate = outcome.gates[0]
        return Report(
            status=Status.ACTION_NEEDED,
            reason=f"{_done(outcome)}; hält vor {gate.name}: {gate.description}",
            reason_code="ACTION_CONTINUE_GATE",
            changed=list(outcome.changed),
            next_command=registry[gate.name].next_command(ctx)  # type: ignore[misc]
            if gate.name in registry
            else None,
            check=status_cmd if gate.name not in registry else None,
            details=common,
        )
    if outcome.inputs:
        step = outcome.inputs[0]
        return Report(
            status=Status.ACTION_NEEDED,
            reason=f"{_done(outcome)}; {step.name} braucht eine Eingabe von aussen: "
            f"{step.description}",
            reason_code="ACTION_CONTINUE_INPUT_REQUIRED",
            changed=list(outcome.changed),
            check=registry[step.name].check_command(ctx),  # type: ignore[misc]
            details=common,
        )
    if outcome.deferred:
        step = outcome.deferred[0]
        return Report(
            status=Status.ACTION_NEEDED,
            reason=f"{_done(outcome)}; {step.name} ist ein {step.cost}-Schritt und läuft "
            "nur nach ausdrücklicher Bestätigung",
            reason_code="ACTION_CONTINUE_CONFIRM_REQUIRED",
            changed=list(outcome.changed),
            next_command=ctx.command("continue", ctx.record_id, "--confirm"),
            details=common,
        )
    if outcome.unbuilt:
        step = outcome.unbuilt[0]
        # Kein NEXT: ein noch nicht gebauter Befehl wird nicht empfohlen.
        return Report(
            status=Status.ACTION_NEEDED,
            reason=f"{_done(outcome)}; {step.name} steht im Graphen, ist aber noch nicht "
            "gebaut (kein Handler registriert). continue empfiehlt nichts, was es nicht gibt.",
            reason_code="ACTION_CONTINUE_NOT_BUILT",
            changed=list(outcome.changed),
            check=status_cmd,
            details=common,
        )
    return Report(
        status=Status.READY,
        reason=f"{_done(outcome)}; der Graph ist für {outcome.record_id} vollständig",
        reason_code="READY_CONTINUE_COMPLETE",
        changed=list(outcome.changed),
        details=common,
    )


def registry_for(profile):
    """P4b ist explizit profilgebunden; Modell-pseudonymise bleibt ungebaut."""
    if not manual_context.enabled(profile):
        return REGISTRY
    from .manual_work import Session
    from .gate import GateError, GateBlocked
    from ..protected_store import ProtectionError

    def draft(ctx, view):
        try:
            session = Session(ctx, "pseudonymise")
            session.publish()
        except (GateError, ProtectionError) as exc:
            # Ausschließlich der neue P4b-Handler transportiert erwartbare Halte.
            # GateBlocked und Integritätsfehler behalten die bisherige STOP-Diagnose.
            if isinstance(exc, GateBlocked) or isinstance(exc, ProtectionError) and exc.code == 1:
                raise
            code = exc.code if isinstance(exc, ProtectionError) else 3
            next_command = None
            if code == 3:
                next_command = ctx.command("continue", ctx.record_id)
                if isinstance(exc, GateError):
                    from .freshness import repair_command
                    from .replay import replay
                    from ..policies.authority import Authority
                    from ..domain.step import build_graph

                    current = replay(
                        list(ctx.journal),
                        graph=build_graph(ctx.ws.profile),
                        authority=Authority.AUTHENTICATED,
                    ).get(ctx.record_id)
                    if current is None or current.findings:
                        raise GateBlocked("Record fehlt oder Replay enthält Befunde") from exc
                    next_command = repair_command(ctx, current)
            return HandlerOutcome(
                halt=Report(
                    status={2: Status.CONFIG, 3: Status.ACTION_NEEDED}[code],
                    reason=str(exc),
                    reason_code={2: "CONFIG_P4B", 3: "ACTION_P4B"}[code],
                    next_command=next_command,
                    check=ctx.command("--json", "doctor"),
                    details={"failure_kind": type(exc).__name__},
                )
            )
        return HandlerOutcome(details={"protected": True})

    def finalise(ctx, view):
        from .finalisation import Work

        try:
            Work(ctx).finalise()
        except (GateError, ProtectionError) as exc:
            if isinstance(exc, GateBlocked) or isinstance(exc, ProtectionError) and exc.code == 1:
                raise
            code = exc.code if isinstance(exc, ProtectionError) else 3
            return HandlerOutcome(
                halt=Report(
                    status={2: Status.CONFIG, 3: Status.ACTION_NEEDED}[code],
                    reason=str(exc),
                    reason_code={2: "CONFIG_P4C", 3: "ACTION_P4C"}[code],
                    next_command=ctx.command(
                        *getattr(exc, "command", ("pseudonymise", "finalise", ctx.record_id))
                    )
                    if code == 3
                    else None,
                )
            )
        return HandlerOutcome(details={"protected": True})

    return {
        **REGISTRY,
        "pseudonymise.finalise": Handler(
            step="pseudonymise.finalise",
            mode=Mode.RUN,
            produces=("transcript.pseudonymised.final", "replacement.report"),
            run=finalise,
        ),
        "pseudonymisation.review": Handler(
            step="pseudonymisation.review",
            mode=Mode.GATE,
            produces=("transcript.pseudonymised.confirmed",),
            next_command=lambda c: c.command("pseudonymisation", "review", c.record_id),
        ),
        "pii.mark": Handler(
            step="pii.mark",
            mode=Mode.GATE,
            produces=("pii.spans",),
            next_command=lambda c: c.command("pii", "mark", c.record_id),
        ),
        "pseudonymise": Handler(
            step="pseudonymise",
            mode=Mode.RUN,
            produces=("transcript.pseudonymised.draft",),
            run=draft,
        ),
        "pseudonymisation.cases": Handler(
            step="pseudonymisation.cases",
            mode=Mode.GATE,
            produces=("pseudonymisation.cases",),
            next_command=lambda c: c.command("pseudonymisation", "cases", c.record_id),
        ),
    }
