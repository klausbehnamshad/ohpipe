"""O-1: direkte Evidenzbindungen, danach transitive Sperrung bis zum Fixpunkt."""

from ohpipe.domain import manual_context

from ..domain.decision import Verdict
from ..domain.state import DerivationState
from ..domain.step import GraphError, confirmed_text_role

EXTRA_ROLES = {"l1.suggestions": "l1.codebook", "metadata.draft": "metadata.input"}


def repair_step(view, artifact):
    """Tatsächlicher Graphschritt; die Oberfläche ergänzt Profil und Wurzel."""
    return view.graph.producer_of(artifact).name


def current_roles(view, artifact):
    step = view.graph.producer_of(artifact)
    roles = set(step.requires)
    if step.confirms is None:
        try:
            role = confirmed_text_role(view.graph, step.name)
        except GraphError:
            pass
        else:
            roles.add(role[2])
    return roles


def evaluate(view):
    """Keine gespeicherten Statusereignisse, keine Dateisystembeobachtung."""
    dependencies = {}
    for name, facts in view.facts.items():
        facts.freshness = None
        facts.freshness_reason = ""
        dependencies[name] = current_roles(view, name)
        if facts.sha256 is None:
            continue
        refs = facts.receipt_inputs if facts.receipt_for else None
        if refs is not None:
            _check_refs(view, facts, refs, facts.receipt_seq, receipt=True)
        decision = view.effective_decision_by_artifact.get(name)
        if decision and decision.verdict is Verdict.ACCEPT and not facts.is_egress:
            # P3_MUTATION_CONTEXT: Entscheidung und tatsächlicher Laufkontext.
            if _foreign_context(decision, view.graph):
                _fail(
                    view,
                    facts,
                    "Entscheidungskontext",
                    "Profil-/Graphbindung passt nicht",
                    missing=True,
                )
            step = view.graph.producer_of(name)
            if step.confirms and decision.input_refs_version != 4:
                key = "transcript" if decision.input_refs_version == 1 else "text"
                refs = (
                    {step.confirms: decision.input_refs[key]} if key in decision.input_refs else {}
                )
            else:
                refs = dict(decision.input_refs)
            _check_refs(view, facts, refs, facts.decision_seq, receipt=False)

    # P3_MUTATION_TRANSITIVE: gleicher Hash ist kein Ersatz für gültige Herkunft.
    changed = True
    while changed:
        changed = False
        for name, required in dependencies.items():
            facts = view.facts[name]
            if facts.sha256 is None or facts.freshness is not None:
                continue
            for role in sorted(required):
                source = view.facts.get(role)
                if source is None or not source.usable(view.enabled):
                    root = source.freshness_reason if source else ""
                    _fail(
                        view, facts, role, "abhängige Quelle nicht nutzbar", missing=source is None
                    )
                    if root:
                        facts.freshness_reason += "; Ursache: " + root
                        facts.repair = source.repair
                    changed = True
                    break

    # Auch bereits direkt veraltete Folgebelege zeigen die früheste Ursache.
    # Diese Runde erläutert nur die berechnete Sperre; sie erzeugt keinen Zustand.
    for step in view.graph.topological():
        for name in step.produces:
            facts = view.facts.get(name)
            if facts is None or facts.freshness is None:
                continue
            for role in sorted(dependencies[name]):
                source = view.facts.get(role)
                if source is not None and source.freshness is not None:
                    facts.freshness_reason = (
                        f"{name}: {role}: abhängige Quelle nicht nutzbar; "
                        f"Ursache: {source.freshness_reason}"
                    )
                    facts.repair = source.repair
                    break


def _foreign_context(decision, graph):
    return (
        decision.profile_id is not None or decision.input_refs_version in (2, 3, 4)
    ) and not graph.matches_context(decision.profile_id, decision.graph_sha256)


def _fail(view, facts, role, why, *, missing=False):
    if facts.freshness is not None:
        return
    facts.freshness = DerivationState.UNVERIFIABLE if missing else DerivationState.STALE
    step = repair_step(view, facts.name)
    if role in EXTRA_ROLES.values() and not view.sources.get(role, (None, 0))[0]:
        step = "sources refresh"
    elif role in view.graph.artifacts and role not in view.facts:
        step = repair_step(view, role)
    facts.repair = step
    facts.freshness_reason = f"{facts.name}: {role}: {why}; nächster Schritt: {step}"


def _check_refs(view, facts, refs, seq, *, receipt):
    required = current_roles(view, facts.name)
    sources = {}
    if receipt and facts.name == "transcript.revision":
        if facts.receipt_kind == "transcript.fulltext.segment_projection.v1":
            required = {"srt", "language_assignment"}
        elif facts.receipt_kind == "transcript.fulltext.separate_input.v1":
            required = {"source"}
        else:
            _fail(view, facts, "Eingaberolle", "Belegart nicht deklariert", missing=True)
            return
        sources = {role: view.sources.get(role) for role in required}
    else:
        sources = {
            role: (view.facts[role].sha256, view.facts[role].epoch) if role in view.facts else None
            for role in required
        }
    extra = EXTRA_ROLES.get(facts.name) if receipt else None
    if extra and (extra in refs or view.sources.get(extra, (None, 0))[0] is not None):
        required.add(extra)
        sources[extra] = view.sources.get(extra)
    from ..domain.p4b_events import ROLES, POLICY

    if manual_context.known(view.graph.profile_id) and facts.name in ROLES.values():
        required.add(POLICY)
        sources[POLICY] = view.sources.get(POLICY)
    from ..domain.p4c_events import FINAL_INPUTS, REVIEW_INPUTS
    from ..registry_store import FINAL, REPORT, GATE

    if manual_context.known(view.graph.profile_id) and facts.name in (FINAL, REPORT, GATE):
        required = set(REVIEW_INPUTS if facts.name == GATE else FINAL_INPUTS)
        sources = {
            role: (
                (view.facts[role].sha256, view.facts[role].epoch)
                if role in view.facts
                else view.sources.get(role)
            )
            for role in required
        }
    historical = {"previous"} if receipt and facts.name == "transcript.revision" else set()
    # P3_MUTATION_EXTRA: Rollenauflösung, nicht bloß Prüfung bekannter Schlüssel.
    if set(refs) - required - historical:
        _fail(view, facts, "Eingaberolle", "nicht deklariert", missing=True)
        return
    for role in sorted(required):
        source = sources.get(role)
        if role not in refs or source is None or source[0] is None:
            _fail(view, facts, role, "Referenz oder belegte Quelle fehlt", missing=True)
            continue
        # P3_MUTATION_DIRECT: Digest UND Journalaktivierung der aktuellen Quelle.
        if refs[role] != source[0] or seq < source[1]:
            _fail(view, facts, role, "Eingabebindung veraltet")
    for role in historical & set(refs):
        if refs[role] not in facts.receipt_history or refs[role] == facts.receipt_for:
            _fail(view, facts, role, "historischer Vorgänger nicht vorher belegt", missing=True)


def repair_command(ctx, view):
    from .steps import registry_for, Mode

    for facts in view.facts.values():
        if facts.withdrawal:
            return ctx.command(
                "decision",
                "undo",
                ctx.record_id,
                facts.name,
                "--undo-of",
                facts.withdrawal,
                "--help",
            )
        if facts.freshness is None:
            continue
        if facts.repair == "sources refresh":
            return ctx.command("sources", "refresh", ctx.record_id)
        handler = registry_for(ctx.ws.profile).get(facts.repair)
        if handler and handler.mode is Mode.GATE and handler.next_command:
            return handler.next_command(ctx)
        if handler and handler.mode is Mode.INPUT and handler.check_command:
            return handler.check_command(ctx)
        return ctx.command("continue", ctx.record_id)
    return ctx.command("continue", ctx.record_id)
