"""Zustand entsteht durch Replay über EVIDENZ — nicht über Behauptungen.

Zwei Fassungen dieses Moduls sind an derselben Stelle gescheitert.

Die erste meldete ``READY``, sobald irgendein Ereignis eine ``record_id`` trug.
Die zweite übernahm gespeicherte ``artifact.state``-Ereignisse direkt — womit
ein handgeschriebenes Ereignis mit ``bound/current/accepted`` einen Record grün
machte, ohne Beleg und ohne Entscheidung. Das war wieder gespeicherter
Workflowzustand, also genau das, was ADR 0003 verbietet, nur an neuer Stelle.

Deshalb gibt es hier **keinen Ereignistyp, der einen Zustand behauptet**. Es
gibt nur Ereignisse, die Evidenz eintragen:

    artifact.produced   Ein Artefakt existiert mit diesem Hash.
    receipt.recorded    Für diesen Artefakthash liegt ein Beleg vor.
    decision.recorded   Ein Mensch hat GENAU DIESE Bytes verantwortet.
    anchor.checked      Das Re-Anchoring gegen die aktuelle Fassung ergab X.
    record.disabled     Der Record ist bewusst aus dem Betrieb.

Die drei Achsen werden daraus BERECHNET. Wer ``READY`` erzeugen will, muss
Beleg und Entscheidung auf denselben Hash fälschen — und beide liegen in einer
hash-verketteten Kette, die vor dem Replay vollständig geprüft wird.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .freshness import evaluate
from ..domain.anchor import ReanchorOutcome
from ..domain.instance import InstanceRegistry, InstanceRegistryError
from ..domain.decision import SHA256_RE, Decision, InvalidDecision, Verdict
from ..domain.events import (
    ANCHOR_CHECKED,
    ARTIFACT_PRODUCED,
    DECISION_RECORDED,
    FORBIDDEN_KINDS,
    RECEIPT_RECORDED,
    RECORD_DISABLED,
)
from ..domain.receipt import FINISH_UNKNOWN, ModelParams, ModelReceipt, UnauthorisedRun
from ..domain.state import (
    ArtifactState,
    DecisionState,
    DerivationState,
    LegacyDisposition,
    SourceBinding,
)
from ..domain.step import (
    DEFAULT_GRAPH,
    ArtifactContract,
    GraphError,
    Kind,
    Step,
    StepGraph,
    check_contracts,
)
from ..policies.authority import CAP_REASON, PROVISIONAL_REASON, Authority
from ..policies.exit_contract import Status

__all__ = ["ArtifactFacts", "RecordView", "replay"]

# Die Namen kommen aus domain/events.py und werden hier nur weitergereicht.
# Vorher standen sie hier ein zweites Mal: Wer eine Art umbenennt, benennt
# dann den Schreibpfad um und das Replay liest weiter den alten Namen — ohne
# Fehler, es sieht die Ereignisse nur nicht mehr. Das ist die stillste aller
# Fehlerarten: Die Kette bleibt heil, die Evidenz verschwindet.

STATUS_ORDER = [
    Status.STOP,
    Status.CONFIG,
    Status.REVIEW_REQUIRED,
    Status.STALE,
    Status.EXCLUDED,
    Status.ACTION_NEEDED,
    Status.READY,
]


@dataclass(frozen=True)
class InheritedDecisionEvidence:
    """Eine geerbte Entscheidung, an beide aktuellen Fassungen gebunden."""

    decision_id: str
    output_sha256: str
    upstream_artifact: str
    upstream_sha256: str


@dataclass
class ArtifactFacts:
    """Was das Journal über EIN Artefakt belegt, und was sein Vertrag verlangt.

    Der Vertrag ist ein PFLICHTFELD ohne Vorgabewert. Die erste Fassung gab ihm
    einen Default aus lauter ``True`` — „dann bleibt fail-closed, wer keinen
    mitgibt". Das war falsch herum gedacht: Ein Default ist eine still erzeugte
    Ersatzkonfiguration, und sie hätte genau dort gegriffen, wo jemand vergisst,
    den Graphen durchzureichen. Der Vertrag kommt aus ``graph.contract_for`` und
    sonst nirgendwoher; wer ihn nicht hat, bekommt einen ``TypeError`` beim Bau
    des Objekts statt einen falschen Status beim Lesen.
    """

    name: str
    contract: ArtifactContract
    is_egress: bool
    sha256: str | None = None
    receipt_for: str | None = None
    receipt_inputs: dict[str, str] = field(default_factory=dict)
    decided_sha: str | None = None
    decided_verdict: str | None = None
    inherited_decision: InheritedDecisionEvidence | None = None
    anchor_outcome: str | None = None
    disposition: LegacyDisposition = LegacyDisposition.OK
    harness_era: str = "current"
    freshness: DerivationState | None = None
    freshness_reason: str = ""
    repair: str = ""
    receipt_kind: str = ""
    receipt_seq: int = 0
    decision_seq: int = 0
    epoch: int = 0
    history: set[str] = field(default_factory=set)
    receipt_history: set[str] = field(default_factory=set)
    withdrawal: str | None = None

    def state(self, enabled: bool = True) -> ArtifactState:
        """Die drei Achsen: erst die Evidenz, und nur wo keine ist, der Vertrag.

        **Die Reihenfolge ist die ganze Zusicherung.** Vorher entschied auf zwei
        Achsen die Fahne ``is_human_artifact``: Ein menschliches Artefakt war
        gebunden, weil es menschlich war, nicht weil ein Anker geprüft worden
        wäre. Das ist gespeicherter Zustand mit anderem Namen — dieselbe Klasse
        wie die ``artifact.state``-Ereignisse aus dem Modulkopf, nur eine Ebene
        tiefer und ohne Ereignis.

        **Die erste Fassung hatte den Vertrag zuerst gefragt** und die Evidenz
        danach: ``decision_required=false`` ⇒ Achse ``NOT_APPLICABLE``, fertig.
        Damit verschwand ein authentifizierter Widerruf, sobald ein Vertrag die
        Entscheidungsachse für nicht zuständig erklärte. ``NOT_APPLICABLE`` ist
        der Wert bei FEHLENDER Evidenz, nie ein Übersteuern vorhandener —
        deshalb steht der Vertrag in jedem der drei Blöcke im ``else``.

        Was als Evidenz zählt, ist je Achse verschieden und steht dort.
        """
        # -- Bindung -------------------------------------------------------
        # Evidenz ist hier ein ``anchor.checked``. Liegt keins vor, sagt der
        # Vertrag, ob das ein Mangel ist (Anker verlangt) oder eine
        # Nichtzuständigkeit (Anker nicht verlangt).
        if self.anchor_outcome in (
            ReanchorOutcome.EXACT.value,
            ReanchorOutcome.UNIQUE_MOVE.value,
        ):
            binding = SourceBinding.BOUND
        elif self.anchor_outcome is not None:
            binding = SourceBinding.DRIFTED
        elif self.contract.binding_required:
            binding = SourceBinding.UNKNOWN
        else:
            binding = SourceBinding.NOT_APPLICABLE

        # -- Ableitung -----------------------------------------------------
        # Evidenz ist ein Beleg. Ein Beleg OHNE Bytes ist vorhandene Evidenz,
        # die nicht aufgeht: Sie bleibt ``UNVERIFIABLE``, auch wenn der Vertrag
        # keine Herkunft verlangt. Sonst neutralisierte der Vertrag einen Beleg,
        # der ins Leere zeigt.
        if self.receipt_for is not None:
            if self.sha256 is None:
                derivation = DerivationState.UNVERIFIABLE
            elif self.receipt_for != self.sha256:
                derivation = DerivationState.STALE
            else:
                derivation = DerivationState.CURRENT
        elif self.contract.provenance_required:
            derivation = DerivationState.UNVERIFIABLE
        else:
            derivation = DerivationState.NOT_APPLICABLE

        if self.freshness is not None:
            derivation = self.freshness

        # -- Entscheidung --------------------------------------------------
        # Evidenz ist ein Verdikt. Ein ACCEPT auf ANDERE Bytes ist vorhandene
        # Evidenz, die diese Bytes nicht deckt: ``UNDECIDED``, unabhängig vom
        # Vertrag. Nur wer gar kein Verdikt hat, fällt an den Vertrag.
        if self.withdrawal or self.decided_verdict == "WITHDRAW":
            decision = DecisionState.WITHDRAWN
        elif self.decided_verdict == "REJECT" and self.decided_sha == self.sha256:
            decision = (
                DecisionState.REJECTED
                if self.decided_verdict == "REJECT"
                else DecisionState.WITHDRAWN
            )
        elif self.inherited_decision is not None:  # noqa: SIM114 - eigener Mutationsanker V19
            decision = DecisionState.ACCEPTED
        elif (
            self.decided_verdict == "ACCEPT"
            and self.decided_sha is not None
            and self.decided_sha == self.sha256
            and not self.is_egress
        ):
            decision = DecisionState.ACCEPTED
        elif self.decided_verdict is not None or self.contract.decision_required:
            decision = DecisionState.UNDECIDED
        else:
            decision = DecisionState.NOT_APPLICABLE

        return ArtifactState(
            source_binding=binding,
            derivation_state=derivation,
            decision_state=decision,
            enabled=enabled,
            disposition=self.disposition,
            harness_era=self.harness_era,
            reason=self.freshness_reason,
        )

    def usable(self, enabled: bool = True) -> bool:
        """E4 · nutzbar heisst: Bytes existieren UND der Status ist ``READY``.

        Zwei Klauseln, absichtlich getrennt und beide tragend. ``sha256 is not
        None`` — E4 nennt „Bytes existieren" als eigene Bedingung; ein Vertrag
        mit drei ``false``-Pflichten (Ingress) ergibt **ohne** Bytes bereits
        ``status is READY`` (drei Achsen ``NOT_APPLICABLE``) und gaelte ohne die
        Byteklausel als nutzbar. ``state(enabled).status is READY`` fasst die
        drei Achsen samt ``enabled``/``EXCLUDED`` zusammen: eine erforderliche
        Achse wird nie ``NOT_APPLICABLE``, also bedeutet ``READY`` fuer jede
        erforderliche Achse den erfuellten Wert. Drift, fehlende Pflicht-
        entscheidung oder Ausschluss oeffnen damit keinen naechsten Schritt.
        """
        return self.sha256 is not None and self.state(enabled).status is Status.READY


@dataclass
class RecordView:
    record_id: str
    facts: dict[str, ArtifactFacts] = field(default_factory=dict)
    enabled: bool = True
    n_events: int = 0
    sources: dict[str, tuple[str | None, int]] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    #: Die ECHTEN Entscheidungen, auf die ein Modellbeleg sich berufen kann.
    #: Nur Zeichenketten zu behalten hat zwei Angriffe offen gelassen: ein
    #: Beleg konnte sich auf eine REJECT-Entscheidung berufen, und er konnte
    #: seinen eigenen Autorisierungszeitpunkt frei behaupten.
    decisions: dict[str, Decision] = field(default_factory=dict)
    #: Der in Journalreihenfolge zuletzt WIRKSAME Entscheidungszustand je
    #: Artefakt. Anders als ``decisions`` ist diese Map kein ID-Index.
    effective_decision_by_artifact: dict[str, Decision] = field(default_factory=dict)
    #: Akte ohne Autorität — angezeigt, aber ohne Wirkung.
    provisional: list[str] = field(default_factory=list)
    #: Beratende Hinweise. Ausdrücklich KEINE Befunde: sie färben nichts rot und
    #: erzeugen keinen Exitcode. Hier landet, was auffällt, ohne dass eine
    #: Maschine darüber entscheiden dürfte — etwa ob ein Abstract deskriptiv
    #: oder analytisch ist (ADR 0020). Ein Hinweis steht neben dem Text, nicht
    #: davor.
    advisory: list[str] = field(default_factory=list)
    authority: Authority = Authority.UNAUTHENTICATED
    graph: StepGraph = field(default_factory=lambda: DEFAULT_GRAPH)
    protected_refs: list[dict] = field(default_factory=list)
    protected_artifacts: list[dict] = field(default_factory=list)

    @property
    def have(self) -> set[str]:
        """Was der Planer als vorhanden ansehen darf — E4, der ganze Vertrag.

        Nicht mehr die Bytepräsenz allein (der Vorgänger fragte nur ``sha256 is
        not None``): ein ausgeschlossenes oder unfertiges Artefakt — ``STOP``,
        ``STALE``, ``REVIEW_REQUIRED``, ``ACTION_NEEDED`` oder ``EXCLUDED`` — ist
        keine Vorbedingung des nächsten Schritts. ``usable`` fasst beide
        E4-Klauseln (Bytes **und** ``status is READY``); ``enabled`` wird
        durchgereicht, damit ein deaktivierter Record ein leeres ``have`` hat.
        Die frühere Sonderabfrage für menschliche Artefakte entfällt: der Status
        kommt seit C2 aus Evidenz und Vertrag, nicht aus einer Fahne.
        """
        return {name for name, facts in self.facts.items() if facts.usable(self.enabled)}

    @property
    def artifacts(self) -> dict[str, ArtifactState]:
        return {n: f.state(self.enabled) for n, f in self.facts.items()}

    @property
    def referenced_addresses(self) -> set[str]:
        """Jede Adresse, die dieses Journal als Bytes benennt.

        Absichtlich vollständig statt nur ``sha256``: Auch die Eingaben eines
        Belegs und die Bytes, auf die sich eine Entscheidung bezieht, sind
        Referenzen. Eine davon ins Leere zeigen zu lassen wäre derselbe Angriff
        mit anderem Feldnamen.
        """
        out: set[str] = {sha for sha, _ in self.sources.values() if sha}
        for decision in self.effective_decision_by_artifact.values():
            out.update(decision.input_refs.values())
        for f in self.facts.values():
            for value in (f.sha256, f.receipt_for, f.decided_sha, *f.receipt_inputs.values()):
                if isinstance(value, str) and value:
                    out.add(value)
        return out

    @property
    def next_gates(self) -> tuple[Step, ...]:
        """ALLE erreichbaren Halte, nicht nur der erste (ADR 0021).

        Mehrzahl, weil der Graph seit ADR 0020 verzweigt ist. Ein einzelner
        Halt hätte den Analysepfad operativ hinter den Katalogpfad gehängt,
        ohne dass eine Kante das behauptet.
        """
        return self.graph.plan(self.have).gates

    @property
    def status(self) -> Status:
        if self.findings:
            return Status.STOP  # verbotene Ereignisart o. Ä. — nie grün
        if not self.enabled:
            return Status.EXCLUDED
        states = self.artifacts
        if not states:
            return Status.ACTION_NEEDED
        worst = min((s.status for s in states.values()), key=STATUS_ORDER.index)
        if worst is Status.READY and self.next_gates:
            return Status.ACTION_NEEDED
        if worst is Status.READY and not self.authority.may_confer_ready:
            # Nutzlastprüfung ist keine Autorisierung (ADR 0017).
            return Status.ACTION_NEEDED
        return worst

    @property
    def explanation(self) -> str:
        if self.findings:
            return self.findings[0]
        if not self.enabled:
            return "bewusst deaktiviert"
        states = self.artifacts
        if not states:
            phrase = _gate_phrase(self.next_gates)
            return f"keine belegten Artefakte; {phrase}" if phrase else "keine belegten Artefakte"
        worst = self.status
        capped = (
            worst is Status.ACTION_NEEDED
            and not self.authority.may_confer_ready
            and not self.next_gates
            and all(s.status is Status.READY for s in states.values())
        )
        if capped:
            return CAP_REASON
        for name, st in states.items():
            if st.status is worst:
                return f"{name}: {st.explanation}"
        return _gate_phrase(self.next_gates) or "vollständig"

    def to_json(self) -> dict[str, Any]:
        gates = self.next_gates
        return {
            "record_id": self.record_id,
            "status": self.status.value,
            "explanation": self.explanation,
            "next_gates": [g.name for g in gates],
            "artifacts": {k: v.to_json() for k, v in sorted(self.artifacts.items())},
            "events": self.n_events,
            "findings": list(self.findings),
            "provisional": list(self.provisional),
            "advisory": list(self.advisory),
            "authority": self.authority.value,
        }


def _gate_phrase(gates: tuple[Step, ...]) -> str:
    """Ein Halt liest sich anders als drei — und drei sind kein Fehler.

    Der Zusatz „unabhängig voneinander" steht da, weil die Aufzählung sonst
    wie eine Reihenfolge aussieht. Sie ist keine: Wer zuerst entscheidet,
    entscheidet nichts über die anderen mit.
    """
    if not gates:
        return ""
    if len(gates) == 1:
        return f"nächster Halt: {gates[0].name}"
    return "offene Halte (unabhängig voneinander): " + ", ".join(g.name for g in gates)


def _human_artifacts(graph: StepGraph) -> set[str]:
    return {a for s in graph if s.kind is Kind.HUMAN for a in s.produces}


VALID_OUTCOMES = {o.value for o in ReanchorOutcome}


def _build_decision(
    p: dict[str, Any], record_id: str, at: str, *, require_negative: bool = False
) -> tuple[Decision | None, str | None]:
    """Baut die echte ``Decision``. Schlägt das fehl, ist das Ereignis keine.

    Der Befund: vier frei konstruierte Ereignisse je Artefakt genügten für
    ``READY``. Der Grund war, dass ``replay`` die Nutzlasten als Wörterbücher
    gelesen hat statt als Domänenobjekte. Ein Wörterbuch mit den richtigen
    Schlüsseln ist aber keine Entscheidung — es hat weder Referenzformat noch
    Akteur noch einen prüfbaren Zeitpunkt.
    """
    if p.get("record_id") and p["record_id"] != record_id:
        return None, (
            f"record_id der Nutzlast ({p['record_id']!r}) weicht von der Ereignishülle "
            f"({record_id!r}) ab"
        )
    try:
        d = Decision(
            record_id=p.get("record_id") or record_id,
            artifact=p.get("artifact", ""),
            subject_sha256=p.get("subject_sha256", ""),
            verdict=Verdict(p.get("verdict", "")),
            reference=p.get("reference", ""),
            actor=p.get("actor", ""),
            at=p.get("at") or at,
            input_refs=p.get("input_refs", {}),
            input_refs_version=p.get("input_refs_version", 1),
            profile_id=p.get("profile_id"),
            graph_sha256=p.get("graph_sha256"),
        )
    except (InvalidDecision, ValueError) as exc:
        return None, f"decision.recorded ist keine gültige Entscheidung: {exc}"
    if require_negative and d.verdict not in (Verdict.REJECT, Verdict.WITHDRAW):
        return None, (
            f"Verdikt {d.verdict.value} deaktiviert nichts (erwartet REJECT oder WITHDRAW)"
        )
    return d, None


def _check_receipt(p: dict[str, Any], *, must_be_model: bool) -> str | ModelReceipt | None:
    """Baut den echten Beleg. Ein Wörterbuch mit den richtigen Schlüsseln ist keiner.

    ``must_be_model`` gilt für Artefakte, die ein Modellschritt erzeugt: dort
    genügt kein deterministischer Beleg. Sonst könnte ein Modellartefakt durch
    einen „deterministic"-ähnlichen Eintrag aktuell werden, und Autorisierung,
    ``finish_reason`` und Parameter würden nie geprüft.
    """
    out = p.get("output_sha256", "")
    if not SHA256_RE.match(out or ""):
        return f"receipt.recorded ohne gültigen output_sha256 ({out!r})"
    inputs = p.get("inputs")
    if not isinstance(inputs, dict) or not inputs:
        return "receipt.recorded ohne deklarierte Eingaben"
    for k, val in inputs.items():
        if not SHA256_RE.match(str(val)):
            return f"receipt.recorded: Eingabe {k!r} ist kein sha256"
    if not p.get("code_version"):
        return "receipt.recorded ohne code_version"

    is_model = p.get("kind") == "model"
    if must_be_model and not is_model:
        return "Modellartefakt mit deterministischem Beleg — Autorisierung würde nie geprüft"
    if not is_model:
        return None

    params = p.get("params") or {}
    if not isinstance(params, dict) or not params.get("model"):
        return "Modellbeleg ohne Parametersatz"
    try:
        r = ModelReceipt(
            step=p.get("step", ""),
            inputs=dict(inputs),
            output_sha256=out,
            code_version=p["code_version"],
            params=ModelParams(
                model=params["model"],
                model_digest=params.get("model_digest"),
                temperature=float(params.get("temperature", 0.0)),
                seed=params.get("seed"),
                num_ctx=params.get("num_ctx"),
                num_predict=params.get("num_predict"),
                max_chars=params.get("max_chars"),
                extra=params.get("extra") or {},
            ),
            prompt_sha256=p.get("prompt_sha256", ""),
            finish_reason=p.get("finish_reason", FINISH_UNKNOWN),
            authorisation=p.get("authorisation", ""),
            authorisation_subject_sha256=p.get("authorisation_subject_sha256", ""),
            authorised_at=p.get("authorised_at", ""),
            started_at=p.get("started_at", ""),
        )
        r.check_authorisation()
    except (TypeError, ValueError) as exc:
        return f"Modellbeleg ist nicht rekonstruierbar: {exc}"
    except UnauthorisedRun as exc:
        return f"Modellbeleg nicht autorisiert: {exc}"
    if r.truncated:
        return f"Modellbeleg mit finish_reason={r.finish_reason!r} — abgeschnittener Lauf"
    return r


def _bind_model_receipt(
    r: ModelReceipt, v: RecordView, record_id: str, artifact: str, graph: StepGraph
) -> str | None:
    """Bindet einen Modellbeleg an die TATSÄCHLICHE Entscheidung.

    Zwei Angriffe waren offen, solange nur Referenzzeichenketten verglichen
    wurden: Ein Beleg konnte sich auf eine ``REJECT``-Entscheidung berufen (eine
    spätere ``ACCEPT`` machte den Endzustand grün), und er konnte seinen eigenen
    ``authorised_at`` frei behaupten, während die wirkliche Entscheidung erst
    später fiel. Im QDA-Kontext hieße das: modellgenerierte Codes entstehen vor
    der Bestätigung des Transkripts und gelten hinterher als autorisiert.
    """
    d = v.decisions.get(r.authorisation)
    if d is None:
        return (
            f"Modellbeleg für {artifact!r} beruft sich auf die Entscheidung "
            f"{r.authorisation!r}, die im Journal (bis hierher) nicht vorkommt"
        )
    if d.verdict is not Verdict.ACCEPT:
        return (
            f"Modellbeleg für {artifact!r} beruft sich auf eine Entscheidung mit Verdikt "
            f"{d.verdict.value} — das autorisiert nichts"
        )
    if d.record_id != record_id:
        return f"Autorisierende Entscheidung gehört zu {d.record_id!r}, nicht zu {record_id!r}"
    producer = next((s for s in graph if artifact in s.produces), None)
    expected = set()
    if producer is not None:
        human = _human_artifacts(graph)
        expected = {a for a in producer.requires if a in human}
    if expected and d.artifact not in expected:
        return (
            f"Autorisierende Entscheidung betrifft {d.artifact!r}; erwartet wurde eine "
            f"Entscheidung über {' oder '.join(sorted(expected))}"
        )
    try:
        r.validate(d)
    except Exception as exc:  # noqa: BLE001 - Meldung ist die Nutzlast
        return f"Modellbeleg für {artifact!r} ist nicht an die Entscheidung gebunden: {exc}"
    return None


def _model_artifacts(graph: StepGraph) -> set[str]:
    return {a for s in graph if s.kind is Kind.MODEL for a in s.produces}


def _egress_artifacts(graph: StepGraph) -> set[str]:
    """Artefakte, die laut tatsächlich übergebenem Laufgraphen hinausgehen."""
    return {artifact for step in graph if step.leaves_system for artifact in step.produces}


def _invalidate_inherited_for_version(v: RecordView, changed_artifact: str) -> None:
    """Löscht Bindungen an eine nachträglich geänderte Fassung."""
    for facts in v.facts.values():
        evidence = facts.inherited_decision
        if (facts.is_egress and facts.name == changed_artifact) or (
            evidence is not None and evidence.upstream_artifact == changed_artifact
        ):
            facts.inherited_decision = None


def _invalidate_inherited_for_decision(v: RecordView, artifact: str) -> None:
    """Löscht Bindungen nach einer wirksamen Nicht-ACCEPT-Entscheidung."""
    for facts in v.facts.values():
        evidence = facts.inherited_decision
        if evidence is not None and evidence.upstream_artifact == artifact:
            facts.inherited_decision = None
        if facts.is_egress and facts.name == artifact:
            facts.inherited_decision = None


def _inherit_egress_decision(
    facts: ArtifactFacts, view: RecordView, graph: StepGraph
) -> InheritedDecisionEvidence | None:
    """Bindet ein Egress-Receipt an die aktuell wirksame Upstreamfreigabe."""
    upstream_needed = set(graph.producer_of(facts.name).requires)
    if set(facts.receipt_inputs) != upstream_needed:
        return None
    if facts.receipt_for != facts.sha256:
        return None
    if len(upstream_needed) != 1:
        return None
    (upstream,) = upstream_needed
    upstream_facts = view.facts.get(upstream)
    if upstream_facts is None or facts.receipt_inputs.get(upstream) != upstream_facts.sha256:
        return None
    effective = view.effective_decision_by_artifact.get(upstream)
    if effective is None:
        return None
    if effective.verdict is not Verdict.ACCEPT:
        return None
    if effective.subject_sha256 != upstream_facts.sha256:
        return None
    return InheritedDecisionEvidence(
        decision_id=effective.id,
        output_sha256=facts.sha256,
        upstream_artifact=upstream,
        upstream_sha256=upstream_facts.sha256,
    )


def replay(
    events: Iterable[Any],
    graph: StepGraph | None = None,
    authority: Authority = Authority.UNAUTHENTICATED,
    *,
    _p4b_expanded: bool = False,
) -> dict[str, RecordView]:
    """Der Graph ist ein PFLICHTARGUMENT in allem, was Records auswertet.

    Er war ein Default auf ``DEFAULT_GRAPH``. Damit plante die Laufzeit für
    einen CHILDLUX-Arbeitsbereich entlang des Sandbox-Graphen — also entlang
    der direkten Kante, die ADR 0024 verbietet. Die CI prüfte den richtigen
    Graphen, die Laufzeit nahm den alten: dieselbe Klasse wie „etwas Wahres
    über etwas Unbenutztes", nur mit vertauschten Rollen.

    ``None`` bleibt erlaubt und bedeutet ausdrücklich ``DEFAULT_GRAPH`` — für
    Tests, die keinen Profilbezug haben. Jeder Produktionsaufruf reicht den
    profilabgeleiteten Graphen durch.
    """
    if graph is None:
        graph = DEFAULT_GRAPH
    # Die dritte Vollstreckungsflaeche, VOR dem Fold und nicht danach.
    #
    # `build_graph` ist seit C1 selbst fail-closed — aber `replay` nimmt einen
    # beliebigen Graphen entgegen, und das ist der Sinn seines Pflichtarguments.
    # Ein Tor, das nur im CI-Job und nur in `build_graph` haengt, liesse einen
    # anders gebauten Profilgraphen trotz verletzter Totalitaet in den Replay
    # — und dort entscheidet die Vertragstabelle ueber Achsen und Status. Der
    # Halt steht deshalb vor der ersten Zustandszeile: danach waere er eine
    # Meldung ueber einen bereits berechneten Zustand.
    verstoesse = check_contracts(graph)
    if verstoesse:
        raise GraphError(
            "Replay gegen einen Graphen, dessen Vertragstabelle ihn nicht deckt:\n  "
            + "\n  ".join(verstoesse)
        )
    protected_refs, protected_artifacts, protected_findings = {}, {}, {}
    if not _p4b_expanded:
        from .protected_replay import expand

        events, protected_refs, protected_artifacts, protected_findings = expand(
            list(events), graph, authority
        )
    model_made = _model_artifacts(graph)
    egress_made = _egress_artifacts(graph)
    #: Nur was ein Schritt erzeugt, ist ein Artefakt. Ohne diese Menge legt
    #: `facts.setdefault` unten fuer JEDEN Namen eine Zeile an — auch fuer
    #: einen erfundenen, und die Zeile laeuft in `have` und in den Planer.
    erzeugbar = graph.artifacts
    views: dict[str, RecordView] = {}

    registry = InstanceRegistry()
    codebook_source: tuple[str | None, int] | None = None
    policy_source = None
    register_source = None
    for index, e in enumerate(events, 1):
        payload = getattr(e, "payload", None) or {}
        if e.kind in ("instance.registered", "instance.retired"):
            try:
                if e.kind == "instance.registered":
                    registry.register(dict(payload))
                else:
                    registry.retire(dict(payload))
            except InstanceRegistryError:
                pass  # Die Registerprüfung bleibt beim spezialisierten Leser.
        rid = getattr(e, "record_id", None)
        if e.kind == "p4c.registry.source":
            register_source = (payload["ref"]["sha256"], payload.get("activation", index))
            continue
        if not rid:
            if (
                e.kind == RECEIPT_RECORDED
                and payload.get("kind") == "transcript.segment_languages.prepared.v1"
            ):
                target = payload.get("target_record_id")
                if target:
                    view = views.setdefault(
                        target, RecordView(record_id=target, graph=graph, authority=authority)
                    )
                    view.sources["srt"] = (payload.get("inputs", {}).get("srt"), index)
                    view.sources["language_assignment"] = (payload.get("output_sha256"), index)
            continue
        v = views.setdefault(rid, RecordView(record_id=rid, graph=graph, authority=authority))
        v.n_events += 1
        kind = e.kind
        p = getattr(e, "payload", None) or {}

        if kind in FORBIDDEN_KINDS:
            v.findings.append(
                f"Ereignisart {kind!r} behauptet einen Zustand, statt Evidenz einzutragen. "
                "Zustand wird berechnet (ADR 0003) — das Ereignis wird nicht ausgewertet."
            )
            continue

        if kind == RECORD_DISABLED:
            # Auch das Deaktivieren ist ein menschlicher Akt. Ohne Entscheidung
            # waere es ein zustandsbehauptendes Ereignis - genau das, was es
            # hier nicht geben darf.
            d, problem = _build_decision(p, rid, getattr(e, "at", ""), require_negative=True)
            if problem:
                v.findings.append(f"record.disabled ohne gültige Entscheidung: {problem}")
                continue
            name = p.get("artifact")
            if name not in erzeugbar:
                v.findings.append(
                    f"Ereignis {kind!r} auf {name!r}: kein Schritt des Graphen erzeugt "
                    "diesen Namen. Der Record wird nicht ausgeschlossen."
                )
                continue
            if not authority.may_confer_exclusion:
                v.provisional.append(f"record.disabled: {PROVISIONAL_REASON}")
                continue
            v.decisions[d.id] = d
            v.enabled = False
            continue

        if kind == "p4c.resolution.source":
            v.sources["pseudonymisation.resolution"] = (p["ref"]["sha256"], index)
            continue
        if kind == "p4b.policy":
            policy_source = (p["sha256"], index)
            continue
        if kind == "input.observed":
            if p.get("role") not in ("l1.codebook", "metadata.input") or (
                p.get("sha256") is not None and not SHA256_RE.fullmatch(str(p["sha256"]))
            ):
                v.findings.append("input.observed: ungültige Rolle oder Adresse")
            else:
                v.sources[p["role"]] = (p["sha256"], index)
                if p["role"] == "l1.codebook":
                    codebook_source = (p["sha256"], index)
            continue
        if kind == "source.ingested" and p.get("media_type") == "text/plain;charset=utf-8":
            v.sources["source"] = (p.get("sha256"), index)
        elif kind == "source.ingested" and p.get("media_type") == "application/x-subrip":
            v.sources["srt"] = (p.get("sha256"), index)
        name = p.get("artifact")
        if not name:
            continue

        if name not in erzeugbar:
            # Graphzugehoerigkeit ist eine Eigenschaft des Namens, nicht der
            # Ereignisart — deshalb steht die Pruefung hier, vor der
            # Fallunterscheidung, an derselben Stelle wie der Defekt.
            v.findings.append(
                f"Ereignis {kind!r} auf {name!r}: kein Schritt des Graphen erzeugt "
                "diesen Namen. Ein Artefakt, das kein Schritt herstellt, hat keinen "
                "Zustand — die Zeile wird nicht angelegt."
            )
            continue

        # `contract_for` kann hier nicht scheitern: `check_contracts` oben hat
        # die Totalitaet in beide Richtungen geprueft, und `name` steht in
        # `erzeugbar`. Der Vertrag wird trotzdem hier geholt und nicht
        # spaeter — ein Fakt ohne Vertrag soll gar nicht erst existieren.
        f = v.facts.setdefault(
            name,
            ArtifactFacts(
                name=name,
                contract=graph.contract_for(name),
                is_egress=name in egress_made,
            ),
        )

        if kind == ARTIFACT_PRODUCED:
            sha = p.get("sha256")
            if not SHA256_RE.match(str(sha)):
                v.findings.append(f"artifact.produced für {name!r} ohne gültigen sha256")
                continue
            if f.sha256 is not None and f.sha256 != sha:
                _invalidate_inherited_for_version(v, name)
            f.sha256 = sha
            f.history.add(sha)
            f.epoch = index
            if p.get("disposition"):
                if not authority.may_confer_exclusion:
                    v.provisional.append(f"disposition auf {name!r}: {PROVISIONAL_REASON}")
                else:
                    try:
                        f.disposition = LegacyDisposition(p["disposition"])
                    except ValueError:
                        f.disposition = LegacyDisposition.EXCLUDED  # unbekannt -> fail-closed
            f.harness_era = p.get("harness_era", f.harness_era)
        elif kind == RECEIPT_RECORDED:
            outcome = _check_receipt(p, must_be_model=name in model_made)
            if isinstance(outcome, str):
                v.findings.append(outcome)
                continue
            if outcome is not None:  # Modellbeleg -> an die echte Entscheidung binden
                bad = _bind_model_receipt(outcome, v, rid, name, graph)
                if bad:
                    v.findings.append(bad)
                    continue
            f.receipt_seq = index
            f.epoch = index
            f.receipt_kind = p.get("kind", "")
            f.receipt_history = set(f.history)
            f.receipt_for = p["output_sha256"]
            f.receipt_inputs = dict(p["inputs"])
            if f.is_egress:
                f.inherited_decision = _inherit_egress_decision(f, v, graph)
        elif kind == DECISION_RECORDED:
            d, problem = _build_decision(p, rid, getattr(e, "at", ""))
            if problem:
                v.findings.append(problem)
                v.effective_decision_by_artifact.pop(name, None)
                f.decided_sha = None
                f.decided_verdict = None
                continue
            if not authority.may_confer_exclusion and d.verdict is not Verdict.ACCEPT:
                # Auch ein REJECT/WITHDRAW/UNDO ist Autorität (ADR 0017).
                v.provisional.append(f"{d.verdict.value} auf {name!r}: {PROVISIONAL_REASON}")
                continue
            v.decisions[d.id] = d
            if d.verdict is Verdict.UNDO:
                try:
                    actor = registry.get(d.actor, active=True)
                    authorised = (
                        actor.source == "mensch"
                        and p.get("undo_of") == f.withdrawal
                        and f.withdrawal is not None
                    )
                except InstanceRegistryError:
                    authorised = False
                if not authorised:
                    v.provisional.append(
                        "UNDO ohne aktive menschliche Instanz oder passenden Widerrufsbezug"
                    )
                    continue
                f.withdrawal = None
            elif d.verdict is Verdict.WITHDRAW:
                f.withdrawal = getattr(e, "digest", None) or d.id
            elif f.withdrawal:
                continue
            f.decision_seq = index
            f.epoch = index
            v.effective_decision_by_artifact[name] = d
            f.decided_sha = d.subject_sha256
            f.decided_verdict = d.verdict.value
            if d.verdict is not Verdict.ACCEPT:
                _invalidate_inherited_for_decision(v, name)
        elif kind == ANCHOR_CHECKED:
            if f.sha256 is None:
                v.findings.append(f"anchor.checked für {name!r} ohne zuvor erzeugte Artefaktbytes")
                continue
            outcome = p.get("outcome")
            if outcome not in VALID_OUTCOMES:
                v.findings.append(f"anchor.checked mit unbekanntem Ergebnis {outcome!r}")
                continue
            f.anchor_outcome = outcome

    for rid in protected_findings:
        views.setdefault(rid, RecordView(record_id=rid, graph=graph, authority=authority))
    for view in views.values():
        view.protected_refs = protected_refs.get(view.record_id, [])
        view.protected_artifacts = protected_artifacts.get(view.record_id, [])
        view.findings.extend(protected_findings.get(view.record_id, []))
        if register_source is not None:
            view.sources["pseudonymisation.registry"] = register_source
        if policy_source is not None:
            view.sources["pseudonymisation.policy"] = policy_source
        if codebook_source is not None:
            view.sources["l1.codebook"] = codebook_source
        evaluate(view)
    return views
