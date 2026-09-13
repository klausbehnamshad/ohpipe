"""Der deklarative Schrittgraph.

``continue`` ist kein Skript, sondern ein topologischer Lauf über diesen
Graphen. Der Unterschied ist nicht Stil: Ein imperatives ``continue`` wird eine
if-Kaskade, die bei jedem neuen Schritt bricht — und irgendwann überschreitet
sie eine Governance-Grenze, weil niemand mehr alle Pfade übersieht.

Hier ist stattdessen prüfbar, was gilt. Die zentrale Invariante:

    Kein Pfad von einem Modellschritt zu einem Artefakt mit
    leaves_system=True ohne ein human_gate dazwischen.

Diese Invariante ist ein Test, kein Vorsatz — siehe :func:`check_egress_gates`.
Sie ist die vollstreckbare Fassung der teuersten Lektion des Vorgängerprojekts:
dort führte der einzige ungeschützte Außenpfad dazu, dass eine still
abgeschnittene Modellantwort fünf von sechs Themen eines öffentlichen
Katalog-Records verschoben hätte — in Richtung der schutzbedürftigsten
Kategorie.

Was NICHT erzwungen wird: dass jede einzelne Unit adjudiziert werden muss. Das
ist Projektpolicy (``Profile``), nicht Kerninvariante. Unverhandelbar ist nur
der Beleg für genau die freizugebenden Bytes.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from enum import Enum

from ohpipe.domain.hashing import NFC_STRICT, PROFILES, sha256_json

__all__ = [
    "DEFAULT_GRAPH",
    "ArtifactContract",
    "GraphError",
    "Kind",
    "Plan",
    "Step",
    "StepGraph",
    "build_graph",
    "check_contracts",
    "confirmed_text_role",
    "check_egress_gates",
    "graph_contract_fingerprint",
]


class Kind(str, Enum):
    DETERMINISTIC = "deterministic"  # reine Berechnung, reproduzierbar
    MODEL = "model"  # generativ, Beleg statt Regeneration
    HUMAN = "human"  # menschliche Verantwortung
    EGRESS = "egress"  # verlässt das System


class GraphError(RuntimeError):
    pass


@dataclass(frozen=True, kw_only=True)
class ArtifactContract:
    """Die drei unabhängigen Pflichten je Artefakt (E2, präzisiert in E2-N).

    Deklariert im Graphen, nie im Einzelfall. Der Vertrag hängt am **Artefakt**
    und nicht am Schritt (E2-N Nummer 1): ``pseudonymise`` erzeugt zwei
    Artefakte, und ein Vertrag am Schritt gäbe beiden denselben.

    **Drei Felder ohne Vorgabewert, und ``kw_only``.** Beides ist Absicht.
    Ein Vorgabewert wäre der stille Default, den E2-N Nummer 2 ausdrücklich
    verbietet — er entstünde dann nicht bei der Abfrage, sondern eine Ebene
    früher beim Eintrag, und die Vertragstabelle liesse sich halb ausgefüllt
    schreiben. Und drei ``bool`` in Folge sind positional nicht unterscheidbar:
    ``ArtifactContract(True, False, True)`` ist gegen eine Vertauschung von
    Bindung und Entscheidung nicht abgesichert, ``binding_required=True,
    provenance_required=False, decision_required=True`` schon. Die erste
    Fassung hatte beides nicht; sie hätte eine falsch sortierte Zeile in der
    Sechzehnertabelle klaglos angenommen.

    Die drei Achsen sind unabhängig. Es gibt ausdrücklich keine Regel
    „Entscheidung erfordert Bindung" oder ähnliches — die Rollentabelle in E2
    belegt jede Kombination einzeln, und eine Kopplung hier machte aus einer
    Deklaration eine Ableitung.
    """

    #: Muss dieses Artefakt an eine Quellfassung gebunden sein (Ankerachse)?
    binding_required: bool
    #: Braucht es einen Ableitungsbeleg (Receipt)?
    provenance_required: bool
    #: Verlangt es eine Entscheidung, bevor sein Zustand ``ACCEPTED`` heissen darf?
    decision_required: bool
    #: Deklarierte Textrevision und ihr Normalisierungsprofil; None ist keine Textrolle.
    text_profile: str | None = None


@dataclass(frozen=True)
class Step:
    name: str
    kind: Kind
    requires: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    #: Hält ``continue`` hier an?
    human_gate: bool = False
    #: Erzeugt dieser Schritt etwas, das das System verlässt?
    leaves_system: bool = False
    idempotent: bool = True
    #: "cheap" | "model" | "human" — ``continue`` fragt vor teuren Schritten.
    cost: str = "cheap"
    description: str = ""
    #: Bestätigte Textrolle eines menschlichen Gates.
    confirms: str | None = None
    #: Explizite Textrolle eines Verbrauchers mit mehreren Gateeingaben.
    reads_text: str | None = None

    def __post_init__(self) -> None:
        if self.kind is Kind.HUMAN and not self.human_gate:
            raise GraphError(f"{self.name}: kind=human erfordert human_gate=True")
        if self.kind is Kind.EGRESS and not self.leaves_system:
            raise GraphError(f"{self.name}: kind=egress erfordert leaves_system=True")
        if self.leaves_system and self.kind is not Kind.EGRESS:
            # Die Umkehrung fehlte, und darin steckte die Luecke: Ein Schritt
            # durfte sich als Kind.MODEL UND leaves_system=True deklarieren.
            # check_egress_gates prueft nur Modelle UPSTREAM des Ausgangs - der
            # Ausgang selbst kam nie vor, und die Invariante meldete gruen.
            # Genau die Konstellation war im Vorgaengersystem offen, nur einen
            # Schritt kuerzer.
            raise GraphError(
                f"{self.name}: leaves_system=True ist ausschließlich für kind=egress. "
                "Ein Schritt, der zugleich generiert und das System verlässt, wäre ein "
                "Modellpfad nach außen ohne Gate dazwischen."
            )


@dataclass(frozen=True)
class Plan:
    """Das Ergebnis von :meth:`StepGraph.plan` — Ausführbares und alle Halte.

    ``gates`` ist bewusst eine Liste und kein einzelner Halt. Zwei Halte
    nebeneinander sind kein Sonderfall, sondern der Normalfall eines Graphen
    mit unabhängigen Zweigen; ein Rückgabewert, der nur einen davon kennt,
    erzwingt eine Reihenfolge, die es gar nicht gibt.
    """

    steps: tuple[Step, ...] = ()
    gates: tuple[Step, ...] = ()

    @property
    def halts(self) -> bool:
        return bool(self.gates)

    @property
    def gate_names(self) -> tuple[str, ...]:
        return tuple(g.name for g in self.gates)


@dataclass
class StepGraph:
    steps: tuple[Step, ...] = ()
    #: Vertrag je erzeugtem Artefaktnamen. Der Vorgabewert ist das LEERE dict
    #: und nicht etwa eine aus ``steps`` errechnete Tabelle: eine errechnete
    #: wäre eine Kopie von ``produces`` und sagte nichts, und
    #: :func:`check_contracts` hätte in der Gegenrichtung nichts zu prüfen.
    #: Ein Graph ohne Tabelle ist deshalb ein unvollständiger Graph — und
    #: genau das soll ein Testgraph sein dürfen, ohne dass der Konstruktor
    #: hält (E15/15a).
    contracts: dict[str, ArtifactContract] = field(default_factory=dict)
    _by_name: dict[str, Step] = field(default_factory=dict, repr=False)
    _producer: dict[str, Step] = field(default_factory=dict, repr=False)
    # Tatsächlicher Laufkontext, separat vom strukturellen Graphfingerprint.
    profile_id: str | None = None

    def matches_context(self, profile_id: str | None, graph_sha256: str | None) -> bool:
        """Nur ein ausdrücklich gebundener Laufgraph bestätigt beide Kontextteile."""
        return (
            self.profile_id is not None
            and profile_id == self.profile_id
            and graph_sha256 == graph_contract_fingerprint(self)
        )

    def __post_init__(self) -> None:
        for s in self.steps:
            if s.name in self._by_name:
                raise GraphError(f"Doppelter Schrittname: {s.name}")
            self._by_name[s.name] = s
            for artifact in s.produces:
                if artifact in self._producer:
                    raise GraphError(
                        f"Artefakt {artifact!r} wird von zwei Schritten erzeugt: "
                        f"{self._producer[artifact].name} und {s.name}. "
                        "Genau ein Schreiber je Artefakt (ADR 005)."
                    )
                self._producer[artifact] = s
        for s in self.steps:
            for need in s.requires:
                if need not in self._producer:
                    raise GraphError(f"{s.name} braucht {need!r}, das niemand erzeugt")

    def __iter__(self) -> Iterator[Step]:
        return iter(self.steps)

    def get(self, name: str) -> Step:
        return self._by_name[name]

    def producer_of(self, artifact: str) -> Step:
        return self._producer[artifact]

    @property
    def artifacts(self) -> set[str]:
        """Alle Namen, die ein Schritt dieses Graphen erzeugt.

        Aus ``_producer`` und nicht aus einer zweiten Schleife über ``steps``:
        ``__post_init__`` hat die Zuordnung bereits gebaut und dabei den
        Doppelschreiber ausgeschlossen (ADR 005). Eine zweite Ableitung wäre
        eine zweite Wahrheit über dieselbe Sache und könnte von der ersten
        abweichen, sobald jemand eine der beiden anfasst.
        """
        return set(self._producer)

    def contract_for(self, artifact: str) -> ArtifactContract:
        """Der Vertrag eines Artefakts — oder ein Fehler, nie ein Default.

        E2-N Nummer 2 wörtlich: *„Ein Artefakt ohne Vertrag ist ein Befund,
        kein Default."* Kein ``contracts.get(name, ArtifactContract(...))``.
        Die erste Fassung gab einen Allesverbieter zurück, was harmlos aussah:
        ein neues Artefakt ohne Tabelleneintrag wäre dann maximal streng
        behandelt worden. Nur wäre es nie aufgefallen — und die Vertragstabelle
        hätte still aufgehört, den Graphen zu decken. Fail-closed heisst hier
        benannt, nicht geraten.
        """
        vertrag = self.contracts.get(artifact)
        if vertrag is None:
            raise GraphError(
                f"{artifact!r} hat keinen Vertrag in diesem Graphen. Ein Artefakt "
                "ohne Vertrag ist ein Befund, kein Default (E2-N Nummer 2). "
                f"Deklariert sind: {sorted(self.contracts)}"
            )
        return vertrag

    def upstream(self, step: Step) -> list[Step]:
        """Alle Schritte, von denen ``step`` transitiv abhängt."""
        seen: dict[str, Step] = {}
        stack = list(step.requires)
        while stack:
            artifact = stack.pop()
            producer = self._producer.get(artifact)
            if producer is None or producer.name in seen:
                continue
            seen[producer.name] = producer
            stack.extend(producer.requires)
        return list(seen.values())

    def topological(self) -> list[Step]:
        done: set[str] = set()
        order: list[Step] = []
        remaining = list(self.steps)
        while remaining:
            progressed = False
            for s in list(remaining):
                if all(a in done for a in s.requires):
                    order.append(s)
                    done.update(s.produces)
                    remaining.remove(s)
                    progressed = True
            if not progressed:
                raise GraphError(
                    "Zyklus oder unerfüllbare Abhängigkeit: " + ", ".join(s.name for s in remaining)
                )
        return order

    def next_steps(self, have: set[str]) -> list[Step]:
        """Was ist als Nächstes ausführbar, gegeben die vorhandenen Artefakte?"""
        return [
            s
            for s in self.topological()
            if all(a in have for a in s.requires) and not set(s.produces) <= have
        ]

    def plan(self, have: set[str]) -> Plan:
        """Der ``continue``-Lauf: alles Unkritische, und JEDER erreichbare Halt.

        Die Vorgängerfassung hieß ``plan_until_human`` und kehrte beim ersten
        Gate zurück. Das war ein stiller Fehler mit sichtbarer Folge: Seit der
        Aufteilung in Katalog- und Analysepfad (ADR 0020) ist
        ``analysis.summarise`` unmittelbar nach ``l1.adjudicated`` ausführbar —
        aber der Plan kam nie dort an, weil vorher ``metadata.confirm``,
        ``abstract.confirm`` und deren Halte dazwischenlagen. Der Analysepfad
        hing damit operativ hinter dem Katalogpfad, obwohl **keine Graphkante
        das behauptet**. Ein Ablaufplan, der eine Abhängigkeit erzeugt, die der
        Graph nicht kennt, ist kein Plan, sondern eine zweite Wahrheit.

        Jetzt gilt: Ein Gate hält nur, was hinter IHM liegt. Alles, was
        unabhängig davon ausführbar ist, wird weitergeplant, und alle
        erreichbaren Gates werden gemeldet. Erst dadurch können Metadaten,
        Abstract und Analyse nebeneinander in einer Reviewoberfläche stehen,
        während Entscheidungen und Bytes getrennt bleiben.

        Ein einziger Durchlauf genügt: :meth:`topological` garantiert, dass die
        Voraussetzungen eines Schritts vor ihm stehen. Ein Gate wird
        übersprungen, ohne seine Erzeugnisse einzutragen — was dahinter liegt,
        scheitert danach von selbst an der ``requires``-Prüfung.
        """
        have = set(have)
        planned: list[Step] = []
        gates: list[Step] = []
        for s in self.topological():
            if set(s.produces) <= have:
                continue
            if not all(a in have for a in s.requires):
                continue
            if s.human_gate:
                gates.append(s)
                continue
            planned.append(s)
            have.update(s.produces)
        return Plan(steps=tuple(planned), gates=tuple(gates))


#: Schutz gegen kombinatorische Explosion bei pathologischen Graphen.
MAX_PATHS = 10_000


def _paths(graph: StepGraph, src: Step, dst: Step) -> list[list[Step]]:
    """Alle einfachen Pfade von ``src`` nach ``dst`` entlang der Artefaktkanten."""
    found: list[list[Step]] = []

    def walk(node: Step, trail: list[Step], seen: frozenset[str]) -> None:
        if len(found) >= MAX_PATHS:
            raise GraphError(f"Mehr als {MAX_PATHS} Pfade — Graph ist nicht prüfbar")
        if node.name == dst.name:
            found.append(trail)
            return
        for artifact in node.produces:
            for nxt in graph.steps:
                if artifact in nxt.requires and nxt.name not in seen:
                    walk(nxt, trail + [nxt], seen | {nxt.name})

    walk(src, [src], frozenset({src.name}))
    return found


def check_egress_gates(graph: StepGraph) -> list[str]:
    """Die Kerninvariante als prüfbare Funktion.

    Für JEDEN Pfad von JEDEM Modellschritt zu JEDEM Artefakt, das das System
    verlässt, muss ein ``human_gate`` **auf diesem Pfad und hinter dem
    Modellschritt** liegen.

    Beide Verschärfungen sind teuer erkauft. Eine frühere Fassung prüfte nur,
    ob irgendwo upstream irgendein Gate existiert. Damit galt ein Graph als
    sicher, dessen einziges Gate VOR dem Modell lag — also genau die
    Konstellation, die im Vorgängersystem offen war: der Mensch bestätigt das
    Transkript, und danach läuft die Modellstatistik ungeprüft nach außen.

    Liefert eine Liste von Verstößen. Leere Liste = grün. Ein Verstoß ist ein
    Buildfehler, keine Warnung.
    """
    violations: list[str] = []
    for egress in graph:
        if not egress.leaves_system:
            continue
        # Der Ausgang SELBST gehört mit in die Kandidaten. ``upstream`` enthält
        # ihn nicht, und damit blieb ein Schritt ungeprüft, der zugleich
        # Kind.MODEL und leaves_system=True ist. ``Step.__post_init__`` schließt
        # das inzwischen schon aus — aber eine Invariante, die sich auf einen
        # Konstruktor an anderer Stelle verlässt, ist keine Invariante.
        kandidaten = [*graph.upstream(egress), *([egress] if egress.kind is Kind.MODEL else [])]
        for model in kandidaten:
            if model.kind is not Kind.MODEL:
                continue
            if model is egress:
                violations.append(
                    f"{egress.name} ist selbst ein Modellschritt und verlässt das System. "
                    "Zwischen Generierung und Ausgang liegt kein Schritt, in dem ein "
                    "human_gate überhaupt stehen könnte."
                )
                continue
            for path in _paths(graph, model, egress):
                # Das Gate muss HINTER dem Modell liegen: path[0] ist das Modell.
                if not any(s.human_gate for s in path[1:]):
                    violations.append(
                        f"{egress.name} verlässt das System. Pfad "
                        + " → ".join(s.name for s in path)
                        + " enthält hinter dem Modellschritt kein human_gate."
                    )
    return violations


def check_contracts(graph: StepGraph) -> list[str]:
    """Die Vertragstotalität als EIGENE Prüfung — in beide Richtungen.

    Zwei Mengen müssen deckungsgleich sein: was der Graph erzeugt, und wofür
    er einen Vertrag deklariert. Eine Richtung allein reicht nicht:

    * nur „erzeugt ⊆ deklariert" liesse einen Vertrag auf einem Namen stehen,
      den kein Schritt erzeugt — die Tabelle driftete gegen den Graphen;
    * nur „deklariert ⊆ erzeugt" wäre erfüllt, sobald jemand die Tabelle aus
      ``produces`` errechnet. Dann wäre sie eine Kopie und sagte nichts.

    **Warum das hier steht und nicht anderswo — beides gemessen (E15/15a).**
    Nicht in ``StepGraph.__post_init__``: ein Konstruktorhalt zwänge jeden
    Testgraphen, sofort vollständig zu sein, und in
    ``tests/test_receipt_and_graph.py`` stehen fünf bewusst winzige Graphen.
    Nicht in :func:`check_egress_gates`: eine Wegwerfprobe hat gezeigt, dass
    die naive Fassung dort **sechs von 53** Tests derselben Datei fallen
    lässt, weil sie auf die exakte Ausgabe dieser Funktion zusichern. Die
    Kerninvariante darf nicht in Vertragslärm untergehen.

    Diese Funktion liefert eine **Liste** und wirft nicht. Aus der Liste macht
    die Produktionsgrenze einen Fehler — :func:`build_graph`, der
    ``invariants``-Job und ``ohpipe.application.replay`` vor dem Fold. Eine
    Prüffunktion, die selbst wirft, ist an genau einer Stelle brauchbar; eine,
    die berichtet, an jeder.

    Leere Liste = grün.
    """
    verstoesse: list[str] = []
    erzeugt = graph.artifacts
    deklariert = set(graph.contracts)
    for name in sorted(erzeugt - deklariert):
        verstoesse.append(
            f"{name!r} wird von Schritt {graph.producer_of(name).name!r} erzeugt, "
            "hat aber keinen Vertrag. Ein Artefakt ohne Vertrag ist ein Befund, "
            "kein Default (E2-N Nummer 2)."
        )
    for name in sorted(deklariert - erzeugt):
        verstoesse.append(
            f"{name!r} trägt einen Vertrag, aber kein Schritt dieses Graphen "
            "erzeugt den Namen. Eine Vertragstabelle, die über den Graphen "
            "hinausreicht, deckt ihn nicht — sie behauptet ihn."
        )
    for name, contract in graph.contracts.items():
        if (
            contract is not None
            and contract.text_profile is not None
            and contract.text_profile not in PROFILES
        ):
            verstoesse.append(f"{name}: unbekanntes Textprofil")
    for step in graph:
        if step.confirms is not None:
            if (
                not step.human_gate
                or step.kind is not Kind.HUMAN
                or step.confirms not in step.requires
            ):
                verstoesse.append(
                    f"{step.name}: confirms muss eine Eingabe eines menschlichen Gates sein"
                )
            contract = graph.contracts.get(step.confirms)
            if contract is None or contract.text_profile is None:
                verstoesse.append(f"{step.name}: confirms bezeichnet keine deklarierte Textrolle")
        gates = [
            (a, graph.producer_of(a)) for a in step.requires if graph.producer_of(a).human_gate
        ]
        if any(g.confirms is not None for _, g in gates):
            candidates = [
                (a, g)
                for a, g in gates
                if g.confirms is not None
                and (step.reads_text is None or g.confirms == step.reads_text)
            ]
            if (len(gates) > 1 and step.reads_text is None) or len(candidates) != 1:
                verstoesse.append(
                    f"{step.name}: mehrdeutige Textrolle; reads_text muss genau ein Textgate auswählen"
                )
        elif step.reads_text is not None:
            verstoesse.append(
                f"{step.name}: reads_text hat kein entsprechendes Textgate in requires"
            )
    return verstoesse


def confirmed_text_role(graph: StepGraph, step_name: str) -> tuple[str, Step, str]:
    """Gateartefakt, Gateschritt, Textartefakt aus dem geprüften Vertrag."""
    problems = check_contracts(graph)
    if problems:
        raise GraphError("; ".join(problems))
    consumer = graph.get(step_name)
    candidates = [
        (artifact, graph.producer_of(artifact))
        for artifact in consumer.requires
        if graph.producer_of(artifact).confirms is not None
        and (
            consumer.reads_text is None
            or graph.producer_of(artifact).confirms == consumer.reads_text
        )
    ]
    if len(candidates) != 1:
        raise GraphError(f"{step_name}: genau eine bestätigte Textrolle erforderlich")
    artifact, gate = candidates[0]
    return artifact, gate, gate.confirms


# ------------------------------------------------- die kanonische Hashdomäne (E8)


#: Domänentrenner und Fassung der Graphvertrags-Berechnung. E8 legt die
#: Berechnung mit **diesem** Commit fest; Laufzeitbindung, Bestandsmigration
#: und Kompatibilitätsakt bekommen eine eigene Serie danach. Unter C1 wird
#: kein Journalfingerprint berechnet und keiner erzwungen.
GRAPH_CONTRACT_DOMAIN = "ohpipe/graph-contract"
GRAPH_CONTRACT_VERSION = 2


def graph_contract_fingerprint(graph: StepGraph) -> str:
    """Die kanonische Hashdomäne des Graphvertrags — festgelegt, nicht gebunden.

    E8 wörtlich: *„Ein ``graph_sha256`` ohne kanonische Hashdomäne ist kein
    ausführbarer Vertrag, sondern ein Name für etwas, das noch niemand rechnen
    kann. Die Berechnung wird mit dem Commit festgelegt, der
    ``ArtifactContract`` einführt."* Genau das ist hier, und **nur** das:
    diese Funktion wird von nichts aufgerufen, was ein Journal liest oder
    schreibt. Wer sie in eine Bindung einbaut, tut das in einer eigenen Serie
    mit eigenem Upgradeakt.

    Was in die Domäne geht, ist **Semantik und nicht Darstellung**:

    * Domänentrenner und Fassungsnummer, damit ein Hash aus einer anderen
      Domäne nie zufällig gleich aussieht und ein Rechenwechsel sichtbar wird;
    * je Schritt: Name, Art, ``requires``, ``produces``, ``human_gate``,
      ``leaves_system``, ``idempotent``;
    * je Artefakt: die drei Vertragsbooleans und das deklarierte Textprofil;
    * confirms und reads_text als explizite Textbindungen.

    Was ausdrücklich NICHT hineingeht: ``description`` und ``cost``. Beides
    ist Prosa beziehungsweise Bedienhinweis. Die erste Fassung nahm den ganzen
    Schritt, und damit hätte eine Tippfehlerkorrektur in einer Beschreibung
    jedes gebundene Journal ungültig gemacht — ein Fingerprint, der auf
    Kommentare anspricht, wird beim ersten Mal umgangen statt eingehalten.
    Ebenfalls nicht drin: die Reihenfolge der Schritte im Tupel. Sie ist laut
    :func:`build_graph` bedeutungslos, deshalb wird nach Namen sortiert.
    """
    schritte = [
        {
            "name": s.name,
            "kind": s.kind.value,
            "requires": sorted(s.requires),
            "confirms": s.confirms,
            "reads_text": s.reads_text,
            "produces": sorted(s.produces),
            "human_gate": s.human_gate,
            "leaves_system": s.leaves_system,
            "idempotent": s.idempotent,
        }
        for s in sorted(graph.steps, key=lambda s: s.name)
    ]
    vertraege = {
        name: {
            "binding_required": v.binding_required,
            "provenance_required": v.provenance_required,
            "decision_required": v.decision_required,
            "text_profile": v.text_profile,
        }
        for name, v in sorted(graph.contracts.items())
    }
    return sha256_json(
        {
            "domain": GRAPH_CONTRACT_DOMAIN,
            "version": GRAPH_CONTRACT_VERSION,
            "steps": schritte,
            "contracts": vertraege,
        }
    )


# ------------------------------------------------- die Vertragstabellen


#: Die Sechzehnertabelle des Sandbox-Graphen, ausgeschrieben.
#:
#: **Ausgeschrieben und nicht aus Rollen errechnet.** Eine Ableitung
#: `Kind.MODEL -> provenance_required=True` sähe kürzer aus und wäre wieder
#: eine Kopie von ``steps``: der Graph prüfte sich gegen sich selbst, und
#: E2-N Nummer 5 (``l1.coverage`` und ``release.preview`` ohne Bindung) hätte
#: als Sonderfall danebengestanden. Die Rollen stehen als Kommentar dabei,
#: damit die Zeilen lesbar bleiben; verbindlich sind die Werte.
_BASISVERTRAEGE: dict[str, ArtifactContract] = {
    # Ingress (1) — E2-N Nummer 3: alle drei Pflichten false. Es hat weder
    # Anker noch Beleg noch Entscheidung; es IST die Fassung, an die gebunden
    # wird, und seine Eingabe liegt ausserhalb des Systems.
    "transcript.revision": ArtifactContract(
        binding_required=False,
        provenance_required=False,
        decision_required=False,
        text_profile=NFC_STRICT.id,
    ),
    # Deterministische Ableitung (4) — Receipt erforderlich, Entscheidung N/A.
    # l1.coverage und release.preview ohne Bindung (E2-N Nummer 5): eine Zahl
    # und eine Vorschau tragen keine Textanker. Mit true stünden beide ohne
    # Ankerereignis dauerhaft auf UNKNOWN -> STOP, oder ihr Erzeuger schriebe
    # BOUND und löge.
    "l1.coverage": ArtifactContract(
        binding_required=False, provenance_required=True, decision_required=False
    ),
    "metadata.draft": ArtifactContract(
        binding_required=True, provenance_required=True, decision_required=False
    ),
    "abstract.draft": ArtifactContract(
        binding_required=True, provenance_required=True, decision_required=False
    ),
    "release.preview": ArtifactContract(
        binding_required=False, provenance_required=True, decision_required=False
    ),
    # Modellvorschlag (2) — Modellreceipt mit Lauf-Autorisierung, Entscheidung
    # N/A. Die fachliche Annahme erzeugt l1.adjudicated, nicht diese Zeile.
    "l1.suggestions": ArtifactContract(
        binding_required=True, provenance_required=True, decision_required=False
    ),
    "analysis.draft": ArtifactContract(
        binding_required=True, provenance_required=True, decision_required=False
    ),
    # Menschlich bestätigtes Ergebnis (5) — E2-N Nummer 6:
    # provenance_required=false, das Gate IST der Beleg. Der Eingabebezug
    # hängt an input_refs, nicht an einem Receipt.
    "transcript.confirmed": ArtifactContract(
        binding_required=True, provenance_required=False, decision_required=True
    ),
    "l1.adjudicated": ArtifactContract(
        binding_required=True, provenance_required=False, decision_required=True
    ),
    "metadata.confirmed": ArtifactContract(
        binding_required=True, provenance_required=False, decision_required=True
    ),
    "abstract.confirmed": ArtifactContract(
        binding_required=True, provenance_required=False, decision_required=True
    ),
    "analysis.confirmed": ArtifactContract(
        binding_required=True, provenance_required=False, decision_required=True
    ),
    # Freigabe (2) — menschliche Decision erforderlich, kein Receipt.
    # analysis.approved bekommt die Werte von release.approved (E2-N Nummer 7);
    # die Symmetrie ist im Graphen angelegt und nicht bloss vermutet.
    "release.approved": ArtifactContract(
        binding_required=True, provenance_required=False, decision_required=True
    ),
    "analysis.approved": ArtifactContract(
        binding_required=True, provenance_required=False, decision_required=True
    ),
    # Egress (2) — Ableitungsbeleg erforderlich. decision_required bleibt
    # true (E2-N Nummer 8) und wird durch eine GEERBTE Entscheidung erfüllt;
    # das WENN aus E2 steckt in der Erfüllung, nicht im Vertragswert. Wie
    # geerbt wird, entscheidet C5 (12a/13a) — hier steht nur die Pflicht.
    "export.bundle": ArtifactContract(
        binding_required=True, provenance_required=True, decision_required=True
    ),
    "analysis.bundle": ArtifactContract(
        binding_required=True, provenance_required=True, decision_required=True
    ),
}


#: Der Referenzgraph des MVP. Bewusst klein: was hier nicht steht, kann
#: ``continue`` auch nicht auslösen.
DEFAULT_GRAPH = StepGraph(
    steps=(
        Step(
            "ingest",
            Kind.DETERMINISTIC,
            produces=("transcript.revision",),
            description="SRT/VTT/DOCX/TXT -> TranscriptRevision (inhaltsadressiert)",
        ),
        Step(
            "transcript.confirm",
            Kind.HUMAN,
            requires=("transcript.revision",),
            confirms="transcript.revision",
            produces=("transcript.confirmed",),
            human_gate=True,
            cost="human",
            description="Der Mensch bestätigt die Fassung, auf die Anker zeigen werden",
        ),
        Step(
            "l1.suggest",
            Kind.MODEL,
            requires=("transcript.confirmed",),
            produces=("l1.suggestions",),
            cost="model",
            description="Deskriptive L1-Vorschläge, lokal; Beleg statt Regeneration",
        ),
        Step(
            "l1.coverage",
            Kind.DETERMINISTIC,
            requires=("l1.suggestions", "transcript.confirmed"),
            produces=("l1.coverage",),
            description="Coverage aus den Ankerspannen; Gate, keine Kennzahl",
        ),
        Step(
            "l1.review",
            Kind.HUMAN,
            requires=("l1.suggestions", "l1.coverage"),
            produces=("l1.adjudicated",),
            human_gate=True,
            cost="human",
            description="Unit-Review: annehmen, ändern, verwerfen",
        ),
        Step(
            "metadata.derive",
            Kind.DETERMINISTIC,
            requires=("l1.adjudicated",),
            produces=("metadata.draft",),
            description="Kontrollierte deskriptive Felder — eigene Datei, nie in die bestätigte (ADR 0005)",
        ),
        Step(
            "metadata.confirm",
            Kind.HUMAN,
            requires=("metadata.draft",),
            produces=("metadata.confirmed",),
            human_gate=True,
            cost="human",
            description="Kontrollierte Felder setzt nur ein Mensch",
        ),
        # -- Ab hier zwei getrennte Pfade (ADR 0020) ----------------------
        # Die Unterscheidung deskriptiv/analytisch wird nicht am Text
        # gemessen, sondern an der Ablage: zwei Artefakte, zwei
        # Entscheidungen, zwei Ausgänge. Für den Workflow dürfen beide auf
        # EINER Reviewseite stehen — die Trennung ist strukturell, nicht
        # bedienerisch.
        Step(
            "abstract.derive",
            Kind.DETERMINISTIC,
            requires=("l1.adjudicated", "metadata.confirmed"),
            produces=("abstract.draft",),
            description="Deskriptiver Katalogabstract, Block B des Metadata Model",
        ),
        Step(
            "abstract.confirm",
            Kind.HUMAN,
            requires=("abstract.draft",),
            produces=("abstract.confirmed",),
            human_gate=True,
            cost="human",
            description="Der Mensch ordnet zu: gehört das hierhin oder in die Analysezusammenfassung?",
        ),
        Step(
            "analysis.summarise",
            Kind.MODEL,
            requires=("l1.adjudicated",),
            produces=("analysis.draft",),
            cost="model",
            description="Analysezusammenfassung — ausdrücklich Interpretation, eigener Pfad",
        ),
        Step(
            "analysis.confirm",
            Kind.HUMAN,
            requires=("analysis.draft",),
            produces=("analysis.confirmed",),
            human_gate=True,
            cost="human",
            description="Eigene Entscheidung, eigene Bytes — nicht dieselbe wie beim Abstract",
        ),
        Step(
            "release.preview",
            Kind.DETERMINISTIC,
            requires=("metadata.confirmed", "abstract.confirmed", "l1.adjudicated"),
            produces=("release.preview",),
            description="Vorschau des Katalogartefakts. Die Analyse ist NICHT enthalten",
        ),
        Step(
            "release.approve",
            Kind.HUMAN,
            requires=("release.preview",),
            produces=("release.approved",),
            human_gate=True,
            cost="human",
            description="Beleg auf genau die freizugebenden Bytes",
        ),
        Step(
            "analysis.approve",
            Kind.HUMAN,
            requires=("analysis.confirmed",),
            produces=("analysis.approved",),
            human_gate=True,
            cost="human",
            description="Eigene Freigabe für den Analysepfad (ADR 0020)",
        ),
        Step(
            "analysis.export",
            Kind.EGRESS,
            requires=("analysis.approved",),
            produces=("analysis.bundle",),
            leaves_system=True,
            description="Analyseausgang — getrennt vom Katalog, als Interpretation markiert",
        ),
        Step(
            "export",
            Kind.EGRESS,
            requires=("release.approved",),
            produces=("export.bundle",),
            leaves_system=True,
            description="WebVTT/JSON/OHMS/DC — Formatadapter, getrennt von der Freigabepolicy",
        ),
    ),
    # `dict(...)` und nicht die Modulkonstante selbst: sonst wäre
    # `DEFAULT_GRAPH.contracts` dasselbe Objekt wie `_BASISVERTRAEGE`, und wer
    # in den Graphen schriebe, änderte die Basis für jeden CHILDLUX-Graphen
    # mit. Dieselbe Falle wie ein veränderliches Default-Argument, nur eine
    # Ebene höher.
    contracts=dict(_BASISVERTRAEGE),
)


# ------------------------------------------------- profilabhängiger Graph


#: Der Pseudonymisierungspfad aus ADR 0024. Er wird zwischen
#: ``transcript.confirmed`` und L1 eingehängt — und wenn er eingehängt ist,
#: sind Anker, L1, Coverage und Export ohne ihn nicht erreichbar.
_PSEUDONYMISATION = (
    Step(
        "pii.detect",
        Kind.MODEL,
        requires=("transcript.confirmed",),
        produces=("pii.spans",),
        cost="model",
        description="Erkennung ausschließlich auf Cue-Payloads (ADR 0024 §1)",
    ),
    Step(
        "pseudonymise",
        Kind.DETERMINISTIC,
        requires=("transcript.confirmed", "pii.spans"),
        produces=("transcript.pseudonymised.draft", "replacement.report"),
        description="Spanbasiert und deterministisch; kein generatives Umschreiben",
    ),
    Step(
        "pseudonymisation.review",
        Kind.HUMAN,
        requires=("transcript.pseudonymised.draft", "replacement.report"),
        produces=("transcript.pseudonymised.confirmed",),
        confirms="transcript.pseudonymised.draft",
        human_gate=True,
        cost="human",
        description="Bindet an Ausgabebytes, Quellhash, Beleg und Bericht zugleich",
    ),
)


#: Die vier Verträge, die NUR im CHILDLUX-Profil gelten — als Erweiterung der
#: Basistabelle, nicht als zweite Gesamtliste.
#:
#: **Gemessen begründet, warum es keine gemeinsame Zwanzigertabelle gibt.**
#: Hinge eine einzige Zwanzigertabelle an beiden Graphen, meldete
#: :func:`check_contracts` für den Sandbox-Graphen **vier** Verstösse der Form
#: „Vertrag ohne erzeugenden Schritt" — genau das, was der
#: C1-Gegenrichtungsmarker abfängt. Die Tabelle wird deshalb gebaut wie die
#: Schritte: profilabhängig, in :func:`build_graph`.
_PSEUDONYMISATION_VERTRAEGE: dict[str, ArtifactContract] = {
    # Modellvorschlag — Erkennung ausschliesslich auf Cue-Payloads (ADR 0024).
    "pii.spans": ArtifactContract(
        binding_required=True, provenance_required=True, decision_required=False
    ),
    # Deterministische Ableitung (2) — spanbasiert, kein generatives
    # Umschreiben, also Beleg statt Entscheidung.
    "transcript.pseudonymised.draft": ArtifactContract(
        binding_required=True,
        provenance_required=True,
        decision_required=False,
        text_profile=NFC_STRICT.id,
    ),
    "replacement.report": ArtifactContract(
        binding_required=True, provenance_required=True, decision_required=False
    ),
    # Menschlich bestätigtes Ergebnis — E2-N Nummer 6 nennt es namentlich mit.
    "transcript.pseudonymised.confirmed": ArtifactContract(
        binding_required=True, provenance_required=False, decision_required=True
    ),
}


# P4a: deklarative Lieferverträge. Keiner dieser fünf Schritte hat einen Handler.
_MANUAL_PSEUDONYMISATION = (
    Step(
        "pii.mark",
        Kind.HUMAN,
        requires=("transcript.confirmed", "transcript.revision"),
        produces=("pii.spans",),
        human_gate=True,
        cost="human",
        reads_text="transcript.revision",
        description="Manuelle Markierung der bestätigten Originalquelle; ungebaut",
    ),
    Step(
        "pseudonymise",
        Kind.DETERMINISTIC,
        requires=("transcript.confirmed", "transcript.revision", "pii.spans"),
        produces=("transcript.pseudonymised.draft",),
        reads_text="transcript.revision",
        description="Provisorischer spanbasierter Entwurf; ungebaut",
    ),
    Step(
        "pseudonymisation.cases",
        Kind.HUMAN,
        requires=(
            "transcript.confirmed",
            "transcript.revision",
            "pii.spans",
            "transcript.pseudonymised.draft",
        ),
        produces=("pseudonymisation.cases",),
        human_gate=True,
        cost="human",
        reads_text="transcript.revision",
        description="Bestätigte Fallsitzung, kein Vollständigkeits- oder Textgate; ungebaut",
    ),
    Step(
        "pseudonymise.finalise",
        Kind.DETERMINISTIC,
        requires=(
            "transcript.confirmed",
            "transcript.revision",
            "pii.spans",
            "pseudonymisation.cases",
        ),
        produces=("transcript.pseudonymised.final", "replacement.report"),
        reads_text="transcript.revision",
        description="Finalisierung und Bericht bei vollständiger Auflösung; ungebaut",
    ),
    Step(
        "pseudonymisation.review",
        Kind.HUMAN,
        requires=(
            "transcript.confirmed",
            "transcript.revision",
            "pii.spans",
            "pseudonymisation.cases",
            "transcript.pseudonymised.final",
            "replacement.report",
        ),
        produces=("transcript.pseudonymised.confirmed",),
        human_gate=True,
        cost="human",
        reads_text="transcript.revision",
        confirms="transcript.pseudonymised.final",
        description="Finale Volltextprüfung mit vollständiger Mehrfachbindung; ungebaut",
    ),
)

# binding_required ist die Domänenankerachse, nicht die Quellprovenienz.
# Vor dem finalen Gate dürfen keine fachlichen Anker entstehen (ADR 0024).
_MANUAL_VERTRAEGE = {
    "pii.spans": ArtifactContract(
        binding_required=False, provenance_required=True, decision_required=True
    ),
    "transcript.pseudonymised.draft": ArtifactContract(
        binding_required=False,
        provenance_required=True,
        decision_required=False,
        text_profile=NFC_STRICT.id,
    ),
    "pseudonymisation.cases": ArtifactContract(
        binding_required=False, provenance_required=True, decision_required=True
    ),
    "transcript.pseudonymised.final": ArtifactContract(
        binding_required=False,
        provenance_required=True,
        decision_required=False,
        text_profile=NFC_STRICT.id,
    ),
    "replacement.report": ArtifactContract(
        binding_required=False, provenance_required=True, decision_required=False
    ),
    "transcript.pseudonymised.confirmed": ArtifactContract(
        binding_required=False, provenance_required=True, decision_required=True
    ),
}


def build_graph(profile: object) -> StepGraph:
    """Der Graph wird aus dem validierten Profil gebaut, nicht global gesetzt.

    ADR 0024 ist eindeutig: „Der Graph wird vor der Planung deterministisch aus
    dem validierten Profil gebaut und enthält nur die gewählte Kante."

    Solange ``DEFAULT_GRAPH`` eine Modulkonstante war und die CI ihre
    Invariante darüber bewies, bewies sie sie über einen Graphen, den die
    Produktion nicht verwenden wird. Das ist die gefährlichste Sorte grüner
    Job: Er sagt etwas Wahres über etwas Unbenutztes.

    Es gibt **kein** Laufzeit-Flag, keinen Per-Record-Override und keinen
    Fallback von der verpflichtenden auf die direkte Kante. Verlangt das Profil
    Pseudonymisierung, existiert die direkte Kante im gebauten Graphen nicht.
    """
    verlangt = bool(getattr(profile, "pseudonymisation_required", False))
    if not verlangt:
        return _fail_closed(
            StepGraph(
                steps=DEFAULT_GRAPH.steps,
                contracts=dict(DEFAULT_GRAPH.contracts),
                profile_id=getattr(profile, "id", None),
            ),
            "Sandbox-",
        )

    mode = getattr(profile, "pii_detection", None)
    if mode not in ("manual", "model"):
        raise GraphError("Pflichtprofil ohne gültiges pii_detection")
    block = _MANUAL_PSEUDONYMISATION if mode == "manual" else _PSEUDONYMISATION
    contracts = _MANUAL_VERTRAEGE if mode == "manual" else _PSEUDONYMISATION_VERTRAEGE
    quelle = "transcript.pseudonymised.confirmed"
    neu_erzeugt = {a for s in block for a in s.produces}
    # JEDES `requires` ausserhalb des Pseudonymisierungsblocks wird umgehaengt,
    # nicht nur das von l1.suggest und l1.coverage. Eine namentliche Liste waere
    # heute vollstaendig und beim naechsten Schritt, der transcript.confirmed
    # verlangt, still unvollstaendig — und die direkte Kante waere wieder da,
    # ohne dass jemand es merkt.
    umgehaengt = tuple(
        replace(
            s,
            requires=tuple(quelle if a == "transcript.confirmed" else a for a in s.requires),
            reads_text="transcript.pseudonymised.final" if mode == "manual" else s.reads_text,
        )
        if "transcript.confirmed" in s.requires and not set(s.produces) & neu_erzeugt
        else s
        for s in DEFAULT_GRAPH.steps
    )
    # Die Reihenfolge im Tupel ist semantisch bedeutungslos: `topological()`
    # sortiert nach `requires`/`produces`, nicht nach Position. Gesplict wird
    # ausschliesslich, damit der gebaute Graph in Fehlermeldungen und im
    # Debugger in der Reihenfolge liest, in der er laeuft. Wer hier vorne einen
    # Schritt einfuegt, aendert die Ausgabe und nicht die Ausfuehrung.
    #
    # `not in kopf` waere hier eine Gleichheits- und keine Identitaetspruefung:
    # zwei strukturgleiche Schritte fielen gemeinsam heraus. Deshalb ueber die
    # Namen, die `StepGraph` ohnehin als eindeutig erzwingt.
    vorne = {"ingest", "transcript.confirm"}
    kopf = tuple(s for s in umgehaengt if s.name in vorne and quelle not in s.requires)
    kopf_namen = {s.name for s in kopf}
    rest = tuple(s for s in umgehaengt if s.name not in kopf_namen)
    return _fail_closed(
        StepGraph(
            steps=kopf + block + rest,
            contracts={**_BASISVERTRAEGE, **contracts},
            profile_id=getattr(profile, "id", None),
        ),
        "pseudonymisierend ",
    )


def _fail_closed(graph: StepGraph, wofuer: str) -> StepGraph:
    """Die erste der drei Vollstreckungsflächen: gebaut wird nur, was deckt.

    :func:`check_contracts` berichtet; **hier** wird daraus ein Fehler. Die
    Grenze sitzt in :func:`build_graph` und nicht im Konstruktor, weil der
    Konstruktor auch die kleinen Testgraphen baut — dieselbe Trennung wie in
    E15/15a, nur von der anderen Seite betrachtet: der Konstruktor darf
    unvollständig, der PRODUKTIONSWEG darf es nicht.

    Der Rückgabewert ist der Graph selbst, damit die Grenze im Aufrufer eine
    Zeile bleibt und nicht als zweite Anweisung danebensteht, die man
    vergessen kann.
    """
    verstoesse = check_contracts(graph)
    if verstoesse:
        raise GraphError(
            f"Der {wofuer}gebaute Graph verletzt die Vertragstotalität:\n  "
            + "\n  ".join(verstoesse)
        )
    return graph
