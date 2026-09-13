"""P4c-Effekte existieren erst mit geprüftem Abschluss; Einbettung im P4b-Fold."""

from ohpipe.domain import manual_context

from types import SimpleNamespace
from ..domain.p4c_events import check, basis
from ..domain.instance import InstanceRegistry
from ..registry_store import REGISTRY, RESOLUTION, GATE
from ..protected_store import canonical, digest


class Expansion:
    def __init__(self):
        self.prepared = {}
        self.prepared_epoch = {}
        self.completed = set()
        self.head = None
        self.initial_preparation = None
        self.refs = []
        self.active_refs = []

    def consume(self, e, output, graph, authority, refs, published):
        from .replay import replay

        p, rid = e.payload, e.record_id
        check(e.kind, p, rid)
        if not manual_context.known(graph.profile_id):
            raise ValueError("Fremder P4c-Graph")

        def emit(kind, payload, record=rid):
            output.append(
                SimpleNamespace(
                    kind=kind, payload=payload, record_id=record, at=e.at, digest=e.digest
                )
            )

        def add(ref, active=False):
            self.refs.append(ref) if ref["role"] == REGISTRY else refs.setdefault(rid, []).append(
                ref
            )
            if active and ref["role"] != REGISTRY:
                published.setdefault(rid, []).append(ref)

        if e.kind in ("p4c.init.prepared", "p4c.initialised"):
            if self.head is not None or not graph.matches_context(
                p["ref"]["aad"]["profile"], p["ref"]["aad"]["graph"]
            ):
                raise ValueError("Register bereits initialisiert oder fremd")
            if e.kind == "p4c.init.prepared":
                if self.initial_preparation is not None:
                    raise ValueError("Mehrdeutige Registerinitialisierung")
                self.initial_preparation = p
                add(p["ref"])
                output.append(e)
                return
            if self.initial_preparation is not None and p != self.initial_preparation:
                raise ValueError("Initialisierungsabschluss widerspricht Vorbereitung")
            # Alte abgeschlossene Initialisierungen bleiben bytegleich lesbar.
            self.head = p["ref"]
            add(self.head)
            self.active_refs.append(self.head)
            emit("p4c.registry.source", {"ref": self.head}, None)
            return
        if e.kind == "p4c.prepared":
            key = digest(canonical(p))
            if key in self.prepared or self.head != p["registry_before"]:
                raise ValueError("Register-CAS oder Operationskennung widersprüchlich")
            self.prepared[key] = (rid, p)
            self.prepared_epoch[key] = len(output) + 1
            for ref in p["refs"].values():
                add(ref)
            if p["registry_after"] != p["registry_before"]:
                add(p["registry_after"])
            output.append(e)
            return
        key = p["prepared_sha256"]
        if key in self.completed or key not in self.prepared or self.prepared[key][0] != rid:
            raise ValueError("P4c-Abschluss ohne eindeutige Vorbereitung")
        p = self.prepared[key][1]
        if e.kind == "p4c.aborted":
            self.completed.add(key)
            output.append(e)
            return
        if self.head != p["registry_before"]:
            raise ValueError("P4c-Register-CAS veraltet")
        view = replay(output, graph=graph, authority=authority, _p4b_expanded=True).get(rid)
        if (
            view is None
            or view.findings
            or not view.enabled
            or any(f.withdrawal for f in view.facts.values())
        ):
            raise ValueError("P4c-Record gesperrt")
        if basis(view, p["phase"]) != p["basis"]:
            raise ValueError("P4c-Grundlage veraltet")
        actors = InstanceRegistry()
        for event in output:
            if event.kind == "instance.registered":
                actors.register(dict(event.payload), event_digest=event.digest)
            elif event.kind == "instance.retired":
                actors.retire(dict(event.payload), event_digest=event.digest)
        human = actors.get(p["actor"], active=True)
        if human.source != "mensch" or human.state_sha256 != p["actor_state"]:
            raise ValueError("P4c-Actor nicht aktuell")
        if p["registry_after"] != self.head:
            self.head = p["registry_after"]
            self.active_refs.append(self.head)
            emit(
                "p4c.registry.source",
                {"ref": self.head, "activation": self.prepared_epoch[key]},
                None,
            )
        inputs = dict(p["basis"])
        if REGISTRY in inputs and p["registry_after"] != p["registry_before"]:
            inputs[REGISTRY] = [self.head["sha256"], self.prepared_epoch[key]]
        if p["phase"] == "resolve":
            ref = p["refs"][RESOLUTION]
            emit("p4c.resolution.source", {"ref": ref, "basis": p["basis"]})
            published.setdefault(rid, []).append(ref)
        else:
            roles = (
                {GATE: digest(canonical(p["marker"]))}
                if p["phase"] == "review"
                else {k: r["sha256"] for k, r in p["refs"].items()}
            )
            for role, sha in roles.items():
                emit("artifact.produced", {"artifact": role, "sha256": sha})
                emit(
                    "receipt.recorded",
                    dict(
                        artifact=role,
                        output_sha256=sha,
                        inputs={k: v[0] for k, v in inputs.items()},
                        code_version="p4c.v1",
                        step="pseudonymisation.review"
                        if p["phase"] == "review"
                        else "pseudonymise.finalise",
                    ),
                )
            if p["phase"] == "review":
                emit(
                    "decision.recorded",
                    dict(
                        artifact=GATE,
                        subject_sha256=roles[GATE],
                        verdict="ACCEPT",
                        reference="p4c-fulltext-v1",
                        actor=p["actor"],
                        at=p["at"],
                        input_refs={k: v[0] for k, v in inputs.items()},
                        input_refs_version=4,
                        profile_id=graph.profile_id,
                        graph_sha256=p["registry_after"]["aad"]["graph"],
                    ),
                )
            else:
                published.setdefault(rid, []).extend(p["refs"].values())
        self.completed.add(key)
