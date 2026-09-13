"""Enge P4b-Publikation: keine Teilwirkung vor dem Abschlussbeleg."""

from ohpipe.domain import manual_context

from types import SimpleNamespace

from ..domain.p4b_events import check, POLICY, ROLES
from ..domain.instance import InstanceRegistry
from ..protected_store import canonical, digest


def basis(view, phase):
    required = set(view.graph.get(phase).requires)
    out = {}
    for role in required:
        f = view.facts.get(role)
        if f is None or role not in view.have:
            raise ValueError("P4b-Eingabe nicht nutzbar")
        out[role] = [f.sha256, f.epoch]
    policy = view.sources.get(POLICY)
    if not policy or not policy[0]:
        raise ValueError("P4b-Policybeobachtung fehlt")
    out[POLICY] = list(policy)
    return out


def effects(p):
    ref = p["ref"]
    a = ref["aad"]
    role, sha = ref["role"], ref["sha256"]
    refs = {k: pair[0] for k, pair in p["basis"].items()}
    out = [
        ("artifact.produced", {"artifact": role, "sha256": sha}),
        (
            "receipt.recorded",
            {
                "artifact": role,
                "output_sha256": sha,
                "inputs": refs,
                "code_version": "p4b.v1",
                "step": a["phase"],
            },
        ),
    ]
    if a["phase"] != "pseudonymise":
        out.append(
            (
                "decision.recorded",
                {
                    "artifact": role,
                    "subject_sha256": sha,
                    "verdict": "ACCEPT",
                    "reference": "p4b-session-v1",
                    "actor": p["actor"],
                    "at": p["at"],
                    "input_refs": refs,
                    "input_refs_version": 3,
                    "profile_id": a["profile"],
                    "graph_sha256": a["graph"],
                },
            )
        )
    return out


def expand(events, graph, authority):
    """Metadaten werden gemeinsam validiert; echte P4b-Effekte nur hier erzeugt.

    Präfix-Replay prüft bei Abschluss die aktuellen Hashes UND Aktivierungen.
    Seine virtuelle Reihenfolge entspricht dem vollständigen Replay exakt.
    """
    from .replay import replay

    from .registry_replay import Expansion
    from ..registry_store import FINAL, REPORT, GATE
    from ..protected_store import ProtectionError

    p4c = Expansion()
    output, prepared, checkpoints, completed = [], {}, {}, set()
    refs, published, findings = {}, {}, {}
    for e in events:
        rid, kind, p = getattr(e, "record_id", None), e.kind, getattr(e, "payload", None) or {}
        if kind.startswith("p4c."):
            try:
                p4c.consume(e, output, graph, authority, refs, published)
            except (ValueError, AttributeError, KeyError, TypeError, ProtectionError):
                findings.setdefault(rid, []).append("P4c-Veröffentlichungsbeleg widersprüchlich")
            continue
        if not kind.startswith("p4b."):
            if (
                manual_context.known(graph.profile_id)
                and p.get("artifact") in (set(ROLES.values()) | {FINAL, REPORT, GATE})
                and kind in ("artifact.produced", "receipt.recorded", "decision.recorded")
                and p.get("verdict") not in ("WITHDRAW", "UNDO", "REJECT")
            ):
                findings.setdefault(rid, []).append("P4b-Effekt ohne abgeschlossenen Schutzakt")
                continue
            output.append(e)
            continue
        try:
            check(kind, p, rid)
            if not manual_context.known(graph.profile_id):
                raise ValueError()
            if kind == "p4b.policy":
                if not graph.matches_context(p["profile"], p["graph"]):
                    raise ValueError()
                output.append(e)
                continue
            if kind == "p4b.completed":
                key = p["prepared_sha256"]
                if key not in prepared or key in completed:
                    raise ValueError()
                plan = prepared[key]
                if plan[0] != rid:
                    raise ValueError()
                p = plan[1]
                view = replay(output, graph=graph, authority=authority, _p4b_expanded=True).get(rid)
                if (
                    view is None
                    or not view.enabled
                    or view.findings
                    or basis(view, p["ref"]["aad"]["phase"]) != p["basis"]
                ):
                    raise ValueError()
                registry = InstanceRegistry()
                for event in output:
                    if event.kind == "instance.registered":
                        registry.register(dict(event.payload), event_digest=event.digest)
                    elif event.kind == "instance.retired":
                        registry.retire(dict(event.payload), event_digest=event.digest)
                actor = registry.get(p["actor"], active=True)
                if actor.source != "mensch" or actor.state_sha256 != p["actor_state"]:
                    raise ValueError()
                if p["checkpoint"] is not None:
                    ck = checkpoints.get((rid, p["ref"]["aad"]["phase"]))
                    if ck is None or digest(canonical(ck)) != p["checkpoint"]:
                        raise ValueError()
                for ek, ep in effects(p):
                    output.append(
                        SimpleNamespace(
                            kind=ek, payload=ep, record_id=rid, at=e.at, digest=e.digest
                        )
                    )
                published.setdefault(rid, []).append(p["ref"])
                completed.add(key)
            else:
                ref = p["ref"]
                a = ref["aad"]
                if not graph.matches_context(a["profile"], a["graph"]):
                    raise ValueError()
                refs.setdefault(rid, []).append(ref)
                if kind == "p4b.prepared":
                    key = digest(canonical(p))
                    if key in prepared:
                        raise ValueError()
                    prepared[key] = (rid, p)
                    refs[rid].append(p["plan"])
                else:
                    key = (rid, a["phase"])
                    prior = checkpoints.get(key)
                    if prior and prior["ref"]["aad"]["session_id"] == a["session_id"]:
                        if (
                            p["previous"] != digest(canonical(prior))
                            or a["revision"] != prior["ref"]["aad"]["revision"] + 1
                            or p["actor"] != prior["actor"]
                        ):
                            raise ValueError()
                    elif a["revision"] != 1 or p["previous"] is not None:
                        raise ValueError()
                    checkpoints[key] = p
                output.append(e)  # conserve les époques; aucune efficacité métier
        except (ValueError, AttributeError, KeyError, TypeError):
            findings.setdefault(rid, []).append("P4b-Veröffentlichungsbeleg widersprüchlich")
    # Registerquellen sind global, ihre Referenzen müssen für jeden Record prüfbar sein.
    records = {getattr(e, "record_id", None) for e in output} - {None}
    for rid in records:
        refs.setdefault(rid, []).extend(p4c.refs)
        if p4c.head:
            published.setdefault(rid, []).extend(p4c.active_refs)
        if findings.get(None):
            findings.setdefault(rid, []).extend(findings[None])
    findings.pop(None, None)
    return output, refs, published, findings
