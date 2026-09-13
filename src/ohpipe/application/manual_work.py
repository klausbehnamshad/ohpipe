"""P4b-Arbeitssitzung: Checkpoints sind keine fachlichen Entscheidungen."""

from ohpipe.domain import manual_context

from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import io
import json
import secrets

from ..domain import manual_pseudonymisation as model
from ..domain.instance import InstanceRegistry, InstanceRegistryError
from ..domain.p4b_events import POLICY, ROLES
from ..domain.step import build_graph
from ..policies.authority import Authority
from ..policies.ownership import CutoverLedger, THIS_RUNTIME
from ..project import Profile, GraphBindingState
from ..protected_store import ProtectedStore, ProtectionError, ProtectionBusy, canonical, digest
from ..workspace_lock import workspace_write_lock
from .confirmed_text import read_confirmed_text
from .gate import GateBlocked, GateError, resolve_active_human
from .protected_replay import basis, effects
from .replay import replay
from .storage_integrity import check_referenced, RegistryConfigurationFinding


@contextmanager
def locked(ctx, store):
    try:
        with (
            workspace_write_lock(ctx.ws.root, blocking=False),
            store.lock(),
            ctx.journal.transaction(blocking=False) as tx,
        ):
            store.ensure_current(ctx.journal.key)
            yield tx
    except BlockingIOError:
        raise ProtectionBusy("Schreibakt belegt; unverändert erneut versuchen") from None


def policy(ctx):
    # Kein Watcher: jeder Einstieg, Wiederanlauf und Bestätigungsversuch liest neu.
    from ..cli.main import _profile_path

    profile = Profile.load(_profile_path(ctx.profile_arg))
    if not manual_context.enabled(profile):
        raise ProtectionError("Manualprofil oder dessen Schutzverträge nicht freigegeben")
    if build_graph(profile) != build_graph(ctx.ws.profile):
        raise ProtectionError("Profil-/Graphkontext geändert")
    rules = {k: dict(v) for k, v in profile.pseudonymisation_rules}
    data = canonical(
        {
            "domain": "ohpipe/pseudonymisation-policy",
            "v": 1,
            "version": profile.pseudonymisation_policy_version,
            "rules": rules,
        }
    )
    if digest(data) != profile.pseudonymisation_policy_sha256:
        raise ProtectionError("Policyvertrag stimmt nicht")
    return rules, data


def snapshot(ctx, events, phase, actor):
    if ctx.ws.inspect_graph_binding()[0] is not GraphBindingState.CURRENT:
        raise GateBlocked("Graphbindung fehlt oder wurde geändert")
    if not ctx.journal.key:
        raise ProtectionError("Authentifiziertes Journal erforderlich")
    CutoverLedger.from_journal(
        events,
        authority=Authority.AUTHENTICATED,
        default_runtime=ctx.ws.profile.legacy_runtime or THIS_RUNTIME,
    ).require_write(ctx.record_id)
    view = replay(events, graph=build_graph(ctx.ws.profile), authority=Authority.AUTHENTICATED).get(
        ctx.record_id
    )
    if view is None or view.findings:
        raise GateBlocked("Record fehlt oder Replay enthält Befunde")
    if not view.enabled or any(f.withdrawal for f in view.facts.values()):
        raise GateBlocked("Record deaktiviert oder fachlicher Widerruf aktiv")
    if any(not isinstance(f, RegistryConfigurationFinding) for f in check_referenced(ctx.ws, view)):
        raise GateBlocked("Speicher-/Zugriffsprüfung fehlgeschlagen")
    registry = InstanceRegistry.from_events(events)
    try:
        active = resolve_active_human(registry, actor)
    except InstanceRegistryError:
        raise GateError("Actor fehlt oder ist nicht aktiv") from None
    try:
        inputs = basis(view, phase)
    except ValueError:
        raise GateError("P4b-Grundlage nicht aktuell; vorgelagerten Akt erneuern") from None
    return view, inputs, registry.get(active, active=True)


def refresh(ctx, store):
    rules, raw = policy(ctx)
    with locked(ctx, store) as tx:
        # Prüft vor Beobachtung P1, Record und Actor, aber noch keine P4b-Policy.
        events = list(tx)
        CutoverLedger.from_journal(
            events,
            authority=Authority.AUTHENTICATED,
            default_runtime=ctx.ws.profile.legacy_runtime or THIS_RUNTIME,
        ).require_write(ctx.record_id)
        view = replay(
            events, graph=build_graph(ctx.ws.profile), authority=Authority.AUTHENTICATED
        ).get(ctx.record_id)
        if not tx.key or view is None or view.findings or not view.enabled:
            raise GateBlocked("P4b-Policybeobachtung gesperrt")
        sha = digest(raw)
        if view.sources.get(POLICY, (None, 0))[0] != sha:
            ctx.ws.store().put(io.BytesIO(raw))
            tx.append_once(
                "p4b.policy",
                {
                    "v": 1,
                    "profile": ctx.ws.profile.id,
                    "graph": ctx.ws.running_graph_sha256(),
                    "sha256": sha,
                },
                record_id=ctx.record_id,
                duplikat=lambda e: False,
            )
    return rules


def latest_checkpoint(events, record, phase):
    return next(
        (
            e.payload
            for e in reversed(events)
            if e.record_id == record
            and e.kind == "p4b.checkpoint"
            and e.payload["ref"]["aad"]["phase"] == phase
        ),
        None,
    )


def reference(view, role):
    sha = view.facts[role].sha256
    # Derselbe logische Texthash darf mehrere historische Cipherfassungen haben.
    # Nur ein abgeschlossener Akt liefert eine aktuelle fachliche Referenz.
    for ref in reversed(view.protected_artifacts):
        if ref["role"] == role and ref["sha256"] == sha:
            return ref
    raise ProtectionError("Abgeschlossener Schutzverweis fehlt")


def checkpoint_completed(events, record, checkpoint, view):
    """Nur der exakte Checkpoint mit gültigem Abschluss ist historische Arbeit.

    protected_artifacts stammt aus dem validierenden Replay; ein bloßer
    Prepare- oder frei stehender Completed-Eintrag reicht ausdrücklich nicht.
    """
    completed = {
        e.payload["prepared_sha256"]
        for e in events
        if e.record_id == record and e.kind == "p4b.completed"
    }
    checkpoint_sha = digest(canonical(checkpoint))
    return any(
        e.record_id == record
        and e.kind == "p4b.prepared"
        and e.payload["checkpoint"] == checkpoint_sha
        and digest(canonical(e.payload)) in completed
        and e.payload["ref"] in view.protected_artifacts
        for e in events
    )


class Session:
    def __init__(self, ctx, phase, actor=None, *, resume=False):
        self.ctx, self.phase = ctx, phase
        self.store = ProtectedStore(ctx.ws, ctx.journal.key)
        self.policy = refresh(ctx, self.store)
        events = list(ctx.journal)
        self.view, self.basis, human = snapshot(ctx, events, phase, actor)
        self.actor, self.actor_state = human.coder_id, human.state_sha256
        self.source = read_confirmed_text(ctx, self.view, phase).revision
        self.previous = latest_checkpoint(events, ctx.record_id, phase)
        self.session_id = secrets.token_hex(16)
        self.revision = 0
        self.capsule = None
        if resume:
            if self.previous is None:
                raise GateError("Kein gesicherter Editorstand vorhanden")
            p = self.previous
            if (
                p["actor"] != self.actor
                or p["actor_state"] != self.actor_state
                or p["basis"] != self.basis
            ):
                raise GateError(
                    "Gesicherte Sitzung gehört zu einem anderen Actor oder Eingabestand"
                )
            self.session_id = p["ref"]["aad"]["session_id"]
            self.revision = p["ref"]["aad"]["revision"]
            self.capsule = json.loads(self.store.open(p["ref"], ctx.record_id))
            model.validate(self.source, self.capsule, self.policy)
            with locked(ctx, self.store) as tx:
                self._recheck(tx)
                self.store.pointer(p["ref"])
        elif self.previous is not None:
            # Ein neuer expliziter Akt ist erlaubt, aber kein Übernehmen fremder
            # Editorbytes; bis zum CAS bleibt die letzte gesicherte Fassung erhalten.
            if self.previous["actor"] != self.actor and not checkpoint_completed(
                events, ctx.record_id, self.previous, self.view
            ):
                raise GateError("Fremde aktive Sitzung; keine stille Übernahme")
        if self.capsule is None:
            if phase == "pii.mark":
                self.capsule = {
                    "v": 1,
                    "source": model.source_contract(self.source),
                    "base": [],
                    "overlay": [],
                    "spans": [],
                    "groups": {},
                    "context": "",
                }
            else:
                base = json.loads(self.store.open(reference(self.view, "pii.spans"), ctx.record_id))
                model.validate(self.source, base, self.policy)
                self.capsule = deepcopy(base)
                if phase == "pseudonymisation.cases":
                    self.draft = self.store.open(
                        reference(self.view, "transcript.pseudonymised.draft"), ctx.record_id
                    )
                    if self.draft != model.render(self.source, base, self.policy):
                        raise ProtectionError("Draft und gebundener Plan widersprechen sich")
        if phase == "pseudonymisation.cases":
            base = json.loads(self.store.open(reference(self.view, "pii.spans"), ctx.record_id))
            model.validate(self.source, base, self.policy)
            if self.capsule["base"] != base["spans"]:
                raise ProtectionError(
                    "Fallüberlagerung passt nicht zur gebundenen Markierungsbasis"
                )
            self.draft = self.store.open(
                reference(self.view, "transcript.pseudonymised.draft"), ctx.record_id
            )
            if self.draft != model.render(self.source, base, self.policy):
                raise ProtectionError("Draft und gebundener Plan widersprechen sich")
        self.saved_bytes = canonical(self.capsule) if resume else None

    def _recheck(self, tx):
        events = list(tx)
        _, actual, actor = snapshot(self.ctx, events, self.phase, self.actor)
        if actual != self.basis or actor.state_sha256 != self.actor_state:
            raise GateError("Grundlage seit Anzeige geändert; erneut öffnen")
        _, raw = policy(self.ctx)
        if digest(raw) != self.basis[POLICY][0]:
            self.ctx.ws.store().put(io.BytesIO(raw))
            tx.append_once(
                "p4b.policy",
                {
                    "v": 1,
                    "profile": self.ctx.ws.profile.id,
                    "graph": self.ctx.ws.running_graph_sha256(),
                    "sha256": digest(raw),
                },
                record_id=self.ctx.record_id,
                duplikat=lambda e: False,
            )
            raise GateError("Policy im Schreibfenster geändert; neuer Akt erforderlich")
        current = latest_checkpoint(events, self.ctx.record_id, self.phase)
        if current != self.previous:
            raise GateError("Editorrevision seit Anzeige geändert; erneut öffnen")

    def _fresh(self):
        rules = refresh(self.ctx, self.store)
        if rules != self.policy:
            raise GateError("Policy seit Anzeige geändert; erneut öffnen")

    def add(self, cue, start, end, typ, *, old=None):
        new = model.mark(self.source, cue, start, end, typ)
        candidate = deepcopy(self.capsule)
        if old is not None:
            self._remove(candidate, old)
        mid = next(iter(model.bound(self.source, [new]))).mention_id
        candidate["spans"].append(new)
        if self.phase == "pii.mark":
            candidate["base"] = deepcopy(candidate["spans"])
        else:
            candidate["overlay"].append({"old": old, "new": new})
        candidate["groups"][secrets.token_hex(16)] = {
            "type": typ,
            "scope": self.policy[typ].get("scope", "local"),
            "mentions": [mid],
            "state": "OPEN",
        }
        model.validate(self.source, candidate, self.policy)
        self.capsule = candidate

    def _remove(self, capsule, mid):
        pairs = model._paired(self.source, capsule["spans"])
        model.require(mid in {s.mention_id for s, _ in pairs})
        capsule["spans"] = [raw for s, raw in pairs if s.mention_id != mid]
        for gid in list(capsule["groups"]):
            g = capsule["groups"][gid]
            if mid in g["mentions"]:
                g["mentions"].remove(mid)
                g["state"] = "OPEN"
            if not g["mentions"]:
                del capsule["groups"][gid]

    def exclude(self, mid):
        candidate = deepcopy(self.capsule)
        self._remove(candidate, mid)
        if self.phase == "pii.mark":
            candidate["base"] = deepcopy(candidate["spans"])
        else:
            candidate["overlay"].append({"old": mid, "new": None})
        model.validate(self.source, candidate, self.policy)
        self.capsule = candidate

    def merge(self, gids):
        candidate = deepcopy(self.capsule)
        model.require(len(set(gids)) == len(gids) and len(gids) >= 2)
        groups = [candidate["groups"][g] for g in gids]
        model.require(len({(g["type"], g["scope"]) for g in groups}) == 1)
        group = deepcopy(groups[0])
        group["mentions"] = sorted(m for g in groups for m in g["mentions"])
        group["state"] = "RESOLVED"
        for g in gids:
            del candidate["groups"][g]
        candidate["groups"][secrets.token_hex(16)] = group
        model.validate(self.source, candidate, self.policy)
        self.capsule = candidate

    def split(self, gid, partitions):
        candidate = deepcopy(self.capsule)
        group = candidate["groups"].pop(gid)
        flat = [m for part in partitions for m in part]
        model.require(
            len(partitions) >= 2
            and all(partitions)
            and len(flat) == len(set(flat))
            and set(flat) == set(group["mentions"])
        )
        for part in partitions:
            candidate["groups"][secrets.token_hex(16)] = {
                **group,
                "mentions": part,
                "state": "RESOLVED",
            }
        model.validate(self.source, candidate, self.policy)
        self.capsule = candidate

    def state(self, gid, state):
        model.require(state in ("OPEN", "RESOLVED", "DEFERRED"))
        self.capsule["groups"][gid]["state"] = state

    def save(self):
        self._fresh()
        model.validate(self.source, self.capsule, self.policy)
        raw = canonical(self.capsule)
        ref, blob = self.store.seal(
            raw,
            role="editor",
            record=self.ctx.record_id,
            phase=self.phase,
            session_id=self.session_id,
            revision=self.revision + 1,
        )
        p = {
            "v": 1,
            "ref": ref,
            "basis": self.basis,
            "actor": self.actor,
            "actor_state": self.actor_state,
            "previous": digest(canonical(self.previous)) if self.revision else None,
        }
        with locked(self.ctx, self.store) as tx:
            self._recheck(tx)
            self.store.put(ref, blob)
            tx.append_once(
                "p4b.checkpoint", p, record_id=self.ctx.record_id, duplikat=lambda e: False
            )
            self.previous, self.revision, self.saved_bytes = p, self.revision + 1, raw
            self.store.pointer(ref)
        return self.revision

    def publish(self, *, displayed=None):
        self._fresh()
        raw = canonical(self.capsule)
        if self.phase != "pseudonymise" and (displayed != digest(raw) or raw != self.saved_bytes):
            raise GateError("Genau gesicherte Revision erst anzeigen und bewusst bestätigen")
        model.validate(self.source, self.capsule, self.policy)
        output = (
            model.render(self.source, self.capsule, self.policy)
            if self.phase == "pseudonymise"
            else raw
        )
        ref, blob = self.store.seal(
            output,
            role=ROLES[self.phase],
            record=self.ctx.record_id,
            phase=self.phase,
            session_id=self.session_id,
            revision=max(self.revision, 1),
        )
        p = {
            "v": 1,
            "ref": ref,
            "basis": self.basis,
            "actor": self.actor,
            "actor_state": self.actor_state,
            "checkpoint": digest(canonical(self.previous))
            if self.previous and self.phase != "pseudonymise"
            else None,
            "at": datetime.now(timezone.utc).isoformat(),
        }
        # Genau diese Decisionbytes werden nach dem UI-Akt verschlüsselt gebunden.
        plan, planblob = self.store.seal(
            canonical({"publication": p, "effects": effects(p)}),
            role="plan",
            record=self.ctx.record_id,
            phase=self.phase,
            session_id=self.session_id,
            revision=max(self.revision, 1),
        )
        p["plan"] = plan
        with locked(self.ctx, self.store) as tx:
            self._recheck(tx)
            self.store.put(ref, blob)
            self.store.put(plan, planblob)
            tx.append_once(
                "p4b.prepared", p, record_id=self.ctx.record_id, duplikat=lambda e: False
            )
            tx.append_once(
                "p4b.completed",
                {"v": 1, "prepared_sha256": digest(canonical(p))},
                record_id=self.ctx.record_id,
                duplikat=lambda e: False,
            )
        return ref["sha256"]


def recover(ctx, actor=None):
    store = ProtectedStore(ctx.ws, ctx.journal.key)
    refresh(ctx, store)
    events = list(ctx.journal)
    completed = {
        e.payload["prepared_sha256"]
        for e in events
        if e.kind == "p4b.completed" and e.record_id == ctx.record_id
    }
    pending = [
        e.payload
        for e in events
        if e.kind == "p4b.prepared"
        and e.record_id == ctx.record_id
        and digest(canonical(e.payload)) not in completed
    ]
    for p in pending:
        phase = p["ref"]["aad"]["phase"]
        _, actual, human = snapshot(ctx, events, phase, actor)
        if (
            actual != p["basis"]
            or human.coder_id != p["actor"]
            or human.state_sha256 != p["actor_state"]
        ):
            raise GateError(
                "Unterbrochener Akt nicht mehr aktuell; neuer bewusster Akt erforderlich"
            )
        expected = {k: v for k, v in p.items() if k != "plan"}
        if json.loads(store.open(p["plan"], ctx.record_id)) != {
            "publication": expected,
            "effects": [[k, v] for k, v in effects(p)],
        }:
            raise ProtectionError("Geschützter Veröffentlichungsplan widersprüchlich")
        store.open(p["ref"], ctx.record_id)
        with locked(ctx, store) as tx:
            _, current, human = snapshot(ctx, list(tx), phase, actor)
            _, current_policy = policy(ctx)
            if digest(current_policy) != p["basis"][POLICY][0]:
                ctx.ws.store().put(io.BytesIO(current_policy))
                tx.append_once(
                    "p4b.policy",
                    {
                        "v": 1,
                        "profile": ctx.ws.profile.id,
                        "graph": ctx.ws.running_graph_sha256(),
                        "sha256": digest(current_policy),
                    },
                    record_id=ctx.record_id,
                    duplikat=lambda e: False,
                )
                raise GateError("Policy im Recoveryfenster geändert; neuer Akt erforderlich")
            ck = latest_checkpoint(list(tx), ctx.record_id, phase)
            if (
                current != actual
                or human.state_sha256 != p["actor_state"]
                or (
                    p["checkpoint"] is not None
                    and (ck is None or digest(canonical(ck)) != p["checkpoint"])
                )
            ):
                raise GateError("Recoverygrundlage geändert")
            key = digest(canonical(p))
            tx.append_once(
                "p4b.completed",
                {"v": 1, "prepared_sha256": key},
                record_id=ctx.record_id,
                duplikat=lambda e, key=key: e.payload["prepared_sha256"] == key,
            )
    return len(pending)
