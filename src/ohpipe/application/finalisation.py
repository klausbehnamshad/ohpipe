"""P4c: menschliche Resolution, atomare Finalisierung, explizites finales Textgate."""

from contextlib import contextmanager
from datetime import datetime, timezone
import io
import json
import secrets

from ..domain import manual_pseudonymisation as manual, stable_pseudonymisation as stable
from ..domain.p4c_events import basis, BASE
from ..domain.step import build_graph
from ..domain.revision_serialization import verify_revision
from ..protected_store import ProtectedStore, ProtectionError, ProtectionBusy, canonical, digest
from ..registry_store import RegistryStore, REGISTRY, RESOLUTION, FINAL, REPORT, GATE, need
from ..workspace_lock import workspace_write_lock
from ..policies.authority import Authority
from . import manual_work
from .gate import GateError, GateBlocked
from .replay import replay
from .protected_replay import expand


class FinalisationAction(GateError):
    def __init__(self, message, *command):
        super().__init__(message)
        self.command = command


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def hook(stage):
    """Prozessbarrieren werden in synthetischen Tests injiziert; kein Produktionsschalter."""


@contextmanager
def locked(ctx, store, protection):
    try:
        with (
            workspace_write_lock(ctx.ws.root, blocking=False),
            store.lock(),
            protection.lock(),
            ctx.journal.transaction(blocking=False) as tx,
        ):
            store.ensure_current(tx.key)
            protection.ensure_current(tx.key)
            yield tx
    except BlockingIOError:
        raise ProtectionBusy("P4c-Schreibakt belegt; unverändert erneut versuchen") from None


def expanded(ctx, events):
    output, refs, published, findings = expand(
        list(events), build_graph(ctx.ws.profile), Authority.AUTHENTICATED
    )
    if any(findings.values()):
        raise ProtectionError("P4c/P4b-Veröffentlichungsbelege widersprüchlich")
    return output, refs, published


def current(ctx, store, events, *, pending=False):
    output, _, _ = expanded(ctx, events)
    observed = [e.payload["ref"] for e in output if e.kind == "p4c.registry.source"]
    head = store.head()
    if not observed:
        init = [e.payload for e in events if e.kind == "p4c.init.prepared"]
        if head is not None and (not init or head != init[0]["ref"]):
            raise ProtectionError("Registerkopf ohne authentifizierten Initialisierungsakt")
        raise FinalisationAction(
            "Register fehlt; ausdrücklich initialisieren", "pseudonymisation", "registry", "init"
        )
    ref = observed[-1]
    if head != ref:
        ended = {
            e.payload["prepared_sha256"]
            for e in events
            if e.kind in ("p4c.completed", "p4c.aborted")
        }
        prepared = [
            e.payload
            for e in events
            if e.kind == "p4c.prepared"
            and digest(canonical(e.payload)) not in ended
            and e.payload["registry_before"] == ref
            and e.payload["registry_after"] == head
        ]
        if head is not None and prepared:
            if not pending:
                raise ProtectionBusy(
                    "Registerpublikation unterbrochen; pseudonymisation recovery ausführen"
                )
        else:
            raise ProtectionError("Registerkopf fehlt, ist fremd oder zurückgerollt")
    reg = json.loads(store.open(ref, None))
    stable.validate_registry(reg)
    need(
        reg["registry_id"] == store.config["registry_id"]
        and reg["candidate_key_id"] == store.config["candidate_key_id"]
    )
    need(reg["candidate_check"] == stable.candidate_check(store.candidate_key, reg["registry_id"]))
    return ref, reg


def initialise(ctx):
    store = RegistryStore(ctx.ws, ctx.journal.key)
    protection = ProtectedStore(ctx.ws, ctx.journal.key)
    with locked(ctx, store, protection) as tx:
        events = list(tx)
        output, _, _ = expanded(ctx, events)
        if any(e.kind == "p4c.registry.source" for e in output):
            current(ctx, store, events)
            return
        pending = [e.payload for e in events if e.kind == "p4c.init.prepared"]
        empty = canonical(
            stable.empty(
                store.config["registry_id"],
                store.config["candidate_key_id"],
                stable.candidate_check(store.candidate_key, store.config["registry_id"]),
            )
        )
        if pending:
            p = pending[0]
            ref = p["ref"]
        else:
            need(store.head() is None)  # R-P4C_INIT_UNBOUND: no authority from a head alone.
            ref, blob = store.seal(empty, REGISTRY, None, secrets.token_hex(16))
            store.put(ref, blob)
            hook("init_cipher_fsync")
            p = dict(v=1, ref=ref, at=now())
            tx.append_once("p4c.init.prepared", p, duplikat=lambda e: False)
            hook("init_prepared")
        # Only the exact authenticated empty candidate may finish this operation.
        need(store.open(ref, None) == empty)
        need(store.head() is None or store.head() == ref)
        store.ensure_current(tx.key)
        protection.ensure_current(tx.key)
        if store.head() is None:
            store.set_head(ref)
        hook("init_head")
        store.ensure_current(tx.key)
        protection.ensure_current(tx.key)
        need(store.head() == ref and store.open(ref, None) == empty)
        tx.append_once("p4c.initialised", p, duplikat=lambda e: False)
        hook("init_completed")


def published(ctx, events, phase):
    complete = {
        e.payload["prepared_sha256"]
        for e in events
        if e.kind == "p4c.completed" and e.record_id == ctx.record_id
    }
    return next(
        (
            e.payload
            for e in reversed(events)
            if e.kind == "p4c.prepared"
            and e.record_id == ctx.record_id
            and e.payload["phase"] == phase
            and digest(canonical(e.payload)) in complete
        ),
        None,
    )


def view(ctx, events):
    return replay(events, graph=build_graph(ctx.ws.profile), authority=Authority.AUTHENTICATED).get(
        ctx.record_id
    )


def refresh(ctx):
    from .storage_integrity import check_referenced, ProtectionConfigurationFinding

    initial = view(ctx, list(ctx.journal))
    if initial is None or initial.findings:
        raise GateBlocked("P4c-Record oder Replay gesperrt")
    findings = check_referenced(ctx.ws, initial)
    if findings and not all(isinstance(f, ProtectionConfigurationFinding) for f in findings):
        raise GateBlocked("P4c-Speicherprüfung gesperrt")
    if findings:
        from ..protected_store import ProtectionConfig

        raise ProtectionConfig(str(findings[0]))
    protection = ProtectedStore(ctx.ws, ctx.journal.key)
    manual_work.refresh(ctx, protection)
    store = RegistryStore(ctx.ws, ctx.journal.key)
    with locked(ctx, store, protection) as tx:
        current(ctx, store, list(tx))
    return store, protection


class Work:
    def __init__(self, ctx, actor=None):
        self.ctx = ctx
        self.store, self.protection = refresh(ctx)
        events = list(ctx.journal)
        self.view, _, human = manual_work.snapshot(ctx, events, "pseudonymisation.cases", actor)
        self.actor, self.actor_state = human.coder_id, human.state_sha256
        try:
            self.base = basis(self.view, "resolve")
        except ValueError:
            raise GateError("P4b-Fallsammlung nicht aktuell bestätigt") from None
        self.registry_ref, self.registry = current(ctx, self.store, events)
        from .confirmed_text import read_confirmed_text

        self.source = read_confirmed_text(ctx, self.view, "pseudonymisation.cases").revision
        self.capsule = json.loads(
            self.protection.open(
                manual_work.reference(self.view, "pseudonymisation.cases"), ctx.record_id
            )
        )
        manual.validate(self.source, self.capsule, self.rules)
        if manual.counts(self.capsule)["open"]:
            raise FinalisationAction(
                "Offene oder zurückgestellte Fälle; Fallsammlung zuerst auflösen",
                "pseudonymisation",
                "cases",
                ctx.record_id,
            )
        self.resolution = dict(
            v=1,
            registry_id=self.registry["registry_id"],
            source=manual.source_contract(self.source),
            mention_set_sha256=stable.mention_digest(self.source, self.capsule),
            assignments={},
        )

    @property
    def rules(self):
        rules = manual_work.policy(self.ctx)[0]
        if any(
            r["action"] == "pseudonym" and r["scope"] != self.store.config["scope"]
            for r in rules.values()
        ):
            from ..protected_store import ProtectionConfig

            raise ProtectionConfig("Policy-Scope passt nicht zur deklarierten Registerdomäne")
        return rules

    def choose(self, gid, entity=None):
        group = self.capsule["groups"][gid]
        eid = entity or secrets.token_hex(16)
        if entity is not None:
            need(
                entity in self.registry["entities"]
                and self.registry["entities"][entity]["type"] == group["type"]
            )
        for mid in group["mentions"]:
            self.resolution["assignments"][mid] = dict(
                entity_id=eid,
                type=group["type"],
                action=self.rules[group["type"]]["action"],
                intent="reuse" if entity else "new",
            )

    def candidates(self, gid):
        group = self.capsule["groups"][gid]
        ids = set()
        for s in manual.bound(self.source, self.capsule["spans"]):
            if s.mention_id in group["mentions"]:
                surface = self.source.segments[s.cue_index].text[s.start : s.end]
                key = stable.token(
                    self.store.candidate_key, self.registry["registry_id"], group["type"], surface
                )
                ids.update(self.registry["aliases"].get(key, []))
        return sorted(ids)

    def _recheck(self, tx, *, expected=None):
        events = list(tx)
        v, _, human = manual_work.snapshot(self.ctx, events, "pseudonymisation.cases", self.actor)
        ref, reg = current(self.ctx, self.store, events)
        if (
            human.state_sha256 != self.actor_state
            or basis(v, "resolve") != self.base
            or ref != self.registry_ref
        ):
            raise GateError("P4c-Grundlage seit Anzeige/Planung geändert; erneut öffnen")
        _, raw = manual_work.policy(self.ctx)
        if digest(raw) != self.base["pseudonymisation.policy"][0]:
            self.ctx.ws.store().put(io.BytesIO(raw))
            tx.append_once(
                "p4b.policy",
                dict(
                    v=1,
                    profile=self.ctx.ws.profile.id,
                    graph=self.ctx.ws.running_graph_sha256(),
                    sha256=digest(raw),
                ),
                record_id=self.ctx.record_id,
                duplikat=lambda e: False,
            )
            raise GateError("Policy im Schreibfenster geändert; neuer Normalakt erforderlich")
        if expected is not None and basis(v, "review") != expected:
            raise GateError("Finale Grundlage seit Anzeige geändert")
        return v, reg

    def envelope(self, phase, inputs, operation):
        return dict(
            v=1,
            phase=phase,
            operation=operation,
            actor=self.actor,
            actor_state=self.actor_state,
            at=now(),
            basis=inputs,
            registry_before=self.registry_ref,
            registry_after=self.registry_ref,
            refs={},
            marker=None,
        )

    def commit(self, tx, p, blobs):
        for ref, blob in blobs:
            self.store.put(ref, blob)
        hook("cipher_fsync")
        self._recheck(tx, expected=p["basis"] if p["phase"] == "review" else None)
        tx.append_once("p4c.prepared", p, record_id=self.ctx.record_id, duplikat=lambda e: False)
        hook("prepared")
        if p["registry_after"] != p["registry_before"]:
            self.store.set_head(p["registry_after"])
        hook("head")
        self.store.ensure_current(tx.key)
        self.protection.ensure_current(tx.key)
        _, policy_raw = manual_work.policy(self.ctx)
        if digest(policy_raw) != self.base["pseudonymisation.policy"][0]:
            self.ctx.ws.store().put(io.BytesIO(policy_raw))
            tx.append_once(
                "p4b.policy",
                dict(
                    v=1,
                    profile=self.ctx.ws.profile.id,
                    graph=self.ctx.ws.running_graph_sha256(),
                    sha256=digest(policy_raw),
                ),
                record_id=self.ctx.record_id,
                duplikat=lambda e: False,
            )
            raise GateError("Policy vor Abschluss geändert; vorbereiteten Akt prüfen")
        from .storage_integrity import check_referenced

        if check_referenced(self.ctx.ws, view(self.ctx, list(tx))):
            raise GateBlocked("Speicherprüfung vor Abschluss gesperrt")
        tx.append_once(
            "p4c.completed",
            dict(v=1, prepared_sha256=digest(canonical(p))),
            record_id=self.ctx.record_id,
            duplikat=lambda e: False,
        )
        hook("completed")

    def accept_resolution(self, displayed):
        stable.validate_resolution(
            self.source, self.capsule, self.rules, self.resolution, self.registry
        )
        need(displayed == digest(canonical(self.resolution)))
        with locked(self.ctx, self.store, self.protection) as tx:
            self._recheck(tx)
            old = published(self.ctx, list(tx), "resolve")
            if (
                old
                and old["basis"] == self.base
                and json.loads(self.store.open(old["refs"][RESOLUTION], self.ctx.record_id))
                == self.resolution
            ):
                return old["refs"][RESOLUTION]
            op = secrets.token_hex(16)
            ref, blob = self.store.seal(
                canonical(self.resolution), RESOLUTION, self.ctx.record_id, op
            )
            p = self.envelope("resolve", self.base, op)
            p["refs"] = {RESOLUTION: ref}
            self.commit(tx, p, [(ref, blob)])
            return ref

    def finalise(self):
        with locked(self.ctx, self.store, self.protection) as tx:
            v, reg = self._recheck(tx)
            res = published(self.ctx, list(tx), "resolve")
            if not res or res["basis"] != self.base:
                raise FinalisationAction(
                    "Bestätigte aktuelle Resolution fehlt",
                    "pseudonymisation",
                    "resolve",
                    self.ctx.record_id,
                )
            self.resolution = json.loads(
                self.store.open(res["refs"][RESOLUTION], self.ctx.record_id)
            )
            stable.validate_resolution(self.source, self.capsule, self.rules, self.resolution, reg)
            inputs = basis(v, "finalise")
            old = published(self.ctx, list(tx), "finalise")
            if old and FINAL in v.have and REPORT in v.have:
                verify_package(self.ctx, self.store, list(tx), old, v)
                return old
            op = secrets.token_hex(16)
            updated = stable.allocate(
                self.source,
                self.capsule,
                self.rules,
                self.resolution,
                reg,
                self.store.candidate_key,
                res["refs"][RESOLUTION],
                self.ctx.record_id,
            )
            p = self.envelope("finalise", inputs, op)
            blobs = []
            output_inputs = dict(inputs)
            if (
                updated != reg
            ):  # P4C_REGISTRY_NOOP: publication history does not version the registry.
                r, blob = self.store.seal(
                    canonical(updated),
                    REGISTRY,
                    None,
                    op,
                    version=self.registry_ref["aad"]["version"] + 1,
                    parent=self.registry_ref["sha256"],
                )
                p["registry_after"] = r
                blobs.append((r, blob))
                output_inputs[REGISTRY] = [r["sha256"], len(expanded(self.ctx, list(tx))[0]) + 1]
            raw, entries, sums = stable.render(
                self.source, self.capsule, self.rules, self.resolution, updated
            )
            final, blob = self.store.seal(raw, FINAL, self.ctx.record_id, op)
            blobs.append((final, blob))
            report = dict(
                v=1,
                record=self.ctx.record_id,
                profile=self.ctx.ws.profile.id,
                graph=self.ctx.ws.running_graph_sha256(),
                operation=op,
                basis=output_inputs,
                registry=p["registry_after"],
                final=final,
                projection=self.source.projection_version,
                renderer="p4c.v1",
                entries=entries,
                sums=sums,
                counts=manual.counts(self.capsule),
            )
            ref, blob = self.store.seal(canonical(report), REPORT, self.ctx.record_id, op)
            blobs.append((ref, blob))
            p["refs"] = {FINAL: final, REPORT: ref}
            self.commit(tx, p, blobs)
            return p

    def review_material(self):
        events = list(self.ctx.journal)
        v = view(self.ctx, events)
        try:
            inputs = basis(v, "review")
        except ValueError:
            raise GateError("Finalisierung nicht aktuell; zuerst finalise ausführen") from None
        p = published(self.ctx, events, "finalise")
        raw, report = verify_package(self.ctx, self.store, events, p, v)
        return inputs, raw, report

    def accept_text(self, displayed, inputs):
        with locked(self.ctx, self.store, self.protection) as tx:
            self._recheck(tx, expected=inputs)
            v = view(self.ctx, list(tx))
            p = published(self.ctx, list(tx), "finalise")
            raw, report = verify_package(self.ctx, self.store, list(tx), p, v)
            need(
                displayed
                == digest(
                    canonical(
                        {
                            "final": digest(raw),
                            "report": p["refs"][REPORT]["sha256"],
                            "basis": inputs,
                        }
                    )
                )
            )
            op = secrets.token_hex(16)
            prepared = self.envelope("review", inputs, op)
            marker = dict(
                domain="ohpipe:p4c:confirmation",
                v=1,
                record=self.ctx.record_id,
                profile=self.ctx.ws.profile.id,
                graph=self.ctx.ws.running_graph_sha256(),
                operation=op,
                actor=self.actor,
                actor_state=self.actor_state,
                at=prepared["at"],
                basis=inputs,
                volltext_gelesen=True,
                counts=report["counts"],
            )
            prepared["marker"] = marker
            self.ctx.ws.store().put(io.BytesIO(canonical(marker)))
            self.commit(tx, prepared, [])
            return digest(canonical(marker))


def bound_policy(ctx, inputs, tx=None):
    """Eine tatsächlich gelesene andere Policy ist keine inhaltsgleiche Freigabe."""
    rules, raw = manual_work.policy(ctx)
    if digest(raw) != inputs["pseudonymisation.policy"][0]:
        if tx is not None:
            ctx.ws.store().put(io.BytesIO(raw))
            tx.append_once(
                "p4b.policy",
                dict(
                    v=1,
                    profile=ctx.ws.profile.id,
                    graph=ctx.ws.running_graph_sha256(),
                    sha256=digest(raw),
                ),
                record_id=ctx.record_id,
                duplikat=lambda e: False,
            )
        raise GateError("Policybindung vor Abschluss geändert; vorbereiteten Akt erneut prüfen")
    return rules


def verify_package(ctx, store, events, p, v, *, tx=None):
    need(p is not None and p["phase"] == "finalise")
    ref, reg = current(ctx, store, events)
    need(ref == p["registry_after"])
    inputs = basis(v, "finalise")
    need(all(inputs[k] == pair for k, pair in p["basis"].items() if k != REGISTRY))
    raw = store.open(p["refs"][FINAL], ctx.record_id)
    revision = verify_revision(raw, p["refs"][FINAL]["sha256"])
    report = json.loads(store.open(p["refs"][REPORT], ctx.record_id))
    res = published(ctx, events, "resolve")
    need(res is not None and res["basis"] == {k: inputs[k] for k in BASE})
    resolution = json.loads(store.open(res["refs"][RESOLUTION], ctx.record_id))
    from .confirmed_text import read_confirmed_text

    source = read_confirmed_text(ctx, v, "pseudonymisation.cases").revision
    protection = ProtectedStore(ctx.ws, ctx.journal.key)
    capsule = json.loads(
        protection.open(manual_work.reference(v, "pseudonymisation.cases"), ctx.record_id)
    )
    rules = bound_policy(ctx, inputs, tx)
    expected_raw, entries, sums = stable.render(source, capsule, rules, resolution, reg)
    expected = dict(
        v=1,
        record=ctx.record_id,
        profile=ctx.ws.profile.id,
        graph=ctx.ws.running_graph_sha256(),
        operation=p["operation"],
        basis=inputs,
        registry=ref,
        final=p["refs"][FINAL],
        projection=revision.projection_version,
        renderer="p4c.v1",
        entries=entries,
        sums=sums,
        counts=manual.counts(capsule),
    )
    need(raw == expected_raw and report == expected)
    return raw, report


def recover(ctx, actor=None):
    store = RegistryStore(ctx.ws, ctx.journal.key)
    protection = ProtectedStore(ctx.ws, ctx.journal.key)
    # Policy refresh is an ordinary observed invalidation, also during recovery.
    manual_work.refresh(ctx, protection)
    with locked(ctx, store, protection) as tx:
        events = list(tx)
        complete = {
            e.payload["prepared_sha256"]
            for e in events
            if e.kind in ("p4c.completed", "p4c.aborted")
        }
        pending = [
            e.payload
            for e in events
            if e.kind == "p4c.prepared"
            and e.record_id == ctx.record_id
            and digest(canonical(e.payload)) not in complete
        ]
        for p in pending:
            ref, _ = current(ctx, store, list(tx), pending=True)
            stale = False
            try:
                v, _, human = manual_work.snapshot(
                    ctx, list(tx), "pseudonymisation.cases", actor or p["actor"]
                )
                stale = (
                    ref != p["registry_before"]
                    or basis(v, p["phase"]) != p["basis"]
                    or human.coder_id != p["actor"]
                    or human.state_sha256 != p["actor_state"]
                )
            except GateBlocked:
                raise
            except (GateError, ValueError):
                stale = True
            if stale:
                # Nur ein belegter unvollständiger Kopf wird auf den letzten
                # wirksamen Stand zurückgestellt; nie ein abgeschlossener Stand.
                if store.head() == p["registry_after"] and p["registry_after"] != ref:
                    store.set_head(ref)
                tx.append_once(
                    "p4c.aborted",
                    dict(v=1, prepared_sha256=digest(canonical(p))),
                    record_id=ctx.record_id,
                    duplikat=lambda e: False,
                )
                raise GateError(
                    "Unterbrochener P4c-Akt veraltet und abgebrochen; neuer bewusster Akt erforderlich"
                )
            validate_prepared(ctx, store, list(tx), p, tx=tx)
            hook("recovery_validated")
            for r in p["refs"].values():
                store.open(r, ctx.record_id)
            if p["registry_after"] != ref:
                stable.validate_registry(json.loads(store.open(p["registry_after"], None)))
                store.set_head(p["registry_after"])
            hook("recovery_head")
            store.ensure_current(tx.key)
            protection.ensure_current(tx.key)
            from .storage_integrity import check_referenced

            v, _, human = manual_work.snapshot(
                ctx, list(tx), "pseudonymisation.cases", actor or p["actor"]
            )
            if check_referenced(ctx.ws, v):
                raise GateBlocked("Speicherprüfung vor Recovery-Abschluss gesperrt")
            ref, _ = current(ctx, store, list(tx), pending=True)
            if (
                ref != p["registry_before"]
                or basis(v, p["phase"]) != p["basis"]
                or human.coder_id != p["actor"]
                or human.state_sha256 != p["actor_state"]
            ):
                raise GateError("Grundlage vor Recovery-Abschluss geändert")
            bound_policy(ctx, p["basis"], tx)  # R-P4C_RECOVERY_POLICY_FINAL
            tx.append_once(
                "p4c.completed",
                dict(v=1, prepared_sha256=digest(canonical(p))),
                record_id=ctx.record_id,
                duplikat=lambda e: False,
            )
    return len(pending)


@contextmanager
def consumer_publication(ctx, bound):
    """P4c-Verbraucher prüfen nach Berechnung erneut, unter derselben Sperrfolge."""
    if bound.decision.input_refs_version != 4:
        yield ctx.journal
        return
    store = RegistryStore(ctx.ws, ctx.journal.key)
    protection = ProtectedStore(ctx.ws, ctx.journal.key)
    with locked(ctx, store, protection) as tx:
        current(ctx, store, list(tx))
        current_view = view(ctx, list(tx))
        from .storage_integrity import check_referenced

        if (
            current_view is None
            or current_view.findings
            or not current_view.enabled
            or check_referenced(ctx.ws, current_view)
        ):
            raise GateBlocked("P4c-Verbraucher vor Veröffentlichung gesperrt")
        _, policy = manual_work.policy(ctx)
        if digest(policy) != current_view.sources["pseudonymisation.policy"][0]:
            ctx.ws.store().put(io.BytesIO(policy))
            tx.append_once(
                "p4b.policy",
                dict(
                    v=1,
                    profile=ctx.ws.profile.id,
                    graph=ctx.ws.running_graph_sha256(),
                    sha256=digest(policy),
                ),
                record_id=ctx.record_id,
                duplikat=lambda e: False,
            )
            raise GateError("Policy während Verbrauch geändert; neue Finalisierung erforderlich")
        if (
            GATE not in current_view.have
            or basis(current_view, "review") != basis(bound.view, "review")
            or current_view.facts[GATE].sha256 != bound.marker_sha256
            or current_view.facts[GATE].epoch != bound.view.facts[GATE].epoch
        ):
            raise GateError("Finale Freigabe während Verbrauch geändert; kein veralteter Beleg")
        yield tx


def validate_prepared(ctx, store, events, p, *, tx=None):
    """Recovery prüft den vollständigen semantischen Plan vor dessen Wirksamkeit."""
    reg = json.loads(store.open(p["registry_before"], None))
    stable.validate_registry(reg)
    v = view(ctx, events)
    from .confirmed_text import read_confirmed_text

    source = read_confirmed_text(ctx, v, "pseudonymisation.cases").revision
    capsule = json.loads(
        ProtectedStore(ctx.ws, ctx.journal.key).open(
            manual_work.reference(v, "pseudonymisation.cases"), ctx.record_id
        )
    )
    rules = bound_policy(ctx, p["basis"], tx)
    if p["phase"] == "resolve":
        resolution = json.loads(store.open(p["refs"][RESOLUTION], ctx.record_id))
        stable.validate_resolution(source, capsule, rules, resolution, reg)
        return
    if p["phase"] == "review":
        _, report = verify_package(ctx, store, events, published(ctx, events, "finalise"), v, tx=tx)
        need(p["marker"]["counts"] == report["counts"])
        sha = digest(canonical(p["marker"]))
        with ctx.ws.store().open_verified(sha) as handle:
            need(handle.read() == canonical(p["marker"]))
        return
    res = published(ctx, events, "resolve")
    need(res is not None and res["basis"] == {k: p["basis"][k] for k in BASE})
    resolution = json.loads(store.open(res["refs"][RESOLUTION], ctx.record_id))
    expected = stable.allocate(
        source,
        capsule,
        rules,
        resolution,
        reg,
        store.candidate_key,
        res["refs"][RESOLUTION],
        ctx.record_id,
    )
    actual = json.loads(store.open(p["registry_after"], None))
    need(
        actual == expected and ((expected == reg) == (p["registry_after"] == p["registry_before"]))
    )
    raw, entries, sums = stable.render(source, capsule, rules, resolution, actual)
    need(store.open(p["refs"][FINAL], ctx.record_id) == raw)
    inputs = dict(p["basis"])
    if p["registry_after"] != p["registry_before"]:
        epoch = next(
            i
            for i, e in enumerate(expanded(ctx, events)[0], 1)
            if e.kind == "p4c.prepared" and e.payload == p
        )
        inputs[REGISTRY] = [p["registry_after"]["sha256"], epoch]
    report = dict(
        v=1,
        record=ctx.record_id,
        profile=ctx.ws.profile.id,
        graph=ctx.ws.running_graph_sha256(),
        operation=p["operation"],
        basis=inputs,
        registry=p["registry_after"],
        final=p["refs"][FINAL],
        projection=source.projection_version,
        renderer="p4c.v1",
        entries=entries,
        sums=sums,
        counts=manual.counts(capsule),
    )
    need(json.loads(store.open(p["refs"][REPORT], ctx.record_id)) == report)
