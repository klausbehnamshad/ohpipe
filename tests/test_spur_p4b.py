"""P4b: tatsächliche lokale Kette, getrennte Cipherablage und Gegenproben."""

from copy import deepcopy
import json
import os
from pathlib import Path
import secrets

import pytest

from ohpipe.application.manual_work import Session, recover
from ohpipe.application.steps import StepContext, registry_for, REGISTRY
from ohpipe.application.storage_integrity import check_referenced
from ohpipe.application.gate import GateError, GateBlocked, current_inputs
from ohpipe.domain import manual_pseudonymisation as model
from ohpipe.domain.transcript import Segment, TranscriptRevision
from ohpipe.domain.revision_serialization import verify_revision
from ohpipe.protected_store import ProtectedStore, ProtectionError, canonical, digest
from ohpipe.policies.authority import Authority
from .test_spur_p4a import ManualWorld, RECORD, PROFILE
from .test_spur_p1 import ACTOR, isolated  # noqa: F401


@pytest.fixture
def world(tmp_path, monkeypatch):
    source_marker = secrets.token_hex(24)
    raw = f"1\n00:00:00,000 --> 00:00:02,000\nZEITZEUGIN: {source_marker}.\n".encode()
    w = ManualWorld(tmp_path, monkeypatch, synthetic_raw=raw)
    w.source_marker = source_marker
    root = tmp_path.resolve()
    for p in (
        root / "protected",
        root / "protected/objects",
        root / "protected/sessions",
        root / "secrets",
    ):
        p.mkdir(mode=0o700)
    key = root / "secrets/protection.key"
    key.write_bytes(secrets.token_bytes(32))
    key.chmod(0o600)
    config = root / "secrets/protection.json"
    config.write_bytes(
        canonical(
            {
                "v": 1,
                "root": str(root / "protected"),
                "key_file": str(key),
                "key_id": secrets.token_hex(16),
                "store_id": secrets.token_hex(16),
            }
        )
    )
    config.chmod(0o600)
    monkeypatch.setenv("OHPIPE_PROTECTION_CONFIG", str(config))
    w.protection_key, w.protection_config = key, config
    w.ctx = StepContext(ws=w.ws, journal=w.journal, record_id=RECORD, profile_arg=str(PROFILE))
    return w


def accepted(w):
    s = Session(w.ctx, "pii.mark", ACTOR)
    s.add(0, 0, 12, "PERSON")
    s.save()
    s.publish(displayed=digest(canonical(s.capsule)))
    return s


def drafted(w):
    accepted(w)
    w.ok(0, "pseudonymise", RECORD, "--actor", ACTOR)
    return Session(w.ctx, "pseudonymisation.cases", ACTOR)


def test_actual_cli_to_final_stop(world):
    w = world
    r = w.run(
        "pii",
        "mark",
        RECORD,
        "--actor",
        ACTOR,
        tty=True,
        as_json=False,
        answer="neu\nmarkieren 0 0 12 PERSON\nbestätigen\nBESTÄTIGEN\n",
    )
    if r.code != 0:
        pytest.fail("P4B_CLI: regulärer Dialog fehlgeschlagen")
    assert "ENTWURF — NICHT FREIGEGEBEN" in r.out
    assert "pii.spans" in w.view().have
    w.ok(0, "pseudonymise", RECORD, "--actor", ACTOR)
    r = w.run(
        "pseudonymisation",
        "cases",
        RECORD,
        "--actor",
        ACTOR,
        tty=True,
        as_json=False,
        answer="neu\nbestätigen\nBESTÄTIGEN\n",
    )
    if r.code != 0:
        pytest.fail("P4B_CLI: regulärer Dialog fehlgeschlagen")
    assert "pseudonymisation.cases" in w.view().have
    # P4c-Auftrag 4.2/4.8: gebauter Handler, fehlende Registerauswahl CONFIG.
    r = json.loads(w.ok(2, "continue", RECORD).out)
    assert r["reason_code"] == "CONFIG_P4C"
    assert r["details"]["unbuilt"] == []
    assert not r.get("next") and not r.get("next_command")
    assert not w.view().have & {
        "transcript.pseudonymised.final",
        "transcript.pseudonymised.confirmed",
        "l1.suggestions",
        "l1.coverage",
        "replacement.report",
    }
    assert not check_referenced(w.ws, w.view())


def test_registry_exact_profile(world):
    from ohpipe.project import Profile

    added = set(registry_for(world.ws.profile)) - set(REGISTRY)
    assert added == {
        "pii.mark",
        "pseudonymise",
        "pseudonymisation.cases",
        "pseudonymise.finalise",
        "pseudonymisation.review",
    }
    for name in ("childlux", "sandbox", "walz"):
        assert registry_for(Profile.load(PROFILE.parent.parent / name / "profile.toml")) is REGISTRY


@pytest.mark.parametrize("json_mode,tty", [(True, True), (False, False), (True, False)])
def test_noninteractive_before_decrypt(world, monkeypatch, json_mode, tty):
    def forbidden(*a, **k):
        pytest.fail("P4B_TTY: noninteractive decryption")

    monkeypatch.setattr(ProtectedStore, "open", forbidden)
    assert world.run("pii", "mark", RECORD, as_json=json_mode, tty=tty).code == 2


def test_save_resume_no_decision(world):
    s = Session(world.ctx, "pii.mark", ACTOR)
    s.add(0, 0, 12, "PERSON")
    s.save()
    assert "pii.spans" not in world.view().have
    assert not any(e.kind == "p4b.prepared" for e in world.journal)
    resumed = Session(world.ctx, "pii.mark", ACTOR, resume=True)
    assert resumed.capsule == s.capsule
    assert resumed.session_id == s.session_id and resumed.revision == 1
    with pytest.raises(GateError):
        resumed.publish()
    resumed.capsule["context"] = "synthetic-unsaved"
    with pytest.raises(GateError):
        resumed.publish(displayed=digest(canonical(resumed.capsule)))
    assert "pii.spans" not in world.view().have


def test_store_is_not_generic_hash_exception(world):
    s = drafted(world)
    v = world.view()
    assert not check_referenced(world.ws, v)
    assert current_inputs(
        world.ws, list(world.journal), RECORD, ["pii.spans"], authority=Authority.AUTHENTICATED
    )
    for ref in v.protected_refs:
        assert not (world.ws.objects / ref["cipher_sha256"]).exists()
    sha = v.facts["transcript.pseudonymised.draft"].sha256
    assert not (world.ws.objects / sha).exists()
    original = v.facts["transcript.revision"].sha256
    path = world.ws.objects / original
    saved = path.read_bytes()
    path.unlink()
    try:
        assert check_referenced(world.ws, v)
        with pytest.raises(GateBlocked):
            current_inputs(
                world.ws,
                list(world.journal),
                RECORD,
                ["pii.spans"],
                authority=Authority.AUTHENTICATED,
            )
    finally:
        path.write_bytes(saved)
        path.chmod(0o600)
    assert not check_referenced(world.ws, v)
    assert s.capsule["groups"]


def test_same_logical_draft_new_activation(world):
    s = accepted(world)
    world.ok(0, "pseudonymise", RECORD, "--actor", ACTOR)
    old = world.view().facts["transcript.pseudonymised.draft"].sha256
    s.publish(displayed=digest(canonical(s.capsule)))
    assert "transcript.pseudonymised.draft" not in world.view().have
    world.ok(0, "pseudonymise", RECORD, "--actor", ACTOR)
    v = world.view()
    assert v.facts["transcript.pseudonymised.draft"].sha256 == old
    assert not check_referenced(world.ws, v), (
        "P4B_STORAGE: same logical text confused cipher generations"
    )
    Session(world.ctx, "pseudonymisation.cases", ACTOR)
    # Historische Cipherobjekte bleiben prüfpflichtig.
    refs = [r for r in v.protected_artifacts if r["role"] == "transcript.pseudonymised.draft"]
    assert len(refs) == 2 and refs[0]["cipher_sha256"] != refs[1]["cipher_sha256"]
    (s.store.root / "objects" / refs[0]["cipher_sha256"]).unlink()
    assert check_referenced(world.ws, v)


@pytest.mark.parametrize(
    "attack",
    [
        "missing",
        "changed",
        "wrong_key",
        "mode",
        "symlink",
        "hardlink",
        "directory",
        "context",
        "missing_ref",
    ],
)
def test_protected_integrity_attacks(world, attack):
    accepted(world)
    v = world.view()
    ref = v.protected_refs[-1]
    store = ProtectedStore(world.ws, world.journal.key)
    path = store.root / "objects" / ref["cipher_sha256"]
    if attack == "missing":
        path.unlink()
    elif attack == "changed":
        path.write_bytes(b"invalid cipher")
    elif attack == "wrong_key":
        world.protection_key.write_bytes(secrets.token_bytes(32))
        store = ProtectedStore(world.ws, world.journal.key)
        with pytest.raises(ProtectionError):
            store.open(ref, RECORD)
        return  # Status claims byte integrity, never AEAD authentication.
    elif attack == "mode":
        path.chmod(0o644)
    elif attack == "symlink":
        other = path.with_suffix(".cipher")
        path.rename(other)
        path.symlink_to(other)
    elif attack == "hardlink":
        os.link(path, path.with_suffix(".cipher"))
    elif attack == "directory":
        path.unlink()
        path.mkdir()
    elif attack == "context":
        v.protected_refs[-1]["aad"]["record"] = "SPURP-902"
    else:
        v.protected_refs = []
    assert check_referenced(world.ws, v), "P4B_AUTH: malformed protected state accepted"


def revision(text):
    return TranscriptRevision.from_segments(
        [Segment(0, 10, 100, text, "speaker", "deu")], projection_version="seg-join-lf.v1"
    )


def capsule(rev, spans, rules):
    groups = {
        f"{i:032x}": {
            "type": s.entity_type.value,
            "scope": rules[s.entity_type.value].get("scope", "local"),
            "mentions": [s.mention_id],
            "state": "OPEN",
        }
        for i, s in enumerate(model.bound(rev, spans))
    }
    return {
        "v": 1,
        "source": model.source_contract(rev),
        "base": deepcopy(spans),
        "overlay": [],
        "spans": spans,
        "groups": groups,
        "context": "",
    }


@pytest.mark.parametrize(
    "typ",
    [
        e
        for e in (
            "PERSON",
            "ORGANISATION",
            "INSTITUTION",
            "LOCATION",
            "DATE",
            "CONTACT",
            "IDENTIFIER",
        )
    ],
)
def test_unicode_renderer_all_types(typ):
    from ohpipe.project import Profile

    rev = revision("é😀 Alpha\nOmega")
    rules = {k: dict(v) for k, v in Profile.load(PROFILE).pseudonymisation_rules}
    c = capsule(rev, [model.mark(rev, 0, 3, 8, typ)], rules)
    raw = model.render(rev, c, rules)
    assert model.render(rev, c, rules) == raw
    out = verify_revision(raw, digest(raw))
    assert out.text.startswith("é😀 ") and out.text.endswith("\nOmega")
    assert (out.segments[0].index, out.segments[0].start_ms, out.segments[0].end_ms) == (0, 10, 100)
    keep = deepcopy(rules)
    keep[typ] = {"action": "keep"}
    c["groups"][next(iter(c["groups"]))]["scope"] = "local"
    assert verify_revision(model.render(rev, c, keep), rev.sha256).text == rev.text


def test_corrections_overlay_and_case_semantics(world):
    s = drafted(world)
    original = deepcopy(s.capsule)
    first = next(iter(s.capsule["groups"]))
    mid = s.capsule["groups"][first]["mentions"][0]
    s.state(first, "DEFERRED")
    assert model.counts(s.capsule)["open"] == 1
    s.add(0, 13, 19, "PERSON")
    second = next(g for g in s.capsule["groups"] if g != first)
    mids = [mid, s.capsule["groups"][second]["mentions"][0]]
    s.merge([first, second])
    gid = next(iter(s.capsule["groups"]))
    with pytest.raises(ManualError):
        s.split(gid, [[mids[0]], [mids[0]]])
    s.split(gid, [[mids[0]], [mids[1]]])
    assert model.counts(s.capsule)["open"] == 0
    s.add(0, 13, 20, "LOCATION", old=mids[1])
    with pytest.raises(ManualError):
        s.merge(list(s.capsule["groups"]))
    s.exclude(mid)
    assert model.counts(s.capsule)["excluded"] == 1
    model.validate(s.source, s.capsule, s.policy)
    s.save()
    s.publish(displayed=digest(canonical(s.capsule)))
    assert "pseudonymisation.cases" in world.view().have
    assert original != s.capsule
    assert "transcript.pseudonymised.confirmed" not in world.view().have


ManualError = model.ManualError


@pytest.mark.parametrize(
    "attack",
    [
        "empty",
        "negative",
        "outside",
        "wrong_cue",
        "byte",
        "overlap",
        "source",
        "projection",
        "normalization",
        "group",
        "duplicate",
    ],
)
def test_closed_position_contract(attack):
    from ohpipe.project import Profile

    rev = revision("é😀 Alpha\nOmega")
    rules = {k: dict(v) for k, v in Profile.load(PROFILE).pseudonymisation_rules}
    s = model.mark(rev, 0, 3, 8, "PERSON")
    c = capsule(rev, [s], rules)
    if attack == "empty":
        s["end"] = s["start"]
    elif attack == "negative":
        s["start"] = -1
    elif attack == "outside":
        s["end"] = 999
    elif attack == "wrong_cue":
        s["cue_index"] = 1
    elif attack == "byte":
        s["unit"] = "utf8_byte"
    elif attack == "overlap":
        c["spans"].append(model.mark(rev, 0, 4, 9, "LOCATION"))
    elif attack == "duplicate":
        c["spans"].append(deepcopy(s))
    elif attack == "source":
        c["source"]["revision_sha256"] = "f" * 64
    elif attack == "projection":
        c["source"]["cue_projection"] = "unknown"
    elif attack == "normalization":
        c["source"]["normalization"] = "unknown"
    else:
        c["groups"][next(iter(c["groups"]))]["type"] = "LOCATION"
    with pytest.raises(ValueError):
        model.validate(rev, c, rules)


def test_empty_accept_does_not_open_final(world):
    s = Session(world.ctx, "pii.mark", ACTOR)
    s.save()
    s.publish(displayed=digest(canonical(s.capsule)))
    world.ok(0, "pseudonymise", RECORD)
    cases = Session(world.ctx, "pseudonymisation.cases", ACTOR)
    assert model.counts(cases.capsule)["open"] == 0
    cases.save()
    cases.publish(displayed=digest(canonical(cases.capsule)))
    # P4c-Auftrag A06: leerer Fallbestand bleibt vor Resolution/Textgate gesperrt.
    report = json.loads(world.ok(2, "continue", RECORD).out)
    assert report["reason_code"] == "CONFIG_P4C", "P4B_FINAL: final gate opened"
    assert report["details"]["unbuilt"] == []
    assert "transcript.pseudonymised.confirmed" not in world.view().have


def test_session_compare_and_swap(world):
    a = Session(world.ctx, "pii.mark", ACTOR)
    b = Session(world.ctx, "pii.mark", ACTOR)
    a.save()
    before = world.journal.head()
    with pytest.raises(GateError):
        b.save()
    assert world.journal.head() == before
    assert Session(world.ctx, "pii.mark", ACTOR, resume=True).session_id == a.session_id


@pytest.mark.parametrize("change", ["key", "key_id", "store_id", "graph"])
def test_configuration_change_during_dialog(world, change):
    s = Session(world.ctx, "pii.mark", ACTOR)
    before = world.journal.head()
    if change == "key":
        world.protection_key.write_bytes(secrets.token_bytes(32))
    elif change == "graph":
        world.ws.graph_binding_path.unlink()
    else:
        config = json.loads(world.protection_config.read_bytes())
        config[change] = secrets.token_hex(16)
        world.protection_config.write_bytes(canonical(config))
    with pytest.raises((ProtectionError, GateBlocked)):
        s.save()
    assert world.journal.head() == before, "P4B_CONTEXT: obsolete open session wrote evidence"


def test_policy_changes_inside_write_window(world, monkeypatch):
    from dataclasses import replace

    alternate = world.tmp / "policy.toml"
    alternate.write_text(PROFILE.read_text())
    ctx = replace(world.ctx, profile_arg=str(alternate))
    s = Session(ctx, "pii.mark", ACTOR)
    original = ProtectedStore.seal

    def intervening(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        alternate.write_text(PROFILE.read_text().replace('value = "ORT"', 'value = "ORT-B"'))
        return result

    monkeypatch.setattr(ProtectedStore, "seal", intervening)
    with pytest.raises(GateError):
        s.save()
    assert not any(e.kind == "p4b.checkpoint" for e in world.journal)
    assert (
        world.view().sources["pseudonymisation.policy"][0] != s.basis["pseudonymisation.policy"][0]
    )


def test_checkpoint_pointer_is_not_authority(world):
    s = Session(world.ctx, "pii.mark", ACTOR)
    s.save()
    pointer = s.store.root / "sessions" / s.session_id
    old = pointer.read_bytes()
    s.add(0, 0, 12, "PERSON")
    s.save()
    pointer.write_bytes(old)
    restored = Session(world.ctx, "pii.mark", ACTOR, resume=True)
    assert restored.revision == 2 and restored.capsule == s.capsule
    pointer.unlink()
    assert Session(world.ctx, "pii.mark", ACTOR, resume=True).revision == 2


@pytest.mark.parametrize("kind", ["symlink", "hardlink"])
def test_dangerous_session_pointer_is_not_overwritten(world, kind):
    s = Session(world.ctx, "pii.mark", ACTOR)
    s.save()
    pointer = s.store.root / "sessions" / s.session_id
    other = pointer.with_suffix(".cipher")
    if kind == "symlink":
        pointer.rename(other)
        pointer.symlink_to(other)
    else:
        os.link(pointer, other)
    before = world.journal.head()
    with pytest.raises(ProtectionError):
        Session(world.ctx, "pii.mark", ACTOR, resume=True)
    assert world.journal.head() == before
    assert pointer.is_symlink() if kind == "symlink" else pointer.stat().st_nlink == 2


def test_profile_error_retains_configuration_exit(world):
    path = world.tmp / "bad-profile.toml"
    path.write_text(
        PROFILE.read_text().replace('pii_detection = "manual"', 'pii_detection = "unknown"')
    )
    world.profile = path
    assert world.run("pii", "mark", RECORD, tty=True, as_json=False).code == 2


@pytest.mark.parametrize(
    "point",
    [
        "before_object",
        "after_object",
        "before_checkpoint",
        "after_checkpoint",
        "before_prepared",
        "after_prepared",
        "before_completed",
        "after_completed",
    ],
)
@pytest.mark.parametrize("signal_name", ["SIGINT", "SIGTERM", "SIGKILL"])
def test_process_crash_boundaries(world, monkeypatch, point, signal_name):
    import select
    import signal
    from ohpipe.journal import _JournalTransaction

    s = Session(world.ctx, "pii.mark", ACTOR)
    s.add(0, 0, 12, "PERSON")
    s.save()
    read_fd, write_fd = os.pipe()

    def boundary(label):
        if label == point:
            os.write(write_fd, b"R")
            # Prozessbarriere: Elternprozess hat den Persistenzpunkt bestätigt.
            signal.pause()

    original_put = ProtectedStore.put
    original_append = _JournalTransaction.append_once

    def put(self, *args, **kwargs):
        boundary("before_object")
        result = original_put(self, *args, **kwargs)
        boundary("after_object")
        return result

    def append(self, kind, *args, **kwargs):
        tag = kind.removeprefix("p4b.")
        boundary("before_" + tag)
        result = original_append(self, kind, *args, **kwargs)
        boundary("after_" + tag)
        return result

    child = os.fork()
    if child == 0:
        os.close(read_fd)
        # Wie nach exec eines frischen CLI-Prozesses: keine aus früheren
        # Mutantentests geerbten Python-Signalhandler im kontrollierten Kind.
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.default_int_handler)
        try:
            monkeypatch.setattr(ProtectedStore, "put", put)
            monkeypatch.setattr(_JournalTransaction, "append_once", append)
            if "checkpoint" in point or "object" in point:
                s.save()
            else:
                s.publish(displayed=digest(canonical(s.capsule)))
        except BaseException:
            os._exit(70)
        os._exit(71)
    os.close(write_fd)
    try:
        ready, _, _ = select.select([read_fd], [], [], 10)
        assert ready and os.read(read_fd, 1) == b"R", "P4B_CRASH: boundary not reached"
        os.kill(child, getattr(signal, signal_name))
    finally:
        os.close(read_fd)
        os.waitpid(child, 0)
    view = world.view()
    assert not view.findings
    if point == "after_completed":
        assert "pii.spans" in view.have
    else:
        assert "pii.spans" not in view.have, "P4B_COMMIT: partial publication became usable"
    should_recover = point in ("after_prepared", "before_completed")
    assert recover(world.ctx, ACTOR) == int(should_recover)
    head = world.journal.head()
    assert recover(world.ctx, ACTOR) == 0
    assert world.journal.head() == head
    if should_recover:
        assert "pii.spans" in world.view().have
    resumed = Session(world.ctx, "pii.mark", ACTOR, resume=True)
    assert resumed.capsule == s.capsule


def test_write_failure_and_lock_competition(world, monkeypatch):
    import select
    from ohpipe.workspace_lock import workspace_write_lock
    from ohpipe.protected_store import ProtectionBusy

    s = Session(world.ctx, "pii.mark", ACTOR)
    s.save()
    before = world.journal.head()
    with monkeypatch.context() as m:
        m.setattr(os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("synthetic ENOSPC")))
        with pytest.raises((OSError, ProtectionError)):
            s.save()
    assert world.journal.head() == before
    read_fd, write_fd = os.pipe()
    release_read, release_write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            with workspace_write_lock(world.ws.root):
                os.write(write_fd, b"L")
                os.read(release_read, 1)
        finally:
            os._exit(0)
    try:
        assert select.select([read_fd], [], [], 10)[0]
        assert os.read(read_fd, 1) == b"L"
        with pytest.raises(ProtectionBusy):
            s.save()
    finally:
        os.write(release_write, b"R")
        os.waitpid(child, 0)
        for fd in (read_fd, write_fd, release_read, release_write):
            os.close(fd)
    assert world.journal.head() == before


def test_policy_observation_two_records_a_b_a(world, monkeypatch):
    from dataclasses import replace
    from ohpipe.application.manual_work import refresh
    from ohpipe.project import Profile

    s = drafted(world)
    s.save()
    original = PROFILE.read_text()
    alternate = world.tmp / "policy.toml"
    alternate.write_text(original)
    ctx = replace(world.ctx, profile_arg=str(alternate))
    # Auch der zweite Record besitzt vor dem Wechsel akzeptierte P4b-Evidenz.
    other_id = "SPURP-902"
    source, mapping = world.tmp / "synthetic.srt", world.tmp / "synthetic.tsv"
    world.ok(3, "ingest", str(source), "--record", other_id)
    world.ok(
        0,
        "transcript",
        "language",
        "prepare",
        other_id,
        str(source),
        str(mapping),
        "--actor",
        ACTOR,
        "--reference",
        "SYNTHETIC-P4B",
        "--confirm",
    )
    world.ok(0, "transcript", "ingest", other_id, str(source), str(mapping), "--confirm")
    world.ok(0, "transcript", "confirm", other_id, "--actor", ACTOR, "--confirm")
    ctx2 = replace(ctx, record_id=other_id)
    second = Session(ctx2, "pii.mark", ACTOR)
    second.save()
    second.publish(displayed=digest(canonical(second.capsule)))
    alternate.write_text(original.replace('value = "ORT"', 'value = "ORT-B"'))
    refresh(ctx2, ProtectedStore(world.ws, world.journal.key))
    v = world.view()
    assert "pii.spans" not in v.have, "P4B_POLICY: different record did not invalidate policy"
    assert not check_referenced(world.ws, v)
    from ohpipe.application.replay import replay
    from ohpipe.domain.step import build_graph

    views = replay(
        world.journal, graph=build_graph(world.ws.profile), authority=Authority.AUTHENTICATED
    )
    assert "pii.spans" not in views[other_id].have, "P4B_POLICY: second record not invalidated"
    alternate.write_text(original)
    refresh(ctx2, ProtectedStore(world.ws, world.journal.key))
    assert "pii.spans" not in world.view().have, "P4B_POLICY: A-B-A revived old receipt"
    with pytest.raises(GateError):
        Session(ctx, "pseudonymisation.cases", ACTOR, resume=True)
    assert (
        Profile.load(alternate).pseudonymisation_policy_sha256
        == world.ws.profile.pseudonymisation_policy_sha256
    )


def test_actor_change_and_source_reactivation(world):
    s = Session(world.ctx, "pii.mark", ACTOR)
    s.save()
    world.ok(
        0,
        "instance",
        "register",
        "OTHER-SYNTHETIC",
        "--source",
        "mensch",
        "--label",
        "Other synthetic",
        "--reference",
        "P4B",
        "--confirm",
    )
    with pytest.raises(GateError):
        Session(world.ctx, "pii.mark", "OTHER-SYNTHETIC", resume=True)
    world.ok(0, "transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")
    # Wenn der Bestätigungsschreiber den identischen Wiederholungsakt dedupliziert,
    # ist der Zustand unverändert; eine echte Markierungsneuaktivierung wird unten geprüft.
    s = accepted(world)
    world.ok(0, "pseudonymise", RECORD, "--actor", ACTOR)
    cases = Session(world.ctx, "pseudonymisation.cases", ACTOR)
    cases.save()
    s = Session(world.ctx, "pii.mark", ACTOR, resume=True)
    s.publish(displayed=digest(canonical(s.capsule)))
    assert "transcript.pseudonymised.draft" not in world.view().have
    with pytest.raises(GateError):
        cases.publish(displayed=digest(canonical(cases.capsule)))


def test_exact_original_inventory_and_leak_oracle(world):
    w = world
    original, new_context = w.source_marker.encode(), secrets.token_hex(24).encode()
    role_by_sha = {}
    for event in w.journal:
        p = event.payload
        if event.kind == "source.ingested":
            role_by_sha[p["sha256"]] = "srt"
        if event.kind == "artifact.produced":
            role_by_sha[p["sha256"]] = p["artifact"]
    inventory = []
    for path in w.tmp.rglob("*"):
        if not path.is_file() or original not in path.read_bytes():
            continue
        sha = digest(path.read_bytes())
        role = (
            "synthetic-fixture-source" if path == w.tmp / "synthetic.srt" else role_by_sha.get(sha)
        )
        assert role in ("srt", "transcript.revision", "synthetic-fixture-source"), (
            "P4B_LEAK: unexpected initial copy"
        )
        inventory.append({"path": str(path), "role": role, "sha256": sha})
    assert {r["role"] for r in inventory} == {
        "srt",
        "transcript.revision",
        "synthetic-fixture-source",
    }
    allowed = {r["path"]: r["sha256"] for r in inventory}

    def oracle():
        issues = []
        for path in __import__("itertools").chain(w.tmp.rglob("*"), PROFILE.parents[4].rglob("*")):
            if not path.is_file():
                continue
            raw = path.read_bytes()
            if new_context in raw or (original in raw and allowed.get(str(path)) != digest(raw)):
                issues.append(str(path))
        for path, sha in allowed.items():
            if not Path(path).is_file() or digest(Path(path).read_bytes()) != sha:
                issues.append(path)
        return issues

    assert not oracle()
    s = drafted(w)
    s.capsule["context"] = new_context.decode()
    s.save()
    s.publish(displayed=digest(canonical(s.capsule)))
    # Status/Doctor zeigen keine entschlüsselten Inhalte und prüfen den externen Weg.
    for command in ("status", "doctor", "continue"):
        r = w.run(command, *([RECORD] if command == "continue" else []))
        assert original not in r.out.encode() and new_context not in r.out.encode()
        assert r.code != 1, "P4B_STORAGE: valid external chain produced STOP"
    assert not oracle(), "P4B_LEAK: new plaintext outside volatile view"
    draft_leak = w.ws.objects / secrets.token_hex(32)
    draft_leak.write_bytes(original)
    assert oracle(), "P4B_LEAK: injected draft was ignored"
    draft_leak.unlink()
    case_leak = w.tmp / "case.log"
    case_leak.write_bytes(new_context)
    assert oracle(), "P4B_LEAK: injected case log was ignored"
    case_leak.unlink()
    assert not oracle()
    # Keine Suchmarker im dauerhaften Beleg, nur Pfade/Rollen/Digests/Zähler.
    print(
        json.dumps(
            {
                "p4b_leakage_inventory": inventory,
                "positive": True,
                "draft_negative_detected": True,
                "case_negative_detected": True,
            }
        )
    )


def test_crash_harness_does_not_inherit_foreign_signal_handler(world, monkeypatch):
    import signal

    marker = world.tmp / "foreign-test-handler.flag"
    before = signal.getsignal(signal.SIGTERM)

    def foreign_handler(signum, frame):
        marker.write_bytes(b"called")
        raise SystemExit(77)

    try:
        signal.signal(signal.SIGTERM, foreign_handler)
        test_process_crash_boundaries(world, monkeypatch, "after_checkpoint", "SIGTERM")
    finally:
        signal.signal(signal.SIGTERM, before)
    assert not marker.exists(), "P4B_CRASH: foreign test signal handler inherited"


def test_review_policy_continue_next_and_no_stale_draft(world):
    import shlex

    alternate = world.tmp / "policy.toml"
    alternate.write_text(PROFILE.read_text())
    world.profile = alternate
    accepted(world)
    alternate.write_text(PROFILE.read_text().replace('value = "ORT"', 'value = "ORT-B"'))
    report = json.loads(world.ok(3, "continue", RECORD).out)
    assert report["reason_code"] == "ACTION_P4B"
    assert shlex.split(report["next"])[-3:] == ["pii", "mark", RECORD]
    assert not {"pii.spans", "transcript.pseudonymised.draft"} & world.view().have
    assert not any(
        e.kind == "p4b.prepared" and e.payload["ref"]["aad"]["phase"] == "pseudonymise"
        for e in world.journal
    )


@pytest.mark.parametrize(
    "error,code,reason",
    [
        ("GateError", 3, "ACTION_P4B"),
        ("GateBlocked", 1, "STOP_CONTINUE_HANDLER"),
        ("ProtectionConfig", 2, "CONFIG_P4B"),
        ("ProtectionBusy", 3, "ACTION_P4B"),
        ("ProtectionError", 1, "STOP_CONTINUE_HANDLER"),
    ],
)
def test_review_continue_handler_error_contract(world, monkeypatch, error, code, reason):
    from ohpipe import protected_store

    accepted(world)
    exception = {"GateError": GateError, "GateBlocked": GateBlocked}.get(error) or getattr(
        protected_store, error
    )

    def fail(self, *args, **kwargs):
        raise exception("synthetic handler halt")

    monkeypatch.setattr(Session, "publish", fail)
    before = world.journal.head()
    report = json.loads(world.ok(code, "continue", RECORD).out)
    assert report["reason_code"] == reason
    assert report["details"]["executed"] == []
    assert bool(report["next"]) == (code == 3)
    assert world.journal.head() == before
    assert "transcript.pseudonymised.draft" not in world.view().have


@pytest.mark.parametrize("phase", ["pii.mark", "pseudonymisation.cases"])
@pytest.mark.parametrize("later_revision", [False, True])
def test_review_new_actor_exact_completed_checkpoint(world, phase, later_revision):
    s = accepted(world) if phase == "pii.mark" else drafted(world)
    if phase == "pseudonymisation.cases":
        s.capsule["context"] = "synthetic previous case context"
        s.save()
        s.publish(displayed=digest(canonical(s.capsule)))
    historical = list(world.journal)
    if later_revision:
        s.capsule["context"] = "synthetic unconfirmed revision"
        s.save()
    other = "OTHER-SYNTHETIC"
    world.ok(
        0,
        "instance",
        "register",
        other,
        "--source",
        "mensch",
        "--label",
        "Other synthetic",
        "--reference",
        "P4B-REVIEW",
        "--confirm",
    )
    before = world.journal.head()
    with pytest.raises(GateError):
        Session(world.ctx, phase, other, resume=True)
    if later_revision:
        with pytest.raises(GateError):
            Session(world.ctx, phase, other)
        assert world.journal.head() == before
        return
    fresh = Session(world.ctx, phase, other)
    assert fresh.actor == other and fresh.revision == 0 and fresh.saved_bytes is None
    assert fresh.session_id != s.session_id and fresh.capsule["context"] == ""
    assert fresh.capsule["overlay"] == []
    if phase == "pii.mark":
        assert fresh.capsule["spans"] == [] and fresh.capsule["groups"] == {}
    assert world.journal.head() == before
    # Zwei neue Sitzungen dürfen die historische Fassung lesen, aber nur eine
    # darf sie per CAS ablösen. Der alte Actor bleibt ebenfalls daran gebunden.
    competing = Session(world.ctx, phase, other)
    fresh.save()
    with pytest.raises(GateError):
        competing.save()
    with pytest.raises(GateError):
        s.save()
    assert list(world.journal)[: len(historical)] == historical
    assert Session(world.ctx, phase, other, resume=True).session_id == fresh.session_id


@pytest.mark.parametrize("phase", ["pii.mark", "pseudonymisation.cases"])
def test_review_prepared_without_completion_is_not_historical(world, phase):
    s = Session(world.ctx, phase, ACTOR) if phase == "pii.mark" else drafted(world)
    s.save()
    # Publikationsabbruch ist bereits an echten Prozessgrenzen separat belegt;
    # hier wird exakt das unvollständige Journalpräfix für beide Phasen geprüft.
    from ohpipe.application.manual_work import checkpoint_completed

    events = list(world.journal)
    assert not checkpoint_completed(events, RECORD, s.previous, world.view())
    s.publish(displayed=digest(canonical(s.capsule)))
    events = list(world.journal)
    assert checkpoint_completed(events, RECORD, s.previous, world.view())
    assert not checkpoint_completed(events[:-1], RECORD, s.previous, world.view())


@pytest.mark.parametrize("scope", ["workspace", "protected"])
def test_review_continue_actual_lock_competition(world, scope):
    import select
    from ohpipe.workspace_lock import workspace_write_lock

    accepted(world)
    before = world.journal.head()
    ready_read, ready_write = os.pipe()
    release_read, release_write = os.pipe()
    child = os.fork()
    if child == 0:
        try:
            lock = (
                workspace_write_lock(world.ws.root)
                if scope == "workspace"
                else ProtectedStore(world.ws, world.journal.key).lock()
            )
            with lock:
                os.write(ready_write, b"L")
                os.read(release_read, 1)
        finally:
            os._exit(0)
    try:
        assert select.select([ready_read], [], [], 10)[0]
        assert os.read(ready_read, 1) == b"L"
        report = json.loads(world.ok(3, "continue", RECORD).out)
        assert report["reason_code"] == "ACTION_P4B"
        assert report["details"]["failure_kind"] == "ProtectionBusy"
        assert world.journal.head() == before
        assert "transcript.pseudonymised.draft" not in world.view().have
    finally:
        os.write(release_write, b"R")
        os.waitpid(child, 0)
        for fd in (ready_read, ready_write, release_read, release_write):
            os.close(fd)
    report = json.loads(world.ok(3, "continue", RECORD).out)
    assert report["reason_code"] == "ACTION_CONTINUE_GATE"
    assert "transcript.pseudonymised.draft" in world.view().have


@pytest.mark.parametrize("selection", ["missing_selection", "missing_key_reference"])
@pytest.mark.parametrize("integrity", ["none", "source_missing", "source_changed", "replay"])
def test_config_before_handler_with_integrity_priority(world, monkeypatch, selection, integrity):
    accepted(world)
    if selection == "missing_selection":
        monkeypatch.delenv("OHPIPE_PROTECTION_CONFIG")
    else:
        config = json.loads(world.protection_config.read_bytes())
        config["key_file"] = ""
        world.protection_config.write_bytes(canonical(config))
    if integrity.startswith("source_"):
        path = world.ws.objects / world.view().facts["transcript.revision"].sha256
        if integrity == "source_missing":
            path.unlink()
        else:
            path.write_bytes(b"synthetic damaged source")
    elif integrity == "replay":
        world.journal.append_once(
            "p4b.completed",
            {"v": 1, "prepared_sha256": "0" * 64},
            record_id=RECORD,
            duplikat=lambda e: False,
        )
    before = world.journal.head()
    result = world.run("continue", RECORD)
    report = json.loads(result.out)
    assert result.code == (2 if integrity == "none" else 1)
    assert report["reason_code"] == (
        "CONFIG_P4B" if integrity == "none" else "STOP_CONTINUE_FINDINGS"
    )
    assert report["details"]["executed"] == [] and not report["next"]
    assert world.journal.head() == before
    assert "transcript.pseudonymised.draft" not in world.view().have
    if integrity == "none":
        assert world.run("pseudonymise", RECORD, "--actor", ACTOR).code == 2
        # Andere bestehende Schutzleser dürfen fehlende Prüfgrundlagen nicht
        # als leere/grüne Befundliste behandeln.
        assert check_referenced(world.ws, world.view())


@pytest.mark.parametrize("damage", ["key_file", "config_file", "wrong_key", "cipher"])
def test_declared_protection_damage_stays_stop(world, damage):
    accepted(world)
    if damage == "key_file":
        world.protection_key.unlink()
    elif damage == "config_file":
        world.protection_config.unlink()
    elif damage == "wrong_key":
        world.protection_key.write_bytes(secrets.token_bytes(32))
    else:
        ref = world.view().protected_refs[-1]
        store = ProtectedStore(world.ws, world.journal.key)
        (store.root / "objects" / ref["cipher_sha256"]).write_bytes(b"synthetic damaged cipher")
    before = world.journal.head()
    for command in [("continue", RECORD), ("pseudonymise", RECORD, "--actor", ACTOR)]:
        assert world.run(*command).code == 1
        assert world.journal.head() == before
        assert "transcript.pseudonymised.draft" not in world.view().have


def test_configuration_text_does_not_reclassify_real_finding(world):
    from ohpipe.application.steps import continue_record, continue_report
    from ohpipe.application.storage_integrity import ProtectionConfigurationFinding

    v = world.view()
    v.findings.append("OHPIPE_PROTECTION_CONFIG fehlt")
    v.findings.append(ProtectionConfigurationFinding("Schlüsselverweis fehlt"))
    registry = registry_for(world.ws.profile)
    outcome = continue_record(world.ctx, graph=v.graph, registry=registry, view_of=lambda: v)
    assert continue_report(outcome, world.ctx, registry).exit_code == 1


def test_missing_selection_does_not_mask_broken_journal(world, monkeypatch):
    accepted(world)
    monkeypatch.delenv("OHPIPE_PROTECTION_CONFIG")
    path = world.journal.path
    path.write_bytes(path.read_bytes() + b"synthetic broken journal\n")
    before = path.read_bytes()
    result = world.run("continue", RECORD)
    report = json.loads(result.out)
    assert result.code == 1 and report["reason_code"] != "CONFIG_P4B"
    assert path.read_bytes() == before
