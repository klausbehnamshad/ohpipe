"""P4c: tatsächliche synthetische Publikation und Konvergenz, keine Freigabeattrappen."""

import json
import os
import secrets
from copy import deepcopy
from pathlib import Path

import pytest

from .test_spur_p4b import world, drafted, ACTOR, RECORD  # noqa: F401
from .test_spur_p1 import isolated  # noqa: F401
from ohpipe.application import finalisation as work
from ohpipe.domain import manual_pseudonymisation as manual
from ohpipe.protected_store import canonical, digest, ProtectionError
from ohpipe.registry_store import RegistryStore, REGISTRY, RESOLUTION, FINAL, REPORT, GATE
from ohpipe.application.confirmed_text import read_confirmed_text


@pytest.fixture
def ready(request, monkeypatch):
    return configured(
        request.getfixturevalue("world"), monkeypatch, initialise=getattr(request, "param", True)
    )


def configured(w, monkeypatch, *, initialise=True):
    root = w.protection_config.parent.parent
    p = root / "registry"
    p.mkdir(mode=0o700)
    (p / "objects").mkdir(mode=0o700)
    key = root / "secrets/registry.key"
    candidate = root / "secrets/candidate.key"
    for f in (key, candidate):
        f.write_bytes(secrets.token_bytes(32))
        f.chmod(0o600)
    config = root / "secrets/registry.json"
    config.write_bytes(
        canonical(
            dict(
                v=1,
                root=str(p),
                registry_id=secrets.token_hex(16),
                workspace=digest(os.fsencode(w.ws.root.resolve())),
                profile="spur-p-manual",
                scope="spur-p-synthetic",
                key_file=str(key),
                key_id=secrets.token_hex(16),
                candidate_key_file=str(candidate),
                candidate_key_id=secrets.token_hex(16),
            )
        )
    )
    config.chmod(0o600)
    monkeypatch.setenv("OHPIPE_REGISTRY_CONFIG", str(config))
    w.registry_config = config
    s = drafted(w)
    for gid in s.capsule["groups"]:
        s.state(gid, "RESOLVED")
    s.save()
    s.publish(displayed=digest(canonical(s.capsule)))
    if initialise:
        w.ok(0, "pseudonymisation", "registry", "init")
    return w


def resolved(w):
    s = work.Work(w.ctx, ACTOR)
    for gid in s.capsule["groups"]:
        s.choose(gid)
    s.accept_resolution(digest(canonical(s.resolution)))
    return s


def approve(w):
    s = work.Work(w.ctx, ACTOR)
    inputs, raw, report = s.review_material()
    s.accept_text(
        digest(canonical({"final": digest(raw), "report": inputs[REPORT][0], "basis": inputs})),
        inputs,
    )
    return raw


def test_finalisation_and_gate(ready):
    w = ready
    from ohpipe.application.storage_integrity import check_referenced

    assert not check_referenced(w.ws, w.view()), check_referenced(w.ws, w.view())
    resolved(w)
    assert not w.view().findings, w.view().findings
    w.ok(0, "pseudonymise", "finalise", RECORD)
    v = w.view()
    assert FINAL in v.have and REPORT in v.have and GATE not in v.have, (
        v.findings,
        {k: f.freshness_reason for k, f in v.facts.items()},
    )
    raw = approve(w)
    v = w.view()
    assert GATE in v.have, (v.findings, {k: f.freshness_reason for k, f in v.facts.items()})
    confirmed = read_confirmed_text(w.ctx, v, "l1.suggest")
    assert confirmed.revision_bytes == raw, "P4C_TEXT: consumer did not read final bytes"
    assert "PERSON-001" in confirmed.revision.text and "?" not in confirmed.revision.text
    assert not (w.ws.objects / confirmed.text_sha256).exists()
    before = list(w.journal)
    w.ok(0, "pseudonymise", "finalise", RECORD)
    assert list(w.journal) == before


def other_record(w, rid="SPURP-902", *, mark=True):
    from dataclasses import replace

    source, mapping = w.tmp / "synthetic.srt", w.tmp / "synthetic.tsv"
    w.ok(3, "ingest", str(source), "--record", rid)
    w.ok(
        0,
        "transcript",
        "language",
        "prepare",
        rid,
        str(source),
        str(mapping),
        "--actor",
        ACTOR,
        "--reference",
        "SYNTHETIC-P4C",
        "--confirm",
    )
    w.ok(0, "transcript", "ingest", rid, str(source), str(mapping), "--confirm")
    w.ok(0, "transcript", "confirm", rid, "--actor", ACTOR, "--confirm")
    ctx = replace(w.ctx, record_id=rid)
    from ohpipe.application.manual_work import Session

    s = Session(ctx, "pii.mark", ACTOR)
    if mark:
        s.add(0, 0, 12, "PERSON")
    s.save()
    s.publish(displayed=digest(canonical(s.capsule)))
    w.ok(0, "pseudonymise", rid)
    s = Session(ctx, "pseudonymisation.cases", ACTOR)
    for gid in s.capsule["groups"]:
        s.state(gid, "RESOLVED")
    s.save()
    s.publish(displayed=digest(canonical(s.capsule)))
    return ctx


def approve_ctx(ctx):
    s = work.Work(ctx, ACTOR)
    inputs, raw, report = s.review_material()
    s.accept_text(
        digest(canonical({"final": digest(raw), "report": inputs[REPORT][0], "basis": inputs})),
        inputs,
    )
    return raw


def consume(w, ctx):
    result = w.run("continue", ctx.record_id, "--confirm")
    assert result.code == 3, json.loads(result.out)["reason"]
    v = work.view(ctx, list(w.journal))
    assert {"l1.suggestions", "l1.coverage", GATE} <= v.have, {
        k: f.freshness_reason for k, f in v.facts.items()
    }


@pytest.mark.parametrize("same_entity", [False, True])
def test_two_record_convergence(ready, same_entity):
    w = ready
    resolved(w).finalise()
    raw_a = approve(w)
    consume(w, w.ctx)
    r1 = RegistryStore(w.ws, w.journal.key).head()
    ctx_b = other_record(w)
    b = work.Work(ctx_b, ACTOR)
    for gid in b.capsule["groups"]:
        candidates = b.candidates(gid)
        assert len(candidates) == 1
        # Even the sole candidate leaves the new Mention unadjudicated.
        with pytest.raises(ProtectionError):
            b.accept_resolution(digest(canonical(b.resolution)))
        b.choose(gid, candidates[0] if same_entity else None)
    b.accept_resolution(digest(canonical(b.resolution)))
    b.finalise()
    raw_b = approve_ctx(ctx_b)
    consume(w, ctx_b)
    store = RegistryStore(w.ws, w.journal.key)
    r2 = store.head()
    assert r2 != r1 and r2["aad"]["version"] == r1["aad"]["version"] + 1
    assert GATE not in w.view().have and "l1.coverage" not in w.view().have
    before_resolutions = sum(
        e.kind == "p4c.prepared" and e.payload["phase"] == "resolve" for e in w.journal
    )
    r2_activation = work.view(ctx_b, list(w.journal)).sources[REGISTRY]
    work.Work(w.ctx, ACTOR).finalise()
    assert w.view().sources[REGISTRY] == r2_activation, (
        "P4C_CONVERGENCE: rebinding generated register activation"
    )
    assert approve(w) == raw_a
    consume(w, w.ctx)
    assert store.head() == r2, "P4C_CONVERGENCE: rebinding generated register version"
    v_a, v_b = work.view(w.ctx, list(w.journal)), work.view(ctx_b, list(w.journal))
    assert {GATE, "l1.coverage"} <= v_a.have and {GATE, "l1.coverage"} <= v_b.have, (
        "P4C_CONVERGENCE: other record invalidated"
    )
    reg_pair = v_a.sources[REGISTRY]
    marker_b = v_b.facts[GATE].sha256
    for ctx in (w.ctx, ctx_b, w.ctx, ctx_b):
        work.Work(ctx, ACTOR).finalise()
        read_confirmed_text(ctx, work.view(ctx, list(w.journal)), "l1.suggest")
        assert (
            store.head() == r2 and work.view(ctx, list(w.journal)).sources[REGISTRY] == reg_pair
        ), "P4C_CONVERGENCE: repeated activation"
    assert work.view(ctx_b, list(w.journal)).facts[GATE].sha256 == marker_b
    assert (
        sum(e.kind == "p4c.prepared" and e.payload["phase"] == "resolve" for e in w.journal)
        == before_resolutions
    )
    from ohpipe.domain.revision_serialization import verify_revision

    assert ("PERSON-001" in verify_revision(raw_b, digest(raw_b)).text) == same_entity


@pytest.mark.parametrize("phase", ["resolve", "review"])
@pytest.mark.parametrize("json_mode,tty", [(True, True), (False, False), (True, False)])
def test_noninteractive_before_decryption(ready, monkeypatch, phase, json_mode, tty):
    def forbidden(*args, **kwargs):
        pytest.fail("P4C_TTY: decryption before terminal gate")

    monkeypatch.setattr(RegistryStore, "open", forbidden)
    assert ready.run("pseudonymisation", phase, RECORD, as_json=json_mode, tty=tty).code == 2


def test_real_cli_resolution_review_and_abort(ready):
    w = ready
    for answer, expected in [("", 3), ("schließen\n", 3), ("neu\nBESTÄTIGEN\n", 0)]:
        r = w.run(
            "pseudonymisation",
            "resolve",
            RECORD,
            "--actor",
            ACTOR,
            tty=True,
            as_json=False,
            answer=answer,
        )
        assert r.code == expected, (r.out, r.err)
    w.ok(0, "pseudonymise", "finalise", RECORD)
    r = w.run(
        "pseudonymisation", "review", RECORD, "--actor", ACTOR, tty=True, as_json=False, answer=""
    )
    assert r.code == 3 and GATE not in w.view().have
    r = w.run(
        "pseudonymisation",
        "review",
        RECORD,
        "--actor",
        ACTOR,
        tty=True,
        as_json=False,
        answer="BESTÄTIGEN\n",
    )
    assert r.code == 0 and "FINALISIERT — NICHT FREIGEGEBEN" in r.out, (r.out, r.err)
    assert "Ich habe den vollständigen Text gelesen" in r.out
    consume(w, w.ctx)


@pytest.mark.parametrize(
    "change",
    [
        "missing_selection",
        "empty_key",
        "missing_file",
        "wrong_key",
        "cipher",
        "head_missing",
        "rollback",
        "mode",
        "symlink",
        "hardlink",
    ],
)
def test_configuration_and_integrity(ready, monkeypatch, change):
    w = ready
    old = RegistryStore(w.ws, w.journal.key).head()
    resolved(w).finalise()
    config = json.loads(w.registry_config.read_bytes())
    root = Path(config["root"])
    if change == "missing_selection":
        monkeypatch.delenv("OHPIPE_REGISTRY_CONFIG")
    elif change == "empty_key":
        config["candidate_key_file"] = ""
        w.registry_config.write_bytes(canonical(config))
    elif change == "missing_file":
        Path(config["key_file"]).unlink()
    elif change == "wrong_key":
        Path(config["key_file"]).write_bytes(secrets.token_bytes(32))
    elif change == "cipher":
        store = RegistryStore(w.ws, w.journal.key)
        r = store.head()
        p = root / "objects" / r["cipher_sha256"]
        p.write_bytes(b"broken")
    elif change == "head_missing":
        (root / "head").unlink()
    elif change == "rollback":
        (root / "head").write_bytes(canonical(old))
    elif change == "mode":
        (root / "head").chmod(0o644)
    else:
        target = root / "other"
        (root / "head").rename(target)
        if change == "symlink":
            (root / "head").symlink_to(target)
        else:
            os.link(target, root / "head")
    before = w.journal.head()
    r = w.run("pseudonymise", "finalise", RECORD)
    assert r.code == (2 if change in ("missing_selection", "empty_key") else 1), (r.out, r.err)
    assert w.journal.head() == before


@pytest.mark.parametrize("signal_name", ["SIGTERM", "SIGKILL"])
@pytest.mark.parametrize("point", ["cipher_fsync", "prepared", "head", "completed"])
def test_process_crash_and_recovery(ready, monkeypatch, signal_name, point):
    import signal
    import select

    w = ready
    resolved(w)
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

        def boundary(stage):
            if stage == point:
                os.write(write_fd, b"R")
                signal.pause()

        monkeypatch.setattr(work, "hook", boundary)
        try:
            work.Work(w.ctx, ACTOR).finalise()
        except BaseException:
            os._exit(70)
        os._exit(71)
    os.close(write_fd)
    try:
        assert select.select([read_fd], [], [], 10)[0] and os.read(read_fd, 1) == b"R", (
            "P4C_CRASH: barrier not reached"
        )
        os.kill(child, getattr(signal, signal_name))
    finally:
        os.close(read_fd)
        os.waitpid(child, 0)
    v = w.view()
    assert not v.findings
    assert (FINAL in v.have) == (point == "completed"), (
        "P4C_ATOMIC: partial publication became usable"
    )
    work.recover(w.ctx, ACTOR)
    work.Work(w.ctx, ACTOR).finalise()
    approve(w)
    before = w.journal.head()
    assert work.recover(w.ctx, ACTOR) == 0
    assert w.journal.head() == before
    store = RegistryStore(w.ws, w.journal.key)
    _, reg = work.current(w.ctx, store, list(w.journal))
    assert reg["counters"] == {"PERSON": 2}, "P4C_RECOVERY: duplicate allocation"


@pytest.mark.parametrize(
    "field", ["missing", "extra", "type", "foreign", "reuse_unknown", "action"]
)
def test_resolution_closed_complete_batch(ready, field):
    w = ready
    s = work.Work(w.ctx, ACTOR)
    for gid in s.capsule["groups"]:
        s.choose(gid)
    assignments = s.resolution["assignments"]
    mid = next(iter(assignments))
    if field == "missing":
        del assignments[mid]
    elif field == "extra":
        assignments["MEN-unknown"] = deepcopy(assignments[mid])
    elif field == "foreign":
        s.resolution["registry_id"] = secrets.token_hex(16)
    elif field == "reuse_unknown":
        assignments[mid]["intent"] = "reuse"
    elif field == "type":
        assignments[mid]["type"] = "ORGANISATION"
    else:
        assignments[mid]["action"] = "keep"
    before = s.store.head(), w.journal.head()
    with pytest.raises(ProtectionError):
        s.accept_resolution(digest(canonical(s.resolution)))
    assert (s.store.head(), w.journal.head()) == before, "P4C_BATCH: invalid batch consumed state"


@pytest.mark.parametrize(
    "change", ["source", "resolution", "registry", "policy", "withdraw", "actor"]
)
def test_review_window_rechecks(ready, monkeypatch, change):
    from dataclasses import replace
    from ohpipe.application.gate import GateError

    w = ready
    resolved(w).finalise()
    s = work.Work(w.ctx, ACTOR)
    inputs, raw, _ = s.review_material()
    displayed = digest(
        canonical({"final": digest(raw), "report": inputs[REPORT][0], "basis": inputs})
    )
    if change == "registry":
        ctx = other_record(w)
        b = work.Work(ctx, ACTOR)
        for gid in b.capsule["groups"]:
            b.choose(gid)
        b.accept_resolution(digest(canonical(b.resolution)))
        b.finalise()
    elif change == "source":
        from ohpipe.domain.language_assignment import build_srt_draft

        source, mapping = w.tmp / "changed.srt", w.tmp / "changed.tsv"
        raw_source = b"1\n00:00:00,000 --> 00:00:02,000\nS: Synthetic changed source.\n"
        source.write_bytes(raw_source)
        draft = build_srt_draft(raw_source)
        mapping.write_text(
            "index\tsegment_sha256\tlanguage\n"
            + "".join(f"{n}\t{cue.sha256}\tdeu\n" for n, cue in enumerate(draft.segments))
        )
        w.ok(
            0,
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(source),
            str(mapping),
            "--actor",
            ACTOR,
            "--reference",
            "SYNTHETIC-P4C-SOURCE",
            "--confirm",
        )
        w.ok(0, "transcript", "ingest", RECORD, str(source), str(mapping), "--confirm")
        assert w.view().facts["transcript.revision"].sha256 != inputs["transcript.revision"][0]
    elif change == "resolution":
        resolved(w)
    elif change == "policy":
        alternate = w.tmp / "policy.toml"
        alternate.write_text(w.profile.read_text().replace('value = "ORT"', 'value = "ORT-B"'))
        s.ctx = replace(w.ctx, profile_arg=str(alternate))
    elif change == "actor":
        w.ok(0, "instance", "retire", ACTOR, "--reference", "SYNTHETIC-P4C", "--confirm")
    else:
        w.ok(
            0,
            "decision",
            "withdraw",
            RECORD,
            "pseudonymisation.cases",
            "--actor",
            ACTOR,
            "--reference",
            "SYNTHETIC-P4C",
            "--confirm",
        )
    before = sum(e.kind == "p4c.prepared" and e.payload["phase"] == "review" for e in w.journal)
    with pytest.raises((GateError, ProtectionError, ValueError)):
        s.accept_text(displayed, inputs)
    assert (
        sum(e.kind == "p4c.prepared" and e.payload["phase"] == "review" for e in w.journal)
        == before
    ), "P4C_WINDOW: stale ACCEPT"


def test_policy_change_after_cipher_prevents_publication(ready, monkeypatch):
    from dataclasses import replace
    from ohpipe.application.gate import GateError

    w = ready
    resolved(w)
    alternate = w.tmp / "policy.toml"
    alternate.write_text(w.profile.read_text())
    ctx = replace(w.ctx, profile_arg=str(alternate))
    s = work.Work(ctx, ACTOR)
    before = s.store.head()

    def change(stage):
        if stage == "cipher_fsync":
            alternate.write_text(w.profile.read_text().replace('value = "ORT"', 'value = "ORT-B"'))

    monkeypatch.setattr(work, "hook", change)
    with pytest.raises(GateError):
        s.finalise()
    assert s.store.head() == before and FINAL not in w.view().have


@pytest.mark.parametrize("damage", ["source", "cipher"])
def test_real_integrity_dominates_missing_configuration(ready, monkeypatch, damage):
    w = ready
    resolved(w).finalise()
    if damage == "source":
        (w.ws.objects / w.view().facts["transcript.revision"].sha256).unlink()
    else:
        p = w.view().protected_refs[0]
        from ohpipe.protected_store import ProtectedStore

        (ProtectedStore(w.ws).root / "objects" / p["cipher_sha256"]).unlink()
    monkeypatch.delenv("OHPIPE_REGISTRY_CONFIG")
    assert w.run("pseudonymise", "finalise", RECORD).code == 1
    assert w.run("continue", RECORD).code == 1


def test_empty_batch_still_requires_human_gate(ready):
    w = ready
    ctx = other_record(w, mark=False)
    s = work.Work(ctx, ACTOR)
    assert not s.capsule["groups"]
    with pytest.raises(work.GateError):
        s.finalise()
    s.accept_resolution(digest(canonical(s.resolution)))
    s.finalise()
    v = work.view(ctx, list(w.journal))
    assert FINAL in v.have and GATE not in v.have
    approve_ctx(ctx)
    before = RegistryStore(w.ws, w.journal.key).head()
    work.Work(ctx, ACTOR).finalise()
    assert RegistryStore(w.ws, w.journal.key).head() == before
    consume(w, ctx)


def test_registry_restore_and_cross_workspace(ready, monkeypatch):
    from dataclasses import replace
    import shutil

    w = ready
    resolved(w).finalise()
    approve(w)
    store = RegistryStore(w.ws, w.journal.key)
    expected = store.head()
    saved = w.tmp / "backup"
    shutil.copytree(store.root, saved)
    # Restore preserves the declaration, key, ciphertext and authenticated anchor.
    for p in (store.root / "objects").iterdir():
        p.unlink()
    for p in (saved / "objects").iterdir():
        shutil.copy2(p, store.root / "objects" / p.name)
    assert work.current(w.ctx, store, list(w.journal))[0] == expected
    foreign = replace(w.ws, root=w.tmp / "foreign-data")
    with pytest.raises(ProtectionError):
        RegistryStore(foreign, w.journal.key)
    config = json.loads(w.registry_config.read_bytes())
    config["registry_id"] = secrets.token_hex(16)
    w.registry_config.write_bytes(canonical(config))
    with pytest.raises((ProtectionError, work.GateBlocked)):
        work.Work(w.ctx, ACTOR)


def test_renderer_all_types_and_report_offsets():
    from ohpipe.domain.transcript import TranscriptRevision, Segment
    from ohpipe.domain import stable_pseudonymisation as stable
    from ohpipe.project import Profile
    from .test_spur_p4a import PROFILE

    source = TranscriptRevision.from_segments(
        [
            Segment(
                index=0,
                start_ms=1200,
                end_ms=2500,
                speaker="S",
                language="deu",
                text="Änne Uni Amt Paris 2026 a@b X9",
            )
        ],
        projection_version="seg-join-lf.v1",
        profile_id="nfc-strict-v1",
    )
    rules = {k: dict(v) for k, v in Profile.load(PROFILE).pseudonymisation_rules}
    fields = [
        ("Änne", "PERSON"),
        ("Uni", "ORGANISATION"),
        ("Amt", "INSTITUTION"),
        ("Paris", "LOCATION"),
        ("2026", "DATE"),
        ("a@b", "CONTACT"),
        ("X9", "IDENTIFIER"),
    ]
    capsule = dict(
        v=1,
        source=manual.source_contract(source),
        base=[],
        overlay=[],
        spans=[],
        groups={},
        context="",
    )
    for n, (word, typ) in enumerate(fields):
        start = source.text.index(word)
        span = manual.mark(source, 0, start, start + len(word), typ)
        capsule["spans"].append(span)
        mid = next(iter(manual.bound(source, [span]))).mention_id
        capsule["groups"][f"{n:032x}"] = dict(
            type=typ, scope=rules[typ].get("scope", "local"), mentions=[mid], state="RESOLVED"
        )
    capsule["base"] = deepcopy(capsule["spans"])
    reg = stable.empty("a" * 32, "b" * 32, "c" * 64)
    resolution = dict(
        v=1,
        registry_id="a" * 32,
        source=capsule["source"],
        mention_set_sha256=stable.mention_digest(source, capsule),
        assignments={},
    )
    for n, span in enumerate(manual.bound(source, capsule["spans"])):
        typ = span.entity_type.value
        eid = f"{n + 10:032x}"
        resolution["assignments"][span.mention_id] = dict(
            entity_id=eid, type=typ, action=rules[typ]["action"], intent="new"
        )
        reg["entities"][eid] = dict(
            type=typ,
            number=1 if rules[typ]["action"] == "pseudonym" else None,
            pseudonym=f"{typ}-001" if rules[typ]["action"] == "pseudonym" else None,
        )
        if rules[typ]["action"] == "pseudonym":
            reg["counters"][typ] = 2
    raw, entries, sums = stable.render(source, capsule, rules, resolution, reg)
    from ohpipe.domain.revision_serialization import verify_revision

    rev = verify_revision(raw, digest(raw))
    assert rev.text == "PERSON-001 ORGANISATION-001 INSTITUTION-001 ORT ZEITRAUM  "
    assert (
        rev.segments[0].speaker == source.segments[0].speaker and rev.segments[0].start_ms == 1200
    )
    assert len(entries) == 7 and sum(sums.values()) == 7
    for e in entries:
        result = rev.segments[e["cue"]].text[slice(*e["result"])]
        assert (result == "") == (e["action"] == "remove")
        assert not {"surface", "entity_id", "pseudonym"} & set(e)
    altered = deepcopy(rules)
    altered["PERSON"] = {"action": "keep"}
    mid = next(e["mention_id"] for e in entries if e["type"] == "PERSON")
    resolution["assignments"][mid]["action"] = "keep"
    capsule["groups"]["0" * 32]["scope"] = "local"
    raw, _, _ = stable.render(source, capsule, altered, resolution, reg)
    assert verify_revision(raw, digest(raw)).text.startswith("Änne ")


def test_stable_batch_merge_split_and_no_reuse(ready):
    from ohpipe.application.manual_work import Session

    w = ready
    cases = Session(w.ctx, "pseudonymisation.cases", ACTOR, resume=True)
    cases.add(0, 12, 24, "PERSON")
    for gid in cases.capsule["groups"]:
        cases.state(gid, "RESOLVED")
    cases.save()
    cases.publish(displayed=digest(canonical(cases.capsule)))
    r = resolved(w)
    ids = sorted(a["entity_id"] for a in r.resolution["assignments"].values())
    r.finalise()
    approve(w)
    store = RegistryStore(w.ws, w.journal.key)
    _, reg = work.current(w.ctx, store, list(w.journal))
    assert [reg["entities"][eid]["pseudonym"] for eid in ids] == ["PERSON-001", "PERSON-002"], (
        "P4C_ALLOCATION: batch not ordered by opaque ID"
    )
    original = deepcopy(reg["entities"])
    cases = Session(w.ctx, "pseudonymisation.cases", ACTOR, resume=True)
    cases.merge(list(cases.capsule["groups"]))
    cases.save()
    cases.publish(displayed=digest(canonical(cases.capsule)))
    r = work.Work(w.ctx, ACTOR)
    r.choose(next(iter(r.capsule["groups"])), ids[1])
    r.accept_resolution(digest(canonical(r.resolution)))
    r.finalise()
    approve(w)
    _, reg = work.current(w.ctx, store, list(w.journal))
    assert reg["entities"] == original and reg["counters"] == {"PERSON": 3}
    cases = Session(w.ctx, "pseudonymisation.cases", ACTOR, resume=True)
    gid = next(iter(cases.capsule["groups"]))
    mids = cases.capsule["groups"][gid]["mentions"]
    cases.split(gid, [[m] for m in mids])
    cases.save()
    cases.publish(displayed=digest(canonical(cases.capsule)))
    r = work.Work(w.ctx, ACTOR)
    for i, gid in enumerate(r.capsule["groups"]):
        r.choose(gid, ids[1] if i == 0 else None)
    r.accept_resolution(digest(canonical(r.resolution)))
    r.finalise()
    approve(w)
    _, reg = work.current(w.ctx, store, list(w.journal))
    assert all(reg["entities"][k] == v for k, v in original.items())
    assert reg["counters"] == {"PERSON": 4}


def test_stale_recovery_keeps_last_completed_registry(ready, monkeypatch):
    from dataclasses import replace

    w = ready
    resolved(w)
    store = RegistryStore(w.ws, w.journal.key)
    before = store.head()

    def interrupt(stage):
        if stage == "head":
            raise OSError("synthetic interrupted")

    with monkeypatch.context() as patch:
        patch.setattr(work, "hook", interrupt)
        with pytest.raises((OSError, ProtectionError)):
            work.Work(w.ctx, ACTOR).finalise()
    alternate = w.tmp / "policy.toml"
    alternate.write_text(w.profile.read_text().replace('value = "ORT"', 'value = "ORT-B"'))
    ctx = replace(w.ctx, profile_arg=str(alternate))
    with pytest.raises(work.GateError):
        work.recover(ctx, ACTOR)
    assert store.head() == before and FINAL not in w.view().have
    assert work.recover(ctx, ACTOR) == 0
    assert any(e.kind == "p4c.aborted" for e in w.journal)


def test_recovery_preserves_activation_across_unrelated_events(ready, monkeypatch):
    w = ready
    resolved(w)

    def interrupt(stage):
        if stage == "prepared":
            raise OSError("synthetic interrupted")

    with monkeypatch.context() as patch:
        patch.setattr(work, "hook", interrupt)
        with pytest.raises((OSError, ProtectionError)):
            work.Work(w.ctx, ACTOR).finalise()
    w.ok(
        0,
        "instance",
        "register",
        "SYNTHETIC-OTHER",
        "--source",
        "mensch",
        "--label",
        "synthetic",
        "--reference",
        "SYNTHETIC-P4C",
        "--confirm",
    )
    assert work.recover(w.ctx, ACTOR) == 1
    approve(w)
    assert GATE in w.view().have


@pytest.mark.parametrize("point", ["put", "fsync"])
def test_write_failures_and_no_allocation(ready, monkeypatch, point):
    w = ready
    resolved(w)
    s = work.Work(w.ctx, ACTOR)
    before = s.store.head(), w.journal.head()

    def fail(*args, **kwargs):
        raise OSError("synthetic write failure")

    with monkeypatch.context() as patch:
        patch.setattr(RegistryStore, "put", fail) if point == "put" else patch.setattr(
            os, "fsync", fail
        )
        with pytest.raises((OSError, ProtectionError)):
            s.finalise()
    assert (s.store.head(), w.journal.head()) == before
    work.Work(w.ctx, ACTOR).finalise()
    assert work.current(w.ctx, s.store, list(w.journal))[1]["counters"] == {"PERSON": 2}


@pytest.mark.parametrize("same_record", [False, True])
def test_two_process_registry_cas(ready, same_record):
    import select

    w = ready
    resolved(w)
    ctx2 = w.ctx if same_record else other_record(w)
    if not same_record:
        s = work.Work(ctx2, ACTOR)
        for gid in s.capsule["groups"]:
            s.choose(gid)
        s.accept_resolution(digest(canonical(s.resolution)))
    sessions = [work.Work(ctx, ACTOR) for ctx in (w.ctx, ctx2)]
    ready_r, ready_w = os.pipe()
    go_r, go_w = os.pipe()
    children = []
    for session in sessions:
        child = os.fork()
        if child == 0:
            os.close(ready_r)
            os.close(go_w)
            os.write(ready_w, b"R")
            os.read(go_r, 1)
            try:
                session.finalise()
            except (work.GateError, ProtectionError) as exc:
                os._exit(3 if not isinstance(exc, ProtectionError) or exc.code == 3 else 70)
            except BaseException:
                os._exit(71)
            os._exit(0)
        children.append(child)
    os.close(ready_w)
    os.close(go_r)
    try:
        for _ in children:
            assert select.select([ready_r], [], [], 10)[0]
            assert os.read(ready_r, 1) == b"R"
        os.write(go_w, b"GG")
        results = [os.waitpid(pid, 0)[1] >> 8 for pid in children]
        assert 0 in results and set(results) <= {0, 3}, (
            "P4C_CAS: lost update or invalid retry outcome"
        )
    finally:
        for fd in (ready_r, go_w):
            os.close(fd)
    for ctx in (w.ctx, ctx2):
        work.Work(ctx, ACTOR).finalise()
    store = RegistryStore(w.ws, w.journal.key)
    _, reg = work.current(w.ctx, store, list(w.journal))
    expected = 1 if same_record else 2
    assert len(reg["entities"]) == expected and reg["counters"] == {"PERSON": expected + 1}
    assert len({e["pseudonym"] for e in reg["entities"].values()}) == expected


def test_wrong_displayed_text_is_not_a_gate(ready):
    w = ready
    resolved(w).finalise()
    s = work.Work(w.ctx, ACTOR)
    inputs, _, _ = s.review_material()
    with pytest.raises(ProtectionError):
        s.accept_text("0" * 64, inputs)
    assert GATE not in w.view().have, "P4C_DISPLAY: full text was not actually bound"


def test_consumer_does_not_publish_after_registry_change(ready):
    from dataclasses import replace
    from ohpipe.application.l1_suggest import run_l1_suggest
    from .test_spur_p2 import Recorder

    w = ready
    resolved(w).finalise()
    approve(w)
    ctx2 = other_record(w)
    b = work.Work(ctx2, ACTOR)
    for gid in b.capsule["groups"]:
        b.choose(gid)
    b.accept_resolution(digest(canonical(b.resolution)))

    class Changing(Recorder):
        def run(self, *args, **kwargs):
            result = super().run(*args, **kwargs)
            work.Work(ctx2, ACTOR).finalise()
            return result

    before = sum(
        e.kind == "artifact.produced" and e.payload["artifact"] == "l1.suggestions"
        for e in w.journal
    )
    with pytest.raises(work.GateError):
        run_l1_suggest(replace(w.ctx, confirm=True), w.view(), adapter=Changing())
    assert (
        sum(
            e.kind == "artifact.produced" and e.payload["artifact"] == "l1.suggestions"
            for e in w.journal
        )
        == before
    )


def test_public_inventory_and_negative_leaks(ready):
    w = ready
    originals = {p: p.read_bytes() for p in w.ws.root.rglob("*") if p.is_file()}
    resolved(w).finalise()
    approve(w)
    s = work.Work(w.ctx, ACTOR)
    p = work.published(w.ctx, list(w.journal), "finalise")
    res = work.published(w.ctx, list(w.journal), "resolve")
    forbidden = [
        s.store.key,
        s.store.candidate_key,
        s.store.open(p["refs"][FINAL], RECORD),
        s.store.open(p["refs"][REPORT], RECORD),
        s.store.open(res["refs"][RESOLUTION], RECORD),
    ]
    _, reg = work.current(w.ctx, s.store, list(w.journal))
    forbidden.extend(e.encode() for e in reg["entities"])
    forbidden.extend(t.encode() for t in reg["aliases"])

    def leaks():
        return [
            str(f.relative_to(w.ws.root))
            for f in w.ws.root.rglob("*")
            if f.is_file()
            and (f not in originals or f.read_bytes() != originals[f])
            and any(secret in f.read_bytes() for secret in forbidden)
        ]

    assert not leaks(), "P4C_LEAK: protected material in public tree"
    injected = w.ws.objects / "synthetic-negative-control"
    for secret in forbidden:
        injected.write_bytes(secret)
        injected.chmod(0o600)
        assert leaks(), "P4C_LEAK: oracle missed injected protected bytes"
        injected.unlink()
    assert not leaks()


@pytest.mark.parametrize("omit_location", [False, True])
def test_cli_gold_all_types_to_coverage(ready, omit_location):
    from ohpipe.domain.language_assignment import build_srt_draft

    w = ready
    payload = "Änne Uni Amt Paris 2026 a@b X9"
    raw = f"1\n00:00:01,200 --> 00:00:02,500\nS: {payload}\n".encode()
    source = w.tmp / "synthetic.srt"
    mapping = w.tmp / "synthetic.tsv"
    source.write_bytes(raw)
    draft = build_srt_draft(raw)
    mapping.write_text(
        "index\tsegment_sha256\tlanguage\n"
        + "".join(f"{n}\t{s.sha256}\tdeu\n" for n, s in enumerate(draft.segments))
    )
    ctx = other_record(w, mark=False)
    fields = [
        ("Änne", "PERSON"),
        ("Uni", "ORGANISATION"),
        ("Amt", "INSTITUTION"),
        ("Paris", "LOCATION"),
        ("2026", "DATE"),
        ("a@b", "CONTACT"),
        ("X9", "IDENTIFIER"),
    ]
    marked = [(word, typ) for word, typ in fields if not (omit_location and typ == "LOCATION")]
    answer = (
        "neu\n"
        + "".join(
            f"markieren 0 {payload.index(word)} {payload.index(word) + len(word)} {typ}\n"
            for word, typ in marked
        )
        + "bestätigen\nBESTÄTIGEN\n"
    )
    r = w.run(
        "pii", "mark", ctx.record_id, "--actor", ACTOR, tty=True, as_json=False, answer=answer
    )
    assert r.code == 0, (r.out, r.err)
    w.ok(0, "pseudonymise", ctx.record_id)
    from ohpipe.application.manual_work import Session

    cases = Session(ctx, "pseudonymisation.cases", ACTOR)
    answer = (
        "neu\n"
        + "".join("auflösen " + gid + "\n" for gid in cases.capsule["groups"])
        + "bestätigen\nBESTÄTIGEN\n"
    )
    r = w.run(
        "pseudonymisation",
        "cases",
        ctx.record_id,
        "--actor",
        ACTOR,
        tty=True,
        as_json=False,
        answer=answer,
    )
    assert r.code == 0, (r.out, r.err)
    r = w.run(
        "pseudonymisation",
        "resolve",
        ctx.record_id,
        "--actor",
        ACTOR,
        tty=True,
        as_json=False,
        answer="neu\n" * len(marked) + "BESTÄTIGEN\n",
    )
    assert r.code == 0, (r.out, r.err)
    w.ok(0, "pseudonymise", "finalise", ctx.record_id)
    r = w.run(
        "pseudonymisation",
        "review",
        ctx.record_id,
        "--actor",
        ACTOR,
        tty=True,
        as_json=False,
        answer="BESTÄTIGEN\n",
    )
    assert r.code == 0, (r.out, r.err)
    consume(w, ctx)
    bound = read_confirmed_text(ctx, work.view(ctx, list(w.journal)), "l1.suggest")
    _, _, report = work.Work(ctx, ACTOR).review_material()
    assert {e["type"] for e in report["entries"]} == {typ for _, typ in marked}
    assert len(report["entries"]) == len(marked)
    # Dieselbe Goldprüfung bewertet echte CLI-Ausgaben mit/ohne LOCATION-Markierung.
    # Ein menschlich übersehener Fall wird nicht durch behauptete Erkennung ersetzt.
    gold_complete = (
        bound.revision.text == "PERSON-001 ORGANISATION-001 INSTITUTION-001 ORT ZEITRAUM  "
        and {e["type"] for e in report["entries"]} == {typ for _, typ in fields}
    )
    assert gold_complete is (not omit_location), "P4C_GOLD: missed omission or wrong replacement"
    assert ("Paris" in bound.revision.text) is omit_location


@pytest.mark.parametrize("missing", ["selection", "candidate_key"])
def test_p4b_work_does_not_require_registry_configuration(ready, monkeypatch, missing):
    from ohpipe.application.manual_work import Session

    w = ready
    resolved(w).finalise()
    if missing == "selection":
        monkeypatch.delenv("OHPIPE_REGISTRY_CONFIG")
    else:
        config = json.loads(w.registry_config.read_bytes())
        config["candidate_key_file"] = ""
        w.registry_config.write_bytes(canonical(config))
    session = Session(w.ctx, "pseudonymisation.cases", ACTOR, resume=True)
    session.save()
    assert w.run("pseudonymise", "finalise", RECORD).code == 2


@pytest.mark.parametrize("ready", [False], indirect=True)
def test_next_command_initialises_missing_registry(ready):
    result = ready.run("continue", RECORD)
    report = json.loads(result.out)
    assert result.code == 3
    assert "pseudonymisation registry init" in (report.get("next") or report.get("next_command"))


def test_policy_scope_is_register_domain(ready):
    from dataclasses import replace
    from ohpipe.protected_store import ProtectionConfig

    w = ready
    alternate = w.tmp / "other-scope.toml"
    alternate.write_text(
        w.profile.read_text().replace('scope = "spur-p-synthetic"', 'scope = "foreign-scope"')
    )
    session = work.Work(w.ctx, ACTOR)
    session.ctx = replace(w.ctx, profile_arg=str(alternate))
    with pytest.raises(ProtectionConfig):
        _ = session.rules


def test_second_workspace_same_policy_is_independent(ready, monkeypatch):
    from .test_spur_p4b import world as create_world

    w = ready
    resolved(w).finalise()
    approve(w)
    s = RegistryStore(w.ws, w.journal.key)
    _, first = work.current(w.ctx, s, list(w.journal))
    root = w.tmp / "second-workspace"
    root.mkdir(mode=0o700)
    with monkeypatch.context() as patch:
        other = create_world.__wrapped__(root, patch)
        configured(other, patch)
        resolved(other).finalise()
        approve(other)
        _, second = work.current(
            other.ctx, RegistryStore(other.ws, other.journal.key), list(other.journal)
        )
        assert first["registry_id"] != second["registry_id"]
        assert not set(first["entities"]) & set(second["entities"])
        assert {e["pseudonym"] for e in first["entities"].values()} == {
            e["pseudonym"] for e in second["entities"].values()
        }
    assert work.current(w.ctx, s, list(w.journal))[1] == first


def pending_operation(w, monkeypatch, phase="review"):
    if phase != "resolve":
        resolved(w)
    if phase == "review":
        work.Work(w.ctx, ACTOR).finalise()
    session = work.Work(w.ctx, ACTOR)
    if phase == "resolve":
        for gid in session.capsule["groups"]:
            session.choose(gid)

        def perform():
            return session.accept_resolution(digest(canonical(session.resolution)))
    elif phase == "finalise":
        perform = session.finalise
    else:
        inputs, raw, _ = session.review_material()
        displayed = digest(
            canonical({"final": digest(raw), "report": inputs[REPORT][0], "basis": inputs})
        )

        def perform():
            return session.accept_text(displayed, inputs)

    def interrupt(stage):
        if stage == "prepared":
            raise OSError("synthetic interrupted operation")

    with monkeypatch.context() as patch:
        patch.setattr(work, "hook", interrupt)
        with pytest.raises((OSError, ProtectionError)):
            perform()
    return session


@pytest.mark.parametrize("phase", ["resolve", "finalise", "review"])
@pytest.mark.parametrize("point", ["recovery_validated", "recovery_head"])
def test_recovery_policy_at_last_boundary(ready, monkeypatch, phase, point):
    from dataclasses import replace

    w = ready
    original = w.profile.read_text()
    policy = w.tmp / "late-policy.toml"
    policy.write_text(original)
    w.ctx = replace(w.ctx, profile_arg=str(policy))
    pending_operation(w, monkeypatch, phase)
    before = sum(e.kind == "p4c.completed" for e in w.journal)
    old_head = RegistryStore(w.ws, w.journal.key).head()
    changed = []

    def change(stage):
        if stage == point:
            policy.write_text(original.replace('value = "ORT"', 'value = "ORT-LATE"'))
            changed.append(True)

    with monkeypatch.context() as patch:
        patch.setattr(work, "hook", change)
        with pytest.raises(work.GateError, match="Policybindung"):
            work.recover(w.ctx, ACTOR)
    assert changed
    assert sum(e.kind == "p4c.completed" for e in w.journal) == before, (
        "R-P4C-01: late stale completion"
    )
    assert GATE not in w.view().have
    assert w.view().sources["pseudonymisation.policy"][0] == digest(
        work.manual_work.policy(w.ctx)[1]
    )
    with pytest.raises(work.GateError, match="abgebrochen"):
        work.recover(w.ctx, ACTOR)
    assert work.recover(w.ctx, ACTOR) == 0
    assert RegistryStore(w.ws, w.journal.key).head() == old_head


@pytest.mark.parametrize("damage", ["registry_key", "candidate_config", "source"])
def test_recovery_rechecks_storage_after_validation(ready, monkeypatch, damage):
    w = ready
    pending_operation(w, monkeypatch)
    before = sum(e.kind == "p4c.completed" for e in w.journal)

    def damage_after(stage):
        if stage != "recovery_validated":
            return
        if damage == "registry_key":
            config = json.loads(w.registry_config.read_bytes())
            Path(config["key_file"]).write_bytes(secrets.token_bytes(32))
        elif damage == "candidate_config":
            config = json.loads(w.registry_config.read_bytes())
            config["candidate_key_id"] = secrets.token_hex(16)
            w.registry_config.write_bytes(canonical(config))
        else:
            (w.ws.objects / w.view().facts["transcript.revision"].sha256).write_bytes(
                b"synthetic damage"
            )

    with monkeypatch.context() as patch:
        patch.setattr(work, "hook", damage_after)
        result = w.run("pseudonymisation", "recovery", RECORD, "--actor", ACTOR)
    assert result.code == 1, "R-P4C-01: integrity damage became a completion"
    assert sum(e.kind == "p4c.completed" for e in w.journal) == before
    assert GATE not in w.view().have


@pytest.mark.parametrize("ready", [False], indirect=True)
@pytest.mark.parametrize("signal_name", ["SIGTERM", "SIGKILL"])
@pytest.mark.parametrize(
    "point", ["init_cipher_fsync", "init_prepared", "init_head", "init_completed"]
)
def test_initialisation_process_recovery(ready, monkeypatch, signal_name, point):
    import select
    import signal

    w = ready
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)

        def barrier(stage):
            if stage == point:
                os.write(write_fd, b"R")
                signal.pause()

        monkeypatch.setattr(work, "hook", barrier)
        try:
            work.initialise(w.ctx)
        except BaseException:
            os._exit(70)
        os._exit(71)
    os.close(write_fd)
    try:
        reached = bool(select.select([read_fd], [], [], 10)[0]) and os.read(read_fd, 1) == b"R"
        os.kill(child, getattr(signal, signal_name))
        assert reached, "R-P4C-02: init barrier not reached"
    finally:
        os.close(read_fd)
        os.waitpid(child, 0)
    prepared = [e.payload for e in w.journal if e.kind == "p4c.init.prepared"]
    assert (REGISTRY in w.view().sources) == (point == "init_completed"), (
        "R-P4C-02: premature init activation"
    )
    store = RegistryStore(w.ws, w.journal.key)
    inventory = {p: p.read_bytes() for p in (store.root / "objects").iterdir() if p.is_file()}
    result = w.run("pseudonymisation", "registry", "init")
    assert result.code == 0, "R-P4C-02: explicit init cannot recover its preparation"
    if prepared:
        assert store.head() == prepared[0]["ref"]
    assert all(p.read_bytes() == raw for p, raw in inventory.items())
    assert len([e for e in w.journal if e.kind == "p4c.initialised"]) == 1
    assert len([e for e in w.journal if e.kind == "p4c.init.prepared"]) == 1
    before = store.head(), w.journal.head()
    w.ok(0, "pseudonymisation", "registry", "init")
    assert (store.head(), w.journal.head()) == before
    assert work.current(w.ctx, store, list(w.journal))[1]["counters"] == {}


@pytest.mark.parametrize("ready", [False], indirect=True)
@pytest.mark.parametrize(
    "damage", ["unbound_head", "different_head", "missing_cipher", "wrong_key"]
)
def test_initialisation_never_adopts_unproven_state(ready, monkeypatch, damage):
    from ohpipe.domain import stable_pseudonymisation as stable

    w = ready
    store = RegistryStore(w.ws, w.journal.key)
    if damage != "unbound_head":

        def interrupt(stage):
            if stage == "init_prepared":
                raise OSError("synthetic init interruption")

        with monkeypatch.context() as patch:
            patch.setattr(work, "hook", interrupt)
            with pytest.raises((OSError, ProtectionError)):
                work.initialise(w.ctx)
    if damage in ("unbound_head", "different_head"):
        raw = canonical(
            stable.empty(
                store.config["registry_id"],
                store.config["candidate_key_id"],
                stable.candidate_check(store.candidate_key, store.config["registry_id"]),
            )
        )
        ref, blob = store.seal(raw, REGISTRY, None, secrets.token_hex(16))
        store.put(ref, blob)
        store.set_head(ref)
    elif damage == "missing_cipher":
        p = next(e.payload for e in w.journal if e.kind == "p4c.init.prepared")
        (store.root / "objects" / p["ref"]["cipher_sha256"]).unlink()
    else:
        Path(store.config["key_file"]).write_bytes(secrets.token_bytes(32))
    before = w.journal.head(), store.head()
    result = w.run("pseudonymisation", "registry", "init")
    assert result.code == 1, "R-P4C-02: unproven init state was adopted"
    assert (w.journal.head(), store.head()) == before
    assert REGISTRY not in w.view().sources


@pytest.mark.parametrize("ready", [False], indirect=True)
@pytest.mark.parametrize("point", ["put", "head"])
def test_initialisation_write_error_is_retryable(ready, monkeypatch, point):
    w = ready

    def fail(*args, **kwargs):
        raise OSError("synthetic init write failure")

    with monkeypatch.context() as patch:
        patch.setattr(RegistryStore, "put" if point == "put" else "set_head", fail)
        with pytest.raises((OSError, ProtectionError)):
            work.initialise(w.ctx)
    w.ok(0, "pseudonymisation", "registry", "init")
    assert sum(e.kind == "p4c.initialised" for e in w.journal) == 1


@pytest.mark.parametrize("ready", [False], indirect=True)
def test_initialisation_completion_bound_and_legacy_readable(ready):
    from types import SimpleNamespace

    w = ready
    work.initialise(w.ctx)
    events = list(w.journal)
    legacy = [e for e in events if e.kind != "p4c.init.prepared"]
    assert (
        work.current(w.ctx, RegistryStore(w.ws, w.journal.key), legacy)[0]
        == RegistryStore(w.ws, w.journal.key).head()
    )
    last = events[-1]
    p = deepcopy(last.payload)
    p["at"] = "2026-09-11T00:00:00+00:00"
    changed = events[:-1] + [
        SimpleNamespace(kind=last.kind, payload=p, record_id=None, at=last.at, digest=last.digest)
    ]
    with pytest.raises(ProtectionError):
        work.expanded(w.ctx, changed)


# R-P4C-01/02: Reviewerfälle und unveränderte Kontrollen dauerhaft erhalten.
@pytest.mark.parametrize("change_policy", [False, True])
def test_recovery_rechecks_policy_before_final_text_accept(ready, monkeypatch, change_policy):
    from dataclasses import replace

    w = ready
    alternate = w.tmp / "review-policy.toml"
    original = w.profile.read_text()
    alternate.write_text(original)
    w.profile = alternate
    w.ctx = replace(w.ctx, profile_arg=str(alternate))
    resolved(w).finalise()
    session = work.Work(w.ctx, ACTOR)
    inputs, raw, _ = session.review_material()
    displayed = digest(
        canonical({"final": digest(raw), "report": inputs[REPORT][0], "basis": inputs})
    )

    def interrupt(stage):
        if stage == "prepared":
            raise OSError("synthetic interrupted review")

    with monkeypatch.context() as m:
        m.setattr(work, "hook", interrupt)
        with pytest.raises((OSError, work.ProtectionError)):
            session.accept_text(displayed, inputs)
    assert GATE not in w.view().have
    prior = sum(e.kind == "p4c.completed" for e in w.journal)
    opened = RegistryStore.open
    changed = []

    def concurrent_policy(self, ref, record):
        result = opened(self, ref, record)
        if change_policy and not changed:
            alternate.write_text(original.replace('value = "ORT"', 'value = "ORT-REVIEW-CHANGED"'))
            changed.append(True)
        return result

    with monkeypatch.context() as m:
        m.setattr(RegistryStore, "open", concurrent_policy)
        from contextlib import suppress

        with suppress(work.GateError, work.ProtectionError, ValueError):
            work.recover(w.ctx, ACTOR)
    if change_policy:
        assert changed
        assert sum(e.kind == "p4c.completed" for e in w.journal) == prior, (
            "Stale recovery ACCEPT",
            "gate_ready",
            GATE in w.view().have,
        )
        assert GATE not in w.view().have
    else:
        assert sum(e.kind == "p4c.completed" for e in w.journal) == prior + 1
        assert GATE in w.view().have


@pytest.mark.parametrize("ready", [False], indirect=True)
def test_registry_init_recovers_after_head_before_journal(ready, monkeypatch):
    w = ready
    original = RegistryStore.set_head

    def interrupted(self, ref):
        original(self, ref)
        raise OSError("synthetic interruption after durable init head")

    with monkeypatch.context() as m:
        m.setattr(RegistryStore, "set_head", interrupted)
        with pytest.raises((OSError, work.ProtectionError)):
            work.initialise(w.ctx)
    assert not any(e.kind == "p4c.initialised" for e in w.journal)
    # Explicit retry must recover its own interrupted init, without deleting head or ciphertext.
    result = w.run("pseudonymisation", "registry", "init")
    assert result.code == 0, "Interrupted first init cannot be completed by explicit retry"


@pytest.mark.parametrize("ready", [False], indirect=True)
def test_normal_registry_init_is_idempotent(ready):
    w = ready
    w.ok(0, "pseudonymisation", "registry", "init")
    before = w.journal.head(), RegistryStore(w.ws, w.journal.key).head()
    w.ok(0, "pseudonymisation", "registry", "init")
    assert before == (w.journal.head(), RegistryStore(w.ws, w.journal.key).head())
