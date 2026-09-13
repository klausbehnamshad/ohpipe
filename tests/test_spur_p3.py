"""P3-Abnahmematrix: Quellenaktualität und vollständige Wiederherstellung."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from ohpipe.application.decision_actions import write_action
from ohpipe.application.gate import GateError
from ohpipe.application.input_sources import observe
from ohpipe.application.replay import replay
from ohpipe.domain.decision import Verdict
from ohpipe.domain.hashing import sha256_bytes
from ohpipe.domain.state import DerivationState
from ohpipe.domain.step import ArtifactContract, Kind, Step, StepGraph
from ohpipe.policies.authority import Authority
from tests.test_spur_p1 import ACTOR, RECORD, World


def h(label):
    return sha256_bytes(label.encode())


class Chain:
    """Kleiner deklarierter Graph: beliebige Namen, um Hashheuristik auszuschließen."""

    def __init__(self):
        self.events = []
        ingress = ArtifactContract(
            binding_required=False, provenance_required=False, decision_required=False
        )
        derived = replace(ingress, provenance_required=True)
        self.graph = StepGraph(
            (
                Step("input", Kind.DETERMINISTIC, produces=("source",)),
                Step("middle", Kind.DETERMINISTIC, requires=("source",), produces=("middle",)),
                Step("end", Kind.DETERMINISTIC, requires=("middle",), produces=("end",)),
                Step("separate", Kind.DETERMINISTIC, produces=("independent",)),
            ),
            contracts={
                "source": ingress,
                "middle": derived,
                "end": derived,
                "independent": ingress,
            },
        )
        self.produce("source", "X")
        self.derive("middle", "same-middle", {"source": h("X")})
        self.derive("end", "same-end", {"middle": h("same-middle")})
        self.produce("independent", "separate")
        assert self.view().have == {"source", "middle", "end", "independent"}

    def add(self, kind, payload):
        self.events.append(
            SimpleNamespace(
                kind=kind,
                payload=payload,
                record_id=RECORD,
                seq=len(self.events) + 1,
                at="2026-09-10T10:00:00+00:00",
            )
        )

    def produce(self, name, value):
        self.add("artifact.produced", {"artifact": name, "sha256": h(value)})

    def derive(self, name, value, inputs):
        self.produce(name, value)
        self.add(
            "receipt.recorded",
            {
                "artifact": name,
                "output_sha256": h(value),
                "inputs": inputs,
                "code_version": "P3-synthetic/1",
            },
        )

    def view(self):
        return replay(self.events, graph=self.graph, authority=Authority.AUTHENTICATED)[RECORD]


def test_direct_input_comparison():
    c = Chain()
    c.produce("source", "Y")
    assert "middle" not in c.view().have, "P3_DIRECT"
    assert c.view().facts["middle"].freshness is DerivationState.STALE


def test_transitive_equal_bytes_and_independent_branch():
    c = Chain()
    c.produce("source", "Y")
    view = c.view()
    assert view.facts["middle"].sha256 == h("same-middle")
    assert "end" not in view.have, "P3_TRANSITIVE"
    assert "independent" in view.have
    assert "source" in view.facts["end"].freshness_reason


@pytest.mark.parametrize("change", ["missing-role", "unknown-role", "wrong-hash", "missing-source"])
def test_receipt_roles_fail_closed(change):
    c = Chain()
    inputs = {"source": h("X")}
    if change == "missing-role":
        inputs = {"alien": h("X")}
    if change == "unknown-role":
        inputs["alien"] = h("private-value-never-log")
    if change == "wrong-hash":
        inputs["source"] = h("Y")
    if change == "missing-source":
        c.events = [e for e in c.events if e.payload.get("artifact") != "source"]
    c.derive("middle", "new-middle", inputs)
    assert "middle" not in c.view().have, "P3_EXTRA"
    assert "private-value-never-log" not in str(c.view().to_json())


def test_partial_then_complete_equal_byte_regeneration():
    c = Chain()
    c.produce("source", "Y")
    c.derive("middle", "same-middle", {"source": h("Y")})
    assert "middle" in c.view().have
    assert "end" not in c.view().have
    c.derive("end", "same-end", {"middle": h("same-middle")})
    assert c.view().have == {"source", "middle", "end", "independent"}


def test_returning_to_old_bytes_does_not_reactivate_old_chain():
    c = Chain()
    c.produce("source", "Y")
    c.produce("source", "X")
    assert "middle" not in c.view().have
    assert "end" not in c.view().have


@pytest.fixture
def released(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    world.preview()
    world.ok(0, "release", "approve", RECORD, "--actor", ACTOR, "--confirm")
    world.ok(0, "export", RECORD, "--output", str(tmp_path / "initial.json"), "--confirm")
    assert "export.bundle" in world.view().have
    return world


def test_text_change_blocks_whole_chain_and_full_repair(released):
    world = released
    world.revision("Y")
    view = world.view()
    for name in (
        "l1.adjudicated",
        "metadata.draft",
        "metadata.confirmed",
        "abstract.draft",
        "abstract.confirmed",
        "release.preview",
        "release.approved",
        "export.bundle",
    ):
        assert name not in view.have, name
    denied = world.run("export", RECORD, "--output", str(world.tmp / "denied.json"), "--confirm")
    assert denied.code != 0 and not (world.tmp / "denied.json").exists()
    assert world.run("release", "approve", RECORD, "--actor", ACTOR, "--confirm").code != 0
    world.ok(0, "transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")
    assert "l1.adjudicated" not in world.view().have
    world.preview()
    world.ok(0, "release", "approve", RECORD, "--actor", ACTOR, "--confirm")
    world.ok(0, "export", RECORD, "--output", str(world.tmp / "repaired.json"), "--confirm")
    assert "export.bundle" in world.view().have


def test_observed_codebook_blocks_l1_and_descendants(released):
    world = released
    observe(world.ws, world.journal, RECORD, "l1.codebook", b"synthetic-codebook-v2")
    for name in (
        "l1.suggestions",
        "l1.coverage",
        "l1.adjudicated",
        "release.approved",
        "export.bundle",
    ):
        assert name not in world.view().have


def test_metadata_ingestion_and_unobserved_o2_boundary(released):
    world = released
    before = world.view().have
    path = world.ws.governance / "metadata" / f"{RECORD}.toml"
    path.write_text(path.read_text().replace("SYNTHETIC-TITLE-P0", "SYNTHETIC-TITLE-P3"))
    assert world.view().have == before  # O-2: kein Journalereignis durch bloße Dateiänderung.
    world.ok(0, "sources", "refresh", RECORD)
    assert "l1.adjudicated" in world.view().have
    assert "metadata.draft" not in world.view().have
    assert "release.approved" not in world.view().have
    assert "metadata.input" in world.view().facts["metadata.draft"].freshness_reason


def test_historical_predecessor_is_not_current_self_dependency(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    old = world.view().facts["transcript.revision"].sha256
    world.revision("Y")
    receipt = next(
        e
        for e in reversed(list(world.journal))
        if e.kind == "receipt.recorded" and e.payload.get("artifact") == "transcript.revision"
    )
    payload = {**receipt.payload, "inputs": {**receipt.payload["inputs"], "previous": old}}
    world.journal.append("receipt.recorded", payload, record_id=RECORD)
    assert "transcript.revision" in world.view().have
    payload["inputs"]["previous"] = h("never-produced")
    world.journal.append("receipt.recorded", payload, record_id=RECORD)
    assert "transcript.revision" not in world.view().have


def test_withdraw_survives_new_bytes_and_requires_authorised_undo(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    write_action(
        world.ws,
        world.journal,
        RECORD,
        "transcript.confirmed",
        Verdict.WITHDRAW,
        ACTOR,
        "SYNTHETIC-WITHDRAW",
    )
    withdrawal = world.view().facts["transcript.confirmed"].withdrawal
    world.revision("Y")
    # Selbst die reguläre erneute Bestätigung kann den Widerruf nicht heilen.
    world.run("transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")
    assert "transcript.confirmed" not in world.view().have
    with pytest.raises((GateError, ValueError)):
        write_action(
            world.ws,
            world.journal,
            RECORD,
            "transcript.confirmed",
            Verdict.UNDO,
            ACTOR,
            "SYNTHETIC-UNDO",
            undo_of=h("wrong"),
        )
    with pytest.raises((GateError, ValueError)):
        write_action(
            world.ws,
            world.journal,
            RECORD,
            "transcript.confirmed",
            Verdict.UNDO,
            "UNKNOWN-ACTOR",
            "SYNTHETIC-UNDO",
            undo_of=withdrawal,
        )
    world.ok(
        0,
        "decision",
        "undo",
        RECORD,
        "transcript.confirmed",
        "--actor",
        ACTOR,
        "--reference",
        "SYNTHETIC-UNDO",
        "--undo-of",
        withdrawal,
        "--confirm",
    )
    assert not world.view().facts["transcript.confirmed"].withdrawal
    assert "transcript.confirmed" not in world.view().have  # UNDO ist keine Annahme.
    world.ok(0, "transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")
    assert "transcript.confirmed" in world.view().have


def test_reject_is_byte_bound():
    c = Chain()
    c.add(
        "decision.recorded",
        {
            "artifact": "source",
            "subject_sha256": h("X"),
            "verdict": "REJECT",
            "reference": "SYNTHETIC-REJECT",
            "actor": ACTOR,
            "at": "2026-09-10T10:00:00+00:00",
        },
    )
    assert "source" not in c.view().have
    c.produce("source", "Y")
    assert c.view().facts["source"].state().decision_state.value == "undecided"


def test_positive_anchor_does_not_rebase_stale_derivation():
    c = Chain()
    c.produce("source", "Y")
    c.add("anchor.checked", {"artifact": "middle", "outcome": "exact"})
    assert "middle" not in c.view().have


def test_real_codebook_refresh_invalidates_and_regeneration_restores(tmp_path, monkeypatch):
    import tests.test_spur_p1 as p1
    from ohpipe.project import Profile
    from tests.test_codebook import _write_book
    from tests.test_l1_suggest import _BlockFixture, _coded_response

    world = World(tmp_path, monkeypatch)
    book = _write_book(tmp_path / "book.toml")
    world.profile.write_text(world.profile.read_text() + '\ncodebook = "book.toml"\n')
    world.ws = replace(world.ws, profile=Profile.load(world.profile))
    monkeypatch.setattr(p1, "FixtureAdapter", lambda *a: _BlockFixture(_coded_response))
    world.preview()
    world.ok(0, "release", "approve", RECORD, "--actor", ACTOR, "--confirm")
    source_before = world.view().sources["l1.codebook"][0]
    book.write_text(book.read_text().replace('version = "V0"', 'version = "V1"'))
    world.ok(0, "sources", "refresh", RECORD)
    assert world.view().sources["l1.codebook"][0] != source_before
    assert "l1.suggestions" not in world.view().have
    assert "release.approved" not in world.view().have
    world.preview()
    world.ok(0, "release", "approve", RECORD, "--actor", ACTOR, "--confirm")
    assert "release.approved" in world.view().have
    before = world.state()
    world.ok(0, "sources", "refresh", RECORD)
    assert world.state() == before


def test_reingesting_historical_bytes_activates_them_without_old_approval(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    x = world.view().facts["transcript.revision"].sha256
    world.revision("Y")
    world.revision("X")
    assert world.view().facts["transcript.revision"].sha256 == x
    assert "transcript.revision" in world.view().have
    assert "transcript.confirmed" not in world.view().have
    world.ok(0, "transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")
    assert "transcript.confirmed" in world.view().have


def test_raw_srt_ingestion_invalidates_before_language_preparation(released):
    world = released
    srt = world.tmp / "new-source.srt"
    srt.write_text("1\n00:00:00,000 --> 00:00:02,000\nSynthetische neue Quelle.\n")
    world.ok(3, "ingest", str(srt), "--record", RECORD)
    view = world.view()
    assert "transcript.revision" not in view.have
    assert "release.approved" not in view.have
    assert "srt" in view.facts["release.approved"].freshness_reason
    result = world.run("export", RECORD, "--output", str(world.tmp / "blocked.json"), "--confirm")
    assert result.code == 3
    assert not (world.tmp / "blocked.json").exists()


def test_unknown_ingress_receipt_cannot_use_only_historical_predecessor(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    old = world.view().facts["transcript.revision"].sha256
    world.revision("Y")
    receipt = next(
        e
        for e in reversed(list(world.journal))
        if e.kind == "receipt.recorded" and e.payload.get("artifact") == "transcript.revision"
    )
    world.journal.append(
        "receipt.recorded",
        {
            "artifact": "transcript.revision",
            "output_sha256": receipt.payload["output_sha256"],
            "code_version": "P3-synthetic/1",
            "kind": "unknown.ingress.v1",
            "inputs": {"previous": old},
        },
        record_id=RECORD,
    )
    view = world.view()
    assert view.facts["transcript.revision"].freshness is DerivationState.UNVERIFIABLE
    assert "transcript.revision" not in view.have
    assert "transcript.confirmed" not in view.have


def test_missing_observed_store_source_blocks_direct_export(released):
    world = released
    sha = world.view().sources["metadata.input"][0]
    (world.ws.objects / sha).unlink()
    status = world.ok(1, "status")
    assert json.loads(status.out)["next"].endswith(" doctor")
    result = world.run("export", RECORD, "--output", str(world.tmp / "missing.json"), "--confirm")
    assert result.code == 1 and not (world.tmp / "missing.json").exists()


def test_status_offers_a_runnable_text_confirmation_repair(released):
    import json
    import shlex

    world = released
    world.revision("Y")
    status = json.loads(world.run("status").out)
    command = shlex.split(status["next"])
    assert command[-3:] == ["transcript", "confirm", RECORD]
    result = world.run(*command[command.index("transcript") :], "--actor", ACTOR, "--confirm")
    assert result.code == 0
    assert "release.approved" not in world.view().have


@pytest.mark.parametrize("change", ["wrong-hash", "unknown-role", "missing-binding"])
def test_human_decision_inputs_are_checked_independently_of_receipt(released, change):
    world = released
    before = world.view().facts["release.approved"]
    payload = dict(
        next(
            e.payload
            for e in reversed(list(world.journal))
            if e.kind == "decision.recorded" and e.payload.get("artifact") == "release.approved"
        )
    )
    if change == "wrong-hash":
        payload["input_refs"] = {"release.preview": h("wrong")}
    elif change == "unknown-role":
        payload["input_refs"] = {**payload["input_refs"], "unknown": h("never-log-values")}
    else:
        payload.pop("input_refs")
        payload.pop("input_refs_version")
    world.journal.append("decision.recorded", payload, record_id=RECORD)
    after = world.view().facts["release.approved"]
    assert before.sha256 == after.sha256
    assert before.receipt_inputs == after.receipt_inputs
    assert "release.approved" not in world.view().have
    assert "export.bundle" not in world.view().have


@pytest.mark.parametrize("role", ["l1.codebook", "metadata.input"])
def test_source_scope_matches_shared_book_and_record_metadata(tmp_path, role):
    from ohpipe.domain.step import build_graph
    from ohpipe.project import Profile
    from tests.test_forgery import wellformed_chain

    events = []
    graph = build_graph(Profile.load("src/ohpipe/profiles/sandbox/profile.toml"))

    def add(record, kind, payload):
        events.append(
            SimpleNamespace(
                record_id=record, kind=kind, payload=payload, at="2026-09-10T10:00:00+00:00"
            )
        )

    for record in ("A", "B"):
        add(record, "input.observed", {"role": role, "sha256": h("source-X")})
        for event in wellformed_chain(tmp_path / record):
            payload = dict(event["payload"])
            artifact = payload.get("artifact")
            consumer = "l1.suggestions" if role == "l1.codebook" else "metadata.draft"
            if event["kind"] == "receipt.recorded" and artifact == consumer:
                payload["inputs"] = {**payload["inputs"], role: h("source-X")}
            add(record, event["kind"], payload)
    # Derselbe Codebuchhash ist kein neuer Quellenstand: regulärer observe-Schreiber
    # dedupliziert ihn. Diese Probe bildet dessen tatsächlich geschriebene Ereignisse ab.
    if role == "l1.codebook":
        events = [e for e in events if not (e.kind == "input.observed" and e.record_id == "B")]
    views = replay(events, graph=graph, authority=Authority.AUTHENTICATED)
    assert all("export.bundle" in v.have for v in views.values())
    add("A", "input.observed", {"role": role, "sha256": h("source-Y")})
    views = replay(events, graph=graph, authority=Authority.AUTHENTICATED)
    assert "export.bundle" not in views["A"].have
    assert ("export.bundle" in views["B"].have) == (role == "metadata.input")
    assert all("transcript.revision" in v.have for v in views.values())


@pytest.mark.parametrize("field", ["profile_id", "graph_sha256"])
@pytest.mark.parametrize("artifact", ["release.approved", "metadata.confirmed"])
def test_foreign_decision_context_blocks_and_recovers(released, artifact, field):
    world = released
    control = world.tmp / "context-control.json"
    world.ok(0, "export", RECORD, "--output", str(control), "--confirm")
    assert control.is_file()
    original = dict(
        next(
            e.payload
            for e in reversed(list(world.journal))
            if e.kind == "decision.recorded" and e.payload.get("artifact") == artifact
        )
    )
    foreign = "foreign-profile-never-log" if field == "profile_id" else "f" * 64
    assert original[field] != foreign and original["input_refs_version"] == 3
    world.journal.append("decision.recorded", {**original, field: foreign}, record_id=RECORD)
    view = world.view()
    assert artifact not in view.have, "P3_CONTEXT"
    assert "release.approved" not in view.have
    assert "export.bundle" not in view.have
    assert "Entscheidungskontext" in view.facts[artifact].freshness_reason
    assert not view.findings
    plan = view.graph.plan(view.have)
    assert (
        "release.approve" if artifact == "release.approved" else "metadata.confirm"
    ) in plan.gate_names
    status = world.run("status")
    assert status.code != 0
    body = json.loads(status.out)
    assert body["details"]["records"][0]["artifacts"][artifact]["status"] != "READY"
    assert "Entscheidungskontext" in status.out and foreign not in status.out
    assert ("release approve" if artifact == "release.approved" else "metadata confirm") in body[
        "next"
    ]
    target = world.tmp / "context-blocked.json"
    result = world.run("export", RECORD, "--output", str(target), "--confirm")
    assert result.code == 3 and not target.exists()
    assert foreign not in result.out and "Entscheidungskontext" in result.out
    if artifact == "metadata.confirmed":
        world.ok(0, "metadata", "confirm", RECORD, "--actor", ACTOR, "--confirm")
        assert "metadata.confirmed" in world.view().have
        assert "release.approved" not in world.view().have
        world.ok(3, "continue", RECORD)
        world.ok(0, "abstract", "confirm", RECORD, "--actor", ACTOR, "--confirm")
        world.ok(3, "continue", RECORD)
    world.ok(0, "release", "approve", RECORD, "--actor", ACTOR, "--confirm")
    world.ok(0, "export", RECORD, "--output", str(target), "--confirm")
    assert target.is_file() and "export.bundle" in world.view().have


def test_missing_runtime_context_cannot_authorize_decisions(released):
    from ohpipe.domain.step import build_graph, graph_contract_fingerprint

    world = released
    unbound = build_graph(SimpleNamespace(pseudonymisation_required=False))
    assert unbound.profile_id is None
    assert graph_contract_fingerprint(unbound) == graph_contract_fingerprint(world.view().graph)
    view = replay(world.journal, graph=unbound, authority=Authority.AUTHENTICATED)[RECORD]
    assert "release.approved" not in view.have
    assert "Entscheidungskontext" in view.facts["release.approved"].freshness_reason


def test_missing_v3_decision_context_is_rejected(released):
    from ohpipe.domain.events import PayloadRejected

    world = released
    payload = dict(
        next(
            e.payload
            for e in reversed(list(world.journal))
            if e.kind == "decision.recorded" and e.payload.get("artifact") == "release.approved"
        )
    )
    payload.pop("profile_id")
    payload.pop("graph_sha256")
    before = world.state()
    with pytest.raises(PayloadRejected):
        world.journal.append("decision.recorded", payload, record_id=RECORD)
    assert world.state() == before


def test_profile_context_is_explicit_and_isolated_from_shared_structure():
    from ohpipe.domain.step import DEFAULT_GRAPH, build_graph, graph_contract_fingerprint

    a = build_graph(SimpleNamespace(id="profile-A", pseudonymisation_required=False))
    b = build_graph(SimpleNamespace(id="profile-B", pseudonymisation_required=False))
    digest = graph_contract_fingerprint(a)
    assert graph_contract_fingerprint(b) == digest
    assert a.profile_id == "profile-A" and b.profile_id == "profile-B"
    assert DEFAULT_GRAPH.profile_id is None
    assert a.matches_context("profile-A", digest)
    assert not a.matches_context("profile-B", digest)
    assert not DEFAULT_GRAPH.matches_context("profile-A", digest)
