"""P2-Abnahme: bestätigte Bytes statt Namen/Hashheuristik, ausschließlich synthetisch."""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import replace

import pytest

from ohpipe.adapters.models.fixture import FixtureAdapter
from ohpipe.application.confirmed_text import read_confirmed_text
from ohpipe.application.coverage import CoverageError, run_l1_coverage
from ohpipe.application.l1_suggest import SuggestError, run_l1_suggest
from ohpipe.application.replay import replay
from ohpipe.application.steps import StepContext, REGISTRY
from ohpipe.domain import step as graph_module
from ohpipe.domain.confirmation import ConfirmationMarker, TextConfirmationMarker
from ohpipe.domain.events import check_payload, PayloadRejected
from ohpipe.domain.operation import canonical_json_bytes
from ohpipe.domain.revision_serialization import verify_revision
from ohpipe.domain.step import (
    ArtifactContract,
    Step,
    StepGraph,
    Kind,
    GraphError,
    build_graph,
    check_contracts,
    confirmed_text_role,
    graph_contract_fingerprint,
)
from ohpipe.journal import Journal
from ohpipe.policies.authority import Authority
from ohpipe.project import Workspace, Profile, GraphBindingState

from .test_spur_p1 import ACTOR, RECORD, World, isolated  # noqa: F401 - autouse Netzwerkverbot
from .test_l1_suggest import _revision


def context(world):
    return StepContext(
        ws=world.ws,
        journal=world.journal,
        record_id=RECORD,
        profile_arg=str(world.profile),
        confirm=True,
        options={},
    )


class Recorder(FixtureAdapter):
    def __init__(self):
        super().__init__("stop")
        self.inputs = []

    def run(self, prompt, params):
        self.inputs.append(json.loads(prompt.partition("\n\n")[2]))
        return super().run(prompt, params)


def confirmation_payload(world):
    return dict(
        [
            e.payload
            for e in world.journal
            if e.kind == "decision.recorded" and e.payload.get("artifact") == "transcript.confirmed"
        ][-1]
    )


def append_confirmation(world, payload):
    world.journal.append("decision.recorded", payload, record_id=RECORD)


def rehash_decision(payload):
    payload.pop("decision_id", None)
    payload["decision_id"] = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def test_confirmed_x_does_not_authorize_model_input_y(tmp_path, monkeypatch):
    """Übernommen aus P0; gültiger Eingang und erfolgreiche Gegenprobe zuerst."""
    world = World(tmp_path, monkeypatch)
    initial = world.view()
    x = initial.facts["transcript.revision"].sha256
    marker_sha = initial.facts["transcript.confirmed"].sha256
    with world.ws.store().open_verified(x) as handle:
        rev_x = verify_revision(handle.read(), x)
    marker = ConfirmationMarker(RECORD, rev_x.projection_version, x)
    with world.ws.store().open_verified(marker_sha) as handle:
        assert handle.read() == marker.bytes
    assert marker_sha == marker.sha256
    world.journal.verify()
    payload = confirmation_payload(world)
    assert payload["input_refs"] == {"transcript": x}
    assert payload["subject_sha256"] == marker.sha256
    assert payload["profile_id"] == world.ws.profile.id
    assert initial.effective_decision_by_artifact["transcript.confirmed"].covers(marker.sha256)
    control = Recorder()
    run_l1_suggest(context(world), initial, adapter=control)
    assert control.inputs
    assert [s["text"] for block in control.inputs for s in block["segments"]] == [
        s.text for s in rev_x.segments
    ]
    world.revision("Y")
    current = world.view()
    y = current.facts["transcript.revision"].sha256
    assert x != y and not current.findings
    assert current.facts["transcript.confirmed"].sha256 == marker_sha
    with world.ws.store().open_verified(y) as handle:
        verify_revision(handle.read(), y)
    probe = Recorder()
    before = world.state()
    reason = ""
    try:
        run_l1_suggest(context(world), current, adapter=probe)
    except SuggestError as exc:
        reason = str(exc)
    assert reason and not probe.inputs, "P0_TEXT_XY: Marker X hat Modellzugriff auf Y erlaubt"
    assert f"transcript confirm {RECORD}" in reason
    assert world.state() == before
    world.ok(0, "transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")
    fresh = Recorder()
    result = run_l1_suggest(context(world), world.view(), adapter=fresh)
    assert fresh.inputs and "Synthetische Fassung Y." in json.dumps(fresh.inputs)
    assert result.written
    coverage = run_l1_coverage(context(world), world.view())
    assert coverage.passed
    bound = read_confirmed_text(context(world), world.view(), "l1.coverage")
    receipts = [e.payload for e in world.journal if e.kind == "receipt.recorded"]
    model = [p for p in receipts if p.get("step") == "l1.suggest"][-1]
    cover = [p for p in receipts if p.get("step") == "l1.coverage"][-1]
    assert model["inputs"] == bound.inputs
    assert cover["inputs"] == {**bound.inputs, "l1.suggestions": result.artifact_sha256}


@pytest.mark.parametrize(
    "change", ["record", "projection", "revision", "extra", "noncanonical", "domain", "version"]
)
def test_marker_tampering_halts_before_adapter(tmp_path, monkeypatch, change):
    world = World(tmp_path, monkeypatch)
    payload = confirmation_payload(world)
    sha = payload["subject_sha256"]
    obj = json.loads((world.ws.objects / sha).read_bytes())
    if change == "record":
        obj["artifact_key"]["scope_id"] = "SANDBOX-902"
    if change == "projection":
        obj["projection_version"] = "wrong-projection"
    if change == "revision":
        obj["revision_sha256"] = "a" * 64
    if change == "extra":
        obj["extra"] = "synthetic"
    if change == "domain":
        obj["domain"] = "unknown"
    if change == "version":
        obj["v"] = 99
    raw = (
        canonical_json_bytes(obj)
        if change != "noncanonical"
        else json.dumps(obj, indent=2).encode()
    )
    changed = world.ws.store().put(io.BytesIO(raw))
    world.journal.append(
        "artifact.produced",
        {"artifact": "transcript.confirmed", "sha256": changed},
        record_id=RECORD,
    )
    payload.update(subject_sha256=changed, reference=changed)
    rehash_decision(payload)
    append_confirmation(world, payload)
    world.journal.append(
        "anchor.checked", {"artifact": "transcript.confirmed", "outcome": "exact"}, record_id=RECORD
    )
    assert "transcript.confirmed" in world.view().have
    before = world.state()
    adapter = Recorder()
    with pytest.raises(SuggestError, match="transcript confirm"):
        run_l1_suggest(context(world), world.view(), adapter=adapter)
    assert not adapter.inputs and world.state() == before


@pytest.mark.parametrize("change", ["refs", "profile", "graph", "digest", "legacy", "reject"])
def test_decision_binding_halts_before_adapter(tmp_path, monkeypatch, change):
    world = World(tmp_path, monkeypatch)
    payload = confirmation_payload(world)
    if change == "refs":
        payload["input_refs"] = {"transcript": "a" * 64}
    if change == "profile":
        payload["profile_id"] = "foreign-profile"
    if change == "graph":
        payload["graph_sha256"] = "b" * 64
    if change == "legacy":
        payload["v"] = 1
        del payload["profile_id"], payload["graph_sha256"]
    if change == "reject":
        payload["verdict"] = "REJECT"
    rehash_decision(payload)
    if change == "digest":
        payload["decision_id"] = "c" * 64
    append_confirmation(world, payload)
    before = world.state()
    adapter = Recorder()
    with pytest.raises(SuggestError, match="transcript confirm"):
        run_l1_suggest(context(world), world.view(), adapter=adapter)
    assert not adapter.inputs and world.state() == before


@pytest.mark.parametrize("artifact", ["transcript.revision", "transcript.confirmed"])
@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_store_bytes_must_verify(tmp_path, monkeypatch, artifact, damage):
    world = World(tmp_path, monkeypatch)
    path = world.ws.objects / world.view().facts[artifact].sha256
    if damage == "missing":
        path.unlink()
    else:
        path.write_bytes(b"synthetic-corruption")
    before = world.state()
    adapter = Recorder()
    with pytest.raises(SuggestError):
        run_l1_suggest(context(world), world.view(), adapter=adapter)
    assert not adapter.inputs and world.state() == before


def test_wrong_record_context_halts(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    adapter = Recorder()
    with pytest.raises(SuggestError, match="Record-/Graphkontext"):
        run_l1_suggest(
            replace(context(world), record_id="SANDBOX-902"), world.view(), adapter=adapter
        )
    assert not adapter.inputs


def test_coverage_rejects_suggestions_from_other_confirmed_revision(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    run_l1_suggest(context(world), world.view(), adapter=Recorder())
    assert run_l1_coverage(context(world), world.view()).passed
    world.revision("Y")
    world.ok(0, "transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")
    # Gegenprobe: Y selbst ist frisch lesbar; nur die Vorschläge gehören noch X.
    assert (
        "Fassung Y."
        in read_confirmed_text(context(world), world.view(), "l1.coverage").revision.normalized
    )
    before = world.state()
    halted = False
    try:
        run_l1_coverage(context(world), world.view())
    except CoverageError:
        halted = True
    assert halted, "P2_COVERAGE: alte Vorschläge wurden an neuen Text gehängt"
    assert world.state() == before


def renamed_graph(*, second=False, selected=None):
    original = graph_module.DEFAULT_GRAPH
    contracts = {
        "edition.text": original.contract_for("transcript.revision"),
        "edition.accepted": original.contract_for("transcript.confirmed"),
        "l1.suggestions": original.contract_for("l1.suggestions"),
        "l1.coverage": original.contract_for("l1.coverage"),
    }
    steps = [
        Step("edition.read", Kind.DETERMINISTIC, produces=("edition.text",)),
        Step(
            "edition.confirm",
            Kind.HUMAN,
            requires=("edition.text",),
            produces=("edition.accepted",),
            human_gate=True,
            confirms="edition.text",
        ),
    ]
    gates = ("edition.accepted",)
    if second:
        contracts["permission.accepted"] = ArtifactContract(
            binding_required=False, provenance_required=False, decision_required=True
        )
        steps.append(
            Step(
                "permission.confirm", Kind.HUMAN, produces=("permission.accepted",), human_gate=True
            )
        )
        gates += ("permission.accepted",)
    steps.extend(
        [
            replace(original.get("l1.suggest"), requires=gates, reads_text=selected),
            replace(
                original.get("l1.coverage"),
                requires=("l1.suggestions", *gates),
                reads_text=selected,
            ),
        ]
    )
    return StepGraph(tuple(steps), contracts)


def test_renamed_gate_reads_declared_text_and_binds_both_hashes(tmp_path, monkeypatch):
    graph = renamed_graph()
    monkeypatch.setattr(graph_module, "DEFAULT_GRAPH", graph)
    profile = Profile.load("src/ohpipe/profiles/sandbox/profile.toml")
    graph.profile_id = profile.id
    ws = Workspace(tmp_path / "data", profile)
    ws.ensure()
    ws.bind_graph_initially()
    journal = Journal(ws.journal_path, key=b"P2-renamed-synthetic-journal-key-1")
    rev = _revision()
    from ohpipe.domain.revision_serialization import canonical_revision_bytes

    assert ws.store().put(io.BytesIO(canonical_revision_bytes(rev))) == rev.sha256
    marker = TextConfirmationMarker(
        RECORD,
        "edition.accepted",
        "edition.text",
        rev.sha256,
        rev.projection_version,
        profile.id,
        ws.running_graph_sha256(),
    )
    ws.store().put(io.BytesIO(marker.bytes))
    for artifact, sha in (("edition.text", rev.sha256), ("edition.accepted", marker.sha256)):
        journal.append("artifact.produced", {"artifact": artifact, "sha256": sha}, record_id=RECORD)
    payload = dict(
        artifact="edition.accepted",
        subject_sha256=marker.sha256,
        verdict="ACCEPT",
        reference="P2-renamed",
        actor=ACTOR,
        at="2026-09-01T11:00:00+00:00",
        input_refs={"text": rev.sha256},
        input_refs_version=2,
        profile_id=profile.id,
        graph_sha256=ws.running_graph_sha256(),
    )
    journal.append("decision.recorded", payload, record_id=RECORD)
    journal.append(
        "anchor.checked", {"artifact": "edition.accepted", "outcome": "exact"}, record_id=RECORD
    )

    def view():
        return replay(journal.verified_events(), graph=graph, authority=Authority.AUTHENTICATED)[
            RECORD
        ]

    ctx = StepContext(
        ws=ws, journal=journal, record_id=RECORD, profile_arg="sandbox", confirm=True, options={}
    )
    assert not view().findings and "edition.accepted" in view().have
    assert dict(view().effective_decision_by_artifact["edition.accepted"].input_refs) == {
        "text": rev.sha256
    }
    adapter = Recorder()
    suggestion = run_l1_suggest(ctx, view(), adapter=adapter)
    assert adapter.inputs and run_l1_coverage(ctx, view()).passed
    receipts = [e.payload for e in journal if e.kind == "receipt.recorded"]
    assert receipts[-2]["inputs"] == {"edition.text": rev.sha256, "edition.accepted": marker.sha256}
    assert receipts[-1]["inputs"] == {
        "edition.text": rev.sha256,
        "edition.accepted": marker.sha256,
        "l1.suggestions": suggestion.artifact_sha256,
    }
    # Kein P4-Handler wird behauptet. Ein vorhandener Handler bestimmt den Befehl.
    handler = replace(
        REGISTRY.get("transcript.confirm"),
        step="edition.confirm",
        next_command=lambda ctx: ctx.command("edition", "confirm", RECORD),
    )
    monkeypatch.setitem(REGISTRY, "edition.confirm", handler)
    payload["input_refs"] = {"text": "e" * 64}
    journal.append("decision.recorded", payload, record_id=RECORD)
    with pytest.raises(SuggestError, match=f"edition confirm {RECORD}"):
        run_l1_suggest(ctx, view(), adapter=Recorder())


@pytest.mark.parametrize(
    "change", ["not-input", "not-text", "unknown-profile", "not-human", "ambiguous", "two-texts"]
)
def test_invalid_text_contract_stops_at_graph_validation(monkeypatch, change):
    graph = renamed_graph(second=change in ("ambiguous", "two-texts"))
    steps, contracts = list(graph.steps), dict(graph.contracts)
    if change == "not-input":
        steps[1] = replace(steps[1], confirms="l1.coverage")
    if change == "not-text":
        contracts["edition.text"] = replace(contracts["edition.text"], text_profile=None)
    if change == "unknown-profile":
        contracts["edition.text"] = replace(contracts["edition.text"], text_profile="unknown")
    if change == "not-human":
        steps[1] = replace(steps[1], kind=Kind.DETERMINISTIC, human_gate=False)
    if change == "two-texts":
        steps[2] = replace(steps[2], requires=("edition.text",), confirms="edition.text")
    graph = StepGraph(tuple(steps), contracts)
    assert check_contracts(graph)
    monkeypatch.setattr(graph_module, "DEFAULT_GRAPH", graph)
    with pytest.raises(GraphError):
        build_graph(object())


def test_explicit_text_role_disambiguates_and_changes_contract_digest():
    selected = renamed_graph(second=True, selected="edition.text")
    assert not check_contracts(selected)
    assert confirmed_text_role(selected, "l1.suggest")[2] == "edition.text"
    ambiguous = renamed_graph(second=True)
    assert graph_contract_fingerprint(selected) != graph_contract_fingerprint(ambiguous)


def test_existing_graph_binding_is_not_replaced(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    before = world.ws.inspect_graph_binding()
    graph = build_graph(world.ws.profile)
    # Gültige Änderung der expliziten Verbraucherdeklaration genügt.
    changed = StepGraph(
        tuple(
            replace(s, reads_text="transcript.revision") if s.name == "l1.suggest" else s
            for s in graph
        ),
        dict(graph.contracts),
    )
    monkeypatch.setattr(graph_module, "DEFAULT_GRAPH", changed)
    assert world.ws.inspect_graph_binding()[0] is not GraphBindingState.CURRENT
    adapter = Recorder()
    with pytest.raises(SuggestError, match="graph-upgrade"):
        run_l1_suggest(context(world), world.view(), adapter=adapter)
    assert world.ws.inspect_graph_binding()[1] == before[1]
    assert not adapter.inputs


@pytest.mark.parametrize(
    "patch",
    [
        {"input_refs": {"other": "a" * 64}},
        {"input_refs_version": 9},
        {"input_refs": None},
        {"profile_id": ""},
        {"graph_sha256": 3},
        {"v": 99},
        {"extra": "synthetic"},
    ],
)
def test_confirmation_schema_is_closed(tmp_path, monkeypatch, patch):
    world = World(tmp_path, monkeypatch)
    payload = confirmation_payload(world) | patch
    with pytest.raises(PayloadRejected):
        check_payload("decision.recorded", payload, RECORD)


def test_future_pseudonym_gate_is_declared_without_producer_implementation():
    graph = build_graph(Profile.load("src/ohpipe/profiles/childlux/profile.toml"))
    artifact, gate, text = confirmed_text_role(graph, "l1.suggest")
    assert (artifact, gate.name, text) == (
        "transcript.pseudonymised.confirmed",
        "pseudonymisation.review",
        "transcript.pseudonymised.draft",
    )
    assert REGISTRY.get(gate.name) is None


@pytest.mark.parametrize(
    "change", ["record", "revision", "anchor", "receipt-marker", "receipt-text"]
)
def test_coverage_checks_suggestion_bytes_and_receipt_roles(tmp_path, monkeypatch, change):
    world = World(tmp_path, monkeypatch)
    result = run_l1_suggest(context(world), world.view(), adapter=Recorder())
    receipt = dict(
        [
            e.payload
            for e in world.journal
            if e.kind == "receipt.recorded" and e.payload.get("step") == "l1.suggest"
        ][-1]
    )
    with world.ws.store().open_verified(result.artifact_sha256) as handle:
        obj = json.load(handle)
    if change == "record":
        obj["record_id"] = "SANDBOX-902"
    if change == "revision":
        obj["revision_sha256"] = "a" * 64
    if change == "anchor":
        obj["suggestions"][0]["anchor"]["transcript_sha256"] = "b" * 64
    sha = world.ws.store().put(
        io.BytesIO((json.dumps(obj, sort_keys=True, separators=(",", ":")) + "\n").encode())
    )
    receipt["output_sha256"] = sha
    if change == "receipt-marker":
        receipt["inputs"]["transcript.confirmed"] = "c" * 64
    if change == "receipt-text":
        receipt["inputs"]["transcript.revision"] = "d" * 64
    world.journal.append(
        "artifact.produced", {"artifact": "l1.suggestions", "sha256": sha}, record_id=RECORD
    )
    world.journal.append("receipt.recorded", receipt, record_id=RECORD)
    world.journal.append(
        "anchor.checked", {"artifact": "l1.suggestions", "outcome": "exact"}, record_id=RECORD
    )
    before = world.state()
    with pytest.raises(CoverageError):
        run_l1_coverage(context(world), world.view())
    assert world.state() == before


def test_revision_normalization_profile_must_match_text_contract(tmp_path, monkeypatch):
    from ohpipe.domain.revision_serialization import canonical_revision_bytes
    from ohpipe.domain.transcript import TranscriptRevision

    world = World(tmp_path, monkeypatch)
    rev = TranscriptRevision.from_segments(
        _revision().segments,
        projection_version=_revision().projection_version,
        source_kind="srt",
        profile_id="foreign-normalization-profile",
    )
    raw = canonical_revision_bytes(rev)
    assert world.ws.store().put(io.BytesIO(raw)) == rev.sha256
    # Inhalt und Digest sind konsistent; allein der deklarierte Profilkontext ist fremd.
    assert verify_revision(raw, rev.sha256).profile_id == "foreign-normalization-profile"
    marker = ConfirmationMarker(RECORD, rev.projection_version, rev.sha256)
    world.ws.store().put(io.BytesIO(marker.bytes))
    world.journal.append(
        "receipt.recorded",
        {
            "artifact": "transcript.revision",
            "output_sha256": rev.sha256,
            "inputs": dict(world.view().facts["transcript.revision"].receipt_inputs),
            "kind": "transcript.fulltext.segment_projection.v1",
            "fulltext_origin": "from_segments",
            "code_version": "P2-synthetic-profile-test",
        },
        record_id=RECORD,
    )
    for artifact, sha in (
        ("transcript.revision", rev.sha256),
        ("transcript.confirmed", marker.sha256),
    ):
        world.journal.append(
            "artifact.produced", {"artifact": artifact, "sha256": sha}, record_id=RECORD
        )
    payload = confirmation_payload(world)
    payload.update(
        subject_sha256=marker.sha256, reference=marker.sha256, input_refs={"transcript": rev.sha256}
    )
    rehash_decision(payload)
    append_confirmation(world, payload)
    world.journal.append(
        "anchor.checked", {"artifact": "transcript.confirmed", "outcome": "exact"}, record_id=RECORD
    )
    adapter = Recorder()
    assert not world.view().findings, world.view().findings
    assert "transcript.revision" in world.view().have, world.view().to_json()
    assert world.view().facts["transcript.revision"].sha256 == rev.sha256
    with pytest.raises(SuggestError, match="Normalisierungsprofil"):
        run_l1_suggest(context(world), world.view(), adapter=adapter)
    assert not adapter.inputs


def test_unkeyed_journal_cannot_authorize_model(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    ctx = replace(context(world), journal=Journal(world.ws.journal_path))
    adapter = Recorder()
    with pytest.raises(SuggestError, match="authentifiziertes Journal"):
        run_l1_suggest(ctx, world.view(), adapter=adapter)
    assert not adapter.inputs


def test_p1_literal_binding_demands_explicit_upgrade(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    path = world.ws.governance / "graph-contract.json"
    obj = json.loads(path.read_bytes())
    obj["graph_sha256"] = "4a4cdeb6ffbf4c7df58fd8da1b1a29aec209c72ec7bf8dfd3c5459c8937a8340"
    path.write_text(json.dumps(obj) + "\n")
    before = path.read_bytes(), world.state()
    result = world.run("continue", RECORD, "--confirm")
    report = json.loads(result.out)
    assert result.code == 3 and report["status"] == "GRAPH_CONTRACT_MISMATCH"
    assert "graph-upgrade" in report["next"]
    assert (path.read_bytes(), world.state()) == before


def test_recomputed_coverage_binds_current_suggestions_and_preserves_history(tmp_path, monkeypatch):
    """R-P2-01: gleiche Deckung bedeutet nicht dieselben gelesenen Vorschläge."""
    from ohpipe.adapters.models.fixture import fixture_params

    class SeedRecorder(Recorder):
        def __init__(self, seed):
            super().__init__()
            self.synthetic_seed = seed

        @property
        def params(self):
            return replace(fixture_params("stop"), seed=self.synthetic_seed)

    world = World(tmp_path, monkeypatch)
    ctx = context(world)
    bound = read_confirmed_text(ctx, world.view(), "l1.coverage")
    first = run_l1_suggest(ctx, world.view(), adapter=SeedRecorder(101))
    coverage_first = run_l1_coverage(ctx, world.view())
    journal_prefix = world.journal.path.read_bytes()
    first_bytes = (world.ws.objects / coverage_first.artifact_sha256).read_bytes()
    second_adapter = SeedRecorder(102)
    second = run_l1_suggest(ctx, world.view(), adapter=second_adapter)
    assert second_adapter.inputs and first.artifact_sha256 != second.artifact_sha256
    assert read_confirmed_text(ctx, world.view(), "l1.coverage").inputs == bound.inputs
    coverage_second = run_l1_coverage(ctx, world.view())
    assert (
        coverage_first.covered,
        coverage_first.total,
        coverage_first.ratio,
        coverage_first.uncovered,
    ) == (
        coverage_second.covered,
        coverage_second.total,
        coverage_second.ratio,
        coverage_second.uncovered,
    )
    view = world.view()
    assert not view.findings and "l1.coverage" in view.have
    assert view.facts["l1.coverage"].receipt_inputs["l1.suggestions"] == second.artifact_sha256, (
        "R-P2-01: recomputed coverage retains old suggestion input"
    )
    assert coverage_first.artifact_sha256 != coverage_second.artifact_sha256
    receipts = [
        e.payload
        for e in world.journal
        if e.kind == "receipt.recorded" and e.payload.get("artifact") == "l1.coverage"
    ]
    assert [p["inputs"] for p in receipts] == [
        {**bound.inputs, "l1.suggestions": first.artifact_sha256},
        {**bound.inputs, "l1.suggestions": second.artifact_sha256},
    ]
    assert world.journal.path.read_bytes().startswith(journal_prefix)
    assert (world.ws.objects / coverage_first.artifact_sha256).read_bytes() == first_bytes
    for result, suggestions in [(coverage_first, first), (coverage_second, second)]:
        with world.ws.store().open_verified(result.artifact_sha256) as handle:
            obj = json.load(handle)
        assert obj["schema"] == "ohpipe.l1.coverage.v3"
        assert obj["inputs"] == {**bound.inputs, "l1.suggestions": suggestions.artifact_sha256}
    before_repeat = world.state()
    repeated = run_l1_coverage(ctx, world.view())
    assert repeated.artifact_sha256 == coverage_second.artifact_sha256 and not repeated.written
    assert world.state() == before_repeat
    assert [
        e.payload
        for e in world.journal
        if e.kind == "receipt.recorded" and e.payload.get("artifact") == "l1.coverage"
    ] == receipts
