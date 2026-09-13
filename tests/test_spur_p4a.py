"""P4a: synthetische Profil-, Vertrags- und Haltproben; keine Pseudonymruntime."""

from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path
import secrets
import tomllib

import pytest

from ohpipe.application.replay import replay
from ohpipe.application.steps import REGISTRY, StepContext
from ohpipe.application.l1_suggest import run_l1_suggest, SuggestError
from ohpipe.application.coverage import run_l1_coverage, CoverageError
from ohpipe.domain.language_assignment import build_srt_draft
from ohpipe.domain.step import build_graph, check_contracts, confirmed_text_role
from ohpipe.journal import Journal
from ohpipe.policies.authority import Authority
from ohpipe.project import Profile, ProfileError, Workspace
from .test_spur_p1 import World, ACTOR, isolated  # noqa: F401
from .test_spur_p2 import Recorder

REPO = Path(__file__).resolve().parents[1]
REFERENCE = REPO / "tests/fixtures/legacy-graphs.json"
PROFILE = REPO / "src/ohpipe/profiles/spur-p-manual/profile.toml"
RECORD = "SPURP-901"
STEPS = (
    "pii.mark",
    "pseudonymise",
    "pseudonymisation.cases",
    "pseudonymise.finalise",
    "pseudonymisation.review",
)


def test_required_mode(tmp_path):
    path = tmp_path / "profile.toml"
    path.write_text(PROFILE.read_text().replace('pii_detection = "manual"', ""))
    try:
        Profile.load(path)
    except ProfileError:
        return
    pytest.fail("P4A_MODE: Pflichtprofil ohne ausdrückliche Auswahl akzeptiert")


@pytest.mark.parametrize(
    "old,new",
    [
        ('pii_detection = "manual"', 'pii_detection = "unknown"'),
        ('pii_detection = "manual"', "pii_detection = 7"),
        ('[profile.pseudonymisation_rules.IDENTIFIER]\naction = "remove"', ""),
        ('action = "remove"', 'action = "invented"'),
        ('value = "ORT"', ""),
        ('scope = "spur-p-synthetic"', ""),
        ('entity_key = "opaque-entity-id"', 'entity_key = "name"'),
        ('pseudonymisation_policy_version = "spur-p-synthetic-v1"', ""),
        ("[profile.pseudonymisation_rules.CONTACT]", "[profile.pseudonymisation_rules.UNKNOWN]"),
        ('action = "remove"', 'action = "remove"\nvalue = "unexpected"'),
        ('value = "ORT"', "value = 7"),
        ('value = "ORT"', 'value = " "'),
        ("pseudonymisation_required = true", "pseudonymisation_required = false"),
    ],
)
def test_invalid_configuration_is_exit_2(tmp_path, monkeypatch, old, new):
    w = object.__new__(World)
    w.profile = tmp_path / "profile.toml"
    w.profile.write_text(PROFILE.read_text().replace(old, new))
    w.key = tmp_path / "key"
    w.key.write_bytes(secrets.token_bytes(32))
    w.monkeypatch = monkeypatch
    # Only the path is used by CLI invocation; invalid profile never creates a workspace.
    w.ws = Workspace(tmp_path / "data", Profile.load(PROFILE))
    result = w.run("init")
    assert result.code == 2, (result.out, result.err)
    assert not w.ws.root.exists()


def test_policy_variants_and_digest(tmp_path):
    p = Profile.load(PROFILE)
    assert not p.production and p.key_required and p.pii_detection == "manual"
    assert p.record_id(1) == "SPURP-001"
    assert p.model_vocabulary == ("fixture:descriptive-l1",)
    for action in ("keep", "remove", "coarsen", "pseudonym"):
        params = {"action": action}
        if action == "coarsen":
            params["value"] = "GROB"
        if action == "pseudonym":
            params.update(scope="another-synthetic-scope", entity_key="opaque-entity-id")
        rules = dict(p.pseudonymisation_rules)
        rules["PERSON"] = tuple(sorted(params.items()))
        q = replace(p, pseudonymisation_rules=tuple(sorted(rules.items())))
        assert q.pseudonymisation_policy_sha256 != p.pseudonymisation_policy_sha256
    assert (
        replace(p, pseudonymisation_policy_version="v2").pseudonymisation_policy_sha256
        != p.pseudonymisation_policy_sha256
    )
    assert (
        replace(
            p, pseudonymisation_rules=tuple(reversed(p.pseudonymisation_rules))
        ).pseudonymisation_policy_sha256
        == p.pseudonymisation_policy_sha256
    )


def test_graph_and_roles():
    graph = build_graph(Profile.load(PROFILE))
    assert not check_contracts(graph)
    assert len(graph.topological()) == len(graph.steps)
    assert tuple(s.name for s in graph if s.name in STEPS) == STEPS
    assert all(name not in REGISTRY for name in STEPS)
    assert "pii.detect" not in {s.name for s in graph}
    assert not any("receipt" in a for a in graph.artifacts)
    assert graph.get("pseudonymise.finalise").produces == (
        "transcript.pseudonymised.final",
        "replacement.report",
    )
    assert "replacement.report" not in graph.get("pseudonymise.finalise").requires
    assert graph.get("pseudonymise").produces == ("transcript.pseudonymised.draft",)
    for name in STEPS:
        assert graph.get(name).reads_text == "transcript.revision"
    for role in ("pii.spans", "pseudonymisation.cases", "transcript.pseudonymised.confirmed"):
        c = graph.contract_for(role)
        assert not c.binding_required and c.provenance_required and c.decision_required


def test_no_original_edge():
    graph = build_graph(Profile.load(PROFILE))
    for name in ("l1.suggest", "l1.coverage"):
        step = graph.get(name)
        assert "transcript.confirmed" not in step.requires, "P4A_EDGE: Originalkante geöffnet"
        assert "transcript.pseudonymised.confirmed" in step.requires, "P4A_EDGE: finales Gate fehlt"
        assert confirmed_text_role(graph, name)[2] == "transcript.pseudonymised.final"
    for have in (
        {"transcript.revision", "transcript.confirmed"},
        {
            "transcript.revision",
            "transcript.confirmed",
            "pii.spans",
            "transcript.pseudonymised.draft",
        },
        {
            "transcript.revision",
            "transcript.confirmed",
            "pii.spans",
            "transcript.pseudonymised.draft",
            "pseudonymisation.cases",
        },
    ):
        assert not {"l1.suggest", "l1.coverage", "export"} & {
            s.name for s in graph.next_steps(have)
        }


def test_final_text_role():
    from ohpipe.domain import step

    gate = next(s for s in step._MANUAL_PSEUDONYMISATION if s.name == "pseudonymisation.review")
    assert gate.confirms == "transcript.pseudonymised.final", "P4A_FINAL: falsche Bestätigungsrolle"


def test_existing_profiles_unchanged():
    # Independent historical graph snapshot, portable without private git history.
    reference = json.loads(REFERENCE.read_text())
    for name in ("sandbox", "walz", "childlux"):
        path = REPO / f"src/ohpipe/profiles/{name}/profile.toml"
        config = tomllib.loads(path.read_text())["profile"]
        config.pop("description", None)
        assert config == reference["profiles"][name]["profile"]
        graph = build_graph(Profile.load(path))
        current = {"steps": [asdict(s) for s in graph],
                   "contracts": {a: asdict(c) for a, c in graph.contracts.items()}}
        assert json.loads(json.dumps(current)) == reference["profiles"][name]["graph"]
        if name == "childlux":
            assert all(s not in REGISTRY for s in
                       ("pii.detect", "pseudonymise", "pseudonymisation.review"))
        else:
            assert not Profile.load(path).pii_detection


class ManualWorld(World):
    def __init__(self, tmp, monkeypatch, model=False, synthetic_raw=None):
        self.tmp, self.monkeypatch = tmp, monkeypatch
        self.key = tmp / "journal.key"
        self.key.write_bytes(secrets.token_bytes(32))
        self.key.chmod(0o600)
        self.profile = PROFILE
        if model:
            self.profile = tmp / "model.toml"
            self.profile.write_text(
                PROFILE.read_text()
                .split("pseudonymisation_policy_version")[0]
                .replace('pii_detection = "manual"', 'pii_detection = "model"')
            )
        self.ws = Workspace(tmp / "data", Profile.load(self.profile))
        self.journal = Journal(self.ws.journal_path, key=self.key.read_bytes())
        self.ok(0, "init")
        self.ok(
            0,
            "instance",
            "register",
            ACTOR,
            "--source",
            "mensch",
            "--label",
            "Synthetic P4a actor",
            "--reference",
            "SYNTHETIC-P4A",
            "--confirm",
        )
        iso = tmp / "iso.txt"
        iso.write_text("deu\nund\nzxx\n")
        self.ok(
            0,
            "iso6393",
            "prepare",
            str(iso),
            "--release",
            "synthetic.2026",
            "--reference",
            "SYNTHETIC-P4A",
            "--confirm",
        )
        raw = (
            synthetic_raw or b"1\n00:00:00,000 --> 00:00:02,000\nZEITZEUGIN: Synthetische Quelle.\n"
        )
        srt = tmp / "synthetic.srt"
        srt.write_bytes(raw)
        draft = build_srt_draft(raw)
        mapping = tmp / "synthetic.tsv"
        mapping.write_text(
            "index\tsegment_sha256\tlanguage\n"
            + "".join(f"{n}\t{s.sha256}\tdeu\n" for n, s in enumerate(draft.segments))
        )
        self.ok(3, "ingest", str(srt), "--record", RECORD)
        self.ok(
            0,
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(srt),
            str(mapping),
            "--actor",
            ACTOR,
            "--reference",
            "SYNTHETIC-P4A",
            "--confirm",
        )
        self.ok(0, "transcript", "ingest", RECORD, str(srt), str(mapping), "--confirm")
        self.ok(0, "transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")

    def view(self):
        self.journal.verify()
        return replay(
            self.journal, graph=build_graph(self.ws.profile), authority=Authority.AUTHENTICATED
        )[RECORD]


@pytest.mark.parametrize("model", [False, True])
def test_regular_entry_stops_unbuilt(tmp_path, monkeypatch, model):
    world = ManualWorld(tmp_path, monkeypatch, model)
    view = world.view()
    assert "transcript.confirmed" in view.have and not view.findings
    before = world.state()
    report = json.loads(world.ok(3, "continue", RECORD, "--confirm").out)
    assert report["reason_code"] == (
        "ACTION_CONTINUE_NOT_BUILT" if model else "ACTION_CONTINUE_GATE"
    ), report
    assert report["details"]["unbuilt"] == (["pii.detect"] if model else [])
    if model:
        assert not report.get("next") and not report.get("next_command")
    else:
        assert "pii mark" in (report.get("next") or report.get("next_command"))
    assert not report["details"]["executed"]
    assert world.state() == before
    ctx = StepContext(
        ws=world.ws,
        journal=world.journal,
        record_id=RECORD,
        profile_arg=str(world.profile),
        confirm=True,
        options={},
    )
    adapter = Recorder()
    with pytest.raises(SuggestError):
        run_l1_suggest(ctx, view, adapter=adapter)
    with pytest.raises(CoverageError):
        run_l1_coverage(ctx, view)
    assert not adapter.inputs and world.state() == before
    assert not set(view.have) & {
        "pii.spans",
        "transcript.pseudonymised.draft",
        "transcript.pseudonymised.final",
        "transcript.pseudonymised.confirmed",
        "replacement.report",
        "export.bundle",
    }
    print(
        json.dumps(
            {
                "synthetic_root": str(world.ws.root),
                "key_outside_root": world.key.parent != world.ws.root,
                "key_mode": oct(world.key.stat().st_mode & 0o777),
                "key_sha256": hashlib.sha256(world.key.read_bytes()).hexdigest(),
                "report": report,
            }
        )
    )


def test_text_marker_cannot_satisfy_multiple_input_gate():
    """In-memory forgery, no final-text writer: preserve the existing P3 rejection."""
    from ohpipe.application.freshness import evaluate, current_roles, _check_refs
    from ohpipe.application.replay import ArtifactFacts, RecordView
    from ohpipe.domain.decision import Decision, Verdict
    from ohpipe.domain.step import graph_contract_fingerprint

    graph = build_graph(Profile.load(PROFILE))
    gate = "transcript.pseudonymised.confirmed"
    view = RecordView(RECORD, graph=graph)
    for role in graph.artifacts:
        sha = hashlib.sha256(role.encode()).hexdigest()
        view.facts[role] = ArtifactFacts(
            role,
            graph.contract_for(role),
            False,
            sha256=sha,
            receipt_for=sha,
            receipt_seq=10,
            decision_seq=10,
            epoch=1,
            decided_sha=sha,
            decided_verdict="ACCEPT",
        )
    for role, fact in view.facts.items():
        fact.receipt_inputs = {r: view.facts[r].sha256 for r in current_roles(view, role)}
    final_sha = view.facts["transcript.pseudonymised.final"].sha256
    decision = Decision(
        RECORD,
        gate,
        view.facts[gate].sha256,
        Verdict.ACCEPT,
        "SYNTHETIC-P4A",
        ACTOR,
        input_refs={"text": final_sha},
        input_refs_version=2,
        profile_id="spur-p-manual",
        graph_sha256=graph_contract_fingerprint(graph),
    )
    view.effective_decision_by_artifact[gate] = decision
    _check_refs(
        view, view.facts[gate], {"transcript.pseudonymised.final": final_sha}, 10, receipt=False
    )
    assert "Referenz oder belegte Quelle fehlt" in view.facts[gate].freshness_reason
    assert "pii.spans" in view.facts[gate].freshness_reason
    evaluate(view)
    assert view.facts[gate].freshness is not None
    assert gate not in view.have
