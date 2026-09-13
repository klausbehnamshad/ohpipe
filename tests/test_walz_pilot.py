"""WALZ-Pilotprofile, ausschließlich erfundene Quellen; Produktionsverträge bleiben aktiv."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys

import pytest

from ohpipe.application import finalisation as work
from ohpipe.application.manual_work import Session
from ohpipe.application.confirmed_text import read_confirmed_text, ConfirmedTextError
from ohpipe.application.replay import replay
from ohpipe.application.steps import StepContext, registry_for, REGISTRY
from ohpipe.application.storage_integrity import check_referenced
from ohpipe.domain import manual_context
from ohpipe.domain.language_assignment import build_srt_draft
from ohpipe.domain.step import build_graph
from ohpipe.journal import Journal
from ohpipe.policies.authority import Authority
from ohpipe.project import Profile, Workspace
from ohpipe.protected_store import canonical, digest, ProtectionError, ProtectedStore
from ohpipe.registry_store import RegistryStore, FINAL, REPORT, GATE
from tools.walz_pilot_setup import prepare, PROFILE, RECORD, TEXT, MARKS, MODEL_DIGEST, model_text
from .test_spur_p1 import World, ACTOR


class PilotWorld(World):
    def __init__(
        self,
        tmp,
        monkeypatch,
        *,
        source_bytes=None,
        languages=None,
        marks=None,
        merge_marks=False,
    ):
        self.tmp, self.monkeypatch = tmp, monkeypatch
        self.setup = prepare(tmp / "synthetic")
        self.root = Path(self.setup["root"])
        for k, v in self.setup["environment"].items():
            monkeypatch.setenv(k, v)
        self.key = Path(self.setup["environment"]["OHPIPE_JOURNAL_KEY"])
        self.profile = PROFILE
        self.ws = Workspace(self.root / "data", Profile.load(PROFILE))
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
            "SYNTHETIC-PILOT",
            "--reference",
            "SYNTHETIC-PILOT",
            "--confirm",
        )
        self.ok(
            0,
            "iso6393",
            "prepare",
            str(self.root / "source/iso.txt"),
            "--release",
            "synthetic.2026",
            "--reference",
            "SYNTHETIC-PILOT",
            "--confirm",
        )
        source = self.root / "source/synthetic.srt"
        if source_bytes is not None:
            source.write_bytes(source_bytes)
        draft = build_srt_draft(source.read_bytes())
        self.draft = draft
        self.marks = marks or [(0, text, kind) for text, kind in MARKS]
        self.merge_marks = merge_marks
        assigned_languages = languages or ["deu"] * len(draft.segments)
        assert len(assigned_languages) == len(draft.segments)
        mapping = self.root / "source/synthetic.tsv"
        mapping.write_text(
            "index\tsegment_sha256\tlanguage\n"
            + "".join(
                f"{s.index}\t{s.sha256}\t{assigned_languages[s.index]}\n" for s in draft.segments
            )
        )
        mapping.chmod(0o600)
        self.ok(3, "ingest", str(source), "--record", RECORD)
        self.ok(
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
            "SYNTHETIC-PILOT",
            "--confirm",
        )
        self.ok(0, "transcript", "ingest", RECORD, str(source), str(mapping), "--confirm")
        self.ok(0, "transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")
        self.ctx = StepContext(
            ws=self.ws, journal=self.journal, record_id=RECORD, profile_arg=str(self.profile)
        )
        self.registry_config = Path(self.setup["environment"]["OHPIPE_REGISTRY_CONFIG"])

    def view(self):
        return replay(
            self.journal, graph=build_graph(self.ws.profile), authority=Authority.AUTHENTICATED
        )[RECORD]

    def final(self):
        marks = "".join(
            f"markieren {index} {self.draft.segments[index].text.index(text)} "
            f"{self.draft.segments[index].text.index(text) + len(text)} {kind}\n"
            for index, text, kind in self.marks
        )
        r = self.run(
            "pii",
            "mark",
            RECORD,
            "--actor",
            ACTOR,
            tty=True,
            as_json=False,
            answer="neu\n" + marks + "bestätigen\nBESTÄTIGEN\n",
        )
        assert r.code == 0, (r.out, r.err)
        self.ok(0, "pseudonymise", RECORD)
        cases = Session(self.ctx, "pseudonymisation.cases", ACTOR)
        if self.merge_marks:
            case_commands = "merge " + " ".join(cases.capsule["groups"]) + "\n"
        else:
            case_commands = "".join("auflösen " + gid + "\n" for gid in cases.capsule["groups"])
        answers = "neu\n" + case_commands + "bestätigen\nBESTÄTIGEN\n"
        r = self.run(
            "pseudonymisation",
            "cases",
            RECORD,
            "--actor",
            ACTOR,
            tty=True,
            as_json=False,
            answer=answers,
        )
        assert r.code == 0, (r.out, r.err)
        self.ok(0, "pseudonymisation", "registry", "init")
        r = self.run(
            "pseudonymisation",
            "resolve",
            RECORD,
            "--actor",
            ACTOR,
            tty=True,
            as_json=False,
            answer="neu\n" * (1 if self.merge_marks else len(cases.capsule["groups"]))
            + "BESTÄTIGEN\n",
        )
        assert r.code == 0, (r.out, r.err)
        self.ok(0, "pseudonymise", "finalise", RECORD)
        return self

    def approve(self):
        r = self.run(
            "pseudonymisation",
            "review",
            RECORD,
            "--actor",
            ACTOR,
            tty=True,
            as_json=False,
            answer="BESTÄTIGEN\n",
        )
        assert r.code == 0, (r.out, r.err)
        assert "Sprecherkennung:" in r.out, "PILOT_SPEAKER: final speaker metadata not shown"
        return read_confirmed_text(self.ctx, self.view(), "l1.suggest")


@pytest.fixture
def pilot(tmp_path, monkeypatch):
    monkeypatch.delenv("OHPIPE_DATA_ROOT", raising=False)

    def no_network(*a, **kw):
        raise AssertionError("PILOT_UNEXPECTED_NETWORK")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    return PilotWorld(tmp_path, monkeypatch)


def test_profile_closed_and_walz_requirements():
    p = Profile.load(PROFILE)
    old = Profile.load(PROFILE.parent.parent / "walz/profile.toml")
    assert manual_context.enabled(p), "PILOT_PROFILE: required production contract missing"
    for k in (
        "languages",
        "processing_routes",
        "coding_mode",
        "codebook",
        "coverage_threshold",
        "model_vocabulary",
        "consent_vocabulary",
        "export_targets",
    ):
        assert getattr(p, k) == getattr(old, k), k
    assert p.id == "walz-pilot-pseudo" and p.pseudonymisation_required
    assert set(registry_for(p)) - set(REGISTRY) == {
        "pii.mark",
        "pseudonymise",
        "pseudonymisation.cases",
        "pseudonymise.finalise",
        "pseudonymisation.review",
    }
    for k, v in [
        ("id", "unknown"),
        ("production", False),
        ("key_required", False),
        ("record_prefix", "OTHER"),
    ]:
        q = replace(p, **{k: v})
        assert not manual_context.enabled(q)
        assert registry_for(q) is REGISTRY
    assert registry_for(old) is REGISTRY


def test_real_cli_all_types_and_noop(pilot):
    w = pilot.final()
    assert GATE not in w.view().have
    bound = w.approve()
    assert bound.revision.text == TEXT.replace("Testperson Zeta", "PERSON-001").replace(
        "test@example.invalid", ""
    ).replace("TEST-ID-42", ""), "PILOT_RULES: final policy differs"
    _, _, report = work.Work(w.ctx, ACTOR).review_material()
    assert {e["type"] for e in report["entries"]} == {t for _, t in MARKS}
    assert not check_referenced(w.ws, w.view())
    before = (w.journal.head(), RegistryStore(w.ws, w.journal.key).head())
    w.ok(0, "pseudonymise", "finalise", RECORD)
    assert before == (w.journal.head(), RegistryStore(w.ws, w.journal.key).head())


@pytest.mark.parametrize("phase", ["pii", "cases", "resolve", "review"])
def test_noninteractive_production_guards(pilot, monkeypatch, phase):
    w = pilot.final()

    def forbidden(*a, **kw):
        pytest.fail("PILOT_TTY: decrypted without terminal")

    monkeypatch.setattr(ProtectedStore, "open", forbidden)
    monkeypatch.setattr(RegistryStore, "open", forbidden)
    args = {
        "pii": ["pii", "mark"],
        "cases": ["pseudonymisation", "cases"],
        "resolve": ["pseudonymisation", "resolve"],
        "review": ["pseudonymisation", "review"],
    }[phase]
    assert w.run(*args, RECORD, "--actor", ACTOR).code == 2


def test_regular_session_resume(pilot):
    w = pilot
    s = Session(w.ctx, "pii.mark", ACTOR)
    s.add(0, 0, 14, "PERSON")
    s.save()
    before = w.journal.head()
    again = Session(w.ctx, "pii.mark", ACTOR, resume=True)
    assert again.capsule == s.capsule and again.session_id == s.session_id
    assert w.journal.head() == before and "pii.spans" not in w.view().have
    again.publish(displayed=digest(canonical(again.capsule)))
    assert "pii.spans" in w.view().have


@pytest.mark.parametrize("change", ["policy", "source", "withdrawal", "cipher", "key"])
def test_pilot_invalidation_blocks_consumer(pilot, change):
    w = pilot.final()
    w.approve()
    if change == "policy":
        f = w.root / "changed-profile.toml"
        f.write_text(
            PROFILE.read_text().replace("walz-pilot-proposal-v1", "walz-pilot-proposal-v2")
        )
        f.chmod(0o600)
        w.profile = f
        w.ctx = replace(w.ctx, profile_arg=str(f))
    elif change == "source":
        sha = w.view().facts["transcript.revision"].sha256
        (w.ws.objects / sha).unlink()
    elif change == "withdrawal":
        w.ok(
            0,
            "decision",
            "withdraw",
            RECORD,
            "pseudonymisation.cases",
            "--actor",
            ACTOR,
            "--reference",
            "SYNTHETIC-PILOT",
            "--confirm",
        )
    elif change == "cipher":
        store = RegistryStore(w.ws, w.journal.key)
        ref = work.published(w.ctx, list(w.journal), "finalise")["refs"][FINAL]
        (store.root / "objects" / ref["cipher_sha256"]).unlink()
    else:
        key = Path(json.loads(w.registry_config.read_text())["key_file"])
        key.write_bytes(b"X" * 32)
    with pytest.raises(ConfirmedTextError):
        read_confirmed_text(w.ctx, w.view(), "l1.suggest")
    assert "l1.suggestions" not in w.view().have


@pytest.mark.parametrize(
    "profile,record",
    [
        ("spur-p-manual", RECORD),
        ("walz", RECORD),
        ("walz-pilot-pseudo", "SPURP-901"),
        ("invented", RECORD),
    ],
)
def test_cipher_context_cannot_cross_profiles(pilot, profile, record):
    w = pilot.final()
    store = RegistryStore(w.ws, w.journal.key)
    ref = deepcopy(work.published(w.ctx, list(w.journal), "finalise")["refs"][FINAL])
    ref["aad"]["profile"] = profile
    ref["aad"]["record"] = record
    with pytest.raises(ProtectionError):
        store.open(ref, RECORD)


def test_leakage_inventory(pilot):
    w = pilot
    before = {p: p.read_bytes() for p in w.ws.root.rglob("*") if p.is_file()}
    w.final()
    w.approve()
    store = RegistryStore(w.ws, w.journal.key)
    p = work.published(w.ctx, list(w.journal), "finalise")
    res = work.published(w.ctx, list(w.journal), "resolve")
    forbidden = [
        store.key,
        store.candidate_key,
        store.open(p["refs"][FINAL], RECORD),
        store.open(p["refs"][REPORT], RECORD),
        store.open(res["refs"]["pseudonymisation.resolution"], RECORD),
    ]

    def leaks():
        return any(
            any(s in f.read_bytes() for s in forbidden)
            for f in w.ws.root.rglob("*")
            if f.is_file() and (f not in before or f.read_bytes() != before[f])
        )

    assert not leaks(), "PILOT_LEAK"
    f = w.ws.objects / "synthetic-negative"
    f.write_bytes(forbidden[0])
    f.chmod(0o600)
    assert leaks()
    f.unlink()


def test_missing_model_does_not_fall_back(pilot):
    from ohpipe.application.l1_suggest import adapter_for, SuggestError

    with pytest.raises(SuggestError, match="Modelladapter"):
        adapter_for(pilot.ws, {})


def test_production_adapter_consumes_final_only(pilot, monkeypatch):
    from ohpipe.adapters.models import ollama
    from .test_ollama_adapter import _skript

    w = pilot.final()
    w.approve()
    sent = []
    script = _skript(
        tags_digest=MODEL_DIGEST,
        generate={
            "done": True,
            "done_reason": "stop",
            "eval_count": 40,
            "response": json.dumps({"results": [{"segment": 0, "code": "Arbeit"}]}),
        },
    )

    class Client:
        def __init__(self, *a, **kw):
            pass

        def get(self, path, timeout):
            return script[path]

        def post(self, path, body, timeout):
            if path == "/api/generate":
                sent.append(body)
            return script[path]

    script["/api/ps"]["models"][0]["digest"] = MODEL_DIGEST
    monkeypatch.setattr(ollama, "_HttpClient", Client)
    f = w.ws.governance / "model.toml"
    f.write_text(model_text())
    f.chmod(0o600)
    result = w.run("continue", RECORD, "--confirm")
    assert sent, "PILOT_INPUT: nothing sent"
    assert all(
        "Testperson Zeta" not in b["prompt"]
        and "test@example.invalid" not in b["prompt"]
        and "PERSON-001" in b["prompt"]
        for b in sent
    ), "PILOT_INPUT: original sent"
    assert result.code == 3, (result.out, result.err)
    assert {"l1.suggestions", "l1.coverage"} <= w.view().have
    assert all(b["model"] == "mistral:7b-instruct" for b in sent)


def test_no_request_before_binding_check(pilot, monkeypatch):
    from ohpipe.application import l1_suggest
    from ohpipe.domain.revision_serialization import verify_revision

    w = pilot.final()
    bound = w.approve()
    original_sha256 = bound.view.facts["transcript.revision"].sha256
    with w.ws.store().open_verified(original_sha256) as handle:
        original_bytes = handle.read()
    inconsistent = replace(
        bound,
        text_sha256=original_sha256,
        revision=verify_revision(original_bytes, original_sha256),
        revision_bytes=original_bytes,
    )
    monkeypatch.setattr(l1_suggest, "read_confirmed_text", lambda *args: inconsistent)

    class NeverCalled:
        def run(self, prompt, params):
            pytest.fail("PILOT_INPUT: request before binding check")

    before_head = w.journal.head()
    before_objects = {path: path.read_bytes() for path in w.ws.objects.iterdir()}
    with pytest.raises(l1_suggest.SuggestError, match="Textbindung vor Modellaufruf"):
        l1_suggest.run_l1_suggest(w.ctx, w.view(), adapter=NeverCalled())
    assert w.journal.head() == before_head
    assert {path: path.read_bytes() for path in w.ws.objects.iterdir()} == before_objects
    assert "l1.suggestions" not in w.view().have


@pytest.mark.parametrize("point", ["init_prepared", "init_head"])
def test_pilot_init_restart(pilot, monkeypatch, point):
    w = pilot

    def interrupt(name):
        if name == point:
            raise OSError("SYNTHETIC_INIT_INTERRUPTION")

    with monkeypatch.context() as patch:
        patch.setattr(work, "hook", interrupt)
        assert w.run("pseudonymisation", "registry", "init").code == 1
    prepared = [e.payload for e in w.journal if e.kind == "p4c.init.prepared"]
    assert len(prepared) == 1
    w.ok(0, "pseudonymisation", "registry", "init")
    assert RegistryStore(w.ws, w.journal.key).head() == prepared[0]["ref"]
    assert sum(e.kind == "p4c.initialised" for e in w.journal) == 1


@pytest.mark.parametrize("changed", [False, True])
def test_pilot_recovery_policy_binding(pilot, monkeypatch, changed):
    w = pilot.final()

    def interrupt(name):
        if name == "prepared":
            raise OSError("SYNTHETIC_REVIEW_INTERRUPTION")

    with monkeypatch.context() as patch:
        patch.setattr(work, "hook", interrupt)
        assert (
            w.run(
                "pseudonymisation",
                "review",
                RECORD,
                "--actor",
                ACTOR,
                tty=True,
                as_json=False,
                answer="BESTÄTIGEN\n",
            ).code
            == 1
        )
    assert GATE not in w.view().have
    before = sum(e.kind == "p4c.completed" for e in w.journal)
    f = w.root / "recovery-profile.toml"
    f.write_bytes(PROFILE.read_bytes())
    f.chmod(0o600)
    w.ctx = replace(w.ctx, profile_arg=str(f))

    def change(name):
        if changed and name == "recovery_head":
            f.write_text(f.read_text().replace("walz-pilot-proposal-v1", "walz-pilot-proposal-v2"))

    with monkeypatch.context() as patch:
        patch.setattr(work, "hook", change)
        if changed:
            with pytest.raises(work.GateError, match="Policybindung"):
                work.recover(w.ctx, ACTOR)
        else:
            assert work.recover(w.ctx, ACTOR) == 1
    assert (GATE in w.view().have) is (not changed)
    assert sum(e.kind == "p4c.completed" for e in w.journal) == before + (not changed)


def test_setup_never_adopts_existing_or_repository_root(tmp_path):
    root = tmp_path / "new"
    prepare(root)
    old = (root / "synthetic-setup.json").read_bytes()
    with pytest.raises(ValueError):
        prepare(root)
    assert (root / "synthetic-setup.json").read_bytes() == old
    with pytest.raises(ProtectionError):
        prepare(PROFILE.parents[4] / "forbidden-synthetic")


def test_setup_real_mode_is_empty_private_and_unselected(tmp_path):
    root = tmp_path / "new-real"
    descriptor = prepare(root, real=True)
    assert descriptor["synthetic_only"] is False
    assert descriptor["real_record_selected"] is False
    assert descriptor["record"] is None
    assert (root / "real-setup.json").is_file()
    assert not (root / "synthetic-setup.json").exists()
    assert not (root / "source/synthetic.srt").exists()
    assert [path.name for path in (root / "source").iterdir()] == ["iso.txt"]
    model_config = root / "data/_governance/model.toml"
    assert descriptor["model_config"] == str(model_config)
    assert "num_predict = 4096" in model_config.read_text()
    for path in root.rglob("*"):
        assert (path.stat().st_mode & 0o777) == (0o700 if path.is_dir() else 0o600)


def test_source_check_never_emits_cue_speaker_or_parser_canary(tmp_path, monkeypatch):
    tool = PROFILE.parents[4] / "tools/walz_pilot_source_check.py"
    secret_label = "GEHEIMCANARY"
    secret_text = "CUECANARY-7f31"
    secret_label_sha256 = hashlib.sha256(secret_label.encode()).hexdigest()
    valid = tmp_path / "WALZ-0003.ohpipe.srt"
    texts = [secret_text] + [f"neutraler Testsatz {index:02d}" for index in range(1, 65)]

    def timecode(seconds):
        minutes, seconds = divmod(seconds, 60)
        return f"00:{minutes:02d}:{seconds:02d},000"

    valid.write_text(
        "\n\n".join(
            f"{index + 1}\n{timecode(index)} --> {timecode(index + 1)}\n"
            f"{secret_label if index == 0 else 'SPEAKER_2'}: {text}"
            for index, text in enumerate(texts)
        )
        + "\n"
    )
    neutral = tmp_path / "WALZ-0004.ohpipe.srt"
    neutral.write_text(valid.read_text().replace(secret_label, "SPEAKER_1"))
    malformed = tmp_path / "WALZ-0003.srt"
    malformed.write_text(f"1\n{secret_text} kein Zeitcode\n{secret_label}: {secret_text}\n")
    metadata_malformed = tmp_path / "WALZ-0005.srt"
    metadata_malformed.write_text(f"1\n00:00:00,000 --> 00:00:01,000\n{secret_label}:\n")

    def checked(path):
        return subprocess.run(
            [
                sys.executable,
                str(tool),
                str(path),
                str(tmp_path / "data"),
                "--record-id",
                "WALZ-0003",
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    good = checked(valid)
    assert good.returncode == 0 and good.stderr == ""
    good_result = json.loads(good.stdout)
    assert good_result["speaker_labels"]["distinct"] == 2
    assert good_result["speaker_labels"] == {
        "distinct": 2,
        "occurrences": 65,
        "warning": "Nichtneutrale Sprecherlabels werden nicht ausgegeben",
    }
    assert good_result["cue_counts"] == {"lossless": 65, "metadata": 65}
    assert good_result["block_size"] == 64
    assert good_result["blocks"] == [
        {
            "block": 1,
            "segments": 64,
            "segment_characters": sum(map(len, texts[:64])),
        },
        {"block": 2, "segments": 1, "segment_characters": len(texts[64])},
    ]
    neutral_result = json.loads(checked(neutral).stdout)
    assert neutral_result["speaker_labels"]["counts"] == {
        "SPEAKER_1": 1,
        "SPEAKER_2": 64,
    }
    bad = checked(malformed)
    assert bad.returncode == 2 and bad.stderr == ""
    assert json.loads(bad.stdout) == {"error": "CUE_DOCUMENT_PARSE_ERROR", "ok": False}
    metadata_bad = checked(metadata_malformed)
    assert metadata_bad.returncode == 2 and metadata_bad.stderr == ""
    assert json.loads(metadata_bad.stdout) == {
        "error": "SRT_METADATA_PARSE_ERROR",
        "ok": False,
    }

    from tools import walz_pilot_source_check as source_check

    document = source_check.CueDocument.parse_bytes(valid.read_bytes(), source_check.CueFormat.SRT)
    with monkeypatch.context() as patch:
        patch.setattr(document.__class__, "render_bytes", lambda self: b"changed")
        result, code = source_check.inspect(valid, None, "WALZ-0003")
        assert code == 2 and result == {"ok": False, "error": "BYTE_ROUNDTRIP_MISMATCH"}
    with monkeypatch.context() as patch:
        patch.setattr(source_check, "parse_srt", lambda text, strict: [])
        result, code = source_check.inspect(valid, None, "WALZ-0003")
        assert code == 2 and result == {"ok": False, "error": "CUE_COUNT_MISMATCH"}

    all_output = (
        good.stdout
        + good.stderr
        + bad.stdout
        + bad.stderr
        + metadata_bad.stdout
        + metadata_bad.stderr
    )
    assert secret_label not in all_output
    assert secret_text not in all_output
    assert secret_label_sha256 not in all_output


def test_runner_reads_both_model_proofs_around_pytest_progress(monkeypatch):
    monkeypatch.syspath_prepend(str(PROFILE.parents[4] / "tools"))
    from model_proof_log import local_model_proofs

    log = (
        'WALZ_LOCAL_MODEL_PROOF {"probe":"single-segment","segments":1}\n'
        '.WALZ_LOCAL_MODEL_PROOF {"probe":"65-segments-64-plus-1","segments":65}\n'
        ".\n2 passed\n"
    )
    assert [proof["segments"] for proof in local_model_proofs(log)] == [65, 1]


def test_reference_validation_rejects_cross_record_schema(pilot):
    from ohpipe.registry_store import validate_ref
    from ohpipe.protected_store import validate_ref as protected_ref

    w = pilot.final()
    a = deepcopy(work.published(w.ctx, list(w.journal), "finalise")["refs"][FINAL])
    a["aad"]["profile"] = "spur-p-manual"
    with pytest.raises(ProtectionError):
        validate_ref(a)
    b = deepcopy(next(e.payload["ref"] for e in w.journal if e.kind == "p4b.checkpoint"))
    b["aad"]["profile"] = "spur-p-manual"
    with pytest.raises(ProtectionError):
        protected_ref(b)


def test_registry_scope_is_not_interchangeable(pilot):
    w = pilot
    config = json.loads(w.registry_config.read_text())
    config["scope"] = "spur-p-synthetic"
    w.registry_config.write_bytes(canonical(config))
    with pytest.raises(ProtectionError):
        RegistryStore(w.ws, w.journal.key)
