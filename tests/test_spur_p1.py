"""P1: übernommene P0-Schutzregressionen und Abnahmematrix, ausschließlich synthetisch."""

from __future__ import annotations

import io
import json
import secrets
import socket
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ohpipe.adapters.models.fixture import FixtureAdapter
from ohpipe.application import l1_suggest
from ohpipe.application.replay import replay
from ohpipe.cli.main import main
from ohpipe.domain.decision import Decision, Verdict
from ohpipe.domain.language_assignment import build_srt_draft
from ohpipe.domain.step import build_graph
from ohpipe.journal import Journal
from ohpipe.policies.authority import Authority
from ohpipe.project import Profile, Workspace

REPO = Path(__file__).resolve().parents[1]
RECORD = "SANDBOX-901"
ACTOR = "SYNTHETIC-ACTOR"
FIELDS = {
    "record_id": RECORD,
    "interview_date": "2026-09-09",
    "interviewer": "SYNTHETIC-INTERVIEWER-P0",
    "consent_status": "research-only",
    "accessRights": "restricted",
    "title": "SYNTHETIC-TITLE-P0",
    "language": "deu",
}


class Terminal(io.StringIO):
    def __init__(self, text="", *, tty=False, on_read=None):
        super().__init__(text)
        self.tty = tty
        self.on_read = on_read
        self.reads = []

    def isatty(self):
        return self.tty

    def readline(self, *args):
        if self.on_read:
            self.reads.append(self.on_read())
        return super().readline(*args)


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    for key in ("OHPIPE_DATA_ROOT", "OHPIPE_JOURNAL_KEY"):
        monkeypatch.delenv(key, raising=False)

    def no_network(*args, **kwargs):
        raise AssertionError("P0: unerlaubter Netzwerkaufruf")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)


class World:
    """Kleinste durch reguläre CLI-Schreiber erzeugte Kette zum jeweiligen Gate."""

    def __init__(self, tmp, monkeypatch, *, production=False):
        tmp.mkdir(parents=True, exist_ok=True)
        self.tmp = tmp
        self.monkeypatch = monkeypatch
        self.key = tmp / "journal.key"
        self.key.write_bytes(secrets.token_bytes(32))
        self.key.chmod(0o600)
        self.profile = tmp / "profile.toml"
        profile = (REPO / "src/ohpipe/profiles/sandbox/profile.toml").read_text()
        if production:
            profile = profile.replace("production = false", "production = true")
        self.profile.write_text(profile)
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
            "Synthetic P0 actor",
            "--reference",
            "SYNTHETIC-P0",
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
            "SYNTHETIC-P0",
            "--confirm",
        )
        self.revision("X", ingress=True)
        self.ok(0, "transcript", "confirm", RECORD, "--actor", ACTOR, "--confirm")
        assert self.view().enabled and not self.view().findings
        assert "transcript.confirmed" in self.view().have

    def run(self, *args, tty=False, answer="", on_read=None, as_json=True):
        stdout, stderr = Terminal(tty=tty), Terminal(tty=tty)
        stdin = Terminal(
            answer,
            tty=tty,
            on_read=lambda: (
                stderr.getvalue(),
                stdout.getvalue(),
                self.state(),
                on_read() if on_read else None,
            ),
        )
        with self.monkeypatch.context() as patch:
            patch.setenv("OHPIPE_JOURNAL_KEY", str(self.key))
            patch.setattr(sys, "stdin", stdin)
            patch.setattr(sys, "stdout", stdout)
            patch.setattr(sys, "stderr", stderr)
            code = main(
                [
                    "--profile",
                    str(self.profile),
                    "--root",
                    str(self.ws.root),
                    *(["--json"] if as_json else []),
                    *args,
                ]
            )
        return SimpleNamespace(
            code=code, out=stdout.getvalue(), err=stderr.getvalue(), reads=stdin.reads
        )

    def ok(self, expected, *args):
        result = self.run(*args)
        assert result.code == expected, (args, result.code, result.out, result.err)
        return result

    def state(self):
        return self.journal.head(), tuple(sorted(p.name for p in self.ws.objects.iterdir()))

    def view(self):
        self.journal.verify()
        return replay(
            self.journal, graph=build_graph(self.ws.profile), authority=Authority.AUTHENTICATED
        )[RECORD]

    def revision(self, label, *, ingress=False):
        srt = self.tmp / f"{label}.srt"
        raw = (
            f"1\n00:00:00,000 --> 00:00:02,000\nZEITZEUGIN: Synthetische Fassung {label}.\n"
        ).encode()
        srt.write_bytes(raw)
        draft = build_srt_draft(raw)
        mapping = self.tmp / f"{label}.tsv"
        mapping.write_text(
            "index\tsegment_sha256\tlanguage\n"
            + "".join(f"{n}\t{s.sha256}\tdeu\n" for n, s in enumerate(draft.segments))
        )
        if ingress:
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
            f"SYNTHETIC-{label}",
            "--confirm",
        )
        self.ok(0, "transcript", "ingest", RECORD, str(srt), str(mapping), "--confirm")

    def preview(self):
        # Produktionskette ausschließlich mit im Speicher eingesetztem Fixtureadapter.
        with self.monkeypatch.context() as patch:
            patch.setattr(l1_suggest, "adapter_for", lambda *a, **kw: FixtureAdapter("stop"))
            self.ok(3, "continue", RECORD, "--confirm")
        self.ok(0, "l1", "review", RECORD, "--actor", ACTOR, "--confirm")
        metadata = self.ws.governance / "metadata" / f"{RECORD}.toml"
        metadata.parent.mkdir(parents=True, exist_ok=True)
        values = FIELDS | {"consent_reference": "SYNTHETIC-P0-NOT-REAL-CONSENT"}
        metadata.write_text(
            "[record]\n"
            + "".join(f"{key} = {json.dumps(value)}\n" for key, value in values.items())
        )
        self.ok(3, "continue", RECORD)
        self.ok(0, "metadata", "confirm", RECORD, "--actor", ACTOR, "--confirm")
        self.ok(3, "continue", RECORD)
        self.ok(0, "abstract", "confirm", RECORD, "--actor", ACTOR, "--confirm")
        self.ok(3, "continue", RECORD)
        view = self.view()
        assert not view.findings and "release.preview" in view.have
        with self.ws.store().open_verified(view.facts["metadata.draft"].sha256) as f:
            metadata_bytes = json.load(f)
        assert metadata_bytes["fields"] == FIELDS
        assert metadata_bytes["open_requirements"] == []


def test_withdraw_blocks_direct_export(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    world.preview()
    world.ok(0, "release", "approve", RECORD, "--actor", ACTOR, "--confirm")
    before = world.view()
    assert "release.approved" in before.have and not before.findings
    # Gegenprobe: dieselbe authentifizierte Freigabe ist vor WITHDRAW exportierbar.
    control = tmp_path / "control.json"
    world.ok(0, "export", RECORD, "--output", str(control), "--confirm")
    assert control.is_file()
    sha = before.facts["release.approved"].sha256
    decision = Decision(
        RECORD, "release.approved", sha, Verdict.WITHDRAW, "SYNTHETIC-P0-WITHDRAW", ACTOR
    )
    payload = {
        key: value for key, value in decision.to_json().items() if key not in {"id", "reason_code"}
    }
    world.journal.append("decision.recorded", payload, record_id=RECORD)
    withdrawn = world.view()
    assert not withdrawn.findings and not withdrawn.provisional
    assert withdrawn.effective_decision_by_artifact["release.approved"].verdict is Verdict.WITHDRAW
    assert "release.approved" not in withdrawn.have
    target = tmp_path / "after-withdraw.json"
    assert not target.exists()
    result = world.run("export", RECORD, "--output", str(target), "--confirm")
    observed = {"exit": result.code, "new_file": target.exists(), "report": json.loads(result.out)}
    print("P0_WITHDRAW_OBSERVED", json.dumps(observed, sort_keys=True))
    assert (result.code, target.exists()) == (3, False), "P0_WITHDRAW: " + json.dumps(observed)


def test_production_release_requires_visible_fields_and_terminal(tmp_path, monkeypatch):
    observations, violations = [], []
    # Jede Variante eigene Wurzel: kein Nulldurchgang verdeckt den Schreibeffekt.
    for tty, confirm, answer in [
        (False, False, ""),
        (False, True, ""),
        (True, False, "b\n"),
        (True, True, "a\n"),
        (True, True, "b\n"),
    ]:
        world = World(tmp_path / f"case-{len(observations)}", monkeypatch, production=True)
        world.preview()
        assert world.ws.profile.production is True
        before = world.state()
        args = ["release", "approve", RECORD, "--actor", ACTOR]
        if confirm:
            args.append("--confirm")
        result = world.run(*args, tty=tty, answer=answer, as_json=False)
        after = world.state()
        machine = [
            json.loads(line.split(" ", 1)[1])
            for line in result.err.splitlines()
            if line.startswith("B3B-VORSCHAU ")
        ]
        # Routing-Record-ID ist bereits Vertragskontext; keine Feldsammlung oder
        # übrigen sechs Feldwerte darf als neue Nutzlast in die JSON-Vorschau.
        machine_text = json.dumps(machine)
        private_values = [v for k, v in FIELDS.items() if k != "record_id"]
        machine_leak = "fields" in machine_text or any(v in machine_text for v in private_values)
        before_text = result.reads[0][0] + result.reads[0][1] if result.reads else ""
        visible_before = "\n".join(
            line for line in before_text.splitlines() if not line.startswith("B3B-VORSCHAU ")
        )
        missing = [k for k, v in FIELDS.items() if v not in visible_before]
        unchanged_at_prompt = all(read[2] == before for read in result.reads)
        observation = {
            "tty": tty,
            "confirm": confirm,
            "answer": answer.strip(),
            "exit": result.code,
            "written": after != before,
            "reads": len(result.reads),
            "missing_before_confirmation": missing,
            "machine_leak": machine_leak,
            "unchanged_at_prompt": unchanged_at_prompt,
            "terminal": result.err + result.out,
        }
        observations.append(observation)
        if machine_leak:
            violations.append("Feldwerte in Maschinenvorschau")
        if not tty and (result.code != 2 or after != before):
            violations.append(
                f"ohne Terminal confirm={confirm}: Exit {result.code}, Schreiben={after != before}"
            )
        if tty:
            if missing or not result.reads or not unchanged_at_prompt:
                violations.append(
                    f"Terminal confirm={confirm}: vor Antwort fehlen {missing}, Leseakte={len(result.reads)}"
                )
            if answer == "a\n" and after != before:
                violations.append("--confirm umgeht ausdruecklichen Abbruch")
            if answer == "b\n" and (result.code != 0 or after == before):
                violations.append("Bewusste Terminalbestaetigung ohne wirksame Freigabe")
    print("P0_FIELDS_OBSERVED", json.dumps(observations, sort_keys=True))
    assert not violations, "P0_FIELDS: " + json.dumps(violations)


def decision(world, artifact, *, kind="decision.recorded", verdict=Verdict.WITHDRAW):
    sha = world.view().facts[artifact].sha256
    bindings = {}
    if verdict is Verdict.ACCEPT:
        bindings = dict(
            input_refs={
                role: world.view().facts[role].sha256
                for role in world.view().graph.producer_of(artifact).requires
            },
            input_refs_version=3,
            profile_id=world.ws.profile.id,
            graph_sha256=world.ws.inspect_graph_binding()[2],
        )
    d = Decision(RECORD, artifact, sha, verdict, "SYNTHETIC-P1-WITHDRAW", ACTOR, **bindings)
    payload = {k: v for k, v in d.to_json().items() if k not in {"id", "reason_code"}}
    world.journal.append(kind, payload, record_id=RECORD)


@pytest.fixture
def released(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch)
    world.preview()
    world.ok(0, "release", "approve", RECORD, "--actor", ACTOR, "--confirm")
    return world


PATHS = [
    (("export", RECORD), "release.approved"),
    (("l1", "review", RECORD), "l1.suggestions"),
    (("metadata", "confirm", RECORD), "metadata.draft"),
    (("abstract", "confirm", RECORD), "abstract.draft"),
    (("release", "approve", RECORD), "release.preview"),
]


@pytest.mark.parametrize(
    "args,artifact", PATHS, ids=["export", "review", "metadata", "abstract", "release"]
)
@pytest.mark.parametrize("obstacle", ["withdraw", "disabled", "finding", "unkeyed"])
def test_direct_paths_require_current_authenticated_replay(released, args, artifact, obstacle):
    world = released
    if obstacle == "withdraw":
        decision(world, artifact)
        assert artifact not in world.view().have
    elif obstacle == "disabled":
        decision(world, "release.approved", kind="record.disabled")
        assert not world.view().enabled
    elif obstacle == "finding":
        # Zulässige Hülle, semantisch unbekanntes Artefakt: echter Replaybefund.
        world.journal.append(
            "artifact.produced",
            {"artifact": "synthetic.unknown", "sha256": "a" * 64},
            record_id=RECORD,
        )
        assert world.view().findings
    else:
        from ohpipe.application.catalog import CONFIRM_GATES, plan_confirm
        from ohpipe.application.export import plan_export
        from ohpipe.application.gate import GateError
        from ohpipe.application.review import plan_l1_review

        # Kein vom Aufrufer bloß angenommener Authentifizierungsdefault.
        events = list(world.journal)
        with pytest.raises(GateError, match="Authentifiziertes"):
            if args[0] == "export":
                plan_export(world.ws, events, record_id=RECORD, output_arg=None)
            elif args[0] == "l1":
                plan_l1_review(world.ws, events, record_id=RECORD, actor_arg=ACTOR)
            else:
                spec, draft, schema = CONFIRM_GATES[args[0] + "_" + args[1]]
                plan_confirm(
                    world.ws,
                    events,
                    record_id=RECORD,
                    actor_arg=ACTOR,
                    spec=spec,
                    draft_artifact=draft,
                    confirmed_schema=schema,
                )
        return
    target = world.tmp / "blocked.json"
    command = [*args, "--confirm"]
    if args[0] == "export":
        command += ["--output", str(target)]
    before = world.state()
    result = world.run(*command)
    report = json.loads(result.out)
    assert result.code == (1 if obstacle == "finding" else 3), report
    assert world.state() == before and not target.exists()
    assert str(world.ws.root) in (report.get("next") or report.get("check") or str(report))


@pytest.mark.parametrize(
    "args,artifact", PATHS, ids=["export", "review", "metadata", "abstract", "release"]
)
def test_direct_plan_change_at_answer_is_not_silently_replaced(released, args, artifact):
    world = released
    at_change = []

    def change():
        world.journal.append(
            "artifact.produced", {"artifact": artifact, "sha256": "b" * 64}, record_id=RECORD
        )
        at_change.append(world.state())

    target = world.tmp / "stale-plan.json"
    command = list(args)
    if args[0] == "export":
        command += ["--output", str(target)]
    result = world.run(*command, tty=True, answer="b\n", on_read=change)
    assert result.reads and result.code == 3, result.out
    assert world.state() == at_change[-1] and not target.exists()


def test_planner_uses_requested_record_not_last_artifact(released):
    world = released
    world.journal.append(
        "artifact.produced",
        {"artifact": "release.approved", "sha256": "c" * 64},
        record_id="SANDBOX-902",
    )
    target = world.tmp / "correct-record.json"
    world.ok(0, "export", RECORD, "--output", str(target), "--confirm")
    assert json.loads(target.read_bytes())["record_id"] == RECORD


@pytest.mark.parametrize("answer", ["", "a\n"])
def test_production_abort_and_eof_have_no_effect(tmp_path, monkeypatch, answer):
    world = World(tmp_path, monkeypatch, production=True)
    world.preview()
    before = world.state()
    result = world.run("release", "approve", RECORD, "--confirm", tty=True, answer=answer)
    assert result.code == 3 and result.reads
    assert world.state() == before


def test_fields_digest_and_machine_privacy(tmp_path, monkeypatch):
    import hashlib

    world = World(tmp_path, monkeypatch, production=True)
    world.preview()
    result = world.run("release", "approve", RECORD, "--confirm", tty=True, answer="b\n")
    assert result.code == 0, result.out
    with world.ws.store().open_verified(world.view().facts["release.approved"].sha256) as handle:
        approval = json.load(handle)
    canonical = (
        json.dumps(
            {"domain": "ohpipe.release.fields", "version": 1, "fields": FIELDS},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    assert approval["fields_sha256"] == hashlib.sha256(canonical).hexdigest()
    assert approval["confirmed"] == world.view().facts["release.preview"].sha256
    machine = result.out + "\n".join(
        line for line in result.err.splitlines() if line.startswith("B3B-VORSCHAU ")
    )
    machine += world.ws.journal_path.read_text()
    for name, value in FIELDS.items():
        if name != "record_id":
            assert value not in machine
    assert '"fields"' not in machine


@pytest.mark.parametrize(
    "change", ["metadata-file", "metadata.draft", "metadata.confirmed", "release.preview"]
)
def test_production_change_after_display_requires_new_confirmation(tmp_path, monkeypatch, change):
    world = World(tmp_path, monkeypatch, production=True)
    world.preview()
    changed = []

    def alter():
        if change == "metadata-file":
            path = world.ws.governance / "metadata" / f"{RECORD}.toml"
            path.write_text(path.read_text().replace(FIELDS["title"], "SYNTHETIC-CHANGED-TITLE"))
        else:
            world.journal.append(
                "artifact.produced", {"artifact": change, "sha256": "b" * 64}, record_id=RECORD
            )
        changed.append(world.state())

    result = world.run(
        "release", "approve", RECORD, "--confirm", tty=True, answer="b\n", on_read=alter
    )
    assert result.code == 3 and result.reads, result.out
    assert all(value in result.reads[0][0] for value in FIELDS.values())
    assert world.state() == changed[-1]
    assert "release.approved" not in world.view().have


def test_redirected_terminal_output_blocks_production(tmp_path, monkeypatch):
    world = World(tmp_path, monkeypatch, production=True)
    world.preview()
    before = world.state()
    stdout, stderr, stdin = Terminal(), Terminal(), Terminal("b\n", tty=True)
    with monkeypatch.context() as patch:
        patch.setenv("OHPIPE_JOURNAL_KEY", str(world.key))
        patch.setattr(sys, "stdin", stdin)
        patch.setattr(sys, "stdout", stdout)
        patch.setattr(sys, "stderr", stderr)
        result = main(
            [
                "--profile",
                str(world.profile),
                "--root",
                str(world.ws.root),
                "--json",
                "release",
                "approve",
                RECORD,
                "--confirm",
            ]
        )
    assert result == 2 and world.state() == before
    assert FIELDS["title"] not in stdout.getvalue() + stderr.getvalue()


@pytest.mark.parametrize(
    "fault", ["before-evidence", "after-evidence", "before-publication", "after-publication"]
)
def test_export_faults_preserve_evidence_and_retry_without_overwrite(released, monkeypatch, fault):
    from ohpipe.application import export

    world = released
    target = world.tmp / "retry.json"
    original_append = Journal._append_locked
    original_publish = export.publish_bytes

    def append(self, fd, kind, payload, **kwargs):
        if (
            fault == "before-evidence"
            and kind == "artifact.produced"
            and payload.get("artifact") == "export.bundle"
        ):
            raise OSError("synthetic before evidence")
        event = original_append(self, fd, kind, payload, **kwargs)
        if (
            fault == "after-evidence"
            and kind == "receipt.recorded"
            and payload.get("artifact") == "export.bundle"
        ):
            raise OSError("synthetic after evidence")
        return event

    def publish(*args, **kwargs):
        if fault == "before-publication":
            raise OSError("synthetic before publication")
        result = original_publish(*args, **kwargs)
        if fault == "after-publication":
            assert result.state == "WRITTEN"
            raise OSError("synthetic after publication")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(Journal, "_append_locked", append)
        patch.setattr(export, "publish_bytes", publish)
        failed = world.run("export", RECORD, "--output", str(target), "--confirm")
    assert failed.code == 1, failed.out
    assert target.exists() == (fault == "after-publication")
    evidence = list(world.journal)
    retry = world.run("export", RECORD, "--output", str(target), "--confirm")
    assert retry.code == (1 if target.exists() and fault == "after-publication" else 0), retry.out
    assert list(world.journal)[: len(evidence)] == evidence
    sha = world.view().facts["export.bundle"].sha256
    assert target.read_bytes() == (world.ws.objects / sha).read_bytes()
    receipts = [
        e
        for e in world.journal
        if e.kind == "receipt.recorded" and e.payload.get("artifact") == "export.bundle"
    ]
    assert len(receipts) == 1
    before = target.read_bytes(), world.state()
    assert world.run("export", RECORD, "--output", str(target), "--confirm").code == 1
    assert (target.read_bytes(), world.state()) == before


def test_export_transaction_never_reenters_public_append(released, monkeypatch):
    world = released

    def forbidden(*args, **kwargs):
        raise AssertionError("public append under journal lock")

    monkeypatch.setattr(Journal, "append", forbidden)
    monkeypatch.setattr(Journal, "append_once", forbidden)
    target = world.tmp / "internal-append.json"
    world.ok(0, "export", RECORD, "--output", str(target), "--confirm")
    assert target.exists()


def test_transaction_snapshot_and_lifetime(released):
    world = released
    with world.journal.transaction() as transaction:
        assert list(transaction) == list(world.journal)
    with pytest.raises(RuntimeError, match="geschlossen"):
        list(transaction)
    with pytest.raises(RuntimeError, match="geschlossen"):
        transaction.append_once("artifact.produced", {}, record_id=RECORD)


@pytest.mark.parametrize("order", ["withdraw-first", "export-first"])
def test_multiprocess_withdraw_and_publication_share_journal_lock(released, order):
    import fcntl
    import multiprocessing
    from contextlib import contextmanager
    from ohpipe.application import export

    world = released
    ctx = multiprocessing.get_context("fork")
    entered, proceed, attempting, withdrawn = [ctx.Event() for _ in range(4)]
    results = ctx.Queue()
    target = world.tmp / "race.json"
    sha = world.view().facts["release.approved"].sha256

    def exporter():
        try:
            if order == "withdraw-first":
                original = Journal.transaction

                @contextmanager
                def transaction(self):
                    entered.set()
                    assert proceed.wait(30), "export barrier timeout"
                    with original(self) as tx:
                        yield tx

                Journal.transaction = transaction
            else:
                original = export._write_export_locked

                def locked(*args):
                    entered.set()
                    assert proceed.wait(30), "export barrier timeout"
                    return original(*args)

                export._write_export_locked = locked
            result = world.run("export", RECORD, "--output", str(target), "--confirm")
            results.put(("export", result.code, result.out))
        except BaseException as exc:
            results.put(("error", repr(exc)))

    def withdrawer():
        try:
            original = fcntl.flock

            def flock(fd, operation):
                if operation == fcntl.LOCK_EX:
                    if order == "export-first":
                        try:
                            original(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        except BlockingIOError:
                            pass
                        else:
                            original(fd, fcntl.LOCK_UN)
                            raise AssertionError(
                                "withdraw acquired export's supposedly held journal lock"
                            )
                    attempting.set()
                return original(fd, operation)

            fcntl.flock = flock
            journal = Journal(world.ws.journal_path, key=world.key.read_bytes())
            d = Decision(
                RECORD, "release.approved", sha, Verdict.WITHDRAW, "SYNTHETIC-P1-RACE", ACTOR
            )
            payload = {k: v for k, v in d.to_json().items() if k not in {"id", "reason_code"}}
            journal.append("decision.recorded", payload, record_id=RECORD)
            withdrawn.set()
            results.put(("withdraw", 0))
        except BaseException as exc:
            results.put(("error", repr(exc)))

    processes = [ctx.Process(target=exporter), ctx.Process(target=withdrawer)]
    try:
        processes[0].start()
        assert entered.wait(30), "export failed to reach barrier"
        processes[1].start()
        assert attempting.wait(30), "withdraw did not use journal flock"
        if order == "withdraw-first":
            assert withdrawn.wait(30), "withdraw deadlocked before export decision"
        else:
            assert not withdrawn.is_set(), "withdraw passed held journal lock"
            assert not target.exists()
        proceed.set()
        for process in processes:
            process.join(30)
            assert not process.is_alive(), "journal deadlock"
            assert process.exitcode == 0
        outcomes = [results.get(timeout=5) for _ in processes]
        assert not any(item[0] == "error" for item in outcomes), outcomes
        expected = 3 if order == "withdraw-first" else 0
        assert next(item[1] for item in outcomes if item[0] == "export") == expected, outcomes
        assert target.exists() == (order == "export-first")
        events = list(world.journal)
        withdrawal = next(e for e in events if e.payload.get("reference") == "SYNTHETIC-P1-RACE")
        receipts = [
            e
            for e in events
            if e.kind == "receipt.recorded" and e.payload.get("artifact") == "export.bundle"
        ]
        assert (receipts[-1].seq < withdrawal.seq) if order == "export-first" else not receipts
        if target.exists():
            bundle = json.loads(target.read_bytes())
            assert bundle["release"]["approved"] == sha
        after = world.tmp / "race-after-withdraw.json"
        assert world.run("export", RECORD, "--output", str(after), "--confirm").code == 3
        assert not after.exists() and not world.view().findings
    finally:
        proceed.set()
        for process in processes:
            if process.pid is not None and process.is_alive():
                process.terminate()
                process.join(5)
        results.close()


@pytest.mark.parametrize("obstacle", ["withdraw", "disabled", "finding"])
def test_export_rechecks_exclusion_and_findings_after_preview(released, obstacle):
    world = released
    after = []

    def change():
        if obstacle == "finding":
            world.journal.append(
                "artifact.produced",
                {"artifact": "synthetic.unknown", "sha256": "a" * 64},
                record_id=RECORD,
            )
        else:
            decision(
                world,
                "release.approved",
                kind="record.disabled" if obstacle == "disabled" else "decision.recorded",
            )
        after.append(world.state())

    target = world.tmp / "changed-after-preview.json"
    result = world.run(
        "export", RECORD, "--output", str(target), tty=True, answer="b\n", on_read=change
    )
    assert result.code == (1 if obstacle == "finding" else 3), result.out
    assert world.state() == after[-1] and not target.exists()


def test_atomic_publication_and_post_link_failure_are_reported(released, monkeypatch):
    import os
    import stat
    from ohpipe.application import local_publish

    world = released
    target = world.tmp / "atomic.json"
    link, fsync = os.link, os.fsync
    boundaries = []

    def linked(source, destination, **kwargs):
        if destination != target.name:
            return link(source, destination, **kwargs)
        assert not target.exists()
        boundaries.append("before-link")
        link(source, destination, **kwargs)
        payload = json.loads(target.read_bytes())
        assert payload["record_id"] == RECORD
        boundaries.append("full-target-after-link")

    def synced(fd):
        if boundaries and stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError("synthetic directory fsync failure after publication")
        return fsync(fd)

    with monkeypatch.context() as patch:
        patch.setattr(local_publish.os, "link", linked)
        patch.setattr(local_publish.os, "fsync", synced)
        result = world.run("export", RECORD, "--output", str(target), "--confirm")
    assert result.code == 1 and boundaries == ["before-link", "full-target-after-link"], result.out
    assert json.loads(result.out)["reason_code"] == "STOP_EXPORT_PERSISTENCE_UNCERTAIN"
    assert json.loads(result.out)["details"]["local_write_state"] == "TARGET_VISIBLE_FULL"
    before = target.read_bytes(), world.state()
    retry = world.run("export", RECORD, "--output", str(target), "--confirm")
    assert retry.code == 1
    details = json.loads(retry.out)["details"]
    assert details["bundle_evidence_state"] == "ALREADY_RECORDED"
    assert details["local_write_state"] == "TARGET_VISIBLE_FULL"
    assert (target.read_bytes(), world.state()) == before


def test_sandbox_confirm_remains_scriptable_and_repeat_is_null(released):
    world = released
    before = world.state()
    result = world.run("release", "approve", RECORD, "--confirm")
    assert result.code == 0 and not result.reads
    assert world.state() == before
    result = world.run("export", RECORD, "--confirm")
    assert result.code == 0
    result = world.run("export", RECORD, "--confirm")
    assert result.code == 0
    details = json.loads(result.out)["details"]
    assert details["operation_result"] == "NULLDURCHGANG"
    assert details["bundle_evidence_state"] == "ALREADY_RECORDED"
    assert details["local_write_state"] == "NONE"


def test_planning_verifies_the_exact_snapshot_after_initial_journal_check(released, monkeypatch):
    world = released
    original = Journal.verify
    altered = []

    def check_then_alter(self):
        original(self)
        lines = self.path.read_text().splitlines()
        last = json.loads(lines[-1])
        last["payload"]["code_version"] = "synthetic-altered-without-mac"
        lines[-1] = json.dumps(last)
        self.path.write_text("\n".join(lines) + "\n")
        altered.append(world.state())

    with monkeypatch.context() as patch:
        patch.setattr(Journal, "verify", check_then_alter)
        result = world.run(
            "export", RECORD, "--output", str(world.tmp / "unverified.json"), "--confirm"
        )
    assert result.code == 1, result.out
    assert "B3B-VORSCHAU" not in result.err
    assert world.state() == altered[-1]
    assert not (world.tmp / "unverified.json").exists()


def test_export_rejects_changed_plan_even_when_new_approval_is_usable(released):
    from ohpipe.application.gate import canonical_bytes
    from ohpipe.domain.hashing import sha256_bytes

    world = released
    old = world.view().facts["release.approved"].sha256
    changed = []

    def replace_approval():
        with world.ws.store().open_verified(old) as handle:
            approval = json.load(handle)
        raw = canonical_bytes({**approval, "synthetic_revision": 2})
        sha = world.ws.store().put(io.BytesIO(raw))
        assert sha == sha256_bytes(raw) and sha != old
        world.journal.append(
            "artifact.produced", {"artifact": "release.approved", "sha256": sha}, record_id=RECORD
        )
        decision(world, "release.approved", verdict=Verdict.ACCEPT)
        world.journal.append(
            "receipt.recorded",
            {
                "artifact": "release.approved",
                "output_sha256": sha,
                "inputs": {"release.preview": approval["confirmed"]},
                "step": "release.approve",
                "code_version": "release-approve/1",
            },
            record_id=RECORD,
        )
        assert "release.approved" in world.view().have
        changed.append(world.state())

    target = world.tmp / "usable-but-different.json"
    result = world.run(
        "export", RECORD, "--output", str(target), tty=True, answer="b\n", on_read=replace_approval
    )
    assert result.code == 3, result.out
    assert "Eingabe seit der Vorschau geaendert" in result.out
    assert world.state() == changed[-1] and not target.exists()
