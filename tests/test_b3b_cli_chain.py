"""Die vier Lücken vor Demo-Moment 1 — geschlossen und über die echte Grenze geprüft.

Gemessen war: ein Sandbox-Record, der jeden B3b-Schritt sauber durchlaufen hat,
stand danach auf ``STOP``. Vier Ursachen, keine davon im Bau von ``continue``:

* **L1** Der gebaute B3b-Ingest hatte keinen CLI-Zweig. ``ohpipe ingest``
  registriert den Record und legt die Quelle ab; die kanonische Fassung
  (``transcript.revision``) entsteht dort nicht.
* **L3** Drei Belege trugen Artefaktnamen, die kein Graphschritt erzeugt.
  ``replay`` legt für solche Namen keine Zeile an und meldet einen Befund —
  fail-closed und richtig, nur war der Name das Problem, nicht der Beleg.
* **L2** ``transcript language prepare`` fiel im Dispatcher durch.
* **L4** ``transcript.confirm`` schrieb keine Bindungsevidenz; die
  Bindungsachse blieb ``UNKNOWN``, und ``UNKNOWN`` ist ``STOP``.

Die Zielaussage steht am Ende: ein frischer Record läuft über das CLI bis vor
den Modellschritt, **ohne Befund**, und ``continue`` nennt den nächsten Befehl.
Sie wird über Unterprozesse geprüft, nicht über die Anwendungsschicht: Die
Lücken saßen alle im CLI oder zwischen CLI und Replay, also genau dort, wo ein
Test auf der Anwendungsschicht nichts gesehen hätte.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from ohpipe.domain.language_assignment import build_srt_draft
from ohpipe.journal import Journal

from ._forge import cli_keyed, forge_keyed, journal_path, place_object, report_lines

RECORD = "SANDBOX-001"

#: Die **ausgelieferte** Beispieldatei — dieselben Bytes, die
#: ``examples/synthetic/durchstich.sh`` und die Handbuchbefehle benutzen.
#: Sie steht hier als Pfad und nicht als Konstante, weil genau die Kopie das
#: Problem war: die Kette lief im Autorenfenster gegen eine eingebaute SRT und
#: auf dem Rechner des Vorführenden gegen diese Datei — und brach dort ab.
AUSGELIEFERT = Path(__file__).resolve().parents[1] / "examples" / "synthetic" / "SANDBOX-001.srt"

#: Die tatsächliche Sprache je Segment der ausgelieferten Datei, in Reihenfolge.
#: Segment 2 ist gemischt (ltz mit deutschem Nachsatz); zugeordnet wird die
#: Sprache des ersten Satzes. Ein Segment trägt genau eine Sprache — die Grenze
#: wird hier benannt, nicht durch Umschreiben des Transkripts versteckt.
AUSGELIEFERTE_SPRACHEN = ("deu", "deu", "ltz", "fra", "deu")

#: Die ausgelieferte KORREKTUR derselben Aufnahme. Zwei Dinge, die eine
#: Transkription regelmaessig verschluckt, sind nachgetragen: der Satz, mit dem
#: das Band anlaeuft, und die Tatsache, dass die Eingangsfrage nach einer
#: Unterbrechung ein zweites Mal gestellt wurde. Genau diese Wiederholung macht
#: den Anker auf die Frage MEHRDEUTIG: das Zitat steht danach zweimal da, und
#: keiner der beiden Kontexte ist der urspruengliche.
KORREKTUR = (
    Path(__file__).resolve().parents[1] / "examples" / "synthetic" / "SANDBOX-001-korrektur.srt"
)
KORREKTUR_SPRACHEN = ("deu", "deu", "deu", "deu", "ltz", "fra", "deu")

SRT = (
    b"1\n00:00:00,500 --> 00:00:05,200\nINTERVIEWER: Wie sah der Schulweg damals aus?\n\n"
    b"2\n00:00:05,600 --> 00:00:13,400\nZEITZEUGIN: Wir sind jeden Morgen zu Fuss gegangen.\n\n"
    b"3\n00:00:14,000 --> 00:00:21,800\nZEITZEUGIN: Das waren gut vierzig Minuten.\n"
)
ISO = b"deu\nund\nzxx\n"

#: Der Wortschatz, den die ausgelieferte Datei braucht. ``und`` und ``zxx``
#: verlangt ``parse_iso6393_snapshot``, der Rest ist der mehrsprachige
#: Charakter des Beispiels.
ISO_MEHRSPRACHIG = b"deu\nfra\nltz\nund\nzxx\n"


def _mapping(srt: bytes, sprache: str = "deu") -> bytes:
    draft = build_srt_draft(srt)
    zeilen = ["index\tsegment_sha256\tlanguage"]
    zeilen += [f"{n}\t{s.sha256}\t{sprache}" for n, s in enumerate(draft.segments)]
    return ("\n".join(zeilen) + "\n").encode("ascii")


def _mapping_je_segment(srt: bytes, sprachen: Sequence[str]) -> bytes:
    """Eine Zuordnung mit **einer Sprache je Segment** — der mehrsprachige Fall.

    Die Zahl der Sprachen muss zur Zahl der Segmente passen. Fehlt eine, ist
    das ein Fehler im Test und keine leere Zeile in der Zuordnung.
    """
    draft = build_srt_draft(srt)
    if len(sprachen) != len(draft.segments):
        raise AssertionError(f"{len(draft.segments)} Segmente, aber {len(sprachen)} Sprachen")
    zeilen = ["index\tsegment_sha256\tlanguage"]
    zeilen += [f"{n}\t{s.sha256}\t{sprachen[n]}" for n, s in enumerate(draft.segments)]
    return ("\n".join(zeilen) + "\n").encode("ascii")


@pytest.fixture
def welt(tmp_path: Path):
    """Ein Arbeitsbereich mit Instanz, ISO-Snapshot und Dateien — sonst nichts."""
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"
    ein = tmp_path / "ein"
    ein.mkdir()
    (ein / "S1.srt").write_bytes(SRT)
    (ein / "iso.txt").write_bytes(ISO)
    (ein / "m.tsv").write_bytes(_mapping(SRT))

    def run(*args: str):
        return cli_keyed(*args, root=wurzel, key=key)

    assert run("init").returncode == 0
    return wurzel, ein, run


def _mit_instanz_und_iso(welt):
    wurzel, ein, run = welt
    assert (
        run(
            "instance",
            "register",
            "KLAUS",
            "--source",
            "mensch",
            "--label",
            "Klaus",
            "--reference",
            "REF-1",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "iso6393",
            "prepare",
            str(ein / "iso.txt"),
            "--release",
            "iso.2025",
            "--reference",
            "REF-2",
            "--confirm",
        ).returncode
        == 0
    )
    return wurzel, ein, run


def _sprachzuordnung(welt, mapping: Path | None = None):
    wurzel, ein, run = _mit_instanz_und_iso(welt)
    ergebnis = run(
        "transcript",
        "language",
        "prepare",
        RECORD,
        str(ein / "S1.srt"),
        str(mapping or ein / "m.tsv"),
        "--actor",
        "KLAUS",
        "--reference",
        "REF-3",
        "--confirm",
    )
    return wurzel, ein, run, ergebnis


def _fassung(welt):
    wurzel, ein, run, ergebnis = _sprachzuordnung(welt)
    assert ergebnis.returncode == 0, ergebnis.stdout
    aufnahme = run(
        "transcript", "ingest", RECORD, str(ein / "S1.srt"), str(ein / "m.tsv"), "--confirm"
    )
    return wurzel, ein, run, aufnahme


def _ereignisse(wurzel: Path) -> list:
    return list(Journal(journal_path(wurzel)))


def _record_json(run) -> dict:
    return json.loads(run("status", "--json").stdout)["details"]["records"][0]


def _bestaetigungsplan(tmp_path: Path):
    """Ein Arbeitsbereich bis unmittelbar vor die Bestaetigung, ohne CLI."""
    from ohpipe.application.confirmation import plan_confirmation
    from ohpipe.application.ingest import plan_b3b_ingest_srt, write_b3b_ingest_srt
    from ohpipe.application.instance_registry import plan_register, write_instance_plan
    from ohpipe.application.iso6393 import plan_iso_prepare, write_iso_prepare
    from ohpipe.application.transcript_language import plan_language_prepare, write_language_prepare
    from ohpipe.domain.iso6393 import parse_iso6393_snapshot
    from ohpipe.domain.revision_serialization import verify_revision
    from ohpipe.project import Profile, Workspace

    profil = Path(__file__).resolve().parents[1] / "src" / "ohpipe" / "profiles" / "sandbox"
    ws = Workspace(tmp_path / "daten", Profile.load(profil / "profile.toml"))
    ws.ensure()
    ws.bind_graph_initially()
    journal = Journal(ws.journal_path)
    (tmp_path / "S1.srt").write_bytes(SRT)
    (tmp_path / "iso.txt").write_bytes(ISO)
    (tmp_path / "m.tsv").write_bytes(_mapping(SRT))

    write_instance_plan(
        ws,
        journal,
        plan_register(list(journal), "KLAUS", source="mensch", label="Klaus", reference="REF-1"),
    )
    write_iso_prepare(
        ws,
        journal,
        plan_iso_prepare(tmp_path / "iso.txt", release_id="iso.2025", reference="REF-2"),
    )
    iso = [e for e in journal if e.kind == "iso6393.snapshot.prepared"][-1]
    wortschatz = parse_iso6393_snapshot(ISO, release_id="iso.2025", reference="REF-2")
    lp = plan_language_prepare(
        record_id=RECORD,
        srt_path=tmp_path / "S1.srt",
        mapping_path=tmp_path / "m.tsv",
        actor="KLAUS",
        reference="REF-3",
        vocabulary=wortschatz,
        iso_snapshot_receipt=iso.digest,
        profile_normalize=ws.profile.normalize_record_id,
        profile_check=ws.profile.is_record_id,
        events=list(journal),
    )
    write_language_prepare(ws, journal, lp)
    sprachbeleg = [
        e
        for e in journal
        if e.kind == "receipt.recorded"
        and e.payload.get("kind") == "transcript.segment_languages.prepared.v1"
    ][-1]
    ip = plan_b3b_ingest_srt(
        record_id=RECORD, assignment=lp.assignment, language_receipt_digest=sprachbeleg.digest
    )
    write_b3b_ingest_srt(ws, journal, ip)
    projektion = [
        e
        for e in journal
        if e.kind == "receipt.recorded"
        and e.payload.get("kind") == "transcript.fulltext.segment_projection.v1"
    ][-1]
    with ws.store().open_verified(ip.revision_sha256) as handle:
        revision = verify_revision(handle.read(), ip.revision_sha256)
    plan = plan_confirmation(
        record_id=RECORD,
        projection_version=revision.projection_version,
        revision_sha256=ip.revision_sha256,
        actor="KLAUS",
        fulltext_origin=projektion.payload["fulltext_origin"],
        fulltext_receipt=projektion.digest,
        iso6393_release=sprachbeleg.payload["iso6393_release"],
        iso6393_vocabulary_sha256=sprachbeleg.payload["iso6393_vocabulary_sha256"],
        iso6393_snapshot_receipt=sprachbeleg.payload["iso6393_snapshot_receipt"],
        events=list(journal),
    )
    return ws, journal, plan


# ------------------------------------------------- L2: der Dispatcherzweig


def test_language_prepare_writes_its_receipt_through_the_cli(welt):
    _wurzel, _ein, _run, ergebnis = _sprachzuordnung(welt)
    assert ergebnis.returncode == 0, ergebnis.stdout
    zeilen = report_lines(ergebnis.stdout)
    assert zeilen["STATUS"].startswith("READY"), zeilen
    belege = [
        e
        for e in _ereignisse(_wurzel)
        if e.kind == "receipt.recorded"
        and e.payload.get("kind") == "transcript.segment_languages.prepared.v1"
    ]
    assert len(belege) == 1, belege
    assert belege[0].payload["target_record_id"] == RECORD


def test_language_prepare_without_an_iso_snapshot_names_the_missing_step(welt):
    wurzel, ein, run = welt
    ergebnis = run(
        "transcript",
        "language",
        "prepare",
        RECORD,
        str(ein / "S1.srt"),
        str(ein / "m.tsv"),
        "--actor",
        "KLAUS",
        "--reference",
        "REF-3",
        "--confirm",
    )
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert zeilen["CHECK"].endswith("iso6393 prepare --help"), zeilen
    assert zeilen["CHANGED"] == "keine"


def test_language_prepare_without_confirm_names_a_runnable_next(welt):
    """Der Bestätigungsweg muss existieren; vorher warf er ``ValueError``."""
    wurzel, ein, run = _mit_instanz_und_iso(welt)
    davor = journal_path(wurzel).read_bytes()
    ergebnis = run(
        "transcript",
        "language",
        "prepare",
        RECORD,
        str(ein / "S1.srt"),
        str(ein / "m.tsv"),
        "--actor",
        "KLAUS",
        "--reference",
        "REF-3",
    )
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert zeilen["NEXT"].endswith("--confirm"), zeilen
    assert "language prepare" in zeilen["NEXT"]
    assert journal_path(wurzel).read_bytes() == davor


# ------------------------------------------------- L1: der Ingestzweig


def test_transcript_ingest_produces_the_canonical_revision(welt):
    wurzel, _ein, _run, aufnahme = _fassung(welt)
    assert aufnahme.returncode == 0, aufnahme.stdout
    ereignisse = _ereignisse(wurzel)
    produced = [
        e
        for e in ereignisse
        if e.kind == "artifact.produced" and e.payload["artifact"] == "transcript.revision"
    ]
    assert len(produced) == 1, produced
    beleg = [
        e
        for e in ereignisse
        if e.kind == "receipt.recorded"
        and e.payload.get("kind") == "transcript.fulltext.segment_projection.v1"
    ]
    assert len(beleg) == 1
    assert beleg[0].payload["output_sha256"] == produced[0].payload["sha256"]


def test_the_declared_srt_input_lies_in_the_store(welt):
    """Eine Eingabe, deren Bytes nirgends liegen, ist eine Referenz ins Leere."""
    wurzel, _ein, run, aufnahme = _fassung(welt)
    assert aufnahme.returncode == 0
    beleg = [
        e
        for e in _ereignisse(wurzel)
        if e.kind == "receipt.recorded"
        and e.payload.get("kind") == "transcript.fulltext.segment_projection.v1"
    ][0]
    for name, adresse in beleg.payload["inputs"].items():
        assert (wurzel / "objects" / adresse).is_file(), name
    assert _record_json(run)["findings"] == []


def test_ingest_recomputes_the_assignment_and_refuses_an_unattested_one(welt):
    """Nicht dem Journal geglaubt: eine andere Mappingdatei ergibt keinen Treffer."""
    wurzel, ein, run, _ = _sprachzuordnung(welt)
    (ein / "falsch.tsv").write_bytes(_mapping(SRT, "und"))
    davor = journal_path(wurzel).read_bytes()
    ergebnis = run(
        "transcript", "ingest", RECORD, str(ein / "S1.srt"), str(ein / "falsch.tsv"), "--confirm"
    )
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert "Sprach-Routingkey" in zeilen["STATUS"], zeilen
    assert zeilen["NEXT"].endswith("--reference '<reference>'"), zeilen
    assert journal_path(wurzel).read_bytes() == davor


def test_ingest_is_a_null_run_the_second_time(welt):
    wurzel, ein, run, erste = _fassung(welt)
    assert erste.returncode == 0
    davor = journal_path(wurzel).read_bytes()
    zweite = run(
        "transcript", "ingest", RECORD, str(ein / "S1.srt"), str(ein / "m.tsv"), "--confirm"
    )
    assert zweite.returncode == 0, zweite.stdout
    assert "bereits bytegleich" in report_lines(zweite.stdout)["STATUS"]
    assert journal_path(wurzel).read_bytes() == davor


def test_the_write_guard_holds_on_this_path_too(tmp_path: Path):
    """ADR 0009: ein zweiter Schreibpfad ohne Eigentumswache waere die Umgehung.

    Geprueft an der ANWENDUNGSSCHICHT, weil die Wache dort steht und nicht im
    CLI: ``write_b3b_ingest_srt`` baut seinen Ledger selbst, damit kein
    Aufrufer ihn weglassen kann — die Reviewoberflaeche eingeschlossen.
    Unbekannte ``childlux``-Records gehoeren dem Vorgaengersystem; ein Ingest
    darf sie nicht anfassen.
    """
    from ohpipe.application.ingest import plan_b3b_ingest_srt, write_b3b_ingest_srt
    from ohpipe.domain.iso6393 import parse_iso6393_snapshot
    from ohpipe.domain.language_assignment import assign_languages
    from ohpipe.policies.ownership import OwnershipError
    from ohpipe.project import Profile, Workspace

    profil = Path(__file__).resolve().parents[1] / "src" / "ohpipe" / "profiles" / "childlux"
    ws = Workspace(tmp_path / "daten", Profile.load(profil / "profile.toml"))
    ws.ensure()
    journal = Journal(ws.journal_path)
    wortschatz = parse_iso6393_snapshot(ISO, release_id="iso.2025", reference="REF-2")
    plan = plan_b3b_ingest_srt(
        record_id="CHILDLUX-0001",
        assignment=assign_languages(
            build_srt_draft(SRT),
            _mapping(SRT),
            target_record_id="CHILDLUX-0001",
            vocabulary=wortschatz,
        ),
        language_receipt_digest="a" * 64,
    )
    vorher = (journal.head(), sorted(p.name for p in ws.objects.iterdir()))
    with pytest.raises(OwnershipError) as exc:
        write_b3b_ingest_srt(ws, journal, plan)
    assert "dinoh" in str(exc.value)
    assert (journal.head(), sorted(p.name for p in ws.objects.iterdir())) == vorher


# ------------------------------------------------- L3: ein Graphname, drei Belege


def test_all_three_b3b_receipts_carry_the_graph_name_and_keep_their_kind(welt):
    wurzel, ein, run, aufnahme = _fassung(welt)
    assert aufnahme.returncode == 0
    volltext = ein / "ft.txt"
    volltext.write_bytes(
        b"Wie sah der Schulweg damals aus?\nWir sind jeden Morgen zu Fuss gegangen.\n"
        b"Das waren gut vierzig Minuten.\n"
    )
    assert (
        run(
            "transcript",
            "fulltext",
            "prepare",
            RECORD,
            str(volltext),
            "--reference",
            "REF-4",
            "--confirm",
        ).returncode
        == 0
    )
    belege = [e for e in _ereignisse(wurzel) if e.kind == "receipt.recorded"]
    arten = {e.payload["kind"] for e in belege}
    assert arten == {
        "transcript.segment_languages.prepared.v1",
        "transcript.fulltext.segment_projection.v1",
        "transcript.fulltext.separate_input.v1",
    }, arten
    assert {e.payload["artifact"] for e in belege} == {"transcript.revision"}


def test_the_separate_fulltext_receipt_does_not_devalue_the_revision(welt):
    """Ein Herkunftsbeleg, dessen Ausgabe nicht die Bytes des Artefakts sind,
    hiesse für ``replay`` ``STALE`` — die Fassung wäre durch ihren eigenen
    Beleg entwertet."""
    wurzel, ein, run, aufnahme = _fassung(welt)
    assert aufnahme.returncode == 0
    revision = [
        e
        for e in _ereignisse(wurzel)
        if e.kind == "artifact.produced" and e.payload["artifact"] == "transcript.revision"
    ][0].payload["sha256"]
    volltext = ein / "ft.txt"
    volltext.write_bytes(b"Ein getrennter Volltext.\n")
    assert (
        run(
            "transcript",
            "fulltext",
            "prepare",
            RECORD,
            str(volltext),
            "--reference",
            "REF-4",
            "--confirm",
        ).returncode
        == 0
    )
    beleg = [
        e
        for e in _ereignisse(wurzel)
        if e.kind == "receipt.recorded"
        and e.payload.get("kind") == "transcript.fulltext.separate_input.v1"
    ][0]
    assert beleg.payload["output_sha256"] == revision
    assert set(beleg.payload["inputs"]) == {"source"}
    zustand = _record_json(run)["artifacts"]["transcript.revision"]
    assert zustand["derivation_state"] == "current", zustand
    assert zustand["status"] == "READY", zustand


# ------------------------------------------------- L4: die Bindungsevidenz


def test_confirm_writes_the_binding_evidence_and_makes_the_gate_ready(welt):
    wurzel, _ein, run, aufnahme = _fassung(welt)
    assert aufnahme.returncode == 0
    ergebnis = run("transcript", "confirm", RECORD, "--confirm")
    assert ergebnis.returncode == 0, ergebnis.stdout
    anker = [
        e
        for e in _ereignisse(wurzel)
        if e.kind == "anchor.checked" and e.payload["artifact"] == "transcript.confirmed"
    ]
    assert len(anker) == 1 and anker[0].payload["outcome"] == "exact"
    zustand = _record_json(run)["artifacts"]["transcript.confirmed"]
    assert (zustand["source_binding"], zustand["decision_state"]) == ("bound", "accepted")
    assert zustand["status"] == "READY", zustand


def test_a_repeated_confirm_restores_a_missing_binding_evidence(welt):
    """Das Fenster zwischen Entscheidung und Bindung wird durch Wiederholung geschlossen.

    Der Abbruch wird gebaut, indem die letzte Zeile — die Bindungsevidenz —
    entfernt wird; die Kette bleibt dabei heil, weil nichts hinter ihr stand.
    Genau so sähe ein Absturz zwischen beiden Schreibvorgängen aus.
    """
    wurzel, _ein, run, aufnahme = _fassung(welt)
    assert aufnahme.returncode == 0
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0
    roh = journal_path(wurzel).read_text(encoding="utf-8").splitlines()
    assert '"anchor.checked"' in roh[-1], roh[-1]
    journal_path(wurzel).write_text("\n".join(roh[:-1]) + "\n", encoding="utf-8")
    assert _record_json(run)["artifacts"]["transcript.confirmed"]["status"] == "STOP"

    ergebnis = run("transcript", "confirm", RECORD, "--confirm")
    assert ergebnis.returncode == 0, ergebnis.stdout
    assert [
        e
        for e in _ereignisse(wurzel)
        if e.kind == "anchor.checked" and e.payload["artifact"] == "transcript.confirmed"
    ]
    assert _record_json(run)["artifacts"]["transcript.confirmed"]["status"] == "READY"


def test_the_null_run_repairs_the_binding_evidence_too(tmp_path: Path):
    """Derselbe Plan zweimal: der Nulldurchgang schreibt keine Entscheidung — aber
    er trägt die fehlende Bindungsevidenz nach, statt sie stehen zu lassen.

    Über die Anwendungsschicht, weil das CLI je Aufruf eine neue
    ``activation_id`` zieht und den Nulldurchgang deshalb nie trifft.
    """
    from ohpipe.application.confirmation import write_confirmation

    ws, journal, plan = _bestaetigungsplan(tmp_path)
    erste = write_confirmation(ws, journal, plan)
    assert erste.reason_code == "READY_B3B_WRITTEN"
    roh = journal.path.read_text(encoding="utf-8").splitlines()
    assert '"anchor.checked"' in roh[-1]
    journal.path.write_text("\n".join(roh[:-1]) + "\n", encoding="utf-8")

    zweite = write_confirmation(ws, journal, plan)
    assert zweite.reason_code == "READY_B3B_NULLDURCHGANG"
    assert "nachgetragen" in zweite.reason
    assert zweite.changed == [str(ws.journal_path)]
    assert [e for e in journal if e.kind == "anchor.checked"]

    dritte = write_confirmation(ws, journal, plan)
    assert dritte.reason_code == "READY_B3B_NULLDURCHGANG"
    assert dritte.changed == [] and "nachgetragen" not in dritte.reason


# ------------------------------------------------- die Zielaussage


def test_a_fresh_record_reaches_the_model_step_without_a_single_finding(welt):
    """Demo-Moment 1: ``continue`` läuft, hält ohne Befund und nennt den Befehl."""
    wurzel, _ein, run, aufnahme = _fassung(welt)
    assert aufnahme.returncode == 0
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0

    ergebnis = run("continue", RECORD)
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert zeilen["STATUS"].startswith("ACTION_NEEDED"), zeilen
    assert "l1.suggest" in zeilen["STATUS"] and "Bestätigung" in zeilen["STATUS"], zeilen
    assert zeilen["NEXT"].endswith("continue SANDBOX-001 --confirm"), zeilen

    record = _record_json(run)
    assert record["findings"] == [], record["findings"]
    assert sorted(record["artifacts"]) == ["transcript.confirmed", "transcript.revision"]
    assert {a["status"] for a in record["artifacts"].values()} == {"READY"}


def test_and_then_the_model_step_runs_and_the_chain_stands_before_coverage(welt):
    wurzel, _ein, run, aufnahme = _fassung(welt)
    assert aufnahme.returncode == 0
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0
    ergebnis = run("continue", RECORD, "--confirm")
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert "Ausgeführt: l1.suggest" in zeilen["STATUS"] and "l1.coverage" in zeilen["STATUS"], (
        zeilen
    )
    record = _record_json(run)
    assert record["findings"] == []
    assert record["artifacts"]["l1.suggestions"]["status"] == "READY"


# ------------------------------------------------- die ausgelieferte Datei


@pytest.fixture
def welt_ausgeliefert(tmp_path: Path):
    """Derselbe Arbeitsbereich — aber mit den **ausgelieferten** Bytes.

    Die Datei wird nicht kopiert und nicht umgeschrieben: der Pfad zeigt in den
    Baum. Wer ``examples/synthetic/SANDBOX-001.srt`` ändert, ändert damit die
    Eingabe dieses Falls, und das ist der ganze Zweck.
    """
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"
    ein = tmp_path / "ein"
    ein.mkdir()
    (ein / "iso.txt").write_bytes(ISO_MEHRSPRACHIG)

    def run(*args: str):
        return cli_keyed(*args, root=wurzel, key=key)

    assert run("init").returncode == 0
    assert (
        run(
            "instance",
            "register",
            "KLAUS",
            "--source",
            "mensch",
            "--label",
            "Klaus",
            "--reference",
            "REF-1",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "iso6393",
            "prepare",
            str(ein / "iso.txt"),
            "--release",
            "iso.2025",
            "--reference",
            "REF-2",
            "--confirm",
        ).returncode
        == 0
    )
    return wurzel, ein, run


def _zuordnung(ein: Path) -> Path:
    """Die Sprachzuordnung zur ausgelieferten Datei — im Testkoerper, nicht in
    der Fixture.

    ``build_srt_draft`` scheitert an einer Cue ohne Sprecher. Stuende dieser
    Aufruf in der Fixture, meldete pytest dafuer ``ERROR`` statt ``FAILED`` —
    und ein ``ERROR`` traegt in der Mutantenbuchhaltung keinen Testnamen. Genau
    dieser Ausfall soll aber einen Namen haben.
    """
    pfad = ein / "m.tsv"
    pfad.write_bytes(_mapping_je_segment(AUSGELIEFERT.read_bytes(), AUSGELIEFERTE_SPRACHEN))
    return pfad


def test_the_shipped_example_carries_a_speaker_on_every_cue():
    """Der Abbruch, den die eingebaute Konstante nicht sehen konnte.

    ``build_srt_draft`` verlangt je Segment einen Sprecher; die ausgelieferte
    Datei trug ihn auf zwei von fünf Cues. Diese Zusicherung fällt, sobald ein
    Präfix aus der Datei verschwindet — mit derselben Meldung, die der
    Vorführende auf seinem Rechner gesehen hat.
    """
    draft = build_srt_draft(AUSGELIEFERT.read_bytes())
    assert [s.speaker for s in draft.segments] == [
        "INTERVIEWER",
        "ZEITZEUGIN",
        "ZEITZEUGIN",
        "INTERVIEWER",
        "ZEITZEUGIN",
    ]
    assert all(
        s.text and not s.text.startswith(("INTERVIEWER", "ZEITZEUGIN")) for s in draft.segments
    )


def test_the_shipped_example_stays_multilingual():
    """deu, ltz, fra — der Grund, warum dieses Beispiel im Repo liegt.

    Ein Sprecherpräfix ist billig anzufügen; die Versuchung, dabei den
    luxemburgischen und den französischen Cue einzudeutschen, ist es auch. Dann
    liefe die Kette grün und bewiese nichts über den ISO-639-3-Wortschatz.
    """
    assert set(AUSGELIEFERTE_SPRACHEN) == {"deu", "ltz", "fra"}
    zuordnung = _mapping_je_segment(AUSGELIEFERT.read_bytes(), AUSGELIEFERTE_SPRACHEN)
    gesetzt = [z.split("\t")[2] for z in zuordnung.decode("ascii").strip().split("\n")[1:]]
    assert gesetzt == list(AUSGELIEFERTE_SPRACHEN)
    assert set(gesetzt) <= set(ISO_MEHRSPRACHIG.decode("ascii").split())


def test_the_shipped_example_runs_the_whole_chain_through_the_cli(welt_ausgeliefert):
    """Die Gegenmaßnahme gegen »im Autorenfenster grün, auf dem Mac rot«.

    Gefahren wird nicht die Konstante dieses Moduls, sondern die Datei, die im
    Vorführskript steht: ``examples/synthetic/durchstich.sh``. Dieselben Bytes,
    dieselben Sprachen, dieselbe Reihenfolge der Befehle. Der Fall muss bei
    jedem weiteren P-Punkt mitlaufen.
    """
    _wurzel, ein, run = welt_ausgeliefert
    zuordnung = _zuordnung(ein)

    vorlage = run(
        "transcript",
        "language",
        "template",
        str(AUSGELIEFERT),
        "--output",
        str(ein / "vorlage.tsv"),
    )
    # Die Vorlage endet mit ACTION_NEEDED, nicht mit 0: sie ist erst halb fertig,
    # solange die Sprachzellen leer sind. Ein Vorführskript mit ``set -e`` bricht
    # hier ab, wenn es das nicht weiss — deshalb steht es hier als Zusicherung.
    assert vorlage.returncode == 3, vorlage.stdout + vorlage.stderr
    assert "Mappingvorlage" in report_lines(vorlage.stdout)["STATUS"]
    kopf, *zeilen = (ein / "vorlage.tsv").read_bytes().decode("ascii").strip().split("\n")
    assert kopf == "index\tsegment_sha256\tlanguage"
    assert len(zeilen) == len(AUSGELIEFERTE_SPRACHEN)
    assert [z.split("\t")[1] for z in zeilen] == [
        z.split("\t")[1] for z in zuordnung.read_bytes().decode("ascii").strip().split("\n")[1:]
    ]

    sprache = run(
        "transcript",
        "language",
        "prepare",
        RECORD,
        str(AUSGELIEFERT),
        str(zuordnung),
        "--actor",
        "KLAUS",
        "--reference",
        "REF-3",
        "--confirm",
    )
    assert sprache.returncode == 0, sprache.stdout + sprache.stderr

    aufnahme = run("transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm")
    assert aufnahme.returncode == 0, aufnahme.stdout + aufnahme.stderr
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0

    ergebnis = run("continue", RECORD)
    zeilen_bericht = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert zeilen_bericht["NEXT"].endswith("continue SANDBOX-001 --confirm"), zeilen_bericht

    record = _record_json(run)
    assert record["findings"] == [], record["findings"]
    assert sorted(record["artifacts"]) == ["transcript.confirmed", "transcript.revision"]
    assert {a["status"] for a in record["artifacts"].values()} == {"READY"}


def test_the_shipped_example_is_not_touched_by_the_chain(welt_ausgeliefert):
    """Der Baum bleibt sauber: die Vorführung liest, sie schreibt nicht zurück."""
    vorher = AUSGELIEFERT.read_bytes()
    _wurzel, ein, run = welt_ausgeliefert
    zuordnung = _zuordnung(ein)
    assert (
        run(
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(AUSGELIEFERT),
            str(zuordnung),
            "--actor",
            "KLAUS",
            "--reference",
            "REF-3",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm"
        ).returncode
        == 0
    )
    assert AUSGELIEFERT.read_bytes() == vorher


DURCHSTICH = Path(__file__).resolve().parents[1] / "examples" / "synthetic" / "durchstich.sh"


def _lauf(tmp_path: Path, pfad_voran: Path | None = None, **zusatz: str):
    """Faehrt ``durchstich.sh`` so, wie ein Mensch es faehrt: als Skript.

    ``pfad_voran`` haengt ein Verzeichnis VOR den PATH — damit stellt der Fall
    unten die Lage des Vorfuehrrechners her.
    """
    import os
    import subprocess

    assert DURCHSTICH.exists(), DURCHSTICH
    assert os.access(DURCHSTICH, os.X_OK), f"{DURCHSTICH.name} ist nicht ausfuehrbar"

    umgebung = dict(os.environ)
    umgebung["OHPIPE_DURCHSTICH_TMP"] = str(tmp_path)
    umgebung.pop("OHPIPE_DATA_ROOT", None)
    umgebung.pop("OHPIPE_JOURNAL_KEY", None)
    if pfad_voran is not None:
        umgebung["PATH"] = f"{pfad_voran}{os.pathsep}{umgebung.get('PATH', '')}"
    umgebung.update(zusatz)

    return subprocess.run(
        [str(DURCHSTICH)],
        capture_output=True,
        text=True,
        check=False,
        cwd=DURCHSTICH.parents[2],
        env=umgebung,
    )


def test_the_demo_script_itself_runs_green(tmp_path: Path):
    """Das Vorfuehrskript selbst — nicht eine Nachbildung davon.

    Der Fall darueber faehrt dieselbe Kette wie ``durchstich.sh``, aber aus
    Python. Zwei Beschreibungen derselben Kette driften auseinander, und
    ausgerechnet die im Repo liegende waere dann die ungeprüfte. Also laeuft
    hier das Skript. Es dauert rund zwei Sekunden und prueft am Ende selbst,
    dass der Record keinen Befund traegt und das Repository unveraendert ist.
    """
    ergebnis = _lauf(tmp_path)
    assert ergebnis.returncode == 0, ergebnis.stdout + ergebnis.stderr
    assert "Befunde: keine" in ergebnis.stdout, ergebnis.stdout
    assert "Durchstich vollstaendig." in ergebnis.stdout, ergebnis.stdout
    # Die Quelle im Protokoll ist die ausgelieferte Datei, nicht irgendeine.
    assert str(AUSGELIEFERT) in ergebnis.stdout, ergebnis.stdout
    assert "ABBRUCH" not in ergebnis.stdout + ergebnis.stderr

    # Und das Skript hat wirklich mehrsprachig zugeordnet. Ohne diese Zeile
    # bestuende es auch, wenn es jedem Segment ``deu`` gaebe — gruen, und ohne
    # eine Aussage ueber den ISO-639-3-Wortschatz.
    #
    # Zwei Tabellen, nicht eine: das Skript ordnet der ausgelieferten Datei zu
    # UND der Korrektur (Moment 2). Beide werden hier gehalten, sonst koennte
    # die zweite still eindeutschen, waehrend die erste den Fall gruen haelt.
    zuordnung = [z for z in ergebnis.stdout.splitlines() if "\t" in z and not z.startswith("index")]
    gesetzt = [z.split("\t")[2] for z in zuordnung]
    assert gesetzt == [*AUSGELIEFERTE_SPRACHEN, *KORREKTUR_SPRACHEN], ergebnis.stdout

    # Die vier Momente stehen IM PROTOKOLL, jeder mit dem Satz aus ROADMAP § 7,
    # den er belegt. Ohne diese Zeilen koennte das Skript die Kette weiter
    # sauber durchlaufen und dabei still aufhoeren, die Vorfuehrung zu sein —
    # genau der Zustand, in dem es am 05.09.2026 war (Moment 3 nur als
    # Kommentar, Moment 4 gar nicht).
    for nummer in (1, 2, 3, 4):
        assert f"########## Demo-Moment {nummer} ##########" in ergebnis.stdout, ergebnis.stdout
    assert ergebnis.stdout.count("ROADMAP § 7:") == 4, ergebnis.stdout

    # Und die zwei Momente, die etwas SCHEITERN lassen, zeigen den Satz des
    # Vertrags, nicht nur einen Exitcode.
    assert "finish_reason='length'" in ergebnis.stdout, ergebnis.stdout
    assert "Eingabebindung veraltet" in ergebnis.stdout, ergebnis.stdout

    # Jede Stufe nennt ihren TATSAECHLICHEN Exitcode, nicht nur den erwarteten.
    # Ohne das verlangt das Protokoll vom Leser Vertrauen in eine Zeile, die er
    # nicht sieht: den Abbruchzweig, der beide gleich haelt.
    # Der Kopf traegt den Baustand. Die Bildschirmaufzeichnung vom 17.09. muss
    # ohne Rueckfrage einem Commit zuzuordnen sein.
    assert "  Baustand     : " in ergebnis.stdout, ergebnis.stdout
    assert "  Zeitpunkt    : " in ergebnis.stdout, ergebnis.stdout

    erwartet = ergebnis.stdout.count("[erwarteter Exitcode")
    tatsaechlich = len([z for z in ergebnis.stdout.splitlines() if z.startswith("Exitcode ")])
    assert erwartet == tatsaechlich > 0, (erwartet, tatsaechlich)


def test_the_demo_script_never_waits_unless_it_is_told_to(tmp_path: Path):
    """Haltepunkte sind fuer den Vorfuehrenden, nicht fuer die Suite.

    Zwei Zusicherungen an einem Lauf. Ohne ``OHPIPE_DURCHSTICH_HALT`` steht
    keine einzige Haltezeile im Protokoll: das Skript verhaelt sich exakt wie
    vorher, und der Fall darueber misst weiter dasselbe. MIT der Variable und
    ohne Terminal laeuft es trotzdem durch — ein Skript, das in einer Pipeline
    auf Enter wartet, haengt bis zum Timeout, und niemand sieht warum.

    Was der Fall NICHT misst: das Warten selbst. Dafuer braucht es ein
    Pseudoterminal, und ein Test, der eine Taste simuliert, misst am Ende die
    Simulation. Der Halt ist eine Zeile und ein ``read``; die Bedingung
    darueber ist das, was schiefgehen kann.
    """
    (tmp_path / "ohne").mkdir()
    (tmp_path / "mit").mkdir()
    ohne = _lauf(tmp_path / "ohne")
    assert ohne.returncode == 0, ohne.stdout + ohne.stderr
    assert "[Enter]" not in ohne.stdout, ohne.stdout
    assert "--- MARKE" not in ohne.stdout, ohne.stdout

    mit = _lauf(tmp_path / "mit", OHPIPE_DURCHSTICH_HALT="1")
    assert mit.returncode == 0, mit.stdout + mit.stderr
    assert "Durchstich vollstaendig." in mit.stdout, mit.stdout
    assert "[Enter]" not in mit.stdout, mit.stdout

    # Die Marken stehen auch ohne Terminal da: sie sind das Kapitelverzeichnis
    # zur Aufzeichnung und nicht die Aufforderung an den, der drueckt. Wer den
    # Lauf mit gesetzter Variable umleitet, bekommt sie als Datei.
    marken = [z for z in mit.stdout.splitlines() if z.startswith("--- MARKE ")]
    assert len(marken) == 5, marken
    assert [z.split(":")[0] for z in marken] == [f"--- MARKE {n}" for n in range(1, 6)], marken


def test_the_demo_script_ignores_a_foreign_ohpipe_on_the_path(tmp_path: Path):
    """Was auf dem PATH liegt, entscheidet nicht, was vorgefuehrt wird.

    Am 05.09.2026 tat es das. Auf dem Vorfuehrrechner lag unter
    /opt/anaconda3/bin/ohpipe eine aeltere Installation; das Skript zog sie dem
    Baum vor, ihr Parser kannte ``instance`` nicht, und Stufe 02 endete mit
    Exitcode 2 statt 0. Im Container fiel das nie auf, weil dort kein ``ohpipe``
    auf dem PATH liegt — der Fall war also gruen und die Vorfuehrung rot.

    Der Fall stellt genau diese Lage her: ein ``ohpipe`` vor dem PATH, das jeden
    Aufruf mit 99 quittiert. Wird es auch nur einmal gefahren, ist der Lauf rot.
    """
    attrappe = tmp_path / "fremder-pfad"
    attrappe.mkdir()
    fremd = attrappe / "ohpipe"
    fremd.write_text("#!/bin/sh\necho FREMDES-OHPIPE-GEFAHREN >&2\nexit 99\n", encoding="utf-8")
    fremd.chmod(0o755)

    ergebnis = _lauf(tmp_path, pfad_voran=attrappe)

    assert ergebnis.returncode == 0, ergebnis.stdout + ergebnis.stderr
    assert "FREMDES-OHPIPE-GEFAHREN" not in ergebnis.stdout + ergebnis.stderr
    assert "Durchstich vollstaendig." in ergebnis.stdout, ergebnis.stdout
    assert "Befunde: keine" in ergebnis.stdout, ergebnis.stdout
    # Und es wird genannt, statt stillschweigend uebergangen: die Stufen zeigen
    # die Nutzerform ``ohpipe ...``, und wer eine davon abschreibt, traefe genau
    # dieses Programm.
    assert f"Auf dem PATH : {fremd} (wird NICHT gefahren)" in ergebnis.stdout, ergebnis.stdout
    # Gefahren wurde der Baum — nachgewiesen an der Modulzeile des Protokolls.
    baum = DURCHSTICH.parents[2] / "src" / "ohpipe"
    assert f"Modul        : {baum}" in ergebnis.stdout, ergebnis.stdout


def test_the_shipped_example_reaches_coverage_over_the_cli(welt_ausgeliefert):
    """P3: dieselbe ausgelieferte Kette, einen Schritt weiter — bis ``l1.coverage``.

    ``continue --confirm`` führt den Modellschritt und die deterministische
    Deckung aus und hält vor dem menschlichen Review. Gefahren wird die
    ausgelieferte Datei, nicht die Modulkonstante.
    """
    _wurzel, ein, run = welt_ausgeliefert
    zuordnung = _zuordnung(ein)
    assert (
        run(
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(AUSGELIEFERT),
            str(zuordnung),
            "--actor",
            "KLAUS",
            "--reference",
            "REF-3",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm"
        ).returncode
        == 0
    )
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0

    ergebnis = run("continue", RECORD, "--confirm")
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 3, ergebnis.stdout
    assert "Ausgeführt: l1.suggest, l1.coverage" in zeilen["STATUS"], zeilen
    assert "l1.review" in zeilen["STATUS"], zeilen

    record = _record_json(run)
    assert record["findings"] == [], record["findings"]
    deckung = record["artifacts"]["l1.coverage"]
    assert deckung["status"] == "READY", deckung
    assert deckung["derivation_state"] == "current", deckung
    assert sorted(record["artifacts"]) == [
        "l1.coverage",
        "l1.suggestions",
        "transcript.confirmed",
        "transcript.revision",
    ]


def test_the_shipped_example_reaches_adjudication_over_the_cli(welt_ausgeliefert):
    """P4: dieselbe ausgelieferte Kette bis zur geschriebenen ``l1.adjudicated``.

    ``continue --confirm`` haelt vor ``l1.review`` und nennt den Reviewbefehl
    (Moment 1). ``l1 review`` ohne ``--confirm`` zeigt die offenen Faelle und
    nennt den Bestaetigungsbefehl; mit ``--confirm`` schreibt es die an die Bytes
    gebundene Entscheidung.
    """
    _wurzel, ein, run = welt_ausgeliefert
    zuordnung = _zuordnung(ein)
    assert (
        run(
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(AUSGELIEFERT),
            str(zuordnung),
            "--actor",
            "KLAUS",
            "--reference",
            "REF-3",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm"
        ).returncode
        == 0
    )
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0

    weiter = run("continue", RECORD, "--confirm")
    wz = report_lines(weiter.stdout)
    assert weiter.returncode == 3, weiter.stdout
    assert "Ausgeführt: l1.suggest, l1.coverage" in wz["STATUS"], wz
    assert wz["NEXT"].endswith(f"l1 review {RECORD}"), wz

    vorschau = run("l1", "review", RECORD)
    vz = report_lines(vorschau.stdout)
    assert vorschau.returncode == 3, vorschau.stdout
    assert vz["CHANGED"] == "keine", vz
    assert vz["NEXT"].endswith(f"l1 review {RECORD} --confirm"), vz

    assert run("l1", "review", RECORD, "--confirm").returncode == 0

    record = _record_json(run)
    assert record["findings"] == [], record["findings"]
    adj = record["artifacts"]["l1.adjudicated"]
    assert adj["status"] == "READY", adj
    assert adj["decision_state"] == "accepted", adj
    assert adj["source_binding"] == "bound", adj
    assert adj["derivation_state"] == "current", adj
    assert sorted(record["artifacts"]) == [
        "l1.adjudicated",
        "l1.coverage",
        "l1.suggestions",
        "transcript.confirmed",
        "transcript.revision",
    ]
    # Der Durchstich steht bis zur geschriebenen l1.adjudicated ohne Befund;
    # continue leitet danach metadata.derive ab und haelt vor metadata.confirm
    # (die drei Katalog-Gates baut P5-P7, geprueft in
    # test_the_shipped_example_reaches_release_approval_over_the_cli).
    danach = run("continue", RECORD)
    dz = report_lines(danach.stdout)
    assert danach.returncode == 3, danach.stdout
    assert "Ausgeführt: metadata.derive" in dz["STATUS"], dz
    assert _record_json(run)["findings"] == []


def _bis_zur_freigabe(welt):
    """Die ausgelieferte Kette bis zur erteilten ``release.approved``.

    Zweimal ausgeschrieben waeren das zwei Beschreibungen derselben Kette, und
    die zweite verrottet still. Der Fall, der die Kette SELBST prueft, steht
    unveraendert in ``test_the_shipped_example_reaches_release_approval_over_the_cli``;
    dieser Helfer ist nur die Vorgeschichte fuer das, was danach kommt.
    """
    wurzel, ein, run = welt
    zuordnung = _zuordnung(ein)
    assert (
        run(
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(AUSGELIEFERT),
            str(zuordnung),
            "--actor",
            "KLAUS",
            "--reference",
            "REF-3",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm"
        ).returncode
        == 0
    )
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0
    assert run("continue", RECORD, "--confirm").returncode == 3
    assert run("l1", "review", RECORD, "--confirm").returncode == 0
    assert run("continue", RECORD).returncode == 3
    assert run("metadata", "confirm", RECORD, "--confirm").returncode == 0
    assert run("continue", RECORD).returncode == 3
    assert run("abstract", "confirm", RECORD, "--confirm").returncode == 0
    assert run("continue", RECORD).returncode == 3
    assert run("release", "approve", RECORD, "--confirm").returncode == 0
    return wurzel, run


def test_the_shipped_example_reaches_the_export_bundle_over_the_cli(welt_ausgeliefert):
    """P8, der Satz von Ingest bis Export — und wovon er haengt.

    ``continue`` legt das Bundle von selbst ab: der Schritt ist billig und
    entscheidet nichts. Vertraglich verlangt ``export.bundle`` trotzdem eine
    Entscheidung (E2-N Nummer 8), und sie wird GEERBT
    (``src/ohpipe/application/replay.py::_inherit_egress_decision``). Der Fall prueft beides an einem
    Stueck: dass der Ausgang ohne zweites Tor READY wird, und dass das Erbe
    faellt, sobald die Freigabe, an der es haengt, andere Bytes traegt. Ein
    Ausgang, der eine Zustimmung ueberdauert, die es nicht mehr gibt, waere
    genau der Fehler, gegen den der Vertrag geschrieben ist.
    """
    wurzel, run = _bis_zur_freigabe(welt_ausgeliefert)

    e = run("continue", RECORD)
    ez = report_lines(e.stdout)
    assert e.returncode == 3, e.stdout
    assert "Ausgeführt: export" in ez["STATUS"], ez

    record = _record_json(run)
    assert record["findings"] == [], record["findings"]
    bundle = record["artifacts"]["export.bundle"]
    assert bundle["status"] == "READY", bundle
    assert bundle["source_binding"] == "bound", bundle
    assert bundle["derivation_state"] == "current", bundle
    # Geerbt, nicht selbst entschieden: es gibt keine decision.recorded auf
    # ``export.bundle``, und trotzdem steht die Entscheidungsachse.
    assert bundle["decision_state"] == "accepted", bundle

    key = wurzel.parent / "journal.key"
    geaendert = place_object(
        wurzel, b'{"schema":"ohpipe.release.approved.v1","edit":"nachtraeglich"}\n'
    )
    forge_keyed(
        wurzel,
        key,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "release.approved", "sha256": geaendert},
            }
        ],
    )
    nachher = _record_json(run)["artifacts"]["export.bundle"]
    assert nachher["decision_state"] != "accepted", nachher
    assert nachher["status"] != "READY", nachher


def test_the_export_writes_the_bundle_where_it_is_told_and_never_over_something(
    welt_ausgeliefert, tmp_path
):
    """Aus dem System heraus geht es erst, wenn ein Ziel genannt ist.

    Drei Aussagen an einem Lauf: mit ``--output`` liegen die Bundlebytes am
    genannten Ort und sind dieselben wie im Store; ein zweiter Lauf auf
    denselben Namen ueberschreibt nichts, sondern haelt; und ein Ziel INNERHALB
    des Datenbaums ist eine Bedienfrage (CONFIG), kein fehlender Schritt —
    ADR 0006 trennt Datenwurzel und Arbeitsplatz, und der Ausgang darf die
    Trennung nicht von innen aufheben.
    """
    wurzel, run = _bis_zur_freigabe(welt_ausgeliefert)
    ziel = tmp_path / "aussen" / f"{RECORD}.bundle.json"
    ziel.parent.mkdir()

    erst = run("export", RECORD, "--output", str(ziel), "--confirm")
    assert erst.returncode == 0, erst.stdout + erst.stderr
    inhalt = ziel.read_bytes()
    geladen = json.loads(inhalt)
    assert geladen["schema"] == "ohpipe.export.bundle.v1", geladen
    assert geladen["record_id"] == RECORD, geladen
    assert geladen["analysis_included"] is False, geladen
    # Dieselben Bytes wie im Store, nicht eine zweite Fassung davon: die Datei
    # traegt genau den Inhalt, unter dessen Adresse das Artefakt abgelegt ist.
    assert (wurzel / "objects" / hashlib.sha256(inhalt).hexdigest()).read_bytes() == inhalt

    zweit = run("export", RECORD, "--output", str(ziel), "--confirm")
    assert zweit.returncode == 1, zweit.stdout + zweit.stderr
    assert ziel.read_bytes() == inhalt

    drin = run("export", RECORD, "--output", str(wurzel / "bundle.json"), "--confirm")
    assert drin.returncode == 2, drin.stdout + drin.stderr
    assert not (wurzel / "bundle.json").exists()


def test_two_exports_of_the_same_record_are_byte_identical(welt_ausgeliefert, tmp_path):
    """Deterministisch heisst: zweimal gerechnet, dieselben Bytes.

    Die ROADMAP verlangt einen deterministischen JSON-Ausgang. Ohne diesen Fall
    waere das eine Behauptung: alle anderen Faelle sehen nur EINEN Lauf.

    Der zweite Export geht in ein ANDERES Zielverzeichnis. Zweimal auf denselben
    Namen zu schreiben wuerde den Overwrite-Schutz messen und nicht den
    Determinismus; verglichen werden die Bytes, nicht der Pfad. Gerechnet wird
    dabei wirklich neu — ``plan_export`` ruft ``build_bundle`` bei jedem Aufruf
    und liest die Kette erneut aus dem Store, statt eine gespeicherte Antwort
    herauszugeben. Der Beleg dafuer steht am Ende: im Journal gibt es genau EINE
    ``artifact.produced`` auf ``export.bundle``, der zweite Lauf hat also
    dieselbe Adresse getroffen und kein zweites Artefakt angelegt.
    """
    wurzel, run = _bis_zur_freigabe(welt_ausgeliefert)
    erst_ziel = tmp_path / "erst" / "bundle.json"
    zweit_ziel = tmp_path / "zweit" / "bundle.json"
    erst_ziel.parent.mkdir()
    zweit_ziel.parent.mkdir()

    erst = run("export", RECORD, "--output", str(erst_ziel), "--confirm")
    assert erst.returncode == 0, erst.stdout + erst.stderr
    zweit = run("export", RECORD, "--output", str(zweit_ziel), "--confirm")
    assert zweit.returncode == 0, zweit.stdout + zweit.stderr

    a = erst_ziel.read_bytes()
    b = zweit_ziel.read_bytes()
    assert a == b, (a[:400], b[:400])
    assert hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest()
    assert (wurzel / "objects" / hashlib.sha256(a).hexdigest()).read_bytes() == a

    zeilen = [
        json.loads(z)
        for z in journal_path(wurzel).read_text(encoding="utf-8").splitlines()
        if z.strip()
    ]
    produziert = [
        z
        for z in zeilen
        if z["kind"] == "artifact.produced" and z["payload"].get("artifact") == "export.bundle"
    ]
    assert len(produziert) == 1, produziert


def _bis_zur_adjudikation(welt):
    """Die ausgelieferte Kette bis zur geschriebenen ``l1.adjudicated``."""
    wurzel, ein, run = welt
    zuordnung = _zuordnung(ein)
    assert (
        run(
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(AUSGELIEFERT),
            str(zuordnung),
            "--actor",
            "KLAUS",
            "--reference",
            "REF-3",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm"
        ).returncode
        == 0
    )
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0
    assert run("continue", RECORD, "--confirm").returncode == 3
    assert run("l1", "review", RECORD, "--confirm").returncode == 0
    return wurzel, ein, run


def _korrigieren(ein: Path, run) -> None:
    """Nimmt die ausgelieferte Korrektur auf — ueber den gebauten Weg.

    Kein eigener Korrekturbefehl: eine korrigierte Fassung aufzunehmen IST
    ``transcript language prepare`` plus ``transcript ingest``. Was fehlte, war
    nicht das Schreiben, sondern die Auskunft darueber, was die Korrektur mit
    den Ankern gemacht hat.
    """
    pfad = ein / "korrektur.tsv"
    pfad.write_bytes(_mapping_je_segment(KORREKTUR.read_bytes(), KORREKTUR_SPRACHEN))
    assert (
        run(
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(KORREKTUR),
            str(pfad),
            "--actor",
            "KLAUS",
            "--reference",
            "KORR-1",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run("transcript", "ingest", RECORD, str(KORREKTUR), str(pfad), "--confirm").returncode == 0
    )


def test_without_a_correction_every_anchor_is_exact(welt_ausgeliefert):
    """Der Nullfall, und er ist keine Formalie.

    Solange die Fassung dieselbe ist, MUSS jeder Anker ``exact`` sein — das ist
    dieselbe Zusicherung, die ``l1.suggest`` beim Setzen prueft. Ein Bericht,
    der schon ohne Korrektur etwas zu melden haette, waere kein Nachweis ueber
    Korrekturen, sondern ein Rauschen.
    """
    _wurzel, _ein, run = _bis_zur_adjudikation(welt_ausgeliefert)
    lauf = run("transcript", "anchors", RECORD)
    assert lauf.returncode == 0, lauf.stdout + lauf.stderr
    bericht = json.loads(run("transcript", "anchors", RECORD, "--json").stdout)["details"]
    assert bericht["same_revision"] is True, bericht
    assert bericht["needs_human"] == 0, bericht
    assert {f["outcome"] for f in bericht["findings"]} == {"exact"}, bericht


def test_a_correction_makes_one_anchor_ambiguous_and_the_machine_does_not_choose(
    welt_ausgeliefert,
):
    """Moment 2, vollstaendig: eine Korrektur macht Anker sichtbar ambiguous.

    Die Korrektur traegt eine wiederholte Eingangsfrage nach. Danach steht das
    Zitat des ersten Ankers ZWEIMAL im Transkript, und keiner der beiden
    Kontexte ist der urspruengliche: ``ambiguous``. Die vier uebrigen Zitate
    stehen weiter genau einmal da, nur an anderer Stelle: ``unique_move``, und
    das darf die Maschine schliessen.

    Die Aussage ist die Trennung, nicht die Zahl. Deshalb wird beides geprueft:
    dass die Mehrdeutigkeit mit ihren Kandidaten VORGELEGT wird, und dass
    nichts sie entscheidet — der Befehl schreibt kein einziges Ereignis, also
    auch keine ``anchor.checked``, die eine Wahl behaupten wuerde.
    """
    wurzel, ein, run = _bis_zur_adjudikation(welt_ausgeliefert)
    _korrigieren(ein, run)

    vorher = journal_path(wurzel).read_bytes()
    lauf = run("transcript", "anchors", RECORD)
    assert lauf.returncode == 3, lauf.stdout + lauf.stderr
    assert journal_path(wurzel).read_bytes() == vorher, "der Ankerbericht hat geschrieben"

    bericht = json.loads(run("transcript", "anchors", RECORD, "--json").stdout)["details"]
    assert bericht["same_revision"] is False, bericht
    assert bericht["needs_human"] == 1, bericht
    ergebnisse = [f["outcome"] for f in bericht["findings"]]
    assert ergebnisse == [
        "ambiguous",
        "unique_move",
        "unique_move",
        "unique_move",
        "unique_move",
    ], ergebnisse
    mehrdeutig = bericht["findings"][0]
    assert len(mehrdeutig["candidates"]) == 2, mehrdeutig
    assert mehrdeutig["needs_human"] is True, mehrdeutig
    # Vorgelegt, nicht gewaehlt: der Bericht sagt ausdruecklich, dass es keinen
    # gebauten Weg gibt, die Wahl zu treffen.
    assert "nicht gebaut" in bericht["resolution"], bericht


def test_a_production_profile_refuses_to_export_a_record_without_its_mandatory_fields(
    welt_ausgeliefert,
):
    """Die Sperre wirkt nur produktiv, und sie nennt die Felder beim Namen.

    Gemessen am Realdatenpfad: das Bundle TEILTE die offenen Pflichtfelder MIT
    (``open_requirements``) und verhinderte nichts. Unter ihnen stehen
    ``consent_status`` und ``accessRights``; ein Katalogpaket ohne sie sagt
    nicht, unter welcher Einwilligung und mit welchen Rechten es hinausgeht.
    Mitteilen reicht an der Systemgrenze nicht.

    Der Fall prueft beide Haelften an denselben Bytes. Mit einem nicht
    produktiven Profil entsteht das Bundle wie bisher — das ist die Zusicherung,
    dass die synthetische Uebungswelt und damit das Vorfuehrskript unveraendert
    bleiben. Mit ``production = true`` faellt derselbe Aufruf, und die Meldung
    traegt die fehlenden Feldnamen, nicht ihre Anzahl.

    Gefahren wird ``build_bundle`` unmittelbar: die Sperre sitzt dort, wo die
    Bytes entstehen, und gilt damit fuer beide Wege, die sie erzeugen
    (``continue`` ueber ``run_export`` und ``ohpipe export`` ueber
    ``plan_export``). Ein Fall je Weg wuerde dieselbe Zeile zweimal messen.
    """
    from types import SimpleNamespace

    from ohpipe.application.export import ExportBlocked, build_bundle
    from ohpipe.store import ContentStore

    wurzel, run = _bis_zur_freigabe(welt_ausgeliefert)
    freigabe = json.loads(run("status", "--json").stdout)["details"]["records"][0]
    assert freigabe["artifacts"]["release.approved"]["status"] == "READY", freigabe

    ereignisse = [
        json.loads(z)
        for z in journal_path(wurzel).read_text(encoding="utf-8").splitlines()
        if z.strip()
    ]
    freigabe_sha = [
        e["payload"]["sha256"]
        for e in ereignisse
        if e["kind"] == "artifact.produced" and e["payload"].get("artifact") == "release.approved"
    ][-1]

    speicher = ContentStore(wurzel)

    def welt(produktiv: bool):
        return SimpleNamespace(
            profile=SimpleNamespace(production=produktiv, id="probe"),
            store=lambda: speicher,
        )

    # Nicht produktiv: unveraendert. Das Bundle entsteht und nennt die offenen
    # Felder, wie es das seit P8 tut.
    daten, zusammenfassung = build_bundle(welt(False), RECORD, freigabe_sha)
    assert zusammenfassung["open_requirements"] == 6, zusammenfassung
    assert json.loads(daten)["catalog"]["metadata"]["open_requirements"], daten

    # Produktiv: derselbe Aufruf faellt, und zwar mit Namen.
    with pytest.raises(ExportBlocked) as gefallen:
        build_bundle(welt(True), RECORD, freigabe_sha)
    meldung = str(gefallen.value)
    for feld in (
        "accessRights",
        "consent_status",
        "interview_date",
        "interviewer",
        "language",
        "title",
    ):
        assert feld in meldung, meldung
    assert "produktiv" in meldung, meldung


def test_a_change_to_the_bound_bytes_shows_the_adjudication_stale(welt_ausgeliefert):
    """Moment 4, zweite Haelfte: nach der Entscheidung eine Aenderung an den
    gebundenen Bytes, und das Artefakt steht sichtbar auf STALE. Kein P2b.

    Die Aenderung ist ein neuer ``artifact.produced`` mit anderer sha; der
    deterministische Beleg zeigt weiter auf die alten Bytes, und ``replay``
    entwertet die Ableitungsachse (Zeile 160, ``receipt_for != sha256``).
    """
    _wurzel, ein, run = welt_ausgeliefert
    zuordnung = _zuordnung(ein)
    assert (
        run(
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(AUSGELIEFERT),
            str(zuordnung),
            "--actor",
            "KLAUS",
            "--reference",
            "REF-3",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm"
        ).returncode
        == 0
    )
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0
    assert run("continue", RECORD, "--confirm").returncode == 3
    assert run("l1", "review", RECORD, "--confirm").returncode == 0

    vorher = _record_json(run)["artifacts"]["l1.adjudicated"]
    assert vorher["status"] == "READY" and vorher["derivation_state"] == "current", vorher

    key = _wurzel.parent / "journal.key"
    geaendert = place_object(
        _wurzel, b'{"schema":"ohpipe.l1.adjudicated.v1","edit":"nachtraeglich"}\n'
    )
    forge_keyed(
        _wurzel,
        key,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "l1.adjudicated", "sha256": geaendert},
            }
        ],
    )
    nachher = _record_json(run)["artifacts"]["l1.adjudicated"]
    assert nachher["derivation_state"] == "stale", nachher
    assert nachher["status"] != "READY", nachher


def test_the_shipped_example_reaches_release_approval_over_the_cli(welt_ausgeliefert):
    """P5-P7: dieselbe ausgelieferte Kette bis zur erteilten ``release.approved``.

    Nach der Adjudikation leitet ``continue`` deterministisch ``metadata.derive``
    ab und haelt vor ``metadata.confirm``; nach der Bestaetigung ebenso
    ``abstract.derive``/``abstract.confirm`` und ``release.preview``/
    ``release.approve``. Drei Gates, drei Bestaetigungen ueber DIESELBE Mechanik
    wie ``l1.review`` (``application/gate.py``). Am Ende: kein Befund, alle
    Artefakte READY, die drei Bestaetigungen ``accepted`` und ``bound``.
    """
    _wurzel, ein, run = welt_ausgeliefert
    zuordnung = _zuordnung(ein)
    assert (
        run(
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(AUSGELIEFERT),
            str(zuordnung),
            "--actor",
            "KLAUS",
            "--reference",
            "REF-3",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm"
        ).returncode
        == 0
    )
    assert run("transcript", "confirm", RECORD, "--confirm").returncode == 0
    assert run("continue", RECORD, "--confirm").returncode == 3
    assert run("l1", "review", RECORD, "--confirm").returncode == 0

    # continue leitet metadata.derive (billig) ab und haelt vor metadata.confirm.
    m = run("continue", RECORD)
    mz = report_lines(m.stdout)
    assert m.returncode == 3, m.stdout
    assert "Ausgeführt: metadata.derive" in mz["STATUS"], mz
    assert mz["NEXT"].endswith(f"metadata confirm {RECORD}"), mz
    # Vorschau ohne --confirm nennt den Bestaetigungsbefehl; mit --confirm schreibt es.
    vorschau = run("metadata", "confirm", RECORD)
    assert vorschau.returncode == 3, vorschau.stdout
    assert report_lines(vorschau.stdout)["NEXT"].endswith(f"metadata confirm {RECORD} --confirm")
    assert run("metadata", "confirm", RECORD, "--confirm").returncode == 0

    a = run("continue", RECORD)
    az = report_lines(a.stdout)
    assert a.returncode == 3, a.stdout
    assert "Ausgeführt: abstract.derive" in az["STATUS"], az
    assert az["NEXT"].endswith(f"abstract confirm {RECORD}"), az
    assert run("abstract", "confirm", RECORD, "--confirm").returncode == 0

    r = run("continue", RECORD)
    rz = report_lines(r.stdout)
    assert r.returncode == 3, r.stdout
    assert "Ausgeführt: release.preview" in rz["STATUS"], rz
    assert rz["NEXT"].endswith(f"release approve {RECORD}"), rz
    assert run("release", "approve", RECORD, "--confirm").returncode == 0

    record = _record_json(run)
    assert record["findings"] == [], record["findings"]
    for art in ("metadata.confirmed", "abstract.confirmed", "release.approved"):
        st = record["artifacts"][art]
        assert st["status"] == "READY", (art, st)
        assert st["decision_state"] == "accepted", (art, st)
        assert st["source_binding"] == "bound", (art, st)
    # Die Ableitungen tragen einen aktuellen Beleg (Moment 4 greift auch hier).
    assert record["artifacts"]["metadata.draft"]["derivation_state"] == "current"
    assert record["artifacts"]["release.preview"]["derivation_state"] == "current"
    assert sorted(record["artifacts"]) == [
        "abstract.confirmed",
        "abstract.draft",
        "l1.adjudicated",
        "l1.coverage",
        "l1.suggestions",
        "metadata.confirmed",
        "metadata.draft",
        "release.approved",
        "release.preview",
        "transcript.confirmed",
        "transcript.revision",
    ]
