"""J1: Das Journal folgt keinem Symlink.

Diese Datei ist der Rotnachweis zu H1. Sie folgt dem in `A1-F4` eingefrorenen
Vertrag, **nicht** dem, was der Code heute tut. Wo beides auseinanderfällt, ist
der Test rot und der Vertrag hat recht.

Der Befund, gegen den sie antritt, ist gemessen: ``Path.exists()`` meldet bei
einem gebrochenen Symlink **Abwesenheit, obwohl der Pfad belegt ist**. Daraus
wird heute „kein Journal", und „kein Journal" ist READY-fähig. Ein grünes
``doctor`` auf einem Arbeitsbereich, dessen Evidenz durch einen Link ersetzt
wurde, ist die gefährlichste Form von Falschaussage, weil sie beruhigt.

Vertrag, kurz:

* Ein Symlink auf Journal- oder Lockpfad — oder auf einer Verzeichniskomponente
  unterhalb der Wurzel — ist ein **Befund**, kein Datenzustand.
* ``JournalUnsafe`` ist Unterklasse von ``JournalBroken``, damit bestehende
  Aufrufer fail-closed bleiben.
* Fehlerdomäne: ``ELOOP``, ``EMLINK``, ``ENOTDIR``, ``ENXIO``, ``EISDIR`` und
  jeder Endpunkt, der nicht ``S_ISREG`` ist.
* Report: ``STOP`` · ``STOP_JOURNAL_UNSAFE`` · rc **1** · ``changed == []`` ·
  ``next is None`` · ``check is None`` · ``RECOVER_JOURNAL_PATH`` ·
  ``details["pfad"] == str(path)`` · ``reason`` einzeilig **und pfadfrei**.

Warum ``check is None`` und nicht ein ``ls -ld <pfad>``: ``Report.__post_init__``
lehnt jeden CHECK ab, der ``;``, ``|`` oder ``&`` als Teilzeichenkette enthält.
Ein zulässiger Wurzelname wie ``fall & review`` würde den Reportbau also mit
``ValueError`` sprengen und den eigentlichen Befund verdecken. ``shlex.join``
hilft dagegen nicht — es quotet, es entfernt nichts.
"""

from __future__ import annotations

import errno
import json
import os
import signal
import subprocess
import sys
from contextlib import contextmanager
from pathlib import Path

import pytest

from ._forge import REPO, cli, journal_path, report_lines

REASON_CODE = "STOP_JOURNAL_UNSAFE"
RECOVERY_CODE = "RECOVER_JOURNAL_PATH"
STOP_RC = 1  # Exit.STOP == 1. rc 3 waere ACTION_NEEDED und damit das Gegenteil.

FAELLE = ("dangling", "fremdziel")

#: Klasse je Testfunktion — die Nodetabelle wird daraus gebaut, nicht von Hand
#: gepflegt. ROTNACHWEIS: am Sockel FAILED, Zusage die J1 erst herstellt.
#: SCHUTZ: am Sockel PASSED, muss nach dem Bau grün bleiben.
#: ERHALTUNG: am Sockel PASSED, bestehende Eigenschaft, Regressionsnetz.
#: Ob die tatsächliche Klasse stimmt, entscheidet der Lauf — hier steht die
#: **deklarierte** Klasse, und ``test_every_node_declares_its_class`` verhindert,
#: dass eine Zeile ohne Deklaration durchrutscht.
KLASSEN: dict[str, str] = {
    "test_reading_a_symlinked_journal_is_refused": "ROTNACHWEIS",
    "test_doctor_stops_instead_of_reporting_ready_on_a_symlinked_journal": "ROTNACHWEIS",
    "test_appending_to_a_symlinked_journal_is_refused": "ROTNACHWEIS",
    "test_locking_a_symlinked_lockfile_is_refused": "ROTNACHWEIS",
    "test_ingest_refuses_a_symlinked_journal": "ROTNACHWEIS",
    "test_a_directory_at_the_journal_path_is_refused_on_read": "ROTNACHWEIS",
    "test_a_directory_at_the_journal_path_is_refused_on_append": "ROTNACHWEIS",
    "test_a_directory_at_the_lock_path_is_refused": "ROTNACHWEIS",
    "test_a_fifo_at_the_journal_path_is_refused_without_blocking": "ROTNACHWEIS",
    "test_a_symlinked_parent_cannot_move_the_journal_out_of_the_root": "ROTNACHWEIS",
    "test_a_broken_symlink_is_presence_not_absence": "ROTNACHWEIS",
    "test_a_missing_parent_is_unsafe_on_write_and_creates_nothing": "ROTNACHWEIS",
    "test_a_stop_after_ensure_reports_what_init_created": "ROTNACHWEIS",
    "test_the_j1_report_reason_is_single_line_and_path_free": "ROTNACHWEIS",
    "test_the_j1_six_lines_survive_a_root_named_with_newline_ampersand_pipe_semicolon_and_quotes": "ROTNACHWEIS",
    "test_details_pfad_is_a_string_and_survives_a_json_roundtrip": "ROTNACHWEIS",
    "test_journal_unsafe_is_not_swallowed_by_journal_broken": "ROTNACHWEIS",
    "test_both_eloop_and_emlink_map_to_journal_unsafe": "ROTNACHWEIS",
    "test_the_lock_path_goes_through_the_same_primitive": "ROTNACHWEIS",
    "test_a_directory_at_the_lock_path_is_eisdir_not_a_crash": "ROTNACHWEIS",
    "test_a_fifo_at_the_lock_path_is_enxio_and_does_not_block": "ROTNACHWEIS",
    "test_a_fifo_as_parent_cannot_hang_the_run": "ROTNACHWEIS",
    "test_a_racing_enoent_on_the_creating_open_is_retried_exactly_once": "ROTNACHWEIS",
    "test_a_second_enoent_on_the_creating_open_is_a_finding_not_a_third_try": "ROTNACHWEIS",
    "test_a_failing_root_probe_forbids_the_retry_entirely": "ROTNACHWEIS",
    "test_the_size_check_reads_from_the_descriptor_not_the_path": "ROTNACHWEIS",
    "test_every_j1_report_keeps_the_operator_contract": "ROTNACHWEIS",
    "test_a_missing_parent_is_pristine_on_read": "SCHUTZ",
    "test_init_on_an_empty_root_is_pristine_not_unsafe": "SCHUTZ",
    "test_every_node_declares_its_class": "SCHUTZ",
    "test_the_probe_payload_reaches_the_write_path": "SCHUTZ",
    "test_a_missing_endpoint_on_the_read_path_is_never_retried": "ERHALTUNG",
    "test_the_lockfile_is_reused_and_not_exclusively_created": "ERHALTUNG",
    "test_a_missing_endpoint_is_created_in_place_in_the_checked_parent": "ERHALTUNG",
}


# --------------------------------------------------------------------------- #
# Hilfen
# --------------------------------------------------------------------------- #


def _init(root: Path) -> dict:
    result = cli("init", "--json", root=root)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def _report(result: subprocess.CompletedProcess) -> dict:
    assert result.stdout.strip(), result.stderr
    return json.loads(result.stdout)


def _lock_path(root: Path) -> Path:
    p = journal_path(root)
    return p.with_suffix(p.suffix + ".lock")


def _probe(nr: str = "A") -> tuple[str, dict[str, str], str]:
    """Die **einzige** Nutzlast, mit der diese Datei das Journal beschreibt.

    ``check_payload`` steht in ``journal.py`` am Kopf beider Schreibwege
    (``append_once`` Z.307, ``append`` Z.319) und lehnt eine unbekannte
    Ereignisart ab, **bevor** die Sperre genommen und irgendeine Datei angefasst
    wird. Eine Probe mit erfundener Art — ``j1.probe``, ``test.event`` — erreicht
    ihre Messstelle deshalb nie: rot aus dem falschen Grund, und rot bliebe sie
    auch nach dem Bau.

    Genau dieser Fehler ist mir dreimal unterlaufen, an drei verschiedenen
    Knoten. Er ist hier an **einer** Stelle behoben statt an drei Aufrufstellen;
    ``test_the_probe_payload_reaches_the_write_path`` ist die zugehörige
    Aufruferwache.

    ``record.registered`` verlangt ``record_id`` und ``profile`` in der Nutzlast
    und dieselbe ``record_id`` in der Hülle. Ein einziges zusätzliches Feld
    genügt, um wieder vor der Messstelle zu scheitern — die Wache lehnt ab, sie
    filtert nicht.
    """
    kennung = f"J1-PROBE-{nr}"
    return "record.registered", {"record_id": kennung, "profile": "sandbox"}, kennung


def _cli_zeitbegrenzt(*args: str, root: Path, timeout: float = 20.0) -> subprocess.CompletedProcess:
    """Wie ``_forge.cli``, aber mit hartem Zeitlimit.

    Bewusst ein eigener Aufruf statt einer Erweiterung von ``_forge.cli``: Für
    den FIFO-Fall **ist** das Zeitlimit die Zusage. Ohne ``O_NONBLOCK`` blockiert
    das Öffnen einer FIFO ohne Gegenstelle unbegrenzt; ein Test ohne Limit würde
    dann nicht fallen, sondern den ganzen Lauf anhalten — und ein hängender
    Mutantensweep ist kein Befund, sondern ein Ausfall.
    """
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(REPO / "src"),
        "OHPIPE_DATA_ROOT": str(root),
    }
    return subprocess.run(
        [sys.executable, "-m", "ohpipe.cli.main", "--profile", "sandbox", *args],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
        env=env,
        timeout=timeout,
    )


def _lege_symlink(ziel_pfad: Path, fall: str, tmp_path: Path) -> Path:
    """Ersetzt ``ziel_pfad`` durch einen Symlink und gibt das Linkziel zurück."""
    if ziel_pfad.exists() or ziel_pfad.is_symlink():
        ziel_pfad.unlink()
    aussen = tmp_path / "ausserhalb"
    aussen.mkdir(exist_ok=True)
    if fall == "fremdziel":
        ziel = aussen / "fremde-datei"
        ziel.write_bytes(b"fremde bytes, die niemand anfassen darf\n")
    else:
        ziel = aussen / "gibt-es-nicht"
    ziel_pfad.symlink_to(ziel)
    return ziel


def _pruefe_befund_kern(report: dict, rc: int, pfad: Path) -> None:
    """Der Reportvertrag ohne ``changed`` — für die Schreibpfade über ``init``.

    ``changed`` wird hier nicht mitgeprüft, weil es auf dem ``init``-Pfad **nicht
    leer sein darf**, sobald ``ws.ensure()`` gelaufen ist. Die Regel lautet nicht
    „J1-STOP hat ``changed == []``", sondern: ``changed`` nennt genau das, was
    dieser Lauf angelegt hat. Lese-, Anhänge- und Lockpfad legen nichts an, also
    ``[]``; der ``init``-Pfad nach der Anlage nennt ``created``.
    Geprüft wird das eigens in
    ``test_a_stop_after_ensure_reports_what_init_created``.
    """
    assert rc == STOP_RC, f"rc {rc}, erwartet {STOP_RC} (Exit.STOP)"
    assert report["status"] == "STOP"
    assert report["reason_code"] == REASON_CODE
    assert report["exit_code"] == STOP_RC
    assert report["source_data_touched"] is False
    assert report["next"] is None
    assert report["check"] is None, "CHECK muss None sein — sonst bricht ein Name mit & ; |"
    assert report["recovery_code"] == RECOVERY_CODE
    assert report["recovery_text"], "recovery_code und recovery_text sind ein Paar"
    assert report["details"].get("pfad") == str(pfad)
    # reason ist einzeilig UND pfadfrei: `reason` steht nicht im
    # Zeilenumbruchverbot von __post_init__ und wird trotzdem gerendert.
    assert report["reason"].splitlines() == [report["reason"]]
    assert str(pfad) not in report["reason"]
    assert pfad.name not in report["reason"]


def _pruefe_befund(report: dict, rc: int, pfad: Path) -> None:
    """Der volle Vertrag — für die Lesepfade, die nichts anlegen dürfen."""
    _pruefe_befund_kern(report, rc, pfad)
    assert report["changed"] == []


def _vorbereitete_wurzel(tmp_path: Path) -> Path:
    """Wurzel mit ``_governance``, aber ohne ``init``.

    **Berichtigung.** Eine frühere Fassung dieses Docstrings behauptete,
    ``append_once`` werde „im ganzen CLI genau einmal" aufgerufen und der
    Schreibpfad sei nur über ``init`` erreichbar. Das war eine Messung mit zu
    engem Geltungsbereich: gesucht wurde nur in ``cli/main.py``. Repoweit gibt es
    **drei** Aufrufstellen:

    ```text
    `src/ohpipe/cli/main.py::cmd_init`          eine Stelle
    `src/ohpipe/application/ingest.py::ingest`  zwei Stellen:
                                                record.registered und
                                                source.ingested
    ```

    ``ohpipe ingest`` erreicht den Schreib- und Lockpfad also ebenfalls, über die
    Anwendungsschicht und zweimal innerhalb derselben Sperre — und ist der
    realistischere Operatorweg, weil er auf einem bereits angelegten
    Arbeitsbereich läuft. Diese Vorbereitung dient dem ``init``-Weg; der
    ``ingest``-Weg hat eigene Tests.
    """
    root = tmp_path / "daten"
    (root / "_governance").mkdir(parents=True)
    return root


def _pruefe_kein_rueckstand(linkpfad: Path, ziel: Path, fall: str, vorher: bytes | None) -> None:
    assert linkpfad.is_symlink(), "der Link muss ein Link bleiben"
    if fall == "fremdziel":
        assert ziel.read_bytes() == vorher, "das Aussenziel wurde angefasst"
    else:
        assert not ziel.exists(), "das dangling Ziel wurde angelegt"


# --------------------------------------------------------------------------- #
# Symlink am Journalpfad — je Öffnung, je Fall
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("fall", FAELLE)
def test_reading_a_symlinked_journal_is_refused(tmp_path, fall):
    root = tmp_path / "daten"
    _init(root)
    pfad = journal_path(root)
    ziel = _lege_symlink(pfad, fall, tmp_path)
    vorher = ziel.read_bytes() if fall == "fremdziel" else None

    ergebnis = cli("status", "--json", root=root)
    _pruefe_befund(_report(ergebnis), ergebnis.returncode, pfad)
    _pruefe_kein_rueckstand(pfad, ziel, fall, vorher)


@pytest.mark.parametrize("fall", FAELLE)
def test_doctor_stops_instead_of_reporting_ready_on_a_symlinked_journal(tmp_path, fall):
    """Der Reviewer-1-Befund: gebrochener Symlink -> doctor meldete READY, rc 0."""
    root = tmp_path / "daten"
    _init(root)
    pfad = journal_path(root)
    ziel = _lege_symlink(pfad, fall, tmp_path)
    vorher = ziel.read_bytes() if fall == "fremdziel" else None

    ergebnis = cli("doctor", "--json", root=root)
    _pruefe_befund(_report(ergebnis), ergebnis.returncode, pfad)
    _pruefe_kein_rueckstand(pfad, ziel, fall, vorher)


@pytest.mark.parametrize("fall", FAELLE)
def test_appending_to_a_symlinked_journal_is_refused(tmp_path, fall):
    """Der eigentliche Schaden: ``init`` schreibt durch den Link nach draussen.

    Bei einem dangling Link meldet ``exists()`` Abwesenheit, ``init`` haelt die
    Wurzel fuer pristine — und legt die Evidenz ausserhalb der Datenwurzel an.

    ``init`` ist **einer** von zwei Schreibwegen (``append_once`` in
    `src/ohpipe/cli/main.py::cmd_init` und zweimal in
    `src/ohpipe/application/ingest.py::ingest`). Den
    zweiten prueft ``test_ingest_refuses_a_symlinked_journal``.
    """
    root = _vorbereitete_wurzel(tmp_path)
    pfad = journal_path(root)
    ziel = _lege_symlink(pfad, fall, tmp_path)
    vorher = ziel.read_bytes() if fall == "fremdziel" else None

    ergebnis = cli("init", "--json", root=root)
    _pruefe_befund_kern(_report(ergebnis), ergebnis.returncode, pfad)
    _pruefe_kein_rueckstand(pfad, ziel, fall, vorher)


@pytest.mark.parametrize("fall", FAELLE)
def test_locking_a_symlinked_lockfile_is_refused(tmp_path, fall):
    """Beim Lockpfad kann das Journal vollstaendig heil sein.

    Genau deshalb ist ``RECOVER_JOURNAL_FROM_BACKUP`` hier der falsche Heilweg:
    er wiese an, eine intakte Kette aus dem Backup zu ersetzen.
    """
    root = _vorbereitete_wurzel(tmp_path)
    lock = _lock_path(root)
    ziel = _lege_symlink(lock, fall, tmp_path)
    vorher = ziel.read_bytes() if fall == "fremdziel" else None

    ergebnis = cli("init", "--json", root=root)
    _pruefe_befund_kern(_report(ergebnis), ergebnis.returncode, lock)
    _pruefe_kein_rueckstand(lock, ziel, fall, vorher)


# --------------------------------------------------------------------------- #
# Nicht-regulaere Endpunkte: Verzeichnis (EISDIR bzw. nicht-S_ISREG), FIFO
# --------------------------------------------------------------------------- #


def test_a_directory_at_the_journal_path_is_refused_on_read(tmp_path):
    """Lesen liefert kein EISDIR: das Verzeichnis oeffnet, ``S_ISREG`` faellt."""
    root = tmp_path / "daten"
    _init(root)
    pfad = journal_path(root)
    pfad.unlink()
    pfad.mkdir()

    ergebnis = cli("status", "--json", root=root)
    _pruefe_befund(_report(ergebnis), ergebnis.returncode, pfad)
    assert pfad.is_dir()


def test_a_directory_at_the_journal_path_is_refused_on_append(tmp_path):
    """Schreiben liefert ``EISDIR`` — symbolisch, nie gegen die Zahl — VOR dem ``fstat``."""
    root = _vorbereitete_wurzel(tmp_path)
    pfad = journal_path(root)
    pfad.mkdir()

    ergebnis = cli("init", "--json", root=root)
    _pruefe_befund_kern(_report(ergebnis), ergebnis.returncode, pfad)
    assert pfad.is_dir() and not any(pfad.iterdir()), "kein Rueckstand im Verzeichnis"


def test_a_directory_at_the_lock_path_is_refused(tmp_path):
    root = _vorbereitete_wurzel(tmp_path)
    lock = _lock_path(root)
    lock.mkdir()

    ergebnis = cli("init", "--json", root=root)
    _pruefe_befund_kern(_report(ergebnis), ergebnis.returncode, lock)
    assert lock.is_dir() and not any(lock.iterdir())


def test_a_fifo_at_the_journal_path_is_refused_without_blocking(tmp_path):
    """``O_NONBLOCK`` ist hier die Zusage, nicht die Optimierung.

    Ohne das Flag blockiert das Oeffnen unbegrenzt; der Test faellt dann als
    ``TimeoutExpired`` statt den Lauf anzuhalten. Genau das braucht J10.
    """
    root = tmp_path / "daten"
    _init(root)
    pfad = journal_path(root)
    pfad.unlink()
    os.mkfifo(pfad)

    ergebnis = _cli_zeitbegrenzt("status", "--json", root=root, timeout=20.0)
    _pruefe_befund(_report(ergebnis), ergebnis.returncode, pfad)


# --------------------------------------------------------------------------- #
# Verzeichnisanker und Praesenz
# --------------------------------------------------------------------------- #


def test_a_symlinked_parent_cannot_move_the_journal_out_of_the_root(tmp_path):
    """``O_NOFOLLOW`` am Dateinamen schuetzt nicht vor einem Link am Elternteil."""
    root = tmp_path / "daten"
    _init(root)
    gov = root / "_governance"
    beute = tmp_path / "beute"
    beute.mkdir()
    for eintrag in gov.iterdir():
        eintrag.replace(beute / eintrag.name)
    gov.rmdir()
    gov.symlink_to(beute)

    ergebnis = cli("status", "--json", root=root)
    _pruefe_befund(_report(ergebnis), ergebnis.returncode, gov)
    assert gov.is_symlink(), "der Link auf das Elternverzeichnis muss ein Link bleiben"


def test_a_broken_symlink_is_presence_not_absence(tmp_path):
    """``Path.exists()`` sagt bei einem dangling Link False — belegt ist der Pfad trotzdem."""
    root = tmp_path / "daten"
    _init(root)
    pfad = journal_path(root)
    ziel = _lege_symlink(pfad, "dangling", tmp_path)
    assert pfad.exists() is False and pfad.is_symlink() is True

    ergebnis = cli("status", "--json", root=root)
    report = _report(ergebnis)
    assert report["reason_code"] != "ACTION_WORKSPACE_NOT_INITIALISED", (
        "belegter Pfad darf nicht als 'kein Journal' gelesen werden"
    )
    _pruefe_befund(report, ergebnis.returncode, pfad)
    assert not ziel.exists()


def test_a_missing_parent_is_pristine_on_read(tmp_path):
    """Fehlt das Elternverzeichnis beim Lesen, ist das pristine — kein Befund."""
    root = tmp_path / "daten"
    ergebnis = cli("status", "--json", root=root)
    report = _report(ergebnis)
    assert report["reason_code"] == "ACTION_WORKSPACE_NOT_INITIALISED"
    assert ergebnis.returncode == 3
    assert not (root / "_governance").exists(), "das Lesen darf nichts anlegen"


def test_a_missing_parent_is_unsafe_on_write_and_creates_nothing(tmp_path):
    """Beim Schreiben ist derselbe Zustand ein Befund — und legt nichts an.

    **Berichtigung.** Eine frühere Fassung schrieb hier, ``init`` sei „der
    einzige CLI-Schreibpfad". Das ist falsch — ``append_once`` steht auch in
    ``application/ingest.py`` (Z.198 und Z.205) —, und es ist dieselbe zu weite
    Behauptung, die R1 und R2 an anderer Stelle beanstandet haben. Meine
    Korrektur hatte sie hier übersehen, weil sie anders formuliert war.

    Richtig und enger, und den Knoten trägt es genauso: ``cmd_init`` ruft vor
    ``append_once`` bereits ``ws.ensure()`` (``cli/main.py`` Z.447) und legt das
    Elternverzeichnis selbst an; ``cmd_ingest`` hält an den Toren davor an, bevor
    ``ingest(...)`` erreicht wird. ``_journal_or_stop`` (Z.147) gibt bei
    fehlendem Journal **keinen** Halt zurück — die Nichterreichbarkeit hängt
    also nicht an dieser Zeile, sondern an ``ws.ensure()`` und den
    ``ingest``-Toren.

    Die Vertragszeile bleibt im Vertrag, weil ``Journal`` ein Modul mit eigener
    Zusage ist. Das ist mit R1 §5 und R2 §3.3 abgeschlossen und **kein
    F5-Vorbehalt mehr**.
    """
    from ohpipe.journal import Journal, JournalUnsafe

    root = tmp_path / "daten"
    gov = root / "_governance"
    journal = Journal(gov / "journal.jsonl")
    art, nutzlast, kennung = _probe()
    with pytest.raises(JournalUnsafe):
        journal.append_once(art, nutzlast, record_id=kennung)
    assert not gov.exists(), "der Schreibpfad hat das Elternverzeichnis angelegt"


def test_a_stop_after_ensure_reports_what_init_created(tmp_path):
    """Ein ``STOP`` nach ``ws.ensure()`` muss nennen, was dieser Lauf angelegt hat.

    Präzedenz steht im Produkt: die STOP-Ausgänge nach der Anlage führen
    ``changed=created`` (``cli/main.py`` Z.466 und Z.479), und der Kommentar über
    ``cmd_init`` (Z.438–440) nennt den Grund — eine frühere Fassung legte
    ``_governance/``, ``records/`` und ``releases/`` an und brach mit leerem
    CHANGED ab: „Beide Aussagen waren damit unwahr."

    Beide ``_journal_or_stop``-Aufrufe (Z.441 vor der Anlage, Z.452 danach)
    reichen ihren Report **unverändert** weiter, also ohne ``changed``. Solange
    dort nur ``STOP_JOURNAL_BROKEN`` entstehen konnte, war das folgenlos genug.
    Mit J1 entsteht nach der Anlage ein neuer ``STOP`` — und der würde melden, es
    sei nichts angelegt worden, während die Verzeichnisse schon dastehen.
    """
    root = _vorbereitete_wurzel(tmp_path)
    lock = _lock_path(root)
    _lege_symlink(lock, "fremdziel", tmp_path)

    ergebnis = cli("init", "--json", root=root)
    report = _report(ergebnis)
    _pruefe_befund_kern(report, ergebnis.returncode, lock)
    assert report["changed"], (
        "ein STOP nach ws.ensure() muss die angelegten Eintraege nennen — sonst "
        "sind Anlage und CHANGED zwei widersprechende Aussagen im selben Bericht"
    )
    # **Berichtigung meiner eigenen Zusage.** Eine frühere Fassung forderte hier
    # `Path(eintrag).exists()` für jeden Eintrag. Das war eine Zusage, die das
    # Produkt nie gegeben hat: `Workspace.ensure` trägt Modusänderungen
    # ausdrücklich als beschriebene Änderung ein — `"<pfad> (Modus 755 → 700)"`,
    # `project.py` Z.630 — und begründet das im Docstring damit, dass eine
    # stillschweigend weggelassene Modusänderung schon einmal teuer war. Ich
    # hatte den Docstring von `Report.changed` („Konkret veränderte Pfade")
    # gelesen und über `ensure()` geschlossen, ohne dort nachzusehen.
    #
    # Geprüft wird deshalb, was die Zeile wirklich zusagt: jeder Eintrag nennt
    # einen **existierenden Pfad**, gegebenenfalls mit angehängter Beschreibung.
    # Dass CHANGED zwei Vokabulare mischt — reiner Pfad und Pfad-mit-Klammerzusatz
    # in derselben `", ".join(...)`-Zeile — ist ein eigener Befund für eine
    # eigene Scheibe und ausdrücklich **kein J1-Scope**; er ist heute schon über
    # `STOP_LEDGER_INVALID` erreichbar, also keine J1-Regression.
    for eintrag in report["changed"]:
        pfad = eintrag.split(" (", 1)[0]
        assert Path(pfad).exists(), f"changed nennt {pfad}, das es nicht gibt"


def test_init_on_an_empty_root_is_pristine_not_unsafe(tmp_path):
    """Schutzzeile: ``_journal_or_stop`` laeuft VOR ``ws.ensure()``.

    Auf einer frischen Wurzel fehlt ``_governance`` zum Zeitpunkt der
    Praesenzpruefung. Behandelt die gemeinsame Semantik das nicht als pristine,
    macht ``init`` sich selbst zu ``STOP_JOURNAL_UNSAFE`` — und niemand kann
    mehr einen Arbeitsbereich anlegen.
    """
    root = tmp_path / "daten"
    ergebnis = cli("init", "--json", root=root)
    assert ergebnis.returncode == 0, ergebnis.stdout + ergebnis.stderr
    report = _report(ergebnis)
    assert report["reason_code"] != REASON_CODE
    assert journal_path(root).is_file()
    assert journal_path(root).read_text(encoding="utf-8").strip(), "erster append fehlt"


# --------------------------------------------------------------------------- #
# Der Operatorvertrag unter feindlichen Pfadnamen
# --------------------------------------------------------------------------- #


def test_the_j1_report_reason_is_single_line_and_path_free(tmp_path):
    root = tmp_path / "daten"
    _init(root)
    pfad = journal_path(root)
    _lege_symlink(pfad, "fremdziel", tmp_path)

    report = _report(cli("status", "--json", root=root))
    # Ohne diese Zeile prueft der Test irgendeinen Report, nicht den J1-Report —
    # und wird gruen, weil der heutige STOP_JOURNAL_BROKEN zufaellig einzeilig ist.
    assert report["reason_code"] == REASON_CODE
    assert report["reason"].splitlines() == [report["reason"]]
    for teil in (str(pfad), pfad.name, str(root)):
        assert teil not in report["reason"]


def test_the_j1_six_lines_survive_a_root_named_with_newline_ampersand_pipe_semicolon_and_quotes(
    tmp_path,
):
    """Ein zulaessiger Ordnername darf den Reportbau nicht sprengen."""
    root = tmp_path / 'fall & review; a|b "zitat"\nzweite zeile'
    _init(root)
    pfad = journal_path(root)
    _lege_symlink(pfad, "fremdziel", tmp_path)

    ergebnis = cli("status", root=root)
    assert ergebnis.returncode == STOP_RC, ergebnis.stdout + ergebnis.stderr
    assert "Traceback" not in ergebnis.stderr, ergebnis.stderr
    zeilen = report_lines(ergebnis.stdout)
    assert len(zeilen) == 6
    assert zeilen["CHECK"].strip() in ("—", "-")
    assert RECOVERY_CODE in zeilen["RECOVERY"]


def test_details_pfad_is_a_string_and_survives_a_json_roundtrip(tmp_path):
    """``json.dumps`` auf ein ``Path`` wirft ``TypeError`` — erst im JSON-Ausgang."""
    root = tmp_path / "daten\nmit umbruch"
    _init(root)
    pfad = journal_path(root)
    _lege_symlink(pfad, "fremdziel", tmp_path)

    ergebnis = cli("status", "--json", root=root)
    rohtext = ergebnis.stdout
    report = json.loads(rohtext)
    # Bewusst als Assert statt als Indexzugriff: ein ``KeyError`` im Rotlauf
    # liest sich wie ein Testdefekt, obwohl er der Befund ist. Ein roter Test
    # muss sagen, was er meint.
    details = report.get("details") or {}
    assert "pfad" in details, (
        "details fuehrt keinen Schluessel 'pfad' — der Befundpfad fehlt im "
        "maschinenlesbaren Teil des Reports"
    )
    assert isinstance(details["pfad"], str), (
        f"details['pfad'] ist {type(details['pfad']).__name__}, erwartet str — "
        "ein Path-Objekt wirft erst im JSON-Ausgang TypeError"
    )
    assert details["pfad"] == str(pfad)
    # Der Umbruch liegt im JSON-Text escaped vor, nicht als echter Zeilenumbruch.
    assert "\\n" in rohtext, "der Umbruch muss als \\n escaped im JSON stehen"
    assert json.loads(json.dumps(report))["details"]["pfad"] == str(pfad)


# --------------------------------------------------------------------------- #
# Ausnahmehierarchie (J7) und Lockwiederverwendung
# --------------------------------------------------------------------------- #


def test_journal_unsafe_is_not_swallowed_by_journal_broken(tmp_path):
    """``JournalUnsafe`` ist Unterklasse von ``JournalBroken`` — **und trägt Verhalten**.

    Der Import steht bewusst **im** Test und nicht am Modulkopf: als
    Modulimport wuerde die ganze Datei beim Einsammeln scheitern, es gaebe
    keine ``nodeid``s und damit keinen Rotnachweis je Node.

    **Zweite Hälfte, nachgezogen auf die H2-Bedingung des PRT.** Die
    Typaussage allein wäre von ``class JournalUnsafe(JournalBroken): pass``
    erfüllt — einer leeren Klasse, die nichts härtet. Ein Knoten, dessen einzige
    frühere Rotfärbung ein fehlender Import war, ist damit unbelegt. Geprüft wird
    deshalb, wofür die Vererbung überhaupt da ist:

    * ein **bestehender** Aufrufer, der nur ``JournalBroken`` kennt, bleibt am
      Symlink fail-closed, ohne dass er dafür angefasst werden muss;
    * wer unterscheiden will, fängt ``JournalUnsafe`` **vorher** — und bekommt
      den beanstandeten Pfad an der Ausnahme, nicht im Meldungstext.
    """
    from ohpipe.journal import Journal, JournalBroken, JournalUnsafe

    assert issubclass(JournalUnsafe, JournalBroken)
    assert JournalUnsafe is not JournalBroken

    gov, pfad = _journal_mit_praepariertem_eltern(tmp_path)
    fremd = tmp_path / "fremdziel.txt"
    fremd.write_text("x", encoding="utf-8")
    pfad.symlink_to(fremd)
    art, nutzlast, kennung = _probe()

    # Der Altaufrufer: kennt JournalUnsafe nicht und haelt trotzdem an.
    with pytest.raises(JournalBroken) as fail_closed:
        Journal(pfad).append(art, nutzlast, record_id=kennung)
    assert isinstance(fail_closed.value, JournalUnsafe), (
        "der Symlinkfall kommt beim Altaufrufer als JournalBroken an, ist aber "
        "kein Kettenbruch — sonst bekaeme der Operator den falschen Recoveryweg"
    )
    assert fail_closed.value.pfad == pfad
    assert str(pfad) not in str(fail_closed.value), "der Pfad gehoert nicht in den Meldungstext"
    assert fremd.read_text(encoding="utf-8") == "x", "durch den Link wurde geschrieben"


def test_the_lockfile_is_reused_and_not_exclusively_created(tmp_path):
    """Negativprobe gegen die eigene Haertung: kein ``O_EXCL`` an der Lockdatei."""
    root = _vorbereitete_wurzel(tmp_path)
    lock = _lock_path(root)
    lock.touch(mode=0o600)

    ergebnis = cli("init", "--json", root=root)
    assert ergebnis.returncode == 0, ergebnis.stdout + ergebnis.stderr
    assert _report(ergebnis)["reason_code"] != REASON_CODE, (
        "eine vorhandene regulaere Lockdatei ist kein Befund — sonst waere O_EXCL drin"
    )
    assert lock.is_file()
    assert journal_path(root).read_text(encoding="utf-8").strip(), "der append gelang"


def test_the_size_check_reads_from_the_descriptor_not_the_path(tmp_path, monkeypatch):
    """Kausal statt symptomatisch — sonst bindet der Test J5 nicht.

    **Warum die Vorgängerfassung J5 verfehlte.** Sie ersetzte den Journalpfad
    *vor* dem Aufruf durch einen Symlink. Eine korrekte Umsetzung hält dann schon
    beim ``O_NOFOLLOW``-Öffnen an; die Größenentscheidung ``fstat(fd)`` gegen
    ``path.stat()`` wird nie erreicht. Der Test wäre nach dem Bau auch dann grün
    gewesen, wenn der J5-Mutant sie zurückdreht.

    **Die kausale Probe.** Beobachtet wird, ob der Journal*pfad* während eines
    Anhängens überhaupt noch nachgeschlagen wird. ``_head_locked`` liest heute
    ``self.path.stat()`` (``journal.py`` Z.224), um den gemerkten Kopf gegen die
    Dateigröße zu prüfen; nach dem Bau muss diese Größe vom geöffneten
    Deskriptor kommen. Der J5-Mutant lässt genau diesen Aufruf wieder auftauchen
    und bringt damit diesen Test zuverlässig zu Fall.

    **Warum drei Namen beobachtet werden und nicht einer.** ``Path.stat`` allein
    wäre eine Scheinprobe: Ein Bau, der ``self.path.stat()`` durch
    ``os.lstat(self.path)`` ersetzt, bliebe pfadgebunden — die Lücke zwischen
    Nachschlagen und Öffnen bliebe offen — und der Test würde trotzdem grün.
    Beobachtet werden deshalb ``os.stat``, ``os.lstat`` und ``Path.stat``; nur
    ``os.fstat`` auf einem gehaltenen Deskriptor bleibt unbeobachtet, und genau
    das ist die Zusage.

    **Selbst gemessen** (Sockelbaum, Python 3.11): heute 2 Treffer auf dem
    Journalpfad im zweiten ``append`` — ein echter Aufruf, doppelt gezählt, weil
    ``Path.stat`` intern ``os.stat`` ruft. Gegen eine nachgebaute
    deskriptorbasierte Fassung: 0 Treffer. Die Zusage kippt also wirklich, statt
    nach dem Bau rot zu bleiben.

    **Erklärte Kopplung.** Der Knoten fällt auch, wenn irgendein *anderes*
    Nachschlagen des Endpunkts über den Pfad den Bau überlebt — etwa
    ``Path.exists()`` im Lesepfad (Ö1, Z.167). Das ist kein Mangel des Knotens:
    J1 sagt für alle Endpunktprüfungen den Deskriptor zu. Es steht hier, damit
    ein späteres Rot richtig gelesen wird.

    **Die zweite Hälfte** ist die positive: Kette heil, ``seq`` läuft weiter.
    Ohne sie wäre die Zusage von einer Fassung erfüllbar, die schlicht nicht
    mehr schreibt.
    """
    from ohpipe.journal import Journal

    root = tmp_path / "daten"
    _init(root)
    pfad = journal_path(root)
    ziel = str(pfad)

    treffer: list[str] = []
    echt_os_stat, echt_os_lstat, echt_path_stat = os.stat, os.lstat, Path.stat

    def _merke(kandidat) -> None:
        if isinstance(kandidat, int):
            return  # ein Deskriptor, kein Pfad — genau der erlaubte Fall
        try:
            name = os.fspath(kandidat)
        except TypeError:
            return
        if str(name) == ziel:
            treffer.append(str(name))

    def _os_stat(p, *a, **k):
        _merke(p)
        return echt_os_stat(p, *a, **k)

    def _os_lstat(p, *a, **k):
        _merke(p)
        return echt_os_lstat(p, *a, **k)

    def _path_stat(selbst, *a, **k):
        _merke(selbst)
        return echt_path_stat(selbst, *a, **k)

    journal = Journal(pfad)
    art, nutzlast_a, kennung_a = _probe("A")
    erstes = journal.append(art, nutzlast_a, record_id=kennung_a)

    # Erst jetzt beobachten: der erste Anhang füllt nur den gemerkten Kopf.
    monkeypatch.setattr(os, "stat", _os_stat)
    monkeypatch.setattr(os, "lstat", _os_lstat)
    monkeypatch.setattr(Path, "stat", _path_stat)
    _, nutzlast_b, kennung_b = _probe("B")
    zweites = journal.append(art, nutzlast_b, record_id=kennung_b)
    waehrend_des_anhaengens = list(treffer)
    monkeypatch.undo()

    assert not waehrend_des_anhaengens, (
        f"der Journalpfad wurde beim Anhaengen {len(waehrend_des_anhaengens)}x ueber "
        "stat/lstat nachgeschlagen; die Groessenentscheidung muss am geoeffneten "
        "Deskriptor haengen (fstat), sonst ist J5 unwirksam"
    )
    assert zweites.seq == erstes.seq + 1, "die Sequenz laeuft nicht weiter"
    Journal(pfad).verify()


# --------------------------------------------------------------------------- #
# Wächter über die J1-Reports als Klasse (Gegenstueck zum F7-Waechter)
# --------------------------------------------------------------------------- #


def test_a_missing_endpoint_is_created_in_place_in_the_checked_parent(tmp_path):
    """Die positive Gegenrichtung zur ENOENT-Härtung.

    Fehlt der Endpunkt in einem **echten** Elternverzeichnis, wird er dort
    angelegt — als reguläre Datei, nicht als Link und nicht anderswo. Ohne diese
    Zeile könnte die Härtung den Normalfall miterschlagen und niemand merkte es
    an den Rotzeilen.
    """
    root = _vorbereitete_wurzel(tmp_path)
    pfad = journal_path(root)
    assert not pfad.exists() and not pfad.is_symlink()

    ergebnis = cli("init", "--json", root=root)
    assert ergebnis.returncode == 0, ergebnis.stdout + ergebnis.stderr
    assert pfad.is_file() and not pfad.is_symlink(), "Endpunkt ist keine regulaere Datei"
    assert pfad.parent.resolve() == (root / "_governance").resolve()
    assert pfad.read_text(encoding="utf-8").strip(), "der erste append fehlt"
    lock = _lock_path(root)
    if lock.exists() or lock.is_symlink():
        assert not lock.is_symlink() and lock.parent == pfad.parent


def test_the_probe_payload_reaches_the_write_path(tmp_path):
    """Aufruferwache für jede Journalprobe dieser Datei.

    Nicht das Ergebnis prüfen, sondern dass die Messung ihre Stelle überhaupt
    erreicht — derselbe Gedanke wie der Rotnachweis selbst. ``check_payload``
    läuft vor der Sperre; kommt ``_probe()`` dort nicht durch, misst **kein**
    Proben-Knoten dieser Datei, was er zu messen behauptet, und alle blieben nach
    dem Bau rot, ohne dass die Ursache sichtbar wäre.

    Geprüft wird beides: die Wache lässt die Nutzlast durch, **und** ein
    tatsächlicher ``append`` landet als Ereignis in einer heilen Kette. Der
    zweite Teil ist der wichtigere — die Wache allein zu befragen hiesse wieder,
    das Instrument statt des Messkreises zu prüfen.
    """
    from ohpipe.domain.events import check_payload
    from ohpipe.journal import Journal

    art, nutzlast, kennung = _probe()
    check_payload(art, nutzlast, kennung)  # wirft nicht

    root = tmp_path / "daten"
    _init(root)
    pfad = journal_path(root)
    vorher = len(Journal(pfad).events())

    ereignis = Journal(pfad).append(art, nutzlast, record_id=kennung)
    assert ereignis.kind == art and ereignis.record_id == kennung

    danach = Journal(pfad)
    danach.verify()
    assert len(danach.events()) == vorher + 1, "der append hat die Kette nicht erreicht"


@pytest.mark.parametrize("name", ["ELOOP", "EMLINK"])
def test_both_eloop_and_emlink_map_to_journal_unsafe(tmp_path, monkeypatch, name):
    """Beide Fehlerwerte **gezielt und getrennt** injiziert.

    Nicht subsumierbar unter die Symlinktests: ein Test, der nur beobachtet, was
    der laufende Kern zurückgibt, bindet J6 nicht — er prüft die eine Hälfte der
    Abbildung und lässt die andere ungetestet. Deshalb wird der Wert injiziert
    statt erhofft.

    **Nur symbolisch, nie gegen Zahlen.** ``errno.ELOOP`` ist auf Linux und
    Darwin dieselbe Konstante, aber nicht dieselbe *Zahl*. Ein Vergleich gegen
    ``== 40`` oder ``== 62`` wäre auf der jeweils anderen Plattform falsch — und
    zwar grün-falsch genau dort, wo er nicht läuft. Der Wert kommt deshalb
    ausschliesslich aus ``getattr(errno, name)``, im Test wie im Produktcode.

    **Plattformtext, berichtigt.** ``ELOOP`` ist die Antwort auf Linux **und**
    auf Darwin. ``EMLINK`` bleibt in der Fehlerdomäne als **Netz für
    BSD-Varianten**, die es so melden — nicht als Darwin-Behauptung. Eine
    frühere Fassung dieses Docstrings ordnete ``EMLINK`` Darwin zu; das war
    übernommen, nicht gemessen, und es war falsch.

    **Aufruferwache, Pflicht.** Der Stub zählt seine Aufrufe, und der Test
    behauptet am Ende, dass er erreicht wurde. Ein Stub, der nie läuft, macht
    den Knoten grün-falsch oder rot aus dem falschen Grund — in H1 ist das
    dasselbe Problem.
    """
    from ohpipe.journal import Journal, JournalUnsafe

    code = getattr(errno, name)
    gov = tmp_path / "daten" / "_governance"
    gov.mkdir(parents=True)
    pfad = gov / "journal.jsonl"
    pfad.write_text("", encoding="utf-8")

    erreicht: list[str] = []

    def stolpern(p, *a, **k):
        erreicht.append(str(p))
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(os, "open", stolpern)

    art, nutzlast, kennung = _probe()
    try:
        with pytest.raises(JournalUnsafe):
            Journal(pfad).append(art, nutzlast, record_id=kennung)
    finally:
        monkeypatch.undo()

    assert erreicht, (
        "der injizierende Stub wurde nie erreicht — der Knoten misst dann nicht "
        f"die Abbildung von {name}, sondern irgendetwas davor"
    )


# --------------------------------------------------------------------------- #
# Der Lockpfad auf Produktebene — vom Mutantenlauf gefunden
#
# Diese vier Knoten gab es in H1 nicht. Der gezielte Mutantenlauf nach dem Bau
# hat sie erzwungen: vier Zusagen aus `A1-F4` waren von keinem Knoten gebunden,
# und die entsprechenden Mutanten überlebten. Sie sind am Sockel rot (kein
# `JournalUnsafe`) und tragen jeweils eine Verhaltensaussage, nicht nur einen
# Import.
#
# Warum sie auf Produktebene stehen und nicht über das CLI: `_journal_or_stop`
# prüft den Lockpfad heute schon lesend, bevor irgendein Schreibweg beginnt. Über
# das CLI ist der Schreibweg zum Lockpfad deshalb gar nicht erreichbar — ein
# Mutant, der genau dort die Primitive umgeht, bliebe unsichtbar.
# --------------------------------------------------------------------------- #


@contextmanager
def _zeitgrenze(sekunden: float, was: str):
    """Harte Grenze im Prozess. Ein hängender Lauf ist kein Befund, sondern ein Ausfall."""

    def _reissleine(signum, rahmen):
        raise TimeoutError(f"{was}: blockiert laenger als {sekunden}s")

    alt = signal.signal(signal.SIGALRM, _reissleine)
    signal.setitimer(signal.ITIMER_REAL, sekunden)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, alt)


def _journal_mit_praepariertem_eltern(tmp_path: Path) -> tuple[Path, Path]:
    """``_governance`` von Hand, ohne ``init`` — der Endpunkt bleibt offen."""
    gov = tmp_path / "daten" / "_governance"
    gov.mkdir(parents=True)
    return gov, gov / "journal.jsonl"


def test_the_lock_path_goes_through_the_same_primitive(tmp_path):
    """J2/J3: die Sperre wird mit **derselben** Öffnung genommen wie der Endpunkt.

    Der Mutant, der diesen Knoten braucht, öffnet die Lockdatei an der Primitive
    vorbei (``os.open(self._lockpfad, …)`` statt über ``_oeffne``). Er überlebte
    jeden CLI-Test, weil der Lesepfad den Lockpfad schon vorher prüft — der
    Schreibweg zum Link ist über die Kommandozeile gar nicht erreichbar. Auf
    Produktebene ist er es.

    Gemessen wird beides: der Befund **und** dass das fremde Ziel unberührt
    bleibt. Eine Sperre auf einem fremden Inode beschädigt nichts — sie hebt die
    Serialisierung auf. Deshalb ist „nichts kaputt" hier kein Freispruch.
    """
    from ohpipe.journal import Journal, JournalUnsafe

    gov, pfad = _journal_mit_praepariertem_eltern(tmp_path)
    fremd = tmp_path / "fremdziel.txt"
    fremd.write_text("gehoert nicht zur evidenz\n", encoding="utf-8")
    vorher = fremd.read_bytes()
    lock = pfad.with_suffix(pfad.suffix + ".lock")
    lock.symlink_to(fremd)

    art, nutzlast, kennung = _probe()
    with pytest.raises(JournalUnsafe) as befund:
        Journal(pfad).append(art, nutzlast, record_id=kennung)

    assert befund.value.pfad == lock, "der Befund muss den Lockpfad nennen, nicht den Endpunkt"
    assert lock.is_symlink(), "der Link muss ein Link bleiben"
    assert fremd.read_bytes() == vorher, "das Aussenziel wurde angefasst"
    assert not pfad.exists(), "der Endpunkt wurde trotz Befund angelegt"


def test_a_directory_at_the_lock_path_is_eisdir_not_a_crash(tmp_path):
    """``EISDIR`` aus der Fehlerdomäne — hier und nur hier erreichbar.

    Am **Endpunkt** fängt ``S_ISREG`` das Verzeichnis ab, bevor ``EISDIR``
    entstehen kann; der Mutant „``EISDIR`` aus der Domäne streichen" überlebte
    deshalb alles. Der **Lockpfad** wird ``O_WRONLY`` geöffnet, und dort quittiert
    der Kern ein Verzeichnis mit genau diesem Fehler.

    Geprüft wird die Ursache **symbolisch**. Eine Zahl stünde hier für einen
    bestimmten Kern; der Name steht für die Zusage.
    """
    from ohpipe.journal import Journal, JournalUnsafe

    gov, pfad = _journal_mit_praepariertem_eltern(tmp_path)
    lock = pfad.with_suffix(pfad.suffix + ".lock")
    lock.mkdir()

    art, nutzlast, kennung = _probe()
    with pytest.raises(JournalUnsafe) as befund:
        Journal(pfad).append(art, nutzlast, record_id=kennung)

    assert befund.value.ursache == errno.errorcode[errno.EISDIR]
    assert befund.value.pfad == lock
    assert lock.is_dir(), "das Verzeichnis wurde angefasst"


def test_a_fifo_at_the_lock_path_is_enxio_and_does_not_block(tmp_path):
    """``ENXIO`` aus der Fehlerdomäne — und die Zeitgrenze ist die halbe Zusage.

    Eine FIFO ohne Gegenstelle, ``O_WRONLY`` geöffnet, ist der einzige Weg zu
    ``ENXIO``: am Endpunkt greift vorher ``S_ISREG``. Ohne ``O_NONBLOCK`` würde
    dasselbe Öffnen **unbegrenzt blockieren** statt zu quittieren — deshalb steht
    die Zeitgrenze im Test und nicht bloss die Ausnahme.
    """
    from ohpipe.journal import Journal, JournalUnsafe

    gov, pfad = _journal_mit_praepariertem_eltern(tmp_path)
    lock = pfad.with_suffix(pfad.suffix + ".lock")
    os.mkfifo(lock)

    art, nutzlast, kennung = _probe()
    with (
        _zeitgrenze(10.0, "append ueber eine FIFO am Lockpfad"),
        pytest.raises(JournalUnsafe) as befund,
    ):
        Journal(pfad).append(art, nutzlast, record_id=kennung)

    assert befund.value.ursache == errno.errorcode[errno.ENXIO]
    assert befund.value.pfad == lock


def test_a_fifo_as_parent_cannot_hang_the_run(tmp_path):
    """``O_DIRECTORY`` am Elternteil ist kein Zierrat — ohne es hängt der Lauf.

    Selbst gemessen: entfernt man ``O_DIRECTORY`` aus der Elternöffnung, blockiert
    ``os.open`` an einer FIFO als Elternteil unbegrenzt. Kein Test fiel dabei —
    der Lauf hielt einfach an. Ein hängender Lauf ist der schlechteste aller
    Ausgänge: kein Befund, kein Bericht, kein Exitcode, und ein Mutantensweep,
    der nie endet.

    Der Knoten behauptet deshalb zweierlei: Befund **und** Zeitgrenze.
    """
    from ohpipe.journal import Journal, JournalUnsafe

    daten = tmp_path / "daten"
    daten.mkdir()
    gov = daten / "_governance"
    os.mkfifo(gov)

    art, nutzlast, kennung = _probe()
    with (
        _zeitgrenze(10.0, "append mit einer FIFO als Elternverzeichnis"),
        pytest.raises(JournalUnsafe) as befund,
    ):
        Journal(gov / "journal.jsonl").append(art, nutzlast, record_id=kennung)

    assert befund.value.pfad == gov, "der Befund muss das Elternverzeichnis nennen"
    assert befund.value.ursache == errno.errorcode[errno.ENOTDIR]


# --------------------------------------------------------------------------- #
# Der erzeugende ENOENT — Darwin-Wettlauf, deterministisch injiziert
# --------------------------------------------------------------------------- #
#
# Warum injiziert und nicht als echter Wettlauf gemessen: der Befund ist
# plattformabhaengig. Auf Darwin fielen 100/100 Laeufe mit 30 gleichzeitigen
# Erstanlagen desselben Namens ueber `dir_fd` mit ENOENT; unter Linux 0/3000
# Oeffnungen. **Die CI laeuft auf Linux.** Ein Knoten, der auf den echten
# Wettlauf wartet, waere dort immer gruen und fienge den Befund nie wieder — er
# wuerde eine Zusage genau dort pruefen, wo sie ohnehin haelt.
#
# Die reale 30-Schreiber-Probe bleibt notwendig, ist aber ein lokales
# Darwin-Tor mit eigenem Protokoll, kein CI-Netz. Beweisort je Zusage:
#
#     Retry-Entscheidung       diese vier Knoten     CI, plattformunabhaengig
#     Wettlauf in der Praxis   30-Schreiber-Probe    nur Darwin, lokal
#     Fehlerdomaene/Primitive  J1-Fokussuite         beide Plattformen


def _injiziere_enoent(
    monkeypatch, *, zielname: str, mit_creat: bool, wirft: int | None
) -> list[int]:
    """Laesst genau die passende ``os.open``-Oeffnung kontrolliert ``ENOENT`` werfen.

    ``wirft`` ist die Zahl der Versuche, die scheitern; ``None`` heisst alle.
    Zurueck kommt die Liste der **passenden** Versuche — ihre Laenge ist die
    Messgroesse, um die es in allen vier Knoten geht.

    Jede andere Oeffnung wird unveraendert an den echten ``os.open``
    durchgereicht. Der Injektor darf den Rest des Laufs nicht veraendern, sonst
    misst er sich selbst.
    """
    echt = os.open
    versuche: list[int] = []

    def verstellt(path, flags, mode=0o777, *, dir_fd=None):
        if isinstance(path, str) and path == zielname and bool(flags & os.O_CREAT) is mit_creat:
            versuche.append(flags)
            if wirft is None or len(versuche) <= wirft:
                raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)
        return echt(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", verstellt)
    return versuche


def test_a_racing_enoent_on_the_creating_open_is_retried_exactly_once(tmp_path, monkeypatch):
    """Der erste erzeugende ``ENOENT`` wird genau einmal wiederholt — und traegt.

    Das ist die eigentliche H2-Zusage. Ohne sie faellt der bestehende
    Release-Blocker ``test_the_journal_survives_concurrent_writers`` auf Darwin.
    Gemessen wird nicht nur, **dass** es gelingt, sondern dass es beim
    **zweiten** Versuch gelingt: ein unbeschraenkter Retry wuerde diesen Knoten
    ebenfalls bestehen, und genau den soll er ausschliessen.
    """
    from ohpipe.journal import Journal

    gov, pfad = _journal_mit_praepariertem_eltern(tmp_path)
    lock = pfad.with_suffix(pfad.suffix + ".lock")
    art, nutzlast, kennung = _probe()

    versuche = _injiziere_enoent(monkeypatch, zielname=lock.name, mit_creat=True, wirft=1)

    journal = Journal(pfad)
    with _zeitgrenze(10.0, "append nach injiziertem ENOENT am Lockpfad"):
        journal.append(art, nutzlast, record_id=kennung)

    assert len(versuche) == 2, (
        f"genau zwei erzeugende Oeffnungen erwartet, gezaehlt {len(versuche)} — "
        "ein Versuch heisst kein Retry, mehr als zwei heisst unbeschraenkter Retry"
    )
    journal.verify()
    assert [e.kind for e in Journal(pfad)] == [art], "die Kette traegt genau das Ereignis"


def test_a_second_enoent_on_the_creating_open_is_a_finding_not_a_third_try(tmp_path, monkeypatch):
    """Der zweite Fehlschlag endet fail-closed — und laesst nichts zurueck.

    „Nie mehr als der zweite Versuch noetig" ist eine Messung ueber 100 Laeufe,
    **keine Kernelgarantie**. Das Restrisiko ist ein seltener, unnoetiger
    ``STOP_JOURNAL_UNSAFE`` unter hoher Nebenlaeufigkeit — fail-closed, also die
    richtige Richtung. Dieser Knoten schreibt es als Verhalten fest: ein zweiter
    Fehlschlag wird als Befund gemeldet, auch wenn er in der Messung nie auftrat.
    """
    from ohpipe.journal import Journal, JournalUnsafe

    gov, pfad = _journal_mit_praepariertem_eltern(tmp_path)
    lock = pfad.with_suffix(pfad.suffix + ".lock")
    art, nutzlast, kennung = _probe()

    versuche = _injiziere_enoent(monkeypatch, zielname=lock.name, mit_creat=True, wirft=None)

    journal = Journal(pfad)
    with (
        _zeitgrenze(10.0, "append mit dauerhaftem ENOENT am Lockpfad"),
        pytest.raises(JournalUnsafe) as befund,
    ):
        journal.append(art, nutzlast, record_id=kennung)

    assert len(versuche) == 2, (
        f"genau zwei Versuche erwartet, gezaehlt {len(versuche)} — nach dem "
        "zweiten Fehlschlag wird nicht weiter versucht"
    )
    assert befund.value.pfad == lock, "der Befund muss den Lockpfad nennen"
    assert befund.value.ursache == errno.errorcode[errno.ENOENT], (
        "die Ursache wird symbolisch gefuehrt, nie als Zahl"
    )
    assert sorted(os.listdir(gov)) == [], (
        "fail-closed heisst auch: kein Journal, keine Lockdatei, kein Rueckstand"
    )


def test_a_failing_root_probe_forbids_the_retry_entirely(tmp_path, monkeypatch):
    """Die Wurzelprobe wird nur injiziert geprueft — sie hat keinen natuerlichen Ausloeser.

    Zusaetzliche fail-closed Wurzelprobe: Kann ``"."`` am bereits verankerten
    ``dir_fd`` nicht mehr gelesen werden, wird **gar nicht** wiederholt — ein
    Versuch, dann Befund. In der gemessenen Fehlerdomaene hat diese Probe keinen
    natuerlichen Ausloeser; sie ist ein zusaetzlicher Waechter fuer den Fall,
    dass selbst ``stat(".")`` scheitert. Begrenzt wird der Retry durch
    ``O_CREAT`` und genau einen zweiten Versuch, nicht durch sie.

    Dieser Knoten ist der einzige, der den Mutanten „Wurzelprobe weglassen"
    faellt: ohne sie bleiben die drei anderen Knoten gruen.

    **Gemessen, nicht angenommen** (Linux 6.18, python 3.11.15): nach
    ``os.rmdir`` des Elternverzeichnisses gelingt ``os.stat(".", dir_fd=…)``
    weiterhin — der Deskriptor haelt den Inode am Leben — waehrend
    ``openat(…, O_CREAT)`` mit ``ENOENT`` quittiert. Ein natuerlich entferntes
    Elternverzeichnis erzeugt die Bedingung dieses Knotens also **nicht**; sie
    wird deshalb injiziert. Siehe die Anmerkung im F2-Paket.
    """
    from ohpipe.journal import Journal, JournalUnsafe

    gov, pfad = _journal_mit_praepariertem_eltern(tmp_path)
    lock = pfad.with_suffix(pfad.suffix + ".lock")
    art, nutzlast, kennung = _probe()

    versuche = _injiziere_enoent(monkeypatch, zielname=lock.name, mit_creat=True, wirft=None)

    echt_stat = os.stat

    def stat_verstellt(path, *, dir_fd=None, follow_symlinks=True):
        if dir_fd is not None and path == ".":
            raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), ".")
        return echt_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(os, "stat", stat_verstellt)

    journal = Journal(pfad)
    with (
        _zeitgrenze(10.0, "append mit fehlschlagender Wurzelprobe"),
        pytest.raises(JournalUnsafe) as befund,
    ):
        journal.append(art, nutzlast, record_id=kennung)

    assert len(versuche) == 1, (
        f"genau ein Versuch erwartet, gezaehlt {len(versuche)} — traegt die "
        "Wurzel nicht, ist der zweite Versuch nicht gerechtfertigt"
    )
    assert befund.value.pfad == lock
    assert befund.value.ursache == errno.errorcode[errno.ENOENT]


@pytest.mark.parametrize("stelle", ["journal", "lock"])
def test_a_missing_endpoint_on_the_read_path_is_never_retried(tmp_path, monkeypatch, stelle):
    """Ohne ``O_CREAT`` bleibt die Missing-Semantik unangetastet.

    Der Retry gehoert an die **erzeugende** Oeffnung und nur dorthin. Ein
    fehlendes Journal und eine fehlende Lockdatei im reinen Leseweg sind
    *pristine* — kein Befund, und erst recht kein Grund, ein zweites Mal zu
    oeffnen. Wuerde der Retry auch hier greifen, machte er aus einem
    Nichtzustand einen doppelt geprueften Nichtzustand und aus ``changed == []``
    ein Versprechen, das der Leseweg nicht mehr allein haelt.

    Klasse ERHALTUNG: dieser Knoten ist am Sockel gruen und muss es bleiben.
    """
    from ohpipe.journal import Journal

    gov, pfad = _journal_mit_praepariertem_eltern(tmp_path)
    lock = pfad.with_suffix(pfad.suffix + ".lock")
    ziel = pfad if stelle == "journal" else lock

    versuche = _injiziere_enoent(monkeypatch, zielname=ziel.name, mit_creat=False, wirft=None)

    journal = Journal(pfad)
    with _zeitgrenze(10.0, f"Leseweg auf {ziel.name}"):
        if stelle == "journal":
            assert list(journal) == [], "ein fehlendes Journal ist kein Befund"
        else:
            assert journal.pruefe_lockpfad() is None, "eine fehlende Lockdatei ist kein Befund"

    assert len(versuche) == 1, (
        f"genau ein Versuch erwartet, gezaehlt {len(versuche)} — ohne O_CREAT wird nicht wiederholt"
    )
    assert sorted(os.listdir(gov)) == [], "der Leseweg legt nichts an"


@pytest.mark.parametrize("stelle", ["journal", "lock"])
def test_ingest_refuses_a_symlinked_journal(tmp_path, stelle):
    """Der zweite Schreibweg: ``ingest`` über die Anwendungsschicht.

    ``append_once`` steht auch in ``application/ingest.py`` Z.198 und Z.205 —
    zweimal innerhalb derselben Sperre. ``ingest`` ist der realistischere
    Operatorweg, weil er auf einem bereits angelegten Arbeitsbereich läuft. Eine
    Matrix, die nur ``init`` prüft, lässt diesen Weg offen.
    """
    quelle = REPO / "examples" / "synthetic" / "SANDBOX-001.srt"
    root = tmp_path / "daten"
    _init(root)
    ziel_pfad = journal_path(root) if stelle == "journal" else _lock_path(root)
    ziel = _lege_symlink(ziel_pfad, "fremdziel", tmp_path)
    vorher = ziel.read_bytes()

    ergebnis = cli("ingest", str(quelle), "--record", "SANDBOX-001", "--json", root=root)
    _pruefe_befund_kern(_report(ergebnis), ergebnis.returncode, ziel_pfad)
    _pruefe_kein_rueckstand(ziel_pfad, ziel, "fremdziel", vorher)


def test_every_j1_report_keeps_the_operator_contract(tmp_path):
    """F7-Gegenstueck: der Waechter in ``test_e8_graph_binding`` deckt nur E8."""
    root = tmp_path / "daten"
    _init(root)
    faelle = {
        "journal-symlink": journal_path(root),
        "lock-symlink": _lock_path(root),
    }
    for name, ziel in faelle.items():
        _lege_symlink(ziel, "fremdziel", tmp_path)
        report = _report(cli("status", "--json", root=root))
        assert report["reason_code"] == REASON_CODE, name
        assert report["check"] is None, name
        assert report["next"] is None, name
        assert report["recovery_code"] == RECOVERY_CODE, name
        assert report["reason"].splitlines() == [report["reason"]], name
        assert str(ziel) not in report["reason"], name
        assert report["details"].get("pfad") == str(ziel), name
        ziel.unlink()
        if name == "journal-symlink":
            _init(root)


def test_every_node_declares_its_class():
    """Buchhaltungswächter: keine Zeile ohne Klassenangabe, keine Angabe ohne Zeile.

    Die Nodetabelle des H1-Belegs wird aus ``KLASSEN`` gebaut. Eine von Hand
    gepflegte Tabelle driftet gegen die Datei, sobald jemand einen Test ergänzt
    und die Tabelle vergisst — genau die Sorte stiller Lücke, gegen die der Rest
    dieser Datei antritt.
    """
    hier = {name for name, obj in globals().items() if name.startswith("test_") and callable(obj)}
    fehlend = sorted(hier - set(KLASSEN))
    ueberzaehlig = sorted(set(KLASSEN) - hier)
    assert not fehlend, f"Test ohne Klassenangabe: {fehlend}"
    assert not ueberzaehlig, f"Klassenangabe ohne Test: {ueberzaehlig}"
    assert set(KLASSEN.values()) <= {"ROTNACHWEIS", "SCHUTZ", "ERHALTUNG"}
