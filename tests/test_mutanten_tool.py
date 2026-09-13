"""Das Mutantenwerkzeug selbst — geprüft, bevor es elf Minuten kostet.

Herkunft, gemessen am 10.08.2026 gegen den eigenen Baum: ``_lauf`` nahm
``subprocess.run(...).stdout`` und liess das ``CompletedProcess`` fallen. Der
Exitcode war damit nicht ungelesen, sondern **unerreichbar**. Ein Fehler, der
sammelt und erst beim Aufbau fällt, sah für das Werkzeug so aus:

    pytest    533 passed, 43 xfailed, 1 error    rc=1   FAILED-Zeilen: 0
    Werkzeug  "Grundlauf: 43 xfail, keine Fehlschlaege."          rc=0

Die Suite war rot, das Werkzeug erklärte die Bezugsmenge für gesund und meldete
Erfolg. Gefunden hat das eine **injizierte Probe von Hand** — und genau das
darf nicht die einzige Absicherung bleiben: eine Handprobe wird beim nächsten
Umbau nicht wiederholt, weil niemand mehr weiss, dass es sie gab.

**Warum gestubbtes ``subprocess.run`` und keine echte Suite.** Diese Datei
prüft die Auswertung, nicht pytest. Ein Test, der die Suite startet, um zu
prüfen wie das Werkzeug eine Suitenausgabe liest, kostet dreissig Sekunden je
Fall und misst dabei zwei Dinge gleichzeitig. Gestubbt kostet er
Millisekunden und misst eins. Die echten Ausgabeformen stehen unten als
Konstanten — abgeschrieben aus gemessenen Läufen, nicht erfunden.

**Warum ``importlib`` und kein ``sys.path``-Eingriff.** ``tools`` ist kein
Paket. Ein ``sys.path.insert`` in einer Testdatei wirkt auf die ganze Session
und kann Importe fremder Tests umlenken; das lädt genau die Sorte Fernwirkung
ein, gegen die dieses Repository gebaut ist.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

WURZEL = Path(__file__).resolve().parents[1]


def _werkzeug():
    """``tools/mutanten.py`` als Modul, ohne ``sys.path`` anzufassen.

    Die Eintragung in ``sys.modules`` unter einem eigenen Namen ist nicht
    optional, sondern gemessen notwendig: ``@dataclass`` löst unter
    ``from __future__ import annotations`` seine Typangaben über
    ``sys.modules[cls.__module__]`` auf. Ohne die Zeile bricht schon der
    Import mit ``AttributeError: 'NoneType' object has no attribute
    '__dict__'`` — und zwar als Sammelfehler, also genau in der Fehlerklasse,
    gegen die diese Datei geschrieben ist.
    """
    pfad = WURZEL / "tools" / "mutanten.py"
    spez = importlib.util.spec_from_file_location("_mutanten_unter_test", pfad)
    assert spez and spez.loader
    modul = importlib.util.module_from_spec(spez)
    sys.modules[spez.name] = modul
    spez.loader.exec_module(modul)
    return modul


mut = _werkzeug()


# --- Gemessene Ausgabeformen, abgeschrieben statt erfunden -----------------

SAUBER = "533 passed, 43 xfailed in 26.71s\n"

#: Ein Fehler, der SAMMELT und erst beim Aufbau faellt. Der teure Zweig:
#: pytest meldet Exitcode 1, es gibt KEINE FAILED-Zeile, und die Summenzeile
#: sieht bis auf drei Worte gesund aus.
AUFBAUFEHLER = "ERROR tests/test_probe.py::test_probe\n533 passed, 43 xfailed, 1 error in 31.32s\n"

#: Ein Fehler beim Sammeln. Exitcode 2, keine Zahlen ausser der Fehlerzahl.
SAMMELFEHLER = (
    "ERROR tests/test_probe.py\n!!! Interrupted: 1 error during collection !!!\n1 error in 1.24s\n"
)

#: K1: genau ein gefallener Test, keine Markerbewegung.
K1_SAUBER = (
    "FAILED tests/test_replay_rejection_paths.py::"
    "test_a_truncated_model_receipt_is_refused_on_the_way_through_the_journal\n"
    "1 failed, 532 passed, 43 xfailed in 27.16s\n"
)

#: E2: der gemeinte Test plus die sieben deklarierten input_refs-Marker.
_E2_MARKER = (
    "tests/test_input_refs_payload.py::test_a_decision_may_carry_input_refs",
    "tests/test_input_refs_payload.py::test_input_refs_is_refused_for_its_content_not_its_name[kein-hash]",
    "tests/test_input_refs_payload.py::test_input_refs_is_refused_for_its_content_not_its_name[zu-kurz]",
    "tests/test_input_refs_payload.py::test_input_refs_is_refused_for_its_content_not_its_name[grossbuchstaben]",
    "tests/test_input_refs_payload.py::test_input_refs_is_refused_for_its_content_not_its_name[liste]",
    "tests/test_input_refs_payload.py::test_input_refs_is_refused_for_its_content_not_its_name[leer]",
    "tests/test_input_refs_payload.py::test_input_refs_refuses_an_unknown_role_for_the_role_not_the_field",
)
E2_SAUBER = (
    "FAILED tests/test_events_and_ingest.py::test_an_unremarkable_unknown_field_is_refused_too\n"
    + "".join(f"FAILED {k}\n" for k in _E2_MARKER)
    + "8 failed, 532 passed, 36 xfailed in 27.58s\n"
)

#: E8: der gemeinte Test plus REGULAERE Zusatzausfaelle. Zulaessig, kein Befund.
E8_SAUBER = (
    "FAILED tests/test_events_and_ingest.py::test_ingest_and_doctor_use_the_same_store\n"
    "FAILED tests/test_state_and_exit.py::test_a_drifted_anchor_still_says_drifted\n"
    "FAILED tests/test_forgery.py::test_the_fixture_itself_is_green\n"
    "3 failed, 530 passed, 43 xfailed in 26.71s\n"
)

MARKIERT_43 = frozenset(
    [
        *_E2_MARKER,
        *(f"tests/test_pseudonymisation_forgery.py::test_platzhalter_{i}" for i in range(36)),
    ]
)


def _lauf(stdout: str, rc: int, stderr: str = "") -> object:
    """Ein :class:`Lauf` aus einer gemessenen Ausgabeform."""
    return mut._auswerten(
        subprocess.CompletedProcess(args=["pytest"], returncode=rc, stdout=stdout, stderr=stderr)
    )


def _m(kennung: str):
    return next(m for m in mut.MUTANTEN if m.id == kennung)


# --- 1 · Der Grundlauf ------------------------------------------------------


def test_a_setup_error_without_any_failed_line_invalidates_the_baseline():
    """Der Fall, der die ganze Härtung ausgelöst hat.

    Exitcode 1, kein einziges ``FAILED``, eine Summenzeile mit gültiger
    ``xfail``-Zahl — und trotzdem ist der Bezug vergiftet. Die
    Vorgängerfassung meldete hier „Grundlauf: 43 xfail, keine Fehlschlaege"
    und lief weiter.
    """
    befund = mut.grundlauf_befund(_lauf(AUFBAUFEHLER, rc=1), MARKIERT_43)

    assert befund is not None, "ein ERROR im Grundlauf muss den Lauf anhalten"
    assert "ERROR" in befund
    assert "Exitcode 1" in befund


def test_a_collection_error_invalidates_the_baseline():
    """Der billige Zweig, der Vollständigkeit halber: Exitcode 2, keine Zahlen."""
    befund = mut.grundlauf_befund(_lauf(SAMMELFEHLER, rc=2), MARKIERT_43)

    assert befund is not None
    assert "Exitcode 2" in befund


def test_a_clean_baseline_is_accepted():
    """Die Gegenrichtung. Ohne sie prüfte die Datei nur, dass immer gehalten wird.

    Genau diese Zeile hat die erste Fassung des Wächters gebraucht: sie hielt
    auch bei einer gesunden Suite, weil die Markermenge nicht mitgeliefert war.
    """
    assert mut.grundlauf_befund(_lauf(SAUBER, rc=0), MARKIERT_43) is None


def test_a_baseline_whose_marker_count_disagrees_with_the_xfail_sum_is_refused():
    """Zwei abgeleitete Zahlen über dieselbe Sache müssen übereinstimmen."""
    befund = mut.grundlauf_befund(_lauf(SAUBER, rc=0), frozenset(list(MARKIERT_43)[:5]))

    assert befund is not None
    assert "markierte Faelle" in befund


# --- 2 · Der Mutantenlauf ---------------------------------------------------


def test_a_mutant_never_turns_green_with_an_error():
    """Der gemeinte Test fällt UND es gibt einen zusätzlichen ``ERROR``.

    Ohne diesen Zweig wäre der Mutant grün: ``faellt`` ist erfüllt, die
    ``xfail``-Summe stimmt, und der ``ERROR`` stünde nur in einer Zeile, die
    niemand liest.
    """
    ausgabe = K1_SAUBER.replace(
        "1 failed, 532 passed, 43 xfailed in 27.16s",
        "1 failed, 531 passed, 43 xfailed, 1 error in 27.16s",
    )
    fund, zeile = mut.bewerte(_m("K1"), _lauf(ausgabe, rc=1), MARKIERT_43, 43)

    assert fund is not None, "ein zusaetzlicher ERROR ist ein Befund"
    assert "ERROR" in fund
    assert "ERROR" in zeile


@pytest.mark.parametrize("rc", [2, 3, 4, 5, -15, -9, 134, 137])
def test_every_exit_code_other_than_0_and_1_is_a_run_abort(rc):
    """Jeder Exitcode ausser 0 und 1 bezeichnet einen abgebrochenen Lauf.

    Sie dürfen weder als „überlebt" noch als „gefallen" gelesen werden — beides
    wäre eine Aussage über eine Zusage, die niemand gemessen hat.
    """
    fund, zeile = mut.bewerte(_m("K1"), _lauf("", rc=rc), MARKIERT_43, 43)

    assert fund is not None
    assert "LAUFABBRUCH" in fund
    assert f"Exitcode {rc}" in fund


def test_a_signal_death_without_failed_names_is_not_a_phantom_survivor():
    """Leere Namen dürfen einen Signaltod nie als UEBERLEBT klassifizieren."""
    fund, zeile = mut.bewerte(_m("K1"), _lauf("", rc=-9), MARKIERT_43, 43)

    assert fund is not None
    assert "LAUFABBRUCH" in fund
    assert "LAUFABBRUCH" in zeile
    assert "UEBERLEBT" not in fund
    assert "UEBERLEBT" not in zeile


def test_a_signal_death_with_expected_failed_names_is_not_a_phantom_kill():
    """Auch passende Namen dürfen einen Signaltod nie als GEFALLEN verbuchen."""
    fund, zeile = mut.bewerte(_m("K1"), _lauf(K1_SAUBER, rc=-9), MARKIERT_43, 43)

    assert fund is not None
    assert "LAUFABBRUCH" in fund
    assert "LAUFABBRUCH" in zeile
    assert "GEFALLEN" not in fund
    assert "GEFALLEN" not in zeile


def test_exit_code_zero_means_the_mutant_survived_and_is_not_a_technical_error():
    """Exitcode 0 ist ein Befund über die ZUSAGE, kein Werkzeugfehler.

    Die Unterscheidung ist der Grund, warum der Abbruchzweig alles ausser 0 und
    1 nimmt: ein Mutant, den keine Zusicherung fängt, ist der eigentliche Fund
    dieses Werkzeugs, und er darf nicht als Infrastrukturproblem verschwinden.
    """
    fund, zeile = mut.bewerte(_m("K1"), _lauf(SAUBER, rc=0), MARKIERT_43, 43)

    assert fund is not None
    assert "UEBERLEBT" in fund
    assert "LAUFABBRUCH" not in fund


def test_a_clean_k1_moves_no_marker():
    """Der Normalfall: ein Test fällt, die ``xfail``-Summe bleibt stehen."""
    fund, zeile = mut.bewerte(_m("K1"), _lauf(K1_SAUBER, rc=1), MARKIERT_43, 43)

    assert fund is None, fund
    assert "Marker gekippt" not in zeile


def test_a_declared_seven_marker_flip_is_reported_as_declared():
    """Die Werkzeugzusage bleibt geprüft, obwohl E2 seit C5 nichts mehr kippt.

    Die sieben Namen stehen oben ausgeschrieben und werden nicht aus
    ``Mutation.kippt`` gezogen: ein Test, der seine Sollmenge aus dem Prüfling
    holt, prüft den Prüfling gegen sich selbst.
    """
    synthetisch = dataclasses.replace(_m("E2"), kippt=_E2_MARKER)

    fund, zeile = mut.bewerte(synthetisch, _lauf(E2_SAUBER, rc=1), MARKIERT_43, 43)

    assert fund is None, fund
    assert "7 Marker gekippt, deklariert" in zeile


def test_an_undeclared_marker_flip_is_a_named_collateral_finding():
    """Die Gegenrichtung: dieselbe Mutation, dieselbe Ausgabe, OHNE Deklaration.

    Isoliert genau eine Variable. Die erste Fassung dieses Tests gab E2s
    Ausgabe an K1 — und bekam `VERHAKT`, weil K1s gemeinter Test darin gar
    nicht fällt. Sie prüfte damit die Reihenfolge der Zweige und nicht die
    Deklaration; grün wäre sie nie geworden, aber aus dem falschen Grund rot.
    """
    ohne = dataclasses.replace(_m("E2"), kippt=())

    fund, zeile = mut.bewerte(ohne, _lauf(E2_SAUBER, rc=1), MARKIERT_43, 43)

    assert fund is not None
    assert "KOLLATERAL" in fund
    assert "test_a_decision_may_carry_input_refs" in fund
    assert "KOLLATERAL" in zeile


def test_regular_collateral_failures_are_allowed_and_not_a_finding():
    """E8, V2 und E9 lassen regulär weitere Tests fallen. Das ist zulässig.

    Genau deshalb ist die Schlusszeile „und nur sie" ersatzlos gestrichen: sie
    behauptete eine Exklusivität, die der Katalog nicht hat und nie hatte.
    """
    fund, zeile = mut.bewerte(_m("E8"), _lauf(E8_SAUBER, rc=1), MARKIERT_43, 43)

    assert fund is None, fund
    assert "weitere Testfunktionen" in zeile
    assert "und nur sie" not in zeile


def test_the_expected_test_not_falling_is_a_named_finding():
    """VERHAKT: es fällt etwas, aber nicht das Gemeinte."""
    ausgabe = "FAILED tests/test_irgendwas.py::test_etwas_anderes\n1 failed, 532 passed, 43 xfailed in 1s\n"
    fund, _ = mut.bewerte(_m("K1"), _lauf(ausgabe, rc=1), MARKIERT_43, 43)

    assert fund is not None
    assert "erwartete Tests fielen NICHT" in fund


# --- 3 · Die Sammlung -------------------------------------------------------


def test_a_failing_collect_only_run_aborts_instead_of_returning_a_plausible_set(monkeypatch):
    """Eine plausible Menge aus einem gescheiterten Lauf ist der teuerste Messwert.

    Gemessen am 10.08.: unter einem Sammelfehler lieferte
    ``--collect-only -m xfail`` **43 Namen** und Exitcode 2. Wer nur die Namen
    liest, bekommt eine vollständig aussehende Bezugsmenge aus einem Lauf, der
    abgebrochen ist.
    """

    def stub(*_a, **_k):
        return subprocess.CompletedProcess(
            args=["pytest"],
            returncode=2,
            stdout="tests/a.py::test_x\n1 error in 1s\n",
            stderr="kaputt\n",
        )

    monkeypatch.setattr(mut.subprocess, "run", stub)
    knoten, befund = mut._markierte_knoten()

    assert knoten == frozenset()
    assert befund is not None
    assert "Exitcode 2" in befund


def test_stderr_is_part_of_the_diagnosis():
    """Regel 17: ein Exitcode ohne die zugehörige Ausgabe ist kein Messwert.

    Ein Aufruffehler (Exitcode 4) schreibt auf **stderr** und lässt stdout
    leer. Wer nur stdout in den Befund nimmt, meldet einen nackten Exitcode.
    """
    diagnose = _lauf(
        "", rc=4, stderr="ERROR: file or directory not found: tests/gibtsnicht\n"
    ).diagnose()

    assert "Exitcode 4" in diagnose
    assert "stderr" in diagnose
    assert "gibtsnicht" in diagnose


# --- 4 · Die Deklarationen im Katalog ---------------------------------------


def test_no_catalog_mutant_declares_a_marker_flip_after_c5():
    """Die grobe Sollmenge über der feinen, von Hand ausgeschrieben.

    ``Mutation.kippt`` deklariert je Mutant die Knoten; diese Zeile deklariert,
    **welche Mutanten überhaupt** eine solche Liste tragen dürfen. Ohne sie
    liesse sich ein Kollateralbefund dadurch stillstellen, dass jemand dem
    betroffenen Mutanten beiläufig ein ``kippt`` mitgibt — und der Diff sähe
    harmlos aus. Ausgeschrieben wie ``ERWARTETE_JOBS``, nicht aus dem Katalog
    errechnet.

    Seit C5 sind die sieben input_refs-Marker grün. Kein Katalogmutant bewegt
    deshalb noch die ``xfail``-Summe.
    """
    XFAIL_MOVER = set()

    ist = {m.id for m in mut.MUTANTEN if m.kippt}

    assert ist == XFAIL_MOVER, (
        f"Mutanten mit deklarierter Markerkippung: {sorted(ist)}, erwartet {sorted(XFAIL_MOVER)}"
    )


def test_e2_declares_no_marker_flip_after_c5():
    """Der lebende E2-Katalogeintrag trägt keine veraltete Rotmarkerzusage."""
    assert _m("E2").kippt == ()


# --- 5 · E1: unverfolgte Zieldateien, Inhaltsbaseline, Exklusivitaet --------
#
# Werkzeugakt E1. Der Befund, den diese Gruppe schliesst: die Eingangspruefung
# lief ueber ``git diff --name-only HEAD --`` und lieferte fuer VIER
# verschiedene Zustaende dieselbe leere Liste — sauberer verfolgter Bestand,
# unverfolgte Zieldatei, kein Git, Git-Fehler. Nach dem Schreiben einer
# Mutation wurde derselbe leere Wert als Anlass genommen, die Gegenprobe auf
# genau eine veraenderte Zieldatei zu UEBERSPRINGEN. In der Rotphase einer
# neuen, noch unverfolgten Produktdatei war damit beides wirkungslos.
#
# **Warum echte tmp-Repositorien und kein Mock von git.** Die Zusage lautet,
# dass das Werkzeug verfolgt, unverfolgt und gitlos unterscheidet. Wer git
# wegmockt, prueft die eigene Vorstellung von git. Die Suitelaeufe dagegen
# werden injiziert: sie sind hier nicht der Gegenstand, und ein Test, der
# dreissig Sekunden pytest startet, um eine Eingangspruefung zu messen, misst
# zwei Dinge gleichzeitig.

GRUNDLAUF_STUB = "2 passed, 0 xfailed in 0.01s\n"
MUTANT_FAELLT_STUB = "FAILED tests/x.py::test_a\n1 failed, 1 passed, 0 xfailed in 0.01s\n"

ZIEL_A = "ziel_a.py"
ZIEL_B = "ziel_b.py"
INHALT_A = "def a():\n    return 1\n"
INHALT_B = "def b():\n    return 3\n"


class Suitezaehler:
    """Ein injizierter Suitelauf, der mitzaehlt, wie oft er gerufen wurde.

    Die Zahl ist der eigentliche Messwert mehrerer Richtungen unten: „haelt
    VOR dem Suitelauf" ist nur dann gemessen, wenn nachweisbar kein Lauf
    stattgefunden hat. Ein Test, der nur den Rueckgabewert prueft, koennte
    denselben Wert auch nach einem teuren Lauf sehen.
    """

    def __init__(self, ausgaben: list[tuple[str, int]] | None = None) -> None:
        self.rufe = 0
        self.ausgaben = ausgaben or []

    def __call__(self):
        self.rufe += 1
        if self.ausgaben:
            stdout, rc = self.ausgaben.pop(0)
        else:
            stdout, rc = MUTANT_FAELLT_STUB, 1
        return _lauf(stdout, rc)


def _keine_marker():
    return frozenset(), None


def _werkbank(tmp_path: Path, *, git: bool, inhalt_a: str = INHALT_A) -> Path:
    """Ein Arbeitsbaum mit zwei Zieldateien, wahlweise unter git."""
    wurzel = tmp_path / "baum"
    wurzel.mkdir()
    (wurzel / ZIEL_A).write_text(inhalt_a, encoding="utf-8")
    (wurzel / ZIEL_B).write_text(INHALT_B, encoding="utf-8")
    if git:
        for befehl in (
            ["git", "init", "-q"],
            ["git", "config", "user.email", "probe@example.invalid"],
            ["git", "config", "user.name", "Probe"],
            ["git", "add", ZIEL_A, ZIEL_B],
            ["git", "commit", "-q", "-m", "sockel"],
        ):
            subprocess.run(befehl, cwd=wurzel, check=True, capture_output=True)
    return wurzel


def _mutation(kennung: str, datei: str, alt: str, neu: str):
    return mut.Mutation(
        id=kennung, datei=datei, alt=alt, neu=neu, was=f"Probe {kennung}", faellt=("test_a",)
    )


M_A = _mutation("TA", ZIEL_A, "    return 1", "    return 2")
M_B = _mutation("TB", ZIEL_B, "    return 3", "    return 4")


def _stelle(monkeypatch, wurzel: Path, mutanten=(M_A, M_B)) -> None:
    monkeypatch.setattr(mut, "REPO", wurzel)
    monkeypatch.setattr(mut, "MUTANTEN", tuple(mutanten))


def _bytes(wurzel: Path) -> dict[str, bytes]:
    return {n: (wurzel / n).read_bytes() for n in (ZIEL_A, ZIEL_B)}


# --- 5.1 · Die fuenf Zustaende werden nicht mehr zusammengezogen ------------


def test_a_tracked_and_clean_target_is_accepted(tmp_path, monkeypatch):
    """Richtung 1. Der Normalfall — und die Gegenprobe zu allem darunter."""
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    lage = mut.gitlage([ZIEL_A, ZIEL_B])

    assert lage.modus is mut.Gitmodus.WORKTREE
    assert lage.verfolgt_sauber == (ZIEL_A, ZIEL_B)
    assert lage.schmutzig == ()
    assert lage.unverfolgt == ()

    stub = Suitezaehler([(GRUNDLAUF_STUB, 0), (MUTANT_FAELLT_STUB, 1)])
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)

    assert rc == 0
    assert stub.rufe == 2, "Grundlauf und genau ein Mutantenlauf"


def test_a_tracked_unstaged_dirty_target_halts_before_the_baseline_run(
    tmp_path, monkeypatch, capsys
):
    """Richtung 2. Verfolgter Schmutz haelt fail-closed — vor jedem Suitelauf."""
    wurzel = _werkbank(tmp_path, git=True)
    (wurzel / ZIEL_A).write_text("def a():\n    return 99\n", encoding="utf-8")
    _stelle(monkeypatch, wurzel)

    lage = mut.gitlage([ZIEL_A, ZIEL_B])
    assert lage.unstaged == (ZIEL_A,)
    assert lage.staged == ()

    stub = Suitezaehler()
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == mut.HALT_VOR_GRUNDLAUF
    assert stub.rufe == 0, "kein Suitelauf gegen einen verfolgt schmutzigen Baum"
    assert ZIEL_A in ausgabe
    assert "unstaged" in ausgabe


def test_a_tracked_staged_dirty_target_halts_before_the_baseline_run(tmp_path, monkeypatch, capsys):
    """Richtung 3. Dieselbe Sperre, andere Seite des Index.

    Die Vorgaengerfassung fragte ``git diff --name-only HEAD``; das deckt
    staged mit ab. Getrennt gemessen wird trotzdem, weil die Meldung die
    Ursache benennen muss und ``staged`` eine andere Ursache ist als
    ``unstaged``.
    """
    wurzel = _werkbank(tmp_path, git=True)
    (wurzel / ZIEL_A).write_text("def a():\n    return 99\n", encoding="utf-8")
    subprocess.run(["git", "add", ZIEL_A], cwd=wurzel, check=True, capture_output=True)
    _stelle(monkeypatch, wurzel)

    lage = mut.gitlage([ZIEL_A, ZIEL_B])
    assert lage.staged == (ZIEL_A,)

    stub = Suitezaehler()
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == mut.HALT_VOR_GRUNDLAUF
    assert stub.rufe == 0
    assert ZIEL_A in ausgabe
    assert "staged" in ausgabe


def test_an_untracked_target_reaches_the_baseline_run(tmp_path, monkeypatch, capsys):
    """Richtung 4. Der Befund selbst: unverfolgt ist erlaubt — und benannt.

    Vor E1 war dieser Zustand von „sauber" nicht zu unterscheiden. Jetzt sagt
    das Werkzeug ``unverfolgt`` und stuetzt die Baseline auf Inhalt.
    """
    wurzel = _werkbank(tmp_path, git=True)
    (wurzel / "ziel_neu.py").write_text("def n():\n    return 7\n", encoding="utf-8")
    neu = _mutation("TN", "ziel_neu.py", "    return 7", "    return 8")
    _stelle(monkeypatch, wurzel, mutanten=(neu,))

    lage = mut.gitlage(["ziel_neu.py"])
    assert lage.unverfolgt == ("ziel_neu.py",)
    assert lage.verfolgt_sauber == ()

    stub = Suitezaehler([(GRUNDLAUF_STUB, 0), (MUTANT_FAELLT_STUB, 1)])
    rc = mut.main(["TN"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == 0
    assert stub.rufe == 2
    assert "unverfolgt" in ausgabe
    assert "sauber laut Git" not in ausgabe


def test_a_stale_template_on_an_untracked_target_halts_before_any_suite_run(
    tmp_path, monkeypatch, capsys
):
    """Richtung 5. Ein stehengebliebener Mutant wird nicht als Baseline gesegnet.

    Genau der Fall, gegen den die git-Eingangspruefung an einer unverfolgten
    Datei blind war: die Datei traegt bereits das MUTIERTE Muster, das
    Ausgangsmuster kommt null Mal vor. Der Zaehler ist der Messwert — nicht
    der Rueckgabewert allein.
    """
    wurzel = _werkbank(tmp_path, git=True)
    (wurzel / "ziel_neu.py").write_text("def n():\n    return 8\n", encoding="utf-8")
    neu = _mutation("TN", "ziel_neu.py", "    return 7", "    return 8")
    _stelle(monkeypatch, wurzel, mutanten=(neu,))

    stub = Suitezaehler()
    rc = mut.main(["TN"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == mut.HALT_VOR_GRUNDLAUF
    assert stub.rufe == 0, "kein Suitelauf gegen einen stehengebliebenen Mutanten"
    assert "TN" in ausgabe
    assert "0" in ausgabe and "Ausgangsmuster" in ausgabe


def test_a_valid_target_still_runs_without_any_git(tmp_path, monkeypatch, capsys):
    """Richtung 6. Kein Git ist ein eigener, tragender Modus — kein stiller Wegfall."""
    wurzel = _werkbank(tmp_path, git=False)
    _stelle(monkeypatch, wurzel)

    lage = mut.gitlage([ZIEL_A, ZIEL_B])
    assert lage.modus is mut.Gitmodus.KEIN_GIT

    stub = Suitezaehler([(GRUNDLAUF_STUB, 0), (MUTANT_FAELLT_STUB, 1)])
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == 0
    assert stub.rufe == 2
    assert "kein Git" in ausgabe


def test_an_unexpected_git_error_halts_with_a_diagnosis(tmp_path, monkeypatch, capsys):
    """Richtung 7. Ein Git-Fehler ist nicht „kein Git", nicht „sauber", nicht „unverfolgt".

    Er ist der Zustand, in dem das Werkzeug nichts weiss — und genau deshalb
    haelt, statt den bequemsten der drei anderen Zustaende anzunehmen.
    """
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)

    def kaputt(*_a, **_k):
        return subprocess.CompletedProcess(
            args=["git"], returncode=129, stdout="", stderr="fatal: unbekannte Option\n"
        )

    monkeypatch.setattr(mut.subprocess, "run", kaputt)

    lage = mut.gitlage([ZIEL_A, ZIEL_B])
    assert lage.modus is mut.Gitmodus.FEHLER
    assert "129" in lage.diagnose

    stub = Suitezaehler()
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == mut.HALT_VOR_GRUNDLAUF
    assert stub.rufe == 0
    assert "129" in ausgabe
    assert "unbekannte Option" in ausgabe


# --- 5.2 · Genau eine Abweichung nach jeder Mutation ------------------------


def test_exactly_the_selected_target_is_accepted_as_deviating(tmp_path, monkeypatch):
    """Richtung 8. Die Gegenprobe laeuft aus Bytes, nicht aus git-Verfolgung."""
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    basis = mut.startbaseline([ZIEL_A, ZIEL_B])[0]
    assert basis is not None

    (wurzel / ZIEL_A).write_text("def a():\n    return 2\n", encoding="utf-8")

    assert mut.abweichung([ZIEL_A, ZIEL_B], basis) == (ZIEL_A,)


def _schreibt(monkeypatch, was):
    monkeypatch.setattr(mut, "_schreibe_mutation", was)


@pytest.mark.parametrize(
    ("richtung", "angriff", "erwartet"),
    [
        ("null", "nichts", "keine"),
        ("zwei", "beide", "zwei"),
        ("falsche", "andere", "andere"),
    ],
)
@pytest.mark.parametrize("mit_git", [True, False])
def test_a_wrong_deviation_set_halts_before_the_mutant_suite_run(
    tmp_path, monkeypatch, capsys, richtung, angriff, erwartet, mit_git
):
    """Richtungen 9, 10, 11 — und 12: dieselben drei ohne Git.

    Der Angriff sitzt im Schreibschritt, weil genau dort ein Werkzeug
    Rueckstand erzeugt. Ein leerer Wert darf die Gegenprobe nie
    ueberspringen; vor E1 tat er genau das.
    """
    wurzel = _werkbank(tmp_path, git=mit_git)
    _stelle(monkeypatch, wurzel)

    def schreibe(ziel, alt, neu):  # noqa: ARG001
        if angriff == "nichts":
            return
        if angriff == "andere":
            (wurzel / ZIEL_B).write_text("def b():\n    return 4\n", encoding="utf-8")
            return
        (wurzel / ZIEL_A).write_text("def a():\n    return 2\n", encoding="utf-8")
        (wurzel / ZIEL_B).write_text("def b():\n    return 4\n", encoding="utf-8")

    _schreibt(monkeypatch, schreibe)

    stub = Suitezaehler([(GRUNDLAUF_STUB, 0)])
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == mut.HALT_VOR_SUITELAUF, richtung
    assert stub.rufe == 1, "nur der Grundlauf, kein Mutantensuitelauf"
    assert "Abweichung" in ausgabe
    assert _bytes(wurzel) == {ZIEL_A: INHALT_A.encode(), ZIEL_B: INHALT_B.encode()}


# --- 5.3 · Wiederherstellung ist bytegenau ---------------------------------


@pytest.mark.parametrize("ausgang", ["erfolg", "befund", "ausnahme"])
def test_every_outcome_leaves_the_targets_byte_identical(tmp_path, monkeypatch, ausgang):
    """Richtung 13. Erfolg, Werkzeugbefund und injizierte Ausnahme.

    Drei Ausgaenge, ein Anspruch: die Startbytes stehen danach wieder da. Die
    Ausnahme ist der Zweig, den ``finally`` traegt und den keine
    git-Vorkehrung ersetzen kann.
    """
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    vorher = _bytes(wurzel)

    if ausgang == "erfolg":
        stub = Suitezaehler([(GRUNDLAUF_STUB, 0), (MUTANT_FAELLT_STUB, 1)])
        assert mut.main(["TA"], lauf=stub, markierte=_keine_marker) == 0
    elif ausgang == "befund":
        stub = Suitezaehler([(GRUNDLAUF_STUB, 0), (GRUNDLAUF_STUB, 0)])
        assert mut.main(["TA"], lauf=stub, markierte=_keine_marker) == 1
    else:

        class Injiziert(RuntimeError):
            pass

        def explodiert():
            if explodiert.rufe:
                raise Injiziert("injizierter Abbruch mitten im Mutantenlauf")
            explodiert.rufe += 1
            return _lauf(GRUNDLAUF_STUB, 0)

        explodiert.rufe = 0
        with pytest.raises(Injiziert):
            mut.main(["TA"], lauf=explodiert, markierte=_keine_marker)

    assert _bytes(wurzel) == vorher


# --- 6 · F2: zwei Gitfehlerklassen, die E1 noch zusammenzog ----------------
#
# R2 hat am E1-Kandidaten 0dd96012 zwei tragende Blocker gemessen:
#
#   1. ``PermissionError`` und jede andere ``OSError``-Ausnahme wurden wie ein
#      fehlendes Git-Binary behandelt. Bei EACCES lief das Werkzeug damit
#      **fail-open** weiter — genau die Richtung, gegen die E1 gebaut war.
#   2. Bei ``git rev-parse --verify -q HEAD`` galt jeder Rueckgabewert ausser
#      null als „Repository ohne HEAD". Ein unerwartetes rc 129 verlor
#      Rueckgabewert und Diagnose und erschien als staged Schmutz.
#
# Beide Befunde sind angenommen. Die Klasse ist dieselbe wie in E1 selbst:
# **verschiedene Zustaende ueber einen Wert zusammengezogen**, nur eine Ebene
# tiefer. Ein Werkzeug gegen unbewiesene Zusagen darf seine eigene
# Fehlerbehandlung nicht raten.
#
# **Warum ``filename`` und nicht der Meldungstext.** Gemessen im Baucontainer,
# CPython 3.11: ein fehlendes Binary liefert ``FileNotFoundError`` mit
# ``filename`` = dem auszufuehrenden Programm, ein fehlendes Arbeits-
# verzeichnis denselben Ausnahmetyp mit ``filename`` = dem Verzeichnis. Der
# Meldungstext ist in beiden Faellen identisch. Die Herkunft steht also im
# Feld, nicht im Text.

import errno as _errno  # noqa: E402


def _git_wirft(monkeypatch, ausnahme: BaseException) -> None:
    """Jeder git-Aufruf wirft; alles andere laeuft echt weiter."""
    echt = subprocess.run

    def stub(befehl, *a, **k):
        if befehl and befehl[0] == mut.GIT_BINARY:
            raise ausnahme
        return echt(befehl, *a, **k)

    monkeypatch.setattr(mut.subprocess, "run", stub)


def _head_sonde_gibt(monkeypatch, rc: int, stderr: str = "") -> None:
    """Nur die HEAD-Sonde antwortet gesetzt; die uebrigen git-Aufrufe echt."""
    echt = subprocess.run

    def stub(befehl, *a, **k):
        if befehl and befehl[0] == mut.GIT_BINARY and "--verify" in befehl:
            return subprocess.CompletedProcess(args=befehl, returncode=rc, stdout="", stderr=stderr)
        return echt(befehl, *a, **k)

    monkeypatch.setattr(mut.subprocess, "run", stub)


# --- 6.1 · Ausnahmen beim Start eines Gitprozesses (F2-1) ------------------


def test_a_missing_git_binary_is_the_only_exception_that_means_no_git(
    tmp_path, monkeypatch, capsys
):
    """F2-Richtung 1. Der echte Kein-Binary-Fall bleibt tragend.

    Er ist die Gegenprobe zu den drei Ausnahmerichtungen darunter: ohne ihn
    pruefte diese Gruppe nur, dass immer gehalten wird.
    """
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    _git_wirft(monkeypatch, FileNotFoundError(_errno.ENOENT, "No such file or directory", "git"))

    lage = mut.gitlage([ZIEL_A, ZIEL_B])
    assert lage.modus is mut.Gitmodus.KEIN_GIT
    assert lage.klasse is mut.Gitklasse.KEIN_BINARY

    stub = Suitezaehler([(GRUNDLAUF_STUB, 0), (MUTANT_FAELLT_STUB, 1)])
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == 0
    assert stub.rufe == 2, "die inhaltsbasierten Tore tragen den Lauf ohne git"
    assert "kein Git" in ausgabe


def test_a_file_not_found_from_another_source_is_not_a_missing_binary(
    tmp_path, monkeypatch, capsys
):
    """F2-Richtung 2. Derselbe Ausnahmetyp, andere Herkunft, anderes Urteil.

    Ein fehlendes Arbeitsverzeichnis ist kein fehlendes git. Wer beide gleich
    liest, laesst einen kaputten Bauort als „kein Git" durchgehen.
    """
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    _git_wirft(
        monkeypatch,
        FileNotFoundError(_errno.ENOENT, "No such file or directory", "/nicht/vorhanden"),
    )

    lage = mut.gitlage([ZIEL_A, ZIEL_B])
    assert lage.modus is mut.Gitmodus.FEHLER
    assert lage.klasse is mut.Gitklasse.AUSNAHME
    assert "/nicht/vorhanden" in lage.diagnose

    stub = Suitezaehler()
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == mut.HALT_VOR_GRUNDLAUF
    assert stub.rufe == 0
    assert "FileNotFoundError" in ausgabe


def test_eacces_holds_fail_closed_instead_of_running_on(tmp_path, monkeypatch, capsys):
    """F2-Richtung 3. Der Blocker selbst: EACCES lief bisher fail-open weiter."""
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    _git_wirft(monkeypatch, PermissionError(_errno.EACCES, "Permission denied", "git"))

    lage = mut.gitlage([ZIEL_A, ZIEL_B])
    assert lage.modus is mut.Gitmodus.FEHLER
    assert lage.klasse is mut.Gitklasse.AUSNAHME
    assert "PermissionError" in lage.diagnose
    assert str(_errno.EACCES) in lage.diagnose

    stub = Suitezaehler()
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == mut.HALT_VOR_GRUNDLAUF
    assert stub.rufe == 0, "kein Suitelauf, wenn git nicht befragt werden konnte"
    assert "PermissionError" in ausgabe
    assert "kein Git" not in ausgabe, "eine Ausnahme ist nicht die bequemere Nachbarklasse"


def test_another_oserror_variant_is_also_a_named_error(tmp_path, monkeypatch, capsys):
    """F2-Richtung 4. Nicht nur die zwei bekannten Ausnahmetypen."""
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    _git_wirft(monkeypatch, OSError(_errno.EMFILE, "Too many open files"))

    lage = mut.gitlage([ZIEL_A, ZIEL_B])
    assert lage.modus is mut.Gitmodus.FEHLER
    assert lage.klasse is mut.Gitklasse.AUSNAHME
    assert "OSError" in lage.diagnose

    stub = Suitezaehler()
    assert mut.main(["TA"], lauf=stub, markierte=_keine_marker) == mut.HALT_VOR_GRUNDLAUF
    assert stub.rufe == 0


def test_an_exception_prints_no_invented_git_return_code(tmp_path, monkeypatch, capsys):
    """Zu F2-1: für eine Ausnahme ohne Prozessresultat gibt es keinen Exitcode.

    Der Werkzeug-Rueckgabewert 2 ist etwas anderes als ein git-Exitcode, und
    die Diagnose darf keinen erfinden.
    """
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    _git_wirft(monkeypatch, PermissionError(_errno.EACCES, "Permission denied", "git"))

    lage = mut.gitlage([ZIEL_A, ZIEL_B])

    assert "Exitcode" not in lage.diagnose
    assert "Rueckgabewert" not in lage.diagnose


# --- 6.2 · Der Rueckgabewert der HEAD-Sonde (F2-2) -------------------------


def test_head_probe_rc_zero_keeps_the_normal_worktree_path(tmp_path, monkeypatch):
    """F2-Richtung 5. Die Gegenprobe zu den drei Richtungen darunter."""
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    _head_sonde_gibt(monkeypatch, 0)

    lage = mut.gitlage([ZIEL_A, ZIEL_B])

    assert lage.modus is mut.Gitmodus.WORKTREE
    assert lage.klasse is mut.Gitklasse.NORMAL
    assert lage.verfolgt_sauber == (ZIEL_A, ZIEL_B)


def test_head_probe_rc_one_keeps_the_unborn_repository_path(tmp_path, monkeypatch):
    """F2-Richtung 6. Ohne HEAD gilt keine Zieldatei als gegen HEAD sauber.

    Das ist kein Fehler und kein Freibrief: ein Repository ohne Commit hat
    keine Bezugsgroesse, gegen die etwas sauber sein koennte.
    """
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    _head_sonde_gibt(monkeypatch, 1)

    lage = mut.gitlage([ZIEL_A, ZIEL_B])

    assert lage.modus is mut.Gitmodus.WORKTREE
    assert lage.klasse is mut.Gitklasse.OHNE_HEAD
    assert lage.verfolgt_sauber == ()
    assert lage.staged == (ZIEL_A, ZIEL_B)


def test_head_probe_rc_129_is_an_error_and_keeps_code_and_stderr(tmp_path, monkeypatch, capsys):
    """F2-Richtung 7. Der zweite Blocker: rc 129 erschien als staged Schmutz."""
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    _head_sonde_gibt(monkeypatch, 129, stderr="fatal: unbekannte Option --verify-xyz\n")

    lage = mut.gitlage([ZIEL_A, ZIEL_B])
    assert lage.modus is mut.Gitmodus.FEHLER
    assert lage.klasse is mut.Gitklasse.UNERWARTETER_RC
    assert "129" in lage.diagnose
    assert "unbekannte Option" in lage.diagnose

    stub = Suitezaehler()
    rc = mut.main(["TA"], lauf=stub, markierte=_keine_marker)
    ausgabe = capsys.readouterr().out

    assert rc == mut.HALT_VOR_GRUNDLAUF
    assert stub.rufe == 0
    assert "129" in ausgabe
    assert "unbekannte Option" in ausgabe
    assert "staged" not in ausgabe, "ein unerwarteter rc ist kein staged Schmutz"


@pytest.mark.parametrize("rc", [2, 3, 127, 128, -9])
def test_no_other_head_probe_code_is_read_as_a_missing_head(tmp_path, monkeypatch, rc):
    """F2-Richtung 8. Nicht nur 129 — jeder Nichtnullwert ausser 1.

    Auch 128: an der Repositoriumssonde heisst 128 „kein Worktree", an der
    HEAD-Sonde heisst es gar nichts Bekanntes. Ein Exitcode traegt seine
    Bedeutung nicht mit sich herum, sondern von der Frage, die ihn erzeugt hat.
    """
    wurzel = _werkbank(tmp_path, git=True)
    _stelle(monkeypatch, wurzel)
    _head_sonde_gibt(monkeypatch, rc, stderr="fatal: irgendwas\n")

    lage = mut.gitlage([ZIEL_A, ZIEL_B])

    assert lage.modus is mut.Gitmodus.FEHLER
    assert lage.klasse is mut.Gitklasse.UNERWARTETER_RC
    assert lage.klasse is not mut.Gitklasse.OHNE_HEAD
    assert str(rc) in lage.diagnose


# --- 6.3 · Etikettentreue der fuenf Klassen (F2-3) -------------------------


def test_the_five_git_classes_carry_five_distinct_labels():
    """F2-3. Fuenf unterscheidbare Klassen, fuenf unterscheidbare Etiketten.

    Ausgeschrieben statt aus dem Enum errechnet: ein Test, der seine Sollmenge
    aus dem Prueflung holt, prueft den Pruefling gegen sich selbst.
    """
    erwartet = {
        mut.Gitklasse.NORMAL,
        mut.Gitklasse.OHNE_HEAD,
        mut.Gitklasse.KEIN_BINARY,
        mut.Gitklasse.KEIN_WORKTREE,
        mut.Gitklasse.AUSNAHME,
        mut.Gitklasse.UNERWARTETER_RC,
    }
    etiketten = {k.value for k in erwartet}

    assert len(etiketten) == 6, f"Etiketten fallen zusammen: {sorted(etiketten)}"
    assert set(mut.Gitklasse) == erwartet
