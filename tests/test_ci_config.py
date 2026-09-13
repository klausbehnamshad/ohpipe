"""Check that the public CI actually runs its stated checks with read-only access."""

from pathlib import Path
import os
import subprocess
import re

import pytest

yaml = pytest.importorskip("yaml", reason="pyyaml belongs to the dev dependencies")
ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {"tests", "lint", "package"}


@pytest.fixture(scope="module")
def ci():
    return yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())


def test_workflow_triggers_and_jobs(ci):
    assert set(ci["on"]) == {"push", "pull_request", "workflow_dispatch"}
    assert set(ci["jobs"]) == EXPECTED


def test_read_only_permissions_and_pinned_actions(ci):
    assert ci["permissions"] == {"contents": "read"}
    for job in ci["jobs"].values():
        assert "permissions" not in job
        for step in job["steps"]:
            if "uses" in step:
                assert re.fullmatch(r"actions/[a-z-]+@[a-f0-9]{40}", step["uses"])
                if step["uses"].startswith("actions/checkout@"):
                    assert step["with"]["persist-credentials"] is False


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_commands_are_strings_and_failures_are_not_hidden(ci, name):
    job = ci["jobs"][name]
    assert not job.get("continue-on-error")
    assert job["timeout-minutes"] <= 30
    for step in job["steps"]:
        assert not step.get("continue-on-error")
        if "run" in step:
            assert isinstance(step["run"], str)
            assert "|| true" not in step["run"]


def commands(ci, name):
    return "\n".join(s.get("run", "") for s in ci["jobs"][name]["steps"])


def test_full_suite_excludes_live_probe_before_collection(ci):
    cmd = commands(ci, "tests")
    assert "-m pytest --ignore=tests/test_ollama_live.py" in cmd
    assert '-k ' not in cmd and '-m "' not in cmd
    assert '--basetemp="$RUNNER_TEMP/' in cmd


def test_lint_includes_every_shipped_python_directory(ci):
    roots = set(_versionierte_python_verzeichnisse())
    assert roots, "No tracked Python files; stage the public checkout before CI checks"
    assert roots <= set(commands(ci, "lint").split())



def test_wheel_is_installed_and_run_outside_the_checkout(ci):
    cmd = commands(ci, "package")
    assert '-m build' in cmd
    assert '-m pip install dist/*.whl' in cmd
    assert 'cd "$RUNNER_TEMP"' in cmd
    assert 'bin/ohpipe" --help' in cmd
    assert 'load_tap()' in cmd
    assert 'bash examples/synthetic/durchstich.sh' in cmd


def _versionierte_python_verzeichnisse(wurzel: Path | None = None) -> list[str]:
    """Die obersten Verzeichnisse, in denen VERSIONIERTES Python liegt.

    Gefragt wird git und nicht das Dateisystem. Vorbild ist
    ``test_b3b_norm_coverage.py::_product_digest``, das aus demselben Grund
    ``git ls-files --stage src`` bindet: Was das Projekt ausmacht, steht im
    Index, nicht auf der Platte.

    ``GIT_OPTIONAL_LOCKS=0`` wie dort: Ein lesender Aufruf soll keine
    Indexsperre anfassen.
    """
    wurzel = wurzel or Path(__file__).resolve().parents[1]
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    roh = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.py"],
        cwd=wurzel,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    oberste = {
        pfad.split("/", 1)[0]
        for pfad in roh.split("\0")
        if pfad and "/" in pfad
    }
    return sorted(oberste)


def test_an_unversioned_directory_with_python_does_not_move_the_check(ci, tmp_path, monkeypatch):
    """Ein Ablageverzeichnis, das git nicht führt, ist kein Befund.

    Der Fall stellt genau das nach, was am 06.09.2026 zweimal passiert ist:
    Ein Verzeichnis im Wurzelverzeichnis, gitignoriert, mit einer ``.py``
    darin. Die frühere Fassung fand es über ``rglob`` und schlug an; diese
    fragt git und sieht es nicht.

    Gefahren wird gegen ein FRISCHES Repositorium im ``tmp_path``, nicht gegen
    den Baum, in dem der Test läuft: Ein Fall, der auf den eigenen
    Arbeitsbaum wirkt, misst mit, was gerade zufällig darin liegt.
    """
    for verzeichnis, datei in (("src", "echt.py"), ("tools", "werkzeug.py")):
        (tmp_path / verzeichnis).mkdir()
        (tmp_path / verzeichnis / datei).write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "_ablage").mkdir()
    (tmp_path / "_ablage" / "hingefallen.py").write_text("y = 2\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("_ablage/\n", encoding="utf-8")

    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    for befehl in (["git", "init", "-q"], ["git", "add", "-A"]):
        subprocess.run(befehl, cwd=tmp_path, env=env, check=True, capture_output=True)

    # Gefahren wird die FUNKTION, nicht eine Kopie ihres git-Aufrufs: Ein Fall,
    # der die Mechanik nachbaut, prueft seine eigene Kopie und faellt nicht,
    # wenn die Funktion sich aendert.
    gemessen = _versionierte_python_verzeichnisse(tmp_path)
    assert gemessen == ["src", "tools"], gemessen
    assert "_ablage" not in gemessen, "das gitignorierte Verzeichnis zaehlt wieder mit"


def test_a_versioned_directory_without_a_lint_entry_still_fails_the_check():
    """Die Gegenprobe: Die Prüfung ist nicht dadurch grün geworden, dass sie schweigt.

    Gemessen wird die Regel selbst, an einer erfundenen Liste: Ein
    versioniertes Verzeichnis, das im lint-Skript nicht vorkommt, muss weiter
    auffallen. Ohne diesen Fall hätte der Umbau die Prüfung wirkungslos machen
    können, ohne dass ein Test es merkt.
    """
    zeilen = "ruff check src tests"
    verzeichnisse = ["src", "tests", "tools"]
    fehlend = [d for d in verzeichnisse if d not in ("build", "dist") and d not in zeilen]
    assert fehlend == ["tools"], fehlend
