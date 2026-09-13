"""E8 bindet den laufenden Graphvertrag außerhalb des Journals.

Die Tests gehen jeweils gegen den Schaden: stille Neubindung, ein grün
durchlaufender Altbestand, ein wirkungsloser Upgradeakt und eine Bindungsdatei,
die nicht der engen gespeicherten Form entspricht.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from ohpipe.cli.main import build_parser

from ._forge import cli, cli_keyed, journal_path

# P2: Graphdomäne v2; kanonische Vektoren unter p2/evidence/graph-contract-v2.json.
SANDBOX_GRAPH_SHA256 = "bcc5a96b8625c90e6ef73bdf505eda151109e16b804cf84a99c7f942b25463be"
CHILDLUX_GRAPH_SHA256 = "79f9988a303b2c21436d5bd71505ac220a5133a36176e4b543e07ef96676d143"


def _binding(root: Path) -> Path:
    return root / "_governance" / "graph-contract.json"


def _init(root: Path):
    result = cli("init", "--json", root=root)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout)


def _replace_binding(root: Path, *, sha256: str) -> bytes:
    path = _binding(root)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["graph_sha256"] = sha256
    path.write_text(json.dumps(raw, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path.read_bytes()


def _report(result: subprocess.CompletedProcess) -> dict:
    assert result.stdout, result.stderr
    return json.loads(result.stdout)


def _assert_e8_commands_are_bound(report: dict, *, profile: str, root: Path) -> None:
    """Prüft nur E8-ohpipe-Ausgaben; export/unset/ls bleiben außerhalb."""
    found = False
    for field in ("next", "check"):
        command = report[field]
        if command is None:
            continue
        # Ein Kommentar beginnt nach der Reportkonvention erst hinter mehreren
        # Leerzeichen. Ein # im shell-quotierten Profilpfad ist Dateninhalt.
        executable = re.split(r"\s{2,}#", command, maxsplit=1)[0]
        if not executable.startswith("ohpipe"):
            continue
        found = True
        tokens = shlex.split(executable)
        parsed = build_parser().parse_args(tokens[1:])
        assert parsed.profile == profile
        assert Path(parsed.root) == root.resolve()
    assert found, report


def _run_emitted(command: str, *, env_root: Path) -> subprocess.CompletedProcess:
    executable = re.split(r"\s{2,}#", command, maxsplit=1)[0]
    tokens = shlex.split(executable)
    assert tokens[0] == "ohpipe"
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src"),
        "OHPIPE_DATA_ROOT": str(env_root),
    }
    return subprocess.run(
        [sys.executable, "-m", "ohpipe.cli.main", *tokens[1:], "--json"],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def _bytes_below(root: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(root)): path.read_bytes() for path in root.rglob("*") if path.is_file()
    }


def test_init_pins_the_literal_graph_outside_the_journal(tmp_path):
    """Leistungen 1 und 5: Ort, Zeitpunkt und der erste Literal-Pin."""
    root = tmp_path / "daten"
    report = _init(root)
    path = _binding(root)

    assert json.loads(path.read_text(encoding="utf-8")) == {
        "graph_sha256": SANDBOX_GRAPH_SHA256,
        "profile": "sandbox",
        "schema": 1,
    }
    assert path != journal_path(root)
    assert path.stat().st_mode & 0o777 == 0o600
    journal = journal_path(root).read_text(encoding="utf-8")
    assert "graph_sha256" not in journal
    assert SANDBOX_GRAPH_SHA256 not in journal
    assert str(path) in report["changed"]


def test_childlux_init_binds_its_own_profile_and_literal(tmp_path):
    """Der Profilname ist Vertragsinhalt und darf nicht auf Sandbox fallen."""
    root = tmp_path / "childlux-daten"
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-ausreichend-langer-testschluessel")
    result = cli_keyed("--profile", "childlux", "init", "--json", root=root, key=key)
    assert result.returncode == 0, result.stdout
    assert json.loads(_binding(root).read_text(encoding="utf-8")) == {
        "graph_sha256": CHILDLUX_GRAPH_SHA256,
        "profile": "childlux",
        "schema": 1,
    }
    assert (
        cli_keyed("--profile", "childlux", "doctor", "--json", root=root, key=key).returncode == 0
    )


def test_a_mismatch_is_named_and_never_silently_rebound(tmp_path):
    """Leistung 2 gegen ihre Gefahr: status liest, meldet und schreibt nichts."""
    root = tmp_path / "daten"
    _init(root)
    vorher = _replace_binding(root, sha256="0" * 64)

    result = cli("status", "--json", root=root)
    assert result.returncode == 3, result.stdout
    report = json.loads(result.stdout)
    assert report["status"] == "GRAPH_CONTRACT_MISMATCH"
    assert report["reason_code"] == "GRAPH_CONTRACT_MISMATCH"
    assert report["changed"] == []
    assert _binding(root).read_bytes() == vorher

    again = cli("init", "--json", root=root)
    assert json.loads(again.stdout)["status"] == "GRAPH_CONTRACT_MISMATCH"
    assert _binding(root).read_bytes() == vorher


def test_the_upgrade_rejects_an_unconfirmed_value_without_change(tmp_path):
    """Leistung 3: --to ist die menschliche Bestätigung, kein Schmuckargument."""
    root = tmp_path / "daten"
    _init(root)
    vorher = _replace_binding(root, sha256="0" * 64)

    result = cli("graph-upgrade", "--to", "1" * 64, "--json", root=root)
    assert result.returncode == 2, result.stdout
    assert json.loads(result.stdout)["reason_code"] == "CONFIG_GRAPH_UPGRADE_TARGET"
    assert _binding(root).read_bytes() == vorher


def test_the_explicit_upgrade_rebinds_to_the_current_literal(tmp_path):
    """Leistung 3 positiv: nur der eigene Befehl hebt die Bindung an."""
    root = tmp_path / "daten"
    _init(root)
    _replace_binding(root, sha256="0" * 64)

    result = cli("graph-upgrade", "--to", SANDBOX_GRAPH_SHA256, "--json", root=root)
    assert result.returncode == 0, result.stdout
    report = json.loads(result.stdout)
    assert report["changed"] == [str(_binding(root))]
    assert json.loads(_binding(root).read_text(encoding="utf-8"))["graph_sha256"] == (
        SANDBOX_GRAPH_SHA256
    )
    assert cli("doctor", "--json", root=root).returncode == 0


def test_a_pre_e8_journal_has_a_named_unbound_state(tmp_path):
    """Leistung 4: Altbestand ist benannt und wird weder grün noch migriert."""
    root = tmp_path / "daten"
    _init(root)
    _binding(root).unlink()

    result = cli("status", "--json", root=root)
    assert result.returncode == 3, result.stdout
    report = json.loads(result.stdout)
    assert report["status"] == "GRAPH_CONTRACT_UNBOUND"
    assert report["reason_code"] == "GRAPH_CONTRACT_UNBOUND"
    assert report["changed"] == []
    assert not _binding(root).exists()

    again = cli("init", "--json", root=root)
    assert json.loads(again.stdout)["status"] == "GRAPH_CONTRACT_UNBOUND"
    assert not _binding(root).exists()


def test_a_pre_e8_journal_can_only_be_bound_by_the_upgrade_act(tmp_path):
    root = tmp_path / "daten"
    _init(root)
    _binding(root).unlink()

    result = cli("graph-upgrade", "--to", SANDBOX_GRAPH_SHA256, "--json", root=root)
    assert result.returncode == 0, result.stdout
    assert _binding(root).exists()
    assert cli("doctor", "--json", root=root).returncode == 0


def test_an_invalid_binding_is_a_safety_stop_and_is_not_overwritten(tmp_path):
    root = tmp_path / "daten"
    _init(root)
    path = _binding(root)
    path.write_text('{"schema": 1, "extra": true}\n', encoding="utf-8")
    path.chmod(0o600)
    vorher = path.read_bytes()

    result = cli("graph-upgrade", "--to", SANDBOX_GRAPH_SHA256, "--json", root=root)
    assert result.returncode == 1, result.stdout
    assert json.loads(result.stdout)["reason_code"] == "STOP_GRAPH_BINDING_INVALID"
    assert path.read_bytes() == vorher


def test_a_symlinked_binding_is_a_safety_stop(tmp_path):
    root = tmp_path / "daten"
    _init(root)
    path = _binding(root)
    ausserhalb = tmp_path / "fremd.json"
    ausserhalb.write_bytes(path.read_bytes())
    path.unlink()
    path.symlink_to(ausserhalb)

    result = cli("doctor", "--json", root=root)
    assert result.returncode == 1, result.stdout
    assert json.loads(result.stdout)["reason_code"] == "STOP_GRAPH_BINDING_INVALID"
    assert path.is_symlink()


def test_a_dangling_binding_is_a_safety_stop_for_doctor_and_status(tmp_path):
    """F6: Ein gebrochener Link ist ungültig, nicht fehlend oder pristine."""
    root = tmp_path / "daten"
    path = _binding(root)
    path.parent.mkdir(parents=True)
    target = tmp_path / "fehlt.json"
    path.symlink_to(target)

    for command in ("doctor", "status"):
        result = cli(command, "--json", root=root)
        assert result.returncode == 1, result.stdout + result.stderr
        report = _report(result)
        assert report["status"] == "STOP"
        assert report["reason_code"] == "STOP_GRAPH_BINDING_INVALID"
        _assert_e8_commands_are_bound(report, profile="sandbox", root=root)
        assert path.is_symlink()
        assert not target.exists()


def test_a_pristine_root_is_initialised_instead_of_migrated(tmp_path):
    root = tmp_path / "daten"
    result = cli("status", "--json", root=root)
    report = json.loads(result.stdout)
    assert report["status"] == "ACTION_NEEDED"
    assert report["reason_code"] == "ACTION_WORKSPACE_NOT_INITIALISED"
    assert " init" in report["next"]
    assert "graph-upgrade" not in report["next"]


def test_repeating_the_confirmed_upgrade_is_idempotent(tmp_path):
    root = tmp_path / "daten"
    _init(root)
    result = cli("graph-upgrade", "--to", SANDBOX_GRAPH_SHA256, "--json", root=root)
    assert result.returncode == 0, result.stdout
    assert json.loads(result.stdout)["changed"] == []
    assert os.stat(_binding(root)).st_mode & 0o777 == 0o600


def test_the_emitted_upgrade_next_changes_only_its_explicit_root(tmp_path):
    """F7: Die Umgebung zeigt auf A, der Befund und sein NEXT aber exakt auf B."""
    root_a = tmp_path / "umgebung-a"
    root_b = tmp_path / "befund-b"
    _init(root_a)
    _init(root_b)
    _replace_binding(root_b, sha256="0" * 64)
    a_before = _bytes_below(root_a)

    mismatch = cli("status", "--root", str(root_b), "--json", root=root_a)
    assert mismatch.returncode == 3, mismatch.stdout + mismatch.stderr
    report = _report(mismatch)
    assert report["reason_code"] == "GRAPH_CONTRACT_MISMATCH"
    _assert_e8_commands_are_bound(report, profile="sandbox", root=root_b)

    upgraded = _run_emitted(report["next"], env_root=root_a)
    assert upgraded.returncode == 0, upgraded.stdout + upgraded.stderr
    assert _bytes_below(root_a) == a_before
    assert json.loads(_binding(root_b).read_text(encoding="utf-8"))["graph_sha256"] == (
        SANDBOX_GRAPH_SHA256
    )


def test_every_emitted_e8_command_parses_with_profile_and_resolved_root(tmp_path):
    """Auflage B: E8-NEXT/CHECK bleiben als Klasse shell-sicher und kontextgebunden."""
    profile_dir = tmp_path / "profil mit leerzeichen # und raute"
    profile_dir.mkdir()
    profile = profile_dir / "profile.toml"
    profile.write_text(
        (
            Path(__file__).resolve().parents[1] / "src/ohpipe/profiles/sandbox/profile.toml"
        ).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    profile_arg = str(profile)

    pristine = tmp_path / "pristine root"
    report = _report(cli("status", "--profile", profile_arg, "--json", root=pristine))
    assert report["reason_code"] == "ACTION_WORKSPACE_NOT_INITIALISED"
    _assert_e8_commands_are_bound(report, profile=profile_arg, root=pristine)

    root = tmp_path / "gebundene root"
    _init(root)
    _binding(root).unlink()
    unbound = _report(cli("status", "--profile", profile_arg, "--json", root=root))
    assert unbound["reason_code"] == "GRAPH_CONTRACT_UNBOUND"
    _assert_e8_commands_are_bound(unbound, profile=profile_arg, root=root)

    wrong_target = _report(
        cli(
            "graph-upgrade",
            "--profile",
            profile_arg,
            "--to",
            "1" * 64,
            "--json",
            root=root,
        )
    )
    assert wrong_target["reason_code"] == "CONFIG_GRAPH_UPGRADE_TARGET"
    _assert_e8_commands_are_bound(wrong_target, profile=profile_arg, root=root)

    upgraded = _report(
        cli(
            "graph-upgrade",
            "--profile",
            profile_arg,
            "--to",
            SANDBOX_GRAPH_SHA256,
            "--json",
            root=root,
        )
    )
    assert upgraded["status"] == "READY"
    _assert_e8_commands_are_bound(upgraded, profile=profile_arg, root=root)

    invalid = _binding(root)
    invalid.write_text("{}\n", encoding="utf-8")
    invalid.chmod(0o600)
    stopped = _report(
        cli(
            "graph-upgrade",
            "--profile",
            profile_arg,
            "--to",
            SANDBOX_GRAPH_SHA256,
            "--json",
            root=root,
        )
    )
    assert stopped["reason_code"] == "STOP_GRAPH_BINDING_INVALID"
    _assert_e8_commands_are_bound(stopped, profile=profile_arg, root=root)
