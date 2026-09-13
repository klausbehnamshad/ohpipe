"""Profilgrenze für das optionale Codebuch; keine Modellverbindung."""

import pytest

from ohpipe.project import Profile, ProfileError


def _profile(tmp_path, extra):
    path = tmp_path / "profile.toml"
    path.write_text('[profile]\nid = "test"\nrecord_prefix = "TEST"\n' + extra)
    return path


def test_codebook_01_profile_missing_named_file_is_profile_error(tmp_path):
    path = _profile(tmp_path, 'codebook = "missing.toml"\n')
    with pytest.raises(ProfileError, match="missing.toml.*Codebuch fehlt"):
        Profile.load(path)
    (tmp_path / "missing.toml").write_text("# existence checked at profile load")
    assert Profile.load(path).codebook == "missing.toml"
    assert Profile.load(_profile(tmp_path, 'codebook = ""\n')).codebook == ""
    assert Profile.load(_profile(tmp_path, "")).codebook == ""


def test_codebook_07_profile_rejects_paths_and_parent_traversal(tmp_path):
    path = _profile(tmp_path, 'codebook = "../woanders.toml"\n')
    with pytest.raises(ProfileError, match="Dateiname ohne Pfad"):
        Profile.load(path)
    for value in ('"/tmp/book.toml"', "'sub\\book.toml'", '"a..toml"', "123"):
        path = _profile(tmp_path, f"codebook = {value}\n")
        with pytest.raises(ProfileError):
            Profile.load(path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "book.toml").write_text("# outside profile directory")
    (tmp_path / "link.toml").symlink_to(outside / "book.toml")
    with pytest.raises(ProfileError, match="außerhalb"):
        Profile.load(_profile(tmp_path, 'codebook = "link.toml"\n'))


def test_codebook_15_unknown_profile_key_remains_an_error(tmp_path):
    path = _profile(tmp_path, 'codebook = ""\ncodebok = ""\n')
    with pytest.raises(ProfileError, match="unbekannte Felder: codebok"):
        Profile.load(path)
