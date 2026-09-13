"""Exercise current C6/C7 placement requirements with synthetic temporary stores."""

import json
from pathlib import Path

import pytest

from ohpipe.protected_store import ProtectedStore, ProtectionError, canonical
from ohpipe.registry_store import RegistryStore

from .test_spur_p1 import isolated  # noqa: F401
from .test_spur_p4b import world  # noqa: F401
from .test_spur_p4c import ready  # noqa: F401


def _private_file(path, data):
    path.write_bytes(data)
    path.chmod(0o600)
    return path


@pytest.mark.parametrize(
    "change",
    [
        "registry_key_equals_candidate_key",
        "registry_key_equals_journal_key",
        "registry_key_equals_protection_key",
        "protection_key_equals_journal_key",
        "registry_aliases_protection_store",
        "registry_inside_workspace",
        "protection_inside_workspace",
        "registry_key_inside_store",
        "protection_key_inside_store",
        "registry_config_inside_workspace",
        "protection_config_inside_workspace",
    ],
)
def test_current_stores_reject_unsafe_placement_and_key_reuse(request, monkeypatch, change):
    w = request.getfixturevalue("ready")
    reg = json.loads(w.registry_config.read_bytes())
    prot = json.loads(w.protection_config.read_bytes())
    registry_key = Path(reg["key_file"])
    if change == "registry_key_equals_candidate_key":
        registry_key.write_bytes(Path(reg["candidate_key_file"]).read_bytes())
    elif change == "registry_key_equals_journal_key":
        registry_key.write_bytes(w.journal.key)
    elif change == "registry_key_equals_protection_key":
        registry_key.write_bytes(w.protection_key.read_bytes())
    elif change == "protection_key_equals_journal_key":
        w.protection_key.write_bytes(w.journal.key)
    elif change == "registry_aliases_protection_store":
        reg["root"] = prot["root"]
    elif change in {"registry_inside_workspace", "protection_inside_workspace"}:
        target = w.ws.root / "synthetic-forbidden-store"
        target.mkdir(mode=0o700)
        for directory in ("objects", "sessions"):
            (target / directory).mkdir(mode=0o700)
        config = reg if change.startswith("registry") else prot
        config["root"] = str(target)
    elif change == "registry_key_inside_store":
        path = _private_file(Path(reg["root"]) / "synthetic.key", registry_key.read_bytes())
        reg["key_file"] = str(path)
    elif change == "protection_key_inside_store":
        path = _private_file(Path(prot["root"]) / "synthetic.key", w.protection_key.read_bytes())
        prot["key_file"] = str(path)
    elif change == "registry_config_inside_workspace":
        path = _private_file(w.ws.root / "synthetic-registry.json", canonical(reg))
        monkeypatch.setenv("OHPIPE_REGISTRY_CONFIG", str(path))
    elif change == "protection_config_inside_workspace":
        path = _private_file(w.ws.root / "synthetic-protection.json", canonical(prot))
        monkeypatch.setenv("OHPIPE_PROTECTION_CONFIG", str(path))
    w.registry_config.write_bytes(canonical(reg))
    w.protection_config.write_bytes(canonical(prot))
    before = w.journal.path.read_bytes()
    with pytest.raises(ProtectionError):
        RegistryStore(w.ws, w.journal.key)
    assert w.journal.path.read_bytes() == before


def test_separate_external_stores_with_distinct_keys_remain_usable(request):
    w = request.getfixturevalue("ready")
    protection = ProtectedStore(w.ws, w.journal.key)
    registry = RegistryStore(w.ws, w.journal.key)
    assert protection.root != registry.root
    assert len({protection.key, registry.key, registry.candidate_key, w.journal.key}) == 4
    assert registry.head() is not None
