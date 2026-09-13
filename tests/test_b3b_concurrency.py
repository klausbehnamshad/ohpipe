from concurrent.futures import ThreadPoolExecutor

import pytest

from ohpipe.domain.instance import InstanceRegistry
from ohpipe.workspace_lock import workspace_write_lock


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-014"])
def test_workspace_lock_serialises_one_hundred_runs(_case, tmp_path):
    state = []
    (tmp_path / "_governance").mkdir()

    def append(number):
        with workspace_write_lock(tmp_path):
            state.append(number)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(append, range(100)))
    assert sorted(state) == list(range(100))


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-015"])
def test_registry_order_is_deterministic_one_hundred_times(_case):
    for _ in range(100):
        registry = InstanceRegistry()
        for coder in ("coder.b", "coder.a"):
            registry.register(
                registry.registration_payload(
                    coder, source="mensch", label=coder, reference="ref.001"
                )
            )
        assert [item.coder_id for item in registry.active_humans()] == ["coder.a", "coder.b"]


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-016"])
def test_lock_file_is_cleaned(_case, tmp_path):
    (tmp_path / "_governance").mkdir()
    with workspace_write_lock(tmp_path):
        assert list((tmp_path / "_governance").glob("*.lock"))
    lock = tmp_path / "_governance" / ".b3b-workspace-write.lock"
    assert lock.is_file() and lock.stat().st_size == 0
