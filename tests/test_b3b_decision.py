import pytest

from ._b3b import assert_case, load_cases

CASES = load_cases("DEC")


@pytest.mark.parametrize("case", CASES, ids=[case["norm_id"] for case in CASES])
def test_b3b_norm_contract(case, tmp_path, monkeypatch):
    assert_case(case, tmp_path, monkeypatch)
