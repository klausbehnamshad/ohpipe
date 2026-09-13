import pytest

from ohpipe.domain.operation import MatrixState, OperationTrace, classify_recovery

PREFIXES = [
    ("B3BEXTRA-017", (), MatrixState.F),
    ("B3BEXTRA-018", ("intent",), MatrixState.E),
    ("B3BEXTRA-019", ("intent", "effect"), MatrixState.D),
    ("B3BEXTRA-020", ("effect",), MatrixState.G),
]


@pytest.mark.parametrize(
    "actual,expected",
    [(actual, expected) for _, actual, expected in PREFIXES],
    ids=[row[0] for row in PREFIXES],
)
def test_persisted_crash_prefix_classification(actual, expected):
    trace = OperationTrace(True, True, True, ("intent", "effect"), actual)
    assert classify_recovery(trace) is expected
