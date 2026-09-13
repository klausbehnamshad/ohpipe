import pytest

from ohpipe.application.operation_recovery import recovery_report
from ohpipe.domain.operation import MatrixState, OperationTrace, classify_recovery

CASES = [
    ("B3BEXTRA-007", MatrixState.A, OperationTrace(False, False, False, ("x",), ())),
    ("B3BEXTRA-008", MatrixState.B, OperationTrace(True, False, True, ("x",), ())),
    ("B3BEXTRA-009", MatrixState.C, OperationTrace(True, True, False, ("x",), ())),
    ("B3BEXTRA-010", MatrixState.D, OperationTrace(True, True, True, ("x",), ("x",))),
    ("B3BEXTRA-011", MatrixState.E, OperationTrace(True, True, True, ("x", "y"), ("x",))),
    ("B3BEXTRA-012", MatrixState.F, OperationTrace(True, True, True, ("x",), ())),
    ("B3BEXTRA-013", MatrixState.G, OperationTrace(True, True, True, ("x",), ("other",))),
]


@pytest.mark.parametrize(
    "expected,trace",
    [(expected, trace) for _, expected, trace in CASES],
    ids=[row[0] for row in CASES],
)
def test_recovery_matrix(expected, trace):
    assert classify_recovery(trace) is expected
    report = recovery_report(trace, retry_command="ohpipe status")
    assert report.details["matrix_state"] == expected.value
    assert report.changed == []
