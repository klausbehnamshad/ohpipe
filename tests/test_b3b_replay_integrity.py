from datetime import datetime, timezone

import pytest

from ohpipe.journal import Event


def _event(operation_intent_sha256="b" * 64):
    values = {
        "seq": 1,
        "at": datetime.now(timezone.utc).isoformat(),
        "kind": "artifact.produced",
        "record_id": "SANDBOX-001",
        "payload": {"artifact": "transcript.revision", "sha256": "a" * 64},
        "prev": "0" * 64,
        "operation_intent_sha256": operation_intent_sha256,
    }
    return Event(
        **values,
        digest=Event.compute_digest(**values),
    )


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-025"])
def test_intent_bound_event_roundtrips(_case):
    event = _event()
    assert Event.from_json(event.to_json()).digest == event.digest


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-026"])
def test_intent_field_changes_digest(_case):
    assert _event("b" * 64).digest != _event("c" * 64).digest


@pytest.mark.parametrize("_case", [None], ids=["B3BEXTRA-027"])
def test_invalid_intent_hash_rejected(_case):
    with pytest.raises(ValueError):
        Event.from_json(_event("short").to_json())
