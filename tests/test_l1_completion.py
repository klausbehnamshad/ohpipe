"""K-V1: begrenzte Ergänzung, vollständige Publikation, überprüfte Wiederverwendung.

Ausschließlich synthetische Fixtures; kein Modellserver und keine menschlichen Akte.
"""

import io
import json
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest

from ohpipe.application import l1_suggest as l1
from ohpipe.adapters.models.fixture import FixtureAdapter
from ohpipe.adapters.models.ollama import OllamaAdapter
from ohpipe.domain.hashing import sha256_bytes, sha256_json, sha256_text
from ohpipe.domain.transcript import Segment

from .test_l1_suggest import (
    RECORD,
    _BlockFixture,
    _coded_response,
    _codebook_world,
    _ctx,
    _document,
    _many_segments,
    _view,
    _welt,
    _zustand,
)


def _omit(response, missing):
    obj = json.loads(response.text)
    obj["results"] = [row for row in obj["results"] if row["segment"] not in missing]
    return replace(response, text=json.dumps(obj, ensure_ascii=False))


def _object(ws, result):
    with ws.store().open_verified(result.artifact_sha256) as handle:
        return json.load(handle)


def test_partial_mode_is_explicit_nonempty_and_proper():
    with pytest.raises(l1.SuggestError):
        l1.parse_answer(_document([2]), [2, 7])
    assert l1.parse_answer(_document([2]), [2, 7], partial=True)[0]["segment"] == 2
    for indices in ([], [2, 7], [2, 2], [2, 9]):
        with pytest.raises(l1.SuggestError):
            l1.parse_answer(_document(indices), [2, 7], partial=True)


@pytest.mark.parametrize("partial", [False, True])
@pytest.mark.parametrize(
    "text",
    [
        "",
        "{}",
        '```json\n{"results": []}\n```',
        '{"results": [], "results": []}',
        '{"results": [{"segment": 0, "segment": 1, "code": "AA"}]}',
        '{"results": [{"segment": NaN, "code": "AA"}]}',
        '{"results": [{"segment": true, "code": "AA"}]}',
        '{"results": [{"segment": 0, "code": " "}]}',
        '{"results": [{"segment": 0, "code": "FREMD"}]}',
        '{"results": [{"segment": 0, "code": "SECRET-CANARY text"}]}',
    ],
)
def test_partial_mode_keeps_all_json_and_code_guards(text, partial):
    with pytest.raises(l1.SuggestError) as error:
        l1.parse_answer(text, [0, 1], frozenset({"AA"}), partial=partial)
    assert "SECRET-CANARY" not in str(error.value)


@pytest.mark.parametrize("missing", [{63}, {2, 7, 63}])
def test_completion_sends_exact_missing_original_segments_and_own_receipt(tmp_path, missing):
    segments = tuple(
        Segment(i, i * 1000, (i + 1) * 1000, f"Synthetisches Segment {i}.", "A", "deu")
        for i in range(65)
    )
    ws, journal, rev = _welt(tmp_path, segmente=segments)
    adapter = _BlockFixture(lambda n, r: _omit(r, missing) if n == 1 else r)
    times = iter(
        ["2026-09-12T10:00:00+00:00", "2026-09-12T10:00:01+00:00", "2026-09-12T10:00:02+00:00"]
    )
    result = l1.run_l1_suggest(
        _ctx(ws, journal), _view(ws, journal), adapter=adapter, clock=lambda: next(times)
    )
    obj = _object(ws, result)
    assert len(adapter.calls) == 3 and result.suggestions == 65
    payloads = [json.loads(prompt.partition("\n\n")[2]) for prompt, _ in adapter.calls]
    assert payloads[1]["segments"] == [s for s in payloads[0]["segments"] if s["index"] in missing]
    assert payloads[1]["supplement"] == {
        "parent_prompt_sha256": sha256_text(adapter.calls[0][0]),
        "segment_indices": sorted(missing),
    }
    assert payloads[1]["revision_sha256"] == rev.sha256
    assert [p is adapter.calls[0][1] for _, p in adapter.calls] == [True] * 3
    assert [r["kind"] for r in obj["requests"]] == ["original", "supplement", "original"]
    request = obj["requests"][1]
    assert request["segments"] == sorted(missing)
    assert request["receipt"]["prompt_sha256"] == sha256_text(adapter.calls[1][0])
    assert request["receipt"]["output_sha256"] == sha256_bytes(
        request["response_text"].encode("utf-8")
    )
    assert request["receipt"]["params"] == adapter.params.to_json()
    assert request["receipt"]["inputs"]["transcript.revision"] == rev.sha256
    assert request["receipt"]["started_at"] == "2026-09-12T10:00:01+00:00"
    assert obj["execution_plan_sha256"] == sha256_json(
        [
            {key: r[key] for key in ("kind", "block", "segments", "prompt_sha256")}
            for r in obj["requests"]
        ]
    )
    assert [s["segment_index"] for s in obj["suggestions"]] == list(range(65))
    assert [s["id"] for s in obj["suggestions"]] == [f"S{i:03d}" for i in range(1, 66)]
    assert [s["anchor"]["quote"] for s in obj["suggestions"]] == [s.text for s in segments]
    assert all("response_text" not in event.payload for event in journal)
    before = _zustand(ws, journal)
    again = l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert not again.written and again.artifact_sha256 == result.artifact_sha256
    assert len(adapter.calls) == 3 and _zustand(ws, journal) == before


def test_multiple_original_blocks_each_get_at_most_one_supplement(tmp_path):
    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(130))
    adapter = _BlockFixture(lambda n, r: _omit(r, {1, 65, 129}) if n % 2 else r)
    result = l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    obj = _object(ws, result)
    assert len(adapter.calls) == 6
    assert [r["block"] for r in obj["requests"]] == [1, 1, 2, 2, 3, 3]
    assert [r["segments"] for r in obj["requests"] if r["kind"] == "supplement"] == [
        [1],
        [65],
        [129],
    ]


@pytest.mark.parametrize(
    "bad",
    [
        _document([]),
        _document([0, 0]),
        _document([0, 9]),
        "not JSON",
        '{"results": [{"segment": 0, "code": ""}]}',
    ],
)
def test_invalid_original_never_opens_supplement(tmp_path, bad):
    ws, journal, _ = _welt(tmp_path)
    adapter = _BlockFixture(lambda n, r: replace(r, text=bad))
    before = _zustand(ws, journal)
    with pytest.raises(l1.SuggestError):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 1 and _zustand(ws, journal) == before


@pytest.mark.parametrize(
    "bad",
    [
        _document([]),
        _document([1]),
        _document([1, 1]),
        _document([1, 0]),
        "not JSON",
        '{"results": [{"segment": 1, "code": ""}, {"segment": 3, "code": "AA"}]}',
    ],
)
def test_invalid_supplement_halts_without_recursion_or_publication(tmp_path, bad):
    ws, journal, _ = _welt(tmp_path)
    adapter = _BlockFixture(lambda n, r: _omit(r, {1, 3}) if n == 1 else replace(r, text=bad))
    before = _zustand(ws, journal)
    with pytest.raises(l1.SuggestError):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == before


@pytest.mark.parametrize("stage", [1, 2])
def test_unclean_request_is_checked_before_parser_and_writes_nothing(tmp_path, monkeypatch, stage):
    ws, journal, _ = _welt(tmp_path)
    parsed = []
    parse = l1.parse_answer

    def tracked(text, *args, **kwargs):
        parsed.append(text)
        return parse(text, *args, **kwargs)

    monkeypatch.setattr(l1, "parse_answer", tracked)
    adapter = _BlockFixture(
        lambda n, r: (
            replace(r, finish_reason="length", text="SECRET-CANARY")
            if n == stage
            else _omit(r, {1})
        )
    )
    before = _zustand(ws, journal)
    with pytest.raises(l1.SuggestError) as error:
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert "SECRET-CANARY" not in str(error.value) and "SECRET-CANARY" not in parsed
    assert len(adapter.calls) == stage and _zustand(ws, journal) == before


def test_supplement_has_its_own_authorisation_check(tmp_path):
    ws, journal, _ = _welt(tmp_path)
    adapter = _BlockFixture(lambda n, r: _omit(r, {1}) if n == 1 else r)
    times = iter(["2026-09-12T10:00:00+00:00", "2026-08-01T10:00:00+00:00"])
    before = _zustand(ws, journal)
    with pytest.raises(l1.SuggestError, match="nicht autorisiert"):
        l1.run_l1_suggest(
            _ctx(ws, journal), _view(ws, journal), adapter=adapter, clock=lambda: next(times)
        )
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == before


def test_codebook_applies_to_supplement_and_is_bound_in_its_receipt(tmp_path):
    ws, journal, _, ctx, _ = _codebook_world(tmp_path)
    adapter = _BlockFixture(
        lambda n, r: _omit(_coded_response(n, r), {1}) if n == 1 else _coded_response(n, r)
    )
    result = l1.run_l1_suggest(ctx, _view(ws, journal), adapter=adapter)
    obj = _object(ws, result)
    assert "l1.codebook" in obj["requests"][1]["receipt"]["inputs"]
    assert obj["suggestions"][1]["code"] == "UNGEKLAERT"
    assert not l1.run_l1_suggest(ctx, _view(ws, journal), adapter=adapter).written
    assert len(adapter.calls) == 2


def test_invalid_supplement_code_halts_without_l1_publication(tmp_path):
    ws, journal, _, ctx, _ = _codebook_world(tmp_path)

    def transform(n, response):
        if n == 1:
            return _omit(_coded_response(n, response), {1})
        return replace(response, text='{"results": [{"segment": 1, "code": "FREMD"}]}')

    adapter = _BlockFixture(transform)
    with pytest.raises(l1.SuggestError, match="unerlaubter Code"):
        l1.run_l1_suggest(ctx, _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2
    assert not any(e.payload.get("artifact") == "l1.suggestions" for e in journal)


def test_failed_supplement_after_complete_first_block_publishes_nothing(tmp_path):
    ws, journal, _ = _welt(tmp_path, segmente=_many_segments(67))
    adapter = _BlockFixture(lambda n, r: r if n == 1 else _omit(r, {66}))
    before = _zustand(ws, journal)
    with pytest.raises(l1.SuggestError, match="Block 2/2"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 3 and _zustand(ws, journal) == before


def test_independent_union_guard_rejects_accidental_overlap(tmp_path, monkeypatch):
    ws, journal, _ = _welt(tmp_path)
    original = l1._parse_original

    def faulty_merge(*args):
        rows, missing = original(*args)
        return rows + rows[:1], missing

    monkeypatch.setattr(l1, "_parse_original", faulty_merge)
    before = _zustand(ws, journal)
    with pytest.raises(l1.SuggestError, match="Endvereinigung"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=_BlockFixture())
    assert _zustand(ws, journal) == before


@pytest.mark.parametrize("failure", [None, "original_pair", "supplement_pair", "second_unload"])
def test_each_original_and_supplement_keeps_the_cold_pair(tmp_path, monkeypatch, failure):
    """Echter Adapter.run, rein lokale Methodendoppel: keine Sockets/Server."""
    ws, journal, _ = _welt(tmp_path)
    fixture = FixtureAdapter()
    adapter = object.__new__(OllamaAdapter)
    adapter.cfg = SimpleNamespace(max_chars=100000, repeat_probe=True, repeat_probe_cold=True)
    adapter._params = replace(
        fixture.params,
        extra={
            **fixture.params.extra,
            "repeat_probe_cold": True,
            "wiederholungsprobe": "synthetic cold pair",
        },
    )
    events = []
    prompts = []

    def unload():
        events.append("unload")
        if failure == "second_unload" and len(prompts) == 3:
            raise l1.SuggestError("Synthetische Entladung nicht bestätigt")

    def generate(prompt):
        events.append("generate")
        prompts.append(prompt)
        response = fixture.run(prompt, fixture.params)
        is_supplement = "supplement" in json.loads(prompt.partition("\n\n")[2])
        if not is_supplement:
            response = _omit(response, {1, 3})
        if (failure == "original_pair" and len(prompts) == 2) or (
            failure == "supplement_pair" and len(prompts) == 4
        ):
            response = replace(response, text="SECRET-CANARY")
        return response.text, response.finish_reason, response.output_tokens

    monkeypatch.setattr(adapter, "_entladen", unload)
    monkeypatch.setattr(adapter, "_einmal", generate)
    monkeypatch.setattr(adapter, "_digest_am_runner", lambda: adapter.params.model_digest)
    before = _zustand(ws, journal)
    if failure:
        with pytest.raises(l1.SuggestError) as error:
            l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
        assert "SECRET-CANARY" not in str(error.value)
        assert _zustand(ws, journal) == before
        assert (
            len(prompts) == {"original_pair": 2, "supplement_pair": 4, "second_unload": 3}[failure]
        )
    else:
        result = l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
        assert result.suggestions == 4
        assert events == ["unload", "generate"] * 4
        assert prompts[0] == prompts[1] and prompts[2] == prompts[3]
        assert prompts[0] != prompts[2]
        assert len(_object(ws, result)["requests"]) == 2


def _replace_current_artifact(ws, journal, obj):
    """Auch nach gültiger Neuadressierung muss die semantische Reuse-Prüfung greifen."""
    receipt = deepcopy([e.payload for e in journal if e.kind == "receipt.recorded"][-1])
    address = ws.store().put(io.BytesIO(json.dumps(obj).encode()))
    receipt["output_sha256"] = address
    journal.append(
        "artifact.produced", {"artifact": "l1.suggestions", "sha256": address}, record_id=RECORD
    )
    journal.append("receipt.recorded", receipt, record_id=RECORD)
    journal.append(
        "anchor.checked", {"artifact": "l1.suggestions", "outcome": "exact"}, record_id=RECORD
    )
    assert "l1.suggestions" in _view(ws, journal).have


@pytest.mark.parametrize(
    "field,value",
    [
        ("kind", "original"),
        ("block", 2),
        ("count", True),
        ("segments", [1, 2, 3]),
        ("first", 0),
        ("prompt_sha256", "a" * 64),
        ("finish_reason", "length"),
        ("output_tokens", True),
        ("started_at", "2026-08-01T00:00:00+00:00"),
        ("response_text", _document([1])),
        ("receipt", {}),
    ],
)
def test_reuse_rejects_changed_supplement_after_rehash(tmp_path, field, value):
    ws, journal, _ = _welt(tmp_path)
    adapter = _BlockFixture(lambda n, r: _omit(r, {1, 3}) if n == 1 else r)
    result = l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    obj = _object(ws, result)
    obj["requests"][1][field] = value
    _replace_current_artifact(ws, journal, obj)
    before = _zustand(ws, journal)
    with pytest.raises(l1.SuggestError, match="Keine Wiederverwendung"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == before


@pytest.mark.parametrize(
    "field,value",
    [
        ("inputs", {}),
        ("params", {}),
        ("authorisation", "FAKE@" + "0" * 12),
        ("authorisation_subject_sha256", "a" * 64),
        ("authorised_at", "2026-01-01"),
        ("code_version", "l1-suggest/6"),
        ("output_sha256", "a" * 64),
        ("prompt_sha256", "a" * 64),
        ("started_at", "2026-01-01"),
    ],
)
def test_reuse_rejects_changed_nested_receipt_after_rehash(tmp_path, field, value):
    ws, journal, _ = _welt(tmp_path)
    adapter = _BlockFixture(lambda n, r: _omit(r, {1}) if n == 1 else r)
    result = l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    obj = _object(ws, result)
    obj["requests"][1]["receipt"][field] = value
    _replace_current_artifact(ws, journal, obj)
    with pytest.raises(l1.SuggestError, match="Keine Wiederverwendung"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2


@pytest.mark.parametrize(
    "mutation",
    [
        "delete",
        "duplicate",
        "missing_receipt",
        "extra_rows",
        "changed_suggestion",
        "wrong_schema",
        "wrong_trace",
    ],
)
def test_reuse_rejects_removed_or_extra_evidence_and_changed_union(tmp_path, mutation):
    ws, journal, _ = _welt(tmp_path)
    adapter = _BlockFixture(lambda n, r: _omit(r, {1}) if n == 1 else r)
    result = l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    obj = _object(ws, result)
    if mutation == "delete":
        obj["requests"].pop()
    elif mutation == "duplicate":
        obj["requests"].append(deepcopy(obj["requests"][-1]))
    elif mutation == "missing_receipt":
        del obj["requests"][-1]["receipt"]
    elif mutation == "extra_rows":
        obj["suggestions"].append(deepcopy(obj["suggestions"][0]))
    elif mutation == "changed_suggestion":
        obj["suggestions"][0]["code"] = "changed"
    elif mutation == "wrong_schema":
        obj["schema"] = "ohpipe.l1.suggestions.v2"
    else:
        obj["execution_plan_sha256"] = "a" * 64
    _replace_current_artifact(ws, journal, obj)
    before = _zustand(ws, journal)
    with pytest.raises(l1.SuggestError, match="Keine Wiederverwendung"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == before
