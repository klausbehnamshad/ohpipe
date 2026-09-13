"""Kalte Vergleichsbedingungen beweisen, Antwortauswahl und Inhaltslecks verhindern."""

import pytest

from ohpipe.adapters.models import ollama
from tests.test_ollama_adapter import DIGEST, MODELL, _Fake, _cfg, _skript

UNLOAD = {"done": True, "done_reason": "unload"}
EMPTY = {"models": []}
LOADED = {"models": [{"name": MODELL, "digest": DIGEST, "context_length": 8192}]}
ANSWER = {"done": True, "done_reason": "stop", "eval_count": 10, "response": "synthetic answer"}


@pytest.mark.parametrize("value", ['"true"', "1", "0", "1.0"])
def test_cold_type_fails_before_connection(tmp_path, value):
    with pytest.raises(ollama.OllamaConfigError):
        _cfg(tmp_path, "http://127.0.0.1:1", repeat_probe_cold=value)


def test_cold_requires_repeat_probe(tmp_path):
    with pytest.raises(ollama.OllamaConfigError, match="repeat_probe"):
        _cfg(tmp_path, "http://127.0.0.1:1", repeat_probe_cold="true", repeat_probe="false")


def test_cold_request_order_and_receipt_binding(tmp_path):
    s = _Fake(
        _skript(
            generate=[UNLOAD, ANSWER, UNLOAD, ANSWER], ps=[LOADED, EMPTY, LOADED, EMPTY, LOADED]
        )
    )
    try:
        a = ollama.OllamaAdapter(_cfg(tmp_path, s.host, repeat_probe_cold="true"))
        old = ollama.OllamaAdapter(_cfg(tmp_path, s.host))
        assert a.params.fingerprint != old.params.fingerprint, "COLD_RECEIPT"
        assert a.params.extra["repeat_probe_cold"] is True
        assert a.params.extra["wiederholungsprobe"] == ollama.KALTE_WIEDERHOLUNGSPROBE
        assert "repeat_probe_cold" not in old.params.extra
        start = len(s.anfragen)
        result = a.run("synthetic prompt", a.params)
        assert result.text == ANSWER["response"]
        requests = s.anfragen[start:]
        assert [p for p, _ in requests] == [
            "/api/generate",
            "/api/ps",
            "/api/ps",
            "/api/generate",
            "/api/ps",
            "/api/generate",
            "/api/ps",
            "/api/generate",
            "/api/ps",
        ]
        bodies = s.bodies("/api/generate")
        assert bodies[0] == bodies[2] == {"model": MODELL, "keep_alive": 0}
        assert bodies[1] == bodies[3] and bodies[1]["prompt"] == "synthetic prompt"
        assert "keep_alive" not in bodies[1]
        assert set(bodies[1]["options"]) == {"temperature", "seed", "num_ctx", "num_predict"}
    finally:
        s.stop()


@pytest.mark.parametrize("finish", [False, True])
def test_cold_rejects_divergence_without_retry(tmp_path, finish):
    second = {**ANSWER, "done_reason": "length"} if finish else {**ANSWER, "response": "different"}
    s = _Fake(_skript(generate=[UNLOAD, ANSWER, UNLOAD, second], ps=[EMPTY, LOADED, EMPTY, LOADED]))
    try:
        a = ollama.OllamaAdapter(_cfg(tmp_path, s.host, repeat_probe_cold="true"))
        with pytest.raises(ollama.OllamaAdapterError, match="nicht wiederholbar"):
            a.run("synthetic prompt", a.params)
        assert len(s.bodies("/api/generate")) == 4
    finally:
        s.stop()


@pytest.mark.parametrize(
    "response",
    [{"done": False, "done_reason": "unload"}, {"done": True, "done_reason": "SECRET-CANARY"}],
)
def test_unconfirmed_unload_does_not_send_prompt_or_leak(tmp_path, response):
    s = _Fake(_skript(generate=response))
    try:
        a = ollama.OllamaAdapter(_cfg(tmp_path, s.host, repeat_probe_cold="true"))
        with pytest.raises(ollama.OllamaAdapterError) as error:
            a.run("SECRET-PROMPT", a.params)
        assert "SECRET" not in str(error.value)
        assert s.bodies("/api/generate") == [{"model": MODELL, "keep_alive": 0}]
    finally:
        s.stop()


@pytest.mark.parametrize("models", [None, ["SECRET-CANARY"], [{"digest": "SECRET-CANARY"}]])
def test_invalid_loaded_state_does_not_send_prompt_or_leak(tmp_path, models):
    s = _Fake(_skript(generate=UNLOAD, ps={"models": models}))
    try:
        a = ollama.OllamaAdapter(_cfg(tmp_path, s.host, repeat_probe_cold="true"))
        with pytest.raises(ollama.OllamaAdapterError) as error:
            a.run("SECRET-PROMPT", a.params)
        assert "SECRET" not in str(error.value)
        assert s.bodies("/api/generate") == [{"model": MODELL, "keep_alive": 0}]
    finally:
        s.stop()


def test_unload_deadline_blocks_generation(tmp_path, monkeypatch):
    s = _Fake(_skript(generate=UNLOAD, ps=LOADED))
    try:
        a = ollama.OllamaAdapter(_cfg(tmp_path, s.host, repeat_probe_cold="true"))
        # The module-local clock avoids altering the HTTP server's real timers.
        from types import SimpleNamespace

        ticks = iter([0, 11])
        monkeypatch.setattr(
            ollama, "time", SimpleNamespace(monotonic=lambda: next(ticks), sleep=lambda _: None)
        )
        with pytest.raises(ollama.OllamaAdapterError, match="weiterhin geladen"):
            a.run("synthetic prompt", a.params)
        assert s.bodies("/api/generate") == [{"model": MODELL, "keep_alive": 0}]
    finally:
        s.stop()


def test_failed_second_unload_never_returns_first_answer(tmp_path):
    s = _Fake(_skript(generate=[UNLOAD, ANSWER, {"done": False}], ps=[EMPTY, LOADED]))
    try:
        a = ollama.OllamaAdapter(_cfg(tmp_path, s.host, repeat_probe_cold="true"))
        with pytest.raises(ollama.OllamaAdapterError, match="nicht bestätigt"):
            a.run("synthetic prompt", a.params)
        assert len(s.bodies("/api/generate")) == 3
    finally:
        s.stop()


def test_both_generations_have_their_own_cold_precondition(tmp_path, monkeypatch):
    s = _Fake(_skript())
    try:
        a = ollama.OllamaAdapter(_cfg(tmp_path, s.host, repeat_probe_cold="true"))
        calls = []
        monkeypatch.setattr(a, "_entladen", lambda: calls.append("unload"))

        def generate(prompt):
            calls.append("generate")
            return "synthetic answer", "stop", 10

        monkeypatch.setattr(a, "_einmal", generate)
        monkeypatch.setattr(a, "_digest_am_runner", lambda: DIGEST)
        a.run("synthetic prompt", a.params)
        assert calls == ["unload", "generate", "unload", "generate"], "COLD_PRECONDITION"
    finally:
        s.stop()


def test_unload_waits_for_actual_absence(tmp_path):
    s = _Fake(_skript(generate=UNLOAD, ps=[LOADED, EMPTY]))
    try:
        a = ollama.OllamaAdapter(_cfg(tmp_path, s.host, repeat_probe_cold="true"))
        a._entladen()
        assert len(s.bodies("/api/ps")) == 2, "COLD_ABSENCE"
        assert len(s.bodies("/api/generate")) == 1
    finally:
        s.stop()
