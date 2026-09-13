"""Der Ollama-Adapter, gefahren gegen einen Fake-Server — 26 Fälle.

Der Fake-Server ist kein Bequemlichkeitsersatz für ein echtes Ollama. Er ist
der Gegenstand: Was dieser Adapter zusichert, sind Aussagen über das VERHALTEN
an der Grenze — was gesendet wird, was akzeptiert wird, was abgelehnt wird,
und was NICHT gesendet wird. Ein echter Server kann keinen dieser Fälle
zuverlässig herstellen (er antwortet, wie er will), und drei der Fälle
verlangen, dass gar keine Anfrage ankommt. Das lässt sich nur an einem Server
messen, der mitzählt.

Der eine Fall gegen echtes Ollama steht in ``test_ollama_live.py`` und läuft
nur dort, wo einer antwortet.

Der Aufbau: ``_Fake`` ist ein ``http.server`` in einem Thread, mit einem
Skript je Endpunkt (Antwort, Status, Verzögerung) und einer Aufzeichnung
aller Anfragen samt Bodys. Die Portnummer kommt vom Betriebssystem, und
``model.toml`` wird je Test mit genau diesem Port geschrieben: Ein fester
Port wäre eine Verabredung mit allem anderen, was auf diesem Rechner läuft.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ohpipe.adapters.models.fixture import FIXTURE_MODEL, FixtureAdapter
from ohpipe.adapters.models.ollama import (
    ADAPTER_VERSION,
    BELEGT,
    NICHT_BELEGT,
    WIEDERHOLUNGSPROBE,
    ModelConfig,
    OllamaAdapter,
    OllamaAdapterError,
    OllamaConfigError,
    load_model_config,
)
from ohpipe.application.l1_suggest import SuggestError, adapter_for
from ohpipe.domain.hashing import sha256_json
from ohpipe.domain.revision_serialization import PROJECTION_VERSION, canonical_revision_bytes
from ohpipe.domain.transcript import Segment, TranscriptRevision
from ohpipe.project import ModelNotAllowed, Profile, Workspace

from ._forge import cli_keyed, forge_keyed, journal_path, place_object, report_lines

PROFIL = Path(__file__).resolve().parents[1] / "src" / "ohpipe" / "profiles" / "sandbox"
RECORD = "SANDBOX-001"
MODELL = "mistral:7b-instruct"
DIGEST = "a" * 64
ANDERER_DIGEST = "b" * 64
ENTSCHIEDEN_AM = "2026-09-01T11:00:00+00:00"

SEGMENTE = (
    Segment(0, 500, 5200, "Wie sah der Schulweg damals aus?", "INTERVIEWER", "deu"),
    Segment(
        1,
        5600,
        13400,
        "Wir sind jeden Morgen zu Fuss gegangen, auch im Winter.",
        "ZEITZEUGIN",
        "deu",
    ),
    Segment(2, 14000, 21800, "Ja.", "ZEITZEUGIN", "deu"),
    Segment(
        3, 22000, 30000, "Das waren gut vierzig Minuten in eine Richtung.", "ZEITZEUGIN", "deu"
    ),
)


# ------------------------------------------------------------------ Fake-Server


class _Fake:
    """Ein Ollama, das genau das sagt, was der Fall verlangt — und mitzählt.

    ``antworten`` ist das Skript: je Pfad entweder ein JSON-Objekt, eine Liste
    von Objekten (eines je Aufruf, für die Wiederholungsprobe), ein
    ``(status, körper)``-Paar für einen Fehler, oder ``None`` für „dieser
    Endpunkt existiert hier nicht".

    ``anfragen`` ist der Nachweis. Drei Fälle dieser Datei prüfen, dass die
    Liste LEER ist: Ein Adapter, der vor einer Ablehnung schon gesendet hat,
    hat die Ablehnung zu spät ausgesprochen.
    """

    def __init__(self, antworten: dict[str, object]) -> None:
        self.antworten = antworten
        self.anfragen: list[tuple[str, dict | None]] = []
        self._zaehler: dict[str, int] = {}
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):  # kein Rauschen in der Testausgabe
                pass

            def _antworte(self, pfad: str, body: dict | None) -> None:
                fake.anfragen.append((pfad, body))
                n = fake._zaehler.get(pfad, 0)
                fake._zaehler[pfad] = n + 1
                skript = fake.antworten.get(pfad)
                if skript is None:
                    self.send_error(404)
                    return
                if isinstance(skript, list):
                    skript = skript[min(n, len(skript) - 1)]
                if isinstance(skript, tuple):
                    status, nutz = skript
                else:
                    status, nutz = 200, skript
                roh = nutz if isinstance(nutz, bytes) else json.dumps(nutz).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(roh)))
                self.end_headers()
                self.wfile.write(roh)

            def do_GET(self):  # noqa: N802 — Signatur von BaseHTTPRequestHandler
                self._antworte(self.path, None)

            def do_POST(self):  # noqa: N802
                laenge = int(self.headers.get("Content-Length", 0))
                roh = self.rfile.read(laenge) if laenge else b"{}"
                try:
                    body = json.loads(roh)
                except ValueError:
                    body = None
                self._antworte(self.path, body)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self.host = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def bodies(self, pfad: str) -> list[dict | None]:
        return [b for p, b in self.anfragen if p == pfad]

    def pfade(self) -> list[str]:
        return [p for p, _ in self.anfragen]

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


def _skript(
    *,
    version: str = "0.32.1",
    tags_digest: str = DIGEST,
    tags_name: str = MODELL,
    show_parameters: str | None = 'num_ctx 4096\\nstop "<|im_end|>"',
    generate: object | None = None,
    ps: object | None = None,
    num_ctx: int = 8192,
) -> dict[str, object]:
    """Das Normalskript. Jeder Fall verbiegt genau eine Stelle daran."""
    show: dict[str, object] = {
        "details": {"quantization_level": "Q4_K_M", "parameter_size": "7.2B"}
    }
    if show_parameters is not None:
        show["parameters"] = show_parameters
    return {
        "/api/version": {"version": version},
        "/api/tags": {"models": [{"name": tags_name, "digest": tags_digest}]},
        "/api/show": show,
        "/api/generate": generate
        if generate is not None
        else {"done": True, "done_reason": "stop", "eval_count": 12, "response": _antwort_text()},
        "/api/ps": ps
        if ps is not None
        else {"models": [{"name": tags_name, "digest": tags_digest, "context_length": num_ctx}]},
    }


def _antwort_text() -> str:
    """Eine Antwort, die ``parse_answer`` und der Anker akzeptieren.

    Genau zwei Felder je Eintrag der results-Liste: Seit 06.09.2026 nennt das Modell die
    Belegstelle nicht mehr, sie kommt aus der Segmentspanne.
    """
    zeilen = [
        {"segment": 0, "code": "L1.01"},
        {"segment": 1, "code": "L1.02"},
        {"segment": 2, "code": "L1.03"},
        {"segment": 3, "code": "L1.04"},
    ]
    return json.dumps({"results": zeilen}, ensure_ascii=False, sort_keys=True)


@pytest.fixture
def fake():
    server: list[_Fake] = []

    def bauen(**kwargs) -> _Fake:
        s = _Fake(_skript(**kwargs))
        server.append(s)
        return s

    yield bauen
    for s in server:
        s.stop()


def _toml(pfad: Path, host: str, **abweichungen) -> Path:
    werte: dict[str, object] = {
        "runtime": '"ollama"',
        "host": f'"{host}"',
        "model": f'"{MODELL}"',
        "model_digest": f'"{DIGEST}"',
        "temperature": "0.0",
        "seed": "7",
        "num_ctx": "8192",
        "num_predict": "2048",
        "max_chars": "12000",
        "timeout_s": "600",
        "repeat_probe": "true",
        "block_size": "64",
    }
    werte.update(abweichungen)
    zeilen = ["[model]"] + [f"{k} = {v}" for k, v in werte.items() if v is not None]
    pfad.parent.mkdir(parents=True, exist_ok=True)
    pfad.write_text("\n".join(zeilen) + "\n", encoding="utf-8")
    return pfad


def _cfg(tmp_path: Path, host: str, **abweichungen) -> ModelConfig:
    return load_model_config(_toml(tmp_path / "model.toml", host, **abweichungen))


def test_missing_block_size_is_rejected_before_connection(tmp_path, fake):
    server = fake()
    with pytest.raises(OllamaConfigError, match="block_size"):
        OllamaAdapter(_cfg(tmp_path, server.host, block_size=None))
    assert server.anfragen == []


def test_zero_block_size_is_rejected_before_connection(tmp_path, fake):
    server = fake()
    with pytest.raises(OllamaConfigError, match="block_size"):
        OllamaAdapter(_cfg(tmp_path, server.host, block_size="0"))
    assert server.anfragen == []


def _revision() -> TranscriptRevision:
    return TranscriptRevision.from_segments(
        SEGMENTE, projection_version=PROJECTION_VERSION, source_kind="srt"
    )


def _ws(tmp_path: Path, *, production: bool = False) -> Workspace:
    from dataclasses import replace

    profil = Profile.load(PROFIL / "profile.toml")
    if production:
        profil = replace(profil, production=True)
    ws = Workspace(tmp_path / "data", profil)
    ws.ensure()
    ws.bind_graph_initially()
    return ws


# ============================================================ 1 bis 3: die Grenze


def test_01_a_foreign_host_is_refused_before_any_connection(tmp_path):
    """Ein Modellserver anderswo wäre eine Datenabgabe, und die entscheidet
    kein Konfigurationswert. Die Regel sitzt im LADEN: Ein fremder Host darf
    nicht erst dadurch auffallen, dass jemand ihn angesprochen hat."""
    with pytest.raises(OllamaConfigError) as fehler:
        _cfg(tmp_path, "http://10.0.0.5:11434")
    text = str(fehler.value)
    assert "10.0.0.5" in text and "127.0.0.1" in text, text
    assert "Kein Lauf, nichts geschrieben." in text


def test_02_the_ollama_host_environment_variable_is_ignored(tmp_path, monkeypatch, fake):
    """``OLLAMA_HOST`` verschiebt die Hostregel nicht.

    Eine Umgebungsvariable, die still entscheidet, wohin ein Interview geht,
    ist genau die Sorte Schalter, gegen die ADR 0017 geschrieben ist. Gemessen
    wird das Gegenteil einer Behauptung: Der Server unter 127.0.0.1 bekommt
    die Anfragen, obwohl die Variable woanders hin zeigt.
    """
    server = fake()
    monkeypatch.setenv("OLLAMA_HOST", "http://10.0.0.5:9999")
    adapter = OllamaAdapter(_cfg(tmp_path, server.host))
    assert adapter.params.model_digest == DIGEST
    assert server.pfade()[:3] == ["/api/version", "/api/tags", "/api/show"]


def test_03_an_http_proxy_in_the_environment_is_not_used(tmp_path, monkeypatch, fake):
    """Die Anfrage kommt am Fake-Server an, nicht am Proxy.

    Ohne ``ProxyHandler({})`` nimmt urllib ``HTTP_PROXY`` aus der Umgebung —
    und ein Lauf gegen ``127.0.0.1`` ginge über einen fremden Rechner. Das ist
    dieselbe Abgabe, die die Hostregel verhindern soll, nur eine Ebene tiefer,
    und sie wäre in keiner Konfigurationsdatei sichtbar.
    """
    server = fake()
    for name in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://10.0.0.5:3128")
    adapter = OllamaAdapter(_cfg(tmp_path, server.host))
    assert adapter.params.extra["ollama_version"] == "0.32.1"
    assert server.pfade(), "keine Anfrage am Fake-Server angekommen"


# ============================================================ 4 bis 11: die Auswahl


def test_04_a_production_profile_without_model_toml_gets_no_adapter_and_no_request(tmp_path, fake):
    """Kein Adapter, und der Server hört nichts davon.

    Die Meldung nennt den erwarteten Pfad: „es gibt keinen" macht ohne ihn
    nicht handlungsfähig. Der Fake-Server läuft und zählt NULL Anfragen — die
    Ablehnung steht vor jeder Verbindung, nicht danach.
    """
    server = fake()
    ws = _ws(tmp_path, production=True)
    with pytest.raises(SuggestError) as fehler:
        adapter_for(ws, {})
    text = str(fehler.value)
    assert "keinen Modelladapter" in text and "model.toml" in text, text
    assert server.anfragen == [], server.anfragen


def test_05_a_sandbox_without_model_toml_still_gets_the_fixture_adapter(tmp_path):
    """Ohne ``model.toml`` bleibt alles, wie es war — und der Aufgezeichnete
    wird trotzdem gegen die Freigabeliste gehalten. Auch eine Aufzeichnung
    steht mit ihrem Modellnamen im Beleg."""
    ws = _ws(tmp_path)
    adapter = adapter_for(ws, {})
    assert isinstance(adapter, FixtureAdapter)
    assert adapter.params.model == FIXTURE_MODEL
    assert FIXTURE_MODEL in ws.profile.model_vocabulary


def test_06_an_unknown_key_in_model_toml_is_an_error(tmp_path):
    """Ein unbekannter Schlüssel ist keine Erweiterung, sondern ein Tippfehler,
    der still nichts tut. Der Fall prüft, dass der Name des Schlüssels in der
    Meldung steht: Sonst sucht der Operator ihn in elf Zeilen."""
    with pytest.raises(OllamaConfigError) as fehler:
        _cfg(tmp_path, "http://127.0.0.1:11434", num_predikt="2048")
    assert "num_predikt" in str(fehler.value), str(fehler.value)


def test_07_a_missing_key_in_model_toml_is_an_error(tmp_path):
    """Für keinen dieser Werte gibt es einen sicheren Vorgabewert. Ein
    fehlendes ``seed`` mit stiller Null wäre ein Beleg über einen Lauf, den
    niemand wiederholen kann."""
    with pytest.raises(OllamaConfigError) as fehler:
        _cfg(tmp_path, "http://127.0.0.1:11434", seed=None)
    assert "seed" in str(fehler.value) and "fehlt" in str(fehler.value)


def test_08_a_wrong_type_in_model_toml_is_an_error(tmp_path):
    """``bool`` ist nicht ``"true"``, ``int`` ist nicht ``1.5``.

    Beide Proben in EINEM Fall, weil sie dieselbe Zusage messen: Der Typ kommt
    aus TOML und nicht aus Pythons Kulanz. Python würde ``"true"`` als wahren
    Wert durchwinken und ``1.5`` als Zahl — die Zusage der Wiederholungsprobe
    hinge dann an einer Zeichenkette, und im Beleg stünde ein ``seed``, den
    niemand wiederholen kann.
    """
    with pytest.raises(OllamaConfigError) as bool_fehler:
        _cfg(tmp_path, "http://127.0.0.1:11434", repeat_probe='"true"')
    assert "repeat_probe" in str(bool_fehler.value), str(bool_fehler.value)

    with pytest.raises(OllamaConfigError) as int_fehler:
        _cfg(tmp_path / "zwei", "http://127.0.0.1:11434", seed="1.5")
    assert "seed" in str(int_fehler.value), str(int_fehler.value)


def test_09_a_model_without_a_tag_is_an_error(tmp_path):
    """``mistral`` ohne Tag steht für das, was eine Registry gerade ``latest``
    nennt: derselbe Wortlaut, morgen ein anderes Gewicht, und der Beleg trüge
    denselben Namen."""
    with pytest.raises(OllamaConfigError) as fehler:
        _cfg(tmp_path, "http://127.0.0.1:11434", model='"mistral"')
    assert "exakter Tag" in str(fehler.value), str(fehler.value)


def test_10_a_model_outside_the_profile_list_is_refused_before_any_request(tmp_path, fake):
    """``ModelNotAllowed``, und der Fake-Server zählt NULL Anfragen.

    Das ist der Kern der Reihenfolge in ``adapter_for``: Ein Modell außerhalb
    der Freigabeliste darf nicht dadurch auffallen, dass es schon geladen
    wurde. Geprüft wird deshalb nicht nur die Ausnahme, sondern die Stille.
    """
    server = fake()
    ws = _ws(tmp_path)
    _toml(ws.governance / "model.toml", server.host, model='"llama3:8b"')
    with pytest.raises(ModelNotAllowed) as fehler:
        adapter_for(ws, {})
    text = str(fehler.value)
    assert "llama3:8b" in text and "sandbox" in text, text
    assert server.anfragen == [], server.anfragen


def test_11_a_fixture_scenario_against_the_ollama_adapter_is_an_error(tmp_path, fake):
    """``--fixture length`` gibt es nur für den Aufgezeichneten.

    Führte das Profil einen Modellserver und akzeptierte trotzdem ein
    Szenario, entstünde ein Beleg über einen Lauf, den kein Modell gefahren
    hat — unter dem Namen des Modells.
    """
    server = fake()
    ws = _ws(tmp_path)
    _toml(ws.governance / "model.toml", server.host)
    with pytest.raises(SuggestError) as fehler:
        adapter_for(ws, {"fixture": "length"})
    assert "aufgezeichneten Adapter" in str(fehler.value)
    assert server.anfragen == [], server.anfragen


# ============================================================ 12 bis 16: der Aufbau


def test_12_an_unreachable_version_endpoint_stops_before_params_exist(tmp_path, fake):
    """Antwortet ``/api/version`` nicht, gibt es keinen Parametersatz.

    Der Adapter misst, was im Beleg steht, BEVOR ein Prompt existiert. Fällt
    diese Messung aus, ist der richtige Zustand „kein Adapter" und nicht „ein
    Adapter ohne Versionsangabe".
    """
    server = _Fake({"/api/version": None})
    try:
        with pytest.raises(OllamaAdapterError) as fehler:
            OllamaAdapter(_cfg(tmp_path, server.host))
        assert "/api/version" in str(fehler.value)
        assert server.pfade() == ["/api/version"], server.pfade()
    finally:
        server.stop()


def test_13_a_tag_missing_from_api_tags_stops_before_generate(tmp_path, fake):
    """„nicht installiert; der Adapter zieht nicht."

    ``ollama pull`` steht ausdrücklich nicht in dieser Scheibe: Ein Werkzeug,
    das im Lauf ein Gewicht nachlädt, entscheidet über den Korpus, während
    der Korpus läuft.
    """
    server = fake(tags_name="gemma3:4b")
    with pytest.raises(OllamaAdapterError) as fehler:
        OllamaAdapter(_cfg(tmp_path, server.host))
    assert "nicht installiert" in str(fehler.value)
    assert "/api/generate" not in server.pfade(), server.pfade()


def test_14_a_digest_that_differs_from_the_pin_stops_the_run(tmp_path, fake):
    """Derselbe Tag, ein anderes Gewicht — der Fall, für den der Pin da ist.

    Ein Tag ist ein Zeiger. Zeigt er heute woanders hin, ist jede
    interviewübergreifende Aussage über den alten Korpus nicht mehr gedeckt
    (ADR 0012, ADR 0018), und der Beleg trüge trotzdem denselben Namen.
    """
    server = fake(tags_digest=ANDERER_DIGEST)
    with pytest.raises(OllamaAdapterError) as fehler:
        OllamaAdapter(_cfg(tmp_path, server.host))
    text = str(fehler.value)
    assert ANDERER_DIGEST in text and DIGEST in text, text
    assert "/api/generate" not in server.pfade()


def test_15_api_show_without_parameters_stops_the_run(tmp_path, fake):
    """Fehlt ``parameters``, weiß der Beleg nicht, wogegen die gesendeten
    Optionen liefen. Leer ist erlaubt — ein Modell ohne Modelfile-Vorgaben —,
    fehlend nicht."""
    server = fake(show_parameters=None)
    with pytest.raises(OllamaAdapterError) as fehler:
        OllamaAdapter(_cfg(tmp_path, server.host))
    assert "parameters" in str(fehler.value)
    assert "/api/generate" not in server.pfade()


def test_16_a_prompt_longer_than_max_chars_stops_before_generate(tmp_path, fake):
    """Abbruch VOR dem Senden, und der Fake-Server zählt kein ``generate``.

    Ollama 0.32 gibt keinen Tokenizer-Zugang, also lässt sich nicht messen, ob
    der Eingang vollständig ankam. ``max_chars`` ist die Korpusentscheidung,
    die diese Unkenntnis ersetzt — nicht eine Notbremse, die man höher dreht.
    """
    server = fake()
    adapter = OllamaAdapter(_cfg(tmp_path, server.host, max_chars="50"))
    vorher = list(server.pfade())
    with pytest.raises(OllamaAdapterError) as fehler:
        adapter.run("x" * 51, adapter.params)
    assert "max_chars" in str(fehler.value)
    assert server.pfade() == vorher, "es wurde trotzdem gesendet"


# ============================================================ 17 bis 25: der Lauf


def test_17_the_generate_body_is_exactly_the_agreed_one(tmp_path, fake):
    """Der Bodynachweis: sechs Schlüssel, vier Optionen, kein ``keep_alive``.

    Der Body IST der Parametersatz. Steht dort ein Schlüssel mehr, lief der
    Lauf unter anderen Bedingungen als der Beleg nennt; fehlt einer, ebenso.
    ``keep_alive`` ist eigens genannt, weil es der bequemste Zusatz wäre und
    das Ladeverhalten ändert, das Schritt 7 prüft.
    """
    server = fake()
    adapter = OllamaAdapter(_cfg(tmp_path, server.host))
    adapter.run("Prompt\n\n{}", adapter.params)

    bodys = server.bodies("/api/generate")
    assert len(bodys) == 2, bodys  # repeat_probe: zwei identische Läufe
    for body in bodys:
        assert set(body) == {"model", "prompt", "stream", "think", "format", "options"}, sorted(
            body
        )
        assert body["stream"] is False and body["think"] is False
        assert body["model"] == MODELL
        assert body["format"] == {
            "type": "object",
            "properties": {
                "results": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"segment": {"type": "integer"}, "code": {"type": "string"}},
                        "required": ["segment", "code"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["results"],
            "additionalProperties": False,
        }
        assert adapter.params.extra["format_sha256"] == sha256_json(body["format"])
        optionen = body["options"]
        assert set(optionen) == {"temperature", "seed", "num_ctx", "num_predict"}, sorted(optionen)
        for ganz in ("seed", "num_ctx", "num_predict"):
            assert isinstance(optionen[ganz], int) and not isinstance(optionen[ganz], bool)
        assert optionen["num_ctx"] == 8192 and optionen["num_predict"] == 2048
    assert bodys[0] == bodys[1], "die Wiederholung sendet einen anderen Body"


def test_18_a_length_finish_is_refused_by_validate_over_the_cli(welt_mit_server):
    """Demo-Moment 3 mit echtem Server statt Aufzeichnung: STOP, nichts geschrieben.

    Der Vorgänger hat fünf Interviews lang abgeschnittene Antworten als
    Ergebnisse geführt. Der Adapter reicht ``done_reason`` wörtlich weiter;
    die Allowlist in ``receipt.py`` entscheidet — und sie kennt ``length``
    nicht.
    """
    wurzel, run, _server = welt_mit_server(
        generate={"done": True, "done_reason": "length", "eval_count": 2048, "response": "halb"}
    )
    davor = journal_path(wurzel).read_bytes()
    ergebnis = run("continue", RECORD, "--confirm")
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 1, ergebnis.stdout
    assert "finish_reason='length'" in zeilen["STATUS"], zeilen
    assert zeilen["CHANGED"] == "keine", zeilen
    assert journal_path(wurzel).read_bytes() == davor


def test_19_a_missing_done_reason_becomes_unknown_and_is_refused(tmp_path, fake, welt_mit_server):
    """Fehlt ``done_reason``, heißt der Grund ``unknown`` — und ``unknown``
    steht nicht in der Allowlist.

    Der Adapter erfindet kein ``stop``. Ein unbenannter Abschluss ist kein
    sauberer Abschluss, und die Entscheidung darüber gehört nach
    ``receipt.py``, nicht hierher. Deshalb zwei Hälften: der Adapter benennt
    ``unknown``, und der Weg über die CLI zeigt, dass das den Lauf fallen
    lässt, statt ihn stillschweigend als sauber zu führen.
    """
    ohne_grund = {"done": True, "eval_count": 12, "response": "x"}
    server = fake(generate=ohne_grund)
    adapter = OllamaAdapter(_cfg(tmp_path, server.host))
    antwort = adapter.run("Prompt", adapter.params)
    assert antwort.finish_reason == "unknown"

    wurzel, run, _ = welt_mit_server(generate=ohne_grund)
    davor = journal_path(wurzel).read_bytes()
    ergebnis = run("continue", RECORD, "--confirm")
    zeilen = report_lines(ergebnis.stdout)
    assert ergebnis.returncode == 1, ergebnis.stdout
    assert "finish_reason='unknown'" in zeilen["STATUS"], zeilen
    assert zeilen["CHANGED"] == "keine", zeilen
    assert journal_path(wurzel).read_bytes() == davor


def test_20_a_non_empty_thinking_field_stops_the_run(tmp_path, fake):
    """``think: false`` war gesendet; ein gefülltes Feld heißt, die Laufzeit
    hält den Parametersatz nicht ein.

    Gemessen an ``qwen3:4b``: ohne ``think:false`` steht der Denktext im Feld
    ``thinking``, ``response`` bleibt leer und das Budget ging ins Denken.
    Denktext im Antwortkörper ist etwas anderes — das ist Modellverhalten und
    fällt später in ``parse_answer``.
    """
    server = fake(
        generate={
            "done": True,
            "done_reason": "stop",
            "eval_count": 12,
            "response": "x",
            "thinking": "Zuerst überlege ich",
        }
    )
    adapter = OllamaAdapter(_cfg(tmp_path, server.host))
    with pytest.raises(OllamaAdapterError) as fehler:
        adapter.run("Prompt", adapter.params)
    assert "Denktext" in str(fehler.value)
    assert "Zuerst überlege ich" not in str(fehler.value), "die Meldung trägt Antworttext"


def test_21_an_eval_count_above_num_predict_stops_the_run(tmp_path, fake):
    """Mehr Tokens als erlaubt heißt: Die Laufzeit hat die Grenze ignoriert.

    ``num_predict`` ist der einzige gesendete Wert, dessen Einhaltung sich an
    der Antwort nachprüfen lässt — deshalb steht im Beleg
    ``options_verified: "num_predict"`` und nicht „options".
    """
    server = fake(
        generate={"done": True, "done_reason": "stop", "eval_count": 2049, "response": "x"}
    )
    adapter = OllamaAdapter(_cfg(tmp_path, server.host))
    with pytest.raises(OllamaAdapterError) as fehler:
        adapter.run("Prompt", adapter.params)
    assert "2049" in str(fehler.value) and "2048" in str(fehler.value)


def test_22_an_http_500_from_generate_stops_the_run(tmp_path, fake):
    """Kein Teilergebnis, keine Wiederholung, kein Weiterlaufen.

    ``stream: false``: Es gibt keinen Fortschritt, den man retten könnte. Ein
    Adapter, der hier still ein zweites Mal fragte, verdeckte genau den
    Zustand, den der Operator sehen muss.
    """
    server = fake(generate=(500, {"error": "boom"}))
    adapter = OllamaAdapter(_cfg(tmp_path, server.host))
    with pytest.raises(OllamaAdapterError) as fehler:
        adapter.run("Prompt", adapter.params)
    text = str(fehler.value)
    assert "/api/generate" in text and "Kein Lauf, nichts geschrieben." in text
    assert "boom" not in text, "die Meldung trägt den Antwortkörper"


def test_23_the_loaded_runner_is_found_by_digest_and_not_by_name(tmp_path, fake):
    """B-1: Der Name am Runner ist unerheblich, der Digest ist es nicht.

    Zwei Hälften in einem Fall, weil sie nur zusammen etwas sagen. Ohne
    Eintrag fällt der Lauf; mit demselben Digest unter einem ANDEREN Namen
    läuft er — denn das ist dasselbe Gewicht. Ein Namensvergleich hätte hier
    grundlos abgebrochen und anderswo grundlos durchgewinkt.
    """
    ohne = fake(ps={"models": []})
    adapter = OllamaAdapter(_cfg(tmp_path, ohne.host))
    with pytest.raises(OllamaAdapterError) as fehler:
        adapter.run("Prompt", adapter.params)
    assert DIGEST in str(fehler.value) and "Runner" in str(fehler.value)

    unter_anderem_namen = fake(
        ps={
            "models": [{"name": "mistral:7b-instruct-q4", "digest": DIGEST, "context_length": 8192}]
        }
    )
    zweiter = OllamaAdapter(_cfg(tmp_path / "zwei", unter_anderem_namen.host))
    antwort = zweiter.run("Prompt", zweiter.params)
    assert antwort.model_digest == DIGEST


def test_24_a_context_length_other_than_num_ctx_stops_the_run(tmp_path, fake):
    """Der Runner lief mit anderem Kontext als der Parametersatz nennt.

    ``num_ctx`` wird gesendet, aber die Laufzeit entscheidet, was sie lädt.
    Ohne diese Prüfung stünde im Beleg eine Zahl, die der Lauf nicht hatte.
    """
    server = fake(ps={"models": [{"name": MODELL, "digest": DIGEST, "context_length": 4096}]})
    adapter = OllamaAdapter(_cfg(tmp_path, server.host))
    with pytest.raises(OllamaAdapterError) as fehler:
        adapter.run("Prompt", adapter.params)
    assert "4096" in str(fehler.value) and "8192" in str(fehler.value)


def test_25_the_repeat_probe_is_a_promise_the_run_has_to_keep(tmp_path, fake):
    """Zwei Läufe, gleicher Body: verschiedene Bytes brechen ab, gleiche nicht.

    Das ist die EINZIGE Aussage dieses Adapters über Determiniertheit, und sie
    gilt für diesen Lauf in diesem Prozess. Sie steht als Zusage im Beleg
    (``extra.wiederholungsprobe``) — nicht als Nachweis für andere Läufe.
    """
    wechselnd = fake(
        generate=[
            {"done": True, "done_reason": "stop", "eval_count": 12, "response": "erste"},
            {"done": True, "done_reason": "stop", "eval_count": 12, "response": "zweite"},
        ]
    )
    adapter = OllamaAdapter(_cfg(tmp_path, wechselnd.host))
    with pytest.raises(OllamaAdapterError) as fehler:
        adapter.run("Prompt", adapter.params)
    assert "nicht wiederholbar" in str(fehler.value)
    assert "erste" not in str(fehler.value) and "zweite" not in str(fehler.value)

    stabil = fake()
    zweiter = OllamaAdapter(_cfg(tmp_path / "zwei", stabil.host))
    antwort = zweiter.run("Prompt", zweiter.params)
    assert antwort.finish_reason == "stop"
    assert zweiter.params.extra["wiederholungsprobe"] == WIEDERHOLUNGSPROBE

    # Ohne repeat_probe steht die Zusage NICHT im Beleg — ein Versprechen, das
    # niemand geprueft hat, gehoert nicht hinein.
    ohne = fake()
    dritter = OllamaAdapter(_cfg(tmp_path / "drei", ohne.host, repeat_probe="false"))
    dritter.run("Prompt", dritter.params)
    assert "wiederholungsprobe" not in dritter.params.extra
    assert len(ohne.bodies("/api/generate")) == 1


# ============================================================ 26: der grüne Lauf


@pytest.fixture
def welt_mit_server(tmp_path: Path):
    """Ein Arbeitsbereich über die CLI, mit ``model.toml`` auf den Fake-Server.

    Der Port kommt vom Betriebssystem und wird in die Datei geschrieben. Ein
    fester Port wäre eine Verabredung mit allem anderen, was auf diesem
    Rechner läuft — und ein Test, der bei einem belegten Port etwas anderes
    misst als er sagt.
    """
    server: list[_Fake] = []
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"

    def bauen(**kwargs):
        s = _Fake(_skript(**kwargs))
        server.append(s)

        def run(*args: str):
            return cli_keyed(*args, root=wurzel, key=key)

        assert run("init").returncode == 0
        rev = _revision()
        assert place_object(wurzel, canonical_revision_bytes(rev)) == rev.sha256
        from .test_l1_suggest import _confirmation, PROFIL
        from ohpipe.project import Workspace, Profile

        marker_bytes, decision = _confirmation(
            Workspace(wurzel, Profile.load(PROFIL / "profile.toml")), rev
        )
        marker = place_object(wurzel, marker_bytes)
        forge_keyed(
            wurzel,
            key,
            [
                {
                    "kind": "artifact.produced",
                    "payload": {"artifact": "transcript.revision", "sha256": rev.sha256},
                },
                {
                    "kind": "artifact.produced",
                    "payload": {"artifact": "transcript.confirmed", "sha256": marker},
                },
                {
                    "kind": "decision.recorded",
                    "payload": decision,
                },
                {
                    "kind": "anchor.checked",
                    "payload": {"artifact": "transcript.confirmed", "outcome": "exact"},
                },
            ],
        )
        _toml(wurzel / "_governance" / "model.toml", s.host)
        return wurzel, run, s

    yield bauen
    for s in server:
        s.stop()


def test_26_a_green_run_over_the_cli_carries_the_chain_and_the_receipt(welt_mit_server):
    """Der ganze Weg: CLI, Fake-Server, Journal, Beleg — und zweimal derselbe Abdruck.

    Was hier gemessen wird, ist nicht „es läuft durch", sondern was im Journal
    steht: ``model_digest`` aus ``/api/tags`` (nicht aus der Konfiguration
    abgeschrieben), ``extra`` genau nach Vertrag § 4, und ein
    ``fingerprint``, der über zwei Läufe gleich bleibt. Ein Parametersatz, der
    sich zwischen zwei identischen Läufen ändert, wäre kein Parametersatz.
    """
    wurzel, run, server = welt_mit_server()
    ergebnis = run("continue", RECORD, "--confirm")
    assert ergebnis.returncode == 3, ergebnis.stdout + ergebnis.stderr
    zeilen = report_lines(ergebnis.stdout)
    assert "Ausgeführt: l1.suggest" in zeilen["STATUS"] and "l1.coverage" in zeilen["STATUS"]

    status = json.loads(run("status", "--json").stdout)["details"]["records"][0]
    assert status["artifacts"]["l1.suggestions"]["status"] == "READY", status["artifacts"]

    # Der Beleg DIESES Schrittes: `l1.coverage` schreibt ebenfalls einen, und
    # der traegt keinen Parametersatz — er ist deterministisch.
    belege = [
        json.loads(z)["payload"]
        for z in journal_path(wurzel).read_text(encoding="utf-8").splitlines()
        if z.strip() and json.loads(z)["kind"] == "receipt.recorded"
    ]
    beleg = [b for b in belege if b.get("step") == "l1.suggest"][-1]
    params = beleg["params"]
    assert params["model"] == MODELL
    assert params["model_digest"] == DIGEST, "der Digest kommt nicht aus /api/tags"
    assert params["num_ctx"] == 8192 and params["num_predict"] == 2048
    extra = params["extra"]
    assert extra["runtime"] == "ollama"
    assert extra["ollama_version"] == "0.32.1"
    assert extra["host"] == server.host
    assert extra["think"] is False
    assert extra["model_details"] == "Q4_K_M/7.2B"
    assert extra["options_verified"] == "num_predict"
    assert extra["belegt"] == BELEGT and extra["nicht_belegt"] == NICHT_BELEGT
    assert extra["wiederholungsprobe"] == WIEDERHOLUNGSPROBE
    assert ADAPTER_VERSION in extra["belegt"]
    # Nichts Fluechtiges: keine Dauern, keine Zeitpunkte, kein prompt_eval_count.
    assert not {"total_duration", "created_at", "prompt_eval_count"} & set(extra), extra

    # Derselbe Abdruck bei einem zweiten Aufbau gegen denselben Server.
    zweiter = OllamaAdapter(load_model_config(wurzel / "_governance" / "model.toml"))
    assert zweiter.params.fingerprint == params["fingerprint"]
