"""Der Modelladapter für einen lokalen Ollama-Server.

Der aufgezeichnete Adapter (``fixture.py``) beweist den Empfangsvertrag ohne
Modellserver. Dieser hier fährt einen echten Lauf — und muss deshalb die
Zusagen belegen, die dort aufgezeichnet waren. Vier Regeln, jede vollstreckt,
jede aus einer Messung an der Laufzeit hergeleitet (Vertrag V1, ADR 0012,
ADR 0017, ADR 0018):

1. **Das Gewicht ist identifiziert, nicht benannt.** Ein Lauf geht bei Ollama
   immer über den Tag; per Digest ist er nicht adressierbar (gemessen:
   ``model: "gemma3:4b@sha256:…"`` gibt 400, ``model: "sha256:…"`` gibt 404).
   Also wird der Digest VOR dem Lauf aus ``/api/tags`` gelesen, gegen den Pin
   aus ``model.toml`` gehalten und NACH dem Lauf am geladenen Runner
   bestätigt (``/api/ps``, per Digest, nicht per Name). Das Fenster zwischen
   Messung und Lauf ist Sekunden groß; es wird hier nicht als geschlossen
   behauptet.
2. **``done_reason`` wird wörtlich weitergereicht.** Die Allowlist steht in
   ``receipt.py`` und entscheidet dort. Dieser Adapter schließt das FELD
   ``thinking`` (``think: false`` wird gesendet und die Antwort darauf
   geprüft); Denktext im Antwortkörper ist Modellverhalten und fällt später
   in ``parse_answer``.
3. **Kein Teilergebnis.** ``stream: false``, ein Body, ein Timeout. Es gibt
   keinen Fortschritt, den man retten könnte, und deshalb auch keinen, den
   man versehentlich als Ergebnis führt.
4. **Der Beleg nennt, was er verspricht und was nicht.** ``extra.belegt`` und
   ``extra.nicht_belegt`` sind Konstanten dieses Moduls und wandern mit
   ``ADAPTER_VERSION``. Die Wiederholungsprobe ist die einzige Aussage über
   Determiniertheit, und sie gilt für DIESEN Lauf: zwei Läufe im selben
   Prozess, bitgleich, sonst Abbruch.

Datenschutz: Keine Meldung dieses Moduls trägt ein Byte des Prompts oder der
Antwort. Was ein Abbruch nennt, sind Pfade, Schlüssel, Digests, Zahlen und
Endpunkte — nie Inhalt (dieselbe Regel wie in ``l1_suggest``).

Der Adapter kennt weder Journal noch Store. Er bekommt einen Prompt und gibt
eine Antwort zurück; alles, was Evidenz ist, entsteht in
``ohpipe.application.l1_suggest``.
"""

from __future__ import annotations

import json
import re
import time
import tomllib
import urllib.error
import urllib.request
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ...application.l1_suggest import ANSWER_SCHEMA, SuggestError
from ...domain.hashing import sha256_json
from ...domain.receipt import ModelParams
from .fixture import ModelResponse

__all__ = [
    "ADAPTER_VERSION",
    "ALLOWED_HOSTS",
    "BELEGT",
    "CONFIG_KEYS",
    "MODEL_CONFIG_NAME",
    "NICHT_BELEGT",
    "ModelConfig",
    "OllamaAdapter",
    "OllamaAdapterError",
    "OllamaConfigError",
    "WIEDERHOLUNGSPROBE",
    "load_model_config",
]

#: Fassung dieses Adapters. Präfix von ``belegt``/``nicht_belegt`` im Beleg:
#: Ändert sich, was der Adapter prüft, ändert sich, was er verspricht.
ADAPTER_VERSION = "ollama-adapter/4"

#: Der Dateiname in ``_governance``. Das Element (dieser eine Server, dieses
#: eine Gewicht) gehört zur Datenwurzel; die Menge der freigegebenen Modelle
#: steht im Profil (``model_vocabulary``). Zwei Objekte, zwei Orte.
MODEL_CONFIG_NAME = "model.toml"

#: Nur der eigene Rechner. Ein Modellserver auf einem anderen Host wäre eine
#: Datenabgabe, und die entscheidet kein Konfigurationswert (ADR 0017).
#: ``OLLAMA_HOST`` wird ABSICHTLICH nicht gelesen: eine Umgebungsvariable
#: könnte die Regel still verschieben, und genau dagegen steht sie hier.
ALLOWED_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})

#: Diese Schlüssel sind Pflicht, unbekannte Schlüssel Fehler. Ein Vorgabewert wäre
#: eine Korpusentscheidung, die niemand getroffen hat (ADR 0012, ADR 0018).
CONFIG_KEYS: dict[str, type | tuple[type, ...]] = {
    "runtime": str,
    "host": str,
    "model": str,
    "model_digest": str,
    "temperature": (int, float),
    "seed": int,
    "num_ctx": int,
    "num_predict": int,
    "max_chars": int,
    "timeout_s": int,
    "repeat_probe": bool,
    "block_size": int,
}
#: Ohne Opt-in bleibt der bisherige Ablauf; die kalte Variante ist zusätzlich gebunden.
OPTIONAL_CONFIG_KEYS = {"repeat_probe_cold": bool}

BELEGT = (
    f"{ADAPTER_VERSION}: Ausgabebytes unter diesem Manifest-Digest, Parametersatz "
    "und dieser Ollama-Version; output_sha256 nachprüfbar"
)
NICHT_BELEGT = (
    f"{ADAPTER_VERSION}: Wiederholbarkeit über Ollama-Versionen, Hardware oder "
    "Prozesse; Vollständigkeit des Eingangs (kein Tokenizer-Zugang an Ollama 0.32); "
    "Übereinstimmung mit einer Attestation, die den Tag nur als Text nennt und "
    "keinen Digest führt"
)
WIEDERHOLUNGSPROBE = "verlangt: zwei Läufe bitgleich im selben Prozess, sonst Abbruch"
KALTE_WIEDERHOLUNGSPROBE = (
    "verlangt: zwei Läufe nach je bestätigter Runnerentladung bitgleich, sonst Abbruch; "
    "keine allgemeine Wiederholbarkeitsgarantie"
)

#: Kurze Wartezeit für die drei Auskunftsendpunkte. Sie fragen einen lokalen
#: Server nach Stammdaten; hängt er dort, ist er nicht in einem Zustand, in
#: dem man ihm ein Interview schickt.
PROBE_TIMEOUT_S = 10

_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")

#: Der Zusatz an JEDER Abbruchmeldung dieses Moduls. Er ist die Antwort auf
#: die einzige Frage, die der Operator im Abbruchfall wirklich hat.
_NICHTS = "Kein Lauf, nichts geschrieben."


class OllamaConfigError(SuggestError):
    """``model.toml`` fehlt oder ist formfalsch.

    Eigene Klasse, weil die Antwort eine andere ist als bei einem Laufabbruch:
    Eine formfalsche Datei korrigiert der Operator in einer Zeile, ein
    Digestbruch ist eine Aussage über das Gewicht auf der Platte.
    """


class OllamaAdapterError(SuggestError):
    """Ein Abbruch aus dem Ablauf: Host, Server, Digest, Antwort, Runner, Probe.

    ``steps.py::continue_record`` fängt ``ValueError``/``RuntimeError`` und
    setzt ``failure_kind`` auf den Klassennamen. Deshalb ist der Name hier
    Teil der Auskunft und nicht nur Innenleben.
    """


@dataclass(frozen=True)
class ModelConfig:
    """Das Element: dieser Server, dieses Gewicht, diese Größen.

    Frozen, weil der Parametersatz eines Laufs nach ADR 0012 einem KORPUS
    gehört: Wird einer dieser Werte während eines Laufs geändert, sind
    interviewübergreifende Aussagen über den alten Korpus nicht mehr gedeckt.
    """

    runtime: str
    host: str
    model: str
    model_digest: str
    temperature: float
    seed: int
    num_ctx: int
    num_predict: int
    max_chars: int
    timeout_s: int
    repeat_probe: bool
    block_size: int
    path: Path
    repeat_probe_cold: bool = False


def _fehler(pfad: Path, schluessel: str | None, grund: str) -> OllamaConfigError:
    ort = f"{pfad}" if schluessel is None else f"{pfad}, Schlüssel {schluessel!r}"
    return OllamaConfigError(f"{ort}: {grund} {_NICHTS}")


def load_model_config(path: Path) -> ModelConfig:
    """Liest ``model.toml`` streng: alle Schlüssel, keine fremden, echte Typen.

    Streng heißt hier auch: ``bool`` ist nicht ``"true"`` und ``int`` ist nicht
    ``1.5``. TOML unterscheidet beides, Python würde es durchwinken, und ein
    ``seed``, der als 1.5 im Beleg steht, ist ein Beleg über einen Lauf, den
    niemand wiederholen kann.
    """
    if not path.exists():
        raise _fehler(path, None, "Modellkonfiguration fehlt.")
    try:
        roh = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise _fehler(path, None, f"nicht lesbar ({exc}).") from exc

    block = roh.get("model")
    if not isinstance(block, dict):
        raise _fehler(path, "model", "Abschnitt [model] fehlt oder ist kein Abschnitt.")

    fremd = sorted(set(block) - set(CONFIG_KEYS) - set(OPTIONAL_CONFIG_KEYS))
    if fremd:
        raise _fehler(
            path,
            ", ".join(fremd),
            "unbekannter Schlüssel. Ein unbekannter Schlüssel ist keine Erweiterung, "
            "sondern ein Tippfehler, der still nichts tut.",
        )
    fehlend = sorted(set(CONFIG_KEYS) - set(block))
    if fehlend:
        raise _fehler(
            path,
            ", ".join(fehlend),
            "fehlt. Für keinen dieser Werte gibt es einen sicheren Vorgabewert "
            "(ADR 0012, ADR 0018).",
        )

    for schluessel, typ in (CONFIG_KEYS | OPTIONAL_CONFIG_KEYS).items():
        if schluessel not in block:
            continue
        wert = block[schluessel]
        # bool ist in Python ein int. Ein `repeat_probe = 1` waere damit still
        # gueltig, und die Zusage im Beleg haenge an einer Zahl.
        if typ is bool:
            if not isinstance(wert, bool):
                raise _fehler(
                    path, schluessel, f"muss ein TOML-Boolean sein, ist {type(wert).__name__}."
                )
            continue
        if isinstance(wert, bool) or not isinstance(wert, typ):
            erwartet = typ.__name__ if isinstance(typ, type) else "Zahl"
            raise _fehler(path, schluessel, f"muss {erwartet} sein, ist {type(wert).__name__}.")

    if block["runtime"] != "ollama":
        raise _fehler(path, "runtime", f"kennt nur 'ollama', nicht {block['runtime']!r}.")
    if block.get("repeat_probe_cold", False) and not block["repeat_probe"]:
        raise _fehler(path, "repeat_probe_cold", "verlangt repeat_probe = true.")
    if block["model"].count(":") != 1:
        raise _fehler(
            path,
            "model",
            f"{block['model']!r} ist kein exakter Tag. Verlangt ist genau ein Doppelpunkt: "
            "ohne ihn ergänzt die Registry stumm ':latest', und derselbe Wortlaut wäre "
            "morgen ein anderes Gewicht.",
        )
    if not _DIGEST_RE.fullmatch(block["model_digest"]):
        raise _fehler(
            path,
            "model_digest",
            "ist kein Manifest-Digest (64 Hexziffern, klein geschrieben, ohne 'sha256:').",
        )
    for schluessel in ("num_ctx", "num_predict", "max_chars", "timeout_s", "block_size"):
        if block[schluessel] <= 0:
            raise _fehler(path, schluessel, "muss größer als null sein.")

    _pruefe_host(block["host"], path)

    return ModelConfig(
        runtime=block["runtime"],
        host=block["host"].rstrip("/"),
        model=block["model"],
        model_digest=block["model_digest"],
        temperature=float(block["temperature"]),
        seed=block["seed"],
        num_ctx=block["num_ctx"],
        num_predict=block["num_predict"],
        max_chars=block["max_chars"],
        timeout_s=block["timeout_s"],
        repeat_probe=block["repeat_probe"],
        block_size=block["block_size"],
        path=path,
        repeat_probe_cold=block.get("repeat_probe_cold", False),
    )


def _pruefe_host(host: str, path: Path) -> None:
    """Schema ``http``, Hostliteral aus :data:`ALLOWED_HOSTS`, Port beliebig.

    Die Prüfung sitzt im LADEN und nicht im ersten Aufruf: Ein fremder Host
    darf nicht erst dadurch auffallen, dass jemand ihn angesprochen hat.
    """
    teile = urlsplit(host)
    if teile.scheme != "http":
        raise _fehler(path, "host", f"Schema {teile.scheme or '(keines)'!r} statt 'http'.")
    name = (teile.hostname or "").lower()
    if name not in ALLOWED_HOSTS:
        raise _fehler(
            path,
            "host",
            f"{name or '(kein Host)'!r} ist nicht der eigene Rechner. Erlaubt sind "
            f"{', '.join(sorted(ALLOWED_HOSTS))}; ein Modellserver anderswo wäre eine "
            "Datenabgabe, und die entscheidet kein Konfigurationswert (ADR 0017).",
        )
    if teile.path.strip("/") or teile.query or teile.fragment:
        raise _fehler(
            path, "host", "trägt Pfad, Abfrage oder Fragment; erwartet ist nur die Wurzel."
        )


class _HttpClient:
    """Der einzige Weg nach draußen: urllib, ohne Proxy, mit Timeout, nur JSON.

    ``ProxyHandler({})`` ist keine Kosmetik. Ohne ihn nimmt urllib ``HTTP_PROXY``
    aus der Umgebung, und ein Lauf gegen ``127.0.0.1`` ginge über einen fremden
    Rechner — genau die Abgabe, die die Hostregel verhindern soll, nur eine
    Ebene tiefer.
    """

    def __init__(self, host: str) -> None:
        self.host = host
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def get(self, pfad: str, timeout: int) -> dict[str, Any]:
        return self._json(urllib.request.Request(f"{self.host}{pfad}", method="GET"), timeout, pfad)

    def post(self, pfad: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
        anfrage = urllib.request.Request(
            f"{self.host}{pfad}",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return self._json(anfrage, timeout, pfad)

    def _json(self, anfrage: urllib.request.Request, timeout: int, pfad: str) -> dict[str, Any]:
        try:
            with self._opener.open(anfrage, timeout=timeout) as antwort:
                if antwort.status != 200:
                    raise OllamaAdapterError(
                        f"{pfad} antwortet mit HTTP {antwort.status}. {_NICHTS}"
                    )
                roh = antwort.read()
        except OllamaAdapterError:
            raise
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            # Der Grund wird benannt, aber nicht die Antwort: eine Fehlerseite
            # kann Inhalt tragen, und Inhalt gehoert nicht in eine Meldung.
            raise OllamaAdapterError(
                f"{pfad} nicht erreichbar oder abgelaufen ({type(exc).__name__}). {_NICHTS}"
            ) from exc
        try:
            obj = json.loads(roh)
        except ValueError as exc:
            raise OllamaAdapterError(f"{pfad} antwortet nicht mit JSON. {_NICHTS}") from exc
        if not isinstance(obj, dict):
            raise OllamaAdapterError(f"{pfad} antwortet nicht mit einem JSON-Objekt. {_NICHTS}")
        return obj


class OllamaAdapter:
    """Ein Lauf gegen den lokalen Server, mit eingefrorenem Parametersatz.

    Der Konstruktor führt die Schritte 1 bis 3a aus: Hostregel, Version, Tag
    und Digest, ``show``. Danach steht ``params`` fest. Das ist Absicht: Was
    im Beleg steht, wird gemessen, BEVOR ein Prompt existiert — sonst könnte
    der Beleg beschreiben, was der Lauf gebraucht hätte, statt was er hatte.
    """

    def __init__(self, cfg: ModelConfig, answer_schema: dict[str, Any] | None = None) -> None:
        self.cfg = cfg
        self._answer_schema = deepcopy(ANSWER_SCHEMA if answer_schema is None else answer_schema)
        self.name = cfg.model
        self._client = _HttpClient(cfg.host)

        version = self._version()
        digest = self._digest_aus_tags()
        defaults, details = self._show()

        self._params = ModelParams(
            model=cfg.model,
            model_digest=digest,
            temperature=cfg.temperature,
            seed=cfg.seed,
            num_ctx=cfg.num_ctx,
            num_predict=cfg.num_predict,
            max_chars=cfg.max_chars,
            extra={
                "block_size": cfg.block_size,
                "runtime": "ollama",
                "ollama_version": version,
                "host": cfg.host,
                "think": False,
                "format_sha256": sha256_json(self._answer_schema),
                "modelfile_defaults": defaults,
                "model_details": details,
                "options_verified": "num_predict",
                "belegt": BELEGT,
                "nicht_belegt": NICHT_BELEGT,
                **({"wiederholungsprobe": WIEDERHOLUNGSPROBE} if cfg.repeat_probe else {}),
                **(
                    {"repeat_probe_cold": True, "wiederholungsprobe": KALTE_WIEDERHOLUNGSPROBE}
                    if cfg.repeat_probe_cold
                    else {}
                ),
            },
        )

    @property
    def params(self) -> ModelParams:
        return self._params

    # ------------------------------------------------ Schritt 2, 3, 3a

    def _version(self) -> str:
        obj = self._client.get("/api/version", PROBE_TIMEOUT_S)
        version = obj.get("version")
        if not isinstance(version, str) or not version:
            raise OllamaAdapterError(
                f"Modellserver antwortet nicht unter {self.cfg.host}; nichts gesendet. {_NICHTS}"
            )
        return version

    def _digest_aus_tags(self) -> str:
        obj = self._client.get("/api/tags", PROBE_TIMEOUT_S)
        modelle = obj.get("models")
        if not isinstance(modelle, list):
            raise OllamaAdapterError(f"/api/tags trägt keine Modellliste. {_NICHTS}")
        for eintrag in modelle:
            if isinstance(eintrag, dict) and eintrag.get("name") == self.cfg.model:
                digest = str(eintrag.get("digest", ""))
                if not _DIGEST_RE.fullmatch(digest):
                    raise OllamaAdapterError(
                        f"/api/tags nennt für {self.cfg.model!r} keinen Manifest-Digest "
                        f"(64 Hexziffern). {_NICHTS}"
                    )
                if digest != self.cfg.model_digest:
                    raise OllamaAdapterError(
                        f"Tag {self.cfg.model!r} trägt heute Digest {digest}, erwartet "
                        f"{self.cfg.model_digest}; das ist ein anderes Gewicht unter demselben "
                        f"Namen (ADR 0012, ADR 0018). {_NICHTS}"
                    )
                return digest
        raise OllamaAdapterError(
            f"Modell {self.cfg.model!r} ist auf diesem Server nicht installiert; der Adapter "
            f"zieht nicht. {_NICHTS}"
        )

    def _show(self) -> tuple[str, str]:
        obj = self._client.post("/api/show", {"model": self.cfg.model}, PROBE_TIMEOUT_S)
        defaults = obj.get("parameters")
        if not isinstance(defaults, str):
            # Leer ist erlaubt (ein Modell ohne Modelfile-Vorgaben), fehlend nicht:
            # dann weiss der Beleg nicht, wogegen die gesendeten Optionen liefen.
            raise OllamaAdapterError(
                f"/api/show nennt für {self.cfg.model!r} kein Feld 'parameters'; die "
                f"Vorgaben des Modelfiles sind damit unbekannt. {_NICHTS}"
            )
        details = obj.get("details") if isinstance(obj.get("details"), dict) else {}
        quant = str(details.get("quantization_level", "?"))
        groesse = str(details.get("parameter_size", "?"))
        return defaults, f"{quant}/{groesse}"

    # ------------------------------------------------ Schritt 4 bis 9

    def run(self, prompt: str, params: ModelParams) -> ModelResponse:
        if params.fingerprint != self._params.fingerprint:
            raise OllamaAdapterError(
                "Der übergebene Parametersatz ist nicht der gemessene dieses Adapters; "
                f"ein Beleg darüber wäre über einen anderen Lauf. {_NICHTS}"
            )
        if len(prompt) > self.cfg.max_chars:
            raise OllamaAdapterError(
                f"Eingang ist {len(prompt)} Zeichen lang, max_chars ist {self.cfg.max_chars}; "
                "er würde mit hoher Wahrscheinlichkeit stumm abgeschnitten. max_chars ist eine "
                f"Korpusentscheidung (ADR 0018), keine Notbremse. {_NICHTS}"
            )

        if self.cfg.repeat_probe_cold:
            self._entladen()
        text, finish, tokens = self._einmal(prompt)
        digest = self._digest_am_runner()

        if self.cfg.repeat_probe:
            if self.cfg.repeat_probe_cold:
                self._entladen()
            zweiter_text, zweiter_finish, _ = self._einmal(prompt)
            self._digest_am_runner()
            if zweiter_text != text or zweiter_finish != finish:
                raise OllamaAdapterError(
                    "Laufzeit ist unter diesem Parametersatz nicht wiederholbar; die Zusage "
                    "im Parametersatz ist verletzt, also gibt es keinen Beleg. "
                    f"(Zwei Läufe, gleicher Body, verschiedene Ausgabe.) {_NICHTS}"
                )

        return ModelResponse(
            text=text, finish_reason=finish, output_tokens=tokens, model_digest=digest
        )

    def _entladen(self) -> None:
        """Ein Entladeauftrag, danach begrenzte Statusbeobachtung; keine Generierungswiederholung."""
        response = self._client.post(
            "/api/generate", {"model": self.cfg.model, "keep_alive": 0}, PROBE_TIMEOUT_S
        )
        if response.get("done") is not True or response.get("done_reason") != "unload":
            raise OllamaAdapterError(f"Runnerentladung nicht bestätigt. {_NICHTS}")
        deadline = time.monotonic() + PROBE_TIMEOUT_S
        while True:
            models = self._client.get("/api/ps", PROBE_TIMEOUT_S).get("models")
            if not isinstance(models, list) or any(
                not isinstance(m, dict)
                or not isinstance(m.get("digest"), str)
                or not _DIGEST_RE.fullmatch(m["digest"])
                for m in models
            ):
                raise OllamaAdapterError(f"Runnerstatus nach Entladeauftrag ungültig. {_NICHTS}")
            if not any(m["digest"] == self.cfg.model_digest for m in models):
                return
            if time.monotonic() >= deadline:
                raise OllamaAdapterError(f"Runner nach Entladeauftrag weiterhin geladen. {_NICHTS}")
            time.sleep(0.1)

    def _einmal(self, prompt: str) -> tuple[str, str, int]:
        """Schritt 5 und 6: ein Body, ein Timeout, dann die Antwort prüfen."""
        antwort = self._client.post(
            "/api/generate",
            {
                "model": self.cfg.model,
                "prompt": prompt,
                "stream": False,
                "think": False,
                "format": self._answer_schema,
                "options": {
                    "temperature": self.cfg.temperature,
                    "seed": int(self.cfg.seed),
                    "num_ctx": int(self.cfg.num_ctx),
                    "num_predict": int(self.cfg.num_predict),
                },
            },
            self.cfg.timeout_s,
        )

        if antwort.get("done") is not True:
            raise OllamaAdapterError(
                f"/api/generate meldet den Lauf nicht als beendet (done ist nicht true). {_NICHTS}"
            )
        denktext = antwort.get("thinking")
        if isinstance(denktext, str) and denktext.strip():
            raise OllamaAdapterError(
                "Antwort trägt Denktext; 'think: false' war gesendet. Eine Laufzeit, die "
                f"das Feld trotzdem füllt, hält den Parametersatz nicht ein. {_NICHTS}"
            )
        finish = antwort.get("done_reason")
        finish = finish if isinstance(finish, str) and finish else "unknown"
        tokens = antwort.get("eval_count")
        if not isinstance(tokens, int) or isinstance(tokens, bool):
            raise OllamaAdapterError(
                f"/api/generate nennt kein ganzzahliges 'eval_count'; die Länge der Ausgabe "
                f"ist damit unbelegt. {_NICHTS}"
            )
        if tokens > self.cfg.num_predict:
            raise OllamaAdapterError(
                f"Laufzeit hat die Grenze ignoriert: eval_count {tokens} über num_predict "
                f"{self.cfg.num_predict}. {_NICHTS}"
            )
        text = antwort.get("response")
        if not isinstance(text, str):
            raise OllamaAdapterError(f"/api/generate nennt kein Feld 'response'. {_NICHTS}")
        return text, finish, tokens

    def _digest_am_runner(self) -> str:
        """Schritt 7: der geladene Runner, per DIGEST gesucht, nicht per Name.

        Der Name ist unerheblich (Prüfvermerk B-1): Derselbe Digest kann unter
        einem zweiten Tag geladen sein, und das ist dasselbe Gewicht. Umgekehrt
        sagt ein passender Name über das Gewicht nichts.
        """
        obj = self._client.get("/api/ps", PROBE_TIMEOUT_S)
        modelle = obj.get("models")
        if not isinstance(modelle, list):
            raise OllamaAdapterError(f"/api/ps trägt keine Modellliste. {_NICHTS}")
        erwartet = self._params.model_digest
        for eintrag in modelle:
            if not isinstance(eintrag, dict) or eintrag.get("digest") != erwartet:
                continue
            kontext = eintrag.get("context_length")
            if kontext != self.cfg.num_ctx:
                raise OllamaAdapterError(
                    f"Laufzeit hat Kontext {kontext} statt {self.cfg.num_ctx} geladen; der "
                    f"Lauf lief unter anderen Bedingungen als der Parametersatz nennt. {_NICHTS}"
                )
            return str(erwartet)
        raise OllamaAdapterError(
            f"Kein geladener Runner mit Digest {erwartet} nach dem Lauf; welches Gewicht "
            f"geantwortet hat, ist damit unbelegt. {_NICHTS}"
        )
