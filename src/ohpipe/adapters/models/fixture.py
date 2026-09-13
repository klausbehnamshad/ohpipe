"""Der aufgezeichnete Modelladapter — ein Modell, das nie läuft.

Demo-Moment 3 des ROADMAP-Entwurfs verlangt einen Modelllauf, der an der
Token-Grenze **scheitert, statt ein Teilergebnis zu liefern**, und zwar ohne
lokalen Modellserver. Genau das leistet dieser Adapter: er antwortet aus einer
Aufzeichnung, deterministisch, in zwei Szenarien.

* ``stop``: eine saubere Antwort, ein Vorschlag je Sprechersegment, jeder mit
  Segmentnummer und Code. Damit läuft die Kette bis ``l1.coverage`` weiter.
* ``length``: dieselbe Antwort, aber an der Token-Grenze abgeschnitten —
  ``finish_reason='length'``, das JSON-Dokument unvollständig. Der Empfangsvertrag
  (``ModelReceipt.validate``) lehnt sie ab, bevor ein Byte gespeichert wird.

**Warum die Antwort aus dem Prompt gerechnet wird und nicht aus einer Datei.**
Eine wörtliche Aufzeichnung passte auf genau ein Transkript; jeder andere
synthetische Record bekäme Segmentnummern, die es in seiner Fassung nicht
gibt, und der Lauf fiele an einer Aufzeichnung statt an seinem Gegenstand.
Das wäre ein Test der Aufzeichnung, nicht des Empfangsvertrags. Aufgezeichnet
ist deshalb das **Verhalten** (Modellname, Digest, Parametersatz,
Abbruchursache), berechnet wird nur der Eintrag je Segment. Was das Modell sagen
würde, ist hier bedeutungslos; was zählt, ist, wie der Lauf endet und ob der
Beleg das ehrlich trägt.

Der Adapter kennt weder Journal noch Store. Er bekommt einen Prompt und gibt
eine Antwort zurück. Alles, was Evidenz ist, entsteht in
``ohpipe.application.l1_suggest``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Protocol

from ...domain.hashing import sha256_text
from ...domain.receipt import FINISH_LENGTH, FINISH_OK, ModelParams

__all__ = [
    "FIXTURE_MODEL",
    "SCENARIOS",
    "FixtureAdapter",
    "ModelAdapter",
    "ModelResponse",
    "fixture_params",
]

#: Der Modellname des Adapters. Der Doppelpunkt trennt Adapterart und
#: Verhalten, wie bei ``gemma4:e4b`` Modell und Variante.
FIXTURE_MODEL = "fixture:descriptive-l1"

#: Die Fassung des aufgezeichneten Verhaltens. Ihr Digest steht als
#: ``model_digest`` im Beleg: ändert sich die Antwortregel, ändert sich der
#: Parametersatz, und ``ModelReceipt.matches`` sieht einen anderen Lauf.
_BEHAVIOUR = (
    "fixture:descriptive-l1/4 — genau ein Vorschlag je Segment, auch bei kurzem Text; "
    "JSON-Objekt mit results-Liste, je Eintrag nur segment und code; "
    "blockweise, Blockgroesse 64"
)

SCENARIOS = (FINISH_OK, FINISH_LENGTH)


@dataclass(frozen=True)
class ModelResponse:
    """Was ein Adapter zurückgibt — nicht mehr. Kein Beleg, keine Evidenz."""

    text: str
    finish_reason: str
    output_tokens: int
    model_digest: str


class ModelAdapter(Protocol):
    name: str
    params: ModelParams

    def run(self, prompt: str, params: ModelParams) -> ModelResponse: ...


def fixture_params(scenario: str) -> ModelParams:
    """Der eingefrorene Parametersatz je Szenario (ADR 0012: Korpussache).

    ``num_predict`` ist im Szenario ``length`` die Grenze, an der der Lauf
    endet. Sie ist klein, damit sie an jedem synthetischen Record greift.
    """
    if scenario not in SCENARIOS:
        raise ValueError(f"Unbekanntes Fixture-Szenario {scenario!r}. Bekannt: {SCENARIOS}")
    return ModelParams(
        model=FIXTURE_MODEL,
        model_digest=sha256_text(_BEHAVIOUR),
        temperature=0.0,
        seed=0,
        num_predict=64 if scenario == FINISH_LENGTH else 4096,
        extra={"scenario": scenario, "block_size": 64},
    )


def _segments(prompt: str) -> list[dict[str, Any]]:
    """Die Segmente aus dem strukturierten Teil des Prompts.

    Der Prompt trägt nach einer Leerzeile ein JSON-Objekt mit ``segments``.
    Ein Prompt ohne diesen Teil ist kein Prompt dieses Adapters — Fehler, kein
    leeres Ergebnis.
    """
    _, _, body = prompt.partition("\n\n")
    try:
        obj = json.loads(body)
        segments = obj["segments"]
    except (ValueError, KeyError, TypeError) as exc:
        raise ValueError("Fixture-Prompt trägt keinen JSON-Segmentblock") from exc
    if not isinstance(segments, list):
        raise ValueError("Fixture-Prompt: segments ist keine Liste")
    return segments


def _rows(segments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Auch kurze Segmente gehören zur vollständigen Antwort (O-3)."""
    return [
        {"segment": seg["index"], "code": f"L1.{n:02d}"} for n, seg in enumerate(segments, start=1)
    ]


class FixtureAdapter:
    """Antwortet aus der Aufzeichnung. ``scenario`` entscheidet, wie der Lauf endet."""

    name = FIXTURE_MODEL

    def __init__(self, scenario: str = FINISH_OK) -> None:
        if scenario not in SCENARIOS:
            raise ValueError(f"Unbekanntes Fixture-Szenario {scenario!r}. Bekannt: {SCENARIOS}")
        self.scenario = scenario

    @property
    def params(self) -> ModelParams:
        return fixture_params(self.scenario)

    def run(self, prompt: str, params: ModelParams) -> ModelResponse:
        if params.model != FIXTURE_MODEL:
            raise ValueError(f"FixtureAdapter kennt nur {FIXTURE_MODEL!r}, nicht {params.model!r}")
        text = json.dumps({"results": _rows(_segments(prompt))}, ensure_ascii=False, sort_keys=True)
        digest = sha256_text(_BEHAVIOUR)
        if self.scenario == FINISH_OK:
            return ModelResponse(text, FINISH_OK, len(text.split()), digest)
        # length: dasselbe Dokument, mitten in der Ausgabe abgeschnitten.
        # Der Beleg weist es vor dem Parsen und vor jedem Schreiben ab.
        text = text[: len(text) // 2]
        return ModelResponse(text, FINISH_LENGTH, int(params.num_predict or 0), digest)
