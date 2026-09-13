"""Ein Lauf gegen ein echtes Ollama — der Fall, den der Fake-Server nicht kann.

Der Fake-Server misst das Verhalten an der Grenze: was gesendet wird, was
abgelehnt wird, was NICHT gesendet wird. Was er nicht messen kann, ist, ob die
Annahmen über die echte Laufzeit stimmen — ob ``/api/tags`` wirklich einen
64-Hex-Digest führt, ob ``/api/show`` ein Feld ``parameters`` hat, ob
``/api/ps`` nach dem Lauf einen Runner mit diesem Digest und diesem
``context_length`` zeigt, und ob zwei Läufe mit ``temperature 0`` und festem
``seed`` im selben Prozess wirklich bitgleich sind. Genau diese vier Annahmen
tragen den Beleg; ein Adapter, der sie nur gegen seine eigene Nachbildung
prüft, prüft seine Nachbildung.

Der Fall überspringt sich, wenn unter ``127.0.0.1:11434`` niemand antwortet
oder das Modell dort nicht liegt. Im Testinventar steht er deshalb als „läuft
nur auf dem Mac": In der CI gibt es keinen Modellserver, und ein Fall, der
dort still grün wäre, träfe keine Aussage.

Der Prompt ist kurz und synthetisch. Reale Interviewbytes stehen in keinem
Test dieses Repositoriums (dieselbe Regel wie in ``test_profile_walz.py``).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from ohpipe.adapters.models.ollama import OllamaAdapter, load_model_config
from ohpipe.application.l1_suggest import build_prompt, parse_answer
from ohpipe.domain.revision_serialization import PROJECTION_VERSION
from ohpipe.domain.transcript import Segment, TranscriptRevision

HOST = "http://127.0.0.1:11434"
MODELL = "mistral:7b-instruct"
PROMPT = build_prompt(
    TranscriptRevision.from_segments(
        (Segment(0, 0, 1000, "Wir gingen jeden Tag zu Fuß zur Schule.", "A", "deu"),),
        projection_version=PROJECTION_VERSION,
        source_kind="srt",
    )
)


def _server_antwortet() -> bool:
    try:
        with urllib.request.urlopen(f"{HOST}/api/version", timeout=2) as antwort:
            return antwort.status == 200
    except (urllib.error.URLError, OSError, TimeoutError):
        return False


def _digest() -> str | None:
    """Der Manifest-Digest des Modells, oder ``None``, wenn es nicht da ist.

    Der Pin wird hier GELESEN und nicht verabredet: Ein Test, der einen festen
    Digest mitbrächte, fiele bei jedem ``ollama pull`` — und zwar als Defekt
    des Adapters, obwohl nur ein Gewicht neuer ist.
    """
    try:
        with urllib.request.urlopen(f"{HOST}/api/tags", timeout=5) as antwort:
            modelle = json.loads(antwort.read()).get("models", [])
    except (urllib.error.URLError, OSError, TimeoutError, ValueError):
        return None
    for eintrag in modelle:
        if eintrag.get("name") == MODELL:
            return str(eintrag.get("digest", "")) or None
    return None


pytestmark = pytest.mark.skipif(
    not _server_antwortet(), reason=f"kein Ollama unter {HOST} (läuft nur auf dem Mac)"
)


def test_a_real_run_against_ollama_keeps_the_four_promises(tmp_path: Path):
    """Digest, Modelfile-Vorgaben, geladener Runner, Wiederholbarkeit — am Objekt.

    Was hier gemessen wird, ist nicht die Antwort des Modells. Was das Modell
    sagt, ist für diese Zusicherung bedeutungslos; gemessen wird, ob der
    Beleg trägt: derselbe Digest vor und nach dem Lauf, ein Runner mit genau
    diesem Digest und dem geladenen Kontext, und zwei bitgleiche Läufe.
    """
    digest = _digest()
    if digest is None:
        pytest.skip(f"{MODELL} liegt auf diesem Server nicht")

    datei = tmp_path / "model.toml"
    datei.write_text(
        "\n".join(
            [
                "[model]",
                'runtime = "ollama"',
                f'host = "{HOST}"',
                f'model = "{MODELL}"',
                f'model_digest = "{digest}"',
                "temperature = 0.0",
                "seed = 7",
                "num_ctx = 4096",
                "num_predict = 128",
                "max_chars = 12000",
                "timeout_s = 600",
                "repeat_probe = true",
                "block_size = 64",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    adapter = OllamaAdapter(load_model_config(datei))
    assert adapter.params.model_digest == digest
    assert adapter.params.extra["runtime"] == "ollama"
    assert adapter.params.extra["ollama_version"], "keine Versionsangabe aus /api/version"
    assert isinstance(adapter.params.extra["modelfile_defaults"], str)
    assert adapter.params.extra["think"] is False

    antwort = adapter.run(PROMPT, adapter.params)
    # Der Lauf ist durch die Wiederholungsprobe gegangen: zwei Laeufe im selben
    # Prozess, bitgleich. Das ist die einzige Aussage ueber Determiniertheit,
    # die dieser Adapter macht, und sie gilt fuer diesen Lauf.
    assert antwort.model_digest == digest
    assert antwort.output_tokens <= 128
    assert antwort.finish_reason, "kein finish_reason"

    assert antwort.finish_reason == "stop"
    assert len(parse_answer(antwort.text, [0])) == 1
