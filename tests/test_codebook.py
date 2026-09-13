"""Codebuchvertrag: nur synthetische Kategorien, kein Modellserver."""

import copy
import json
from dataclasses import replace

import pytest

from ohpipe.adapters.models import ollama
from ohpipe.application.codebook import load_codebook
from ohpipe.application.l1_suggest import ANSWER_SCHEMA, answer_schema, build_prompt
from ohpipe.domain.hashing import sha256_json
from ohpipe.domain.revision_serialization import PROJECTION_VERSION
from ohpipe.domain.transcript import Segment, TranscriptRevision


def _book_text(ids=("ZZ", "AA", "UNGEKLAERT")):
    text = '''schema = "ohpipe.l1.codebook.v1"
corpus = "synthetic"
version = "V0"
language = "de"
created = "2026-09-07"
source_artifacts = []
[rules]
priority = ["Sachkategorie zuerst.", "Sonst UNGEKLAERT."]
'''
    for cid in ids:
        text += f'''
[[category]]
id = "{cid}"
label = "Testkategorie {cid}"
definition = "Synthetische Definition."
include = "Synthetischer Einschluss."
exclude = "Synthetischer Ausschluss."
examples = ["BEISPIEL_NUR_FUER_MENSCHEN"]
'''
    return text


def _write_book(path, text=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_book_text() if text is None else text, encoding="utf-8")
    return path


def test_codebook_02_duplicate_id_halts_and_names_id(tmp_path):
    path = _write_book(tmp_path / "book.toml", _book_text(("AA", "AA", "UNGEKLAERT")))
    with pytest.raises(ValueError, match="ID AA doppelt") as error:
        load_codebook(path)
    assert str(path) in str(error.value)
    assert str(error.value).endswith("Kein Teilergebnis, nichts geschrieben.")


def test_codebook_03_missing_ungeklaert_halts(tmp_path):
    path = _write_book(tmp_path / "book.toml", _book_text(("AA",)))
    with pytest.raises(ValueError, match="UNGEKLAERT fehlt"):
        load_codebook(path)


def test_codebook_04_no_categories_halts(tmp_path):
    path = _write_book(tmp_path / "book.toml", _book_text(()))
    with pytest.raises(ValueError, match=r"keine einzige \[\[category\]\]"):
        load_codebook(path)


def test_codebook_05_missing_exclude_and_invalid_documents_halt(tmp_path):
    path = tmp_path / "book.toml"
    with pytest.raises(ValueError, match="Codebuch fehlt"):
        load_codebook(path)
    invalid = [
        (_book_text().replace('exclude = "Synthetischer Ausschluss."\n', "", 1), "exclude"),
        (_book_text().replace('exclude = "Synthetischer Ausschluss."', 'exclude = ""', 1), "exclude"),
        (_book_text().replace('["BEISPIEL_NUR_FUER_MENSCHEN"]', "[]", 1), "examples"),
        (_book_text().replace("ohpipe.l1.codebook.v1", "other"), "schema"),
        ("[broken", "TOML"),
    ]
    for text, reason in invalid:
        _write_book(path, text)
        with pytest.raises(ValueError, match=reason) as error:
            load_codebook(path)
        assert str(path) in str(error.value)
        assert str(error.value).endswith("Kein Teilergebnis, nichts geschrieben.")


def test_codebook_06_lowercase_id_halts(tmp_path):
    path = _write_book(tmp_path / "book.toml", _book_text(("aa", "UNGEKLAERT")))
    with pytest.raises(ValueError, match="ID entspricht nicht"):
        load_codebook(path)


def test_codebook_08_schema_enum_preserves_file_order(tmp_path):
    book = load_codebook(_write_book(tmp_path / "book.toml"))
    original = copy.deepcopy(ANSWER_SCHEMA)
    schema = answer_schema(book)
    code = schema["properties"]["results"]["items"]["properties"]["code"]
    assert code == {"type": "string", "enum": ["ZZ", "AA", "UNGEKLAERT"]}
    assert book.ids == {"AA", "ZZ", "UNGEKLAERT"}
    assert book.raw == (tmp_path / "book.toml").read_bytes()
    del code["enum"]
    assert schema == ANSWER_SCHEMA == original


def test_codebook_09_prompt_head_has_no_blank_line_and_body_is_json(tmp_path):
    text = _book_text().replace(
        'definition = "Synthetische Definition."',
        'definition = """Synthetische\n\nDefinition."""',
    )
    book = load_codebook(_write_book(tmp_path / "book.toml", text))
    rev = TranscriptRevision.from_segments(
        (Segment(0, 0, 1000, "Test.", "A", "deu"),), projection_version=PROJECTION_VERSION
    )
    prompt = build_prompt(rev, codebook=book)
    head, separator, body = prompt.partition("\n\n")
    assert separator and "\n\n" not in book.prompt_text
    assert json.loads(body)["segments"][0]["index"] == 0
    assert "Synthetische Definition." in head
    assert all(f"{cid}: Testkategorie {cid}" in head for cid in book.ids)
    assert "Einschluss:" in head and "Ausschluss:" in head
    assert "1. Sachkategorie zuerst." in head and "2. Sonst UNGEKLAERT." in head
    assert "BEISPIEL_NUR_FUER_MENSCHEN" not in prompt
    assert "genau eine ID je Segment" in head


def test_codebook_16_adapter_fingerprint_matches_sent_schema(tmp_path, monkeypatch):
    # Kein Socket: dieselben Adapterpfade gegen einen vollständig lokalen Transport.
    sent = []
    digest = "a" * 64

    class Client:
        def __init__(self, host):
            pass

        def get(self, path, timeout):
            return {
                "/api/version": {"version": "0.32.1"},
                "/api/tags": {"models": [{"name": "test:1", "digest": digest}]},
                "/api/ps": {"models": [{"digest": digest, "context_length": 8192}]},
            }[path]

        def post(self, path, body, timeout):
            if path == "/api/show":
                return {"parameters": "", "details": {}}
            assert path == "/api/generate"
            sent.append(copy.deepcopy(body))
            return {"done": True, "done_reason": "stop", "eval_count": 1,
                    "response": '{"results": []}'}

    monkeypatch.setattr(ollama, "_HttpClient", Client)
    cfg = ollama.ModelConfig("ollama", "http://127.0.0.1:11434", "test:1", digest,
                             0.0, 7, 8192, 4096, 12000, 600, False, 64, tmp_path / "model.toml")
    plain = ollama.OllamaAdapter(cfg)
    schema = answer_schema(load_codebook(_write_book(tmp_path / "book.toml")))
    bound = ollama.OllamaAdapter(cfg, answer_schema=schema)
    expected = copy.deepcopy(schema)
    schema["properties"]["results"]["items"]["properties"]["code"]["enum"].append("MUTATION")
    assert plain.params.extra["format_sha256"] == sha256_json(ANSWER_SCHEMA)
    assert bound.params.extra["format_sha256"] == sha256_json(expected)
    assert plain.params.fingerprint != bound.params.fingerprint
    plain.run("synthetisch", plain.params)
    bound.run("synthetisch", bound.params)
    assert sent[0]["format"] == ANSWER_SCHEMA
    assert sent[1]["format"] == expected
    for adapter, body in zip((plain, bound), sent, strict=True):
        assert adapter.params.extra["format_sha256"] == sha256_json(body["format"])
    assert replace(bound.params, extra=plain.params.extra) == plain.params
