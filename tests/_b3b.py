"""Ausfuehrung der geschlossenen B3b-Normmatrix ueber echte Produktwege.

Der Reiz enthaelt ausschliesslich Eingaben und Ausgangszustand. Diese Datei
erzeugt weder Soll-Reports noch ergaenzt sie unbeobachtete Ausgaenge. Jede
Observation stammt aus dem bezeichneten Domain-, Recovery- oder CLI-Aufruf
und aus Vor-/Nachmessungen seines synthetischen Workspace.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import sys
from copy import deepcopy
from collections.abc import Callable
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from ohpipe.application.confirmation import ConfirmPlan, write_confirmation
from ohpipe.application.operation_recovery import recovery_report
from ohpipe.application.replay import replay
from ohpipe.cli.main import main as cli_main
from ohpipe.domain.confirmation import ConfirmationDecision, ConfirmationMarker
from ohpipe.domain.events import check_payload
from ohpipe.domain.instance import InstanceRegistry
from ohpipe.domain.iso6393 import parse_iso6393_snapshot
from ohpipe.domain.language_assignment import build_srt_draft, parse_mapping
from ohpipe.domain.operation import OperationTrace, RetryIntent, canonical_json_bytes
from ohpipe.domain.token import (
    _DEFAULT_IGNORABLE_RANGES,
    is_default_ignorable_15_1,
    validate_label,
    validate_model_value,
    validate_token,
)
from ohpipe.journal import Journal
from ohpipe.policies.exit_contract import Report
from ohpipe.project import Profile, Workspace

ROOT = Path(__file__).resolve().parents[1]
COVERAGE = ROOT / "docs" / "b3b-norm-coverage.json"
PROFILE = ROOT / "src" / "ohpipe" / "profiles" / "sandbox" / "profile.toml"
ORIGINAL_FSYNC = os.fsync
ORIGINAL_REPORT_EMIT = Report.emit


def canonical_case_binding(value: Any) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def canonical_lf(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


def load_coverage() -> dict[str, Any]:
    document = json.loads(COVERAGE.read_text(encoding="ascii"))
    if not isinstance(document, dict) or not isinstance(document.get("cases"), list):
        raise AssertionError("B3b-Abdeckung braucht ein Objekt mit cases-Liste")
    return document


def load_cases(prefix: str) -> list[dict[str, Any]]:
    rows = load_coverage()["cases"]
    selected = [row for row in rows if row["norm_id"].startswith(f"{prefix}-")]
    if not selected:
        raise AssertionError(f"unbekannte oder leere Normklasse {prefix}")
    return selected


def _pointer_get(value: Any, pointer: str) -> Any:
    if not pointer.startswith("/"):
        raise AssertionError(f"ungueltiger JSON-Pointer {pointer!r}")
    current = value
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            current = current[int(token)]
        elif isinstance(current, dict):
            current = current[token]
        else:
            raise AssertionError(f"JSON-Pointer {pointer!r} laeuft in einen Skalar")
    return current


def _selector_get(value: Any, selector: str) -> tuple[bool, Any]:
    current = value
    for token in selector.split("."):
        if not isinstance(current, dict) or token not in current:
            return False, None
        current = current[token]
    return True, current


def _before_product_call(
    stimulus: dict[str, Any], runtime: dict[str, Any], entrypoint: str
) -> None:
    """Bindet den wirklichen Eintritt und einen semantischen Zielwert am Aufrufrand."""
    if entrypoint != runtime["expected_entrypoint"]:
        return
    runtime["entrypoint_call_count"] = runtime.get("entrypoint_call_count", 0) + 1
    runtime["observed_entrypoint"] = entrypoint
    proof = runtime["norm_predicate_proof"]
    if proof["predicate_kind"] != "consumed_target_exact":
        return
    pointer = proof["consumed_target"]["json_path"]
    value = _pointer_get(stimulus, pointer)
    runtime["observed_pre_call_state"] = {
        "json_path": pointer,
        "canonical_value": value,
        "canonical_value_sha256": hashlib.sha256(canonical_lf(value)).hexdigest(),
        "value_type": type(value).__name__,
        "measurement": f"exact consumed stimulus object immediately before {entrypoint}",
    }


def fingerprint_objects(case: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    fingerprint = case["effective_consumption_fingerprint"]
    facets = case["expected_result_facets_fingerprint"]
    return fingerprint, facets


def validate_fingerprints(case: dict[str, Any]) -> list[dict[str, Any]]:
    core, proof = fingerprint_objects(case)
    core_bytes = canonical_lf(core)
    proof_bytes = canonical_lf(proof)
    if core_bytes.decode("ascii") != case["effective_consumption_fingerprint_canonical"]:
        raise AssertionError(f"{case['norm_id']}: Konsumptionsfingerabdruck weicht ab")
    if hashlib.sha256(core_bytes).hexdigest() != case["effective_consumption_fingerprint_sha256"]:
        raise AssertionError(f"{case['norm_id']}: Konsumptionsfingerabdruck-sha256 weicht ab")
    if proof_bytes.decode("ascii") != case["expected_result_facets_fingerprint_canonical"]:
        raise AssertionError(f"{case['norm_id']}: Facettenfingerabdruck weicht ab")
    if hashlib.sha256(proof_bytes).hexdigest() != case["expected_result_facets_fingerprint_sha256"]:
        raise AssertionError(f"{case['norm_id']}: Facettenfingerabdruck-sha256 weicht ab")

    trace: list[dict[str, Any]] = []
    for binding in core["consumed_values"]:
        observed = _pointer_get(case["stimulus"], binding["source_path"])
        if observed != binding["canonical_value"]:
            raise AssertionError(
                f"{case['norm_id']}: konsumierter Wert {binding['source_path']} weicht ab"
            )
        trace.append(
            {
                "name": binding["source_path"].rsplit("/", 1)[-1],
                "stimulus_json_pointer": binding["source_path"],
                "consumer": binding["consumer"],
                "canonical_value": observed,
                "canonical_value_sha256": hashlib.sha256(canonical_lf(observed)).hexdigest(),
                "consumption_proof": binding["decision_boundary"],
            }
        )
    return trace


def validate_intent_consumption_fingerprint(case: dict[str, Any]) -> list[dict[str, Any]]:
    """Prueft die zusaetzliche, erwartungsneutrale Writer-Verbrauchsbindung."""
    fingerprint = case.get("act_writer_consumption_fingerprint")
    if fingerprint is None:
        return []
    canonical = canonical_lf(fingerprint)
    if canonical.decode("ascii") != case["act_writer_consumption_fingerprint_canonical"]:
        raise AssertionError(f"{case['norm_id']}: Writer-Verbrauchsbindung weicht ab")
    if hashlib.sha256(canonical).hexdigest() != case[
        "act_writer_consumption_fingerprint_sha256"
    ]:
        raise AssertionError(f"{case['norm_id']}: Writer-Verbrauchsbindung-sha256 weicht ab")
    trace: list[dict[str, Any]] = []
    previous: tuple[str, str, str] | None = None
    for binding in fingerprint["components"]:
        order_key = (
            binding["norm_id"],
            binding["component_name"],
            binding["source_json_path"],
        )
        if previous is not None and order_key <= previous:
            raise AssertionError(f"{case['norm_id']}: Writer-Komponenten nicht kanonisch sortiert")
        previous = order_key
        prefix = "/stimulus/"
        source = binding["source_json_path"]
        if not source.startswith(prefix):
            raise AssertionError(f"{case['norm_id']}: Writer-Quelle liegt nicht in stimulus")
        pointer = "/" + source[len(prefix):]
        observed = _pointer_get(case["stimulus"], pointer)
        if observed != binding["canonical_consumed_value"] or type(observed) is not type(
            binding["canonical_consumed_value"]
        ):
            raise AssertionError(
                f"{case['norm_id']}: Writer-Wert {binding['component_name']} weicht ab"
            )
        declared = binding["declared_type"]
        if declared == "string" and type(observed) is not str:
            raise AssertionError(f"{case['norm_id']}: Writer-Typ {source} ist nicht string")
        if declared == "integer" and type(observed) is not int:
            raise AssertionError(f"{case['norm_id']}: Writer-Typ {source} ist nicht integer")
        trace.append(
            {
                "component_name": binding["component_name"],
                "source_json_path": source,
                "consumer_symbol": binding["consumer_symbol"],
                "canonical_consumed_value": observed,
                "consumption_evidence": binding["consumption_evidence"],
            }
        )
    return trace


def validate_intent_relations(case: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    """Validiert Decision-, RetryIntent-, Store- und Reportrelationen roh."""
    proof = actual["norm_predicate_runtime"]["intent_relational_proof"]
    retry_bytes = bytes.fromhex(proof["retry_intent_bytes_hex"])
    checks = {
        "activation_id_bound": proof["activation_id"] == case["stimulus"]["activation_id"],
        "at_bound": proof["at"] == case["stimulus"]["at"],
        "actor_validation_preserved": proof["validated_actor"]
        == case["stimulus"]["plan_actor"],
        "decision_id_canonical": proof["decision_id"]
        == proof["decision_canonical_sha256"],
        "retry_bytes_hash": hashlib.sha256(retry_bytes).hexdigest()
        == proof["retry_intent_sha256"],
        "store_address": proof["store_address"] == proof["retry_intent_sha256"],
        "store_bytes": proof["store_bytes_sha256"] == proof["retry_intent_sha256"]
        and proof["store_bytes_equal_retry_intent_bytes"] is True,
        "reported_intent": proof["reported_intent_sha256"]
        == proof["retry_intent_sha256"],
    }
    failed = sorted(name for name, value in checks.items() if not value)
    if failed:
        raise AssertionError(
            f"{case['norm_id']}: relationale Intentpruefung scheitert: {','.join(failed)}"
        )
    return checks


class _Stream(io.StringIO):
    def __init__(self, text: str = "", *, tty: bool) -> None:
        super().__init__(text)
        self._tty = tty
        self.flush_count = 0
        self.read_count = 0
        self.consumed_lines: list[str] = []

    def isatty(self) -> bool:
        return self._tty

    def flush(self) -> None:
        self.flush_count += 1
        super().flush()

    def readline(self, *args: Any, **kwargs: Any) -> str:
        self.read_count += 1
        value = super().readline(*args, **kwargs)
        self.consumed_lines.append(value.encode("ascii").hex())
        return value


def _tree_snapshot(root: Path) -> dict[str, str]:
    if not root.exists():
        return {}
    snapshot: dict[str, str] = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        snapshot[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def _event_snapshot(journal_path: Path) -> tuple[list[str], list[list[str]]]:
    if not journal_path.exists():
        return [], []
    events = list(Journal(journal_path))
    return [event.kind for event in events], [sorted(event.payload) for event in events]


def _workspace(tmp_path: Path, fixture_id: str) -> tuple[Workspace, Journal]:
    ws = Workspace(tmp_path / fixture_id / "workspace", Profile.load(PROFILE))
    ws.ensure()
    ws.bind_graph_initially()
    return ws, Journal(ws.journal_path)


def _normalise_return(value: Any) -> Any:
    if isinstance(value, bytes):
        return {"bytes_sha256": hashlib.sha256(value).hexdigest(), "bytes": len(value)}
    if isinstance(value, (tuple, list)):
        return [_normalise_return(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalise_return(child) for key, child in value.items()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if hasattr(value, "to_json"):
        return value.to_json()
    if hasattr(value, "object") and callable(value.object):
        return value.object()
    if hasattr(value, "__dict__"):
        return {key: _normalise_return(child) for key, child in value.__dict__.items()}
    return type(value).__name__


def _normalise_paths(value: Any, ws: Workspace) -> Any:
    """Entfernt nur den zufaelligen pytest-Temporaerpfad aus Messwerten."""
    replacements = (
        (str(ws.root.parent / "input.srt"), "{source}"),
        (str(ws.root), "{root}"),
    )
    if isinstance(value, str):
        for actual, stable in replacements:
            value = value.replace(actual, stable)
        return value
    if isinstance(value, list):
        return [_normalise_paths(item, ws) for item in value]
    if isinstance(value, dict):
        return {key: _normalise_paths(child, ws) for key, child in value.items()}
    return value


def _observe_call(
    case: dict[str, Any],
    tmp_path: Path,
    monkeypatch: Any,
    call: Callable[[Workspace, Journal], Any],
    *,
    tty: bool | None = None,
    confirm: bool | None = None,
) -> dict[str, Any]:
    ws, journal = _workspace(tmp_path, case["fixture_id"])
    stimulus = case["stimulus"]
    for event in stimulus.get("journal_setup", []):
        journal.append(
            event["kind"],
            dict(event["payload"]),
            record_id=event.get("record_id"),
        )
    before_tree = _tree_snapshot(ws.root)
    before_events, before_fields = _event_snapshot(ws.journal_path)
    fsync_fds: list[int] = []

    def measured_fsync(fd: int) -> None:
        fsync_fds.append(fd)
        ORIGINAL_FSYNC(fd)

    monkeypatch.setattr(os, "fsync", measured_fsync)
    stdin = _Stream(stimulus.get("input_text", ""), tty=bool(tty))
    stdout = _Stream(tty=bool(tty))
    stderr = _Stream(tty=bool(tty))
    monkeypatch.setattr(sys, "stdin", stdin)
    returned: Any = None
    exception_type: str | None = None
    exception_message: str | None = None
    process_exit_code: int | None = None
    try:
        with redirect_stdout(stdout), redirect_stderr(stderr):
            returned = call(ws, journal)
    except BaseException as exc:
        exception_type = type(exc).__name__
        exception_message = str(exc)
        if isinstance(exc, SystemExit) and isinstance(exc.code, int):
            process_exit_code = exc.code
    after_tree = _tree_snapshot(ws.root)
    after_events, after_fields = _event_snapshot(ws.journal_path)
    before_objects = {key for key in before_tree if "/objects/" in f"/{key}"}
    after_objects = {key for key in after_tree if "/objects/" in f"/{key}"}
    report = _normalise_paths(returned.to_json(), ws) if isinstance(returned, Report) else None
    flattened = {
        "status": report["status"] if report else None,
        "reason": report["reason"] if report else None,
        "reason_code": report["reason_code"] if report else None,
        "changed": report["changed"] if report else None,
        "next": report["next"] if report else None,
        "details": report["details"] if report else None,
        "source_data_touched": report["source_data_touched"] if report else None,
        "operation_result": report["details"].get("operation_result") if report else None,
        "local_write_state": report["details"].get("local_write_state") if report else None,
    }
    return {
        "entrypoint": case["entrypoint"],
        "return_type": type(returned).__name__ if returned is not None else None,
        "return_value": _normalise_paths(_normalise_return(returned), ws),
        "exception_type": exception_type,
        "exception_message": exception_message,
        "stdout": _normalise_paths(stdout.getvalue(), ws),
        "stderr": _normalise_paths(stderr.getvalue(), ws),
        "exit_code": report["exit_code"] if report is not None else process_exit_code,
        "report": report,
        "journal_before": before_events,
        "journal_after": after_events,
        "journal_delta": len(after_events) - len(before_events),
        "store_before": sorted(before_objects),
        "store_after": sorted(after_objects),
        "store_delta": len(after_objects) - len(before_objects),
        "event_sequence": after_events[len(before_events) :],
        "event_field_sets": after_fields[len(before_fields) :],
        "bindings": {"graph": ws.running_graph_sha256(), "root": "{root}"},
        "lock_before": any(path.endswith(".lock") for path in before_tree),
        "lock_after": any(path.endswith(".lock") for path in after_tree),
        "lock": {
            "before": any(path.endswith(".lock") for path in before_tree),
            "after": any(path.endswith(".lock") for path in after_tree),
        },
        "fsync_count": len(fsync_fds),
        "replay": report.get("details", {}).get("matrix_state") if report else None,
        "restart": None,
        "tty": tty,
        "non_tty": None if tty is None else not tty,
        "confirm": confirm,
        "input_bytes_sequence": list(stdin.consumed_lines),
        "input_read_count": stdin.read_count,
        "prompt_count": stderr.getvalue().count("[b] Bestaetigen / [a] Abbrechen\n"),
        "visible_stream_flush_count": stderr.flush_count,
        **flattened,
    }


def _event_call(
    stimulus: dict[str, Any], runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(_ws: Workspace, _journal: Journal) -> str:
        if runtime["norm_id"] == "E10-03":
            payload = stimulus["payload"]
            runtime["observed_pre_call_state"] = {
                "field_path": "/call_payload/fulltext_origin",
                "field_present": "fulltext_origin" in payload,
                "field_value": payload.get("fulltext_origin"),
                "field_value_type": type(payload["fulltext_origin"]).__name__
                if "fulltext_origin" in payload
                else "MISSING",
                "measurement": "dict-membership on exact payload immediately before check_payload",
            }
        _before_product_call(stimulus, runtime, "ohpipe.domain.events.check_payload")
        check_payload(stimulus["event_kind"], stimulus["payload"], stimulus["record_id"])
        return "accepted"

    return call


def _registry_call(
    stimulus: dict[str, Any], runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(_ws: Workspace, _journal: Journal) -> Any:
        registry = InstanceRegistry()
        outputs: list[Any] = []
        for operation in stimulus["operations"]:
            name = operation["name"]
            if name == "register":
                _before_product_call(
                    stimulus, runtime, "ohpipe.domain.instance.InstanceRegistry.register"
                )
                outputs.append(registry.register(dict(operation["payload"])))
            elif name == "retire":
                _before_product_call(
                    stimulus, runtime, "ohpipe.domain.instance.InstanceRegistry.retire"
                )
                outputs.append(registry.retire(dict(operation["payload"])))
            elif name == "get":
                _before_product_call(
                    stimulus, runtime, "ohpipe.domain.instance.InstanceRegistry.get"
                )
                outputs.append(registry.get(operation["coder_id"], active=operation["active"]))
            elif name == "active_humans":
                if runtime["norm_id"] == "ACT-01":
                    active = [
                        item.coder_id
                        for item in registry._instances.values()
                        if not item.retired and item.source == "mensch"
                    ]
                    runtime["observed_pre_call_state"] = {
                        "active_human_count": len(active),
                        "active_human_coder_ids": sorted(active),
                        "registry_entry_count": len(registry._instances),
                        "measurement": "same InstanceRegistry._instances immediately before active_humans",
                    }
                _before_product_call(
                    stimulus, runtime, "ohpipe.domain.instance.InstanceRegistry.active_humans"
                )
                outputs.append(registry.active_humans())
            else:
                raise AssertionError(f"unbekannte Registryoperation {name!r}")
        return outputs

    return call


def _decision_call(
    stimulus: dict[str, Any], runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(_ws: Workspace, _journal: Journal) -> Any:
        marker = ConfirmationMarker(
            record_id=stimulus["record_id"],
            projection_version=stimulus["projection_version"],
            revision_sha256=stimulus["revision_sha256"],
        )
        if stimulus["projection"] == "marker_bytes":
            _before_product_call(
                stimulus, runtime, "ohpipe.domain.confirmation.ConfirmationMarker.bytes"
            )
            return marker.bytes
        payload = dict(stimulus["decision_payload_items"])
        if runtime["norm_id"] == "DEC-01":
            runtime["observed_pre_call_state"] = {
                "field_path": "/call_payload/subject_sha256",
                "field_present": "subject_sha256" in payload,
                "field_value": payload.get("subject_sha256"),
                "field_value_type": type(payload["subject_sha256"]).__name__
                if "subject_sha256" in payload
                else "MISSING",
                "payload_field_count": len(payload),
                "measurement": "dict-membership on exact decision payload immediately before check_payload",
            }
        _before_product_call(stimulus, runtime, "ohpipe.domain.events.check_payload")
        check_payload(
            stimulus["event_kind"],
            payload,
            stimulus["record_id"],
        )
        return "accepted"

    return call


def _iso_call(stimulus: dict[str, Any]) -> Callable[[Workspace, Journal], Any]:
    def call(_ws: Workspace, _journal: Journal) -> Any:
        runtime = stimulus["_norm_runtime"]
        _before_product_call(
            stimulus, runtime, "ohpipe.domain.iso6393.parse_iso6393_snapshot"
        )
        return parse_iso6393_snapshot(
            bytes.fromhex(stimulus["raw_hex"]),
            release_id=stimulus["release_id"],
            reference=stimulus["reference"],
        )

    return call


def _token_call(
    stimulus: dict[str, Any], runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(_ws: Workspace, _journal: Journal) -> Any:
        if stimulus["validator"] == "label":
            _before_product_call(stimulus, runtime, "ohpipe.domain.token.validate_label")
            return validate_label(stimulus["value"])
        if stimulus["validator"] == "model_value":
            _before_product_call(
                stimulus, runtime, "ohpipe.domain.token.validate_model_value"
            )
            return validate_model_value(stimulus["value"], field=stimulus["field"])
        if runtime["norm_id"] == "TOK-01":
            value = stimulus["value"]
            non_ascii = [
                {"index": index, "codepoint": f"U+{ord(character):04X}", "value": character}
                for index, character in enumerate(value)
                if ord(character) > 127
            ]
            runtime["observed_pre_call_state"] = {
                "field": stimulus["field"],
                "value_json_path": "/stimulus/value",
                "value": value,
                "non_ascii_codepoints": non_ascii,
                "measurement": "Unicode codepoint scan immediately before validate_token",
            }
        _before_product_call(stimulus, runtime, "ohpipe.domain.token.validate_token")
        return validate_token(stimulus["value"], field=stimulus["field"])

    return call


def _token_table_call(
    stimulus: dict[str, Any], runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(_ws: Workspace, _journal: Journal) -> Any:
        copied_ranges = deepcopy(_DEFAULT_IGNORABLE_RANGES)
        _before_product_call(
            stimulus, runtime, "ohpipe.domain.token.is_default_ignorable_15_1"
        )
        character = stimulus["probe"]
        return {
            "bound_table": [list(item) for item in copied_ranges],
            "probe": character,
            "probe_is_default_ignorable": is_default_ignorable_15_1(character),
        }

    return call


def _actor_replay_call(
    stimulus: dict[str, Any], runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(_ws: Workspace, _journal: Journal) -> Any:
        marker = ConfirmationMarker(
            record_id=stimulus["record_id"],
            projection_version=stimulus["projection_version"],
            revision_sha256=stimulus["revision_sha256"],
        )
        decision = ConfirmationDecision.create(
            marker=marker,
            actor=stimulus["actor"],
            fulltext_origin="from_segments",
            fulltext_receipt="b" * 64,
            iso6393_release="iso.2025",
            iso6393_vocabulary_sha256="c" * 64,
            iso6393_snapshot_receipt="d" * 64,
        )
        event = SimpleNamespace(
            seq=stimulus["sequence"],
            at=decision.at,
            kind="decision.recorded",
            record_id=stimulus["record_id"],
            payload=decision.object(),
        )
        _before_product_call(stimulus, runtime, "ohpipe.application.replay.replay")
        return replay([event])

    return call


def _actor_writer_call(
    stimulus: dict[str, Any], runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(ws: Workspace, journal: Journal) -> Any:
        marker = ConfirmationMarker(
            record_id=stimulus["record_id"],
            projection_version=stimulus["projection_version"],
            revision_sha256=stimulus["revision_sha256"],
        )
        decision = ConfirmationDecision(
            marker=marker,
            actor=validate_token(stimulus["plan_actor"], field="actor"),
            fulltext_origin=stimulus["fulltext_origin"],
            fulltext_receipt=stimulus["fulltext_receipt"],
            iso6393_release=stimulus["iso6393_release"],
            iso6393_vocabulary_sha256=stimulus["iso6393_vocabulary_sha256"],
            iso6393_snapshot_receipt=stimulus["iso6393_snapshot_receipt"],
            activation_id=stimulus["activation_id"],
            at=stimulus["at"],
        )
        plan = ConfirmPlan(
            marker,
            decision,
            stimulus["actor_state_sha256"],
            stimulus["actor_event_digest"],
        )
        _before_product_call(
            stimulus, runtime, "ohpipe.application.confirmation.write_confirmation"
        )
        report = write_confirmation(ws, journal, plan)
        reported_intent = report.details["intent_sha256"]
        store_bytes = (ws.objects / reported_intent).read_bytes()
        retry_intent = RetryIntent.from_mapping(json.loads(store_bytes))
        retry_bytes = retry_intent.bytes
        runtime["intent_relational_proof"] = {
            "activation_id": decision.activation_id,
            "at": decision.at,
            "validated_actor": decision.actor,
            "decision_id": decision.decision_id,
            "decision_canonical_sha256": hashlib.sha256(
                canonical_json_bytes(decision.object_without_id())
            ).hexdigest(),
            "retry_intent_bytes_hex": retry_bytes.hex(),
            "retry_intent_sha256": retry_intent.sha256,
            "store_address": reported_intent,
            "store_bytes_sha256": hashlib.sha256(store_bytes).hexdigest(),
            "store_bytes_equal_retry_intent_bytes": store_bytes == retry_bytes,
            "reported_intent_sha256": reported_intent,
        }
        return report

    return call


def _language_call(
    stimulus: dict[str, Any], runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(_ws: Workspace, _journal: Journal) -> Any:
        draft = build_srt_draft(bytes.fromhex(stimulus["srt_hex"]))
        vocabulary = parse_iso6393_snapshot(
            bytes.fromhex(stimulus["iso_hex"]),
            release_id=stimulus["release_id"],
            reference=stimulus["reference"],
        )
        mapping = (
            stimulus["mapping"]
            .replace("{segment_sha256}", draft.segments[0].sha256)
            .encode("ascii")
        )
        if runtime["norm_id"] in {"LNG-02", "LNG-03"}:
            lines = mapping.decode("ascii").splitlines()
            runtime["observed_pre_call_state"] = {
                "draft_segment_count": len(draft.segments),
                "mapping_data_row_count": max(len(lines) - 1, 0),
                "mapping_header": lines[0] if lines else None,
                "mapping_bytes_sha256": hashlib.sha256(mapping).hexdigest(),
                "measurement": "draft.segments and encoded mapping rows immediately before parse_mapping",
            }
        _before_product_call(
            stimulus, runtime, "ohpipe.domain.language_assignment.parse_mapping"
        )
        return parse_mapping(mapping, draft, vocabulary)

    return call


def _recovery_call(
    stimulus: dict[str, Any], runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(_ws: Workspace, _journal: Journal) -> Any:
        trace = stimulus["trace"]
        _before_product_call(
            stimulus, runtime, "ohpipe.application.operation_recovery.recovery_report"
        )
        return recovery_report(
            OperationTrace(
                intent_present=trace["intent_present"],
                intent_valid=trace["intent_valid"],
                causal_prestate_equal=trace["causal_prestate_equal"],
                expected_effects=tuple(trace["expected_effects"]),
                actual_effects=tuple(trace["observed_effects"]),
            ),
            retry_command=stimulus["retry_command"],
        )

    return call


def _cli_call(
    stimulus: dict[str, Any], monkeypatch: Any, runtime: dict[str, Any]
) -> Callable[[Workspace, Journal], Any]:
    def call(ws: Workspace, journal: Journal) -> Any:
        source_path = ws.root.parent / "input.srt"
        if "source_hex" in stimulus:
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(bytes.fromhex(stimulus["source_hex"]))
        argv = [
            token.replace("{root}", str(ws.root)).replace("{source}", str(source_path))
            for token in stimulus["argv"]
        ]
        if runtime["norm_id"] in {"UX-01", "UX-02", "UX-15"}:
            coder_index = argv.index("register") + 1
            coder_id = argv[coder_index]
            runtime["observed_pre_call_state"] = {
                "argv": [
                    token.replace(str(ws.root), "{root}").replace(str(source_path), "{source}")
                    for token in argv
                ],
                "action": "instance_register",
                "confirm_flag_present": "--confirm" in argv,
                "coder_id_json_path": f"/stimulus/argv/{coder_index}",
                "coder_id": coder_id,
                "coder_id_non_ascii_codepoints": [
                    f"U+{ord(character):04X}" for character in coder_id if ord(character) > 127
                ],
                "required_arguments_present": all(
                    token in argv for token in ("--source", "--label", "--reference")
                ),
                "measurement": "resolved argv immediately before ohpipe.cli.main.main",
            }
        captured_reports: list[Report] = []

        def measured_emit(report: Report, as_json: bool = False, stream: Any = None) -> int:
            captured_reports.append(report)
            return ORIGINAL_REPORT_EMIT(report, as_json=as_json, stream=stream)

        monkeypatch.setattr(Report, "emit", measured_emit)
        _before_product_call(stimulus, runtime, "ohpipe.cli.main.main")
        exit_code = cli_main(argv)
        if not captured_reports:
            return {"exit_code": exit_code, "report": None}
        report = captured_reports[-1]
        if exit_code != report.exit_code:
            raise AssertionError("CLI-Rueckgabe und wirklich emittierter Report widersprechen sich")
        return report

    return call


def exercise_case(
    case: dict[str, Any],
    tmp_path: Path,
    monkeypatch: Any,
    *,
    validate_artifact: bool = True,
) -> dict[str, Any]:
    """Fuehrt den im Artefakt explizit bezeichneten Produktweg aus."""
    consumption_trace = validate_fingerprints(case) if validate_artifact else []
    intent_consumption_trace = (
        validate_intent_consumption_fingerprint(case) if validate_artifact else []
    )
    stimulus = case["stimulus"]
    runtime: dict[str, Any] = {
        "norm_id": case["norm_id"],
        "expected_entrypoint": case["entrypoint"],
        "norm_predicate_proof": case["norm_predicate_proof"],
        "intent_consumption_trace": intent_consumption_trace,
    }
    operation = stimulus["operation"]
    if operation == "event_contract":
        call = _event_call(stimulus, runtime)
    elif operation in {"registry_contract", "actor_contract"}:
        call = _registry_call(stimulus, runtime)
    elif operation == "decision_contract":
        call = _decision_call(stimulus, runtime)
    elif operation == "iso_contract":
        stimulus["_norm_runtime"] = runtime
        call = _iso_call(stimulus)
    elif operation == "token_contract":
        call = _token_call(stimulus, runtime)
    elif operation == "token_table_contract":
        call = _token_table_call(stimulus, runtime)
    elif operation == "language_contract":
        call = _language_call(stimulus, runtime)
    elif operation == "recovery_contract":
        call = _recovery_call(stimulus, runtime)
    elif operation in {"cli", "act_cli_contract"}:
        call = _cli_call(stimulus, monkeypatch, runtime)
    elif operation == "act_replay_contract":
        call = _actor_replay_call(stimulus, runtime)
    elif operation == "act_writer_contract":
        call = _actor_writer_call(stimulus, runtime)
    else:
        raise AssertionError(f"unbekannte stimulus.operation {operation!r}")
    actual = _observe_call(
        case,
        tmp_path,
        monkeypatch,
        call,
        tty=stimulus.get("tty"),
        confirm=stimulus.get("confirm"),
    )
    if case["norm_id"] in {"UX-01", "UX-15"}:
        runtime["post_call_state"] = {
            "preview_reached": actual["stderr"].startswith("B3B-VORSCHAU "),
            "abort_action_observed": (
                actual["reason_code"] == "ACTION_B3B_USER_ABORTED"
                and actual["input_bytes_sequence"] == ["610a"]
                and actual["input_read_count"] == 1
            ),
            "reason_code": actual["reason_code"],
            "changed": actual["changed"],
        }
    elif case["norm_id"] == "UX-02":
        runtime["post_call_state"] = {
            "validation_error_reached": bool(
                actual["exception_type"]
                or actual["reason_code"] in {"STOP_PAYLOAD_REJECTED", "STOP_B3B_INVARIANT"}
                or "ASCII" in (actual["reason"] or "")
                or "Token" in (actual["reason"] or "")
            ),
            "reason_code": actual["reason_code"],
            "exception_type": actual["exception_type"],
            "reason": actual["reason"],
            "changed": actual["changed"],
        }
    stimulus.pop("_norm_runtime", None)
    actual.update(
        consumption_trace=consumption_trace,
        effective_consumption_fingerprint_sha256=case[
            "effective_consumption_fingerprint_sha256"
        ],
        expected_result_facets_fingerprint_sha256=case[
            "expected_result_facets_fingerprint_sha256"
        ],
        entrypoint_reached=(
            runtime.get("observed_entrypoint") == case["entrypoint"]
            and runtime.get("entrypoint_call_count", 0) >= 1
        ),
        norm_predicate_runtime=runtime,
    )
    return actual


def evaluate_norm_predicate(case: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    """Wertet nur den fachlich entscheidenden, am Aufrufrand gemessenen Zustand aus."""
    proof = case["norm_predicate_proof"]
    runtime = actual["norm_predicate_runtime"]
    state = runtime["observed_pre_call_state"]
    kind = proof["predicate_kind"]
    if kind in {"required_field_absent", "marker_field_absent"}:
        operands = {"field_present": state["field_present"]}
        satisfied = state["field_present"] is False
    elif kind == "active_human_count_zero":
        operands = {"active_human_count": state["active_human_count"]}
        satisfied = state["active_human_count"] == 0
    elif kind == "preview_aborted":
        operands = {
            "required_arguments_present": state["required_arguments_present"],
            "confirm_flag_present": state["confirm_flag_present"],
            "preview_reached": runtime["post_call_state"]["preview_reached"],
            "abort_action_observed": runtime["post_call_state"]["abort_action_observed"],
        }
        satisfied = (
            state["required_arguments_present"] is True
            and state["confirm_flag_present"] is False
            and runtime["post_call_state"]["preview_reached"] is True
            and runtime["post_call_state"]["abort_action_observed"] is True
        )
    elif kind == "preview_validation_error":
        operands = {
            "non_ascii_codepoints": state["coder_id_non_ascii_codepoints"],
            "validation_error_reached": runtime["post_call_state"]["validation_error_reached"],
        }
        satisfied = (
            bool(state["coder_id_non_ascii_codepoints"])
            and runtime["post_call_state"]["validation_error_reached"]
        )
    elif kind == "coder_id_contains_non_ascii":
        operands = {"non_ascii_codepoints": state["non_ascii_codepoints"]}
        satisfied = bool(state["non_ascii_codepoints"])
    elif kind == "mapping_rows_segment_count_minus_one":
        operands = {
            "draft_segment_count": state["draft_segment_count"],
            "mapping_data_row_count": state["mapping_data_row_count"],
        }
        satisfied = state["mapping_data_row_count"] == state["draft_segment_count"] - 1
    elif kind == "mapping_rows_segment_count_plus_one":
        operands = {
            "draft_segment_count": state["draft_segment_count"],
            "mapping_data_row_count": state["mapping_data_row_count"],
        }
        satisfied = state["mapping_data_row_count"] == state["draft_segment_count"] + 1
    elif kind == "consumed_target_exact":
        operands = {
            "json_path": state["json_path"],
            "canonical_value": state["canonical_value"],
            "canonical_value_sha256": state["canonical_value_sha256"],
            "value_type": state["value_type"],
        }
        target = proof["consumed_target"]
        satisfied = (
            state["json_path"] == target["json_path"]
            and state["canonical_value"] == target["canonical_value"]
            and state["canonical_value_sha256"] == target["canonical_value_sha256"]
            and state["value_type"] == target["value_type"]
        )
    else:
        raise AssertionError(f"unbekannte Praedikatsart {kind!r}")
    return {
        "predicate_kind": kind,
        "comparison_rule": proof["predicate_derivation"]["comparison_rule"],
        "operands": operands,
        "predicate_satisfied": bool(satisfied),
    }


def validate_norm_predicate(case: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    proof = case["norm_predicate_proof"]
    runtime = actual["norm_predicate_runtime"]
    evaluation = evaluate_norm_predicate(case, actual)
    if runtime["observed_pre_call_state"] != proof["observed_pre_call_state"]:
        raise AssertionError(f"{case['norm_id']}: gemessener Vorzustand weicht vom Beleg ab")
    if evaluation != proof["predicate_derivation"]:
        raise AssertionError(f"{case['norm_id']}: Praedikatsableitung weicht vom Beleg ab")
    if proof["predicate_satisfied"] is not True or not evaluation["predicate_satisfied"]:
        raise AssertionError(f"{case['norm_id']}: Normpraedikat ist nicht erfuellt")
    if proof["entrypoint_identity"] != actual["entrypoint"]:
        raise AssertionError(f"{case['norm_id']}: Eintrittspunkt weicht ab")
    if proof["entrypoint_reached"] is not True or actual["entrypoint_reached"] is not True:
        raise AssertionError(f"{case['norm_id']}: Eintrittspunkt wurde nicht erreicht")
    return evaluation


def compare_all(
    actual: dict[str, Any], expected: dict[str, Any], selectors: list[str]
) -> list[dict[str, Any]]:
    differences: list[dict[str, Any]] = []
    for field_path in sorted(selectors):
        expected_present, expected_value = _selector_get(expected, field_path)
        actual_present, actual_value = _selector_get(actual, field_path)
        if expected_present and actual_present and expected_value == actual_value:
            continue
        differences.append(
            {
                "field_path": field_path,
                "expected_present": expected_present,
                "actual_present": actual_present,
                "expected": expected_value,
                "actual": actual_value,
                "expected_type": type(expected_value).__name__ if expected_present else "MISSING",
                "actual_type": type(actual_value).__name__ if actual_present else "MISSING",
                "comparison_rule": "exact-json-value-and-type",
            }
        )
    return differences


def assert_expected(actual: dict[str, Any], expected: dict[str, Any], selectors: list[str]) -> None:
    differences = compare_all(actual, expected, selectors)
    if differences:
        raise AssertionError(
            json.dumps(differences, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        )


def assert_case(case: dict[str, Any], tmp_path: Path, monkeypatch: Any) -> None:
    if (
        hashlib.sha256(canonical_case_binding(case["stimulus"])).hexdigest()
        != case["stimulus_sha256"]
    ):
        raise AssertionError("stimulus_sha256 weicht ab")
    if (
        hashlib.sha256(canonical_case_binding(case["expected"])).hexdigest()
        != case["expected_sha256"]
    ):
        raise AssertionError("expected_sha256 weicht ab")
    actual = exercise_case(case, tmp_path, monkeypatch)
    differences = compare_all(actual, case["expected"], case["asserted_output_fields"])
    measurement = {
        "norm_id": case["norm_id"],
        "norm_text_sha256": case["norm_text_sha256"],
        "effective_consumption_fingerprint_sha256": case[
            "effective_consumption_fingerprint_sha256"
        ],
        "effective_consumption_fingerprint_canonical": case[
            "effective_consumption_fingerprint_canonical"
        ],
        "expected_result_facets_fingerprint_sha256": case[
            "expected_result_facets_fingerprint_sha256"
        ],
        "expected_result_facets_fingerprint_canonical": case[
            "expected_result_facets_fingerprint_canonical"
        ],
        "entrypoint_reached": actual["entrypoint"],
        "actual": actual,
        "expected": case["expected"],
        "differences": differences,
        "rc": 1 if differences else 0,
        "verdict": "ROT" if differences else "GRUEN",
    }
    print(
        "B3B_ROT_RESULT "
        + json.dumps(measurement, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    )
    if differences:
        raise AssertionError(
            json.dumps(differences, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        )
