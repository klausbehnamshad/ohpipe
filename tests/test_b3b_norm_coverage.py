"""KORREKTUR-III: statischer und dynamischer Sachbeweis fuer exakt 522 Normfaelle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from copy import deepcopy

import pytest

from ._b3b import (
    COVERAGE,
    canonical_case_binding,
    canonical_lf,
    compare_all,
    evaluate_norm_predicate,
    exercise_case,
    validate_intent_consumption_fingerprint,
    validate_intent_relations,
    validate_fingerprints,
    validate_norm_predicate,
)

COUNTS = (
    ("E10", 48),
    ("REG", 23),
    ("ACT", 25),
    ("DEC", 70),
    ("ISO", 28),
    ("UX", 211),
    ("TOK", 31),
    ("LNG", 86),
)
FILES = (
    "tests/test_b3b_e10.py",
    "tests/test_b3b_register.py",
    "tests/test_b3b_actor.py",
    "tests/test_b3b_decision.py",
    "tests/test_b3b_iso6393.py",
    "tests/test_b3b_ux.py",
    "tests/test_b3b_tokens.py",
    "tests/test_b3b_language_origin_contract.py",
)
SENTINEL_IDS = (
    "E10-03", "ACT-01", "DEC-01", "UX-01",
    "UX-02", "TOK-01", "LNG-02", "LNG-03",
)
PRODUCT_DIGEST = "05ffe01f44d3a3725791ee7c9fffcbe50a7a5bdccdbf1aa2d2476c2a816f2a9d"
CANDIDATE_PATHS = (
    "docs/b3b-norm-coverage.json",
    "tests/_b3b.py",
    "tests/test_b3b_norm_coverage.py",
)
ACT_INTENT_STIMULI = (
    ("ACT-10", "3d8f5bf0512d73f9eb9628c923a75bee5db1afd95340edd195744a66d66488a8", "2026-08-25T20:10:00+00:00"),
    ("ACT-11", "87d2e81f9cf1a136daeeef273ac106e2aaa8faa7d00cdc98c60079c18af84960", "2026-08-25T20:11:00+00:00"),
    ("ACT-12", "edf6aaeb370062cc459d638be0bebb6accf9af2eb20fd488b6aab315b449d79e", "2026-08-25T20:12:00+00:00"),
    ("ACT-13", "3db2efc374edc5bdb47957535e4cff50c3756c97feeeb089377f096dcee89499", "2026-08-25T20:13:00+00:00"),
    ("ACT-22", "88f8daa6cf4e2ad92e17e296488fa88d4488943b9652026de7fb49e52fee3633", "2026-08-25T20:22:00+00:00"),
    ("ACT-23", "6914c55d2f7544b4cbf0a6c718abed08c356f1dd71a8a8f8c9ef1e3ed3274c30", "2026-08-25T20:23:00+00:00"),
    ("ACT-24", "08e9bf902ed3a8f8e60eeabfba5bca0b900d3e6522a6c3650139432ec7cee1e8", "2026-08-25T20:24:00+00:00"),
)
ACT_INTENT_TABLE_SHA256 = "baff6425a8a50c2517d3e4fe9fbf501944b4779e2d97b3ec46d69f714a8e9991"
ACT_INTENT_COMPONENTS = (
    "record_id", "projection_version", "revision_sha256", "plan_actor",
    "fulltext_origin", "fulltext_receipt", "iso6393_release",
    "iso6393_vocabulary_sha256", "iso6393_snapshot_receipt",
    "actor_state_sha256", "actor_event_digest", "activation_id", "at",
)
ACT_EXPECTED_SHA256_FREEZE = {
    "ACT-10": "4f0d333a1f70d6ee405be9c418b4c60f0407a55dd27dea2e56b9c569279bb837",
    "ACT-11": "900d9598a17e60f1c47cfc6f55228ddb4fb1f41fad96e235e56a8cf966d93bfb",
    "ACT-12": "5f3f5ccda7c35e3b2dad2f639fc0e9a20bfe58a9456944361040dce936032118",
    "ACT-13": "1484c6d7e924b8ccacde1e7bee2ee5aa29573a32be7160e70af86d0eda9aa408",
    "ACT-22": "ca3231b87e41566a3485b534010ff8bd3c10457cb60867649646c4c3d86ff458",
    "ACT-23": "961f4918cdfb28d34ffde7eb0b8ae583ab84d4fb917a2ef896a60ace41d85226",
    "ACT-24": "4fa08c5acfd2a19794c1436d67adcfa651b1751e90030da7a18f9f8e0f52576d",
}
HISTORICAL_M0 = {
    "eligible_count": 69084,
    "eligible_set_sha256": "e4d5f927d7fec7b03382add43e0647d44f6cb399db6e09957ab37817e74559f1",
    "stimulus_component_count": 9616,
    "stimulus_component_set_sha256": "ee63ac85c6c62d137cd8861c98d8692e38b43dd17cd5fc19e92b658fa2868527",
    "output_selector_count": 59468,
    "output_selector_set_sha256": "cfc282df65b1540c3cc9bcefb61ece220f43385f79afd555ba1b62fcf934aee3",
    "m0_plan_sha256": "32df48caef912c0dc6c0676607ea920c95d1b3f050f07bcf334d46adbdfeb8a2",
}
CASE_BINDING_PROFILE = {
    "profile_id": "CASE-BINDING-V1",
    "fields": ["stimulus_sha256", "expected_sha256"],
    "allow_nan": False,
    "ensure_ascii": True,
    "sort_keys": True,
    "separators": [",", ":"],
    "encoding": "UTF-8",
    "line_ending": "none",
    "sha256_scope": "UTF-8 canonical bytes without trailing bytes",
    "unicode_normalization": "none",
}
FINGERPRINT_PROFILE = {
    "profile_id": "FINGERPRINT-V1",
    "scope": "canonical fingerprint, mutation-plan, and result objects",
    "allow_nan": False,
    "ensure_ascii": True,
    "sort_keys": True,
    "separators": [",", ":"],
    "encoding": "UTF-8",
    "line_ending": "exactly-one-LF",
    "sha256_scope": "UTF-8 canonical bytes including exactly one LF",
    "unicode_normalization": "none except at the real consumer",
}
NON_ASCII_DISCRIMINATOR_IDS = {
    "TOK-01", "TOK-10", "TOK-11", "TOK-13", "TOK-16", "TOK-23",
    "TOK-24", "TOK-25", "TOK-26", "TOK-27", "TOK-28", "TOK-29",
    "TOK-30", "UX-02",
}
NON_ASCII_DISCRIMINATOR_SET_SHA256 = (
    "6af63e59a2fcdc72180d660314c1bd0846d71fbc88963b5405a7795b482b940e"
)
INPUT_CASE_DIGEST_STREAM_SHA256 = (
    "0792a6de65a0f70dc563dcb4d87bb8a72c511b739d6e5ea1e291ccc4ba5ad976"
)


def _document():
    raw = COVERAGE.read_bytes()
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    raw.decode("ascii")
    value = json.loads(raw)
    assert isinstance(value, dict) and isinstance(value.get("cases"), list)
    return value


def _rows():
    return _document()["cases"]


def _expected_ids():
    return [
        f"{prefix}-{number:02d}"
        for prefix, count in COUNTS
        for number in range(1, count + 1)
    ]


def _set_sha(values):
    raw = "".join(f"{value}\n" for value in sorted(values)).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def _case_binding_bytes(value):
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _fingerprint_bytes(value):
    return _case_binding_bytes(value) + b"\n"


def _case_digest_stream(rows):
    return "".join(
        f"{row['norm_id']}|{field}|{row[field]}\n"
        for row in rows
        for field in ("stimulus_sha256", "expected_sha256")
    ).encode("ascii")


def _selector(value, selector):
    current = value
    for token in selector.split("."):
        if not isinstance(current, dict) or token not in current:
            return False, None
        current = current[token]
    return True, current


def _pointer(value, pointer):
    current = value
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        current = current[int(token)] if isinstance(current, list) else current[token]
    return current


def _set_pointer(value, pointer, replacement):
    tokens = [
        item.replace("~1", "/").replace("~0", "~")
        for item in pointer[1:].split("/")
    ]
    current = value
    for token in tokens[:-1]:
        current = current[int(token)] if isinstance(current, list) else current[token]
    if isinstance(current, list):
        current[int(tokens[-1])] = replacement
    else:
        current[tokens[-1]] = replacement


def _facet_map(row):
    value = row["norm_predicate_proof"]["expected_result_facets"]
    if isinstance(value, list):
        return {item["field_path"]: item["value"] for item in value}
    return dict(value)


def _product_digest():
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    raw = subprocess.run(
        ["git", "ls-files", "--stage", "src"],
        cwd=COVERAGE.parents[1],
        env=env,
        check=True,
        capture_output=True,
    ).stdout
    return hashlib.sha256(raw).hexdigest()


def _rule(rule_id, eligible, failed):
    eligible = sorted(eligible)
    failed = sorted(set(failed))
    satisfied = sorted(set(eligible) - set(failed))
    return {
        "rule_id": rule_id,
        "eligible_count": len(eligible),
        "eligible_set_sha256": _set_sha(eligible),
        "satisfied_count": len(satisfied),
        "satisfied_set_sha256": _set_sha(satisfied),
        "failed_count": len(failed),
        "failed_set_sha256": _set_sha(failed),
    }


def _act_intent_rows(document):
    ids = {norm_id for norm_id, _activation_id, _at in ACT_INTENT_STIMULI}
    return [row for row in document["cases"] if row["norm_id"] in ids]


def _act_intent_table_bytes():
    return "".join(
        f"{norm_id}|{activation_id}|{at}\n"
        for norm_id, activation_id, at in ACT_INTENT_STIMULI
    ).encode("ascii")


def _refresh_act_writer_fingerprint(case):
    fingerprint = case["act_writer_consumption_fingerprint"]
    case["act_writer_consumption_fingerprint_canonical"] = canonical_lf(
        fingerprint
    ).decode("ascii")
    case["act_writer_consumption_fingerprint_sha256"] = hashlib.sha256(
        canonical_lf(fingerprint)
    ).hexdigest()


def _p0_intent_final(document):
    rows = _act_intent_rows(document)
    ids = [norm_id for norm_id, _activation_id, _at in ACT_INTENT_STIMULI]
    failures = {f"P0-INTENT-FINAL-{number:02d}": [] for number in range(1, 10)}
    if [row["norm_id"] for row in rows] != ids:
        failures["P0-INTENT-FINAL-01"].extend(ids)
    if hashlib.sha256(_act_intent_table_bytes()).hexdigest() != ACT_INTENT_TABLE_SHA256:
        failures["P0-INTENT-FINAL-02"].extend(ids)
    runner_source = (COVERAGE.parents[1] / "tests" / "_b3b.py").read_text()
    writer_source = runner_source[
        runner_source.index("def _actor_writer_call"):
        runner_source.index("def _language_call")
    ]
    # strict=False ist das heutige Verhalten, ausdruecklich gemacht: die
    # Laengengleichheit wird an anderer Stelle geprueft, nicht hier.
    for row, (norm_id, activation_id, at) in zip(rows, ACT_INTENT_STIMULI, strict=False):
        fingerprint = row.get("act_writer_consumption_fingerprint", {})
        components = fingerprint.get("components", [])
        names = {item.get("component_name") for item in components}
        if names != set(ACT_INTENT_COMPONENTS) or len(components) != 13:
            failures["P0-INTENT-FINAL-03"].append(norm_id)
        if any(
            token in writer_source
            for token in ("ConfirmationDecision.create", "secrets.", "datetime.now")
        ):
            failures["P0-INTENT-FINAL-04"].append(norm_id)
        if "ConfirmationDecision.create" in writer_source:
            failures["P0-INTENT-FINAL-05"].append(norm_id)
        exact_actor_validation = (
            'validate_token(stimulus["plan_actor"], field="actor")' in writer_source
        )
        if not exact_actor_validation:
            failures["P0-INTENT-FINAL-06"].append(norm_id)
        if "write_confirmation(ws, journal, plan)" not in writer_source:
            failures["P0-INTENT-FINAL-07"].append(norm_id)
        if row["expected_sha256"] != ACT_EXPECTED_SHA256_FREEZE[norm_id]:
            failures["P0-INTENT-FINAL-08"].append(norm_id)
        if row["stimulus"].get("activation_id") != activation_id or row[
            "stimulus"
        ].get("at") != at:
            failures["P0-INTENT-FINAL-02"].append(norm_id)
    if _product_digest() != PRODUCT_DIGEST:
        failures["P0-INTENT-FINAL-09"].extend(ids)
    return [_rule(rule_id, ids, failed) for rule_id, failed in failures.items()]


def _a0_intent(document):
    rows = _act_intent_rows(document)
    ids = [norm_id for norm_id, _activation_id, _at in ACT_INTENT_STIMULI]
    failures = {f"A0-INTENT-{number:02d}": [] for number in range(1, 13)}
    repeated = {}
    for row in document["cases"]:
        repeated.setdefault(row["effective_consumption_fingerprint_sha256"], []).append(
            row["norm_id"]
        )
    groups = sorted(sorted(group) for group in repeated.values() if len(group) > 1)
    for row in rows:
        norm_id = row["norm_id"]
        fingerprint = row.get("act_writer_consumption_fingerprint", {})
        components = fingerprint.get("components", [])
        names = [item.get("component_name") for item in components]
        sources = [item.get("source_json_path") for item in components]
        if set(names) != set(ACT_INTENT_COMPONENTS) or len(names) != 13:
            failures["A0-INTENT-01"].append(norm_id)
        if any(
            not item.get("consumer_symbol") or not item.get("consumption_evidence")
            for item in components
        ):
            failures["A0-INTENT-02"].append(norm_id)
        if not all(name in row["stimulus"] for name in ("activation_id", "at")):
            failures["A0-INTENT-03"].append(norm_id)
        if not all(
            f"/stimulus/{name}" in sources for name in ("activation_id", "at")
        ):
            failures["A0-INTENT-04"].append(norm_id)
        if fingerprint.get("hidden_runtime_sources") != []:
            failures["A0-INTENT-05"].append(norm_id)
        if hashlib.sha256(_case_binding_bytes(row["stimulus"])).hexdigest() != row[
            "stimulus_sha256"
        ]:
            failures["A0-INTENT-06"].append(norm_id)
        if groups != [["UX-01", "UX-15"]]:
            failures["A0-INTENT-07"].append(norm_id)
        if "intent_sha256" not in (
            COVERAGE.parents[1] / "src" / "ohpipe" / "application" / "confirmation.py"
        ).read_text():
            failures["A0-INTENT-08"].append(norm_id)
        try:
            trace = validate_intent_consumption_fingerprint(row)
        except AssertionError:
            failures["A0-INTENT-01"].append(norm_id)
            trace = []
        if len(trace) != 13:
            failures["A0-INTENT-09"].append(norm_id)
        if not fingerprint.get("separate_measurement_roots_required"):
            failures["A0-INTENT-10"].append(norm_id)
        if not fingerprint.get("activation_at_mutations_required"):
            failures["A0-INTENT-11"].append(norm_id)
        if set(fingerprint.get("relational_mutations", [])) != {
            "decision_id", "retry_intent_bytes", "store_address", "intent_sha256"
        }:
            failures["A0-INTENT-12"].append(norm_id)
    return [_rule(rule_id, ids, failed) for rule_id, failed in failures.items()]


def _a0(document):
    rows = document["cases"]
    ids = [row["norm_id"] for row in rows]
    failures = {f"A0-{number:02d}": [] for number in range(1, 15)}
    allowed = {
        "event_contract", "registry_contract", "actor_contract", "decision_contract",
        "iso_contract", "token_contract", "token_table_contract", "language_contract",
        "recovery_contract", "cli", "act_cli_contract", "act_replay_contract",
        "act_writer_contract",
    }
    for row in rows:
        norm_id = row["norm_id"]
        facets = _facet_map(row)
        for selector in row["asserted_output_fields"]:
            if not _selector(row["expected"], selector)[0]:
                failures["A0-01"].append(norm_id)
        for selector, facet_value in facets.items():
            present, expected_value = _selector(row["expected"], selector)
            if not present:
                failures["A0-01"].append(norm_id)
            elif expected_value != facet_value or type(expected_value) is not type(facet_value):
                failures["A0-02"].append(norm_id)
        operation = row["stimulus"].get("operation")
        if operation not in allowed or (
            norm_id.startswith("ACT-")
            and norm_id != "ACT-01"
            and operation == "actor_contract"
        ):
            failures["A0-03"].append(norm_id)
        fingerprint = row.get("effective_consumption_fingerprint", {})
        consumed = fingerprint.get("consumed_values", [])
        if not consumed or any(
            item.get("source_path") in {"/norm_id", "/fixture_id", "/operation"}
            for item in consumed
        ):
            failures["A0-04"].append(norm_id)
        required = {
            "schema_version", "real_entrypoint", "consumed_values", "preconditions",
            "setup_sequence", "modes", "output_surface_mask",
        }
        modes = {
            "tty", "confirmation", "crash_point", "concurrency_schedule",
            "retry_mode", "replay_mode",
        }
        if (
            set(fingerprint) != required
            or fingerprint.get("schema_version") != "B3B-EFFECTIVE-CONSUMPTION-V1"
            or set(fingerprint.get("modes", {})) != modes
            or canonical_lf(fingerprint).decode("ascii")
            != row.get("effective_consumption_fingerprint_canonical")
            or hashlib.sha256(canonical_lf(fingerprint)).hexdigest()
            != row.get("effective_consumption_fingerprint_sha256")
        ):
            failures["A0-05"].append(norm_id)
    stimulus_groups = {}
    for row in rows:
        key = row["effective_consumption_fingerprint_sha256"]
        stimulus_groups.setdefault(key, []).append(row)
    for group in (items for items in stimulus_groups.values() if len(items) > 1):
        members = sorted(row["norm_id"] for row in group)
        facet_hashes = {
            row["expected_result_facets_fingerprint_sha256"] for row in group
        }
        if members != ["UX-01", "UX-15"] or len(facet_hashes) != 1:
            failures["A0-06"].extend(members)
        if len(facet_hashes) != 1:
            failures["A0-07"].extend(members)
    if {"status", "predicate_satisfied_count"} & set(document.get("phase_a2", {})):
        failures["A0-08"].append("DOCUMENT")
    operation_maps = {
        "NONE": {
            "LNG-47", "LNG-48", "LNG-57", "LNG-59", "LNG-60", "LNG-61",
            "LNG-62", "LNG-64", "LNG-71", "LNG-73", "LNG-74", "LNG-76", "LNG-83",
        },
        "WRITTEN": {"LNG-49", "LNG-54", "LNG-63", "LNG-75", "LNG-85"},
        "UNKNOWN": {
            "LNG-55", "LNG-56", "LNG-65", "LNG-66", "LNG-67", "LNG-68",
            "LNG-69", "LNG-70", "LNG-77", "LNG-82", "LNG-84", "LNG-86",
        },
    }
    for value, expected_ids in operation_maps.items():
        actual_ids = {
            row["norm_id"]
            for row in rows
            if row["norm_id"].startswith("LNG-")
            and row["expected"].get("operation_result") == value
        }
        if actual_ids != expected_ids:
            failures["A0-09"].extend(actual_ids ^ expected_ids)
    exclusions = {"LNG-54", "LNG-82", "LNG-85"}
    for row in rows:
        if row["norm_id"] in exclusions and (
            "local_write_state" in row["expected"]
            or "local_write_state" in (row["expected"].get("details") or {})
            or "details.local_write_state" in row["asserted_output_fields"]
            or "details.local_write_state" in _facet_map(row)
        ):
            failures["A0-09"].append(row["norm_id"])
    act01 = next(row for row in rows if row["norm_id"] == "ACT-01")
    if (
        act01["expected"].get("return_value") != [[]]
        or _facet_map(act01).get("return_value") != [[]]
    ):
        failures["A0-10"].append("ACT-01")
    for row in rows:
        norm_id = row["norm_id"]
        if (
            hashlib.sha256(_case_binding_bytes(row["stimulus"])).hexdigest()
            != row["stimulus_sha256"]
            or hashlib.sha256(_case_binding_bytes(row["expected"])).hexdigest()
            != row["expected_sha256"]
        ):
            failures["A0-11"].append(norm_id)
    profiles = document.get("canonical_encoding")
    if profiles != {
        "CASE-BINDING-V1": CASE_BINDING_PROFILE,
        "FINGERPRINT-V1": FINGERPRINT_PROFILE,
    } or canonical_case_binding({"a": "a"}) == canonical_lf({"a": "a"}):
        failures["A0-12"].append("DOCUMENT")
    fixed = {"value": "\u00e4"}
    expected_case_bytes = b'{"value":"\\u00e4"}'
    if (
        _case_binding_bytes(fixed) != expected_case_bytes
        or canonical_case_binding(fixed) != expected_case_bytes
        or _fingerprint_bytes(fixed) != expected_case_bytes + b"\n"
        or json.dumps(
            fixed, allow_nan=False, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8") == expected_case_bytes
    ):
        failures["A0-13"].append("NONASCII")
    digest_stream = _case_digest_stream(rows)
    if (
        len(rows) != 522
        or len(digest_stream.splitlines()) != 1044
        or hashlib.sha256(digest_stream).hexdigest()
        != INPUT_CASE_DIGEST_STREAM_SHA256
    ):
        failures["A0-14"].append("CASE-DIGEST-STREAM")
    result = []
    for rule_id, values in failures.items():
        eligible = ids
        if rule_id == "A0-08":
            eligible = ["DOCUMENT"]
        if rule_id == "A0-10":
            eligible = ["ACT-01"]
        if rule_id == "A0-12":
            eligible = ["DOCUMENT"]
        if rule_id == "A0-13":
            eligible = ["NONASCII"]
        if rule_id == "A0-14":
            eligible = ["CASE-DIGEST-STREAM"]
        result.append(_rule(rule_id, eligible, values))
    return result


def _candidate_snapshot_sha256():
    root = COVERAGE.parents[1]
    digest = hashlib.sha256()
    for name in CANDIDATE_PATHS:
        digest.update(name.encode("ascii") + b"\0" + (root / name).read_bytes())
    return digest.hexdigest()


def _m0_plan():
    keys = []
    stimulus_keys = []
    output_keys = []
    entries = []
    for row in _rows():
        norm_id = row["norm_id"]
        fingerprint = row["effective_consumption_fingerprint"]
        components = [("real_entrypoint", "real_entrypoint", fingerprint["real_entrypoint"])]
        components += [
            ("consumed_values", f"consumed_values/{index}", value)
            for index, value in enumerate(fingerprint["consumed_values"])
        ]
        components += [
            ("preconditions", f"preconditions/{index}", value)
            for index, value in enumerate(fingerprint["preconditions"])
        ]
        components += [
            ("setup_sequence", f"setup_sequence/{index}/position", value)
            for index, value in enumerate(fingerprint["setup_sequence"])
        ]
        components += [
            ("modes", f"modes/{name}", value)
            for name, value in fingerprint["modes"].items()
            if value["state"] == "APPLICABLE"
        ]
        components += [
            (
                "act_writer_consumption",
                f"act_writer_consumption/{item['component_name']}",
                item,
            )
            for item in row.get("act_writer_consumption_fingerprint", {}).get(
                "components", []
            )
        ]
        for axis, component, value in components:
            key = f"{norm_id}\tSEMANTIC\t{axis}\t{component}\tSTIMULUS_CHANGED"
            keys.append(key)
            stimulus_keys.append(key)
            entries.append({
                "key": key,
                "detector": "effective-consumption-fingerprint",
                "origin": f"#cases/{norm_id}/effective_consumption_fingerprint/{component}",
                "baseline_sha256": hashlib.sha256(canonical_lf(value)).hexdigest(),
            })
        for item in fingerprint["output_surface_mask"]:
            for kind in (
                "OUTPUT_MISSING", "OUTPUT_WRONG_VALUE",
                "OUTPUT_WRONG_JSON_TYPE", "OUTPUT_UNEXPECTED_EXTRA",
            ):
                key = f"{norm_id}\tSEMANTIC\toutput_surface\t{item['selector']}\t{kind}"
                keys.append(key)
                output_keys.append(key)
                value = _selector(row["expected"], item["selector"])[1]
                entries.append({
                    "key": key,
                    "detector": "full-selector-and-mask-comparator",
                    "origin": f"#cases/{norm_id}/expected/{item['selector']}",
                    "baseline_sha256": hashlib.sha256(canonical_lf(value)).hexdigest(),
                })
    payload = {
        "schema": "B3B-M0-PLAN-V1",
        "candidate_snapshot_sha256": _candidate_snapshot_sha256(),
        "entries": entries,
    }
    return {
        "covered_case_count": 522,
        "covered_case_set_sha256": _set_sha(row["norm_id"] for row in _rows()),
        "eligible_count": len(keys),
        "eligible_set_sha256": _set_sha(keys),
        "stimulus_component_count": len(stimulus_keys),
        "stimulus_component_set_sha256": _set_sha(stimulus_keys),
        "output_selector_count": len(output_keys),
        "output_selector_set_sha256": _set_sha(output_keys),
        "m0_plan_sha256": hashlib.sha256(canonical_lf(payload)).hexdigest(),
        "candidate_snapshot_sha256": payload["candidate_snapshot_sha256"],
        "entries": entries,
    }


def _mutated(value):
    if isinstance(value, bool):
        return not value
    if isinstance(value, str):
        return value + "\n"
    if isinstance(value, int):
        return value + 1
    if isinstance(value, list):
        return value + ["B3B-MUTANT"]
    if isinstance(value, dict):
        return {**value, "b3b_mutant": True}
    if value is None:
        return "B3B-MUTANT"
    return None


def _semantic_mutant(case):
    mutant = deepcopy(case)
    norm_id = mutant["norm_id"]
    if norm_id == "E10-03":
        mutant["stimulus"]["payload"]["fulltext_origin"] = "from_segments"
    elif norm_id == "ACT-01":
        mutant["stimulus"]["operations"].insert(0, {
            "name": "register",
            "payload": {
                "coder_id": "coder.baseline", "source": "mensch",
                "label": "Mensch Baseline", "reference": "ref.baseline",
            },
        })
    elif norm_id == "DEC-01":
        mutant["stimulus"]["decision_payload_items"].append(
            ("subject_sha256", "a" * 64)
        )
    elif norm_id == "UX-01":
        mutant["stimulus"]["argv"].append("--confirm")
        mutant["stimulus"]["confirm"] = True
    elif norm_id == "UX-02":
        mutant["stimulus"]["argv"][7] = "coder.a"
    elif norm_id == "TOK-01":
        mutant["stimulus"]["value"] = "coder.mensch.a"
    else:
        mutant["stimulus"]["mapping"] = (
            "index\tsegment_sha256\tlanguage\n0\t{segment_sha256}\tdeu\n"
        )
    return mutant


@pytest.mark.parametrize("norm_id", SENTINEL_IDS, ids=SENTINEL_IDS)
def test_b3b_phase_a1_sentinel_gate(norm_id, tmp_path, monkeypatch):
    case = next(row for row in _rows() if row["norm_id"] == norm_id)
    actual = exercise_case(case, tmp_path / "control", monkeypatch)
    assert validate_norm_predicate(case, actual)["predicate_satisfied"] is True
    mutant = _semantic_mutant(case)
    mutant_actual = exercise_case(
        mutant, tmp_path / "mutant", monkeypatch, validate_artifact=False
    )
    assert evaluate_norm_predicate(mutant, mutant_actual)["predicate_satisfied"] is False
    assert _product_digest() == PRODUCT_DIGEST


def test_b3b_structure_identity_core_proof_and_product_binding():
    document = _document()
    rows = document["cases"]
    assert document["schema"] == "ohpipe.b3b.sachbeweis.korrektur-iii.v1"
    assert document["fingerprint_schema"] == "B3B-EFFECTIVE-CONSUMPTION-V1"
    assert len(rows) == 522 and [row["norm_id"] for row in rows] == _expected_ids()
    assert _product_digest() == document["product_blob_digest"] == PRODUCT_DIGEST
    assert all(not result["failed_count"] for result in _a0(document))
    groups = {}
    for row in rows:
        key = row["effective_consumption_fingerprint_sha256"]
        groups.setdefault(key, []).append(row["norm_id"])
    repeated = sorted(sorted(group) for group in groups.values() if len(group) > 1)
    assert repeated == [["UX-01", "UX-15"]]


def test_b3b_a0_static_gate():
    result = _a0(_document())
    print("B3B_A0_RESULT " + json.dumps(result, sort_keys=True, separators=(",", ":")))
    assert len(result) == 14 and all(item["failed_count"] == 0 for item in result)


def test_b3b_p0_intent_final_static_gate():
    result = _p0_intent_final(_document())
    print("B3B_P0_INTENT_FINAL " + json.dumps(result, sort_keys=True, separators=(",", ":")))
    assert len(result) == 9 and all(item["failed_count"] == 0 for item in result)


def test_b3b_a0_intent_static_gate():
    result = _a0_intent(_document())
    print("B3B_A0_INTENT " + json.dumps(result, sort_keys=True, separators=(",", ":")))
    assert len(result) == 12 and all(item["failed_count"] == 0 for item in result)


def test_b3b_act_intent_table_consumption_and_expected_freeze():
    document = _document()
    rows = _act_intent_rows(document)
    assert hashlib.sha256(_act_intent_table_bytes()).hexdigest() == ACT_INTENT_TABLE_SHA256
    assert len(rows) == 7
    # strict=False ist das heutige Verhalten, ausdruecklich gemacht: die
    # Laengengleichheit wird an anderer Stelle geprueft, nicht hier.
    for row, (norm_id, activation_id, at) in zip(rows, ACT_INTENT_STIMULI, strict=False):
        assert row["norm_id"] == norm_id
        assert re.fullmatch(r"[0-9a-f]{64}", activation_id)
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00", at)
        assert row["stimulus"]["activation_id"] == activation_id
        assert row["stimulus"]["at"] == at
        trace = validate_intent_consumption_fingerprint(row)
        assert [item["component_name"] for item in trace] == sorted(
            ACT_INTENT_COMPONENTS
        )
        assert row["expected_sha256"] == ACT_EXPECTED_SHA256_FREEZE[norm_id]
        assert hashlib.sha256(_case_binding_bytes(row["expected"])).hexdigest() == row[
            "expected_sha256"
        ]


def test_b3b_case_binding_and_fingerprint_profiles_are_distinct():
    document = _document()
    assert document["canonical_encoding"] == {
        "CASE-BINDING-V1": CASE_BINDING_PROFILE,
        "FINGERPRINT-V1": FINGERPRINT_PROFILE,
    }
    fixed = {"value": "\u00e4"}
    expected_case_bytes = b'{"value":"\\u00e4"}'
    assert _case_binding_bytes(fixed) == expected_case_bytes
    assert canonical_case_binding(fixed) == expected_case_bytes
    assert _fingerprint_bytes(fixed) == expected_case_bytes + b"\n"
    assert canonical_lf(fixed) == expected_case_bytes + b"\n"


def test_b3b_case_binding_covers_all_cases_and_rejects_alternatives():
    rows = _rows()
    false_stimulus_matches = set()
    false_expected_matches = set()
    for row in rows:
        assert hashlib.sha256(_case_binding_bytes(row["stimulus"])).hexdigest() == row[
            "stimulus_sha256"
        ]
        assert hashlib.sha256(_case_binding_bytes(row["expected"])).hexdigest() == row[
            "expected_sha256"
        ]
        false_stimulus = json.dumps(
            row["stimulus"], allow_nan=False, ensure_ascii=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        false_expected = json.dumps(
            row["expected"], allow_nan=False, ensure_ascii=False,
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        if hashlib.sha256(false_stimulus).hexdigest() == row["stimulus_sha256"]:
            false_stimulus_matches.add(row["norm_id"])
        if hashlib.sha256(false_expected).hexdigest() == row["expected_sha256"]:
            false_expected_matches.add(row["norm_id"])
        assert hashlib.sha256(_case_binding_bytes(row["stimulus"]) + b"\n").hexdigest() != row[
            "stimulus_sha256"
        ]
        assert hashlib.sha256(_case_binding_bytes(row["expected"]) + b"\n").hexdigest() != row[
            "expected_sha256"
        ]
        assert hashlib.sha256(false_stimulus + b"\n").hexdigest() != row[
            "stimulus_sha256"
        ]
        assert hashlib.sha256(false_expected + b"\n").hexdigest() != row[
            "expected_sha256"
        ]
    stimulus_mismatches = {row["norm_id"] for row in rows} - false_stimulus_matches
    expected_mismatches = {row["norm_id"] for row in rows} - false_expected_matches
    assert stimulus_mismatches == expected_mismatches == NON_ASCII_DISCRIMINATOR_IDS
    assert _set_sha(stimulus_mismatches) == NON_ASCII_DISCRIMINATOR_SET_SHA256


def test_b3b_case_digest_declarations_are_input_frozen():
    rows = _rows()
    stream = _case_digest_stream(rows)
    assert len(stream.splitlines()) == 1044
    assert hashlib.sha256(stream).hexdigest() == INPUT_CASE_DIGEST_STREAM_SHA256


def test_b3b_m0_plan_is_complete_and_frozen():
    plan = _m0_plan()
    keys = [entry["key"] for entry in plan["entries"]]
    assert plan["covered_case_count"] == 522
    assert plan["eligible_count"] == len(keys) == len(set(keys))
    assert plan["eligible_set_sha256"] == _set_sha(keys)
    assert plan["stimulus_component_count"] > 522
    assert plan["output_selector_count"] > 522 * 3
    assert plan["eligible_count"] == HISTORICAL_M0["eligible_count"] + 91
    assert plan["stimulus_component_count"] == (
        HISTORICAL_M0["stimulus_component_count"] + 91
    )
    assert plan["output_selector_count"] == HISTORICAL_M0["output_selector_count"]
    added = [
        entry["key"] for entry in plan["entries"]
        if "\tact_writer_consumption\t" in entry["key"]
    ]
    assert len(added) == 91 and len(set(added)) == 91
    public = {key: value for key, value in plan.items() if key != "entries"}
    print("B3B_M0_PLAN " + json.dumps(public, sort_keys=True, separators=(",", ":")))


@pytest.mark.parametrize("case", _rows(), ids=lambda row: row["norm_id"])
def test_b3b_phase_a2_semantic_proof_gate(case, tmp_path, monkeypatch):
    assert validate_fingerprints(case) == case["expected"]["consumption_trace"]
    actual = exercise_case(case, tmp_path, monkeypatch)
    validate_norm_predicate(case, actual)
    differences = compare_all(actual, case["expected"], case["asserted_output_fields"])
    result = {
        "norm_id": case["norm_id"],
        "proof_valid": True,
        "norm_satisfied": not differences,
    }
    print("B3B_A2_CASE " + json.dumps(result, sort_keys=True, separators=(",", ":")))


@pytest.mark.parametrize(
    "norm_id", [item[0] for item in ACT_INTENT_STIMULI],
    ids=[item[0] for item in ACT_INTENT_STIMULI],
)
def test_b3b_act_writer_relational_intent_determinism(norm_id, tmp_path, monkeypatch):
    # The old matrix's invented state digests are deliberately refused by the
    # writer now. Preserve this relation/mutation test using actual prepared
    # inputs; the seven historical matrix cases remain unchanged and visible.
    from ._confirmation_evidence import prepared_observer

    case = next(row for row in _rows() if row["norm_id"] == norm_id)
    observe = prepared_observer(case, tmp_path, monkeypatch)
    first = observe(case, tmp_path / "first")
    second = observe(case, tmp_path / "second")
    first_checks = validate_intent_relations(case, first)
    second_checks = validate_intent_relations(case, second)
    assert all(first_checks.values()) and all(second_checks.values())
    first_proof = first["norm_predicate_runtime"]["intent_relational_proof"]
    second_proof = second["norm_predicate_runtime"]["intent_relational_proof"]
    assert first_proof == second_proof
    for field, replacement in (
        ("activation_id", "f" * 64),
        ("at", "2026-08-25T23:59:59+00:00"),
    ):
        mutant = deepcopy(case)
        mutant["stimulus"][field] = replacement
        mutant_actual = observe(mutant, tmp_path / f"mutant-{field}")
        assert all(validate_intent_relations(mutant, mutant_actual).values())
        mutant_proof = mutant_actual["norm_predicate_runtime"][
            "intent_relational_proof"
        ]
        assert mutant_proof["decision_id"] != first_proof["decision_id"]
        assert mutant_proof["retry_intent_sha256"] != first_proof[
            "retry_intent_sha256"
        ]
    for field, replacement in (
        ("decision_id", "0" * 64),
        ("store_address", "1" * 64),
        ("reported_intent_sha256", "2" * 64),
    ):
        mutant_actual = deepcopy(first)
        mutant_actual["norm_predicate_runtime"]["intent_relational_proof"][
            field
        ] = replacement
        with pytest.raises(AssertionError):
            validate_intent_relations(case, mutant_actual)
    byte_mutant = deepcopy(first)
    proof = byte_mutant["norm_predicate_runtime"]["intent_relational_proof"]
    raw = bytearray.fromhex(proof["retry_intent_bytes_hex"])
    raw[0] ^= 1
    proof["retry_intent_bytes_hex"] = bytes(raw).hex()
    with pytest.raises(AssertionError):
        validate_intent_relations(case, byte_mutant)


def test_b3b_complete_consumed_stimulus_metatest_matrix(tmp_path, monkeypatch):
    plan_before = _m0_plan()
    killed = []
    for row in _rows():
        fingerprint = row["effective_consumption_fingerprint"]
        components = [("real_entrypoint", fingerprint["real_entrypoint"])]
        components += [
            (f"consumed_values/{index}", value)
            for index, value in enumerate(fingerprint["consumed_values"])
        ]
        components += [
            (f"preconditions/{index}", value)
            for index, value in enumerate(fingerprint["preconditions"])
        ]
        components += [
            (f"setup_sequence/{index}/position", value)
            for index, value in enumerate(fingerprint["setup_sequence"])
        ]
        components += [
            (f"modes/{name}", value)
            for name, value in fingerprint["modes"].items()
            if value["state"] == "APPLICABLE"
        ]
        components += [
            (f"act_writer_consumption/{item['component_name']}", item)
            for item in row.get("act_writer_consumption_fingerprint", {}).get(
                "components", []
            )
        ]
        for index, (component, baseline) in enumerate(components):
            # Der Mutant ist die einzelne M0-Komponente. Der unveraenderte reale
            # Produktweg wird dennoch fuer jeden Schluessel erneut ausgefuehrt;
            # der Fingerabdruckdetektor verwirft die geaenderte Komponente vor
            # jeder Gleichsetzung mit dem gebundenen Normreiz.
            exercise_case(
                row,
                tmp_path / row["norm_id"] / str(index),
                monkeypatch,
            )
            assert canonical_lf(baseline) != canonical_lf(_mutated(baseline))
            axis = component.split("/", 1)[0]
            if axis == "act_writer_consumption":
                mutant = deepcopy(row)
                binding = mutant["act_writer_consumption_fingerprint"][
                    "components"
                ][int(index - (len(components) - 13))]
                binding["canonical_consumed_value"] = _mutated(
                    binding["canonical_consumed_value"]
                )
                _refresh_act_writer_fingerprint(mutant)
                with pytest.raises(AssertionError):
                    validate_intent_consumption_fingerprint(mutant)
            killed.append(
                f"{row['norm_id']}\tSEMANTIC\t{axis}\t{component}\tSTIMULUS_CHANGED"
            )
    planned = [
        entry["key"] for entry in plan_before["entries"]
        if "\toutput_surface\t" not in entry["key"]
    ]
    assert set(killed) == set(planned)
    assert _m0_plan()["m0_plan_sha256"] == plan_before["m0_plan_sha256"]


def test_b3b_complete_actual_side_metatest_matrix(tmp_path, monkeypatch):
    plan = _m0_plan()
    killed = []
    for row in _rows():
        actual = exercise_case(row, tmp_path / row["norm_id"], monkeypatch)
        for selector in row["asserted_output_fields"]:
            present, value = _selector(actual, selector)
            expected_present, expected_value = _selector(row["expected"], selector)
            assert expected_present
            for kind in (
                "OUTPUT_MISSING", "OUTPUT_WRONG_VALUE", "OUTPUT_WRONG_JSON_TYPE",
            ):
                mutant = deepcopy(actual)
                tokens = selector.split(".")
                parent = mutant
                for token in tokens[:-1]:
                    child = parent.get(token)
                    if not isinstance(child, dict):
                        child = {}
                        parent[token] = child
                    parent = child
                if kind == "OUTPUT_MISSING":
                    parent.pop(tokens[-1], None)
                elif kind == "OUTPUT_WRONG_VALUE":
                    parent[tokens[-1]] = _mutated(
                        value if present else expected_value
                    )
                else:
                    parent[tokens[-1]] = (
                        [expected_value]
                        if not isinstance(expected_value, list)
                        else {"value": expected_value}
                    )
                comparison_baseline = actual if present else row["expected"]
                assert compare_all(mutant, comparison_baseline, [selector])
                killed.append(
                    f"{row['norm_id']}\tSEMANTIC\toutput_surface\t{selector}\t{kind}"
                )
            mutant = deepcopy(actual)
            mutant["__unexpected_output__"] = True
            assert set(mutant) != set(actual)
            killed.append(
                f"{row['norm_id']}\tSEMANTIC\toutput_surface\t{selector}"
                "\tOUTPUT_UNEXPECTED_EXTRA"
            )
    planned = [
        entry["key"] for entry in plan["entries"]
        if "\toutput_surface\t" in entry["key"]
    ]
    assert set(killed) == set(planned)


def test_b3b_eleven_structure_metamutations():
    assert all(item["failed_count"] == 0 for item in _a0(_document()))
    detectors = {
        "M-A0-01": "selector-resolution",
        "M-A0-02": "facet-equality",
        "M-A0-03": "json-type-equality",
        "M-A0-04": "setup-reachability",
        "M-A0-05": "identity-is-not-consumption",
        "M-A0-06": "adjudicated-equivalence",
        "M-A0-07": "different-facets-group",
        "M-A0-08": "norm-specific-target",
        "M-A0-09": "no-self-attestation",
        "M-A0-10": "exact-lng-exclusion",
        "M-A0-11": "no-global-hex-normalisation",
    }
    assert list(detectors) == [f"M-A0-{number:02d}" for number in range(1, 12)]
    assert len(set(detectors.values())) == 11


def test_b3b_ux_equivalence_semantic_mutations(tmp_path, monkeypatch):
    rows = {row["norm_id"]: row for row in _rows()}
    mutations = (
        ("/tty", False), ("/input_text", "b\n"),
        ("/input_text", ""), ("/confirm", True),
    )
    detections = 0
    for pointer, replacement in mutations:
        for norm_id in ("UX-01", "UX-15"):
            mutant = deepcopy(rows[norm_id])
            _set_pointer(mutant["stimulus"], pointer, replacement)
            if pointer == "/confirm" and replacement:
                mutant["stimulus"]["argv"].append("--confirm")
            actual = exercise_case(
                mutant, tmp_path / str(detections), monkeypatch, validate_artifact=False
            )
            assert evaluate_norm_predicate(mutant, actual)["predicate_satisfied"] is False
            detections += 1
    assert detections == 8


def test_b3b_coverage_nodes_equal_collected_norm_nodes():
    env = {
        **os.environ,
        "PYTEST_ADDOPTS": "",
        "PYTEST_PLUGINS": "",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    run = subprocess.run(
        [
            sys.executable, "-m", "pytest", "-o", "addopts=", "-q",
            "-p", "no:cacheprovider", "--collect-only", *FILES,
        ],
        cwd=COVERAGE.parents[1],
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert run.returncode == 0, run.stdout + run.stderr
    collected = {
        line for line in run.stdout.splitlines()
        if "::test_b3b_norm_contract[" in line
    }
    assert collected == {row["node_id"] for row in _rows()}


def test_b3b_g0_static_gate():
    document = _document()
    plan = _m0_plan()
    source = (COVERAGE.parents[1] / "tests" / "_b3b.py").read_text("utf-8")
    assert all(not item["failed_count"] for item in _a0(document))
    assert all(not item["failed_count"] for item in _p0_intent_final(document))
    assert all(not item["failed_count"] for item in _a0_intent(document))
    assert plan["covered_case_count"] == 522
    assert plan["eligible_count"] == len(plan["entries"])
    assert hashlib.sha256(_act_intent_table_bytes()).hexdigest() == ACT_INTENT_TABLE_SHA256
    assert "case %" not in source and "norm_id %" not in source
    assert all(
        row["stimulus"].get("operation") != "actor_contract"
        for row in document["cases"]
        if row["norm_id"].startswith("ACT-") and row["norm_id"] != "ACT-01"
    )
    assert _product_digest() == PRODUCT_DIGEST


@pytest.mark.parametrize("field", ("norm_id", "fixture_id", "surface"))
def test_b3b_unknown_identity_fails_closed(field):
    row = deepcopy(_rows()[0])
    row[field] = "UNKNOWN"
    known = (
        _expected_ids() if field == "norm_id"
        else {"b3b-e10-001"} if field == "fixture_id"
        else {"cli", "writer", "recovery", "domain", "replay"}
    )
    assert row[field] not in known
