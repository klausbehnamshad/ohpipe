"""Measure real confirmation intent relations from a valid synthetic snapshot."""

from dataclasses import replace
import hashlib
import json
import os
import shutil

import ohpipe.cli.main as cli
from ohpipe.application.confirmation import write_confirmation
from ohpipe.application.instance_registry import plan_register, write_instance_plan
from ohpipe.domain.operation import RetryIntent, canonical_json_bytes
from ohpipe.journal import Journal
from ohpipe.project import Workspace

from . import test_b3b_ux as helpers


def prepared_observer(case, tmp_path, monkeypatch):
    """Keep fixed actor/activation/time stimuli, but use actual state bindings."""
    key = os.urandom(32)
    with monkeypatch.context() as patch:
        patch.setattr(helpers, "Journal", lambda path: Journal(path, key=key))
        seed = helpers._prepare_confirmation(tmp_path / "prepared")
    journal = Journal(seed.journal_path, key=key)
    actor = case["stimulus"]["plan_actor"]
    write_instance_plan(
        seed,
        journal,
        plan_register(
            list(journal),
            actor,
            source="mensch",
            label="Synthetic Intent Actor",
            reference="synthetic.intent",
        ),
    )
    argv = helpers._confirmation_argv(seed)
    argv[-1] = actor
    args = cli.build_parser().parse_args(argv)
    seed_plan, _ = cli._transcript_confirmation_plan(seed, list(journal), args)

    def observe(stimulus_case, target):
        shutil.copytree(seed.root, target)
        ws = Workspace(target, seed.profile)
        journal = Journal(ws.journal_path, key=key)
        stimulus = stimulus_case["stimulus"]
        plan = replace(
            seed_plan,
            decision=replace(
                seed_plan.decision, activation_id=stimulus["activation_id"], at=stimulus["at"]
            ),
        )
        report = write_confirmation(ws, journal, plan)
        assert report.reason_code == "READY_B3B_WRITTEN"
        reported = report.details["intent_sha256"]
        with ws.store().open_verified(reported) as handle:
            stored = handle.read()
        retry = RetryIntent.from_mapping(json.loads(stored))
        decision = next(
            e.payload for e in reversed(journal.verified_events()) if e.kind == "decision.recorded"
        )
        assert decision == plan.decision.object()
        without_id = {k: v for k, v in decision.items() if k != "decision_id"}
        proof = {
            "activation_id": decision["activation_id"],
            "at": decision["at"],
            "validated_actor": decision["actor"],
            "decision_id": decision["decision_id"],
            "decision_canonical_sha256": hashlib.sha256(
                canonical_json_bytes(without_id)
            ).hexdigest(),
            "retry_intent_bytes_hex": retry.bytes.hex(),
            "retry_intent_sha256": retry.sha256,
            "store_address": reported,
            "store_bytes_sha256": hashlib.sha256(stored).hexdigest(),
            "store_bytes_equal_retry_intent_bytes": stored == retry.bytes,
            "reported_intent_sha256": reported,
        }
        return {"norm_predicate_runtime": {"intent_relational_proof": proof}}

    return observe
