"""Geschlossene öffentliche Metadatenverträge, keine Sitzungsinhalte."""

from ohpipe.domain import manual_context

import re

from .decision import SHA256_RE
from .token import validate_token

ROLES = {
    "pii.mark": "pii.spans",
    "pseudonymise": "transcript.pseudonymised.draft",
    "pseudonymisation.cases": "pseudonymisation.cases",
}
POLICY = "pseudonymisation.policy"


def check(kind, p, record):
    from ..protected_store import ProtectionError, validate_ref

    def need(ok):
        if not ok:
            raise ValueError("Ungültiger P4b-Metadatenvertrag")

    def sha(value):
        need(isinstance(value, str) and SHA256_RE.fullmatch(value))

    try:
        need(manual_context.record(record))
        fields = {
            "p4b.policy": "v profile graph sha256",
            "p4b.checkpoint": "v ref basis actor actor_state previous",
            "p4b.prepared": "v ref plan basis actor actor_state checkpoint at",
            "p4b.completed": "v prepared_sha256",
        }[kind]
        need(
            isinstance(p, dict)
            and set(p) == set(fields.split())
            and type(p["v"]) is int
            and p["v"] == 1
        )
        if kind == "p4b.policy":
            need(manual_context.record(record, p["profile"]))
            sha(p["graph"])
            sha(p["sha256"])
        elif kind == "p4b.completed":
            sha(p["prepared_sha256"])
        else:
            validate_ref(p["ref"])
            need(p["ref"]["aad"]["record"] == record)
            phase = p["ref"]["aad"]["phase"]
            validate_token(p["actor"], field="actor")
            sha(p["actor_state"])
            need(isinstance(p["basis"], dict))
            allowed = {"transcript.confirmed", "transcript.revision", POLICY}
            if phase != "pii.mark":
                allowed.add("pii.spans")
            if phase == "pseudonymisation.cases":
                allowed.add("transcript.pseudonymised.draft")
            need(set(p["basis"]) == allowed)
            for pair in p["basis"].values():
                need(isinstance(pair, list) and len(pair) == 2)
                sha(pair[0])
                need(type(pair[1]) is int and pair[1] > 0)
            if kind == "p4b.checkpoint":
                need(p["ref"]["role"] == "editor" and phase != "pseudonymise")
                if p["previous"] is not None:
                    sha(p["previous"])
                need((p["previous"] is None) == (p["ref"]["aad"]["revision"] == 1))
            else:
                need(p["ref"]["role"] == ROLES[phase])
                validate_ref(p["plan"])
                need(p["plan"]["role"] == "plan")
                need(
                    all(
                        p["plan"]["aad"][k] == v
                        for k, v in p["ref"]["aad"].items()
                        if k != "object_id"
                    )
                )
                if phase != "pseudonymise":
                    sha(p["checkpoint"])
                else:
                    need(p["checkpoint"] is None)
                need(
                    isinstance(p["at"], str)
                    and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?\+00:00", p["at"])
                )
    except (KeyError, TypeError, ProtectionError):
        raise ValueError("Ungültiger P4b-Metadatenvertrag") from None
