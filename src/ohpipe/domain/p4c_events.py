"""P4c-Metadaten: geschlossene Rollen, keine Register- oder Positionsinhalte."""

from ohpipe.domain import manual_context

from .decision import SHA256_RE, parse_aware_iso
from .manual_pseudonymisation import OPAQUE
from .token import validate_token
from ..registry_store import REGISTRY, RESOLUTION, FINAL, REPORT, GATE, need, validate_ref
from ..protected_store import ProtectionError

POLICY = "pseudonymisation.policy"
BASE = {
    "transcript.revision",
    "transcript.confirmed",
    "pii.spans",
    "transcript.pseudonymised.draft",
    "pseudonymisation.cases",
    POLICY,
}
FINAL_INPUTS = BASE | {REGISTRY, RESOLUTION}
REVIEW_INPUTS = FINAL_INPUTS | {FINAL, REPORT}
PHASES = {"resolve": {RESOLUTION}, "finalise": {FINAL, REPORT}, "review": {GATE}}


def basis(view, phase):
    required = (
        BASE if phase == "resolve" else FINAL_INPUTS if phase == "finalise" else REVIEW_INPUTS
    )
    out = {}
    for role in required:
        if role in view.graph.artifacts:
            f = view.facts.get(role)
            if not f or role not in view.have:
                raise ValueError("P4c-Eingabe nicht aktuell")
            out[role] = [f.sha256, f.epoch]
        else:
            pair = view.sources.get(role)
            if not pair or not pair[0]:
                raise ValueError("P4c-Quellbindung fehlt")
            out[role] = list(pair)
    return out


def check(kind, p, record):
    def sha(s):
        need(isinstance(s, str) and SHA256_RE.fullmatch(s))

    try:
        need(isinstance(p, dict) and type(p["v"]) is int and p["v"] == 1)
        if kind in ("p4c.init.prepared", "p4c.initialised"):
            need(record is None and set(p) == {"v", "ref", "at"})
            validate_ref(p["ref"])
            need(
                p["ref"]["role"] == REGISTRY
                and p["ref"]["aad"]["version"] == 1
                and p["ref"]["aad"]["parent"] is None
            )
            need(parse_aware_iso(p["at"]) is not None)
            return
        need(manual_context.record(record))
        if kind in ("p4c.completed", "p4c.aborted"):
            need(set(p) == {"v", "prepared_sha256"})
            sha(p["prepared_sha256"])
            return
        need(
            kind == "p4c.prepared"
            and set(p)
            == set(
                [
                    "v",
                    "phase",
                    "operation",
                    "actor",
                    "actor_state",
                    "at",
                    "basis",
                    "registry_before",
                    "registry_after",
                    "refs",
                    "marker",
                ]
            )
        )
        phase = p["phase"]
        need(
            phase in PHASES and isinstance(p["operation"], str) and OPAQUE.fullmatch(p["operation"])
        )
        validate_token(p["actor"], field="actor")
        sha(p["actor_state"])
        need(parse_aware_iso(p["at"]) is not None)
        required = (
            BASE if phase == "resolve" else FINAL_INPUTS if phase == "finalise" else REVIEW_INPUTS
        )
        need(isinstance(p["basis"], dict) and set(p["basis"]) == required)
        for pair in p["basis"].values():
            need(isinstance(pair, list) and len(pair) == 2 and type(pair[1]) is int and pair[1] > 0)
            sha(pair[0])
        for k in ("registry_before", "registry_after"):
            validate_ref(p[k])
            need(p[k]["role"] == REGISTRY)
        b, a = p["registry_before"], p["registry_after"]
        need(a["aad"]["registry_id"] == b["aad"]["registry_id"])
        if a != b:
            need(
                phase == "finalise"
                and a["aad"]["parent"] == b["sha256"]
                and a["aad"]["version"] == b["aad"]["version"] + 1
                and a["aad"]["operation"] == p["operation"]
            )
        need(
            isinstance(p["refs"], dict)
            and set(p["refs"]) == (set() if phase == "review" else PHASES[phase])
        )
        for role, ref in p["refs"].items():
            validate_ref(ref)
            need(
                ref["role"] == role
                and ref["aad"]["record"] == record
                and ref["aad"]["operation"] == p["operation"]
            )
            need(
                all(
                    ref["aad"][k] == a["aad"][k]
                    for k in ("workspace", "profile", "graph", "registry_id", "key_id")
                )
            )
        if phase == "review":
            m = p["marker"]
            need(
                isinstance(m, dict)
                and set(m)
                == set(
                    [
                        "domain",
                        "v",
                        "record",
                        "profile",
                        "graph",
                        "operation",
                        "actor",
                        "actor_state",
                        "at",
                        "basis",
                        "volltext_gelesen",
                        "counts",
                    ]
                )
            )
            need(m["domain"] == "ohpipe:p4c:confirmation" and type(m["v"]) is int and m["v"] == 1)
            need(
                m["record"] == record
                and manual_context.record(record, m["profile"])
                and m["graph"] == a["aad"]["graph"]
            )
            need(m["volltext_gelesen"] is True and m["basis"] == p["basis"])
            need(
                isinstance(m["counts"], dict)
                and set(m["counts"]) == {"total", "worked", "open", "excluded", "added"}
            )
            need(
                all(type(n) is int and n >= 0 for n in m["counts"].values())
                and m["counts"]["open"] == 0
            )
            need(all(m[k] == p[k] for k in ("operation", "actor", "actor_state", "at")))
        else:
            need(p["marker"] is None)
    except (ProtectionError, ValueError, KeyError, TypeError):
        raise ValueError("Ungültiger P4c-Metadatenvertrag") from None
