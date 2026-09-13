"""P4c: vollständige Resolution, stabile Vergabe und reiner finaler Renderer."""

from ohpipe.domain import manual_context

from copy import deepcopy
from dataclasses import replace
import hashlib
import hmac
import unicodedata

from . import manual_pseudonymisation as manual
from .pii import EntityType
from .revision_serialization import canonical_revision_bytes
from .transcript import TranscriptRevision
from ..protected_store import canonical, digest
from ..registry_store import need


def mention_digest(source, capsule):
    return digest(
        canonical(
            sorted(
                (s.mention_id, s.cue_index, s.start, s.end, s.entity_type.value)
                for s in manual.bound(source, capsule["spans"])
            )
        )
    )


def empty(registry_id, candidate_key_id, candidate_check):
    return dict(
        v=1,
        registry_id=registry_id,
        index_version="nfc-casefold-hmac-v1",
        candidate_key_id=candidate_key_id,
        candidate_check=candidate_check,
        entities={},
        counters={},
        aliases={},
        resolutions={},
    )


def validate_registry(reg):
    need(
        set(reg)
        == set(
            [
                "v",
                "registry_id",
                "index_version",
                "candidate_key_id",
                "candidate_check",
                "entities",
                "counters",
                "aliases",
                "resolutions",
            ]
        )
    )
    need(type(reg["v"]) is int and reg["v"] == 1 and reg["index_version"] == "nfc-casefold-hmac-v1")
    for k in ("registry_id", "candidate_key_id"):
        need(isinstance(reg[k], str) and manual.OPAQUE.fullmatch(reg[k]))
    need(all(isinstance(reg[k], dict) for k in ("entities", "counters", "aliases", "resolutions")))
    need(
        isinstance(reg["candidate_check"], str)
        and __import__("re").fullmatch("[0-9a-f]{64}", reg["candidate_check"])
    )
    types = {t.value for t in EntityType}
    labels = set()
    maxima = {}
    for eid, e in reg["entities"].items():
        need(isinstance(eid, str) and manual.OPAQUE.fullmatch(eid))
        need(set(e) == {"type", "pseudonym", "number"} and e["type"] in types)
        n = e["number"]
        need(n is None or type(n) is int and n > 0)
        need(e["pseudonym"] == (None if n is None else f"{e['type']}-{n:03d}"))
        if n is not None:
            need(e["pseudonym"] not in labels)
            labels.add(e["pseudonym"])
            maxima[e["type"]] = max(n, maxima.get(e["type"], 0))
    need(set(reg["counters"]) == set(maxima))
    need(all(type(n) is int and n == maxima[t] + 1 for t, n in reg["counters"].items()))
    for token, candidates in reg["aliases"].items():
        need(isinstance(token, str) and __import__("re").fullmatch("[0-9a-f]{64}", token))
        need(
            isinstance(candidates, list)
            and candidates == sorted(set(candidates))
            and bool(candidates)
        )
        need(all(e in reg["entities"] for e in candidates))
    for rid, ref in reg["resolutions"].items():
        from ..registry_store import validate_ref, RESOLUTION

        need(manual_context.record(rid))
        validate_ref(ref)
        need(
            ref["role"] == RESOLUTION
            and ref["aad"]["record"] == rid
            and ref["aad"]["registry_id"] == reg["registry_id"]
        )


def token(key, registry_id, typ, surface):
    return hmac.new(
        key,
        canonical(
            [
                "ohpipe:p4c:candidate:v1",
                registry_id,
                typ,
                unicodedata.normalize("NFC", surface).casefold(),
            ]
        ),
        hashlib.sha256,
    ).hexdigest()


def validate_resolution(source, capsule, policy, resolution, registry):
    mentions = manual.validate(source, capsule, policy)
    need(manual.counts(capsule)["open"] == 0)
    need(
        set(resolution) == set(["v", "registry_id", "source", "mention_set_sha256", "assignments"])
    )
    need(type(resolution["v"]) is int and resolution["v"] == 1)
    need(resolution["registry_id"] == registry["registry_id"])
    need(resolution["source"] == manual.source_contract(source))
    need(resolution["mention_set_sha256"] == mention_digest(source, capsule))
    by_id = {s.mention_id: s for s in mentions}
    need(
        isinstance(resolution["assignments"], dict) and set(resolution["assignments"]) == set(by_id)
    )
    planned = {}
    for mid, a in resolution["assignments"].items():
        need(set(a) == {"entity_id", "type", "action", "intent"})
        typ = by_id[mid].entity_type.value
        need(a["type"] == typ and a["action"] == policy[typ]["action"])
        eid = a["entity_id"]
        need(
            isinstance(eid, str)
            and manual.OPAQUE.fullmatch(eid)
            and a["intent"] in ("new", "reuse")
        )
        if eid in registry["entities"]:
            need(registry["entities"][eid]["type"] == typ)
        else:
            need(a["intent"] == "new")
        need(eid not in planned or planned[eid] == (typ, a["action"]))
        planned[eid] = (typ, a["action"])
    return mentions, planned


def allocate(source, capsule, policy, resolution, registry, candidate_key, resolution_ref, record):
    validate_registry(registry)
    mentions, planned = validate_resolution(source, capsule, policy, resolution, registry)
    updated = deepcopy(registry)
    for eid in sorted(planned):
        typ, action = planned[eid]
        if eid in updated["entities"]:
            need((updated["entities"][eid]["number"] is not None) == (action == "pseudonym"))
            continue
        n = updated["counters"].get(typ, 1) if action == "pseudonym" else None
        updated["entities"][eid] = dict(
            type=typ, number=n, pseudonym=None if n is None else f"{typ}-{n:03d}"
        )
        if n is not None:
            updated["counters"][typ] = n + 1
    for span in mentions:
        eid = resolution["assignments"][span.mention_id]["entity_id"]
        surface = source.segments[span.cue_index].text[span.start : span.end]
        key = token(candidate_key, registry["registry_id"], span.entity_type.value, surface)
        updated["aliases"][key] = sorted(set(updated["aliases"].get(key, [])) | {eid})
    # A01: unchanged confirmed resolution is not publication history.
    updated["resolutions"][record] = resolution_ref
    validate_registry(updated)
    return updated


def render(source, capsule, policy, resolution, registry):
    mentions, _ = validate_resolution(source, capsule, policy, resolution, registry)
    segments, entries, sums = [], [], {}
    for i, segment in enumerate(source.segments):
        cursor, position, chunks = 0, 0, []
        for s in sorted(mentions.for_cue(i), key=lambda x: x.start):
            prefix = segment.text[cursor : s.start]
            chunks.append(prefix)
            position += len(prefix)
            a = resolution["assignments"][s.mention_id]
            rule = policy[s.entity_type.value]
            action = a["action"]
            if action == "keep":
                value = segment.text[s.start : s.end]
            elif action == "remove":
                value = ""
            elif action == "coarsen":
                value = rule["value"]
            else:
                need(action == "pseudonym" and a["entity_id"] in registry["entities"])
                value = registry["entities"][a["entity_id"]]["pseudonym"]
                need(isinstance(value, str) and not value.endswith("?"))
            entries.append(
                dict(
                    mention_id=s.mention_id,
                    type=s.entity_type.value,
                    cue=i,
                    source=[s.start, s.end],
                    result=[position, position + len(value)],
                    action=action,
                    confirmed=True,
                )
            )
            key = s.entity_type.value + ":" + action
            sums[key] = sums.get(key, 0) + 1
            chunks.append(value)
            position += len(value)
            cursor = s.end
        chunks.append(segment.text[cursor:])
        segments.append(replace(segment, text="".join(chunks)))
    out = TranscriptRevision.from_segments(
        segments,
        projection_version=source.projection_version,
        profile_id=source.profile_id,
        source_kind=source.source_kind,
        source_sha256=source.source_sha256,
    )
    return canonical_revision_bytes(out), entries, sums


def candidate_check(key, registry_id):
    return hmac.new(
        key, canonical(["ohpipe:p4c:candidate-key-check:v1", registry_id]), hashlib.sha256
    ).hexdigest()
