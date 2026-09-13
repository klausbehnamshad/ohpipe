"""P4b: reine Positions-, Überlagerungs- und provisorische Renderverträge.

Dieses Modul hat keine Ablage und erzeugt keine Zufallskennungen. Alle hier
serialisierten Sitzungsdaten gehören ausschließlich in einen Schutzumschlag.
"""

from dataclasses import replace
import re

from .cue import CueDocument, CueFormat
from .pii import Span, SpanSet
from .revision_serialization import canonical_revision_bytes
from .transcript import TranscriptRevision

PROJECTION = "ohpipe:manual-cues:v1"
OPAQUE = re.compile(r"[0-9a-f]{32}\Z")


class ManualError(ValueError):
    """Meldungen enthalten keine abgelehnten Eingabewerte."""


def require(test):
    if not test:
        raise ManualError("Geschützter P4b-Datenvertrag verletzt")


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names.split()))


def projection(revision):
    canonical_revision_bytes(revision)
    require(revision.profile_id == "nfc-strict-v1")
    # Die Rahmenzeit ist nur eine Parserhülle, niemals Eingabe des Renderers.
    text = "WEBVTT\n\n" + "".join(
        f"{i}\n00:00:00.000 --> 00:00:01.000\n{s.text}\n\n" for i, s in enumerate(revision.segments)
    )
    document = CueDocument.parse(text, CueFormat.VTT)
    require(document.payloads() == tuple(s.text for s in revision.segments))
    return document


def source_contract(revision):
    doc = projection(revision)
    return {
        "revision_sha256": revision.sha256,
        "document_sha256": doc.sha256,
        "normalization": revision.profile_id,
        "revision_projection": revision.projection_version,
        "cue_projection": PROJECTION,
        "segment_indices": [s.index for s in revision.segments],
    }


def mark(revision, cue, start, end, entity_type):
    doc = projection(revision)
    require(type(cue) is int and 0 <= cue < len(doc.payloads()))
    import hashlib

    span = Span(
        hashlib.sha256(doc.payloads()[cue].encode()).hexdigest(),
        "codepoint",
        cue,
        start,
        end,
        entity_type,
        "human",
    )
    SpanSet(doc.sha256, (span,)).bind(doc)
    return span.to_json()


def bound(revision, spans):
    doc = projection(revision)
    parsed = tuple(Span.from_json(s) for s in spans)
    require(all(s.unit.value == "codepoint" and s.recogniser == "human" for s in parsed))
    return SpanSet(doc.sha256, parsed).bind(doc)


def validate(revision, capsule, policy):
    fields(capsule, "v source base overlay spans groups context")
    require(type(capsule["v"]) is int and capsule["v"] == 1)
    require(capsule["source"] == source_contract(revision))
    require(isinstance(capsule["context"], str) and len(capsule["context"]) <= 10000)
    require(isinstance(capsule["base"], list) and isinstance(capsule["overlay"], list))
    effective = {s.mention_id: raw for s, raw in _paired(revision, capsule["base"])}
    for change in capsule["overlay"]:
        fields(change, "old new")
        old, new = change["old"], change["new"]
        require(old is not None or new is not None)
        if old is not None:
            require(old in effective)
            del effective[old]
        if new is not None:
            pairs = _paired(revision, [new])
            require(pairs[0][0].mention_id not in effective)
            effective[pairs[0][0].mention_id] = new
    actual = {s.mention_id: raw for s, raw in _paired(revision, capsule["spans"])}
    require(actual == effective)
    mentions = bound(revision, capsule["spans"])
    by_id = {s.mention_id: s for s in mentions}
    require(isinstance(capsule["groups"], dict))
    assigned = []
    for gid, group in capsule["groups"].items():
        require(isinstance(gid, str) and OPAQUE.fullmatch(gid))
        fields(group, "type scope mentions state")
        require(group["state"] in ("OPEN", "RESOLVED", "DEFERRED"))
        require(isinstance(group["mentions"], list) and bool(group["mentions"]))
        require(group["type"] in policy)
        require(group["scope"] == policy[group["type"]].get("scope", "local"))
        for mid in group["mentions"]:
            require(mid in by_id and by_id[mid].entity_type.value == group["type"])
        assigned.extend(group["mentions"])
    require(len(assigned) == len(set(assigned)) and set(assigned) == set(by_id))
    return mentions


def _paired(revision, spans):
    require(isinstance(spans, list))
    # Persistierte Mengen sind bereits kanonisch: die bestehende Span-Bindung
    # darf identische Rohbefunde normalisieren, die Sitzung speichert jeden nur einmal.
    result = bound(revision, spans)
    require(len(result) == len(spans))
    originals = {}
    for raw in spans:
        s = next(iter(bound(revision, [raw])))
        originals[s.mention_id] = raw
    return [(s, originals[s.mention_id]) for s in result]


def render(revision, capsule, policy):
    mentions = validate(revision, capsule, policy)
    labels = {}
    counts = {}
    for gid in sorted(capsule["groups"]):
        g = capsule["groups"][gid]
        typ = g["type"]
        counts[typ] = counts.get(typ, 0) + 1
        for mid in g["mentions"]:
            labels[mid] = f"{typ}-{counts[typ]:03d}?"
    segments = []
    for i, segment in enumerate(revision.segments):
        text = segment.text
        for s in sorted(mentions.for_cue(i), key=lambda x: x.start, reverse=True):
            rule = policy[s.entity_type.value]
            action = rule["action"]
            if action == "keep":
                replacement = text[s.start : s.end]
            elif action == "remove":
                replacement = ""
            elif action == "coarsen":
                replacement = rule["value"]
            else:
                require(action == "pseudonym")
                replacement = labels[s.mention_id]
            text = text[: s.start] + replacement + text[s.end :]
        segments.append(replace(segment, text=text))
    output = TranscriptRevision.from_segments(
        segments,
        projection_version=revision.projection_version,
        profile_id=revision.profile_id,
        source_kind=revision.source_kind,
        source_sha256=revision.source_sha256,
    )
    return canonical_revision_bytes(output)


def counts(capsule):
    groups = capsule["groups"]
    return {
        "total": len(groups),
        "worked": sum(g["state"] != "OPEN" for g in groups.values()),
        "open": sum(g["state"] != "RESOLVED" for g in groups.values()),
        "excluded": sum(c["old"] is not None and c["new"] is None for c in capsule["overlay"]),
        "added": sum(c["old"] is None for c in capsule["overlay"]),
    }
