"""SRT-Draft, Zuordnungsdatei und identitaetstragende Segmentbytes aus L1."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable

from ..adapters.input.srt import SrtParseError, parse_srt
from .iso6393 import IsoSnapshot
from .revision_serialization import PROJECTION_VERSION
from .transcript import Segment, TranscriptRevision

__all__ = [
    "DRAFT_PARSER_VERSION",
    "LanguageAssignment",
    "LanguageAssignmentError",
    "SrtDraft",
    "assign_languages",
    "build_srt_draft",
    "language_assigned_segments_bytes",
    "mapping_template_bytes",
    "parse_mapping",
]

DRAFT_PARSER_VERSION = "ohpipe-srt-draft-v1"
ASSIGNMENT_CODE_VERSION = "transcript-segment-language-assignment.v1"
MAPPING_HEADER = b"index\tsegment_sha256\tlanguage\n"


class LanguageAssignmentError(ValueError):
    pass


def _canonical(value: Any) -> bytes:
    def validate(item: Any) -> None:
        if isinstance(item, (bool, float)):
            raise LanguageAssignmentError("kanonisches JSON verbietet bool und float")
        if isinstance(item, str):
            if unicodedata.normalize("NFC", item) != item:
                raise LanguageAssignmentError("Zeichenkette muss bereits NFC sein")
            if any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise LanguageAssignmentError("Unicode-Surrogat im kanonischen Objekt")
        elif isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise LanguageAssignmentError("Objektschluessel muss Zeichenkette sein")
                validate(key)
                validate(child)
        elif isinstance(item, list):
            for child in item:
                validate(child)

    validate(value)
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


@dataclass(frozen=True)
class DraftSegment:
    index: int
    start_ms: int
    end_ms: int
    text: str
    speaker: str

    def object(self) -> dict[str, Any]:
        return {
            "domain": "transcript_srt_draft_segment",
            "v": 1,
            "index": self.index,
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "text": self.text,
            "speaker": self.speaker,
        }

    @property
    def bytes(self) -> bytes:
        return _canonical(self.object())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.bytes).hexdigest()


@dataclass(frozen=True)
class SrtDraft:
    raw_bytes: bytes
    segments: tuple[DraftSegment, ...]
    profile_id: str = "nfc-strict-v1"
    projection_version: str = PROJECTION_VERSION

    @property
    def srt_bytes_sha256(self) -> str:
        return hashlib.sha256(self.raw_bytes).hexdigest()

    def object(self) -> dict[str, Any]:
        return {
            "domain": "transcript_srt_draft",
            "v": 1,
            "srt_bytes_sha256": self.srt_bytes_sha256,
            "parser_version": DRAFT_PARSER_VERSION,
            "profile_id": self.profile_id,
            "projection_version": self.projection_version,
            "segments": [segment.object() for segment in self.segments],
        }

    @property
    def bytes(self) -> bytes:
        return _canonical(self.object())

    @property
    def draft_segments_sha256(self) -> str:
        return hashlib.sha256(self.bytes).hexdigest()


def build_srt_draft(raw: bytes) -> SrtDraft:
    try:
        text = raw.decode("utf-8-sig")
        parsed = parse_srt(text, strict=True)
    except (UnicodeDecodeError, SrtParseError) as exc:
        raise LanguageAssignmentError(f"SRT-Draft ungueltig: {exc}") from exc
    draft: list[DraftSegment] = []
    for index, segment in enumerate(parsed):
        if segment.speaker is None:
            raise LanguageAssignmentError(f"Segment {index}: speaker fehlt ausser language")
        if segment.start_ms is None or segment.end_ms is None:
            raise LanguageAssignmentError(f"Segment {index}: Zeitgrenze fehlt")
        draft.append(
            DraftSegment(
                index=index,
                start_ms=segment.start_ms,
                end_ms=segment.end_ms,
                text=segment.text,
                speaker=segment.speaker,
            )
        )
    return SrtDraft(raw_bytes=raw, segments=tuple(draft))


def mapping_template_bytes(draft: SrtDraft) -> bytes:
    rows = [MAPPING_HEADER]
    rows.extend(f"{item.index}\t{item.sha256}\t\n".encode("ascii") for item in draft.segments)
    return b"".join(rows)


def parse_mapping(
    raw: bytes, draft: SrtDraft, vocabulary: IsoSnapshot
) -> tuple[dict[str, Any], ...]:
    if raw.startswith(b"\xef\xbb\xbf") or b"\r" in raw or not raw.endswith(b"\n"):
        raise LanguageAssignmentError("Mapping muss ASCII ohne BOM/CR und mit genau einem LF enden")
    try:
        lines = raw.decode("ascii").splitlines(keepends=True)
    except UnicodeDecodeError as exc:
        raise LanguageAssignmentError("Mapping ist nicht ASCII") from exc
    if not lines or lines[0].encode("ascii") != MAPPING_HEADER:
        raise LanguageAssignmentError("Mapping-Kopfzeile weicht ab")
    if len(lines) != len(draft.segments) + 1:
        raise LanguageAssignmentError("Mapping braucht genau eine Zeile je Draftsegment")
    out: list[dict[str, Any]] = []
    for expected, line in zip(draft.segments, lines[1:], strict=True):
        if not line.endswith("\n") or line.count("\t") != 2:
            raise LanguageAssignmentError("Mappingzeile braucht genau zwei TAB und ein Schluss-LF")
        index, digest, language = line[:-1].split("\t")
        canonical_index = str(expected.index)
        if index != canonical_index or digest != expected.sha256:
            raise LanguageAssignmentError("Mappingindex oder segment_sha256 weicht vom Draft ab")
        if (
            len(language) != 3
            or not language.isascii()
            or not language.isalpha()
            or not language.islower()
        ):
            raise LanguageAssignmentError(
                "language muss aus genau drei ASCII-Kleinbuchstaben bestehen"
            )
        if not vocabulary.contains(language):
            raise LanguageAssignmentError("language ist nicht im gebundenen ISO-639-3-Vokabular")
        out.append({"index": expected.index, "segment_sha256": digest, "language": language})
    return tuple(out)


@dataclass(frozen=True)
class LanguageAssignment:
    target_record_id: str
    draft: SrtDraft
    mapping_bytes: bytes
    assignments: tuple[dict[str, Any], ...]
    iso6393_vocabulary_sha256: str

    def object(self) -> dict[str, Any]:
        return {
            "domain": "transcript_segment_language_assignment",
            "v": 1,
            "target_record_id": self.target_record_id,
            "srt_bytes_sha256": self.draft.srt_bytes_sha256,
            "parser_version": DRAFT_PARSER_VERSION,
            "draft_segments_sha256": self.draft.draft_segments_sha256,
            "mapping_bytes_sha256": hashlib.sha256(self.mapping_bytes).hexdigest(),
            "assignments": [dict(item) for item in self.assignments],
            "iso6393_vocabulary_sha256": self.iso6393_vocabulary_sha256,
        }

    @property
    def bytes(self) -> bytes:
        return _canonical(self.object())

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.bytes).hexdigest()


def assign_languages(
    draft: SrtDraft,
    mapping_bytes: bytes,
    *,
    target_record_id: str,
    vocabulary: IsoSnapshot,
) -> LanguageAssignment:
    if not target_record_id:
        raise LanguageAssignmentError("target_record_id fehlt")
    assignments = parse_mapping(mapping_bytes, draft, vocabulary)
    return LanguageAssignment(
        target_record_id=target_record_id,
        draft=draft,
        mapping_bytes=mapping_bytes,
        assignments=assignments,
        iso6393_vocabulary_sha256=vocabulary.vocabulary_sha256,
    )


def language_assigned_segments_bytes(
    draft: SrtDraft, assignments: Iterable[dict[str, Any]]
) -> bytes:
    by_index = {item["index"]: item for item in assignments}
    if set(by_index) != set(range(len(draft.segments))):
        raise LanguageAssignmentError("Assignmentindexmenge ist nicht lueckenlos")
    out = []
    for segment in draft.segments:
        assignment = by_index[segment.index]
        if assignment.get("segment_sha256") != segment.sha256:
            raise LanguageAssignmentError("Assignment bindet einen fremden Segmentdigest")
        out.append(
            {
                "end_ms": segment.end_ms,
                "index": segment.index,
                "language": assignment["language"],
                "speaker": segment.speaker,
                "start_ms": segment.start_ms,
                "text": segment.text,
            }
        )
    return _canonical(out)


def revision_from_assignment(draft: SrtDraft, assignment: LanguageAssignment) -> TranscriptRevision:
    segments = tuple(
        Segment(
            index=segment.index,
            start_ms=segment.start_ms,
            end_ms=segment.end_ms,
            text=segment.text,
            speaker=segment.speaker,
            language=assignment.assignments[segment.index]["language"],
        )
        for segment in draft.segments
    )
    return TranscriptRevision.from_segments(
        segments,
        projection_version=draft.projection_version,
        source_kind="srt",
        source_sha256=draft.srt_bytes_sha256,
        profile_id=draft.profile_id,
    )
