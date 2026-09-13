#!/usr/bin/env python3
"""Nur lesende, inhaltsfreie Strukturpruefung einer lokal bereitgestellten SRT."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import sys

from ohpipe.adapters.input.srt import parse_srt
from ohpipe.domain.cue import CueDocument, CueFormat


_BASENAME = re.compile(r"WALZ-[0-9]{4}(?:\.ohpipe)?\.srt\Z")
_RECORD_ID = re.compile(r"WALZ-[0-9]{4}\Z")
_NEUTRAL_SPEAKER = re.compile(r"SPEAKER_[0-9]+\Z")
_BLOCK_SIZE = 64


def _timecode(milliseconds: int) -> str:
    hours, rest = divmod(milliseconds, 3_600_000)
    minutes, rest = divmod(rest, 60_000)
    seconds, millis = divmod(rest, 1_000)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d},{millis:03d}"


def inspect(source: Path, data_root: Path | None, record_id: str) -> tuple[dict, int]:
    """Prueft Bytes und Struktur, gibt aber weder Cue-Text noch freie Labels aus."""
    if not _RECORD_ID.fullmatch(record_id):
        return {"ok": False, "error": "RECORD_ID_FORMAT"}, 2
    try:
        raw = source.read_bytes()
    except OSError:
        return {"ok": False, "error": "SOURCE_READ_ERROR"}, 2

    # Dieselbe verlustfreie Eingangsgrenze wie beim realen Ingest. Kein
    # Parserfehler darf seinen (moeglicherweise quellhaltigen) Detailtext an
    # stdout oder stderr weiterreichen.
    try:
        document = CueDocument.parse_bytes(raw, CueFormat.SRT)
    except Exception:
        return {"ok": False, "error": "CUE_DOCUMENT_PARSE_ERROR"}, 2
    try:
        roundtrip = document.render_bytes()
    except Exception:
        return {"ok": False, "error": "BYTE_ROUNDTRIP_ERROR"}, 2
    if roundtrip != raw:
        return {"ok": False, "error": "BYTE_ROUNDTRIP_MISMATCH"}, 2

    # Die zweite Sicht ist fuer Sprecher- und Zeitmetadaten zustaendig. Auch
    # sie arbeitet auf genau der bereits verlustfrei dekodierten Quelle.
    try:
        segments = parse_srt(document.source, strict=True)
    except Exception:
        return {"ok": False, "error": "SRT_METADATA_PARSE_ERROR"}, 2
    lossless_cues = len(document.payloads())
    metadata_cues = len(segments)
    if lossless_cues != metadata_cues:
        return {"ok": False, "error": "CUE_COUNT_MISMATCH"}, 2

    base = {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "bytes": len(raw),
        "basename_valid": bool(_BASENAME.fullmatch(source.name)),
        "record_id": record_id,
        "record_exists": (
            None if data_root is None else (data_root.resolve() / "records" / record_id).exists()
        ),
    }
    if not base["basename_valid"]:
        base["basename_warning"] = (
            "Neutraler Basename WALZ-####.srt oder WALZ-####.ohpipe.srt erforderlich"
        )

    speakers = Counter(segment.speaker for segment in segments if segment.speaker is not None)
    speaker_pairs = sorted(speakers.items())
    labels = {
        "distinct": len(speaker_pairs),
        "occurrences": sum(speakers.values()),
    }
    if all(_NEUTRAL_SPEAKER.fullmatch(label) for label in speakers):
        labels["counts"] = dict(speaker_pairs)
    else:
        labels["warning"] = "Nichtneutrale Sprecherlabels werden nicht ausgegeben"

    blocks = []
    for start in range(0, metadata_cues, _BLOCK_SIZE):
        block = segments[start : start + _BLOCK_SIZE]
        blocks.append(
            {
                "block": len(blocks) + 1,
                "segments": len(block),
                "segment_characters": sum(len(segment.text) for segment in block),
            }
        )

    first, last = segments[0], segments[-1]
    return (
        {
            **base,
            "ok": True,
            "cues": metadata_cues,
            "cue_counts": {
                "lossless": lossless_cues,
                "metadata": metadata_cues,
            },
            "first_timecode": {
                "start": _timecode(first.start_ms),
                "end": _timecode(first.end_ms),
            },
            "last_timecode": {
                "start": _timecode(last.start_ms),
                "end": _timecode(last.end_ms),
            },
            "speaker_labels": labels,
            "characters_total": sum(len(segment.text) for segment in segments),
            "longest_cue_characters": max(len(segment.text) for segment in segments),
            "block_size": _BLOCK_SIZE,
            "blocks": blocks,
        },
        0,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("data_root", nargs="?", type=Path)
    parser.add_argument("--record-id", required=True)
    args = parser.parse_args(argv)
    result, code = inspect(args.source, args.data_root, args.record_id)
    sys.stdout.write(json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
