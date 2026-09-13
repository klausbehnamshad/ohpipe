"""Ausdrückliches Einlesen zusätzlicher Quellen; kein Dateiwächter (O-2)."""

import io
from pathlib import Path

from ..domain.step import build_graph
from ..policies.authority import Authority
from ..policies.ownership import THIS_RUNTIME, CutoverLedger
from ..workspace_lock import workspace_write_lock
from .replay import replay


def observe(ws, journal, record_id, role, data):
    if role not in ("l1.codebook", "metadata.input"):
        raise ValueError("Nicht deklarierte Quellenrolle")
    with workspace_write_lock(ws.root), journal.transaction() as transaction:
        if not transaction.key:
            raise ValueError("Quelleneinlesen verlangt authentifiziertes Journal")
        events = list(transaction)
        CutoverLedger.from_journal(
            events,
            authority=Authority.AUTHENTICATED,
            default_runtime=ws.profile.legacy_runtime or THIS_RUNTIME,
        ).require_write(record_id)
        view = replay(events, graph=build_graph(ws.profile), authority=Authority.AUTHENTICATED).get(
            record_id
        )
        if view is None or not view.enabled or view.findings:
            raise ValueError("Quelle verlangt einen vorhandenen aktiven Record ohne Befunde")
        sha = ws.store().put(io.BytesIO(data)) if data is not None else None
        if view.sources.get(role, (None, 0))[0] == sha:
            return sha
        transaction.append_once(
            "input.observed",
            {"role": role, "sha256": sha},
            record_id=record_id,
            duplikat=lambda e: False,
        )
        return sha


def refresh(ws, journal, record_id, profile_path):
    from ..policies.metadata import load_record_metadata
    from .catalog import metadata_input_path
    from .codebook import load_codebook

    codebook = None
    if ws.profile.codebook:
        codebook = load_codebook(Path(profile_path).resolve().parent / ws.profile.codebook).raw
    metadata = metadata_input_path(ws, record_id)
    raw = load_record_metadata(metadata, record_id=record_id).raw if metadata.exists() else None
    # Beide Eingaben vor dem ersten Journalakt validieren.
    observe(ws, journal, record_id, "l1.codebook", codebook)
    observe(ws, journal, record_id, "metadata.input", raw)
