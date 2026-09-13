"""B-v2: echte Antwortbytes und ausschließlich eigene L1-Fehlerbereinigung."""

import io
import json
import os
import stat
from contextlib import contextmanager
from dataclasses import replace

import pytest

from ohpipe.application import finalisation, l1_publication, l1_suggest as l1
from ohpipe.application.coverage import CoverageError, run_l1_coverage
from ohpipe.domain.hashing import sha256_bytes, sha256_text
from ohpipe.store import ContentStore, StoreWriteFailed

from .test_l1_completion import _object, _omit, _replace_current_artifact
from .test_l1_suggest import RECORD, _BlockFixture, _ctx, _view, _welt, _zustand


@pytest.mark.parametrize("index", [0, 1])
@pytest.mark.parametrize("suffix", ["  \r\n", "\n", "\t\r\n\n"])
def test_raw_response_change_requires_new_individual_digest(tmp_path, index, suffix):
    ws, journal, _ = _welt(tmp_path)
    adapter = _BlockFixture(lambda n, r: _omit(r, {1}) if n == 1 else r)
    result = l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    obj = _object(ws, result)
    request = obj["requests"][index]
    before = request["response_text"]
    assert request["receipt"]["output_sha256"] == sha256_bytes(before.encode("utf-8"))
    request["response_text"] += suffix
    assert sha256_text(before) == sha256_text(request["response_text"])
    assert sha256_bytes(before.encode("utf-8")) != sha256_bytes(
        request["response_text"].encode("utf-8")
    )
    _replace_current_artifact(ws, journal, obj)
    unchanged = _zustand(ws, journal)
    with pytest.raises(l1.SuggestError, match="Keine Wiederverwendung"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    assert len(adapter.calls) == 2 and _zustand(ws, journal) == unchanged


def test_non_ascii_answer_digest_is_exact_utf8_without_normalization(tmp_path):
    ws, journal, _ = _welt(tmp_path)
    raw = '{"results": [{"segment": 0, "code": "Cafe\u0301"}, {"segment": 1, "code": "AA"}, {"segment": 2, "code": "AA"}, {"segment": 3, "code": "AA"}]}\r\n'
    adapter = _BlockFixture(lambda n, r: replace(r, text=raw))
    result = l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter)
    request = _object(ws, result)["requests"][0]
    assert request["response_text"] == raw
    assert request["receipt"]["output_sha256"] == sha256_bytes(raw.encode("utf-8"))
    assert request["receipt"]["output_sha256"] != sha256_text(raw)
    assert not l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=adapter).written
    assert len(adapter.calls) == 1


def _foreign_temp(ws):
    foreign = ws.objects / ".incoming-foreign-operation"
    foreign.write_bytes(b"another operation")
    return foreign


def _fail_after_bytes(fd, data, name):
    os.write(fd, data)
    raise OSError("synthetic write failure after bytes")


def test_write_failure_removes_only_own_temporary_file(tmp_path, monkeypatch):
    ws, journal, _ = _welt(tmp_path)
    foreign = _foreign_temp(ws)
    before = _zustand(ws, journal)
    monkeypatch.setattr(ContentStore, "_write_all", staticmethod(_fail_after_bytes))
    with pytest.raises(StoreWriteFailed, match="eigener Tempalias bereinigt"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=_BlockFixture())
    assert _zustand(ws, journal) == before
    assert foreign.read_bytes() == b"another operation"


def test_written_bytes_are_verified_before_final_link(tmp_path, monkeypatch):
    ws, journal, _ = _welt(tmp_path)
    before = _zustand(ws, journal)
    monkeypatch.setattr(
        ContentStore, "_write_all", staticmethod(lambda fd, data, name: os.write(fd, data[:20]))
    )
    with pytest.raises(StoreWriteFailed, match="vor finalem Link nicht verifizierbar"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=_BlockFixture())
    assert _zustand(ws, journal) == before


def test_other_publisher_can_reference_final_link_before_our_failure(tmp_path, monkeypatch):
    """Gezieltes Interleaving der vom Reviewer benannten gemeinsamen Hashadresse."""
    ws, journal, _ = _welt(tmp_path)
    real_link = os.link
    referenced = []

    def link_and_publish_elsewhere(source, destination, **kwargs):
        real_link(source, destination, **kwargs)
        ws.store().verify(destination)
        journal.append(
            "artifact.produced",
            {"artifact": "l1.suggestions", "sha256": destination},
            record_id=RECORD,
        )
        referenced.append(destination)
        raise OSError("synthetic failure after another publisher referenced the object")

    monkeypatch.setattr(l1_publication.os, "link", link_and_publish_elsewhere)
    with pytest.raises(StoreWriteFailed):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=_BlockFixture())
    assert len(referenced) == 1
    ws.store().verify(referenced[0])
    assert not list(ws.objects.glob(".incoming-l1-*"))
    assert any(e.payload.get("sha256") == referenced[0] for e in journal)


@pytest.mark.parametrize("stage", ["file_fsync", "before_link", "after_link", "directory_fsync"])
def test_store_errors_clean_only_temp_and_never_unlink_final_object(tmp_path, monkeypatch, stage):
    ws, journal, _ = _welt(tmp_path)
    _foreign_temp(ws)
    before = _zustand(ws, journal)
    real_link = os.link
    real_fsync = os.fsync
    real_dir_fsync = ContentStore._fsync_dir
    fired = False

    def link(*args, **kwargs):
        if stage == "before_link":
            raise OSError("synthetic prelink failure")
        result = real_link(*args, **kwargs)
        if stage == "after_link":
            raise OSError("synthetic postlink failure")
        return result

    def fsync(fd):
        if stage == "file_fsync" and stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError("synthetic file fsync failure")
        return real_fsync(fd)

    def dir_fsync(fd):
        nonlocal fired
        if stage == "directory_fsync" and not fired:
            fired = True
            raise StoreWriteFailed("synthetic directory fsync failure")
        return real_dir_fsync(fd)

    monkeypatch.setattr(l1_publication.os, "link", link)
    monkeypatch.setattr(l1_publication.os, "fsync", fsync)
    monkeypatch.setattr(ContentStore, "_fsync_dir", staticmethod(dir_fsync))
    with pytest.raises(StoreWriteFailed):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=_BlockFixture())
    if stage in {"before_link", "file_fsync"}:
        assert _zustand(ws, journal) == before
    else:
        assert journal.head() == before[0]
        added = set(p.name for p in ws.objects.iterdir()) - set(before[1])
        assert len(added) == 1
        address = added.pop()
        ws.store().verify(address)
        assert b'"response_text"' in (ws.objects / address).read_bytes()
        assert not list(ws.objects.glob(".incoming-l1-*"))


@pytest.mark.parametrize("kind", ["artifact.produced", "receipt.recorded", "anchor.checked"])
@pytest.mark.parametrize("after_write", [False, True])
def test_journal_failure_retains_complete_object_and_existing_recovery_state(
    tmp_path, monkeypatch, kind, after_write
):
    ws, journal, _ = _welt(tmp_path)
    _foreign_temp(ws)
    files_before = sorted(p.name for p in ws.objects.iterdir())
    append = journal.append_once

    def failing(event_kind, payload, **kwargs):
        if event_kind == kind and not after_write:
            raise OSError("synthetic journal prewrite failure")
        result = append(event_kind, payload, **kwargs)
        if event_kind == kind:
            raise OSError("synthetic journal postwrite failure")
        return result

    monkeypatch.setattr(journal, "append_once", failing)
    with pytest.raises(StoreWriteFailed, match="eigener Tempalias bereinigt"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=_BlockFixture())
    added = set(p.name for p in ws.objects.iterdir()) - set(files_before)
    assert len(added) == 1 and not list(ws.objects.glob(".incoming-l1-*"))
    address = added.pop()
    ws.store().verify(address)
    with ws.store().open_verified(address) as handle:
        obj = json.load(handle)
    assert len(obj["suggestions"]) == 4
    monkeypatch.setattr(journal, "append_once", append)
    if kind == "anchor.checked" and after_write:
        # Alle drei Ereignisse waren vor der Ausnahme tatsächlich geschrieben.
        # Das vollständige Ergebnis bleibt nutzbar und braucht keinen Modellretry.
        assert run_l1_coverage(_ctx(ws, journal), _view(ws, journal)).covered == 4
    else:
        with pytest.raises(CoverageError):
            run_l1_coverage(_ctx(ws, journal), _view(ws, journal))
        assert not any(e.payload.get("artifact") == "l1.coverage" for e in journal)


def test_consumer_context_exit_failure_is_inside_cleanup_boundary(tmp_path, monkeypatch):
    ws, journal, _ = _welt(tmp_path)
    files_before = sorted(p.name for p in ws.objects.iterdir())
    original = finalisation.consumer_publication

    @contextmanager
    def failure(ctx, bound):
        with original(ctx, bound) as journal:
            yield journal
        raise OSError("synthetic journal context exit failure")

    monkeypatch.setattr(finalisation, "consumer_publication", failure)
    with pytest.raises(StoreWriteFailed):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=_BlockFixture())
    added = set(p.name for p in ws.objects.iterdir()) - set(files_before)
    assert len(added) == 1 and not list(ws.objects.glob(".incoming-l1-*"))
    ws.store().verify(added.pop())
    monkeypatch.setattr(finalisation, "consumer_publication", original)
    assert run_l1_coverage(_ctx(ws, journal), _view(ws, journal)).covered == 4


def test_failure_never_deletes_preexisting_identical_object(tmp_path):
    ws, _, _ = _welt(tmp_path)
    data = b'{"response_text":"synthetic existing successful object"}'
    store = ws.store()
    address = store.put(io.BytesIO(data))
    foreign = _foreign_temp(ws)
    files_before = sorted(p.name for p in ws.objects.iterdir())
    with pytest.raises(StoreWriteFailed), l1_publication.l1_object_publication(store) as publish:
        assert publish(data) == address
        raise OSError("synthetic journal failure")
    assert sorted(p.name for p in ws.objects.iterdir()) == files_before
    assert (ws.objects / address).read_bytes() == data
    assert foreign.read_bytes() == b"another operation"


def test_exclusive_temp_collision_does_not_delete_foreign_file(tmp_path, monkeypatch):
    ws, _, _ = _welt(tmp_path)
    name = ".incoming-l1-" + (b"a" * 16).hex()
    foreign = ws.objects / name
    foreign.write_bytes(b"foreign collision")
    monkeypatch.setattr(l1_publication.os, "urandom", lambda n: b"a" * n)
    with (
        pytest.raises(StoreWriteFailed),
        l1_publication.l1_object_publication(ws.store()) as publish,
    ):
        publish(b'{"response_text":"synthetic new bytes"}')
    assert foreign.read_bytes() == b"foreign collision"


def test_replaced_object_name_is_not_deleted(tmp_path):
    ws, _, _ = _welt(tmp_path)
    with (
        pytest.raises(StoreWriteFailed),
        l1_publication.l1_object_publication(ws.store()) as publish,
    ):
        address = publish(b'{"response_text":"synthetic new bytes"}')
        path = ws.objects / address
        path.unlink()
        path.write_bytes(b"foreign replacement")
        raise OSError("synthetic journal failure")
    assert path.read_bytes() == b"foreign replacement"
    assert not list(ws.objects.glob(".incoming-l1-*"))


def test_cleanup_failure_is_reported_without_false_erasure_claim(tmp_path, monkeypatch):
    ws, journal, _ = _welt(tmp_path)
    monkeypatch.setattr(ContentStore, "_write_all", staticmethod(_fail_after_bytes))
    real_unlink = os.unlink

    def fail_cleanup(name, **kwargs):
        if str(name).startswith(".incoming-l1-"):
            raise OSError("synthetic cleanup denial")
        return real_unlink(name, **kwargs)

    monkeypatch.setattr(l1_publication.os, "unlink", fail_cleanup)
    before = journal.head()
    with pytest.raises(StoreWriteFailed, match="nicht sicher vollständig bereinigt"):
        l1.run_l1_suggest(_ctx(ws, journal), _view(ws, journal), adapter=_BlockFixture())
    assert journal.head() == before
    assert any(b'"response_text"' in p.read_bytes() for p in ws.objects.glob(".incoming-l1-*"))


def test_regular_store_recovery_contract_is_unchanged(tmp_path, monkeypatch):
    ws, _, _ = _welt(tmp_path)
    monkeypatch.setattr(ContentStore, "_write_all", staticmethod(_fail_after_bytes))
    with pytest.raises(StoreWriteFailed, match="als Beleg liegen"):
        ws.store().put(io.BytesIO(b"synthetic regular-store recovery evidence"))
    assert any(p.read_bytes() for p in ws.objects.glob(".incoming-*"))
