"""Der Content Store im Normalbetrieb — nicht unter Angriff.

``test_content_store_forgery.py`` prüft, was der Store abwehrt. Diese Datei
prüft, dass er überhaupt tut, wozu er da ist. Beides zu vermischen wäre
bequem und falsch: Ein Store, der alles ablehnt, bestünde jeden Angriffstest.
"""

from __future__ import annotations

import errno
import hashlib
import io
import os
import stat
from pathlib import Path

import pytest

from ohpipe.store import ContentStore, CorruptObject, StoreOutsideRoot


@pytest.fixture
def store(tmp_path: Path) -> ContentStore:
    root = tmp_path / "data"
    root.mkdir()
    return ContentStore(root)


def test_put_returns_the_address_and_open_verified_returns_the_bytes(store):
    """Der Rundlauf. Ohne ihn prüfte alles andere die Abwehr eines Stores, der
    vielleicht gar nichts speichert."""
    payload = b"ein Interviewtranskript, der Einfachheit halber kurz"
    address = store.put(io.BytesIO(payload))

    assert address == hashlib.sha256(payload).hexdigest()
    with store.open_verified(address) as fh:
        assert fh.read() == payload, "gelesen wurde nicht ab Position 0"


def test_open_verified_hands_out_a_stream_not_a_blob(store):
    """Der Streaming-Vertrag auf der Leseseite.

    Ein ``read(8)`` muss acht Bytes liefern und nicht das ganze Objekt — sonst
    ist ``open_verified`` ein ``get() -> bytes`` mit Kontextmanager drumherum.
    """
    payload = b"z" * 4096
    address = store.put(io.BytesIO(payload))
    with store.open_verified(address) as fh:
        assert fh.read(8) == b"z" * 8
        assert len(fh.read()) == 4088


def test_putting_the_same_bytes_twice_is_one_object(store):
    """Inhaltsadressierung heißt: zweimal dasselbe ist einmal dasselbe.

    Der zweite Lauf trifft im Publikationsprotokoll auf ``EEXIST`` und prüft
    das vorhandene Ziel, statt es zu überschreiben oder blind zu glauben.
    """
    payload = b"zweimal abgelegt"
    first = store.put(io.BytesIO(payload))
    second = store.put(io.BytesIO(payload))

    assert first == second
    assert store.object_names() == [first]
    assert store.stale_temporaries() == [], "die Temporärdatei des zweiten Laufs blieb liegen"


def test_an_empty_object_is_a_legitimate_object(store):
    """Null Bytes haben einen Hash wie alles andere.

    Der Sonderfall ist billig zu übersehen und teuer zu debuggen: eine
    ``while chunk := read()``-Schleife, die bei leerer Eingabe nie eine Datei
    anlegt, liefert eine Adresse ohne Objekt.
    """
    address = store.put(io.BytesIO(b""))
    assert address == hashlib.sha256(b"").hexdigest()
    info = store.verify(address)
    assert info.size == 0
    with store.open_verified(address) as fh:
        assert fh.read() == b""


def test_a_large_object_survives_more_than_one_chunk(store):
    """Über die Blockgrenze hinweg. Ein Hash, der nur den ersten Block sieht,
    fällt sonst erst bei echten Audiodateien auf."""
    payload = os.urandom(3 * 1024 * 1024 + 17)
    address = store.put(io.BytesIO(payload))
    assert address == hashlib.sha256(payload).hexdigest()
    with store.open_verified(address) as fh:
        assert fh.read() == payload


def test_verify_describes_what_it_checked(store):
    payload = b"beschreibbar"
    address = store.put(io.BytesIO(payload))
    info = store.verify(address)

    assert info.address == address
    assert info.size == len(payload)
    assert info.nlink == 1 and not info.suspicious_links
    assert info.mode == 0o600 and not info.too_permissive


def test_the_store_creates_its_directory_tightly(store):
    store.put(io.BytesIO(b"legt das Verzeichnis an"))
    assert stat.S_IMODE(store.objects.stat().st_mode) == 0o700


def test_a_hardlinked_object_is_reported_as_a_hint_not_as_proof(store, tmp_path):
    """D3, ehrlich gehalten.

    Ein Hardlink ist durch Pfadauflösung nicht erkennbar — dieselbe Inode hat
    nur zwei Namen, es gibt keinen Pfad, den man auflösen könnte. Der Store
    meldet ``nlink > 1`` als Hinweis und behauptet nicht, etwas bewiesen zu
    haben. Geschützt hat hier das erneute Hashen.
    """
    address = store.put(io.BytesIO(b"einmal abgelegt, zweimal benannt"))
    os.link(store.objects / address, tmp_path / "zweiter-name")

    info = store.verify(address)
    assert info.suspicious_links, "der Hinweis fehlt"
    audit = store.audit()
    assert audit.findings == [], "aus einem Hinweis wurde ein Befund"
    assert any("Namen" in n for n in audit.notes)


def test_the_object_directory_may_not_be_the_data_root_itself(tmp_path):
    """Sonst läge das Journal im Store und würde als Objekt geprüft."""
    root = tmp_path / "data"
    root.mkdir()
    with pytest.raises(StoreOutsideRoot):
        ContentStore(root, objects=root)


def test_a_corrupt_object_is_never_handed_out_partially(store):
    """Die Prüfung steht VOR der Ausgabe, nicht daneben.

    Ein Leser, der schon Bytes bekommen hat und erst danach von einem Fehler
    erfährt, hat die Bytes trotzdem. Deshalb wird das Objekt vollständig
    gehasht, bevor der Deskriptor herausgeht.
    """
    payload = b"urspruenglich korrekt"
    address = store.put(io.BytesIO(payload))
    target = store.objects / address
    target.chmod(0o600)
    target.write_bytes(b"nachtraeglich ausgetauscht")

    with pytest.raises(CorruptObject), store.open_verified(address) as fh:
        fh.read()  # pragma: no cover — hierhin darf es nicht kommen


def test_a_failing_directory_fsync_is_not_swallowed(store, monkeypatch):
    """F4 — Dauerhaftigkeit, die man nicht prüfen kann, ist keine Zusage.

    Die erste Fassung fing JEDEN Fehler von ``fsync`` auf das Verzeichnis ab.
    Damit sah ein ``EIO`` genauso aus wie ein Dateisystem, das
    Verzeichnis-``fsync`` gar nicht kennt — und die Zusage „der Name übersteht
    einen Absturz" war unbelegbar.

    Ehrlich: Der Fehler wird hier injiziert, das Dateisystem ist in Ordnung.
    Geprüft wird die Behandlung von ``EIO``, nicht die Platte.
    """
    import ohpipe.store as m

    real = os.fsync

    def only_directories_fail(fd: int):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "I/O error")
        return real(fd)

    monkeypatch.setattr(m.os, "fsync", only_directories_fail)
    with pytest.raises(m.StoreWriteFailed):
        store.put(io.BytesIO(b"geschrieben, aber nicht dauerhaft benannt"))


def test_a_filesystem_without_directory_fsync_is_tolerated(store, monkeypatch):
    """Die Gegenprobe. Nicht jedes Dateisystem kennt ``fsync`` auf Verzeichnissen.

    Ohne diese Unterscheidung wäre die Verschärfung oben schlimmer als das
    Verschlucken: Der Store liefe auf manchen Dateisystemen gar nicht mehr.
    """
    import ohpipe.store as m

    real = os.fsync

    def unsupported_on_directories(fd: int):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EINVAL, "Invalid argument")
        return real(fd)

    monkeypatch.setattr(m.os, "fsync", unsupported_on_directories)
    assert len(store.put(io.BytesIO(b"laeuft auch dort"))) == 64
