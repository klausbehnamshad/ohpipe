"""L1-eigene Storepublikation mit begrenzter Bereinigung bei behandeltem Fehler.

ContentStore.put bewahrt abgebrochene Schreibversuche für die allgemeine
Recovery auf. Das bleibt unverändert. Neue L1-Antwortbelege benötigen einen
engeren Weg: ausschließlich der hier exklusiv angelegte Tempalias wird bei
einem behandelbaren Fehler bis zum Ende der Journalpublikation entfernt.
Ab dem finalen Link bleibt der Objektname erhalten: andere Publizierer können
ihn bereits referenziert haben. Journalereignisse werden nicht zurückgerollt.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from ..domain.hashing import sha256_bytes
from ..store import OBJECT_MODE, TEMP_PREFIX, ContentStore, StoreWriteFailed


@contextmanager
def l1_object_publication(store: ContentStore) -> Iterator[Callable[[bytes], str]]:
    """Umfasst auch den nachfolgenden Journalabschluss des Aufrufers.

    Eintritt öffnet nur den Verzeichnisdeskriptor. Erst der zurückgegebene
    Schreiber legt Bytes ab, nach dem bestehenden Verbraucher-Gate. Es gibt
    keine Verzeichnissuche und keine Bereinigung von Endobjekten. Auch ein
    neu verlinktes Endobjekt kann bereits von einem anderen Publizierer benutzt
    werden; nach dem Link gilt die bestehende Store-/Journal-Recovery.
    SIGKILL, Stromausfall oder ein weiterer Löschfehler können die Bereinigung
    verhindern; dies ist keine sichere Löschung auf Datenträgerebene.
    """
    with store._dir(create=True) as dir_fd:
        temp_name = f"{TEMP_PREFIX}l1-{os.urandom(16).hex()}"
        fd = None
        identity = None
        address = None
        called = False

        def discard(name):
            if name is None or identity is None:
                return
            try:
                current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            if (current.st_dev, current.st_ino) == identity:
                os.unlink(name, dir_fd=dir_fd)

        def publish(data: bytes) -> str:
            nonlocal fd, identity, address, called
            if called:
                raise StoreWriteFailed("L1-Publikation erlaubt genau ein Vorschlagsobjekt")
            called = True
            address = sha256_bytes(data)
            fd = os.open(
                temp_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                OBJECT_MODE,
                dir_fd=dir_fd,
            )
            owned = os.fstat(fd)
            identity = (owned.st_dev, owned.st_ino)
            os.fchmod(fd, OBJECT_MODE)
            store._write_all(fd, data, temp_name)
            os.fsync(fd)
            if store._digest(fd) != address:
                raise StoreWriteFailed("L1-Vorschlagsbytes vor finalem Link nicht verifizierbar")
            try:
                os.link(temp_name, address, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            except FileExistsError:
                # Dieses Objekt gehört nicht diesem Schreibversuch. Prüfen und
                # erhalten, auch wenn die anschließende Journaloperation fällt.
                store._verify_at(dir_fd, address)
            store._fsync_dir(dir_fd)
            store._verify_at(dir_fd, address)
            return address

        try:
            yield publish
            discard(temp_name)
            if called:
                store._fsync_dir(dir_fd)
        except BaseException as exc:
            # Nie den Endnamen löschen: ab link können auch andere Schreiber
            # das vollständige Objekt referenzieren, selbst vor unserem append.
            errors = []
            for name in (temp_name,):
                try:
                    discard(name)
                except OSError as error:
                    errors.append(error)
            try:
                if called:
                    store._fsync_dir(dir_fd)
            except (OSError, StoreWriteFailed) as error:
                errors.append(error)
            if errors:
                raise StoreWriteFailed(
                    "L1-Publikation abgebrochen; eigener Tempalias konnte nicht sicher "
                    "vollständig bereinigt werden. Lokale Store-/Journaldiagnose erforderlich."
                ) from exc
            if isinstance(exc, OSError):
                raise StoreWriteFailed(
                    "L1-Publikation abgebrochen; eigener Tempalias bereinigt. "
                    "Bereits verlinkte Objekte und Journalereignisse bleiben zur Recovery erhalten."
                ) from exc
            raise
        finally:
            if fd is not None:
                os.close(fd)
