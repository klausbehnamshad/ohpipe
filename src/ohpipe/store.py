"""Der inhaltsadressierte Speicher — Bytes, sonst nichts.

Ein Objekt heißt wie sein SHA-256. Der Name trägt keine Information über den
Inhalt: keine Record-ID, keinen Titel, keinen Personennamen. Im Vorgängersystem
lagen namenshaltige Analyseartefakte im aktiven Arbeitsverzeichnis; hier ist
das strukturell ausgeschlossen statt durch Disziplin verhindert.

**Der Store trägt keine Autorität** (ADR 0017). Er beantwortet „welche Bytes
gehören zu dieser Adresse" — nicht „ist dieses Artefakt gültig". Das entscheidet
das Journal. Bytes hinzulegen ändert kein Urteil.

Entworfen gegen ``docs/ATTACK-LIST_content-store.md``; die dort als erste Runde
markierten Fälschungstests standen vor der ersten Zeile hier (ADR 0015). Die
Zahlen stehen bewusst nicht hier: Eine Docstring, die zählt, driftet, und der
``zahlen``-Job sah bis eben nur README und ROADMAP. Diese Fassung nannte „32
Angriffe" und „vierzehn Fälschungstests"; die Liste führte längst 35.

Drei Entscheidungen, die im API sichtbar sind:

**Gelesen wird streamend.** Es gibt kein ``get() -> bytes``. Ein Interview mit
Audio gehört nicht am Stück in den Speicher.

**Es gibt keinen öffentlichen Pfad.** ``_path_for`` ist privat. Wer einen Pfad
herausgibt, gibt die Hash- und Symlinkprüfung mit heraus — der Aufrufer öffnet
dann selbst und alle Zusicherungen dieses Moduls sind Dekoration.

**Es gibt kein ``contains()``.** Existenz, Integrität und Sicherheit lassen
sich nicht ehrlich in einem Boolean zusammenfassen. Wer wissen will, ob ein
Objekt benutzbar ist, ruft :meth:`ContentStore.verify` und behandelt den
Fehler, den er bekommt.
"""

from __future__ import annotations

import errno
import hashlib
import os
import re
import stat
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

__all__ = [
    "BadAddress",
    "ContentStore",
    "CorruptObject",
    "MissingObject",
    "ObjectInfo",
    "StoreAudit",
    "StoreError",
    "StoreOutsideRoot",
    "StoreWriteFailed",
    "UnsafeObject",
]

#: Eine Adresse ist reines Kleinhex. Nichts anderes wird zu einem Pfad.
ADDRESS_RE = re.compile(r"^[0-9a-f]{64}$")

#: Präfix für unfertige Objekte. Bewusst NICHT ``<sha>.tmp``: Zwei gleichzeitige
#: Schreiber desselben Objekts schrieben sonst in dieselbe Datei (E1).
TEMP_PREFIX = ".incoming-"

#: 1 MiB. Groß genug, dass der Systemaufruf nicht dominiert, klein genug, dass
#: ein Interviewtranskript samt Audio nicht im Speicher landet.
CHUNK = 1 << 20

DIR_MODE = 0o700
OBJECT_MODE = 0o600


class StoreError(RuntimeError):
    """Basisklasse. Jeder Fehler dieses Moduls ist übersetzt, nie durchgereicht."""


class BadAddress(StoreError):
    """Keine gültige Adresse. Geprüft VOR jedem Pfadbau (D1, D5)."""


class StoreOutsideRoot(StoreError):
    """Das Objektverzeichnis liegt außerhalb der Datenwurzel (D6)."""


class MissingObject(StoreError):
    """Die Bytes gibt es nicht (A4)."""


class CorruptObject(StoreError):
    """Name und Inhalt passen nicht zusammen (A1, A2, E2)."""


class UnsafeObject(StoreError):
    """Kein reguläres Objekt — Symlink, Verzeichnis, Gerät (D2, A6)."""


class StoreWriteFailed(StoreError):
    """Das Schreiben ist abgebrochen. Ein Torso bleibt ein Torso."""


@dataclass(frozen=True)
class ObjectInfo:
    """Was über ein geprüftes Objekt gesagt werden kann.

    ``nlink`` ist der ehrliche Teil: Ein Hardlink auf eine Datei außerhalb des
    Stores ist durch Pfadauflösung **nicht** erkennbar — es gibt keinen Pfad,
    den man auflösen könnte, dieselbe Inode hat nur zwei Namen. Was tatsächlich
    schützt, ist das erneute Hashen. ``nlink > 1`` ist ein *Hinweis*, kein
    Beweis (D3).
    """

    address: str
    size: int
    nlink: int
    mode: int

    @property
    def suspicious_links(self) -> bool:
        return self.nlink > 1

    @property
    def too_permissive(self) -> bool:
        return bool(self.mode & 0o077)


@dataclass(frozen=True)
class StoreAudit:
    """Das Ergebnis von :meth:`ContentStore.audit`.

    ``findings`` halten an, ``notes`` nicht. Beides in einen Topf zu werfen
    hieße, entweder einen Absturzrest zum Blocker zu machen oder ein
    weltlesbares Interview zur Randnotiz.
    """

    findings: list[str]
    notes: list[str]


def check_address(address: object) -> str:
    """Die einzige Stelle, an der aus einer Zeichenkette eine Adresse wird.

    Vor jedem Pfadbau, nicht danach: ``../`` darf nie zu einem ``Path``
    zusammengesetzt werden, auch nicht kurz.
    """
    if not isinstance(address, str) or not ADDRESS_RE.match(address):
        shown = address if isinstance(address, str) and len(address) <= 80 else type(address)
        raise BadAddress(
            f"{shown!r} ist keine Objektadresse. Gültig ist ausschließlich "
            "^[0-9a-f]{64}$ — Kleinhex, keine Pfade, keine Großbuchstaben."
        )
    return address


@dataclass
class ContentStore:
    """Objekte unter ``root/objects``, adressiert über ihren SHA-256."""

    root: Path
    objects: Path | None = None

    def __post_init__(self) -> None:
        self.root = Path(self.root).expanduser().resolve()
        objects = Path(self.objects).expanduser() if self.objects else self.root / "objects"
        # ``strict=False``: Das Verzeichnis darf noch nicht existieren, ein
        # Symlink darauf wird aber JETZT aufgelöst — sonst führte ein
        # nachträglich untergeschobener Link aus der Datenwurzel hinaus (D6).
        resolved = objects.resolve()
        # Strikt INNERHALB, nicht „innerhalb oder gleich": Wäre das
        # Objektverzeichnis die Datenwurzel selbst, läge das Journal im Store
        # und würde als Objekt geprüft.
        if self.root not in resolved.parents:
            raise StoreOutsideRoot(
                f"Das Objektverzeichnis {resolved} liegt außerhalb der Datenwurzel "
                f"{self.root}. Dieselbe Regel wie für --root (ADR 0006): Reale Bytes "
                "liegen dort, wo die Datenwurzel sie verantwortet, und nirgends sonst."
            )
        self.objects = resolved

    # ------------------------------------------------------------ intern
    #
    # Alles unterhalb arbeitet auf einem VERZEICHNISDESKRIPTOR, nicht auf
    # Pfaden. Der Grund ist ein reproduzierter Angriff: Die Auflösung im
    # Konstruktor ist eine Aussage über EINEN Zeitpunkt. Wer danach
    # ``objects/`` gegen einen Symlink tauscht, bekam Bytes an eine Stelle
    # geschrieben, für die niemand einsteht. Ein einmal geöffneter Deskriptor
    # zeigt auf die Inode, nicht auf den Namen — zwischen Prüfen und Schreiben
    # liegt dann kein Pfad mehr, den jemand austauschen könnte.

    def _make_dir(self) -> None:
        """Legt das Objektverzeichnis an, falls es fehlt. Kein ``chmod``.

        ``0700`` hat keine Gruppen- oder Andere-Bits, die umask kann daran
        nichts beschneiden. Ein bestehendes, zu weit geöffnetes Verzeichnis
        wird hier ABSICHTLICH nicht stillschweigend engegezogen: Das meldet
        :meth:`audit` als Befund, und ``init`` zieht es eng und sagt es
        (``CHANGED``). Ein Schreibpfad, der nebenbei Rechte ändert, verändert
        mehr, als er zusagt.
        """
        try:
            os.mkdir(self.objects, DIR_MODE)
        except FileExistsError:
            pass
        except FileNotFoundError:
            self.objects.parent.mkdir(parents=True, exist_ok=True)
            os.mkdir(self.objects, DIR_MODE)

    @contextmanager
    def _dir(self, create: bool = False) -> Iterator[int]:
        """Der Verzeichnisdeskriptor. ``O_DIRECTORY | O_NOFOLLOW``.

        ``O_NOFOLLOW`` scheitert, wenn die letzte Komponente ein Symlink ist —
        genau der Angriff. ``O_DIRECTORY`` scheitert, wenn dort inzwischen eine
        Datei liegt.
        """
        if create:
            self._make_dir()
        try:
            fd = os.open(self.objects, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise StoreOutsideRoot(
                    f"{self.objects} ist ein Symlink. Das Objektverzeichnis ist ein echtes "
                    "Verzeichnis in der Datenwurzel — ein Link führt aus dem Bereich hinaus, "
                    "für den dieses Werkzeug einsteht (ADR 0006). Es wurde nichts geschrieben."
                ) from exc
            if exc.errno == errno.ENOTDIR:
                raise StoreOutsideRoot(f"{self.objects} ist kein Verzeichnis.") from exc
            if isinstance(exc, FileNotFoundError):
                raise
            raise StoreError(f"Objektverzeichnis nicht zugänglich: {exc}") from exc
        try:
            yield fd
        finally:
            os.close(fd)

    @staticmethod
    def _fsync_dir(dir_fd: int) -> None:
        """Ohne das überlebt der neue Verzeichniseintrag keinen Stromausfall,
        obwohl die Datei es tut.

        Früher wurde hier JEDER Fehler verschluckt. Damit war die Zusage
        „übersteht einen Absturz" unprüfbar: Ein ``EIO`` sieht dann aus wie ein
        Dateisystem, das Verzeichnis-``fsync`` nicht kennt. Abgestuft wird nur
        das ausdrücklich Nichtunterstützte; I/O- und Platzfehler sind Fehler.
        """
        try:
            os.fsync(dir_fd)
        except OSError as exc:
            if exc.errno in (errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP, errno.EBADF):
                return  # Dateisystem kennt fsync auf Verzeichnissen nicht
            raise StoreWriteFailed(
                f"Der Verzeichniseintrag konnte nicht dauerhaft gemacht werden ({exc}). "
                "Das Objekt ist geschrieben, sein Name überlebt aber möglicherweise keinen "
                "Absturz. Das ist ein Befund und kein Detail."
            ) from exc

    @contextmanager
    def _opened(self, dir_fd: int, address: str) -> Iterator[tuple[int, os.stat_result]]:
        """Öffnet ein Objekt sicher, relativ zum Verzeichnisdeskriptor.

        ``O_NOFOLLOW`` ist die eigentliche Verteidigung gegen D2: Ein Symlink
        auf eine Datei *mit passendem Inhalt* würde jede Hashprüfung bestehen.
        Geprüft wird am Deskriptor (``fstat``), nicht am Pfad — zwischen einem
        ``lstat`` und einem späteren ``open`` läge ein Zeitfenster.
        """
        name = check_address(address)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dir_fd)
        except FileNotFoundError as exc:
            raise MissingObject(
                f"Objekt {address[:12]}… fehlt. Das Journal verweist auf Bytes, "
                "die im Speicher nicht liegen."
            ) from exc
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise UnsafeObject(
                    f"Objekt {address[:12]}… ist ein Symlink. Der Store liest nur, was "
                    "ihm gehört — auch wenn der Inhalt am Ziel zum Namen passte."
                ) from exc
            raise StoreError(f"Objekt {address[:12]}… nicht lesbar: {exc}") from exc
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise UnsafeObject(
                    f"Objekt {address[:12]}… ist keine reguläre Datei "
                    f"(Modus {stat.filemode(st.st_mode)})."
                )
            yield fd, st
        finally:
            os.close(fd)

    def _verify_at(self, dir_fd: int, address: str) -> ObjectInfo:
        with self._opened(dir_fd, address) as (fd, st):
            digest = self._digest(fd)
            if digest != address:
                raise CorruptObject(
                    f"Objekt {address[:12]}… trägt einen Namen, den sein Inhalt nicht "
                    f"deckt (tatsächlich {digest[:12]}…). Ein Store, der nur beim "
                    "Schreiben prüft, vertraut seinem eigenen Dateisystem."
                )
            return ObjectInfo(
                address=address,
                size=st.st_size,
                nlink=st.st_nlink,
                mode=stat.S_IMODE(st.st_mode),
            )

    # ------------------------------------------------------------ Lesen

    def verify(self, address: str) -> ObjectInfo:
        """Prüft ein Objekt vollständig und beschreibt es.

        Ersetzt ein ``contains()``: Das Ergebnis ist entweder eine Beschreibung
        oder ein benannter Fehler — nie ein Boolean, das drei verschiedene
        Sachverhalte in sich zusammenfallen lässt.
        """
        check_address(address)
        try:
            with self._dir() as dir_fd:
                return self._verify_at(dir_fd, address)
        except FileNotFoundError as exc:
            raise MissingObject(
                f"Objekt {address[:12]}… fehlt; es gibt noch kein Objektverzeichnis."
            ) from exc

    @contextmanager
    def open_verified(self, address: str) -> Iterator[BinaryIO]:
        """Prüft vollständig und gibt **denselben** Deskriptor zurückgespult heraus.

        Derselbe Deskriptor ist der Punkt. Ein zweites ``open`` nach der Prüfung
        wäre eine Lücke zwischen Prüfen und Lesen: Wer den Pfad in dieser Lücke
        austauscht, wird gelesen, nachdem sein Vorgänger geprüft wurde.
        """
        check_address(address)
        try:
            dir_ctx = self._dir()
            dir_fd = dir_ctx.__enter__()
        except FileNotFoundError as exc:
            raise MissingObject(
                f"Objekt {address[:12]}… fehlt; es gibt noch kein Objektverzeichnis."
            ) from exc
        try:
            with self._opened(dir_fd, address) as (fd, _st):
                digest = self._digest(fd)
                if digest != address:
                    raise CorruptObject(
                        f"Objekt {address[:12]}… trägt einen Namen, den sein Inhalt nicht "
                        f"deckt (tatsächlich {digest[:12]}…)."
                    )
                os.lseek(fd, 0, os.SEEK_SET)
                # ``closefd=False``: Der Deskriptor gehört weiterhin ``_opened``.
                with open(fd, "rb", closefd=False) as fh:
                    yield fh
        finally:
            dir_ctx.__exit__(None, None, None)

    @staticmethod
    def _digest(fd: int) -> str:
        os.lseek(fd, 0, os.SEEK_SET)
        h = hashlib.sha256()
        while chunk := os.read(fd, CHUNK):
            h.update(chunk)
        return h.hexdigest()

    # ---------------------------------------------------------- Schreiben

    def put(self, source: BinaryIO) -> str:
        """Legt Bytes ab und gibt ihre Adresse zurück. Streamend, nie am Stück.

        Das Publikationsprotokoll aus der Angriffsliste, Schritt für Schritt —
        alles relativ zum Verzeichnisdeskriptor, kein einziger Pfad:

        1. eindeutige Temporärdatei IM Objektverzeichnis, ``O_CREAT|O_EXCL`` —
           nicht ``<sha>.tmp``, sonst schreiben zwei Prozesse in dieselbe Datei
           (E1), und im selben Verzeichnis, weil ``link`` nicht über
           Dateisysteme geht
        2. blockweise schreiben und dabei hashen, dann ``fsync`` auf die Datei
        3. atomar publizieren OHNE Überschreiben: ``os.link`` schlägt bei
           vorhandenem Ziel mit ``EEXIST`` fehl. ``os.rename`` wäre falsch — es
           überschreibt stillschweigend
        4. bei ``EEXIST`` das vorhandene Ziel **prüfen**, nicht annehmen (E2)
        5. ``fsync`` auf das Verzeichnis
        """
        with self._dir(create=True) as dir_fd:
            tmp_name = f"{TEMP_PREFIX}{os.urandom(8).hex()}"
            fd = os.open(
                tmp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                OBJECT_MODE,
                dir_fd=dir_fd,
            )
            h = hashlib.sha256()
            try:
                os.fchmod(fd, OBJECT_MODE)  # unabhängig von der umask
                while True:
                    chunk = source.read(CHUNK)
                    if not chunk:
                        break
                    h.update(chunk)
                    self._write_all(fd, chunk, tmp_name)
                os.fsync(fd)
            except StoreError:
                raise
            except OSError as exc:
                # Die Temporärdatei bleibt ABSICHTLICH liegen: Sie ist der Beleg,
                # dass hier etwas abgebrochen ist. ``doctor`` meldet sie (E5).
                raise StoreWriteFailed(
                    f"Schreiben abgebrochen ({exc}). Die Temporärdatei {tmp_name} bleibt "
                    "als Beleg liegen; ein Torso trägt nie den finalen Namen."
                ) from exc
            finally:
                os.close(fd)

            address = h.hexdigest()
            try:
                os.link(tmp_name, address, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            except FileExistsError:
                # Schritt 4. „Liegt schon da" ist eine Behauptung, keine Prüfung.
                self._verify_at(dir_fd, address)  # wirft CorruptObject / UnsafeObject
                os.unlink(tmp_name, dir_fd=dir_fd)
                return address
            except OSError as exc:
                raise StoreWriteFailed(f"Publizieren fehlgeschlagen: {exc}") from exc
            os.unlink(tmp_name, dir_fd=dir_fd)
            self._fsync_dir(dir_fd)
            return address

    @staticmethod
    def _write_all(fd: int, data: bytes, tmp_name: str) -> None:
        """``os.write`` darf kurz schreiben. Ein ignorierter Rest wäre ein
        stiller Datenverlust mit korrekt berechnetem Hash."""
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:  # pragma: no cover — POSIX schließt das aus
                raise StoreWriteFailed(f"Schreiben lieferte {written} Bytes ({tmp_name}).")
            view = view[written:]

    # ------------------------------------------------------------ Pflege

    def _names(self) -> list[str]:
        """Alle Einträge, über den Deskriptor gelesen. Leer, wenn es das
        Verzeichnis nicht gibt — ein fehlender Store ist kein Fehler."""
        try:
            with self._dir() as dir_fd:
                return sorted(os.listdir(dir_fd))
        except FileNotFoundError:
            return []

    def stale_temporaries(self) -> list[Path]:
        """Liegengebliebene Temporärdateien — **gemeldet, nie gelöscht**.

        Automatisches Aufräumen war im Vorgängersystem der Weg, auf dem Befunde
        verschwanden. Löschen ist ein bewusster Akt eines Menschen. Die Pfade
        sind für genau diesen Menschen da; gearbeitet wird auf dem Deskriptor.
        """
        return [self.objects / n for n in self._names() if n.startswith(TEMP_PREFIX)]

    def object_names(self) -> list[str]:
        """Alle Einträge, die kein Temporärname sind — auch die ungültigen.

        Ungültige Namen werden bewusst mit zurückgegeben: Sie herauszufiltern
        hieße, den Befund verschwinden zu lassen, um den es geht (D5).
        """
        return [n for n in self._names() if not n.startswith(TEMP_PREFIX)]

    # ------------------------------------------------------------- Prüfung

    def check_referenced(self, addresses: Iterable[str]) -> list[str]:
        """Halten die Bytes, auf die sich das Journal beruft?

        Das ist die Richtung, die für einen Record zählt: Eine Referenz ins
        Leere ist ein Halt, auch wenn im Store sonst alles in Ordnung ist. Die
        Gegenrichtung — Objekte, die niemand referenziert — ist ausdrücklich
        **kein** Befund (A5); verwaiste Bytes sind harmlos, ihr stilles Löschen
        wäre es nicht.
        """
        findings: list[str] = []
        for address in sorted(set(addresses)):
            try:
                self.verify(address)
            except StoreError as exc:
                findings.append(str(exc))
        return findings

    def audit(self) -> StoreAudit:
        """Der ganze Store, von innen betrachtet — für ``doctor``.

        Die Trennung in ``findings`` und ``notes`` ist eine Dosierungsfrage und
        keine Kosmetik. Ein korruptes Objekt oder ein weltlesbares Interview ist
        ein Halt. Eine liegengebliebene Temporärdatei ist es nicht — sie ist die
        Spur eines Absturzes, die gemeldet und **nicht** weggeräumt gehört. Ein
        abgebrochener Schreibvorgang, der die ganze Arbeit blockiert, erzieht
        nur dazu, das Verzeichnis heimlich zu leeren.
        """
        findings: list[str] = []
        notes: list[str] = []
        try:
            dir_ctx = self._dir()
            dir_fd = dir_ctx.__enter__()
        except FileNotFoundError:
            return StoreAudit(findings=findings, notes=notes)

        try:
            mode = stat.S_IMODE(os.fstat(dir_fd).st_mode)
            if mode & 0o077:
                findings.append(
                    f"Das Objektverzeichnis ist für andere Benutzer zugänglich (Modus {mode:o}, "
                    "erwartet 700). Bei Oral-History-Material ist das die Weitergabe, die "
                    "keine Einwilligung deckt."
                )

            entries = sorted(os.listdir(dir_fd))
            for name in (n for n in entries if not n.startswith(TEMP_PREFIX)):
                try:
                    info = self._verify_at(dir_fd, name)
                except StoreError as exc:
                    findings.append(str(exc))
                    continue
                if info.too_permissive:
                    findings.append(
                        f"Objekt {name[:12]}… ist für andere Benutzer lesbar "
                        f"(Modus {info.mode:o}, erwartet 600)."
                    )
                if info.suspicious_links:
                    # Kein Befund: Ein Hardlink ist durch Pfadauflösung nicht
                    # erkennbar, und st_nlink > 1 hat harmlose Ursachen (D3).
                    notes.append(
                        f"Objekt {name[:12]}… hat {info.nlink} Namen. Das ist ungewöhnlich und "
                        "kein Beweis — geschützt hat hier das erneute Hashen."
                    )

            for name in (n for n in entries if n.startswith(TEMP_PREFIX)):
                notes.append(
                    f"Liegengebliebene Temporärdatei {name} — Spur eines abgebrochenen "
                    "Schreibvorgangs. Sie wird gemeldet und nicht gelöscht; das Löschen ist "
                    "ein bewusster Akt."
                )
        finally:
            dir_ctx.__exit__(None, None, None)
        return StoreAudit(findings=findings, notes=notes)
