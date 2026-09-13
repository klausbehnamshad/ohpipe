"""Der eine sichere Weg, Bytes NEBEN den Datenbaum zu legen.

Zwei Stellen schreiben eine Datei dorthin, wo ein Mensch sie erwartet: die
Mappingvorlage (``src/ohpipe/application/transcript_language.py::export_language_template``) und das
Katalogbundle (``src/ohpipe/application/export.py::write_export``). Beide muessen dasselbe koennen,
und zwar genau: nicht in eine produktverwaltete Wurzel schreiben (ADR 0006),
keinen bestehenden Namen ueberschreiben, keinem Symlink folgen, erst schreiben
und fsyncen, dann unter dem Zielnamen sichtbar machen, und am Ende die
sichtbaren Bytes gegen den Plan lesen.

Als zweite Kopie waere das die Stelle, an der eine der beiden Fassungen still
abweicht: das ``O_NOFOLLOW`` fehlt, der ``fsync`` auf das Verzeichnis
entfaellt, die Nachlese wird weggelassen. Deshalb steht die Mechanik hier
einmal, und die Aufrufer uebersetzen nur ihr Ergebnis in ihre eigenen
Meldungsbausteine — der Vertrag jedes Aufrufers bleibt seiner.

Der Zustand nach einem Fehler ist Teil der Auskunft: ``published`` sagt, ob der
Zielname schon sichtbar geworden ist. Ein Aufrufer, der das nicht
unterscheidet, meldet einen halben Schreibvorgang als gescheitert und laesst
eine Datei stehen, von der niemand mehr weiss.
"""

from __future__ import annotations

import errno
import os
import stat
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

__all__ = ["PublishOutcome", "check_target", "publish_bytes"]


@dataclass(frozen=True)
class PublishOutcome:
    """Was aus dem Schreibversuch geworden ist, ohne Meldungstext.

    ``state`` ist eines von ``WRITTEN`` (Zielname sichtbar, Bytes nachgelesen),
    ``TARGET_EXISTS`` (der Name war belegt, vorher geprueft oder konkurrierend
    aufgetaucht; nichts ueberschrieben), ``FAILED`` (nichts sichtbar geworden)
    und ``UNCERTAIN`` (der Zielname ist sichtbar, der Abschluss aber nicht
    belegt). ``detail`` traegt den Ausnahmetext, sonst die leere Zeichenkette.
    """

    state: str
    detail: str = ""
    raced: bool = False
    existing_matches: bool = False

    @property
    def published(self) -> bool:
        return self.state in {"WRITTEN", "UNCERTAIN"}


def _outside_managed(parent: Path, managed_roots: tuple[Path, ...]) -> bool:
    resolved_parent = parent.resolve(strict=True)
    for root in managed_roots:
        resolved_root = root.resolve(strict=False)
        if resolved_parent == resolved_root or resolved_root in resolved_parent.parents:
            return False
    return True


def check_target(output: Path, managed_roots: tuple[Path, ...]) -> tuple[Path | None, str, str]:
    """Prueft die Ausgabelage, ohne zu schreiben.

    Zurueck kommt ``(parent, "", "")``, oder ``None`` mit einer Art und ihrem
    Grund: ``PARTS`` fuer einen Pfad mit leerer, Punkt- oder Elternkomponente,
    ``UNSAFE`` fuer eine Lage, die sich nicht als sicher beweisen laesst. Die
    ART kommt von hier, der SATZ vom Aufrufer: die Meldungsbausteine gehoeren
    zu seinem Vertrag, nicht zu dieser Mechanik.

    Getrennt von :func:`publish_bytes`, weil die Aufrufer zwischen Lagepruefung
    und Schreibvorgang noch eigene Arbeit haben und ihre Reihenfolge behalten
    sollen: erst die Lage, dann der Inhalt.
    """
    if any(part in {"", ".", ".."} for part in Path(output).parts):
        return None, "PARTS", ""
    try:
        parent = Path(output).parent.resolve(strict=True)
        if not _outside_managed(parent, managed_roots):
            raise ValueError("Ausgabeparent liegt in einer produktverwalteten Wurzel")
    except (OSError, ValueError) as exc:
        return None, "UNSAFE", str(exc)
    return parent, "", ""


def _existing_matches(dir_fd: int, name: str, body: bytes) -> bool:
    """Wiederanlauf: vorhandene reguläre Datei prüfen, ohne Links/FIFOs zu folgen."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        with os.fdopen(fd, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                return False
            return handle.read(len(body) + 1) == body
    except OSError:
        return False


def publish_bytes(body: bytes, output: Path, *, parent: Path, temp_prefix: str) -> PublishOutcome:
    """Legt ``body`` unter ``output`` ab, ohne Overwrite und ohne Symlinkfolge.

    ``parent`` ist das bereits aufgeloeste Elternverzeichnis aus
    :func:`check_target`; es wird als Verzeichnisdeskriptor gehalten, damit
    zwischen Pruefung und Schreibvorgang kein Pfadbestandteil ausgetauscht
    werden kann.
    """
    output = Path(output)
    dir_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temp_name = f"{temp_prefix}{os.urandom(8).hex()}"
    temp_fd = -1
    published = False
    try:
        try:
            os.stat(output.name, dir_fd=dir_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            return PublishOutcome(
                "TARGET_EXISTS", existing_matches=_existing_matches(dir_fd, output.name, body)
            )
        temp_fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=dir_fd,
        )
        view = memoryview(body)
        while view:
            count = os.write(temp_fd, view)
            view = view[count:]
        os.fsync(temp_fd)
        temp_stat = os.fstat(temp_fd)
        if not stat.S_ISREG(temp_stat.st_mode):
            raise OSError(errno.EINVAL, "Tempziel ist nicht regulaer")
        os.link(temp_name, output.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        published = True
        os.fsync(dir_fd)
        os.unlink(temp_name, dir_fd=dir_fd)
        os.fsync(dir_fd)
        with open(
            output.name,
            "rb",
            opener=lambda name, flags: os.open(name, flags | os.O_NOFOLLOW, dir_fd=dir_fd),
        ) as handle:
            if handle.read() != body:
                raise OSError(errno.EIO, "Zielbytes weichen vom Plan ab")
        return PublishOutcome("WRITTEN")
    except FileExistsError:
        return PublishOutcome(
            "TARGET_EXISTS",
            raced=True,
            existing_matches=_existing_matches(dir_fd, output.name, body),
        )
    except OSError as exc:
        return PublishOutcome("UNCERTAIN" if published else "FAILED", str(exc))
    finally:
        if temp_fd >= 0:
            os.close(temp_fd)
        with suppress(OSError):
            os.unlink(temp_name, dir_fd=dir_fd)
        os.close(dir_fd)
