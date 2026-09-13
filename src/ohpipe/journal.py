"""Das append-only Ereignisjournal — die kanonische Evidenz.

Alles, was passiert, ist ein Ereignis. Der Zustand des Systems ist das Ergebnis
eines Replays, kein gepflegtes Feld. Daraus folgt, was DINOH teuer gelernt hat:
es gibt keinen Zustand, der "repariert" werden kann und daher auch keinen, der
kaputtgehen kann.

Die Datei ist JSONL, jede Zeile ein Ereignis, jede Zeile hash-verkettet mit der
vorherigen. Eine nachträglich veränderte Zeile bricht die Kette sichtbar.

SQLite kommt später — ausschließlich als regenerierbarer Suchindex (ADR 008).
Wenn der Index verloren geht, ist das ein `rebuild`, kein Datenverlust.
"""

from __future__ import annotations

import errno
import fcntl
import hmac
import json
import os
import re
import stat as statmodul
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .domain.events import ENVELOPE_FIELDS, PayloadRejected, check_payload
from .domain.hashing import sha256_json

__all__ = ["ENV_KEY", "Event", "Journal", "JournalBroken", "PayloadRejected", "load_key"]

GENESIS = "0" * 64

#: Pfad auf eine Schlüsseldatei. Sie gehört bewusst NICHT in die Datenwurzel:
#: Sonst hätte, wer die Journaldatei schreiben darf, auch den Schlüssel — und
#: der Unterschied zwischen Integrität und Authentizität wäre wieder weg
#: (ADR 0016).
ENV_KEY = "OHPIPE_JOURNAL_KEY"


def load_key(root: Path | None = None) -> bytes | None:
    """Lädt den Journalschlüssel, falls einer gesetzt ist."""
    raw = os.environ.get(ENV_KEY)
    if not raw:
        return None
    p = Path(raw).expanduser().resolve()
    if root is not None:
        r = Path(root).resolve()
        if p == r or r in p.parents:
            raise JournalBroken(
                f"Der Journalschlüssel liegt in der Datenwurzel ({p}). Damit schützt er "
                "nichts: Wer die Journaldatei schreiben darf, hätte auch ihn."
            )
    try:
        data = p.read_bytes()
    except OSError as exc:
        raise JournalBroken(f"Journalschlüssel nicht lesbar: {exc}") from exc
    if len(data) < 16:
        raise JournalBroken("Journalschlüssel ist zu kurz (mindestens 16 Bytes).")
    return data


class JournalBroken(RuntimeError):
    """Die Hash-Kette des Journals ist gebrochen."""


#: Der Wortlaut des J1-Befunds. **Einzeilig und pfadfrei.**
#: Der Pfad steht in ``details["pfad"]``, nicht im Fliesstext: ein Reportfeld mit
#: einem Pfad darin ist genau die Zeile, die bei einem Wurzelnamen mit
#: Zeilenumbruch aus dem Sechszeiler einen Siebenzeiler macht.
UNSAFE_REASON = (
    "Der Journalpfad ist belegt, aber nicht durch eine reguläre Journaldatei. "
    "Es wurde nichts gelesen und nichts geschrieben."
)

#: Fehlerdomäne für J1 — **symbolisch, nie gegen Zahlen.**
#: ``errno.ELOOP`` ist auf Linux und Darwin dieselbe Konstante, aber nicht
#: dieselbe Zahl (40 gegen 62). Ein Vergleich gegen eine Zahl wäre auf der
#: jeweils anderen Plattform falsch — und zwar grün-falsch genau dort, wo er
#: nicht läuft. ``EMLINK`` steht als Netz für BSD-Varianten, die ein
#: ``O_NOFOLLOW`` so quittieren; es ist keine Aussage über einen bestimmten Kern.
UNSICHER_ERRNO = frozenset({errno.ELOOP, errno.EMLINK, errno.ENOTDIR, errno.ENXIO, errno.EISDIR})


class JournalUnsafe(JournalBroken):
    """Der Pfad ist belegt — nur nicht durch ein reguläres Journal.

    **Unterklasse von** ``JournalBroken``, damit jeder bestehende Aufrufer
    fail-closed bleibt: wer heute ``except JournalBroken`` schreibt, hält auch
    beim Symlink an, ohne dass er dafür angefasst werden muss. Wer den Fall
    unterscheiden will, fängt vorher ``JournalUnsafe`` — und diese Reihenfolge
    ist der Grund, warum es überhaupt zwei Klassen sind.

    Der beanstandete Pfad hängt an der Ausnahme statt in der Meldung. Er ist
    **nicht** immer der Endpunkt: liegt der Link am Elternverzeichnis, ist das
    Elternverzeichnis der Befund, und der Operator soll den lesen, den er
    anfassen muss.
    """

    def __init__(self, pfad: Path, ursache: str = "") -> None:
        super().__init__(UNSAFE_REASON)
        self.pfad = Path(pfad)
        #: Symbolischer Fehlername (``ELOOP``, ``EISDIR``, ``nicht-S_ISREG``, …).
        #: Nur für Diagnose — nie im ``reason``, weil er dort nichts erklärt und
        #: die Zeile plattformabhängig machen würde.
        self.ursache = ursache


@dataclass(frozen=True)
class Event:
    seq: int
    at: str
    kind: str
    record_id: str | None
    payload: dict[str, Any]
    prev: str
    operation_intent_sha256: str | None = None
    #: Hash über (seq, at, kind, record_id, payload, prev)
    digest: str = field(default="")

    @staticmethod
    def compute_digest(
        seq: int,
        at: str,
        kind: str,
        record_id: str | None,
        payload: dict[str, Any],
        prev: str,
        key: bytes | None = None,
        operation_intent_sha256: str | None = None,
    ) -> str:
        body = {
            "seq": seq,
            "at": at,
            "kind": kind,
            "record_id": record_id,
            "payload": payload,
            "prev": prev,
        }
        if operation_intent_sha256 is not None:
            body["operation_intent_sha256"] = operation_intent_sha256
        if key is None:
            return sha256_json(body)
        blob = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hmac.new(key, blob.encode("utf-8"), "sha256").hexdigest()

    def to_json(self) -> dict[str, Any]:
        # Die Feldliste steht in domain/events.ENVELOPE_FIELDS, nicht hier.
        # Vorher zählten `to_json` und `from_json` dieselben sieben Namen
        # unabhängig voneinander auf: Wer eines ergänzt und das andere vergisst,
        # schreibt ein Feld, das beim Lesen verschwindet — und die Hashprüfung
        # bestätigt beide Fassungen, weil jede für sich stimmig ist.
        out = {name: getattr(self, name) for name in ENVELOPE_FIELDS}
        if self.operation_intent_sha256 is not None:
            out["operation_intent_sha256"] = self.operation_intent_sha256
        return out

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> Event:
        """Prüft Anwesenheit UND Typ jedes Feldes.

        Eine korrekt verkettete Zeile mit ``payload: [1]`` bestand sonst die
        Hashprüfung und stürzte erst im Replay ab — also ein Traceback zwei
        Schichten von der Stelle entfernt, an der der Fehler lag.
        """
        allowed = set(ENVELOPE_FIELDS) | {"operation_intent_sha256"}
        if set(raw) - allowed:
            raise ValueError(f"fremde Huellenfelder: {sorted(set(raw) - allowed)}")
        werte: dict[str, Any] = {}
        for name, (typ, optional) in ENVELOPE_FIELDS.items():
            if name not in raw:
                raise ValueError(f"Pflichtfeld {name!r} fehlt")
            v = raw[name]
            if optional and v is None:
                werte[name] = None
                continue
            # `bool` ist in Python eine `int`-Unterklasse: ohne diesen Zusatz
            # ginge `seq: true` als gültige Sequenznummer durch.
            if (isinstance(v, bool) and typ is int) or not isinstance(v, typ):
                raise ValueError(f"{name!r} ist {type(v).__name__}, erwartet {typ.__name__}")
            werte[name] = v
        operation_intent_sha256 = raw.get("operation_intent_sha256")
        if operation_intent_sha256 is not None and (
            not isinstance(operation_intent_sha256, str)
            or re.fullmatch(r"[0-9a-f]{64}", operation_intent_sha256) is None
        ):
            raise ValueError("operation_intent_sha256 ist kein voller ASCII-Kleinhex-sha256")
        return cls(**werte, operation_intent_sha256=operation_intent_sha256)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Journal:
    """Append-only, hash-verkettet, ein Prozess schreibt.

    Bewusst KEIN Lösch- oder Update-Pfad. Ein Widerruf ist ein neues Ereignis,
    kein entferntes.
    """

    def __init__(self, path: Path, key: bytes | None = None) -> None:
        self.path = Path(path)
        self.key = key
        #: Gemerkter Kopf (seq, prev) — NUR gültig, solange dieses Objekt der
        #: letzte Schreiber war. Siehe ``_head_locked``.
        self._kopf: tuple[int, str] | None = None

    @property
    def integrity(self) -> str:
        """``keyed`` oder ``unkeyed`` — der Unterschied ist kein Detail."""
        return "keyed" if self.key else "unkeyed"

    # -- Die eine Oeffnung ------------------------------------------------

    @property
    def _lockpfad(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".lock")

    @contextmanager
    def _elternverzeichnis(self, *, pflicht: bool) -> Iterator[int | None]:
        """Der Deskriptor des Elternverzeichnisses. ``O_DIRECTORY | O_NOFOLLOW``.

        Ohne diese Prüfung schützt ``O_NOFOLLOW`` am Dateinamen nichts: der
        Angreifer hängt den Link eine Ebene höher, und der Endpunkt ist dann ein
        völlig regulärer Name in einem fremden Verzeichnis. ``O_DIRECTORY``
        scheitert zusätzlich, wenn dort inzwischen eine Datei liegt.

        ``pflicht`` trennt die beiden Bedeutungen von ``ENOENT``: beim **Lesen**
        ist ein fehlendes Elternverzeichnis *pristine* — es gibt schlicht kein
        Journal, und das ist kein Befund. Beim **Schreiben** ist es einer, denn
        der Schreibpfad legt nichts mehr an: wer sein Elternverzeichnis selbst
        anlegt, legt es auch durch einen Symlink an. Das Anlegen gehört
        ``Workspace.ensure()``, und nur dorthin.
        """
        eltern = self.path.parent
        try:
            fd = os.open(eltern, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except FileNotFoundError as exc:
            if pflicht:
                raise JournalUnsafe(eltern, "ENOENT") from exc
            yield None
            return
        except OSError as exc:
            if exc.errno in UNSICHER_ERRNO:
                raise JournalUnsafe(eltern, errno.errorcode.get(exc.errno, "")) from exc
            raise
        try:
            yield fd
        finally:
            os.close(fd)

    def _roh_oeffne(self, dir_fd: int, name: str, flags: int, *, pfad: Path) -> int:
        """Die rohe Öffnung samt Abbildung der Fehlerdomäne — **ohne** Retry.

        Ausgelagert, damit der eine Wiederholversuch in ``_oeffne`` denselben
        Aufruf ein zweites Mal macht statt einen zweiten, leicht anderen. Zwei
        Öffnungen, die auseinanderlaufen können, wären genau die Art stiller
        Lücke, gegen die J1 geschrieben ist.

        ``FileNotFoundError`` geht unverändert nach oben: ob ``ENOENT`` ein
        Nichtzustand oder ein Befund ist, entscheidet allein ``_oeffne`` — hier
        ist es weder das eine noch das andere.
        """
        try:
            return os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=dir_fd)
        except FileNotFoundError:
            raise
        except OSError as exc:
            if exc.errno in UNSICHER_ERRNO:
                raise JournalUnsafe(pfad, errno.errorcode.get(exc.errno, "")) from exc
            raise

    def _oeffne(self, dir_fd: int, name: str, flags: int, *, pfad: Path) -> int:
        """Die **eine** Stelle, an der J1 einen Endpunkt öffnet.

        Drei Zusagen in einer Primitive, und alle drei mutieren gemeinsam:

        * ``O_NOFOLLOW`` — der Link am Namen wird nicht verfolgt.
        * ``O_NONBLOCK`` — eine FIFO ohne Gegenstelle blockiert das Öffnen sonst
          unbegrenzt. Ein hängender Lauf ist kein Befund, sondern ein Ausfall;
          mit dem Flag quittiert der Kern mit einem Fehler aus der Domäne.
        * ``fstat`` + ``S_ISREG`` — geprüft wird am **geöffneten Objekt**, nie am
          Pfad. Zwischen einem ``lstat`` und einem späteren ``open`` läge genau
          das Zeitfenster, das J1 schliesst.

        Der Name wird relativ zu ``dir_fd`` geöffnet, nicht absolut: sonst würde
        der Pfad ein zweites Mal aufgelöst, und die eben geprüfte
        Verzeichniskomponente könnte inzwischen eine andere sein.

        **Der eine Wiederholversuch.** Auf Darwin scheitert die gleichzeitige
        *Erstanlage* desselben Namens über ``openat``/``dir_fd`` mit ``ENOENT``,
        lange bevor ``flock`` erreicht ist: 100/100 Läufe mit 30 gleichzeitigen
        Schreibern. Unter Linux 0/3000 Öffnungen. Deshalb — und nur deshalb —
        darf eine **erzeugende** Öffnung ihren ersten ``ENOENT`` genau einmal
        wiederholen, mit demselben Namen, denselben Flags, demselben Modus und
        vor allem demselben bereits geprüften ``dir_fd``.

        Zwei Grenzen halten den Versuch klein:

        * **Nur mit ``O_CREAT``.** Ohne das Flag behält die Öffnung ihre
          Missing-Semantik: ein fehlendes Journal und eine fehlende Lockdatei im
          reinen Leseweg bleiben *pristine* und werden nicht durch einen Retry
          in einen Befund umgedeutet.
        * **Genau einer.** Kein Sleep, kein Backoff, keine Schleife. Scheitert
          auch der zweite Versuch, ist das ein Befund.

        Zusätzliche fail-closed Wurzelprobe: Kann ``"."`` am bereits verankerten
        ``dir_fd`` nicht mehr gelesen werden, wird nicht wiederholt. In der
        gemessenen Fehlerdomäne hat diese Probe keinen natürlichen Auslöser —
        ein offener ``dir_fd`` hält den Inode, ``stat(".")`` gelingt auf Darwin
        wie auf Linux auch nach ``rmdir`` des Elternverzeichnisses. Sie ist ein
        zusätzlicher Wächter für den Fall, dass selbst ``stat(".")`` scheitert,
        und wird nur injiziert geprüft. Begrenzt wird der Retry durch
        ``O_CREAT`` und genau einen zweiten Versuch.

        Ehrliche Abgrenzung: „nie mehr als der zweite Versuch nötig" ist eine
        Messung über 100 Läufe, **keine Kernelgarantie**. Das Restrisiko ist ein
        seltener, unnötiger ``STOP_JOURNAL_UNSAFE`` unter hoher Nebenläufigkeit.
        Fail-closed ist die richtige Richtung, aber der zweite Fehlschlag wird
        als Befund gemeldet, auch wenn er in der Messung nie auftrat.
        """
        try:
            fd = self._roh_oeffne(dir_fd, name, flags, pfad=pfad)
        except FileNotFoundError:
            if not flags & os.O_CREAT:
                raise
            try:
                os.stat(".", dir_fd=dir_fd)
            except OSError as wurzel:
                raise JournalUnsafe(pfad, "ENOENT") from wurzel
            try:
                fd = self._roh_oeffne(dir_fd, name, flags, pfad=pfad)
            except FileNotFoundError as zweiter:
                raise JournalUnsafe(pfad, "ENOENT") from zweiter
        try:
            if not statmodul.S_ISREG(os.fstat(fd).st_mode):
                raise JournalUnsafe(pfad, "nicht-S_ISREG")
        except BaseException:
            os.close(fd)
            raise
        return fd

    # -- Lesen ------------------------------------------------------------

    @staticmethod
    def _aus_datei(fh: Any) -> Iterator[Event]:
        """Jeder Lese-, Parse- oder Schemafehler wird zu ``JournalBroken``.

        Grund: `status` und `doctor` sollen bei beschädigter Evidenz den
        D-1-Wortlaut und den Vierzeiler ausgeben — nicht einen Traceback. Ein
        `JSONDecodeError`, der bis in die Fronttür durchschlägt, ist genau die
        Sorte Fehlermeldung, die man nachts um elf nicht deuten kann.
        """
        for n, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise JournalBroken(f"Zeile {n} ist kein gültiges JSON: {exc}") from exc
            except OSError as exc:
                raise JournalBroken(f"Lesefehler in Zeile {n}: {exc}") from exc
            if not isinstance(raw, dict):
                raise JournalBroken(f"Zeile {n} ist kein Objekt, sondern {type(raw).__name__}")
            try:
                yield Event.from_json(raw)
            except (KeyError, TypeError, ValueError) as exc:
                raise JournalBroken(
                    f"Zeile {n}: Pflichtfeld fehlt oder passt nicht ({exc})"
                ) from exc

    def __iter__(self) -> Iterator[Event]:
        """Lesen über die Primitive. Fehlt das Journal, ist das kein Befund."""
        with self._elternverzeichnis(pflicht=False) as dfd:
            if dfd is None:
                return
            try:
                fd = self._oeffne(dfd, self.path.name, os.O_RDONLY, pfad=self.path)
            except FileNotFoundError:
                return
            except JournalUnsafe:
                raise
            except OSError as exc:
                raise JournalBroken(f"Journal nicht lesbar: {exc}") from exc
        with os.fdopen(fd, "r", encoding="utf-8") as fh:
            yield from self._aus_datei(fh)

    def _am_deskriptor(self, fd: int) -> Iterator[Event]:
        """Vollständig lesen, **ohne den Pfad noch einmal anzufassen**.

        Die Kopie ist nötig, weil ``fdopen`` beim Schliessen den Deskriptor
        mitnimmt — und der gehört der Sperre, nicht diesem Lesevorgang.
        """
        kopie = os.dup(fd)
        os.lseek(kopie, 0, os.SEEK_SET)
        with os.fdopen(kopie, "r", encoding="utf-8") as fh:
            yield from self._aus_datei(fh)

    def events(self, *, record_id: str | None = None, kind: str | None = None) -> list[Event]:
        return [
            e
            for e in self
            if (record_id is None or e.record_id == record_id) and (kind is None or e.kind == kind)
        ]

    def head(self) -> tuple[int, str]:
        """Liest die ganze Datei. Read-only und immer korrekt."""
        seq, prev = 0, GENESIS
        for e in self:
            seq, prev = e.seq, e.digest
        return seq, prev

    def _head_locked(self, fd: int) -> tuple[int, str]:
        """Der Kopf unter gehaltener Sperre — mit gemerktem Wert.

        ``head()`` liest die vollständige Datei. Beim Anhängen von N Ereignissen
        in einem Lauf — genau das tut ``ingest`` je Record — ergibt das O(n²):
        Der 500. Cue liest 499 Zeilen, bevor er eine schreibt. Das ist der
        Unterschied zwischen einem Ingest von einer Sekunde und einem von
        Minuten, und er wächst mit dem Korpus.

        Der gemerkte Wert ist **nur** gültig, wenn seit dem letzten eigenen
        Schreiben niemand sonst angehängt hat. Das prüft die Dateigröße: Sie
        wächst monoton (append-only) und ändert sich bei jedem fremden Schreiben.
        Passt sie nicht, wird vollständig gelesen. Ein Fehler in die falsche
        Richtung ist hier nicht tolerierbar — ein falsches ``prev`` bricht die
        Kette, und ein Kettenbruch sieht aus wie Manipulation.

        **J5: die Größe kommt vom geöffneten Deskriptor, nicht vom Pfad.**
        ``path.stat()`` beschreibt, worauf der Pfad *jetzt* zeigt; ``fstat(fd)``
        beschreibt genau das Objekt, in das gleich geschrieben wird. Zwischen
        beidem liegt ein Fenster, in dem der Pfad ein anderer werden kann — der
        gemerkte Kopf gälte dann für eine fremde Datei, und die Kette bräche
        gegen ein ``prev``, das nie zu ihr gehört hat.
        """
        groesse = os.fstat(fd).st_size
        if self._kopf is not None and groesse == self._groesse_nach_schreiben:
            return self._kopf
        seq, prev = 0, GENESIS
        for e in self._am_deskriptor(fd):
            seq, prev = e.seq, e.digest
        self._kopf = (seq, prev)
        self._groesse_nach_schreiben = groesse
        return self._kopf

    #: Dateigröße unmittelbar nach dem letzten eigenen Schreiben. Weicht die
    #: tatsächliche Größe ab, hat jemand anders angehängt und der gemerkte
    #: Kopf ist wertlos.
    _groesse_nach_schreiben: int = -1

    def pruefe_lockpfad(self) -> None:
        """Prüft den Lockpfad, **ohne zu sperren und ohne anzulegen**.

        Warum ein reiner Lesebefehl das überhaupt tut: ein Link am Lockpfad
        beschädigt nichts. Er verschiebt die Sperre auf einen fremden Inode und
        hebt damit lautlos die Serialisierung auf, für die es sie gibt — gemessen
        läuft ein ``ingest`` darüber vollständig durch und meldet seinen normalen
        Ausgang. Ein Zustand, den nur der Schreibweg bemerkt, ist ein Zustand,
        den der Operator nie erfährt; ``doctor`` und ``status`` sind genau die
        Stelle, an der er ihn erfahren soll.

        ``O_CREAT`` steht hier ausdrücklich **nicht**: ein Lesebefehl, der die
        Lockdatei anlegt, hinterlässt einen Rückstand — und der Vertrag sagt für
        diese Pfade ``changed == []``. Fehlt die Lockdatei, ist das kein Befund;
        sie entsteht beim ersten Schreiben.
        """
        with self._elternverzeichnis(pflicht=False) as dfd:
            if dfd is None:
                return
            try:
                fd = self._oeffne(dfd, self._lockpfad.name, os.O_RDONLY, pfad=self._lockpfad)
            except FileNotFoundError:
                return
            os.close(fd)

    def verified_events(self) -> list[Event]:
        """Genau den zurückgegebenen Snapshot prüfen, ohne zweiten Lesevorgang."""
        events = list(self)
        self._verify_events(events)
        return events

    def verify(self) -> None:
        """Prüft die Kette vollständig. Read-only, wirft bei Bruch."""
        self._verify_events(self)

    def _verify_events(self, events) -> None:
        expected_seq, prev = 1, GENESIS
        for e in events:
            if e.seq != expected_seq:
                raise JournalBroken(f"Sequenzlücke: erwartet {expected_seq}, gefunden {e.seq}")
            if e.prev != prev:
                raise JournalBroken(f"Kettenbruch bei seq={e.seq}: prev passt nicht")
            want = Event.compute_digest(
                e.seq,
                e.at,
                e.kind,
                e.record_id,
                e.payload,
                e.prev,
                self.key,
                e.operation_intent_sha256,
            )
            if want != e.digest:
                raise JournalBroken(f"Inhalt bei seq={e.seq} wurde nachträglich verändert")
            expected_seq, prev = e.seq + 1, e.digest

    # -- Schreiben --------------------------------------------------------

    @contextmanager
    def _exclusive(self, *, blocking=True):
        """Sperrt das Journal für Lesen-des-Kopfes UND Anhängen.

        ``O_APPEND`` allein genügt NICHT: Es macht das Schreiben atomar, aber
        nicht die Vergabe der Sequenznummer. Zwei Prozesse lesen denselben Kopf,
        vergeben beide ``seq+1`` und verketten beide gegen dasselbe ``prev`` —
        die Kette ist danach gebrochen, und zwar auf eine Weise, die wie
        Manipulation aussieht. Bei 30 gleichzeitigen Schreibern brach sie in
        5 von 5 Läufen.

        Die Sperre liegt auf einer eigenen Datei, damit sie nicht selbst Teil
        der Evidenz ist. Sie geht durch **dieselbe** Primitive wie der Endpunkt:
        eine Sperre auf einem fremden Inode ist keine Sperre. Sie beschädigt
        nichts — geschrieben wird in die Lockdatei nie —, sie hebt lautlos die
        Serialisierung auf, für die es sie gibt. Bei 30 gleichzeitigen Schreibern
        brach die Kette dann in 5 von 5 Läufen.

        Angelegt wird hier **nichts** mehr. Der frühere ``mkdir(parents=True)``
        legte das Elternverzeichnis notfalls durch einen Symlink an und schuf
        damit genau den Zustand, den J1 als Befund führt.

        Herausgereicht wird der Deskriptor des Journals, nicht ein Pfad: alles,
        was unter der Sperre passiert — Kopf lesen, Duplikat prüfen, anhängen —
        arbeitet an diesem einen Objekt. Ein zweites Auflösen des Pfades gäbe es
        nicht, also auch kein Fenster dazwischen.
        """
        with self._elternverzeichnis(pflicht=True) as dfd:
            lock_fd = self._oeffne(
                dfd, self._lockpfad.name, os.O_WRONLY | os.O_CREAT, pfad=self._lockpfad
            )
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
                fd = self._oeffne(
                    dfd,
                    self.path.name,
                    os.O_RDWR | os.O_CREAT | os.O_APPEND,
                    pfad=self.path,
                )
                try:
                    yield fd
                finally:
                    os.close(fd)
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)

    @contextmanager
    def transaction(self, *, blocking=True):
        """Verifizierter Snapshot und internes Anhängen unter derselben Sperre.

        Sperrreihenfolge für beteiligte Schreiber: Workspace, dann Journal.
        Wer nur Journal schreibt, nimmt ausschließlich diese Journalsperre.
        Keine Terminalwartezeit, Modellarbeit oder Ableitung im Kontext.
        """
        with self._exclusive(blocking=blocking) as fd:
            events = list(self._am_deskriptor(fd))
            self._verify_events(events)
            transaction = _JournalTransaction(self, fd, events)
            try:
                yield transaction
            finally:
                transaction.close()

    def append_once(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        record_id: str | None = None,
        duplikat: Callable[[Event], bool] | None = None,
        operation_intent_sha256: str | None = None,
    ) -> Event | None:
        """Hängt an, falls es diese Ereignisart noch nicht gibt.

        Prüfung UND Schreiben liegen in derselben Sperre. Ohne das schrieben
        fünf gleichzeitige `init`-Aufrufe fünf `workspace.initialised` —
        die Kette blieb heil, die Operation war aber nicht idempotent.

        ``duplikat`` verschiebt die Frage „gibt es das schon?" von der
        Ereignisart auf die Nutzlast. Ohne sie gilt: dieselbe Art für denselben
        Record ist ein Duplikat. Mit ihr entscheidet der Aufrufer — für
        ``source.ingested`` etwa der Hash der Bytes, nicht der Dateiname.

        Sie ist der Grund, warum es diesen Parameter überhaupt gibt: ``ingest``
        hatte seine Duplikatsprüfung als Listenausdruck VOR dem ``append``
        stehen, also ausserhalb der Sperre. Sequenziell war das idempotent,
        nebenläufig nicht — acht gleichzeitige Aufrufe schrieben acht Mal, die
        Kette blieb dabei heil und ``doctor`` meldete READY. Eine
        Prüfen-dann-Handeln-Folge über eine Sperrgrenze hinweg ist keine
        Prüfung; sie ist eine Vermutung mit gutem Timing.
        """
        check_payload(kind, payload, record_id)
        with self._exclusive() as fd:
            for e in self._am_deskriptor(fd):
                if e.kind != kind or e.record_id != record_id:
                    continue
                if duplikat is None or duplikat(e):
                    return None
            return self._append_locked(
                fd,
                kind,
                payload,
                record_id=record_id,
                operation_intent_sha256=operation_intent_sha256,
            )

    def append(
        self,
        kind: str,
        payload: dict[str, Any],
        *,
        record_id: str | None = None,
        operation_intent_sha256: str | None = None,
    ) -> Event:
        # VOR der Sperre. Eine abgelehnte Nutzlast soll keine Sperre halten und
        # keinen Endpunkt anlegen — `_exclusive` oeffnet mit `O_CREAT`.
        check_payload(kind, payload, record_id)
        with self._exclusive() as fd:
            return self._append_locked(
                fd,
                kind,
                payload,
                record_id=record_id,
                operation_intent_sha256=operation_intent_sha256,
            )

    def _append_locked(
        self,
        fd: int,
        kind: str,
        payload: dict[str, Any],
        *,
        record_id: str | None = None,
        operation_intent_sha256: str | None = None,
    ) -> Event:
        seq, prev = self._head_locked(fd)
        at = _now()
        seq += 1
        digest = Event.compute_digest(
            seq,
            at,
            kind,
            record_id,
            payload,
            prev,
            self.key,
            operation_intent_sha256,
        )
        ev = Event(
            seq=seq,
            at=at,
            kind=kind,
            record_id=record_id,
            payload=payload,
            prev=prev,
            operation_intent_sha256=operation_intent_sha256,
            digest=digest,
        )
        line = json.dumps(ev.to_json(), ensure_ascii=False, sort_keys=True) + "\n"
        # O_APPEND + fsync: ein abgebrochener Lauf hinterlässt keine halbe Zeile.
        # Der Deskriptor kommt aus `_exclusive` und ist derselbe, an dem eben der
        # Kopf gelesen wurde — kein zweites Auflösen des Pfades.
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
        # Erst NACH fsync merken. Bricht das Schreiben ab, bleibt der
        # gemerkte Kopf ungültig und der nächste Lauf liest vollständig.
        self._kopf = (ev.seq, ev.digest)
        self._groesse_nach_schreiben = os.fstat(fd).st_size
        return ev


class _JournalTransaction:
    """Nur innerhalb Journal.transaction verwendbarer Schreiber ohne erneutes flock."""

    def __init__(self, journal, fd, events):
        self._journal = journal
        self._fd = fd
        self._events = events
        self.path = journal.path
        self.key = journal.key

    def close(self):
        self._fd = None

    def _require_open(self):
        if self._fd is None:
            raise RuntimeError("Journaltransaktion ist geschlossen")

    def __iter__(self):
        self._require_open()
        return iter(tuple(self._events))

    def append_once(
        self, kind, payload, *, record_id=None, duplikat=None, operation_intent_sha256=None
    ):
        self._require_open()
        check_payload(kind, payload, record_id)
        for event in self._events:
            if (
                event.kind == kind
                and event.record_id == record_id
                and (duplikat is None or duplikat(event))
            ):
                return None
        event = self._journal._append_locked(
            self._fd,
            kind,
            payload,
            record_id=record_id,
            operation_intent_sha256=operation_intent_sha256,
        )
        self._events.append(event)
        return event
