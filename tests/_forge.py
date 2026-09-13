"""Werkzeug für Fälschungstests — kein Testmodul.

Die Hashkette hier von Hand nachzurechnen ist der Kern jedes Fälschungstests
(ADR 0015): Ein Angreifer mit Schreibzugriff rechnet sie selbstverständlich
nach, und ein Test, der eine offensichtlich kaputte Kette anhängt, prüft nur
den Kettenprüfer.

Diese Arithmetik stand zweimal gleich in zwei Dateien. Das ist die gefährliche
Sorte Duplikat: Ändert sich die Digestbildung, verrottet eine Kopie still — und
die Tests dieser Kopie bleiben grün, weil sie dann gegen ein Journalformat
fälschen, das es nicht mehr gibt. Deshalb liegt sie hier einmal.
"""

from __future__ import annotations

import hmac
import json
import os
import subprocess
import sys
from pathlib import Path

from ohpipe.domain.hashing import sha256_json

REPO = Path(__file__).resolve().parents[1]
GENESIS = "0" * 64
DEFAULT_RECORD = "SANDBOX-001"


def cli(*args: str, root: Path, key: Path | None = None) -> subprocess.CompletedProcess:
    """Das echte Produkt, über die echte Grenze — als Unterprozess.

    Die Umgebung ist bewusst klein: Wer den Test liest, sieht genau, worauf das
    Werkzeug zugreifen kann.

    **Die kleine Umgebung hatte eine unbemerkte Nebenwirkung.** 45 Angriffe
    laufen über diesen Aufruf, und keiner davon meldete Coverage zurück — die
    Messung sah nur den Elternprozess. ``cli/main.py`` stand mit 18 %, und das
    war keine Aussage über den Operatorvertrag, sondern gar keine Aussage.

    Deshalb wird ``COVERAGE_PROCESS_START`` **nur dann** durchgereicht, wenn
    der Elternprozess selbst misst. Im Normallauf bleibt die Umgebung genau so
    klein wie vorher; wer den Test liest, sieht weiterhin, worauf das Werkzeug
    zugreifen kann.
    """
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(REPO / "src"),
        "OHPIPE_DATA_ROOT": str(root),
    }
    if key is not None:
        env["OHPIPE_JOURNAL_KEY"] = str(key)

    befehl = [sys.executable, "-m", "ohpipe.cli.main", "--profile", "sandbox", *args]
    rcfile = os.environ.get("COVERAGE_PROCESS_START")
    if rcfile:
        env["COVERAGE_PROCESS_START"] = rcfile
        befehl = [sys.executable, "-m", "coverage", "run", f"--rcfile={rcfile}", *befehl[1:]]

    return subprocess.run(
        befehl,
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
        env=env,
    )


def cli_keyed(*args: str, root: Path, key: Path) -> subprocess.CompletedProcess:
    return cli(*args, root=root, key=key)


def journal_path(root: Path) -> Path:
    return root / "_governance" / "journal.jsonl"


def _append(root: Path, events: list[dict], digest) -> None:
    p = journal_path(root)
    lines = [ln for ln in p.read_text(encoding="utf-8").split("\n") if ln.strip()]
    seq, prev = 0, GENESIS
    if lines:
        last = json.loads(lines[-1])
        seq, prev = last["seq"], last["digest"]
    for ev in events:
        seq += 1
        row = {
            "seq": seq,
            "at": ev.get("at", "2026-09-01T10:00:00+00:00"),
            "kind": ev["kind"],
            "record_id": ev.get("record_id", DEFAULT_RECORD),
            "payload": ev.get("payload", {}),
            "prev": prev,
        }
        row["digest"] = digest(row)
        prev = row["digest"]
        lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def forge(root: Path, events: list[dict]) -> None:
    """Hängt Ereignisse an — mit korrekt nachgerechneter Hashkette."""
    _append(root, events, sha256_json)


def forge_keyed(root: Path, key: Path, events: list[dict]) -> None:
    """Wie :func:`forge`, aber HMAC-verkettet — die Sicht eines Schlüsselinhabers.

    Damit erreichen die Tests die ZWEITE Verteidigungslinie: Nutzlastprüfung und
    Kausalbindung, dort wo die Autoritätsregel bereits erfüllt ist.
    """
    k = key.read_bytes()

    def digest(row: dict) -> str:
        blob = json.dumps(row, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hmac.new(k, blob.encode("utf-8"), "sha256").hexdigest()

    _append(root, events, digest)


def place_object(root: Path, data: bytes) -> str:
    """Legt Bytes unter ihrer Adresse ab — an der Store-API vorbei.

    Ein Angreifer benutzt ``ContentStore.put`` nicht; er schreibt in das
    Verzeichnis. Der Modus ist ``0600``, weil sonst der Rechteprüfer (G1)
    anschlägt und der Test etwas anderes fände als das, was er sucht.
    """
    import hashlib

    address = hashlib.sha256(data).hexdigest()
    d = root / "objects"
    d.mkdir(parents=True, exist_ok=True)
    target = d / address
    target.write_bytes(data)
    target.chmod(0o600)
    return address


#: Die sechs Label des Operatorvertrags, in normativer Reihenfolge (E6).
#: Ausgeschrieben und nicht aus ``Report.render`` abgeleitet: Ein Leser, der
#: seine Erwartung aus dem Erzeuger holt, prüft den Erzeuger gegen sich selbst.
REPORT_LABELS = ("STATUS", "CHANGED", "SAFE", "NEXT", "CHECK", "RECOVERY")


def report_lines(out: str) -> dict[str, str]:
    """Der Sechszeiler als Wörterbuch — geprüft wird die Ausgabe, kein Rückgabewert.

    **Warum diese Funktion die Vorgängerin ``four_lines`` ersetzt und nicht
    neben ihr steht.** ``four_lines`` matchte nur ``STATUS``, ``CHANGED``,
    ``SAFE``, ``NEXT``. Seit Serie 3a hat der Vertrag sechs Zeilen; die
    Fälschungstests prüften seither zwei Drittel davon. Ein gefälschter Bericht
    durfte ein erfundenes ``RECOVERY`` tragen, und keine Zusicherung schaute
    hin. Zwei Leser desselben Berichts nebeneinander wären genau die zweite
    Wahrheit, gegen die der Rest dieses Moduls antritt — deshalb Ersatz.

    **Und warum die Reihenfolge mitgeprüft wird.** ``four_lines`` iterierte
    Zeilen und Label unabhängig; ein geschüttelter Bericht bestand. E6 macht die
    Reihenfolge normativ, also ist sie hier eine Zusicherung und keine Annahme.

    Text vor und nach dem Block bleibt erlaubt — geprüft wird der Block, der mit
    ``STATUS`` beginnt.
    """
    zeilen = out.strip().split("\n")
    for i, zeile in enumerate(zeilen):
        if zeile.startswith(REPORT_LABELS[0]):
            block = zeilen[i : i + len(REPORT_LABELS)]
            break
    else:
        raise AssertionError(f"Keine Zeile beginnt mit STATUS — kein Bericht:\n{out}")

    if len(block) != len(REPORT_LABELS):
        raise AssertionError(
            f"Bericht bricht nach {len(block)} statt {len(REPORT_LABELS)} Zeilen ab:\n{out}"
        )
    for label, zeile in zip(REPORT_LABELS, block, strict=True):
        if not zeile.startswith(label):
            raise AssertionError(
                f"Zeile {block.index(zeile) + 1} des Berichts beginnt nicht mit {label!r} "
                f"— die Reihenfolge des Sechszeilers ist Vertrag (E6):\n{out}"
            )
    return {
        label: zeile.split(":", 1)[1].strip()
        for label, zeile in zip(REPORT_LABELS, block, strict=True)
    }
