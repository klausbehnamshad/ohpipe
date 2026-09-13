"""Die vierzehn Fälschungstests zum Content Store — geschrieben vor dem Store.

Herkunft: ``docs/ATTACK-LIST_content-store.md`` (32 Angriffe in acht Klassen).
Vierzehn davon sind hier ausformuliert:

    A1 A2 A4 · B1 B2 · C2 · D1 D2 D5 D6 · E1 E2 E5 · G1

**Zwei Fälle sind gegenüber der ersten Fassung getauscht**, und der Grund ist
in beiden Fällen derselbe: Ein Test, der etwas anderes prüft, als sein Name
behauptet, ist schlimmer als kein Test.

  `F2` **raus.** Ein Lesefehler an der Quelle ist kein voller Zieldatenträger.
       Die erste Fassung löste ``ENOSPC`` beim Lesen aus und hätte als
       bestandener „Datenträger voll"-Test gegolten. Gehört in einen
       Integrationstest auf einem tatsächlich begrenzten Dateisystem
       (tmpfs bzw. DMG) — offen, benannt, nicht stillschweigend erledigt.
  `H2` **raus.** Es gibt keinen Index (ADR 0022). Ein Test hätte ein Schema
       festgeschrieben, das niemand gemessen braucht.
  `E2` **rein.** Ein bereits vorhandenes, korruptes Ziel darf von ``put()``
       niemals überschrieben werden. Das ist Schritt 4 des
       Publikationsprotokolls und der einzige Ort, an dem „ist schon da"
       gefährlich wird.
  `G1` **rein.** ``0700``/``0600`` ist bei Oral-History-Material eine
       Sicherheitsinvariante, keine Ressourcenfrage.

**Zwei Grenzen, bewusst getrennt** (ADR 0015 verlangt die CLI-Grenze, aber
nicht jeder Angriff geht durch sie):

  ÜBER DIE CLI     Der Angreifer hat Schreibzugriff auf die Platte, das
                   Werkzeug wird danach normal benutzt: `A1` `A4` `B1` `B2`
                   `C2` `D5` `E5` `G1`.
  ÜBER DIE API     Der Angreifer IST der Aufrufer — eine bösartige Adresse
                   oder Konfiguration erreicht die CLI gar nicht erst:
                   `A2` `D1` `D2` `D6` `E1` `E2`.

Und was hier **nicht** prüfbar ist: `D5` deckt auf Linux nur die Ablehnung der
Großbuchstaben-Adresse ab; die Case-Insensitivität von APFS ist hier nicht
reproduzierbar. Das steht am Test.

Das API, das diese Datei festschreibt — streamend, ohne Umgehung::

    from ohpipe.store import ContentStore
    ContentStore(root: Path, objects: Path | None = None)   # default: root/"objects"
    .put(source: BinaryIO) -> str                # blockweise lesen und hashen
    .open_verified(address) -> ContextManager[BinaryIO]
    .verify(address) -> ObjectInfo               # address, size, nlink, mode
    .stale_temporaries() -> list[Path]           # meldet, löscht nie

``open_verified`` öffnet mit ``O_NOFOLLOW``, prüft Dateityp und Hash
vollständig, spult **denselben Deskriptor** zurück und gibt ihn erst dann
heraus. Derselbe Deskriptor ist der Punkt: Ein zweites ``open`` nach der
Prüfung wäre eine Lücke zwischen Prüfen und Lesen.

Es gibt bewusst **kein** öffentliches ``path_for()`` und **kein**
``contains()``. Ein herausgegebener Pfad ist eine Einladung, an Hash- und
Symlinkprüfung vorbeizulesen; und Existenz, Integrität und Sicherheit lassen
sich nicht ehrlich in einem Boolean zusammenfassen — wer wissen will, ob ein
Objekt benutzbar ist, ruft ``verify`` und behandelt den Fehler.

    StoreError
      BadAddress        D1, D5      keine gültige Adresse
      StoreOutsideRoot  D6          Objektverzeichnis außerhalb der Datenwurzel
      MissingObject     A4          referenzierte Bytes fehlen
      CorruptObject     A1, A2, E2  Name und Inhalt passen nicht zusammen
      UnsafeObject      D2          Symlink; auch: st_nlink > 1 als Hinweis (D3)
      StoreWriteFailed              Schreiben abgebrochen, Torso bleibt Torso
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from ._forge import REPO, REPORT_LABELS, cli, cli_keyed, forge, report_lines

TEMP_PREFIX = ".incoming-"


# --------------------------------------------------------------- Werkzeug


def store_module():
    """Der Store. Der Import steht in JEDEM Test und nicht am Dateikopf.

    Am Kopf wäre die ganze Datei ein einziger Sammelfehler beim Einsammeln und
    die vierzehn Fälle wären ununterscheidbar. So scheitert jeder Fall an
    seiner eigenen Sache.
    """
    import ohpipe.store as m

    return m


def make_store(root: Path, objects: Path | None = None):
    m = store_module()
    return m.ContentStore(root) if objects is None else m.ContentStore(root, objects=objects)


def objects_dir(root: Path) -> Path:
    d = root / "objects"
    d.mkdir(parents=True, exist_ok=True)
    return d


def address_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def produced(artifact: str, address: str) -> dict:
    """Ein wohlgeformtes Ereignis, das genau diese Bytes referenziert."""
    return {"kind": "artifact.produced", "payload": {"artifact": artifact, "sha256": address}}


def names_in(root: Path) -> tuple[list[str], list[str]]:
    """(finale Objekte, Temporärdateien) — die Unterscheidung, um die es geht."""
    entries = [p.name for p in objects_dir(root).iterdir()]
    return (
        sorted(n for n in entries if not n.startswith(TEMP_PREFIX)),
        sorted(n for n in entries if n.startswith(TEMP_PREFIX)),
    )


class Interrupted(io.RawIOBase):
    """Eine Quelle, die mitten im Lesen abbricht — der Absturz beim Schreiben."""

    def __init__(self, good: bytes, exc: BaseException) -> None:
        self._good = good
        self._exc = exc
        self._served = False

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if not self._served:
            self._served = True
            return self._good
        raise self._exc

    readinto = None  # erzwingt den read()-Pfad


class Watched(io.RawIOBase):
    """Eine Quelle, die mitschreibt, in welchen Häppchen sie gelesen wurde."""

    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)
        self.requests: list[int] = []

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        self.requests.append(size)
        return self._buf.read(size if size and size > 0 else None)

    readinto = None


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "data"
    assert cli("init", root=r).returncode == 0
    return r


# ------------------------------------------------------------ A. Korruption


def test_a1_an_object_that_lies_about_its_own_name_is_a_finding(root):
    """A1 — Der Name behauptet einen Hash, die Bytes sagen etwas anderes.

    Ein Store, der nur beim Schreiben prüft, ist ein Store, der seinem eigenen
    Dateisystem vertraut. Geprüft wird deshalb beim LESEN — und zwar bevor ein
    einziges Byte herausgegeben wird.
    """
    address = address_of(b"was der Name verspricht")
    (objects_dir(root) / address).write_bytes(b"was tatsaechlich dasteht")
    forge(root, [produced("transcript.revision", address)])

    r = cli("doctor", root=root)
    assert r.returncode == 1, f"exit {r.returncode} — korrupte Bytes sind kein Hinweis"
    assert "Traceback" not in r.stderr
    assert set(report_lines(r.stdout)) == set(REPORT_LABELS)
    assert address[:12] in r.stdout, "der Befund benennt die Adresse nicht"

    m = store_module()
    store = make_store(root)
    with pytest.raises(m.CorruptObject):
        store.verify(address)
    with pytest.raises(m.CorruptObject), store.open_verified(address):
        pass  # pragma: no cover — der Eintritt darf gar nicht stattfinden


def test_a2_an_interrupted_write_never_reaches_the_final_name(root):
    """A2 — Abbruch mitten im Schreiben. Ein Torso trägt nie den finalen Namen.

    Genau deshalb ist ``open(O_CREAT|O_EXCL)`` unter dem Zielnamen falsch: Es
    hinterließe diesen Torso. Geschrieben wird in eine Temporärdatei, und der
    finale Name entsteht erst, wenn alle Bytes da sind.
    """
    payload = b"x" * 4096
    store = make_store(root)
    with pytest.raises(KeyboardInterrupt):
        store.put(Interrupted(payload, KeyboardInterrupt()))

    finals, _ = names_in(root)
    assert finals == [], f"Torso unter finalem Namen: {finals}"
    with pytest.raises(store_module().MissingObject):
        store.verify(address_of(payload))


def test_a4_a_referenced_object_that_is_missing_stops_without_a_traceback(root):
    """A4 — Das Journal referenziert Bytes, die es nicht gibt.

    Kein „wird schon". Fehlende Bytes sind ein Halt mit Begründung, und der
    Befund benennt die Adresse — sonst weiß niemand, wonach er suchen soll.
    """
    address = address_of(b"diese Bytes hat nie jemand abgelegt")
    forge(root, [produced("transcript.revision", address)])

    for cmd in ("status", "doctor"):
        r = cli(cmd, root=root)
        assert r.returncode == 1, f"{cmd}: exit {r.returncode}"
        assert "Traceback" not in r.stderr, f"{cmd}: Traceback statt Report"
        lines = report_lines(r.stdout)
        assert set(lines) == set(REPORT_LABELS), cmd
        assert "STOP" in lines["STATUS"], cmd
        assert address[:12] in r.stdout, f"{cmd}: die fehlende Adresse wird nicht benannt"

    with pytest.raises(store_module().MissingObject):
        make_store(root).verify(address)


# --------------------------------------------------- B. Unbefugter Schreiber


def test_b1_an_object_nobody_referenced_changes_no_verdict(root):
    """B1 — Der Store trägt keine Autorität (ADR 0017).

    Geprüft wird nicht ein bestimmter Ausgang, sondern eine Differenz: Das
    Urteil vor und nach dem Ablegen muss dasselbe sein. Sonst könnte man sich
    Zustand herbeischreiben, indem man Bytes hinlegt.
    """
    before = cli("status", "--json", root=root)
    address = make_store(root).put(io.BytesIO(b"korrekt gehasht, nur eben unreferenziert"))
    assert len(address) == 64
    after = cli("status", "--json", root=root)

    assert after.returncode == before.returncode
    assert (
        json.loads(after.stdout)["details"]["records"]
        == (json.loads(before.stdout)["details"]["records"])
    ), "abgelegte Bytes haben das Urteil verändert"


def test_b2_replacing_an_object_leaves_a_dangling_reference(root):
    """B2 — Objekt ersetzt, Name neu berechnet, Journal unverändert.

    Der Angriff zerfällt in zwei bekannte Fälle: Die alte Referenz zeigt ins
    Leere (A4), der neue Name kommt im Journal nicht vor (B1). Wichtig ist,
    dass die neuen Bytes den Befund NICHT heilen.
    """
    old = address_of(b"die Bytes, auf die sich die Entscheidung bezog")
    new_bytes = b"was der Angreifer stattdessen dort haben will"
    forge(root, [produced("transcript.revision", old)])
    (objects_dir(root) / address_of(new_bytes)).write_bytes(new_bytes)

    r = cli("status", root=root)
    assert r.returncode == 1, "die ersetzten Bytes wurden akzeptiert"
    assert old[:12] in r.stdout, "der Befund nennt die verwaiste Referenz nicht"
    assert address_of(new_bytes)[:12] not in r.stdout, (
        "der neue Name wird wie eine Referenz behandelt"
    )


# ------------------------------------------------------------- C. Vollzugriff


def test_c2_a_rewrite_without_the_key_fails_the_chain(tmp_path):
    """C2 — Die Gegenprobe zur Autoritätsregel.

    C1 und C3 sind dokumentierte Grenzen: ohne Schlüssel bzw. mit Schlüssel in
    der Hand ist ein vollständiges Neuschreiben nicht erkennbar. Genau deshalb
    darf der Fall dazwischen — Schlüssel gesetzt, Angreifer hat ihn nicht —
    nicht bloß behauptet werden.

    Ehrlich dazu: Dieser Fall ist grün, seit es das Journal gibt. Er steht
    hier, weil der Store ihn brechen KÖNNTE — Bytes neben dem Journal dürfen
    die Schlüsselprüfung nicht aufweichen.
    """
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    r = tmp_path / "keyed-data"
    assert cli_keyed("init", root=r, key=key).returncode == 0

    payload = b"konsistent gefaelscht: Store und Journal passen zueinander"
    address = address_of(payload)
    (objects_dir(r) / address).write_bytes(payload)
    forge(r, [produced("transcript.revision", address)])  # unkeyed, bei gesetztem Schlüssel

    out = cli_keyed("doctor", root=r, key=key)
    assert out.returncode == 1
    assert "Integritätsprüfung" in out.stdout
    assert (objects_dir(r) / address).exists(), "das Werkzeug hat Beweismittel entfernt"


# ------------------------------------------------------- D. Pfade und Namen


@pytest.mark.parametrize(
    "address",
    [
        "../" + "a" * 61,
        "../../etc/passwd",
        "/etc/passwd",
        "a" * 32 + "/../" + "b" * 28,
        "a" * 63,
        "a" * 65,
        "g" * 64,
        "",
        "a" * 63 + "\n",
        "a" * 63 + "\x00",
    ],
)
def test_d1_a_hostile_address_is_refused_before_a_path_exists(root, address):
    """D1 — Nur ``^[0-9a-f]{64}$`` ist eine Adresse. Validierung VOR dem Pfadbau.

    Beide öffentlichen Lesewege werden geprüft. Ein drittes ``path_for()``
    gibt es absichtlich nicht: Wer einen Pfad herausgibt, gibt die Prüfung mit
    heraus.
    """
    m = store_module()
    store = make_store(root)
    before = sorted(p.name for p in objects_dir(root).iterdir())
    with pytest.raises(m.BadAddress):
        store.verify(address)
    with pytest.raises(m.BadAddress), store.open_verified(address):
        pass  # pragma: no cover
    assert sorted(p.name for p in objects_dir(root).iterdir()) == before


def test_d2_a_symlink_out_of_the_store_is_refused_even_with_matching_content(root, tmp_path):
    """D2 — Der Symlink zeigt auf eine Datei, deren Inhalt zum Namen PASST.

    Damit greift das erneute Hashen (A1) gerade nicht — der Hash stimmt ja.
    Was hier schützt, ist ``O_NOFOLLOW`` bzw. die Typprüfung vor dem Lesen.
    Sonst liest der Store an einer Stelle, die nicht ihm gehört, und liefert
    formal korrekte Bytes aus einer Quelle, die niemand kontrolliert.
    """
    outside = tmp_path / "ausserhalb.bin"
    payload = b"inhaltlich voellig korrekt, nur am falschen Ort"
    outside.write_bytes(payload)
    address = address_of(payload)
    (objects_dir(root) / address).symlink_to(outside)

    m = store_module()
    store = make_store(root)
    with pytest.raises(m.UnsafeObject):
        store.verify(address)
    with pytest.raises(m.UnsafeObject), store.open_verified(address):
        pass  # pragma: no cover


def test_d5_an_uppercase_address_is_invalid_not_also_ok(root):
    """D5 — Hex ist durchgängig klein.

    Auf APFS sind ``AAAA…`` und ``aaaa…`` dieselbe Datei, auf ext4 nicht.
    Prüfbar ist hier die Ablehnung der Adresse und dass ein Objekt mit
    Großbuchstaben im Namen ein Befund ist statt „auch ok". Die
    Case-Insensitivität selbst ist auf Linux nicht reproduzierbar — dieser
    Test deckt sie nicht ab und behauptet es auch nicht.
    """
    payload = b"gross geschrieben abgelegt"
    upper = address_of(payload).upper()
    (objects_dir(root) / upper).write_bytes(payload)

    with pytest.raises(store_module().BadAddress):
        make_store(root).verify(upper)

    r = cli("doctor", root=root)
    assert r.returncode == 1, "ein Objektname mit Grossbuchstaben blieb folgenlos"
    assert "Traceback" not in r.stderr


def test_d6_an_object_directory_outside_the_data_root_is_refused(root, tmp_path):
    """D6 — Dieselbe Regel wie ``--root`` im Repository (ADR 0006).

    Beide Wege hinaus werden geprüft: die Konfiguration, die direkt hinauszeigt,
    und das Verzeichnis, das per Symlink hinausführt. Wer nur den ersten prüft,
    hat die Regel nicht.
    """
    m = store_module()
    with pytest.raises(m.StoreOutsideRoot):
        make_store(root, objects=tmp_path / "woanders")

    elsewhere = tmp_path / "woanders-echt"
    elsewhere.mkdir()
    linked = root / "objects-link"
    linked.symlink_to(elsewhere, target_is_directory=True)
    with pytest.raises(m.StoreOutsideRoot):
        make_store(root, objects=linked)


# ------------------------------------------------------- E. Nebenläufigkeit


PUT_IN_A_SUBPROCESS = """
import io, sys
from pathlib import Path
from ohpipe.store import ContentStore
data = b"y" * 1_000_000
print(ContentStore(Path(sys.argv[1])).put(io.BytesIO(data)))
"""


def test_e1_eight_processes_writing_the_same_object_collide_on_nothing(root):
    """E1 — Der eigentliche Fehler ist die Kollision der TEMPORÄRDATEI.

    Ein festes ``<sha>.tmp`` hieße: Acht Schreiber schreiben in dieselbe Datei
    und das Ergebnis ist ein Mischmasch mit gültigem Namen. Deshalb echte
    Prozesse und keine Threads — der Angriff zielt auf einen Namen, den sich
    Prozesse teilen.
    """
    objects_dir(root)
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", PUT_IN_A_SUBPROCESS, str(root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=REPO,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(REPO / "src")},
        )
        for _ in range(8)
    ]
    results = [p.communicate() for p in procs]
    expected = address_of(b"y" * 1_000_000)
    for i, (out, err) in enumerate(results):
        assert procs[i].returncode == 0, f"Schreiber {i}: {err}"
        assert out.strip() == expected, f"Schreiber {i} meldet {out.strip()!r}"

    finals, temps = names_in(root)
    assert finals == [expected], f"im Store liegt: {finals}"
    assert temps == [], f"Temporärdateien nach sauberem Lauf: {temps}"
    assert (objects_dir(root) / expected).read_bytes() == b"y" * 1_000_000


def test_e2_put_never_overwrites_an_existing_corrupt_target(root):
    """E2 — Schritt 4 des Publikationsprotokolls, und der gefährlichste.

    Das Ziel existiert schon, trägt den richtigen Namen und den falschen
    Inhalt. Zwei falsche Antworten wären möglich: überschreiben (dann
    verschwindet der Befund) oder „ist schon da" zurückmelden (dann gilt eine
    Fälschung als erfolgreich abgelegt). Richtig ist: prüfen, nicht annehmen,
    und den Befund melden — die Bytes bleiben unangetastet als Beweismittel.
    """
    payload = b"die echten Bytes, die abgelegt werden sollen"
    address = address_of(payload)
    forged = b"was schon dort liegt und ganz anders lautet"
    target = objects_dir(root) / address
    target.write_bytes(forged)

    with pytest.raises(store_module().CorruptObject):
        make_store(root).put(io.BytesIO(payload))

    assert target.read_bytes() == forged, "das vorhandene Ziel wurde überschrieben"


def test_e5_stale_temporaries_are_reported_and_never_removed(root):
    """E5 — ``doctor`` meldet, der Mensch löscht.

    Automatisches Aufräumen war im Vorgängersystem der Weg, auf dem Befunde
    verschwanden. Die zweite Zusicherung ist deshalb die wichtigere: Die Datei
    liegt hinterher noch da.
    """
    leftover = objects_dir(root) / f"{TEMP_PREFIX}7f3a91"
    leftover.write_bytes(b"haelfte eines Objekts")

    r = cli("doctor", root=root)
    assert leftover.name in r.stdout, "die liegengebliebene Temporärdatei wird nicht gemeldet"
    assert leftover.exists(), "doctor hat aufgeräumt — doctor ist read-only"
    assert make_store(root).stale_temporaries() == [leftover]


# ---------------------------------------------------------------- G. Rechte


def test_g1_the_store_is_not_readable_for_other_users(root):
    """G1 — ``0700`` auf Verzeichnisse, ``0600`` auf Objekte.

    Bei Oral-History-Material ist das eine Sicherheitsinvariante und keine
    Ressourcenfrage: Auf einem geteilten Rechner ist ein weltlesbares Objekt
    genau die Weitergabe, die die Einwilligung nicht deckt.

    Zwei Zusicherungen, und die zweite ist die eigentliche: Was der Store
    anlegt, ist eng — und wenn jemand nachträglich aufmacht, ist das ein
    Befund und kein stilles Zurechtrücken.
    """
    store = make_store(root)
    address = store.put(io.BytesIO(b"einwilligung deckt keinen dritten"))

    d = objects_dir(root)
    assert stat.S_IMODE(d.stat().st_mode) == 0o700, oct(stat.S_IMODE(d.stat().st_mode))
    obj = d / address
    assert stat.S_IMODE(obj.stat().st_mode) == 0o600, oct(stat.S_IMODE(obj.stat().st_mode))

    os.chmod(obj, 0o644)
    r = cli("doctor", root=root)
    assert r.returncode == 1, "ein weltlesbares Objekt blieb folgenlos"
    assert address[:12] in r.stdout


# -------------------------------------------- Vertrag, kein Angriff (kein Fall)


def test_put_reads_the_source_in_blocks_and_never_in_one_piece(root):
    """Kein Angriff aus der Liste — der Streaming-Vertrag selbst.

    Er steht hier, weil ``get() -> bytes`` und ``read_bytes()`` genau der
    Fehler waren, den das API loswerden sollte: Bei Audio läge sonst das ganze
    Objekt im Speicher. Ein API umzubenennen und weiter alles einzulesen wäre
    die schlechteste Art, einen Review zu erfüllen.
    """
    src = Watched(b"m" * (3 * 1024 * 1024))
    make_store(root).put(src)

    assert src.requests, "die Quelle wurde gar nicht über read() gelesen"
    assert all(n and n > 0 for n in src.requests), (
        f"read() ohne Größenangabe — das ist read_bytes() mit anderem Namen: {src.requests[:5]}"
    )
    assert len(src.requests) > 1, "in einem Stück gelesen"


# ------------------------- D8/D9: Verzeichnistausch NACH der Auflösung
#
# Nachgetragen am 04.08.2026. Beide Angriffe liefen gegen die erste Fassung des
# Stores durch — nicht theoretisch, sondern reproduziert. Die Auflösung des
# Pfades im Konstruktor ist eine Aussage über EINEN Zeitpunkt; alles, was
# danach passiert, deckt sie nicht ab.


def test_d8_swapping_the_object_directory_after_construction_is_refused(root, tmp_path):
    """D8 — ``objects/`` wird nach der Konstruktion durch einen Symlink ersetzt.

    Der Angriff, wie er tatsächlich lief: ``ContentStore`` erzeugen, dann
    ``objects/`` gegen einen Symlink nach außen tauschen, dann ``put()``.
    Die Bytes landeten außerhalb der Datenwurzel — bei realem Material wäre
    das Interviewmaterial an einem Ort, den niemand verantwortet.

    Was schützt, ist nicht erneutes ``resolve()``, sondern ein
    Verzeichnisdeskriptor mit ``O_DIRECTORY | O_NOFOLLOW`` und Dateioperationen
    relativ zu ihm. Zwischen Prüfen und Schreiben liegt dann kein Pfad mehr,
    den jemand austauschen könnte.
    """
    m = store_module()
    outside = tmp_path / "aussen"
    outside.mkdir()

    store = make_store(root)  # löst objects/ einmal auf
    objects = root / "objects"
    for p in objects.iterdir():  # pragma: no cover - nach init leer
        p.unlink()
    objects.rmdir()
    objects.symlink_to(outside, target_is_directory=True)

    with pytest.raises(m.StoreOutsideRoot):
        store.put(io.BytesIO(b"reale Interviewbytes, ausserhalb der Datenwurzel"))
    with pytest.raises(m.StoreOutsideRoot):
        store.verify("a" * 64)

    assert list(outside.iterdir()) == [], "es wurde ausserhalb der Datenwurzel geschrieben"


def test_d9_init_neither_follows_an_object_symlink_nor_hides_a_mode_change(tmp_path):
    """D9 — ``init`` folgte einem ``objects/``-Symlink und schwieg darüber.

    Zwei Fehler in einem: ``exists()``, ``stat()`` und ``chmod()`` folgen
    Symlinks, also änderte ``init`` den Modus eines Verzeichnisses AUSSERHALB
    der Datenwurzel — von ``0755`` auf ``0700``. Und ``CHANGED`` meldete
    „keine", obwohl genau das passiert war.

    ``CHANGED: keine`` ist eine Zusage, kein Hinweis (ADR 0004). Eine Zusage,
    die nicht stimmt, ist schlimmer als gar keine.
    """
    root = tmp_path / "data"
    root.mkdir()
    outside = tmp_path / "aussen"
    outside.mkdir()
    os.chmod(outside, 0o755)
    (root / "objects").symlink_to(outside, target_is_directory=True)

    r = cli("init", root=root)
    assert r.returncode == 1, f"init lief auf einem Symlink durch (exit {r.returncode})"
    assert "Traceback" not in r.stderr
    assert stat.S_IMODE(outside.stat().st_mode) == 0o755, (
        "init hat ein Verzeichnis ausserhalb der Datenwurzel veraendert"
    )


def test_init_reports_every_mode_it_changes(tmp_path):
    """Die zweite Hälfte von D9, ohne Symlink: Ehrlichkeit von ``CHANGED``.

    Ein zu weit geöffnetes Verzeichnis wird engegezogen — das ist richtig. Es
    stillschweigend zu tun ist es nicht.
    """
    root = tmp_path / "data"
    (root / "records").mkdir(parents=True)
    os.chmod(root / "records", 0o755)

    r = cli("init", root=root)
    assert r.returncode == 0, r.stdout
    changed = report_lines(r.stdout)["CHANGED"]
    assert "records" in changed and "755" in changed, (
        f"CHANGED verschweigt die Modusaenderung: {changed}"
    )
    assert stat.S_IMODE((root / "records").stat().st_mode) == 0o700
