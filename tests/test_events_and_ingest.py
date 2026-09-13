"""Der erste Schreibpfad — und die Wache, die dort zum ersten Mal steht.

Herkunft: ADR 0017 (Nutzlastprüfung ist keine Autorisierung), P1-1
(Nutzlast-Allowlist), P1-2 (Journalkopf), A-2 (Feldnamen standen doppelt).

Der Punkt dieser Datei ist nicht, dass ``ingest`` funktioniert. Er ist, dass
rund fünfzehn ältere Zusagen der Form „das System würde X ablehnen" bis heute
Aussagen über einen Pfad waren, den es nicht gab: ``require_write`` hatte
**null Aufrufer**. Eine Wache, die nie gestanden hat, ist keine Wache.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from ohpipe.domain.events import KINDS, PayloadRejected, check_payload
from ohpipe.journal import Journal

from ._forge import cli, cli_keyed, journal_path

FIXTURE = Path(__file__).resolve().parents[1] / "examples/synthetic/SANDBOX-001.srt"
REC = "SANDBOX-001"


@pytest.fixture
def welt(tmp_path: Path):
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"

    def run(*args: str):
        return cli_keyed(*args, root=wurzel, key=key)

    assert run("init").returncode == 0
    return wurzel, key, run


# ------------------------------------------------------- Nutzlast-Allowlist


def test_an_unknown_event_kind_never_reaches_the_file(tmp_path):
    """Abgelehnt wird VOR der Sperre — die Datei entsteht gar nicht erst.

    Das Journal ist append-only. Ein Feld, das beim Schreiben durchrutscht, ist
    dauerhaft; deshalb ist die Prüfung eine Schreibbedingung und keine
    Lesehilfe.
    """
    p = tmp_path / "j.jsonl"
    j = Journal(p)
    with pytest.raises(PayloadRejected, match="unbekannte Ereignisart"):
        j.append("wasauchimmer", {"x": 1}, record_id=REC)
    assert not p.exists(), "eine abgelehnte Nutzlast hat die Journaldatei angelegt"


def test_a_state_asserting_kind_is_named_as_such(tmp_path):
    j = Journal(tmp_path / "j.jsonl")
    with pytest.raises(PayloadRejected, match="behauptet einen Zustand"):
        j.append("artifact.state", {"artifact": "a"}, record_id=REC)


@pytest.mark.parametrize("feld", ["surface", "quote", "context", "replacement", "text", "name"])
def test_fields_that_typically_carry_a_surface_form_are_refused_by_name(feld):
    """Diese Felder wären ohnehin „nicht erlaubt". Der eigene Befund existiert,
    damit die Meldung nach Sicherheitsregel klingt und nicht nach Tippfehler —
    und damit sie ihn nennt, ohne den Wert zu nennen (D4)."""
    with pytest.raises(PayloadRejected, match="Oberflächenform"):
        check_payload(
            "artifact.produced", {"artifact": "a", "sha256": "a" * 64, feld: "Marie"}, REC
        )


def test_an_unremarkable_unknown_field_is_refused_too():
    """Die Kernzusage der Allowlist — und sie war unbewiesen.

    Die Mutationsprobe hat es gefunden: `fremd = []` (also: unbekannte Felder
    durchlassen) überlebte die vollständige Suite. Der Grund war, dass jeder
    vorhandene Test ein Feld aus `KLARTEXTVERDACHT` benutzte und damit den
    ANDEREN Zweig traf. Ein harmlos klingendes Feld wie `zusatz` war nirgends
    geprüft — und genau so eines schreibt jemand versehentlich hinein.

    Es wird nicht gefiltert, sondern abgelehnt: Ein stillschweigend verworfenes
    Feld lässt den Aufrufer glauben, sein Wert sei angekommen.
    """
    with pytest.raises(PayloadRejected, match="nicht erlaubte Felder"):
        check_payload(
            "artifact.produced",
            {"artifact": "a", "sha256": "a" * 64, "zusatz": "irgendwas"},
            REC,
        )


def test_the_rejection_never_echoes_the_rejected_value():
    """Ein Fehlertext ist eine Logzeile. Eine Logzeile mit einer
    Oberflächenform darin ist der Re-Identifikationspfad aus D4."""
    geheim = "Marie Schmitz"
    with pytest.raises(PayloadRejected) as exc:
        check_payload(
            "artifact.produced", {"artifact": "a", "sha256": "a" * 64, "name": geheim}, REC
        )
    assert geheim not in str(exc.value)
    assert "Marie" not in str(exc.value)


def test_a_record_id_in_the_payload_must_agree_with_the_envelope():
    """Zwei Orte für dieselbe Angabe sind ein Angriffsweg: Die Hülle bestimmt
    die Zuordnung, die Nutzlast bestimmt, was ``ownership`` liest."""
    with pytest.raises(PayloadRejected, match="widersprechen sich"):
        check_payload(
            "record.adopted",
            {"record_id": "CHILDLUX-0001", "from": "dinoh", "to": "ohpipe", "reference": "PI-1"},
            "CHILDLUX-0007",
        )


@pytest.mark.parametrize("kind", sorted(KINDS))
def test_every_kind_refuses_a_payload_that_is_missing_one_required_field(kind):
    """Für JEDE Art: ein Pflichtfeld weg -> Ablehnung. Ohne diese Schleife
    prüfte die Suite die Allowlist nur an den Arten, die zufällig anderswo
    vorkommen."""
    spec = KINDS[kind]
    voll = {f: "x" for f in spec.pflicht}
    rid = None if not spec.braucht_record else REC
    if "record_id" in voll:
        voll["record_id"] = REC
    for fehlend in sorted(spec.pflicht):
        teil = {k: v for k, v in voll.items() if k != fehlend}
        with pytest.raises(PayloadRejected, match="Pflichtfelder fehlen"):
            check_payload(kind, teil, rid)


# ------------------------------------------------------------- Journalkopf


def test_the_cached_head_is_dropped_when_someone_else_appended(tmp_path):
    """Der gemerkte Kopf gilt nur, solange dieses Objekt der letzte Schreiber
    war. Ein falsches ``prev`` bricht die Kette — und ein Kettenbruch sieht aus
    wie Manipulation."""
    p = tmp_path / "j.jsonl"
    a = Journal(p)
    b = Journal(p)
    a.append("anchor.checked", {"artifact": "eins", "outcome": "exact"}, record_id=REC)
    b.append("anchor.checked", {"artifact": "zwei", "outcome": "exact"}, record_id=REC)
    # `a` hält jetzt einen veralteten Kopf. Der nächste Anhang muss ihn
    # verwerfen, sonst verkettet er gegen seq 1 statt seq 2.
    a.append("anchor.checked", {"artifact": "drei", "outcome": "exact"}, record_id=REC)
    a.verify()
    assert a.head()[0] == 3


def test_many_appends_do_not_reread_the_whole_file_each_time(tmp_path):
    """P1-2. Gemessen wird nicht die Zeit — die schwankt —, sondern die Zahl
    der Lesevorgänge.

    **Messstelle nachgezogen (J1/H2), Zusage unverändert.** Diese Zeile zählte
    bisher ``Journal.head``. Mit der descriptor-gebundenen Umsetzung liest
    ``_head_locked`` bei einem Fehlschlag des gemerkten Kopfes über den bereits
    geöffneten Deskriptor (``_am_deskriptor``) statt über ``head()``, weil ein
    zweites Auflösen des Pfades genau das Fenster wäre, das J1 schliesst.
    ``head()`` lief danach 0× — der Test wäre rot geworden, **obwohl die
    Eigenschaft besser erfüllt ist als vorher**.

    Gezählt werden deshalb jetzt **beide** Volllesungen und ihre Summe geprüft.
    Das ist unabhängig davon, welchen Weg die Umsetzung nimmt, und strikt
    schärfer als vorher: eine Fassung, die ``head()`` nur wegdefiniert, kommt
    damit nicht durch. Selbst gemessen an 50 ``append``-Aufrufen: Summe 1,
    Kette heil.
    """
    p = tmp_path / "j.jsonl"
    j = Journal(p)
    gelesen = 0
    echt_head = Journal.head
    echt_deskriptor = Journal._am_deskriptor

    def zaehlend(self):
        nonlocal gelesen
        gelesen += 1
        return echt_head(self)

    def zaehlend_am_deskriptor(self, fd):
        nonlocal gelesen
        gelesen += 1
        return echt_deskriptor(self, fd)

    Journal.head = zaehlend  # type: ignore[method-assign]
    Journal._am_deskriptor = zaehlend_am_deskriptor  # type: ignore[method-assign]
    try:
        for i in range(50):
            j.append("anchor.checked", {"artifact": f"a{i}", "outcome": "exact"}, record_id=REC)
    finally:
        Journal.head = echt_head  # type: ignore[method-assign]
        Journal._am_deskriptor = echt_deskriptor  # type: ignore[method-assign]
    assert gelesen == 1, (
        f"die Datei wurde {gelesen}x vollstaendig gelesen statt einmal — "
        "der Kopf wird nicht gemerkt"
    )
    j.verify()


# ----------------------------------------------------------------- ingest


def test_ingest_writes_a_record_and_the_status_sees_it(welt):
    wurzel, key, run = welt
    r = run("ingest", str(FIXTURE), "--record", REC, "--json")
    assert r.returncode == 3, r.stdout + r.stderr
    d = json.loads(r.stdout)
    assert d["details"]["record_id"] == REC
    assert d["details"]["cues"] == 5
    assert d["details"]["neuer_record"] is True

    st = json.loads(run("status", "--json").stdout)
    assert any(rec["record_id"] == REC for rec in st["details"]["records"])


def test_ingest_reports_what_it_changed_and_that_the_source_is_untouched(welt):
    """Die CHANGED-Zeile ist eine Zusage, keine Zierde — und die Quelldatei
    wird gelesen, nie geschrieben."""
    wurzel, key, run = welt
    vorher = FIXTURE.read_bytes()
    r = run("ingest", str(FIXTURE), "--record", REC)
    assert "CHANGED:" in r.stdout
    assert "SAFE" in r.stdout
    assert "Quelldaten unverändert" in r.stdout
    assert FIXTURE.read_bytes() == vorher


def test_ingest_refuses_a_record_that_belongs_to_the_legacy_system(welt):
    """Der Grund, warum es diese Datei gibt: Bis heute hatte die Wache keinen
    Aufrufer. Jetzt hat sie einen, und sie hält."""
    wurzel, key, run = welt
    r = run("ingest", str(FIXTURE), "--record", "SANDBOX-0001", "--json")
    assert r.returncode == 2, r.stdout
    # Und der echte Ownership-Fall über ein eigens als CHILDLUX gebundenes
    # Arbeitsverzeichnis. Ein Profilwechsel auf derselben Sandbox-Wurzel wird
    # seit E8 vorher und zu Recht als Graphabweichung angehalten.
    childlux_root = wurzel.parent / "childlux-daten"
    initial = cli_keyed("--profile", "childlux", "init", root=childlux_root, key=key)
    assert initial.returncode == 0, initial.stdout
    r = cli_keyed(
        "--profile",
        "childlux",
        "ingest",
        str(FIXTURE),
        "--record",
        "CHILDLUX-0001",
        "--json",
        root=childlux_root,
        key=key,
    )
    assert r.returncode == 1, r.stdout
    d = json.loads(r.stdout)
    assert d["reason_code"] == "STOP_OWNERSHIP"
    assert "dinoh" in d["reason"]


def test_ingest_refuses_a_file_the_parser_cannot_read(welt, tmp_path):
    """Umbenannt nach einer Mutationsprobe: Der Test hiess vorher
    ``..._it_cannot_reproduce_byte_for_byte`` und prüfte etwas anderes.

    Eine kaputte Zeitcodezeile wird schon vom PARSER abgelehnt; der
    Bytegleichheits-Vergleich in ``ingest`` wird dabei nie erreicht. Der Test
    war grün und sein Name war falsch — die Mutation ``if False:`` auf genau
    jenem Vergleich überlebte die vollständige Suite.

    Zum Bytegleichheits-Vergleich selbst siehe den Kommentar in
    ``application/ingest.py``: Er ist eine Stolperdraht-Zusicherung gegen eine
    künftige Parseränderung, kein Eingangsfilter — es gibt heute keine
    akzeptierte Eingabe, die ihn auslöst.
    """
    wurzel, key, run = welt
    kaputt = tmp_path / "kaputt.srt"
    kaputt.write_text("1\n00:00:01,000 --> nicht,ein,zeitcode\nText\n", encoding="utf-8")
    r = run("ingest", str(kaputt), "--record", REC, "--json")
    assert r.returncode == 2, r.stdout
    assert json.loads(r.stdout)["reason_code"] == "CONFIG_INGEST"


def test_ingest_does_not_guess_the_format_from_content(welt, tmp_path):
    wurzel, key, run = welt
    getarnt = tmp_path / "transkript.txt"
    getarnt.write_bytes(FIXTURE.read_bytes())
    r = run("ingest", str(getarnt), "--record", REC, "--json")
    assert r.returncode == 2
    assert "nicht geraten" in json.loads(r.stdout)["reason"]


def test_a_second_ingest_of_the_same_source_does_not_register_the_record_twice(welt):
    wurzel, key, run = welt
    assert run("ingest", str(FIXTURE), "--record", REC).returncode == 3
    zweite = json.loads(run("ingest", str(FIXTURE), "--record", REC, "--json").stdout)
    assert zweite["details"]["neuer_record"] is False

    j = Journal(journal_path(wurzel), key=key.read_bytes())
    j.verify()
    assert len(j.events(kind="record.registered", record_id=REC)) == 1


def test_ingest_without_the_required_key_is_config_not_a_silent_write(tmp_path):
    """``childlux`` verlangt eine authentifizierte Kette. Ohne Schlüssel darf
    der erste Schreibbefehl nicht schreiben — und nicht so tun, als hätte er."""
    wurzel = tmp_path / "daten"
    assert cli("--profile", "childlux", "init", root=wurzel).returncode == 2
    r = cli(
        "--profile", "childlux", "ingest", str(FIXTURE), "--record", "CHILDLUX-0007", root=wurzel
    )
    assert r.returncode == 2, r.stdout
    assert not journal_path(wurzel).exists()


# ------------------------------------------- genau EIN Aufrufer der Wache


def test_require_write_has_exactly_one_caller_in_the_application_layer():
    """Der Test, der rot wird, sobald ein ZWEITER Schreibpfad entsteht.

    Eine Wache mit zwei Aufrufern ist noch keine Lücke — aber sie ist der
    Anfang davon: Der zweite Aufrufer wird kopiert, der dritte vergisst sie,
    und niemand merkt es, weil die Wache ja „aufgerufen wird". Der
    RETIRED-Marker im Vorgängersystem war genau das: vorhanden, geprüft, an
    zwei Stellen umgangen.

    Wenn hier ein neuer Schreibpfad auftaucht, ist das kein Fehler — aber er
    gehört in diese Liste, und zwar bewusst.
    """
    #: Jeder Schreibpfad, der die Wache passiert — als ``datei::funktion`` und
    #: nicht als Dateiname. Die erste Fassung zaehlte Dateien und verlangte
    #: zusaetzlich, dass es insgesamt genau EIN Aufruf sei; damit war jeder
    #: zweite Schreibpfad rot, auch der bewusst eingetragene. Gemeint war nie
    #: „genau einer", sondern „jeder benannt": Was hier nicht steht, kommt
    #: nicht durch, und was hier steht, hat jemand hingeschrieben.
    #:
    #: ``write_b3b_ingest_srt`` kam am 05.09.2026 dazu (B3b-Ingest ueber das
    #: CLI). Er baut seinen Ledger selbst, damit kein Aufrufer ihn weglassen
    #: kann — deshalb steht die Wache dort und nicht in ``cli/main.py``.
    erlaubt = {
        "src/ohpipe/application/ingest.py::ingest",
        "src/ohpipe/application/ingest.py::write_b3b_ingest_srt",
        "src/ohpipe/application/input_sources.py::observe",
        "src/ohpipe/application/decision_actions.py::write_action",
        "src/ohpipe/application/manual_work.py::snapshot",
        "src/ohpipe/application/manual_work.py::refresh",
    }

    wurzel = Path(__file__).resolve().parents[1]
    gefunden: set[str] = set()
    doppelt: dict[str, int] = {}
    for datei in sorted((wurzel / "src").rglob("*.py")):
        baum = ast.parse(datei.read_text(encoding="utf-8"))
        for knoten in ast.walk(baum):
            if not isinstance(knoten, ast.FunctionDef):
                continue
            n = sum(
                1
                for k in ast.walk(knoten)
                if isinstance(k, ast.Call)
                and isinstance(k.func, ast.Attribute)
                and k.func.attr == "require_write"
            )
            if n:
                stelle = f"{datei.relative_to(wurzel)}::{knoten.name}"
                gefunden.add(stelle)
                if n > 1:
                    doppelt[stelle] = n

    assert gefunden == erlaubt, (
        f"Aufrufer von require_write haben sich geändert: {sorted(gefunden)}. "
        f"Erwartet genau {sorted(erlaubt)}. Ein neuer Schreibpfad ist erlaubt — "
        f"aber er gehört hier ausdrücklich eingetragen, nicht stillschweigend."
    )
    assert doppelt == {}, (
        f"Mehrfachaufrufe in derselben Funktion: {doppelt}. Zwei Aufrufe an einer "
        "Stelle heissen, dass ein Zweig die Wache umgehen kann, ohne dass diese "
        "Liste sich ändert."
    )


# ------------------------------------------------- Runde 8: vier Befunde


def test_ingest_and_doctor_use_the_same_store(welt):
    """P0 aus Runde 8, und der Grund, warum er 438 Tests überlebt hat.

    ``ContentStore`` leitet sein Verzeichnis selbst als ``root/"objects"`` ab.
    ``ingest`` reichte ``ws.objects`` hinein und schrieb damit nach
    ``objects/objects/<sha>``; ``doctor`` und ``status`` lasen eine Ebene
    höher. Jede Stelle war für sich konsistent — sie schrieb und las, was sie
    selbst konstruiert hatte. Nur ein Test, der ``ingest`` und DANACH
    ``doctor`` laufen lässt, sieht es.

    Verdeckt wurde es zusätzlich davon, dass ``source.ingested`` noch kein
    ``artifact.produced`` ist: ``referenced_addresses`` blieb leer, also
    schlug ``status`` nichts nach.
    """
    wurzel, key, run = welt
    assert run("ingest", str(FIXTURE), "--record", REC).returncode == 3

    eintraege = sorted(p.name for p in (wurzel / "objects").iterdir())
    assert eintraege and all(len(n) == 64 for n in eintraege), (
        f"Objektverzeichnis enthält Nicht-Adressen: {eintraege}"
    )

    d = run("doctor", "--json")
    assert d.returncode == 0, json.loads(d.stdout)["reason"]


def test_ingesting_the_same_bytes_twice_appends_nothing(welt):
    """Append-only: erzeugtes Rauschen ist nicht mehr entfernbar. Und
    „hat das geklappt? nochmal" ist die normalste Operatorhandlung, die es
    gibt."""
    wurzel, key, run = welt
    assert run("ingest", str(FIXTURE), "--record", REC).returncode == 3
    zweite = run("ingest", str(FIXTURE), "--record", REC, "--json")
    d = json.loads(zweite.stdout)
    assert d["details"]["bereits_vorhanden"] is True
    assert d["changed"] == [], d["changed"]
    assert "bereits" in d["reason"]

    j = Journal(journal_path(wurzel), key=key.read_bytes())
    j.verify()
    assert len(j.events(kind="source.ingested", record_id=REC)) == 1


def test_the_call_that_registered_the_record_says_so_even_if_the_source_was_there(welt):
    """CHANGED ist vollständig: Jede Änderung wird von genau einem Aufruf behauptet.

    Der Befund kam aus einem erzwungenen Interleaving: Gewinnt Aufruf A
    ``record.registered`` und Aufruf B ``source.ingested``, meldeten **beide**
    ``neuer_record=False`` — B zu Recht, A weil der Frühausstieg es hart setzte
    und das Ergebnis des ersten ``append_once`` wegwarf. Der Record war
    angelegt, und niemand behauptete es.

    Hier deterministisch **ohne Threads**: Die Quelle liegt schon im Journal,
    der Record ist noch nicht registriert — genau die Lage, die das
    Interleaving erzeugt, nur reproduzierbar.

    **Warum die Zusicherung auf dem JOURNALPFAD sitzt und nicht auf
    ``changed != []``.** Der Objekteintrag wandert in ``geschrieben``,
    *bevor* über das Anhängen entschieden wird — er ist also unabhängig von
    dieser Reparatur da. Eine Prüfung auf „nicht leer" wäre auch dann grün,
    wenn der Journalpfad weiter vergessen würde. Unterscheidend ist allein,
    dass der Journalpfad dabei ist.

    Die Gegenprobe steht nebenan: ``test_ingesting_the_same_bytes_twice_
    appends_nothing`` verlangt für den echten Wiederholungsfall ``changed == []``.
    """
    import hashlib

    from ohpipe.domain.events import SOURCE_INGESTED

    wurzel, key, run = welt
    roh = FIXTURE.read_bytes()
    adresse = hashlib.sha256(roh).hexdigest()

    j = Journal(journal_path(wurzel), key=key.read_bytes())
    j.append(
        SOURCE_INGESTED,
        {
            "record_id": REC,
            "sha256": adresse,
            "media_type": "application/x-subrip",
            "filename": FIXTURE.name,
            "bytes": len(roh),
        },
        record_id=REC,
    )

    d = json.loads(run("ingest", str(FIXTURE), "--record", REC, "--json").stdout)

    assert d["details"]["address"] == adresse, (
        "Der Store adressiert anders als sha256(Rohbytes) — dann trifft das "
        "vorgelegte Ereignis nicht und der Test prüft den falschen Zweig."
    )
    assert d["details"]["bereits_vorhanden"] is True, (
        "Die Quelle lag vor — sonst prüft dieser Test den falschen Zweig."
    )
    assert d["details"]["neuer_record"] is True, (
        "Dieser Aufruf hat record.registered geschrieben und muss es behaupten."
    )
    assert any(c.endswith("journal.jsonl") for c in d["changed"]), (
        f"Die Journaländerung fehlt in CHANGED: {d['changed']}"
    )
    assert "Nichts angehängt" not in d["reason"], (
        f"Die Meldung widerspricht CHANGED: {d['reason']!r} bei changed={d['changed']}"
    )

    j2 = Journal(journal_path(wurzel), key=key.read_bytes())
    j2.verify()
    assert len(j2.events(kind=SOURCE_INGESTED, record_id=REC)) == 1, (
        "Die Adresse muss getroffen haben — sonst wäre eine zweite Fassung "
        "entstanden und `neuer_record` wäre aus dem falschen Grund True."
    )


def test_a_different_source_for_the_same_record_is_history_not_a_duplicate(welt, tmp_path):
    """Andere Bytes sind eine neue Fassung, kein Duplikat. Maßgeblich ist der
    Hash, nicht der Dateiname."""
    wurzel, key, run = welt
    assert run("ingest", str(FIXTURE), "--record", REC).returncode == 3
    zweite_datei = tmp_path / "revision.srt"
    geaendert = FIXTURE.read_bytes().replace(b"Winter", b"Sommer")
    # Die zweite Fassung muss sich wirklich unterscheiden. Ohne diese Zeile
    # koennte eine Aenderung an der Beispieldatei das Ersetzen ins Leere laufen
    # lassen; der Test faele dann zwar, aber mit der falschen Begruendung.
    assert geaendert != FIXTURE.read_bytes(), (
        f"{FIXTURE.name} enthaelt kein 'Winter' mehr — die zweite Fassung waere "
        "byteidentisch und dieser Test pruefte den Duplikatzweig."
    )
    zweite_datei.write_bytes(geaendert)
    d = json.loads(run("ingest", str(zweite_datei), "--record", REC, "--json").stdout)
    assert d["details"]["bereits_vorhanden"] is False
    j = Journal(journal_path(wurzel), key=key.read_bytes())
    assert len(j.events(kind="source.ingested", record_id=REC)) == 2


@pytest.mark.parametrize(
    "wert,warum",
    [
        ("ohpipe", "Profil erklärt sich selbst zum Vorgängersystem"),
        ("wasauchimmer", "unbekanntes Laufzeitsystem"),
    ],
)
def test_legacy_runtime_is_treated_like_the_other_two_safety_switches(tmp_path, wert, warum):
    """Der dritte Sicherheitsschalter bekam zunächst keine der Behandlungen
    der ersten beiden. ``legacy_runtime = "ohpipe"`` heisst: unbekannte
    Records gehören uns — exakt das Fail-open, gegen das ADR 0009/0014
    stehen."""
    from ohpipe.project import Profile, ProfileError

    quelle = Path("src/ohpipe/profiles/childlux/profile.toml").read_text(encoding="utf-8")
    ziel = tmp_path / "profile.toml"
    ziel.write_text(
        quelle.replace('legacy_runtime = "dinoh"', f'legacy_runtime = "{wert}"'), "utf-8"
    )
    with pytest.raises(ProfileError, match="legacy_runtime"):
        Profile.load(ziel)


def test_a_production_profile_must_declare_legacy_runtime(tmp_path):
    from ohpipe.project import Profile, ProfileError

    quelle = Path("src/ohpipe/profiles/childlux/profile.toml").read_text(encoding="utf-8")
    ziel = tmp_path / "profile.toml"
    ziel.write_text(quelle.replace('legacy_runtime = "dinoh"', ""), "utf-8")
    with pytest.raises(ProfileError, match="legacy_runtime"):
        Profile.load(ziel)


def test_the_ledger_keeps_the_profile_default_even_when_the_file_exists(tmp_path):
    """Dieselbe Frage bekam zwei Antworten je nach Aufrufweg.

    ``load()`` gab ``default_runtime`` hartkodiert als ``dinoh`` zurück, sobald
    ``cutover.json`` existierte — der übergebene Profilwert wurde verworfen.
    Heute latent, weil die Wache ``from_journal`` benutzt. Latent heisst nicht
    harmlos: Es ist die zweite Wahrheit eine Ebene unter der, die
    ``legacy_runtime`` im Profil beseitigt hat.
    """
    from ohpipe.policies.ownership import CutoverLedger

    p = tmp_path / "cutover.json"
    ohne_datei = CutoverLedger.load(p, default_runtime="ohpipe")
    assert ohne_datei.may_write("IRGENDWAS-001") is True

    CutoverLedger(default_runtime="ohpipe").save(p)
    mit_datei = CutoverLedger.load(p, default_runtime="ohpipe")
    assert mit_datei.default_runtime == "ohpipe"
    assert mit_datei.may_write("IRGENDWAS-001") is True


def test_the_lossless_tripwire_still_fires_when_it_is_reached(tmp_path, monkeypatch):
    """Der Stolperdraht, den heute keine Eingabe auslöst — direkt konstruiert.

    Klaus' Einwand: Ein Stolperdraht, den kein Test auslösen kann, ist auch
    unsichtbar, wenn er reisst. Also wird der unerreichbare Zustand hier am
    Parser vorbei hergestellt — dieselbe Bewegung wie beim Umgehen des
    Konstruktors in den Fälschungstests. Nach der nächsten Parseränderung
    weiss damit jemand, ob der Vergleich noch funktioniert.

    Simuliert wird genau das eine Szenario, gegen das er steht: ein Parser,
    der akzeptiert, was er nicht bytegleich zurückgibt.
    """
    from ohpipe.application import ingest as modul
    from ohpipe.domain.cue import CueDocument

    quelle = tmp_path / "x.srt"
    quelle.write_bytes(FIXTURE.read_bytes())

    monkeypatch.setattr(CueDocument, "render_bytes", lambda self: b"etwas anderes als die Eingabe")
    with pytest.raises(modul.IngestError, match="bytegleich"):
        modul.ingest(_DummyWs(tmp_path), None, _DummyLedger(), quelle, REC)


class _DummyLedger:
    def require_write(self, record_id: str) -> None:
        return None


class _DummyWs:
    """Nur so viel Workspace, wie ``ingest`` bis zum Stolperdraht braucht."""

    def __init__(self, wurzel: Path) -> None:
        self.root = wurzel

        class P:
            id = "sandbox"
            record_prefix = "SANDBOX"
            record_digits = 3

            @staticmethod
            def normalize_record_id(v: str) -> str:
                return v

            @staticmethod
            def is_record_id(v: str) -> bool:
                return True

        self.profile = P()


# ------------------------------------------- E9 nebenläufig (Befund B2, 05.08.)


@pytest.mark.parametrize("runde", (1, 2, 3))
def test_concurrent_ingest_of_the_same_bytes_writes_exactly_once(tmp_path, runde):
    """Idempotenz muss auch NEBENLÄUFIG gelten, sonst ist sie keine.

    Die Vorgängerfassung las das Journal als Listenausdruck **vor** dem
    ``append``. Sequenziell war das idempotent — der Test dafür war grün. Acht
    gleichzeitige Aufrufe schrieben trotzdem acht ``record.registered`` und
    acht ``source.ingested``: Prüfen und Handeln lagen auf verschiedenen Seiten
    der Sperre.

    Das Tückische daran ist, wie harmlos es aussieht. Die Hashkette bleibt
    heil — jeder Schreiber hält die Sperre beim Anhängen —, ``doctor`` meldet
    READY, und weil das Journal append-only ist, bleibt das Rauschen für immer
    drin. Ein Befund, den keine Integritätsprüfung je meldet.

    **Die Barriere ist der Test.** Ohne sie starten acht Aufrufe hintereinander
    statt gleichzeitig, das Fenster geht nie auf, und der Test bezeugt nur, dass
    sequenzielle Idempotenz funktioniert — die war nie das Problem. Fünf
    CLI-Unterprozesse reproduzieren es aus demselben Grund nicht: der
    Interpreterstart staffelt sie.

    **Drei Runden, nicht eine.** Bei einem Durchlauf hielt der Test die
    zugehoerige Mutation in 19 von 20 Laeufen — einmal in zwanzig meldete
    `mutanten.py` "ueberlebt" und damit einen falschen Befund. Ein
    Nebenlaeufigkeitsfenster geht nicht in jedem Anlauf auf; ein Pruefer,
    der in 5 % der Faelle das Gegenteil behauptet, ist schlimmer als
    keiner. Mit drei Runden: mutiert 20 von 20 gefallen, unmutiert 0 von 20.
    """
    import threading

    from ohpipe.application.ingest import ingest
    from ohpipe.cli.main import _profile_path
    from ohpipe.policies.ownership import CutoverLedger
    from ohpipe.project import Workspace

    N = 8
    wurzel = tmp_path / "daten"
    ws = Workspace.resolve(_profile_path("sandbox"), wurzel)
    ws.ensure()
    journal = Journal(ws.journal_path)
    ledger = CutoverLedger(default_runtime=ws.profile.legacy_runtime or "ohpipe")

    tor = threading.Barrier(N)
    fehler: list[BaseException] = []

    def lauf() -> None:
        try:
            tor.wait(timeout=10)  # alle acht gleichzeitig losschicken
            ingest(ws, journal, ledger, FIXTURE, REC)
        except BaseException as exc:  # noqa: BLE001 — der Test wertet aus
            fehler.append(exc)

    faeden = [threading.Thread(target=lauf) for _ in range(N)]
    for f in faeden:
        f.start()
    for f in faeden:
        f.join(timeout=30)

    assert not fehler, f"Aufrufe scheiterten: {fehler[:2]}"

    gezaehlt: dict[str, int] = {}
    for e in journal:
        gezaehlt[e.kind] = gezaehlt.get(e.kind, 0) + 1
    assert gezaehlt.get("record.registered") == 1, gezaehlt
    assert gezaehlt.get("source.ingested") == 1, gezaehlt

    # Und die Kette ist heil — das war sie vorher auch. Genau deshalb steht die
    # Zusicherung hier UNTER den Zählungen: Sie ist die schwächere Aussage und
    # darf nicht als Beleg für die stärkere durchgehen.
    journal.verify()
