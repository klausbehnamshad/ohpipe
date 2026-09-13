"""Der Eingabeweg für die Pflichtfelder des Metadata Models.

Bis hierher setzte ``metadata.derive`` genau ein Feld: den ``record_id``. Die
sechs übrigen Pflichtfelder standen als offene Anforderungen im Entwurf, und
unter einem produktiven Profil fiel der Record am Ausgang an der Exportsperre
(``export.py::ExportBlocked``). Es gab keinen Weg, sie einzutragen.

Jetzt gibt es einen, und er ist eine Datei: ``_governance/metadata/<ID>.toml``,
einmal je Interview vom Operator geschrieben. Was diese Datei besonders macht
und was diese Fälle deshalb messen:

1. **Ihre Rohbytes gehen in den Store**, ihr Digest als ``metadata.input`` in
   die Belegeingaben. Ein Katalogeintrag lässt sich damit auf die Bytes
   zurückführen, die ein Mensch getippt hat.
2. **Sie trägt die Herkunft der Rechtezusage** (``consent_reference``).
   ``consent_status`` wird nicht hier entschieden, sondern vom Controller
   ausserhalb; der Beleg soll sagen, worauf die Zusage beruht.
3. **Sie nennt ihren eigenen Record.** Der Dateiname ist keine Prüfung.
4. **Fehlt sie, hält ein produktives Profil an** — die synthetische Übungswelt
   dagegen läuft weiter wie bisher.

Der letzte Fall dieser Datei spielt durch, was ein späteres ÄNDERN bedeutet.
Er ist der einzige, der die volle Kette über die CLI fährt: Die Wirkung einer
Änderung entsteht im Zusammenspiel von Ableitungs- und Entscheidungsachse, und
die lässt sich an einem Aufruf von ``run_metadata_derive`` nicht messen.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ohpipe.application.catalog import metadata_input_path, run_metadata_derive
from ohpipe.application.replay import replay
from ohpipe.application.steps import StepContext
from ohpipe.domain.step import build_graph
from ohpipe.domain.transcript import Segment
from ohpipe.journal import Journal
from ohpipe.policies.authority import Authority
from ohpipe.policies.metadata import (
    RECORD_INPUT_KEYS,
    RecordMetadataError,
    load_record_metadata,
)
from ohpipe.project import Profile, Workspace

from ._forge import cli_keyed, journal_path, report_lines

PROFIL = Path(__file__).resolve().parents[1] / "src" / "ohpipe" / "profiles" / "sandbox"
AUSGELIEFERT = Path(__file__).resolve().parents[1] / "examples" / "synthetic" / "SANDBOX-001.srt"
RECORD = "SANDBOX-001"
ENTSCHIEDEN_AM = "2026-09-01T11:00:00+00:00"

SEGMENTE = (
    Segment(0, 500, 5200, "Wie sah der Schulweg damals aus?", "INTERVIEWER", "deu"),
    Segment(
        1,
        5600,
        13400,
        "Wir sind jeden Morgen zu Fuss gegangen, auch im Winter.",
        "ZEITZEUGIN",
        "deu",
    ),
)

VOLLSTAENDIG = {
    "record_id": RECORD,
    "interview_date": "2026-09-01",
    "interviewer": "Synthetic Interviewer",
    "consent_status": "research-only",
    "accessRights": "restricted",
    "title": "Synthetisches Interview zur Abnahme",
    "language": "deu",
    "consent_reference": "SYNTHETIC-CONSENT-REF",
}


def _toml(werte: dict[str, object]) -> str:
    zeilen = ["[record]"] + [f'{k} = "{v}"' for k, v in werte.items() if v is not None]
    return "\n".join(zeilen) + "\n"


def _schreibe(ws: Workspace, record_id: str = RECORD, **abweichungen) -> Path:
    werte = dict(VOLLSTAENDIG)
    werte.update(abweichungen)
    pfad = metadata_input_path(ws, record_id)
    pfad.parent.mkdir(parents=True, exist_ok=True)
    pfad.write_text(_toml(werte), encoding="utf-8")
    return pfad


def _ws(tmp_path: Path, *, production: bool = False) -> tuple[Workspace, Journal]:
    """Ein Arbeitsbereich mit adjudizierter Ausgangslage, ohne die volle Kette.

    ``metadata.derive`` verlangt genau eine Eingabe: ``l1.adjudicated``. Der
    Weg dorthin ist an anderer Stelle gemessen (``test_l1_suggest``,
    ``test_b3b_cli_chain``); ihn hier nachzufahren, hiesse dieselben Schritte
    ein drittes Mal zu pruefen und den Gegenstand dieses Moduls zu verdecken.
    """
    from dataclasses import replace

    profil = Profile.load(PROFIL / "profile.toml")
    if production:
        profil = replace(profil, production=True)
    ws = Workspace(tmp_path / "data", profil)
    ws.ensure()
    ws.bind_graph_initially()
    from .test_forgery import wellformed_chain

    journal = Journal(ws.journal_path, key=b"P3-independent-synthetic-journal-key")
    for event in wellformed_chain(ws.root):
        # Nur die vollständige Vorstufe bis einschließlich Adjudikation.
        artifact = event["payload"].get("artifact")
        if artifact not in {
            "transcript.revision",
            "transcript.confirmed",
            "l1.suggestions",
            "l1.coverage",
            "l1.adjudicated",
        }:
            continue
        journal.append(event["kind"], event["payload"], record_id=RECORD)
    return ws, journal


def _ctx(ws: Workspace, journal: Journal) -> StepContext:
    return StepContext(
        ws=ws,
        journal=journal,
        record_id=RECORD,
        profile_arg="sandbox",
        confirm=True,
        options={},
    )


def _view(ws: Workspace, journal: Journal):
    return replay(journal, graph=build_graph(ws.profile), authority=Authority.UNAUTHENTICATED)[
        RECORD
    ]


def _entwurf(ws: Workspace, sha: str) -> dict:
    return json.loads((ws.objects / sha).read_bytes())


def _beleg(journal_pfad: Path, step: str) -> dict:
    belege = [
        json.loads(z)["payload"]
        for z in journal_pfad.read_text(encoding="utf-8").splitlines()
        if z.strip() and json.loads(z)["kind"] == "receipt.recorded"
    ]
    return [b for b in belege if b.get("step") == step][-1]


# ============================================================ die Datei allein


def test_the_input_file_carries_the_seven_model_fields_and_the_consent_reference():
    """Acht Schlüssel, und der achte gehört ausdrücklich nicht ins Modell.

    ``consent_reference`` steht nicht in der DCTAP, und das ist kein Versehen:
    Das Metadata Model beschreibt das Interview, nicht den Verwaltungsakt, auf
    dem seine Freigabe beruht. Deshalb wandert der Wert auch nicht in
    ``fields`` — dort meldete ihn ``check_record`` als Feld, das das Modell
    nicht kennt, und es hätte recht damit.
    """
    assert set(RECORD_INPUT_KEYS) == set(VOLLSTAENDIG), RECORD_INPUT_KEYS
    assert "consent_reference" in RECORD_INPUT_KEYS


def test_an_unknown_key_in_the_input_file_is_an_error(tmp_path):
    """Ein Tippfehler im Feldnamen täte sonst still nichts.

    Der Wert stünde da, das Pflichtfeld bliebe offen, und die einzige Auskunft
    wäre die zweite Hälfte davon. Deshalb hält die Datei an, statt nur zu
    bemängeln.
    """
    pfad = tmp_path / "x.toml"
    pfad.write_text(_toml(dict(VOLLSTAENDIG) | {"interviewr": "K"}), encoding="utf-8")
    with pytest.raises(RecordMetadataError) as fehler:
        load_record_metadata(pfad, record_id=RECORD)
    assert "interviewr" in str(fehler.value), str(fehler.value)


@pytest.mark.parametrize("fehlt", RECORD_INPUT_KEYS)
def test_every_key_of_the_input_file_is_actually_required(tmp_path, fehlt):
    """Für keine dieser Angaben gibt es einen sicheren Vorgabewert.

    Parametrisiert über die Liste selbst, nicht über eine Handkopie: Kommt ein
    Schlüssel dazu, prüft dieser Fall ihn mit, ohne dass jemand daran denkt.
    """
    werte = {k: v for k, v in VOLLSTAENDIG.items() if k != fehlt}
    pfad = tmp_path / f"{fehlt}.toml"
    pfad.write_text(_toml(werte), encoding="utf-8")
    with pytest.raises(RecordMetadataError) as fehler:
        load_record_metadata(pfad, record_id=RECORD)
    assert fehlt in str(fehler.value), str(fehler.value)


def test_a_record_id_that_does_not_match_the_call_is_an_error(tmp_path):
    """Der Dateiname ist keine Prüfung.

    Eine kopierte, umbenannte oder in den falschen Ordner gelegte Eingabedatei
    ist genau der Fehler, der unbemerkt in einen Katalogeintrag läuft — und
    dort ist er nicht mehr sichtbar. Die Angabe steht deshalb doppelt, und die
    Abweichung hält an.
    """
    pfad = tmp_path / "falsch.toml"
    pfad.write_text(_toml(dict(VOLLSTAENDIG) | {"record_id": "SANDBOX-999"}), encoding="utf-8")
    with pytest.raises(RecordMetadataError) as fehler:
        load_record_metadata(pfad, record_id=RECORD)
    text = str(fehler.value)
    assert "SANDBOX-999" in text and RECORD in text, text


@pytest.mark.parametrize(
    ("abweichung", "erwartet"),
    [
        ({"consent_reference": "zwei Wörter"}, "consent_reference"),
        ({"consent_reference": "ab"}, "consent_reference"),
        ({"language": "de"}, "language"),
        ({"language": "DEU"}, "language"),
        ({"interview_date": "gestern"}, "interview_date"),
        ({"interview_date": "01.09.2026"}, "interview_date"),
    ],
)
def test_the_loader_enforces_the_form_of_reference_language_and_date(
    tmp_path, abweichung, erwartet
):
    """Formstrenge im Loader, nicht in ``check_record``.

    ``check_record`` liefert Befunde und wirft nicht; es ist die Modellprüfung
    und hat weitere Aufrufer. Der Loader ist die Formprüfung EINER
    Operatoreingabe. Zwei Prüfungen, zwei Orte — dasselbe Muster wie
    ``Profile.load`` gegenüber ``Profile.check_model``.

    Die Referenz trägt dieselbe Strenge wie eine Entscheidungsreferenz, weil
    sie dieselbe Aufgabe hat: nachschlagbar sein. Ein mehrwortiger Freitext
    wäre eine Notiz, und eine Notiz schlägt niemand nach.
    """
    pfad = tmp_path / "form.toml"
    pfad.write_text(_toml(dict(VOLLSTAENDIG) | abweichung), encoding="utf-8")
    with pytest.raises(RecordMetadataError) as fehler:
        load_record_metadata(pfad, record_id=RECORD)
    assert erwartet in str(fehler.value), str(fehler.value)


# ============================================================ check_record


def test_check_record_now_refuses_a_date_that_is_not_a_date():
    """Der ``valueDatatype`` der DCTAP wird geprüft, nicht nur mitgeführt.

    Gemessen vor diesem Akt: ``interview_date = "gestern"`` lief ohne einen
    einzigen Befund durch. Ein Wertebereich, der nur dasteht, ist keiner — und
    ein Katalogeintrag mit einem Datum, das keines ist, kam an keiner Stelle
    mehr zum Halt.
    """
    from ohpipe.policies.metadata import check_record

    gueltig = {k: v for k, v in VOLLSTAENDIG.items() if k != "consent_reference"}
    assert check_record(gueltig) == []
    befunde = check_record(gueltig | {"interview_date": "gestern"})
    assert any("interview_date" in b and "ISO 8601" in b for b in befunde), befunde


def test_check_record_now_names_a_field_the_model_does_not_know():
    """Ein unbekannter Feldname ist ein Befund und kein Beifang."""
    from ohpipe.policies.metadata import check_record

    gueltig = {k: v for k, v in VOLLSTAENDIG.items() if k != "consent_reference"}
    befunde = check_record(gueltig | {"interviewr": "K"})
    assert any("interviewr" in b and "Metadata Models" in b for b in befunde), befunde


def test_check_record_reads_repeatable_from_the_dctap():
    """``keywords`` ist wiederholbar und trägt deshalb eine Liste.

    Ohne diese Unterscheidung fiele ein gültiges ``keywords = ["a", "b"]`` an
    einer Typregel, die es gar nicht meint — die Typprüfung hätte dann mehr
    kaputtgemacht, als sie schließt.
    """
    from ohpipe.policies.metadata import check_record

    gueltig = {k: v for k, v in VOLLSTAENDIG.items() if k != "consent_reference"}
    assert check_record(gueltig | {"keywords": ["Schulweg", "Winter"]}) == []
    befunde = check_record(gueltig | {"keywords": "Schulweg"})
    assert any("keywords" in b and "Liste" in b for b in befunde), befunde


# ============================================================ metadata.derive


def test_without_an_input_file_a_sandbox_derives_exactly_as_before(tmp_path):
    """Die synthetische Übungswelt läuft weiter wie bisher.

    Sie soll die ganze Kette zeigen dürfen, gerade weil ihr Record keine
    Erschliessung hat — derselbe Satz, mit dem die Exportsperre in
    ``export.py`` auf produktive Profile beschränkt ist.
    """
    ws, journal = _ws(tmp_path)
    ergebnis = run_metadata_derive(_ctx(ws, journal), _view(ws, journal))
    entwurf = _entwurf(ws, ergebnis.artifact_sha256)
    assert entwurf["fields"] == {"record_id": RECORD}
    assert len(entwurf["open_requirements"]) == 6, entwurf["open_requirements"]
    assert entwurf["metadata_input"] is None and entwurf["consent_reference"] is None
    assert "metadata.input" not in _beleg(journal.path, "metadata.derive")["inputs"]


def test_without_an_input_file_a_production_profile_stops_and_names_the_path(tmp_path):
    """Für reale Daten ist ein Entwurf ohne Einwilligungs- und Rechteangabe
    kein Entwurf, sondern eine leere Form mit einem Recordnamen.

    Der Pfad steht in der Meldung, weil „es fehlt etwas" ohne ihn nicht
    handlungsfähig macht. Und es wird nichts geschrieben: kein halber Entwurf,
    den später jemand für vollständig hält.
    """
    ws, journal = _ws(tmp_path, production=True)
    vorher = journal.head()
    with pytest.raises(RecordMetadataError) as fehler:
        run_metadata_derive(_ctx(ws, journal), _view(ws, journal))
    text = str(fehler.value)
    assert str(metadata_input_path(ws, RECORD)) in text, text
    assert "nichts geschrieben" in text
    assert journal.head() == vorher


def test_a_complete_input_file_closes_every_open_requirement(tmp_path):
    """Sieben Felder im Entwurf, null offene Anforderungen.

    Das ist der Punkt der ganzen Scheibe: Unter einem produktiven Profil fällt
    dieser Record am Ausgang jetzt nicht mehr an der Exportsperre, weil ihm
    nichts mehr fehlt.
    """
    ws, journal = _ws(tmp_path, production=True)
    _schreibe(ws)
    ergebnis = run_metadata_derive(_ctx(ws, journal), _view(ws, journal))
    entwurf = _entwurf(ws, ergebnis.artifact_sha256)
    assert entwurf["open_requirements"] == [], entwurf["open_requirements"]
    assert entwurf["fields"]["consent_status"] == "research-only"
    assert entwurf["fields"]["accessRights"] == "restricted"
    assert "consent_reference" not in entwurf["fields"], "die Herkunft gehört nicht ins Modell"


def test_the_raw_bytes_go_into_the_store_and_their_digest_into_the_receipt(tmp_path):
    """Der Weg von der getippten Datei zum Beleg, byteweise nachprüfbar.

    Kanonisiert wird nichts: Was der Operator geschrieben hat, IST die Aussage.
    Bei einem Streit über ``consent_status`` will man genau diese Datei sehen
    und nicht eine geglättete Zweitfassung, deren Verhältnis zur ersten
    niemand belegt.
    """
    from ohpipe.domain.hashing import sha256_bytes

    ws, journal = _ws(tmp_path, production=True)
    pfad = _schreibe(ws)
    roh = pfad.read_bytes()

    ergebnis = run_metadata_derive(_ctx(ws, journal), _view(ws, journal))
    adresse = sha256_bytes(roh)

    assert (ws.objects / adresse).read_bytes() == roh, "die Rohbytes liegen nicht im Store"
    beleg = _beleg(journal.path, "metadata.derive")
    assert beleg["inputs"]["metadata.input"] == adresse, beleg["inputs"]
    entwurf = _entwurf(ws, ergebnis.artifact_sha256)
    assert entwurf["metadata_input"] == adresse


def test_the_consent_reference_travels_into_the_draft(tmp_path):
    """Der Beleg sagt, WORAUF die Zusage beruht, nicht nur wer sie getippt hat.

    ``consent_status`` wird nicht beim Eintragen entschieden, sondern vom
    Controller ausserhalb dieses Systems; was hier passiert, ist eine
    Übertragung. Ohne die Referenz wäre im Katalogeintrag eine Rechtezusage
    ohne auffindbaren Grund.

    Sie steht in den Entwurfsbytes und nicht in ``inputs``: ``inputs`` bildet
    Namen auf Hashes ab, und eine Referenz ist kein Hash. Der Beleg nennt die
    Entwurfsbytes über ``output_sha256``, und die Bytes tragen die Referenz.
    """
    ws, journal = _ws(tmp_path, production=True)
    _schreibe(ws, consent_reference="ERP-26-049")
    ergebnis = run_metadata_derive(_ctx(ws, journal), _view(ws, journal))
    entwurf = _entwurf(ws, ergebnis.artifact_sha256)
    assert entwurf["consent_reference"] == "ERP-26-049"
    assert _beleg(journal.path, "metadata.derive")["output_sha256"] == ergebnis.artifact_sha256


def test_a_consent_status_outside_the_profile_vocabulary_stays_an_open_requirement(tmp_path):
    """Ein Modellbefund hält den Schritt NICHT an — er bleibt eine offene Anforderung.

    Die Trennung ist die bestehende Architektur: Ableiten sagt, was fehlt; der
    Ausgang entscheidet, ob das reicht (``export.py``). Ein zweiter Halt an
    früherer Stelle machte die Sperre am Ausgang unprüfbar, weil sie nie mehr
    feuerte.
    """
    ws, journal = _ws(tmp_path, production=True)
    _schreibe(ws, consent_status="erfunden")
    ergebnis = run_metadata_derive(_ctx(ws, journal), _view(ws, journal))
    entwurf = _entwurf(ws, ergebnis.artifact_sha256)
    assert any("Profilvokabular" in o for o in entwurf["open_requirements"]), entwurf


def test_a_malformed_input_file_stops_both_profile_kinds(tmp_path):
    """Eine kaputte Datei ist etwas anderes als keine Datei.

    Bei „keine" hat niemand etwas behauptet; bei „kaputt" schon, und was
    behauptet wurde, ist unklar. Deshalb hält auch die Sandbox an, obwohl sie
    ohne Datei weiterläuft.
    """
    for produktiv in (False, True):
        ws, journal = _ws(tmp_path / f"p{produktiv}", production=produktiv)
        pfad = metadata_input_path(ws, RECORD)
        pfad.parent.mkdir(parents=True, exist_ok=True)
        pfad.write_text('[record]\nrecord_id = "SANDBOX-001"\n', encoding="utf-8")
        with pytest.raises(RecordMetadataError):
            run_metadata_derive(_ctx(ws, journal), _view(ws, journal))


# ============================================================ das spätere Ändern


@pytest.fixture
def kette(tmp_path: Path):
    """Die volle Kette über die CLI bis vor ``metadata.derive``.

    Nachgefahren ist die Reihenfolge aus ``examples/synthetic/durchstich.sh``.
    Der Aufwand ist hier nötig und sonst nirgends: Was ein späteres Ändern
    bedeutet, entsteht im Zusammenspiel von Ableitungs- und
    Entscheidungsachse, und das lässt sich an einem Aufruf von
    ``run_metadata_derive`` nicht messen.
    """
    from ohpipe.domain.language_assignment import build_srt_draft

    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"
    ein = tmp_path / "ein"
    ein.mkdir()
    (ein / "iso.txt").write_bytes(b"deu\nfra\nltz\nund\nzxx\n")

    def run(*args: str):
        return cli_keyed(*args, root=wurzel, key=key)

    assert run("init").returncode == 0
    assert (
        run(
            "instance",
            "register",
            "KLAUS",
            "--source",
            "mensch",
            "--label",
            "Klaus",
            "--reference",
            "REF-1",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "iso6393",
            "prepare",
            str(ein / "iso.txt"),
            "--release",
            "iso.2025",
            "--reference",
            "REF-2",
            "--confirm",
        ).returncode
        == 0
    )

    draft = build_srt_draft(AUSGELIEFERT.read_bytes())
    sprachen = ("deu", "deu", "ltz", "fra", "deu")
    zeilen = ["index\tsegment_sha256\tlanguage"]
    zeilen += [f"{n}\t{s.sha256}\t{sprachen[n]}" for n, s in enumerate(draft.segments)]
    zuordnung = ein / "m.tsv"
    zuordnung.write_bytes(("\n".join(zeilen) + "\n").encode("ascii"))

    assert run("ingest", str(AUSGELIEFERT), "--record", RECORD).returncode == 3
    assert (
        run(
            "transcript",
            "language",
            "prepare",
            RECORD,
            str(AUSGELIEFERT),
            str(zuordnung),
            "--actor",
            "KLAUS",
            "--reference",
            "REF-3",
            "--confirm",
        ).returncode
        == 0
    )
    assert (
        run(
            "transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm"
        ).returncode
        == 0
    )
    assert run("transcript", "confirm", RECORD, "--actor", "KLAUS", "--confirm").returncode == 0
    assert run("continue", RECORD, "--confirm").returncode == 3
    assert run("l1", "review", RECORD, "--actor", "KLAUS", "--confirm").returncode == 0
    return wurzel, run


def _artefakt(run, name: str) -> dict:
    daten = json.loads(run("status", "--json").stdout)["details"]["records"][0]
    return daten["artifacts"].get(name, {})


def _entwuerfe(wurzel: Path) -> list[str]:
    """Alle je abgelegten ``metadata.draft``-Hashes, in Reihenfolge.

    Gezaehlt wird im Journal und nicht im Status: Der Status zeigt den
    aktuellen Stand, und die Frage dieses Abschnitts ist, ob ueberhaupt ein
    zweiter Entwurf ENTSTANDEN ist.
    """
    return [
        json.loads(z)["payload"]["sha256"]
        for z in journal_path(wurzel).read_text(encoding="utf-8").splitlines()
        if z.strip()
        and json.loads(z)["kind"] == "artifact.produced"
        and json.loads(z)["payload"].get("artifact") == "metadata.draft"
    ]


def test_the_input_file_counts_once_and_a_later_change_has_no_effect(kette):
    """Was ein späteres Ändern bedeutet — gemessen, nicht abgeleitet: NICHTS.

    Der Entwurf zu diesem Akt sagte voraus, eine geänderte Eingabedatei
    entwerte die Bestätigung, die auf der alten Angabe stand. Am laufenden
    Objekt gemessen stimmt das nicht. ``metadata.derive`` läuft **genau
    einmal**: Sobald ``metadata.draft`` vorliegt und READY ist, führt der
    Planer den Schritt nicht mehr aus (`Nichts auszuführen`), und zwar
    unabhängig davon, ob schon bestätigt wurde. Die Datei wird kein zweites
    Mal gelesen, es entstehen keine neuen Entwurfsbytes, und weil nichts sich
    bewegt, fällt auch nichts auf.

    Die Folge für den Operator, und sie gehört ins Handbuch: **Die
    Eingabedatei zählt zu dem Zeitpunkt, an dem ``metadata.derive`` das erste
    Mal läuft.** Wer danach etwas ändert, ändert eine Datei, die das System
    nicht mehr ansieht — und der Katalogeintrag trägt weiter die alte Zusage,
    ohne Hinweis darauf, dass daneben eine neuere Datei liegt.

    Die Ursache sitzt im Planer und nicht in diesem Schritt; sie zu beheben
    hiesse zu entscheiden, wann eine Ableitung ihre Eingaben erneut liest, und
    das ist ein eigener Gegenstand (offene Stelle in ``TRACEABILITY.md``).
    Dieser Fall hält den heutigen Stand fest, damit die Behebung ihn bewegt
    statt ihn zu bestätigen.
    """
    wurzel, run = kette
    governance = wurzel / "_governance" / "metadata"
    governance.mkdir(parents=True, exist_ok=True)
    eingabe = governance / f"{RECORD}.toml"
    eingabe.write_text(_toml(VOLLSTAENDIG), encoding="utf-8")

    assert run("continue", RECORD).returncode == 3
    erste_entwuerfe = _entwuerfe(wurzel)
    assert len(erste_entwuerfe) == 1, erste_entwuerfe
    assert run("metadata", "confirm", RECORD, "--actor", "KLAUS", "--confirm").returncode == 0
    bestaetigt_vorher = _artefakt(run, "metadata.confirmed")
    assert bestaetigt_vorher["status"] == "READY"

    # Eine andere Rechtezusage, nach der Bestaetigung eingetragen.
    eingabe.write_text(
        _toml(dict(VOLLSTAENDIG) | {"accessRights": "closed", "consent_status": "withdrawn"}),
        encoding="utf-8",
    )
    danach = run("continue", RECORD)
    assert danach.returncode == 3, danach.stdout

    # Gemessen: kein zweiter Entwurf, beide Artefakte unveraendert READY, und
    # die Kette laeuft zum naechsten Schritt weiter, als waere nichts gewesen.
    assert _entwuerfe(wurzel) == erste_entwuerfe, "es entstand doch ein zweiter Entwurf"
    assert _artefakt(run, "metadata.draft")["status"] == "READY"
    assert _artefakt(run, "metadata.confirmed") == bestaetigt_vorher
    assert "abstract" in report_lines(danach.stdout)["STATUS"], report_lines(danach.stdout)


def test_a_change_before_the_confirm_is_equally_unnoticed(kette):
    """Auch VOR der Bestätigung wird nicht neu gelesen.

    Der Unterschied wäre naheliegend gewesen — solange niemand etwas
    verantwortet hat, könnte man neu ableiten. Er besteht nicht: Entscheidend
    ist allein, dass ``metadata.draft`` vorliegt und READY ist. Der Fall
    trennt die beiden Lesarten, damit die Meldung nicht die eine für die
    andere nimmt.
    """
    wurzel, run = kette
    governance = wurzel / "_governance" / "metadata"
    governance.mkdir(parents=True, exist_ok=True)
    eingabe = governance / f"{RECORD}.toml"
    eingabe.write_text(_toml(VOLLSTAENDIG), encoding="utf-8")

    assert run("continue", RECORD).returncode == 3
    vorher = _entwuerfe(wurzel)
    eingabe.write_text(_toml(dict(VOLLSTAENDIG) | {"title": "Ein anderer Titel"}), encoding="utf-8")
    zweiter = run("continue", RECORD)

    assert _entwuerfe(wurzel) == vorher, "es entstand doch ein zweiter Entwurf"
    assert "Nichts auszuführen" in report_lines(zweiter.stdout)["STATUS"], zweiter.stdout


def test_the_input_file_must_exist_before_the_first_derive_under_production(tmp_path):
    """Die praktische Folge der beiden Fälle oben, an der Stelle, wo sie greift.

    Unter einem produktiven Profil hält der erste ``metadata.derive`` ohne
    Datei an. Das ist kein Ärgernis, sondern der Schutz: Liefe er durch und
    legte einen Entwurf mit sechs offenen Anforderungen ab, wäre dieser
    Entwurf endgültig — die Datei nachzureichen änderte daran nichts mehr.
    """
    ws, journal = _ws(tmp_path, production=True)
    with pytest.raises(RecordMetadataError):
        run_metadata_derive(_ctx(ws, journal), _view(ws, journal))
    _schreibe(ws)
    ergebnis = run_metadata_derive(_ctx(ws, journal), _view(ws, journal))
    assert _entwurf(ws, ergebnis.artifact_sha256)["open_requirements"] == []


# ============================================================ die Sichtbarkeit am Ausgang


@pytest.fixture
def kette_bis_freigabe(kette):
    """Die Kette weiter bis ``release.approved``, mit vollständiger Eingabedatei.

    Ab hier ist der Gegenstand nicht mehr ``metadata.derive``, sondern der
    Ausgang: Was passiert, wenn die Eingabedatei zwischen Entwurf und Export
    auseinandergeht. Der Weg dorthin ist der aus ``durchstich.sh``, nur
    zusätzlich mit der Datei.
    """
    wurzel, run = kette
    governance = wurzel / "_governance" / "metadata"
    governance.mkdir(parents=True, exist_ok=True)
    eingabe = governance / f"{RECORD}.toml"
    eingabe.write_text(_toml(VOLLSTAENDIG), encoding="utf-8")

    assert run("continue", RECORD).returncode == 3
    assert run("metadata", "confirm", RECORD, "--actor", "KLAUS", "--confirm").returncode == 0
    assert run("continue", RECORD).returncode == 3
    assert run("abstract", "confirm", RECORD, "--actor", "KLAUS", "--confirm").returncode == 0
    assert run("continue", RECORD).returncode == 3
    assert run("release", "approve", RECORD, "--actor", "KLAUS", "--confirm").returncode == 0

    freigabe_sha = [
        json.loads(z)["payload"]["sha256"]
        for z in journal_path(wurzel).read_text(encoding="utf-8").splitlines()
        if z.strip()
        and json.loads(z)["kind"] == "artifact.produced"
        and json.loads(z)["payload"].get("artifact") == "release.approved"
    ][-1]
    return wurzel, run, eingabe, freigabe_sha


def _welt(wurzel: Path, produktiv: bool):
    """Ein Arbeitsbereich für ``build_bundle``, im Muster von ``test_b3b_cli_chain``.

    ``production`` ist der einzige Unterschied zwischen den beiden Hälften
    jedes Falls unten. Dieselben Bytes, dieselbe Datei, ein Schalter.
    """
    from types import SimpleNamespace

    from ohpipe.store import ContentStore

    return SimpleNamespace(
        profile=SimpleNamespace(production=produktiv, id="probe"),
        store=lambda: ContentStore(wurzel),
        governance=wurzel / "_governance",
    )


def test_an_unchanged_input_file_lets_the_export_through(kette_bis_freigabe):
    """(a) Solange die Datei dieselbe ist, ändert sich nichts.

    Der Fall ist die Gegenprobe zu den drei folgenden: Ohne ihn prüfte diese
    Sperre nur, dass sie überhaupt feuert, und nicht, dass sie im Normalfall
    schweigt. Ein Wächter, der immer anschlägt, ist keiner.
    """
    from ohpipe.application.export import build_bundle

    wurzel, _run, _eingabe, freigabe_sha = kette_bis_freigabe
    daten, zusammenfassung = build_bundle(_welt(wurzel, True), RECORD, freigabe_sha)
    assert zusammenfassung["open_requirements"] == 0, zusammenfassung
    entwurf = json.loads(daten)["catalog"]["metadata"]
    assert entwurf["fields"]["consent_status"] == "research-only", entwurf


def test_a_changed_input_file_blocks_the_export_and_says_why(kette_bis_freigabe):
    """(b) Geänderte Datei, produktives Profil: Halt mit der Ursache im Satz.

    Das ist der Fall, für den diese Sperre da ist. O-2 bleibt offen — der
    Entwurf wird nicht neu abgeleitet, und das kann diese Zeile nicht ändern.
    Was sie ändert: Der Katalogeintrag geht nicht hinaus, ohne dass jemand
    gesehen hat, dass die Eingabe daneben eine andere geworden ist.

    Die Meldung nennt beide Digests. Wer sie liest, soll entscheiden können,
    welche Fassung stimmt, und dafür braucht er beide Seiten.
    """
    from ohpipe.application.export import ExportBlocked, build_bundle

    wurzel, _run, eingabe, freigabe_sha = kette_bis_freigabe
    eingabe.write_text(
        _toml(dict(VOLLSTAENDIG) | {"accessRights": "closed", "consent_status": "withdrawn"}),
        encoding="utf-8",
    )
    with pytest.raises(ExportBlocked) as gefallen:
        build_bundle(_welt(wurzel, True), RECORD, freigabe_sha)
    meldung = str(gefallen.value)
    assert "nach dem Entwurf" in meldung and "geaendert" in meldung, meldung
    assert "ALTEN Fassung" in meldung, meldung
    assert "O-2" in meldung, meldung
    assert str(eingabe) in meldung, meldung


def test_a_deleted_input_file_blocks_the_export_with_the_other_sentence(kette_bis_freigabe):
    """(c) Datei weg: derselbe Halt, ein anderer Satz.

    „Geändert" und „nicht mehr da" sind zwei verschiedene Lagen, und der
    Operator tut in beiden etwas anderes. Ein gemeinsamer Satz zwänge ihn,
    erst nachzusehen, welche der beiden vorliegt.
    """
    from ohpipe.application.export import ExportBlocked, build_bundle

    wurzel, _run, eingabe, freigabe_sha = kette_bis_freigabe
    eingabe.unlink()
    with pytest.raises(ExportBlocked) as gefallen:
        build_bundle(_welt(wurzel, True), RECORD, freigabe_sha)
    meldung = str(gefallen.value)
    assert "keine Datei mehr" in meldung, meldung
    assert "geaendert" not in meldung, "der Satz für den geänderten Fall"
    assert "O-2" in meldung, meldung


def test_in_a_sandbox_profile_nothing_changes(kette_bis_freigabe):
    """(d) Ohne Produktion schweigt die Sperre, auch wenn die Datei fort ist.

    Dieselbe Beschränkung wie beim ersten Satz: Die synthetische Übungswelt
    soll die ganze Kette zeigen dürfen, und das Vorführskript muss unverändert
    laufen. Geprüft wird der schärfste Fall — geändert UND gelöscht —, weil
    ein Fall mit unveränderter Datei nichts über die Beschränkung sagte.
    """
    from ohpipe.application.export import build_bundle

    wurzel, _run, eingabe, freigabe_sha = kette_bis_freigabe

    eingabe.write_text(_toml(dict(VOLLSTAENDIG) | {"title": "anders"}), encoding="utf-8")
    daten, _z = build_bundle(_welt(wurzel, False), RECORD, freigabe_sha)
    assert json.loads(daten)["record_id"] == RECORD

    eingabe.unlink()
    daten_ohne, _z2 = build_bundle(_welt(wurzel, False), RECORD, freigabe_sha)
    assert daten_ohne == daten, "das Bundle haengt an den Entwurfsbytes, nicht an der Datei"
