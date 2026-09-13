"""Das Profil des ersten echten Laufs, gefahren auf synthetischen Bytes.

`src/ohpipe/profiles/walz/profile.toml` ist das Profil des Bestandes Loretta
Walz: reale Daten, authentifizierte Evidenzkette, kein Vorgaengersystem. Der
Pfad endet bewusst vor `l1.suggest`.

Dieser Fall faehrt die Kette unter diesem Profil bis `transcript confirm` und
danach genau einen Schritt weiter, um zu zeigen, dass es keinen weiteren gibt.
Gefahren wird dabei die AUSGELIEFERTE SYNTHETISCHE Datei und kein reales
Material: ein Test, der echte Interviewbytes braucht, waere in einem Repository
nicht wiederholbar und in einer CI nicht zulaessig. Was hier gemessen wird, ist
das Profil und nicht der Bestand.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from ohpipe.domain.language_assignment import build_srt_draft
from ohpipe.project import ModelNotAllowed, Profile, ProfileError

from ._forge import cli_keyed, report_lines

AUSGELIEFERT = Path(__file__).resolve().parents[1] / "examples" / "synthetic" / "SANDBOX-001.srt"
PROFILDATEI = (
    Path(__file__).resolve().parents[1] / "src" / "ohpipe" / "profiles" / "walz" / "profile.toml"
)
RECORD = "WALZ-0001"
SPRACHEN = ("deu", "deu", "ltz", "fra", "deu")
ISO = b"deu\nfra\nltz\nund\nzxx\n"


@pytest.fixture
def welt(tmp_path: Path):
    """Ein Arbeitsbereich unter dem Profil ``walz``, mit Schluessel.

    Der Schluessel ist keine Testkosmetik: ``key_required = true`` steht im
    Profil, und ohne ihn haelt das Werkzeug vor dem ersten Schreibvorgang.
    """
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"
    ein = tmp_path / "ein"
    ein.mkdir()
    (ein / "iso.txt").write_bytes(ISO)

    def run(*args: str):
        return cli_keyed(*args, "--profile", "walz", root=wurzel, key=key)

    return wurzel, ein, run


def _mapping(ein: Path) -> Path:
    """Die Sprachzuordnung zur ausgelieferten Datei, eine Sprache je Segment.

    Die Segmentsummen kommen aus ``build_srt_draft`` und nicht aus einer
    zweiten, hier nachgebauten Rechnung: eine handgeschriebene Kopie der
    Segmentierung wuerde nicht das Profil pruefen, sondern die Kopie.
    """
    draft = build_srt_draft(AUSGELIEFERT.read_bytes())
    if len(SPRACHEN) != len(draft.segments):
        raise AssertionError(f"{len(draft.segments)} Segmente, aber {len(SPRACHEN)} Sprachen")
    zeilen = ["index\tsegment_sha256\tlanguage"]
    zeilen += [f"{n}\t{s.sha256}\t{SPRACHEN[n]}" for n, s in enumerate(draft.segments)]
    pfad = ein / "walz.tsv"
    pfad.write_bytes(("\n".join(zeilen) + "\n").encode("ascii"))
    return pfad


def test_the_walz_profile_reaches_transcript_confirm_and_stops_before_the_model(welt):
    """Acht Schritte mit ihren Exitcodes, und dann der Halt, der die Grenze ist.

    Der letzte Aufruf ist der eigentliche Gegenstand. ``continue --confirm``
    ist der Befehl, der in der synthetischen Welt den Modellschritt fuehrt;
    unter einem produktiven Profil gibt es fuer ihn keinen Adapter, und das ist
    kein Mangel, sondern die Aussage dieses Profils. Ein aufgezeichneter
    Adapter, der reale Transkripte "kodiert", waere eine Attrappe mit echtem
    Beleg.
    """
    wurzel, ein, run = welt
    zuordnung = _mapping(ein)

    assert run("init").returncode == 0
    assert run(
        "instance", "register", "KLAUS", "--source", "mensch",
        "--label", "Klaus Behnamshad", "--reference", "WALZ-01", "--confirm",
    ).returncode == 0
    assert run(
        "iso6393", "prepare", str(ein / "iso.txt"),
        "--release", "iso.2025", "--reference", "WALZ-01", "--confirm",
    ).returncode == 0
    # Die Quelle kommt in den Store und ist damit noch keine Fassung: 3.
    assert run("ingest", str(AUSGELIEFERT), "--record", RECORD).returncode == 3
    # Die Vorlage ist angelegt und muss ausgefuellt werden: 3.
    assert run(
        "transcript", "language", "template", str(AUSGELIEFERT),
        "--output", str(ein / "vorlage.tsv"),
    ).returncode == 3
    assert run(
        "transcript", "language", "prepare", RECORD, str(AUSGELIEFERT), str(zuordnung),
        "--actor", "KLAUS", "--reference", "WALZ-01", "--confirm",
    ).returncode == 0
    assert run(
        "transcript", "ingest", RECORD, str(AUSGELIEFERT), str(zuordnung), "--confirm"
    ).returncode == 0
    assert run("transcript", "confirm", RECORD, "--actor", "KLAUS", "--confirm").returncode == 0

    weiter = run("continue", RECORD, "--confirm")
    assert weiter.returncode == 1, weiter.stdout + weiter.stderr
    zeilen = report_lines(weiter.stdout)
    assert "l1.suggest ist gescheitert" in zeilen["STATUS"], zeilen
    assert "keinen Modelladapter" in zeilen["STATUS"], zeilen
    assert "'walz'" in zeilen["STATUS"], zeilen
    assert zeilen["CHANGED"] == "keine", zeilen


def test_the_profile_carries_a_closed_model_vocabulary_with_exact_tags():
    """EIN Tag, ausgeschrieben, und es ist der attestierte.

    Geprueft wird die Datei und nicht eine Konstante im Test: Die Liste ist die
    Entscheidung, welche Gewichte fuer diesen Bestand laufen duerfen, und sie
    steht im Profil, weil sie das Projekt betrifft und nicht den Aufruf.

    Die Zahl EINS ist der Gegenstand dieses Falls. Die Controller-Attestation
    zu diesem Bestand nennt genau ``mistral:7b-instruct``; jeder weitere
    Eintrag waere eine Freigabe ohne Entscheidung dahinter. Steht hier eines
    Tages ein zweiter Tag, faellt dieser Fall — und das ist beabsichtigt: die
    Attestation kommt dann zuerst.

    ``mistral`` ohne Tag waere kein Eintrag, sondern ein Zeiger auf das, was
    eine Registry gerade ``latest`` nennt — derselbe Wortlaut, morgen ein
    anderes Gewicht, und der Beleg truege trotzdem denselben Namen.
    """
    profil = Profile.load(PROFILDATEI)
    erwartet = ("mistral:7b-instruct",)
    assert profil.model_vocabulary == erwartet, profil.model_vocabulary
    assert profil.default_model == "mistral:7b-instruct"
    assert all(tag.count(":") == 1 for tag in profil.model_vocabulary), profil.model_vocabulary
    assert profil.check_model("mistral:7b-instruct") == "mistral:7b-instruct"

    # Und die beiden Tags, die frueher hier standen, halten jetzt an: sie kamen
    # aus der Adaptermessung an der Installation, nicht aus einer Entscheidung
    # ueber diesen Bestand.
    for gemessen_aber_nicht_entschieden in ("gemma3:4b", "qwen3:8b"):
        with pytest.raises(ModelNotAllowed):
            profil.check_model(gemessen_aber_nicht_entschieden)


def test_a_model_outside_the_closed_list_is_a_halt_and_not_a_warning(welt, tmp_path):
    """Der Registerakt einer Maschineninstanz haelt an, wenn das Modell fremd ist.

    Das ist die Stelle, an der ein Modelltag in dieser Strecke ins System
    kommt: ``instance register --source maschine`` schreibt ihn dauerhaft ins
    Register. Ein Vermerk „ausserhalb der Liste, trotzdem gefahren" waere genau
    der Beleg, den spaeter niemand mehr aufloest — deshalb STOP und keine
    Warnung, und deshalb steht danach nichts im Journal.
    """
    wurzel, _ein, run = welt
    assert run("init").returncode == 0
    vorher = (wurzel / "_governance" / "journal.jsonl").read_bytes()

    fremd = run(
        "instance", "register", "MASCHINE",
        "--source", "maschine",
        "--label", "Modellkodierer",
        "--reference", "WALZ-01",
        "--model", "llama3:8b",
        "--parametersatz", "temperatur-0.0",
        "--confirm",
    )
    assert fremd.returncode == 1, fremd.stdout + fremd.stderr
    zeilen = report_lines(fremd.stdout)
    assert "llama3:8b" in zeilen["STATUS"], zeilen
    assert "mistral:7b-instruct" in zeilen["STATUS"], zeilen
    assert zeilen["CHANGED"] == "keine", zeilen
    assert (wurzel / "_governance" / "journal.jsonl").read_bytes() == vorher

    # Und die Vorgabe der Liste laeuft — sonst pruefte der Fall oben nur, dass
    # `instance register --source maschine` ueberhaupt nicht geht.
    vorgabe = run(
        "instance", "register", "MASCHINE",
        "--source", "maschine",
        "--label", "Modellkodierer",
        "--reference", "WALZ-01",
        "--model", "mistral:7b-instruct",
        "--parametersatz", "temperatur-0.0",
        "--confirm",
    )
    assert vorgabe.returncode == 0, vorgabe.stdout + vorgabe.stderr


def test_a_bare_family_name_without_a_tag_is_rejected_when_the_profile_loads(tmp_path):
    """Die Pruefung sitzt im Laden des Profils, nicht erst im Aufruf.

    Ein Profil mit ``mistral`` statt ``mistral:7b-instruct`` ist nicht ein
    Profil mit einem ungenauen Eintrag, sondern eines, dessen Liste keine
    Aussage mehr traegt. Deshalb faellt es beim Laden und nicht dann, wenn
    zufaellig jemand dieses Modell benennt.
    """
    datei = tmp_path / "profile.toml"
    datei.write_text(
        PROFILDATEI.read_text(encoding="utf-8").replace(
            '"mistral:7b-instruct"', '"mistral"'
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProfileError, match="exakter Tag"):
        Profile.load(datei)

    # Und eine Dublette faellt ebenfalls: sie waere keine groessere Menge,
    # sondern eine zweite Vorgabe an anderer Stelle.
    doppelt = tmp_path / "doppelt.toml"
    doppelt.write_text(
        PROFILDATEI.read_text(encoding="utf-8").replace(
            'model_vocabulary = ["mistral:7b-instruct"]',
            'model_vocabulary = ["mistral:7b-instruct", "mistral:7b-instruct"]',
        ),
        encoding="utf-8",
    )
    with pytest.raises(ProfileError, match="doppelt"):
        Profile.load(doppelt)


def test_an_empty_model_vocabulary_is_a_halt_and_not_a_pass_through():
    """(a) Kein Vokabular heisst kein Modell — und zwar fuer jeden Tag.

    Gemessen am ausgelieferten ``childlux``: Dieses Profil traegt die leere
    Liste, weil ueber kein Gewicht entschieden ist. Die Gegenlesart — keine
    Liste, keine Pruefung — machte die Freigabe genau dort wirkungslos, wo
    noch niemand sie gefuellt hat, und das ist die einzige Stelle, an der sie
    gebraucht wird.

    Geprueft wird auch der WORTLAUT: Er ist die einzige Auskunft, die der
    Operator an dieser Stelle bekommt, und er muss sagen, dass nichts
    freigegeben ist — nicht, dass etwas nicht gefunden wurde.
    """
    childlux = (
        Path(__file__).resolve().parents[1]
        / "src" / "ohpipe" / "profiles" / "childlux" / "profile.toml"
    )
    profil = Profile.load(childlux)
    assert profil.model_vocabulary == (), profil.model_vocabulary
    assert profil.default_model == ""

    with pytest.raises(ModelNotAllowed) as fehler:
        profil.check_model("mistral:7b-instruct")
    assert str(fehler.value) == (
        "Profil 'childlux' führt kein Modellvokabular; kein Modell ist "
        "freigegeben. Kein Lauf."
    ), str(fehler.value)

    # Und es ist kein Sonderfall EINES Tags: auch die Vorgabe eines anderen
    # Profils faellt, sonst pruefte der Fall oben nur einen Namen.
    with pytest.raises(ModelNotAllowed):
        profil.check_model("fixture:descriptive-l1")


def test_a_production_profile_without_the_model_key_is_invalid(tmp_path):
    """(b) Ein Produktionsprofil muss den Schluessel fuehren, auch leer.

    Verlangt ist das VORHANDENSEIN, nicht ein Inhalt: die leere Liste ist eine
    Angabe (``childlux``), ein fehlender Schluessel ist keine. Dieselbe Regel
    wie bei ``key_required`` und ``pseudonymisation_required`` (ADR 0017,
    ADR 0024), und sie faellt beim Laden — nicht dann, wenn zufaellig jemand
    ein Modell benennt.
    """
    ohne = tmp_path / "profile.toml"
    zeilen = [
        z
        for z in PROFILDATEI.read_text(encoding="utf-8").splitlines()
        if not z.startswith("model_vocabulary")
    ]
    ohne.write_text("\n".join(zeilen) + "\n", encoding="utf-8")

    with pytest.raises(ProfileError) as fehler:
        Profile.load(ohne)
    assert "model_vocabulary" in str(fehler.value), str(fehler.value)

    # Gegenprobe: mit leerer Liste laedt dasselbe Profil, und es ist dann ein
    # Profil ohne freigegebenes Modell — nicht eines ohne Aussage.
    mit_leerer = tmp_path / "leer.toml"
    mit_leerer.write_text(
        "\n".join(zeilen) + "\nmodel_vocabulary = []\n", encoding="utf-8"
    )
    geladen = Profile.load(mit_leerer)
    assert geladen.model_vocabulary == ()
    with pytest.raises(ModelNotAllowed):
        geladen.check_model("mistral:7b-instruct")


def test_the_check_command_names_the_profile_from_the_arguments(monkeypatch):
    """(c) R-4 — der CHECK bei ``ProfileError`` nennt ``walz`` und nicht ``sandbox``.

    Der CHECK ist ein Kommando zum Kopieren. Nannte es wörtlich ``sandbox``,
    schickte es den Operator in eine andere Welt als die, in der er steht: Nach
    der Berichtigung eines produktiven Profils ist die Wiederholung UNTER
    DIESEM PROFIL der Nachweis, und ein Lauf unter ``sandbox`` sagt darueber
    nichts.

    Gefahren wird ``cmd_doctor`` unmittelbar, mit einem gestellten
    ``ProfileError`` aus der Profilaufloesung: Gegenstand ist die eine Zeile,
    die den CHECK baut, und nicht der Weg dorthin.
    """
    from ohpipe.cli import main as cli_main

    def haelt_an(name: str):
        raise ProfileError(f"Profil {name!r} ist zu Pruefzwecken ungueltig.")

    monkeypatch.setattr(cli_main, "_profile_path", haelt_an)

    unter_walz = cli_main.cmd_doctor(
        argparse.Namespace(profile="walz", root=None, json=False)
    )
    assert unter_walz.reason_code == "CONFIG_PROFILE", unter_walz
    assert unter_walz.check == "ohpipe --profile walz doctor", unter_walz.check

    # Und der Fallback greift dort, wo kein brauchbares Profilargument vorliegt.
    # Gemessen am einzigen Weg, auf dem die CLI das erzeugen kann: `--profile ""`
    # kommt bis hierher (der Parser hat einen Default, aber keine Leerprüfung).
    # Ohne den Fallback nennte der CHECK `--profile ''` und schickte den
    # Operator in denselben Fehler zurueck.
    leer = cli_main.cmd_doctor(argparse.Namespace(profile="", root=None, json=False))
    assert leer.check == "ohpipe --profile sandbox doctor", leer.check


def test_a_sandbox_workspace_is_not_silently_taken_over_by_walz(tmp_path):
    """Gleicher Fingerprint, anderes Profil — die Bindung sagt trotzdem nein.

    ``walz`` und ``sandbox`` haben denselben Graphvertrag (16 Artefakte, gleiche
    Vertragsachsen); ihr ``graph_contract_fingerprint`` ist byteweise derselbe.
    Getrennt werden sie durch den Profilnamen IN der Bindungsdatei, den
    ``Workspace.inspect_graph_binding`` mitvergleicht.

    Ohne diesen Vergleich liefe ein synthetischer Arbeitsbereich unter dem
    Profil des realen Bestandes weiter, ohne dass irgendetwas auffiele — mit
    ``production = true`` und ``key_required = true``, aber auf Sandboxbytes.
    """
    key = tmp_path / "journal.key"
    key.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "daten"

    assert cli_keyed("init", "--profile", "sandbox", root=wurzel, key=key).returncode == 0

    fremd = cli_keyed("status", "--profile", "walz", root=wurzel, key=key)
    assert fremd.returncode == 3, fremd.stdout + fremd.stderr
    zeilen = report_lines(fremd.stdout)
    assert "Graphvertrag" in zeilen["STATUS"], zeilen
    assert zeilen["CHANGED"] == "keine", zeilen
