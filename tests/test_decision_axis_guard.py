"""Regressionen zur Entscheidungsachse und zu Journal-Evidenz.

Die früheren Rotmarker D1/D2 sind seit der Replay-Korrektur vom 13.09.2026
reguläre Regressionstests. Die historische Begründung folgt zur Einordnung.

**Diese Datei hat zwei Sorten Test, und die Sorte steht bei jedem einzeln
dran.** Das ist der Punkt, an dem Serie 3d beinahe denselben Fehler wie T3
gemacht hätte, nur mit vertauschtem Vorzeichen.

    DAUERWÄCHTER   heute grün, muss grün bleiben. Er beschreibt eine
                   Eigenschaft, die 4a nicht verlieren darf. Seine Zähne sind
                   NICHT an seiner Farbe abzulesen — sie sind in
                   ``tools/mutanten.py`` gemessen (V1, V2).

    ROTMARKER      ``xfail(strict)``, heute rot an der Zielassertion. Er
                   beschreibt einen Defekt, der HEUTE besteht.

**Warum der B1-Kern kein Rotmarker ist.** Der Einwilligungs-Bypass entsteht
erst, wenn ein ``ArtifactContract`` existiert, der die Entscheidungsachse für
nicht zuständig erklären kann. Der existiert nicht. Ein ``xfail(strict)``
darauf wäre heute grün — also ``XPASS(strict)`` und damit rot aus dem Grund
„es gibt noch nichts zu prüfen". Ein Wartemarker auf etwas Unerreichbares, wie
T3 in Serie 3b.

**Und warum grün allein hier nichts beweist.** Der Wächter unten ist heute aus
einem billigen Grund grün: Es gibt keinen Vertrag, den er schlagen müsste. Ein
Wächter, dessen Wirksamkeit man nicht messen kann, ist eine Behauptung.
Deshalb sind V1 und V2 in ``tools/mutanten.py`` Teil derselben Lieferung — sie
stellen die zwei Stellen nach, an denen 4a die Eigenschaft brechen kann, und
der Mutationslauf misst, dass genau dieser Wächter fällt.

**Eine Korrektur an der Reviewvorgabe, gemessen statt hergeleitet.** Review 2
nannte als Zielassertion ``status is READY`` trotz ``WITHDRAW``. Auf
``transcript.revision`` — dem Artefakt aus dem Bewertungsdokument — ist das
nicht erreichbar: gemessen steht es mit einem authentifizierten ``WITHDRAW``
auf ``STOP``, weil die Bindungsachse ``unknown`` ist und ``UNKNOWN → STOP``
oberhalb von ``WITHDRAWN → EXCLUDED`` in der Leiter steht. Ein Wächter, der
dort den Status zusichert, hinge an zwei Achsen und würde nach einer reinen
Entscheidungskorrektur rot bleiben — genau der T3-Fehler.

Deshalb steht der Wächter auf ``transcript.confirmed``. Dort sind die anderen
zwei Achsen in allen drei Verdikten gleich (``bound`` / ``not_applicable``),
und der Status ist die unmittelbare Folge der EINEN Achse. Gemessen:

    ACCEPT   -> bound / not_applicable / accepted   -> READY
    WITHDRAW -> bound / not_applicable / withdrawn  -> EXCLUDED  („zurückgezogen")
    REJECT   -> bound / not_applicable / rejected   -> EXCLUDED  („verworfen")

Das ist zugleich die Szene aus dem Bewertungsdokument in erreichbarer Form:
ein Artefakt, das ohne den Widerruf grün wäre.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ohpipe.application.replay import replay
from ohpipe.journal import Journal

from ._forge import cli, cli_keyed, forge, forge_keyed, place_object

#: Das Ingressartefakt — ohne Anker, ohne Beleg. Trägt hier die zwei Rotmarker.
INGRESS = "transcript.revision"

#: Ein menschlich bestätigtes Artefakt. Es trägt den B1-Wächter, weil bei ihm
#: die anderen zwei Achsen verdiktunabhängig feststehen (siehe Modulkopf).
BESTAETIGT = "transcript.confirmed"

REFERENZ = "PROT-2026-08-08"


def _welt(tmp_path: Path) -> Path:
    wurzel = tmp_path / "daten"
    assert cli("init", root=wurzel).returncode == 0
    return wurzel


def _record(ergebnis) -> dict:
    """Der Record, wie ``status --json`` ihn ausgibt — OHNE Befundwächter.

    Die Schwester ``_artefakt`` in ``test_contract_axes_red.py`` besteht auf
    ``findings == []``. Hier darf sie das nicht: Zwei der Marker unten sind
    genau dann eingelöst, wenn ein Befund entsteht. Ein geerbter Wächter, der
    die Zielbedingung vorher abfängt, macht aus einem eingelösten Marker einen
    ``xfail``, der aus dem falschen Grund rot bleibt.
    """
    return json.loads(ergebnis.stdout)["details"]["records"][0]


def _entscheidung(artefakt: str, sha: str, verdikt: str) -> dict:
    return {
        "kind": "decision.recorded",
        "payload": {
            "artifact": artefakt,
            "subject_sha256": sha,
            "verdict": verdikt,
            **({"input_refs": {"transcript": sha}} if artefakt == BESTAETIGT else {}),
            "reference": REFERENZ,
            "actor": "kbs",
            "at": "2026-09-01T10:00:00+00:00",
        },
    }


@pytest.fixture
def authentifiziert(tmp_path: Path):
    """Eine authentifizierte Welt — Schlüssel AUSSERHALB der Datenwurzel.

    Die Autorität muss echt sein, nicht behauptet: Ein ``WITHDRAW`` aus einer
    unauthentifizierten Kette wäre ohnehin ``provisional`` (ADR 0017) und
    verschwände aus einem Grund, der mit dem Vertrag nichts zu tun hat. Der
    Wächter würde dann grün bleiben, während die Sache kaputt ist.
    """
    schluessel = tmp_path / "journal.key"
    schluessel.write_bytes(b"ein-schluessel-der-nicht-im-datenbaum-liegt")
    wurzel = tmp_path / "keyed-data"

    def lauf(*args: str):
        return cli_keyed(*args, root=wurzel, key=schluessel)

    assert lauf("init").returncode == 0
    return wurzel, schluessel, lauf


def _bestaetigtes_artefakt(authentifiziert, verdikt: str) -> dict:
    """Die Fixture, an der die drei Wächter unten hängen.

    **Das ``anchor.checked`` ist seit C2 fachlich erforderlich, nicht
    kosmetisch.** Vorher war ``transcript.confirmed`` gebunden, weil es ein
    menschliches Artefakt ist — die Fahne ``is_human_artifact`` ersetzte die
    Ankerprüfung. C2 nimmt diesen Sonderweg weg: Bei ``binding_required=true``
    bindet nur echte Ankerevidenz. Ohne dieses Ereignis stünde das Artefakt auf
    ``unknown`` und damit auf ``STOP``, und alle drei Wächter würden aus der
    falschen Achse rot: Der Docstring der Datei sagt ausdrücklich, dass genau
    hier die anderen zwei Achsen über alle drei Verdikte gleich sein müssen.
    """
    wurzel, schluessel, lauf = authentifiziert
    sha = place_object(wurzel, b"eine bestaetigte Fassung")
    forge_keyed(
        wurzel,
        schluessel,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": "transcript.revision", "sha256": sha},
            },
            {"kind": "artifact.produced", "payload": {"artifact": BESTAETIGT, "sha256": sha}},
            {"kind": "anchor.checked", "payload": {"artifact": BESTAETIGT, "outcome": "exact"}},
            _entscheidung(BESTAETIGT, sha, verdikt),
        ],
    )
    rec = _record(lauf("status", "--json"))
    assert rec["findings"] == [], rec["findings"]
    assert rec["provisional"] == [], rec["provisional"]
    assert rec["authority"] == "authenticated", rec["authority"]
    return rec["artifacts"][BESTAETIGT]


# ================================================ B1 · die Entscheidungsachse
#
# DAUERWÄCHTER — heute grün, müssen grün bleiben. Zähne gemessen über V1/V2.


def test_a_human_artifact_with_an_acceptance_is_ready(authentifiziert):
    """Gegenprobe: ohne das Verdikt ist dieses Artefakt grün.

    Ohne sie wäre der Wächter darunter auch dann grün, wenn jemand
    ``transcript.confirmed`` pauschal auf ``EXCLUDED`` setzte — dann überlebte
    der Widerruf zwar, aber die Annahme auch nicht, und der Wächter merkte
    nichts. Diese Zeile ist der Grund, warum „Widerruf überlebt" überhaupt
    etwas heißt: Der Unterschied zwischen den beiden Läufen ist genau das
    Verdikt und sonst nichts.
    """
    artefakt = _bestaetigtes_artefakt(authentifiziert, "ACCEPT")
    assert artefakt["status"] == "READY", artefakt
    assert artefakt["decision_state"] == "accepted", artefakt


@pytest.mark.parametrize(
    ("verdikt", "achse", "wortlaut"),
    [("WITHDRAW", "withdrawn", "zurückgezogen"), ("REJECT", "rejected", "verworfen")],
)
def test_an_authenticated_verdict_is_not_overridden(authentifiziert, verdikt, achse, wortlaut):
    """Ein Verdikt über die Einwilligung wird von keinem Vertrag aufgehoben.

    **Die Regel, die 4a nicht verlieren darf:** ``NOT_APPLICABLE`` ist der
    Wert bei FEHLENDER Evidenz, nie ein Übersteuern vorhandener. Die naive
    Lesart des Plans — ``decision_required = false`` ⇒ Achse nicht zuständig —
    lässt einen authentifizierten, formal gültigen Widerruf verschwinden. Das
    ist dieselbe Asymmetrie wie T1 aus Serie 3b, eine Ebene höher: Ein
    Verdikt, das über die Einwilligung verfügt, darf nicht aufgehoben werden —
    nicht durch neue Bytes (T1), und nicht durch einen Vertrag, der sagt, hier
    werde nichts entschieden.

    **Warum drei Zusicherungen und trotzdem eine Achse.** Sie lesen dieselbe
    Achse an drei Punkten desselben Laufs: den Wert, seine Folge in der Leiter
    und den Satz, den ein Operator davon zu sehen bekommt. Zwei Mutanten decken
    die zwei Stellen, an denen 4a die Eigenschaft brechen kann: V1 bricht die
    Ableitung in ``replay.py`` (dann fällt schon die erste Zeile), V2 die
    Leiterstufe in ``state.py`` (dann fällt die zweite). Ein Wächter, den nur
    eine der beiden Stellen fällen könnte, ließe die andere ungedeckt.

    **Was hier NICHT noch einmal behauptet wird.** Die Leiterstufe selbst —
    ``REJECTED``/``WITHDRAWN`` ⇒ ``EXCLUDED`` — gehört
    ``test_rejected_and_withdrawn_are_excluded_not_stop`` in
    ``test_state_and_exit.py``; sie wird dort als Einheit auf ``ArtifactState``
    zugesichert. Dieser Test sagt etwas anderes: dass ein authentifiziertes
    Verdikt den ganzen Weg vom Journal über ``replay`` bis in die
    Operatorausgabe überlebt. Zwei Formulierungen derselben Regel wären ein
    Defekt; zwei Ebenen desselben Wegs sind es nicht.

    **Warum die Erklärung mitgeprüft wird.** Das Bewertungsdokument nennt als
    eigentlichen Schaden nicht den Status, sondern den Satz daneben: Unter der
    naiven Lesart behauptet die Erklärung „aktuell gebunden, Eingaben
    unverändert, von einem Menschen verantwortet" — drei Halbsätze, von denen
    keiner stimmt. Ein Operator liest den Satz, nicht das Enum.

    **Verworfene erste Fassung:** dasselbe auf ``transcript.revision``, mit
    ``status == "EXCLUDED"`` als Zielzeile. Gemessen steht das Artefakt dort
    auf ``STOP`` — die Bindungsachse ist ``unknown`` und greift früher. Der
    Wächter hätte an einer Achse gehangen, die er gar nicht meint, und wäre
    nach der Entscheidungskorrektur rot geblieben.
    """
    artefakt = _bestaetigtes_artefakt(authentifiziert, verdikt)

    assert artefakt["decision_state"] == achse, (
        f"Ein authentifiziertes {verdikt} auf {BESTAETIGT!r} meldet "
        f"{artefakt['decision_state']!r} statt {achse!r}. Vorhandene Evidenz "
        "auf der Entscheidungsachse wird übersteuert."
    )
    assert artefakt["status"] == "EXCLUDED", (
        f"Ein authentifiziertes {verdikt} auf {BESTAETIGT!r} führt zu Status "
        f"{artefakt['status']!r}. Ein Verdikt über die Einwilligung muss das "
        "Artefakt aus dem Betrieb nehmen."
    )
    assert artefakt["explanation"] == wortlaut, artefakt["explanation"]


# ====================== D1 · artifact.produced ohne Autoritätsprüfung
#
# ROTMARKER — heute rot. Der Zweig `src/ohpipe/application/replay.py::ARTIFACT_PRODUCED`
# gegen die Autoritätsprüfung im Zweig `src/ohpipe/application/replay.py::DECISION_RECORDED`.


def test_a_disposition_from_an_authenticated_chain_still_excludes(authentifiziert):
    """Gegenprobe zum Marker darunter: mit Schlüssel bleibt ``disposition`` wirksam.

    Ohne sie wäre der Marker auch dann eingelöst, wenn jemand das Feld
    ``disposition`` schlicht nicht mehr auswertete. Dann verschwände mit dem
    ungesicherten Weg auch der gesicherte — und ein Altlauf unter der
    heutigen Schwelle (``LegacyDisposition``) ließe sich gar nicht mehr aus
    dem Betrieb nehmen.
    """
    wurzel, schluessel, lauf = authentifiziert
    sha = place_object(wurzel, b"eine Transkriptfassung")
    forge_keyed(
        wurzel,
        schluessel,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": INGRESS, "sha256": sha, "disposition": "excluded"},
            }
        ],
    )
    rec = _record(lauf("status", "--json"))
    assert rec["artifacts"][INGRESS]["disposition"] == "excluded", rec["artifacts"][INGRESS]
    assert rec["status"] == "EXCLUDED", rec["status"]


def test_an_unauthenticated_chain_cannot_exclude_through_a_disposition(tmp_path: Path):
    """Wer den Schlüssel nicht hat, nimmt kein Interview aus dem Betrieb.

    ``Authority.may_confer_exclusion`` begründet sich selbst so: *„Ein
    negativer Akt ist genauso folgenreich wie ein positiver: Ein
    ausgeblendeter QDA-Fall verschwindet aus jeder Auswertung."* Genau dagegen
    ist ``record.disabled`` gegated (Zweig
    ``src/ohpipe/application/replay.py::RECORD_DISABLED``), und genau dagegen
    ist auch das negative Verdikt gegated (Zweig
    ``src/ohpipe/application/replay.py::DECISION_RECORDED``).

    Gemessen, heute, dieselbe unauthentifizierte Kette, zwei Wege:

        record.disabled  · WITHDRAW      -> provisional, ohne Wirkung, STOP
        artifact.produced · disposition  -> disposition=excluded, Status
                                            EXCLUDED, cross_record_claims
                                            _allowed=false

    Der zweite Weg braucht keine Entscheidung, keinen Akteur, keine Referenz —
    ein optionales Feld auf einem Ereignis, das gar nicht als Akt gedacht ist.
    Ein unbekannter Wert fällt dort ausserdem fail-closed ebenfalls auf
    ``EXCLUDED`` (``:507``), das heißt: ein Tippfehler genügt.

    **Warum die Zielzeile die Achse liest und nicht den Status.** Zwei
    Reparaturen sind plausibel — ``disposition`` ohne Autorität wird
    ``provisional`` wie bei ``:527``, oder sie wird ein Befund wie bei einem
    unbekannten Ankerergebnis. Beide führen zu ``STOP``, aber nur die zweite
    zu einem Eintrag in ``findings``. Eine Zielzeile auf ``findings`` wäre
    unter der ersten Reparatur rot geblieben; eine auf ``status`` wäre auch
    von einem STOP aus ganz anderem Grund erfüllt. Die Achse selbst ist die
    Eigenschaft, alles andere ist ihr Stellvertreter.

    **Was dieser Marker ausdrücklich NICHT verlangt:** dass
    ``artifact.produced`` als Ganzes ohne Schlüssel unwirksam wird. Das
    Journal darf ohne Autorität ein Arbeitsprotokoll sein (ADR 0017); es darf
    nur nichts ausschließen.
    """
    wurzel = _welt(tmp_path)
    sha = place_object(wurzel, b"eine Transkriptfassung")
    forge(
        wurzel,
        [
            {
                "kind": "artifact.produced",
                "payload": {"artifact": INGRESS, "sha256": sha, "disposition": "excluded"},
            }
        ],
    )
    rec = _record(cli("status", "--json", root=wurzel))

    # Wächter, heute wahr: die Prämisse des Markers ist die fehlende Autorität.
    assert rec["authority"] == "unauthenticated", rec["authority"]

    view = next(iter(replay(Journal(wurzel / "_governance" / "journal.jsonl")).values()))
    assert view.facts[INGRESS].sha256 == sha
    assert rec["provisional"], "Unwirksame Verfügung muss sichtbar bleiben"
    assert rec["status"] != "EXCLUDED"
    verfuegung = rec["artifacts"].get(INGRESS, {}).get("disposition", "ok")
    assert verfuegung != "excluded", (
        f"Eine nicht authentifizierte Kette setzt {INGRESS!r} auf disposition="
        f"{verfuegung!r} und damit auf EXCLUDED — über artifact.produced, "
        "während derselbe Ausschluss über record.disabled provisorisch bleibt."
    )


# =============================== D2 · anchor.checked ohne erzeugte Bytes
#
# ROTMARKER — heute rot. Der Zweig `src/ohpipe/application/replay.py::ANCHOR_CHECKED`
# gegen den fail-closed-Default im Bindungsblock von
# `src/ohpipe/application/replay.py::ArtifactFacts.state`.


def test_an_anchor_check_after_the_bytes_still_binds(tmp_path: Path):
    """Gegenprobe zum Marker darunter: in der richtigen Reihenfolge bindet er.

    Ohne sie wäre der Marker auch dann eingelöst, wenn jemand
    ``anchor.checked`` pauschal ablehnte — und damit die Bindungsachse
    stillstellte, an der Demo-Moment 2 hängt.
    """
    wurzel = _welt(tmp_path)
    sha = place_object(wurzel, b"eine Transkriptfassung")
    forge(
        wurzel,
        [
            {"kind": "artifact.produced", "payload": {"artifact": INGRESS, "sha256": sha}},
            {"kind": "anchor.checked", "payload": {"artifact": INGRESS, "outcome": "exact"}},
        ],
    )
    rec = _record(cli("status", "--json", root=wurzel))
    assert rec["findings"] == [], rec["findings"]
    assert rec["artifacts"][INGRESS]["source_binding"] == "bound", rec["artifacts"][INGRESS]


def test_an_anchor_check_without_produced_bytes_does_not_bind(tmp_path: Path):
    """Ein Ankerergebnis über Bytes, die es nicht gibt, bindet nichts.

    Gemessen, heute — ein Journal mit genau EINEM Ereignis:

        anchor.checked · transcript.revision · exact
          -> source_binding = bound     <- über Bytes, die nie erzeugt wurden
             derivation     = unverifiable
             findings       = []

    Die Bindungsachse ist die, die zuerst greift und die die Erklärung
    schreibt. Sie steht hier auf ``bound``, obwohl ``sha256`` ``None`` ist —
    also grün aus einem Ereignis, das sich auf nichts bezieht. Dass der Status
    heute trotzdem ``STOP`` ist, verdankt sich allein der Ableitungsachse; nach
    4a trägt gerade das Ingressartefakt dort ``not_applicable``, und dann hält
    diese Achse nichts mehr.

    Dieselbe Klasse wie B1, eine Achse weiter: ein Zustand, der nicht aus
    Evidenz über DIESES Artefakt abgeleitet ist.

    **Warum die Zielzeile eine Verneinung ist.** ``replay`` kennt für ein
    Ereignis, das sich auf etwas beruft, das im Journal (bis hierher) nicht
    vorkommt, bereits eine Antwort: einen Befund (``_bind_model_receipt``).
    Ebenso plausibel ist, den fail-closed-Default stehen zu lassen, also
    ``unknown``. Die erste Reparatur nimmt das Artefakt aus der Zustandstabelle
    heraus, die zweite lässt es darin. Eine Zielzeile auf einem der beiden
    Ergebnisse wäre unter der anderen Reparatur rot geblieben — der T3-Fehler.
    Verneint man stattdessen den Defekt selbst („kein Befund UND trotzdem
    gebunden"), sind beide Reparaturen grün und keine dritte, die nichts tut.

    **Nicht Teil dieses Markers, aber gemessen und offen:** derselbe Aufbau mit
    ``artifact: 'erfunden.artefakt'`` — einem Namen, den kein Schritt des
    Graphen erzeugt — legt diesen Namen klaglos in der Zustandstabelle an. Das
    ist ein zweiter, eigener Befund (Graphzugehörigkeit statt Ereignisfolge)
    und gehört in einen eigenen Marker, nicht als zweite Wahrheit in diesen.
    """
    wurzel = _welt(tmp_path)
    forge(
        wurzel,
        [{"kind": "anchor.checked", "payload": {"artifact": INGRESS, "outcome": "exact"}}],
    )
    rec = _record(cli("status", "--json", root=wurzel))

    befunde = rec["findings"]
    achse = rec["artifacts"].get(INGRESS, {}).get("source_binding")
    assert not (befunde == [] and achse == "bound"), (
        f"{INGRESS!r} meldet source_binding='bound' ohne ein einziges "
        "artifact.produced und ohne Befund. Die Bindungsachse ist grün über "
        "Bytes, die das Journal nicht kennt."
    )
