"""B1 · Der vierteilige `ArtifactKey` — und die Grenze, an der er nicht schreibt.

Diese Datei ist zuerst ROT geschrieben und danach durch die kleinste
vollständige Implementierung grün gemacht (ROADMAP § 13, Arbeitsregel je
Scheibe, Schritte 2 und 3).

**Die Invariante, in einem Satz.** Ein `ArtifactKey` trägt immer alle vier
Felder; der eininstanzige Fall führt `instance_id` ausdrücklich als `None`;
ein abwesendes Feld, die leere Zeichenkette und jeder nichtleere
`instance_id` werden beim Bau zurückgewiesen, der nichtleere ausschliesslich
deshalb, weil am Sockel kein normativer Formatmassstab hinterlegt ist.

**Warum der nichtleere Fall zurückgewiesen wird und nicht geprüft.**
`docs/adr/0027-artefaktidentitaet-und-evidenzbindung.md § Entscheidung · A ·
Identität` macht ein kontrolliertes Format zur einzigen zulässigen Form und
delegiert die Formatdetails an ADR 0028B; ADR 0028B liegt am Sockel nicht vor.
Eine positive Formatprüfung ist ohne Maßstab nicht konstruierbar. Die
Zurückweisung sagt deshalb, dass kein Maßstab hinterlegt ist — sie behauptet
nicht, gegen ein vorhandenes Format geprüft zu haben.

Jeder Test steht als **Fälschungstest mit Gegenprobe** (ADR 0015): zu jeder
Zurückweisung gehört der Nachweis, dass der zulässige Fall in derselben
Messung durchgeht. Ein Test, der nur die eigene Richtung prüft, findet den
eigenen Rückschritt nicht.
"""

from __future__ import annotations

import dataclasses

import pytest

from ohpipe.domain.artifact_key import (
    NO_FORMAT_STANDARD_REASON,
    ArtifactKey,
    InvalidArtifactKey,
    Scope,
)


#: Ein zulässiger eininstanziger Schlüssel. Er ist die Gegenprobe zu jeder
#: Zurückweisung unten: geht er in derselben Messung nicht durch, misst der
#: Test nicht die Zurückweisung, sondern einen kaputten Konstruktor.
def _singleton() -> ArtifactKey:
    return ArtifactKey(
        scope=Scope.RECORD,
        scope_id="SANDBOX-001",
        kind="transcript.revision",
        instance_id=None,
    )


class TestDerVolleSchluessel:
    def test_singleton_traegt_instance_id_ausdruecklich_als_none(self) -> None:
        key = _singleton()
        assert key.scope is Scope.RECORD
        assert key.scope_id == "SANDBOX-001"
        assert key.kind == "transcript.revision"
        assert key.instance_id is None

    def test_der_schluessel_ist_vierteilig_und_unveraenderlich(self) -> None:
        key = _singleton()
        assert ArtifactKey.FIELDS == ("scope", "scope_id", "kind", "instance_id")
        with pytest.raises(dataclasses.FrozenInstanceError):
            key.kind = "etwas anderes"  # type: ignore[misc]

    def test_gleicher_inhalt_ist_gleicher_schluessel(self) -> None:
        assert _singleton() == _singleton()
        assert hash(_singleton()) == hash(_singleton())


class TestScopeIstGeschlossen:
    def test_die_beiden_zulaessigen_werte_gehen_durch(self) -> None:
        assert Scope("workspace") is Scope.WORKSPACE
        assert Scope("record") is Scope.RECORD

    def test_ein_dritter_wert_ist_ein_fehler_kein_unbekannt(self) -> None:
        with pytest.raises(InvalidArtifactKey) as exc:
            ArtifactKey.from_mapping(
                {
                    "scope": "unit",
                    "scope_id": "SANDBOX-001",
                    "kind": "coding.decision",
                    "instance_id": None,
                }
            )
        assert "unit" in str(exc.value)
        assert "workspace" in str(exc.value) and "record" in str(exc.value)

    def test_gegenprobe_derselbe_weg_mit_record_geht_durch(self) -> None:
        key = ArtifactKey.from_mapping(
            {
                "scope": "record",
                "scope_id": "SANDBOX-001",
                "kind": "coding.decision",
                "instance_id": None,
            }
        )
        assert key.scope is Scope.RECORD


class TestInstanceId:
    def test_nichtleerer_instance_id_bleibt_bis_zum_formatmassstab_gesperrt(self) -> None:
        """Enger B1-Warteschutz bis ADR 0028B — hier wird kein Positivformat gemessen.

        Dies ist der enge B1-Warteschutz bis ADR 0028B.

        Gemessen wird die fail-closed Sperre nichtleerer `instance_id`, solange
        kein normativer Formatmaßstab vorliegt.

        Ein Positivformat für einen nichtleeren `instance_id` wird nicht
        gemessen, und das ADR-0027-Abnahmekriterium bleibt bis ADR 0028B offen.

        Der Singleton mit `instance_id` null ist eine Gegenprobe für den
        weiterhin zulässigen Singletonweg, aber kein positiver Formatfall aus
        dem nichtleeren Wertebereich.
        """
        for verworfen in ("u1", "UNIT-0001", "1", "  ", "x" * 64):
            with pytest.raises(InvalidArtifactKey) as exc:
                ArtifactKey(
                    scope=Scope.RECORD,
                    scope_id="SANDBOX-001",
                    kind="coding.decision",
                    instance_id=verworfen,
                )
            assert NO_FORMAT_STANDARD_REASON in str(exc.value)

        # Gegenprobe in derselben Messung: der eininstanzige Fall geht durch.
        assert _singleton().instance_id is None

    def test_die_zurueckweisung_behauptet_keine_formatpruefung(self) -> None:
        with pytest.raises(InvalidArtifactKey) as exc:
            ArtifactKey(
                scope=Scope.RECORD,
                scope_id="SANDBOX-001",
                kind="coding.decision",
                instance_id="u1",
            )
        meldung = str(exc.value)
        assert "0028B" in meldung
        assert "nicht gegen ein vorhandenes Format geprüft" in meldung

    def test_unit_id_ist_kein_sonderfall(self) -> None:
        """R1 Fassung V, B-β: der unitgebundene nichtleere `instance_id` ist
        formatpflichtig; die Vertagung des `unit`-Scope ist keine Ausnahme."""
        with pytest.raises(InvalidArtifactKey) as exc:
            ArtifactKey.from_mapping(
                {
                    "scope": "record",
                    "scope_id": "SANDBOX-001",
                    "kind": "coding.decision",
                    "instance_id": "unit-0001",
                }
            )
        assert NO_FORMAT_STANDARD_REASON in str(exc.value)

    def test_leere_zeichenkette_ist_keine_singletondarstellung(self) -> None:
        with pytest.raises(InvalidArtifactKey) as exc:
            ArtifactKey(
                scope=Scope.RECORD,
                scope_id="SANDBOX-001",
                kind="transcript.revision",
                instance_id="",
            )
        meldung = str(exc.value)
        assert "leere Zeichenkette" in meldung
        assert NO_FORMAT_STANDARD_REASON not in meldung

        # Gegenprobe: null geht durch, die leere Zeichenkette nicht.
        assert _singleton().instance_id is None

    def test_die_zwei_zurueckweisungen_nennen_verschiedene_ursachen(self) -> None:
        with pytest.raises(InvalidArtifactKey) as leer:
            ArtifactKey(Scope.RECORD, "SANDBOX-001", "k", "")
        with pytest.raises(InvalidArtifactKey) as nichtleer:
            ArtifactKey(Scope.RECORD, "SANDBOX-001", "k", "u1")
        assert str(leer.value) != str(nichtleer.value)


class TestFeldabwesenheit:
    def test_ein_fehlendes_feld_ist_nicht_der_volle_schluessel(self) -> None:
        for fehlt in ArtifactKey.FIELDS:
            vollstaendig = {
                "scope": "record",
                "scope_id": "SANDBOX-001",
                "kind": "transcript.revision",
                "instance_id": None,
            }
            del vollstaendig[fehlt]
            with pytest.raises(InvalidArtifactKey) as exc:
                ArtifactKey.from_mapping(vollstaendig)
            assert fehlt in str(exc.value)

        # Gegenprobe: mit allen vier Feldern geht derselbe Weg durch.
        key = ArtifactKey.from_mapping(
            {
                "scope": "record",
                "scope_id": "SANDBOX-001",
                "kind": "transcript.revision",
                "instance_id": None,
            }
        )
        assert key.instance_id is None

    def test_abwesend_und_null_sind_verschiedene_faelle(self) -> None:
        ohne = {"scope": "record", "scope_id": "S", "kind": "k"}
        mit = dict(ohne, instance_id=None)
        with pytest.raises(InvalidArtifactKey):
            ArtifactKey.from_mapping(ohne)
        assert ArtifactKey.from_mapping(mit).instance_id is None

    def test_ein_fremdes_feld_wird_nicht_stillschweigend_verworfen(self) -> None:
        with pytest.raises(InvalidArtifactKey) as exc:
            ArtifactKey.from_mapping(
                {
                    "scope": "record",
                    "scope_id": "S",
                    "kind": "k",
                    "instance_id": None,
                    "projection_version": "v1",
                }
            )
        assert "projection_version" in str(exc.value)


class TestScopeIdUndKind:
    def test_leerer_scope_id_und_leeres_kind_werden_abgewiesen(self) -> None:
        with pytest.raises(InvalidArtifactKey):
            ArtifactKey(Scope.RECORD, "", "transcript.revision", None)
        with pytest.raises(InvalidArtifactKey):
            ArtifactKey(Scope.RECORD, "SANDBOX-001", "", None)

        # Gegenprobe: mit beiden nichtleer geht derselbe Weg durch.
        assert _singleton().kind == "transcript.revision"

    def test_scope_muss_ein_geschlossener_wert_sein(self) -> None:
        with pytest.raises(InvalidArtifactKey):
            ArtifactKey("record", "SANDBOX-001", "k", None)  # type: ignore[arg-type]
