"""B2 · Der dreiteilige `RevisionAnchor` — Fassung, Projektion und Herkunft in einem Wert.

Diese Datei ist zuerst ROT geschrieben und danach durch die kleinste
vollständige Implementierung grün gemacht (ROADMAP § 13, Arbeitsregel je
Scheibe, Schritte 2 und 3).

**Die Invariante, in einem Satz.** Ein `RevisionAnchor` ist genau das
unveränderliche Tripel aus einem vollständigen `ArtifactKey`, einem
kleingeschriebenen sha256 der Revision und einer nichtleeren, unverändert
getragenen `projection_version`; kein Feld fehlt, kein fremdes Feld wird
verworfen und kein Wert wird still ersetzt.

**Woher das Tripel kommt.**
`docs/adr/0028A-transkriptvertrag-was-transcript-confirm-bestaetigt.md § Der
Vertrag` bindet den Anker an `(artifact_key, revision_sha256,
projection_version)` und begründet die Dreiteiligkeit damit, dass dieser
Vertrag die Herkunft aus der Identität ausschliesst und an den `ArtifactKey`
legt: ein Anker ohne `ArtifactKey` führt die Herkunft dorthin, wo sie niemand
mehr erreicht. Derselbe Abschnitt hält fest, dass Anker bei einer neuen
Fassung nicht mitwandern. `docs/adr/0028A-transkriptvertrag-was-transcript-confirm-bestaetigt.md
§ Folgen` nennt einen Anker ohne Projektionsangabe oder ohne `ArtifactKey`
unvollständig.

**Was hier ausdrücklich NICHT geprüft wird.** B2 prüft für
`projection_version` ausschliesslich Typ und Nichtleere. Am Sockel gibt es
keinen Katalog bekannter Projektionsversionen, und das Bestätigungstor, das
eine unbekannte Kennung nach ADR 0028A blockieren soll, ist nicht gebaut. Kein
Test dieser Datei behauptet deshalb, eine Projektionskennung sei bekannt oder
gegen einen Katalog geprüft — geprüft ist, dass der Anker die ausdrücklich
übergebene Kennung zeichengenau trägt. Ebenso berechnet B2 den Revisionshash
nicht und prüft ihn nicht gegen eine Fassung; geprüft ist allein seine Form.

Jeder Test steht als **Fälschungstest mit Gegenprobe** (ADR 0015): zu jeder
Zurückweisung gehört der Nachweis, dass der zulässige Fall in derselben
Messung durchgeht. Ein Test, der nur die eigene Richtung prüft, findet den
eigenen Rückschritt nicht.
"""

from __future__ import annotations

import dataclasses

import pytest

from ohpipe.domain.artifact_key import ArtifactKey, InvalidArtifactKey, Scope
from ohpipe.domain.revision_anchor import InvalidRevisionAnchor, RevisionAnchor

#: Zwei gültige, kleingeschriebene 64-Hex-Werte. Sie stehen für zwei
#: verschiedene Fassungen. B2 berechnet sie nicht und vergleicht sie nicht mit
#: einer Revision — sie sind hier Formbeispiele, keine Identitätsaussage.
REVISION_A = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
REVISION_B = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"

#: Eine ausdrücklich übergebene Projektionskennung. Dass sie hier steht, sagt
#: nichts darüber, ob sie bekannt ist — B2 führt keinen Katalog.
PROJEKTION = "segment-join.v1"


def _key() -> ArtifactKey:
    return ArtifactKey(
        scope=Scope.RECORD,
        scope_id="SANDBOX-001",
        kind="transcript.revision",
        instance_id=None,
    )


def _key_abbildung() -> dict[str, object]:
    return {
        "scope": "record",
        "scope_id": "SANDBOX-001",
        "kind": "transcript.revision",
        "instance_id": None,
    }


def _anker() -> RevisionAnchor:
    return RevisionAnchor(
        artifact_key=_key(),
        revision_sha256=REVISION_A,
        projection_version=PROJEKTION,
    )


def _abbildung(**abweichungen: object) -> dict[str, object]:
    """Die vollständige Ankerabbildung, für den einzelnen Testfall abwandelbar."""
    daten: dict[str, object] = {
        "artifact_key": _key_abbildung(),
        "revision_sha256": REVISION_A,
        "projection_version": PROJEKTION,
    }
    daten.update(abweichungen)
    return daten


class TestR1DasVolleTripel:
    def test_der_anker_traegt_seine_drei_felder_in_vertragsreihenfolge(self) -> None:
        anker = _anker()
        assert [feld.name for feld in dataclasses.fields(anker)] == [
            "artifact_key",
            "revision_sha256",
            "projection_version",
        ]
        assert anker.artifact_key == _key()
        assert anker.revision_sha256 == REVISION_A
        assert anker.projection_version == PROJEKTION

    def test_der_anker_ist_unveraenderlich(self) -> None:
        anker = _anker()
        with pytest.raises(dataclasses.FrozenInstanceError):
            anker.revision_sha256 = REVISION_B  # type: ignore[misc]
        assert anker.revision_sha256 == REVISION_A

    def test_gleicher_inhalt_ist_gleicher_anker_und_hashbar(self) -> None:
        assert _anker() == _anker()
        assert hash(_anker()) == hash(_anker())
        assert len({_anker(), _anker()}) == 1

    def test_der_fehler_ist_ein_eigener_typ_und_ein_valueerror(self) -> None:
        assert issubclass(InvalidRevisionAnchor, ValueError)
        assert InvalidRevisionAnchor is not InvalidArtifactKey


class TestR2FehlendesTopLevelFeld:
    @pytest.mark.parametrize("feld", ["artifact_key", "revision_sha256", "projection_version"])
    def test_jedes_der_drei_felder_faellt_einzeln(self, feld: str) -> None:
        daten = _abbildung()
        del daten[feld]
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(daten)
        assert feld in str(exc.value)

    def test_gegenprobe_die_vollstaendige_abbildung_geht_durch(self) -> None:
        assert RevisionAnchor.from_mapping(_abbildung()) == _anker()

    def test_der_direkte_konstruktor_bleibt_bei_pythons_typeerror(self) -> None:
        """Eine fehlende Aufrufarity ist Pythons Fall und wird nicht umetikettiert."""
        with pytest.raises(TypeError) as exc:
            RevisionAnchor(  # type: ignore[call-arg]
                artifact_key=_key(),
                revision_sha256=REVISION_A,
            )
        assert not isinstance(exc.value, InvalidRevisionAnchor)


class TestR3FremdesTopLevelFeld:
    @pytest.mark.parametrize("fremd", ["note", "source_sha256", "profile_id"])
    def test_ein_fremdes_feld_faellt_und_wird_nicht_verworfen(self, fremd: str) -> None:
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(_abbildung(**{fremd: "irgendetwas"}))
        assert fremd in str(exc.value)

    def test_gegenprobe_ohne_das_fremde_feld_geht_dieselbe_abbildung_durch(self) -> None:
        assert RevisionAnchor.from_mapping(_abbildung()) == _anker()


class TestR4ArtifactKeyObjektUndAbbildung:
    def test_ein_fertiger_schluessel_geht_durch(self) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung(artifact_key=_key()))
        assert isinstance(anker.artifact_key, ArtifactKey)
        assert anker.artifact_key == _key()

    def test_eine_vollstaendige_abbildung_geht_ueber_den_bestehenden_vertrag_durch(
        self,
    ) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung())
        assert isinstance(anker.artifact_key, ArtifactKey)
        assert anker.artifact_key.scope is Scope.RECORD
        assert anker.artifact_key.kind == "transcript.revision"

    def test_der_direkte_konstruktor_nimmt_nur_den_gebauten_schluessel(self) -> None:
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor(
                artifact_key=_key_abbildung(),  # type: ignore[arg-type]
                revision_sha256=REVISION_A,
                projection_version=PROJEKTION,
            )
        assert "artifact_key" in str(exc.value)

    def test_gegenprobe_derselbe_konstruktor_mit_dem_gebauten_schluessel(self) -> None:
        anker = RevisionAnchor(
            artifact_key=_key(),
            revision_sha256=REVISION_A,
            projection_version=PROJEKTION,
        )
        assert anker.artifact_key == _key()


class TestR5DerArtifactKeyVertragBleibtDieEinzigePruefung:
    @pytest.mark.parametrize("feld", ["scope", "scope_id", "kind", "instance_id"])
    def test_ein_fehlendes_schluesselfeld_faellt_ueber_den_bestehenden_vertrag(
        self, feld: str
    ) -> None:
        schluessel = _key_abbildung()
        del schluessel[feld]
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(_abbildung(artifact_key=schluessel))
        assert isinstance(exc.value.__cause__, InvalidArtifactKey)
        assert feld in str(exc.value.__cause__)

    def test_ein_fremdes_schluesselfeld_faellt_ueber_den_bestehenden_vertrag(self) -> None:
        schluessel = _key_abbildung()
        schluessel["unit_id"] = "U-1"
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(_abbildung(artifact_key=schluessel))
        assert isinstance(exc.value.__cause__, InvalidArtifactKey)
        assert "unit_id" in str(exc.value.__cause__)

    def test_eine_leere_instance_id_wird_nicht_zu_null_normalisiert(self) -> None:
        schluessel = _key_abbildung()
        schluessel["instance_id"] = ""
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(_abbildung(artifact_key=schluessel))
        assert isinstance(exc.value.__cause__, InvalidArtifactKey)
        assert "instance_id" in str(exc.value.__cause__)

    def test_artifact_key_ist_weder_schluessel_noch_abbildung(self) -> None:
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(_abbildung(artifact_key="SANDBOX-001"))
        assert "artifact_key" in str(exc.value)

    def test_gegenprobe_null_bleibt_null_und_geht_durch(self) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung())
        assert anker.artifact_key.instance_id is None
        schluessel = anker.to_mapping()["artifact_key"]
        assert "instance_id" in schluessel
        assert schluessel["instance_id"] is None


class TestR6RevisionSha256:
    def test_ein_kleingeschriebener_64_hexwert_geht_durch(self) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung())
        assert anker.revision_sha256 == REVISION_A

    @pytest.mark.parametrize(
        "wert",
        [
            REVISION_A.upper(),
            REVISION_A[:63],
            REVISION_A + "0",
            "g" + REVISION_A[1:],
            REVISION_A + "\n",
            REVISION_A + "\r",
            REVISION_A + " ",
            "\n" + REVISION_A,
            "",
        ],
        ids=[
            "grossbuchstaben",
            "zu-kurz",
            "zu-lang",
            "nicht-hex",
            "mit-lf",
            "mit-cr",
            "mit-leerzeichen",
            "fuehrendes-lf",
            "leer",
        ],
    )
    def test_jede_formabweichung_faellt(self, wert: str) -> None:
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(_abbildung(revision_sha256=wert))
        assert "revision_sha256" in str(exc.value)

    @pytest.mark.parametrize(
        "wert",
        [None, 42, b"0f1e2d3c", ["0f1e2d3c"]],
        ids=["null", "zahl", "bytes", "liste"],
    )
    def test_ein_nichtstringwert_faellt(self, wert: object) -> None:
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(_abbildung(revision_sha256=wert))
        assert "revision_sha256" in str(exc.value)

    def test_gegenprobe_ein_zweiter_gueltiger_wert_geht_denselben_weg(self) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung(revision_sha256=REVISION_B))
        assert anker.revision_sha256 == REVISION_B


class TestR7ProjectionVersion:
    def test_eine_nichtleere_kennung_wird_zeichengenau_getragen(self) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung(projection_version="segment-join.v2"))
        assert anker.projection_version == "segment-join.v2"

    def test_die_leere_kennung_faellt(self) -> None:
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(_abbildung(projection_version=""))
        assert "projection_version" in str(exc.value)

    @pytest.mark.parametrize("wert", [None, 1, ["segment-join.v1"]], ids=["null", "zahl", "liste"])
    def test_ein_nichtstringwert_faellt(self, wert: object) -> None:
        with pytest.raises(InvalidRevisionAnchor) as exc:
            RevisionAnchor.from_mapping(_abbildung(projection_version=wert))
        assert "projection_version" in str(exc.value)

    def test_die_pruefung_behauptet_keinen_katalog(self) -> None:
        """Typ und Nichtleere — nicht Bekanntheit. B2 führt keinen Katalog."""
        anker = RevisionAnchor.from_mapping(_abbildung(projection_version="voellig-unbekannt"))
        assert anker.projection_version == "voellig-unbekannt"


class TestR8DieStrukturelleAbbildung:
    def test_genau_drei_top_level_felder_in_vertragsreihenfolge(self) -> None:
        abbildung = _anker().to_mapping()
        assert list(abbildung) == [
            "artifact_key",
            "revision_sha256",
            "projection_version",
        ]

    def test_genau_die_vier_schluesselfelder(self) -> None:
        schluessel = _anker().to_mapping()["artifact_key"]
        assert tuple(schluessel) == ArtifactKey.FIELDS

    def test_scope_ist_ein_reiner_string_und_kein_enum(self) -> None:
        scope = _anker().to_mapping()["artifact_key"]["scope"]
        assert type(scope) is str
        assert scope == "record"

    def test_instance_id_null_bleibt_ausdruecklich_vorhanden(self) -> None:
        schluessel = _anker().to_mapping()["artifact_key"]
        assert "instance_id" in schluessel
        assert schluessel["instance_id"] is None

    def test_gegenprobe_der_workspace_scope_wird_ebenso_als_string_ausgegeben(self) -> None:
        anker = RevisionAnchor(
            artifact_key=ArtifactKey(
                scope=Scope.WORKSPACE,
                scope_id="WS-1",
                kind="transcript.revision",
                instance_id=None,
            ),
            revision_sha256=REVISION_A,
            projection_version=PROJEKTION,
        )
        scope = anker.to_mapping()["artifact_key"]["scope"]
        assert type(scope) is str
        assert scope == "workspace"


class TestR9Roundtrip:
    def test_from_mapping_der_eigenen_ausgabe_ergibt_denselben_anker(self) -> None:
        anker = _anker()
        assert RevisionAnchor.from_mapping(anker.to_mapping()) == anker

    def test_der_roundtrip_ist_auch_in_der_abbildung_stabil(self) -> None:
        anker = _anker()
        zurueck = RevisionAnchor.from_mapping(anker.to_mapping())
        assert zurueck.to_mapping() == anker.to_mapping()

    def test_der_roundtrip_traegt_die_kennung_zeichengenau_durch(self) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung(projection_version=" Segment-Join.V1 "))
        assert RevisionAnchor.from_mapping(anker.to_mapping()).projection_version == (
            " Segment-Join.V1 "
        )


class TestR10KeineGeteilteInnereAbbildung:
    def test_zwei_aufrufe_teilen_die_innere_abbildung_nicht(self) -> None:
        anker = _anker()
        erste = anker.to_mapping()
        zweite = anker.to_mapping()
        assert erste == zweite
        assert erste is not zweite
        assert erste["artifact_key"] is not zweite["artifact_key"]

    def test_eine_mutation_der_ausgabe_erreicht_den_anker_nicht(self) -> None:
        anker = _anker()
        erste = anker.to_mapping()
        erste["artifact_key"]["kind"] = "etwas anderes"
        erste["revision_sha256"] = REVISION_B
        zweite = anker.to_mapping()
        assert zweite["artifact_key"]["kind"] == "transcript.revision"
        assert zweite["revision_sha256"] == REVISION_A
        assert anker.artifact_key == _key()
        assert anker.revision_sha256 == REVISION_A


class TestR11AnkerWandernNicht:
    def test_eine_neue_revision_ergibt_einen_anderen_anker(self) -> None:
        alt = _anker()
        neu = RevisionAnchor.from_mapping(_abbildung(revision_sha256=REVISION_B))
        assert neu != alt
        assert neu.revision_sha256 == REVISION_B
        assert alt.revision_sha256 == REVISION_A
        assert alt == _anker()

    def test_eine_neue_projektionskennung_ergibt_einen_anderen_anker(self) -> None:
        alt = _anker()
        neu = RevisionAnchor.from_mapping(_abbildung(projection_version="segment-join.v2"))
        assert neu != alt
        assert neu.projection_version == "segment-join.v2"
        assert alt.projection_version == PROJEKTION
        assert alt == _anker()

    def test_gegenprobe_dasselbe_tripel_bleibt_derselbe_anker(self) -> None:
        assert RevisionAnchor.from_mapping(_abbildung()) == _anker()


class TestR12KeinStillesErsetzen:
    def test_die_kennung_wird_nicht_getrimmt(self) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung(projection_version=" segment-join.v1 "))
        assert anker.projection_version == " segment-join.v1 "
        assert anker.to_mapping()["projection_version"] == " segment-join.v1 "

    def test_die_kennung_wird_nicht_kleingeschrieben(self) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung(projection_version="Segment-Join.V1"))
        assert anker.projection_version == "Segment-Join.V1"
        assert anker.to_mapping()["projection_version"] == "Segment-Join.V1"

    def test_der_revisionshash_wird_zeichengenau_getragen_und_nicht_ersetzt(self) -> None:
        anker = RevisionAnchor.from_mapping(_abbildung(revision_sha256=REVISION_B))
        assert anker.revision_sha256 == REVISION_B
        assert anker.to_mapping()["revision_sha256"] == REVISION_B

    def test_der_konstruktor_setzt_keinen_default_fuer_die_kennung(self) -> None:
        with pytest.raises(TypeError):
            RevisionAnchor(  # type: ignore[call-arg]
                artifact_key=_key(),
                revision_sha256=REVISION_A,
            )

    def test_die_abbildung_traegt_keine_berechnete_zusatzkennung(self) -> None:
        abbildung = _anker().to_mapping()
        for fremd in (
            "anchor_id",
            "source_sha256",
            "transcript_sha256",
            "profile_id",
            "note",
        ):
            assert fremd not in abbildung
