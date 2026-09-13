"""B3a · Der seiteneffektfreie Revisionskern — Projektion, CANON, Hash.

Diese Datei ist zuerst ROT geschrieben und danach durch die Implementierung
grün gemacht (ROADMAP § 13, Arbeitsregel je Scheibe).

**Die Invariante, in einem Satz.** Zu jeder gültigen identitätsbildenden
`TranscriptRevision` existiert genau eine kanonische UTF-8-Bytefolge ohne
Folgebyte; aus ihr sind alle identitätsbildenden Felder wiederherstellbar,
ihr sha256 ist die Revisionsidentität, und jeder Regelbruch fällt in der
festgelegten Priorität fail-closed, ohne Eingaben zu reparieren.

Die normativen Werte stammen aus
`docs/adr/0028B-S-revisionsserialisierung-und-P-projektionsvertrag.md`.
Die vier positiven Vektoren führen ihre vollständige erwartete Hexfolge; sie
wird hier nicht berechnet, sondern gegen die Implementierung gehalten.

Jeder negative Test steht als **Fälschungstest mit Gegenprobe** (ADR 0015).
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass

import pytest

from ohpipe.domain.artifact_key import ArtifactKey, Scope
from ohpipe.domain.revision_anchor import RevisionAnchor
from ohpipe.domain.revision_serialization import (
    KNOWN_PROJECTION_VERSIONS,
    PROJECTION_VERSION,
    InvalidProjectionVersion,
    InvalidRevisionNormalization,
    InvalidRevisionSchema,
    InvalidRevisionType,
    InvalidSegmentOrder,
    ProjectionDefinitionUnavailable,
    ProjectionMismatch,
    RevisionHashMismatch,
    RevisionReconstructionMismatch,
    RevisionValidationError,
    UnknownProjectionVersion,
    canonical_revision_bytes,
    project_segments,
    reconstruct_revision,
    revision_sha256,
    validate_revision,
    verify_revision,
)
from ohpipe.domain.transcript import Segment, TranscriptRevision

LF = chr(10)
CR = chr(13)
KOMBI_TREMA = chr(776)


@dataclass(frozen=True)
class _Vektor:
    """Ein normativer Positivvektor mit seinen vollen Sollwerten."""

    name: str
    profile_id: str
    projection_version: str
    segments: tuple[Segment, ...]
    fulltext: str
    canon_hex: str
    n_bytes: int
    schlussbyte: str
    sha256: str

    def revision(self) -> TranscriptRevision:
        return TranscriptRevision(
            text=self.fulltext,
            projection_version=self.projection_version,
            profile_id=self.profile_id,
            segments=self.segments,
        )

    def canon(self) -> bytes:
        return bytes.fromhex(self.canon_hex)


VEKTOREN: dict[str, _Vektor] = {
    "V1": _Vektor(
        name="V1",
        profile_id="dinoh-lux",
        projection_version="seg-join-lf.v1",
        segments=(
            Segment(
                index=0, start_ms=0, end_ms=1500, text="Guten Tag.", speaker="S1", language="deu"
            ),
        ),
        fulltext="Guten Tag.",
        canon_hex=(
            "7b22646f6d61696e223a227472616e7363726970745f7265766973696f6e222c2266756c"
            "6c74657874223a22477574656e205461672e222c2270726f66696c655f6964223a226469"
            "6e6f682d6c7578222c2270726f6a656374696f6e5f76657273696f6e223a227365672d6a"
            "6f696e2d6c662e7631222c227365676d656e7473223a5b7b22656e645f6d73223a313530"
            "302c22696e646578223a302c226c616e6775616765223a22646575222c22737065616b65"
            "72223a225331222c2273746172745f6d73223a302c2274657874223a22477574656e2054"
            "61672e227d5d2c2276223a317d"
        ),
        n_bytes=229,
        schlussbyte="7d",
        sha256="181855bbe875290a5468e5e15713153c829b20f8a57c0f0203a4adac0f797fa5",
    ),
    "V2": _Vektor(
        name="V2",
        profile_id="dinoh-lux",
        projection_version="seg-join-lf.v1",
        segments=(
            Segment(
                index=0, start_ms=0, end_ms=1500, text="Guten Tag.", speaker="S1", language="deu"
            ),
            Segment(
                index=1,
                start_ms=1500,
                end_ms=3200,
                text="Auf Wiedersehen.",
                speaker="S2",
                language="deu",
            ),
        ),
        fulltext="Guten Tag.\nAuf Wiedersehen.",
        canon_hex=(
            "7b22646f6d61696e223a227472616e7363726970745f7265766973696f6e222c2266756c"
            "6c74657874223a22477574656e205461672e5c6e41756620576965646572736568656e2e"
            "222c2270726f66696c655f6964223a2264696e6f682d6c7578222c2270726f6a65637469"
            "6f6e5f76657273696f6e223a227365672d6a6f696e2d6c662e7631222c227365676d656e"
            "7473223a5b7b22656e645f6d73223a313530302c22696e646578223a302c226c616e6775"
            "616765223a22646575222c22737065616b6572223a225331222c2273746172745f6d7322"
            "3a302c2274657874223a22477574656e205461672e227d2c7b22656e645f6d73223a3332"
            "30302c22696e646578223a312c226c616e6775616765223a22646575222c22737065616b"
            "6572223a225332222c2273746172745f6d73223a313530302c2274657874223a22417566"
            "20576965646572736568656e2e227d5d2c2276223a317d"
        ),
        n_bytes=347,
        schlussbyte="7d",
        sha256="6fb042f38df5fd2d9174f862b787cb49115d6c172e8485e1f6462394dbf8bf61",
    ),
    "V3": _Vektor(
        name="V3",
        profile_id="dinoh-lux",
        projection_version="seg-join-lf.v1",
        segments=(
            Segment(
                index=0,
                start_ms=0,
                end_ms=2000,
                text="Straße in Köln",
                speaker="S1",
                language="deu",
            ),
            Segment(
                index=1,
                start_ms=2000,
                end_ms=4000,
                text="Café – précis",
                speaker="S2",
                language="fra",
            ),
        ),
        fulltext="Straße in Köln\nCafé – précis",
        canon_hex=(
            "7b22646f6d61696e223a227472616e7363726970745f7265766973696f6e222c2266756c"
            "6c74657874223a2253747261c39f6520696e204bc3b66c6e5c6e436166c3a920e2809320"
            "7072c3a9636973222c2270726f66696c655f6964223a2264696e6f682d6c7578222c2270"
            "726f6a656374696f6e5f76657273696f6e223a227365672d6a6f696e2d6c662e7631222c"
            "227365676d656e7473223a5b7b22656e645f6d73223a323030302c22696e646578223a30"
            "2c226c616e6775616765223a22646575222c22737065616b6572223a225331222c227374"
            "6172745f6d73223a302c2274657874223a2253747261c39f6520696e204bc3b66c6e227d"
            "2c7b22656e645f6d73223a343030302c22696e646578223a312c226c616e677561676522"
            "3a22667261222c22737065616b6572223a225332222c2273746172745f6d73223a323030"
            "302c2274657874223a22436166c3a920e28093207072c3a9636973227d5d2c2276223a31"
            "7d"
        ),
        n_bytes=361,
        schlussbyte="7d",
        sha256="7bf46e39eba41dec1f84315ae96e537f3c830b03efb16a986eebeeef34183074",
    ),
    "V5": _Vektor(
        name="V5",
        profile_id="dinoh-lux",
        projection_version="seg-join-lf.v1",
        segments=(
            Segment(index=0, start_ms=0, end_ms=0, text="", speaker="S1", language="zxx"),
            Segment(index=1, start_ms=0, end_ms=900, text="hm", speaker="S2", language="und"),
        ),
        fulltext="\nhm",
        canon_hex=(
            "7b22646f6d61696e223a227472616e7363726970745f7265766973696f6e222c2266756c"
            "6c74657874223a225c6e686d222c2270726f66696c655f6964223a2264696e6f682d6c75"
            "78222c2270726f6a656374696f6e5f76657273696f6e223a227365672d6a6f696e2d6c66"
            "2e7631222c227365676d656e7473223a5b7b22656e645f6d73223a302c22696e64657822"
            "3a302c226c616e6775616765223a227a7878222c22737065616b6572223a225331222c22"
            "73746172745f6d73223a302c2274657874223a22227d2c7b22656e645f6d73223a393030"
            "2c22696e646578223a312c226c616e6775616765223a22756e64222c22737065616b6572"
            "223a225332222c2273746172745f6d73223a302c2274657874223a22686d227d5d2c2276"
            "223a317d"
        ),
        n_bytes=292,
        schlussbyte="7d",
        sha256="3c013489b62c6fe99a8c3d992ba7f6a2f1d9eb4be7b53eec0704b551b50de8f2",
    ),
}

#: Die N6-Bytes aus der Norm: in die sonst unveränderten V2-CANON-Bytes ist
#: genau ein ASCII-Leerzeichen (Hexwert 20) unmittelbar nach dem ersten
#: Doppelpunkt hinter ``"domain"`` eingefügt.
N6_HEX = (
    "7b22646f6d61696e223a20227472616e7363726970745f7265766973696f6e222c226675"
    "6c6c74657874223a22477574656e205461672e5c6e41756620576965646572736568656e"
    "2e222c2270726f66696c655f6964223a2264696e6f682d6c7578222c2270726f6a656374"
    "696f6e5f76657273696f6e223a227365672d6a6f696e2d6c662e7631222c227365676d65"
    "6e7473223a5b7b22656e645f6d73223a313530302c22696e646578223a302c226c616e67"
    "75616765223a22646575222c22737065616b6572223a225331222c2273746172745f6d73"
    "223a302c2274657874223a22477574656e205461672e227d2c7b22656e645f6d73223a33"
    "3230302c22696e646578223a312c226c616e6775616765223a22646575222c2273706561"
    "6b6572223a225332222c2273746172745f6d73223a313530302c2274657874223a224175"
    "6620576965646572736568656e2e227d5d2c2276223a317d"
)
N6_BYTES = 348
N6_SHA256 = "b79c87c3f5554d152ec8735453ab6020bb120ce41bf93173e32254d4da17f68d"

#: Der falsch vorgelegte Digest aus N7: formgültige 64 Hexziffern, aber nicht
#: der aus CANON berechnete Wert. Die erste Ziffer 6 ist zu 7 geändert.
N7_FALSCHER_DIGEST = "7fb042f38df5fd2d9174f862b787cb49115d6c172e8485e1f6462394dbf8bf61"


def _v(name: str) -> _Vektor:
    return VEKTOREN[name]


def _rev(**abweichungen: object) -> TranscriptRevision:
    """V2 als gesunde Grundform, für den einzelnen Testfall abwandelbar."""
    v = _v("V2")
    daten: dict[str, object] = {
        "text": v.fulltext,
        "projection_version": v.projection_version,
        "profile_id": v.profile_id,
        "segments": v.segments,
    }
    daten.update(abweichungen)
    return TranscriptRevision(**daten)  # type: ignore[arg-type]


def _seg(i: int, a: int, e: int, sp: str, la: str, tx: str) -> Segment:
    return Segment(index=i, start_ms=a, end_ms=e, text=tx, speaker=sp, language=la)


def _bestandsrevision() -> TranscriptRevision:
    """Eine gueltige Revision unter einem im Bestand bekannten Normalisierungsprofil.

    Die normativen Vektoren tragen `profile_id` ``dinoh-lux``. Teil S verlangt
    dafuer nur eine nichtleere Zeichenkette und prueft sie nicht gegen die
    Normalisierungsprofile des Bestands — die Diagnostik `text_sha256` und die
    Anzeige `to_json` greifen aber darauf zu. Tests, die Diagnostik oder
    Anzeige messen, verwenden deshalb diese Fassung.
    """
    from ohpipe.domain.hashing import NFC_STRICT

    segs = _v("V2").segments
    return TranscriptRevision(
        text=project_segments(segs, PROJECTION_VERSION),
        projection_version=PROJECTION_VERSION,
        profile_id=NFC_STRICT.id,
        segments=segs,
    )


# --- Normative Positivvektoren -------------------------------------------


class TestPositivvektoren:
    @pytest.mark.parametrize("name", ["V1", "V2", "V3", "V5"])
    def test_canon_trifft_die_normativen_bytes(self, name: str) -> None:
        v = _v(name)
        canon = canonical_revision_bytes(v.revision())
        assert canon == v.canon()
        assert len(canon) == v.n_bytes
        assert canon[-1:].hex() == v.schlussbyte

    @pytest.mark.parametrize("name", ["V1", "V2", "V3", "V5"])
    def test_hash_trifft_den_normativen_sollwert(self, name: str) -> None:
        v = _v(name)
        assert revision_sha256(v.revision()) == v.sha256
        assert hashlib.sha256(v.canon()).hexdigest() == v.sha256

    @pytest.mark.parametrize("name", ["V1", "V2", "V3", "V5"])
    def test_projektion_und_volltext_treffen(self, name: str) -> None:
        v = _v(name)
        assert project_segments(v.segments, v.projection_version) == v.fulltext

    @pytest.mark.parametrize("name", ["V1", "V2", "V3", "V5"])
    def test_rekonstruktion_und_roundtrip(self, name: str) -> None:
        v = _v(name)
        zurueck = reconstruct_revision(v.canon())
        assert zurueck.text == v.fulltext
        assert zurueck.projection_version == v.projection_version
        assert zurueck.profile_id == v.profile_id
        assert tuple(zurueck.segments) == v.segments
        assert canonical_revision_bytes(zurueck) == v.canon()

    @pytest.mark.parametrize("name", ["V1", "V2", "V3", "V5"])
    def test_verify_geht_mit_dem_richtigen_digest_durch(self, name: str) -> None:
        v = _v(name)
        assert verify_revision(v.canon(), v.sha256).text == v.fulltext

    def test_v4_bleibt_begruendet_entfallen(self) -> None:
        """Kein positiver V4: das Schema kennt keine null- oder optionale Feldform."""
        assert "V4" not in VEKTOREN
        with pytest.raises(InvalidRevisionType):
            canonical_revision_bytes(
                _rev(
                    segments=(
                        _seg(0, 0, 1, "S1", "deu", "a"),
                        Segment(
                            index=1, start_ms=None, end_ms=2, text="b", speaker="S2", language="deu"
                        ),
                    )
                )
            )


# --- Normative Negativvektoren -------------------------------------------


class TestN1ProjectionMismatch:
    def test_fulltext_weicht_von_der_segmentprojektion_ab(self) -> None:
        v = _v("V2")
        with pytest.raises(ProjectionMismatch) as exc:
            canonical_revision_bytes(_rev(text="Guten Tag. Auf Wiedersehen."))
        assert "fulltext" in str(exc.value)
        assert canonical_revision_bytes(v.revision()) == v.canon()

    def test_der_volltext_wird_nicht_aus_den_segmenten_ersetzt(self) -> None:
        abweichend = _rev(text="etwas ganz anderes")
        with pytest.raises(ProjectionMismatch):
            canonical_revision_bytes(abweichend)
        assert abweichend.text == "etwas ganz anderes"


class TestN2UnknownProjectionVersion:
    def test_syntaktisch_gueltig_aber_nicht_im_katalog(self) -> None:
        with pytest.raises(UnknownProjectionVersion) as exc:
            canonical_revision_bytes(_rev(projection_version="seg-join-lf.v2"))
        assert "seg-join-lf.v2" in str(exc.value)

    def test_gegenprobe_der_katalogwert_geht_durch(self) -> None:
        assert canonical_revision_bytes(_v("V2").revision()) == _v("V2").canon()
        assert PROJECTION_VERSION == "seg-join-lf.v1"
        assert tuple(KNOWN_PROJECTION_VERSIONS) == ("seg-join-lf.v1",)


class TestN3Normalisierung:
    def test_n3_nicht_nfc_normalisierter_string(self) -> None:
        text = "K" + chr(111) + KOMBI_TREMA + "ln"
        assert not unicodedata.is_normalized("NFC", text)
        segs = (_seg(0, 0, 1500, "S1", "deu", text), _v("V2").segments[1])
        with pytest.raises(InvalidRevisionNormalization) as exc:
            canonical_revision_bytes(_rev(segments=segs, text=text + LF + segs[1].text))
        assert "NFC" in str(exc.value)

    def test_n3b_cr_im_segmenttext(self) -> None:
        text = "Guten Tag." + CR
        segs = (_seg(0, 0, 1500, "S1", "deu", text), _v("V2").segments[1])
        with pytest.raises(InvalidRevisionNormalization) as exc:
            canonical_revision_bytes(_rev(segments=segs, text=text + LF + segs[1].text))
        assert "000D" in str(exc.value) or "U+000D" in str(exc.value)

    def test_gegenprobe_nfc_ohne_cr_geht_durch(self) -> None:
        assert canonical_revision_bytes(_v("V3").revision()) == _v("V3").canon()


class TestN4Segmentordnung:
    def test_n4_doppelte_indizes(self) -> None:
        segs = (_seg(0, 0, 1500, "S1", "deu", "a"), _seg(0, 1500, 3200, "S2", "deu", "b"))
        with pytest.raises(InvalidSegmentOrder):
            canonical_revision_bytes(_rev(segments=segs, text="a" + LF + "b"))

    def test_n4b_luecke_in_den_indizes(self) -> None:
        segs = (_seg(0, 0, 1500, "S1", "deu", "a"), _seg(2, 1500, 3200, "S2", "deu", "b"))
        with pytest.raises(InvalidSegmentOrder):
            canonical_revision_bytes(_rev(segments=segs, text="a" + LF + "b"))

    def test_gegenprobe_lueckenlose_indizes_gehen_durch(self) -> None:
        segs = (_seg(0, 0, 1500, "S1", "deu", "a"), _seg(1, 1500, 3200, "S2", "deu", "b"))
        assert canonical_revision_bytes(_rev(segments=segs, text="a" + LF + "b"))


class TestN5TypUndSchema:
    def test_n5_falscher_typ(self) -> None:
        segs = (
            Segment(index=0, start_ms="0", end_ms=1500, text="a", speaker="S1", language="deu"),
        )
        with pytest.raises(InvalidRevisionType) as exc:
            canonical_revision_bytes(_rev(segments=segs, text="a"))
        assert "start_ms" in str(exc.value)

    def test_n5b_null(self) -> None:
        segs = (Segment(index=0, start_ms=0, end_ms=1500, text="a", speaker=None, language="deu"),)
        with pytest.raises(InvalidRevisionType) as exc:
            canonical_revision_bytes(_rev(segments=segs, text="a"))
        assert "speaker" in str(exc.value)

    def test_n5c_unbekannter_objektschluessel(self) -> None:
        roh = json.loads(_v("V2").canon().decode("utf-8"))
        roh["note"] = "durchgesehen"
        bytes_ = json.dumps(roh, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        with pytest.raises(InvalidRevisionSchema) as exc:
            reconstruct_revision(bytes_)
        assert "note" in str(exc.value)

    def test_gegenprobe_ohne_fremdes_feld_geht_dieselbe_abbildung_durch(self) -> None:
        assert reconstruct_revision(_v("V2").canon()).text == _v("V2").fulltext


class TestN6ReconstructionMismatch:
    def test_ein_leerzeichen_nach_domain_erzeugt_eine_nichtkanonische_byteform(self) -> None:
        n6 = bytes.fromhex(N6_HEX)
        assert len(n6) == N6_BYTES == 348
        assert hashlib.sha256(n6).hexdigest() == N6_SHA256
        assert n6.decode("utf-8").startswith('{"domain": "transcript_revision",')
        assert json.loads(n6.decode("utf-8")) == json.loads(_v("V2").canon().decode("utf-8"))
        assert n6 != _v("V2").canon()

    def test_n6_faellt_ausschliesslich_als_reconstruction_mismatch(self) -> None:
        with pytest.raises(RevisionReconstructionMismatch) as exc:
            reconstruct_revision(bytes.fromhex(N6_HEX))
        assert not isinstance(exc.value, InvalidRevisionSchema)

    def test_die_reserialisierung_trifft_die_unveraenderten_347_bytes(self) -> None:
        roh = json.loads(bytes.fromhex(N6_HEX).decode("utf-8"))
        wieder = canonical_revision_bytes(
            TranscriptRevision(
                text=roh["fulltext"],
                projection_version=roh["projection_version"],
                profile_id=roh["profile_id"],
                segments=tuple(
                    Segment(
                        index=s["index"],
                        start_ms=s["start_ms"],
                        end_ms=s["end_ms"],
                        text=s["text"],
                        speaker=s["speaker"],
                        language=s["language"],
                    )
                    for s in roh["segments"]
                ),
            )
        )
        assert wieder == _v("V2").canon()
        assert len(wieder) == 347

    def test_gegenprobe_die_kanonische_form_geht_durch(self) -> None:
        assert reconstruct_revision(_v("V2").canon()).text == _v("V2").fulltext


class TestN7HashMismatch:
    def test_canon_bleibt_unveraendert_und_nur_der_digest_ist_falsch(self) -> None:
        canon = _v("V2").canon()
        assert len(canon) == 347
        assert canon[-1:].hex() == "7d"
        assert hashlib.sha256(canon).hexdigest() == _v("V2").sha256
        assert _v("V2").sha256 != N7_FALSCHER_DIGEST
        assert N7_FALSCHER_DIGEST[1:] == _v("V2").sha256[1:]
        assert len(N7_FALSCHER_DIGEST) == 64

    def test_n7_faellt_ausschliesslich_als_hash_mismatch(self) -> None:
        with pytest.raises(RevisionHashMismatch) as exc:
            verify_revision(_v("V2").canon(), N7_FALSCHER_DIGEST)
        assert not isinstance(exc.value, RevisionReconstructionMismatch)

    def test_gegenprobe_der_richtige_digest_geht_durch(self) -> None:
        assert verify_revision(_v("V2").canon(), _v("V2").sha256).text == _v("V2").fulltext


class TestRegelklassenOhnePflichtvektor:
    @pytest.mark.parametrize(
        "wert",
        [
            "SEG-JOIN-LF.V1",
            "seg-join-lf.v0",
            "seg-join-lf",
            "-seg.v1",
            "seg--join.v1",
            "a1",
            "s" + chr(228) + "g-join-lf.v1",
            "a" * 62 + ".v1",
            "",
        ],
        ids=[
            "gross",
            "v0",
            "ohne-version",
            "fuehrender-strich",
            "doppelter-strich",
            "unter-drei-zeichen",
            "nicht-ascii",
            "ueber-64-zeichen",
            "leer",
        ],
    )
    def test_invalid_projection_version_bei_syntax_laenge_und_nicht_ascii(self, wert: str) -> None:
        """Alle neun Werte verletzen Syntax oder Laengengrenze aus Teil P.

        Der kuerzeste syntaktisch gueltige Wert ist vierstellig; die
        Untergrenze 3 ist deshalb nur ueber einen Syntaxverstoss erreichbar.
        """
        with pytest.raises(InvalidProjectionVersion):
            canonical_revision_bytes(_rev(projection_version=wert))

    def test_projection_definition_unavailable_als_konsistenzwaechter(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Katalogwert ohne Produktdefinition. Lokale, reversible Testmutation."""
        from ohpipe.domain import revision_serialization as rs

        vorher = dict(rs._PROJEKTIONEN)
        monkeypatch.setattr(rs, "_PROJEKTIONEN", {})
        with pytest.raises(ProjectionDefinitionUnavailable):
            canonical_revision_bytes(_v("V2").revision())
        monkeypatch.undo()
        assert dict(rs._PROJEKTIONEN) == vorher
        assert canonical_revision_bytes(_v("V2").revision()) == _v("V2").canon()


# --- Pflichttests T1 bis T24 ---------------------------------------------


class TestT1BisT5ProjektionUndText:
    def test_t1_null_segmente(self) -> None:
        assert project_segments((), PROJECTION_VERSION) == ""
        with pytest.raises(InvalidRevisionSchema) as exc:
            canonical_revision_bytes(_rev(segments=(), text=""))
        assert "segments" in str(exc.value)

    def test_t2_joinerzahl(self) -> None:
        assert canonical_revision_bytes(_v("V1").revision()) == _v("V1").canon()
        assert _v("V1").fulltext.count(LF) == 0
        assert _v("V2").fulltext.count(LF) == 1
        drei = tuple(_seg(i, i * 10, i * 10 + 5, "S", "deu", f"t{i}") for i in range(3))
        assert project_segments(drei, PROJECTION_VERSION).count(LF) == 2

    def test_t3_leerer_segmenttext_bleibt_erhalten(self) -> None:
        v = _v("V5")
        assert v.segments[0].text == ""
        assert v.fulltext.startswith(LF)
        assert canonical_revision_bytes(v.revision()) == v.canon()
        assert len(reconstruct_revision(v.canon()).segments) == 2

    def test_t4_whitespace_bleibt_identitaetsbildend(self) -> None:
        segs = (_seg(0, 0, 10, "S1", "deu", "  Rand  "),)
        canon = canonical_revision_bytes(_rev(segments=segs, text="  Rand  "))
        assert b'"text":"  Rand  "' in canon
        ohne = canonical_revision_bytes(
            _rev(segments=(_seg(0, 0, 10, "S1", "deu", "Rand"),), text="Rand")
        )
        assert canon != ohne

    def test_t5_cr_und_nicht_nfc_werden_verworfen_nicht_repariert(self) -> None:
        for text in ("a" + CR + "b", "K" + chr(111) + KOMBI_TREMA + "ln"):
            segs = (_seg(0, 0, 10, "S1", "deu", text),)
            with pytest.raises(InvalidRevisionNormalization):
                canonical_revision_bytes(_rev(segments=segs, text=text))
        gut = (_seg(0, 0, 10, "S1", "deu", "K" + chr(246) + "ln"),)
        assert canonical_revision_bytes(_rev(segments=gut, text="K" + chr(246) + "ln"))


class TestT6BisT11Byteform:
    def test_t6_sortierte_schluessel_minimale_separatoren_ensure_ascii_false(self) -> None:
        canon = _v("V3").canon()
        text = canon.decode("utf-8")
        assert text.startswith('{"domain":"transcript_revision",')
        assert '", "' not in text and '": "' not in text
        assert "Stra" + chr(223) in text
        assert (chr(92) + "u") not in text

    def test_t7_slash_unescaped_und_nicht_bmp_als_utf8(self) -> None:
        segs = (_seg(0, 0, 10, "S1", "deu", "a/b " + chr(0x1F600)),)
        canon = canonical_revision_bytes(_rev(segments=segs, text="a/b " + chr(0x1F600)))
        assert b"a/b" in canon
        assert chr(0x1F600).encode("utf-8") in canon
        assert (chr(92) + "u").encode() not in canon

    def test_t8_bool_null_float_negativ_und_unbekanntes_feld_fallen(self) -> None:
        faelle = [
            (_seg(0, 0, 10, "S1", "deu", "a"), {"start_ms": True}),
            (_seg(0, 0, 10, "S1", "deu", "a"), {"end_ms": None}),
            (_seg(0, 0, 10, "S1", "deu", "a"), {"start_ms": 1.5}),
            (_seg(0, 0, 10, "S1", "deu", "a"), {"start_ms": -1}),
        ]
        for basis, abw in faelle:
            segs = (
                Segment(
                    index=basis.index,
                    start_ms=abw.get("start_ms", basis.start_ms),
                    end_ms=abw.get("end_ms", basis.end_ms),
                    text=basis.text,
                    speaker=basis.speaker,
                    language=basis.language,
                ),
            )
            with pytest.raises(InvalidRevisionType):
                canonical_revision_bytes(_rev(segments=segs, text="a"))
        assert canonical_revision_bytes(
            _rev(segments=(_seg(0, 0, 10, "S1", "deu", "a"),), text="a")
        )

    def test_t9_ueberlappung_geht_durch_endms_kleiner_startms_faellt(self) -> None:
        ueberlappend = (_seg(0, 0, 2000, "S1", "deu", "a"), _seg(1, 1000, 3000, "S2", "deu", "b"))
        assert canonical_revision_bytes(_rev(segments=ueberlappend, text="a" + LF + "b"))
        kaputt = (_seg(0, 2000, 1000, "S1", "deu", "a"),)
        with pytest.raises(InvalidRevisionType) as exc:
            canonical_revision_bytes(_rev(segments=kaputt, text="a"))
        assert "end_ms" in str(exc.value)

    def test_t10_canon_beginnt_7b_endet_7d_ohne_bom_und_folgebyte(self) -> None:
        for name in ("V1", "V2", "V3", "V5"):
            canon = canonical_revision_bytes(_v(name).revision())
            assert canon[:1] == bytes.fromhex("7b")
            assert canon[-1:] == bytes.fromhex("7d")
            assert not canon.startswith(b"\xef\xbb\xbf")
            assert not canon.endswith(LF.encode())

    def test_t11_praeimage_ist_exakt_canon(self) -> None:
        for name in ("V1", "V2", "V3", "V5"):
            v = _v(name)
            canon = canonical_revision_bytes(v.revision())
            assert hashlib.sha256(canon).hexdigest() == revision_sha256(v.revision())
            assert hashlib.sha256(canon + LF.encode()).hexdigest() != v.sha256
            assert hashlib.sha256(b"transcript_revision" + canon).hexdigest() != v.sha256


class TestT12BisT18RundtripUndB2:
    def test_t12_to_json_ist_anzeige_und_nicht_canon(self) -> None:
        """`to_json` ist Anzeige und nicht bytegleich zu CANON.

        Seit dem Korrekturkandidaten fuehrt die Anzeige **keine**
        Normalisierungsdiagnostik mehr mit und liest kein Profilregister; die
        feste Schluesselgestalt misst
        `TestB3a7ProfilgrenzeUndAnzeige`. Hier bleibt gemessen, was der Name
        sagt: Anzeige ist nicht CANON.
        """
        rev = _bestandsrevision()
        anzeige = rev.to_json()
        canon = canonical_revision_bytes(rev)
        assert isinstance(anzeige, dict)
        assert (
            json.dumps(anzeige, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
                "utf-8"
            )
            != canon
        )
        assert "n_chars" in anzeige and "n_chars" not in canon.decode("utf-8")
        assert anzeige["sha256"] == revision_sha256(rev)

    def test_t13_reconstruct_erhaelt_alle_identitaetsbildenden_felder(self) -> None:
        v = _v("V3")
        zurueck = reconstruct_revision(v.canon())
        assert zurueck.profile_id == v.profile_id
        assert zurueck.projection_version == v.projection_version
        assert zurueck.text == v.fulltext
        for a, b in zip(zurueck.segments, v.segments, strict=True):
            assert (a.index, a.start_ms, a.end_ms, a.speaker, a.language, a.text) == (
                b.index,
                b.start_ms,
                b.end_ms,
                b.speaker,
                b.language,
                b.text,
            )

    def test_t14_roundtrip_ist_bytegleich(self) -> None:
        for name in ("V1", "V2", "V3", "V5"):
            v = _v(name)
            assert canonical_revision_bytes(reconstruct_revision(v.canon())) == v.canon()

    def test_t15_n6_erreicht_den_hashvergleich_nicht_n7_erst_danach(self) -> None:
        """Die Stufenordnung, scharf gemessen.

        N6 wird mit dem Digest der logischen Revision vorgelegt — also mit
        dem Wert, den ein Aufrufer erwartet. Beide Stufen waeren damit
        verletzt: die Bytes sind nicht kanonisch (Stufe 6) UND der Digest
        passt nicht zu ihnen (Stufe 7). Traegt die Ordnung, faellt
        ausschliesslich Stufe 6. Zoege jemand den Hashvergleich vor, kaeme
        hier RevisionHashMismatch — und der Test faellt.
        """
        with pytest.raises(RevisionReconstructionMismatch) as exc:
            verify_revision(bytes.fromhex(N6_HEX), _v("V2").sha256)
        assert not isinstance(exc.value, RevisionHashMismatch)

        # Auch mit dem Digest der N6-Bytes selbst bleibt es Stufe 6.
        with pytest.raises(RevisionReconstructionMismatch):
            verify_revision(bytes.fromhex(N6_HEX), N6_SHA256)

        # N7 erreicht Stufe 7 erst nach bestandener Reserialisierung.
        with pytest.raises(RevisionHashMismatch) as exc7:
            verify_revision(_v("V2").canon(), N7_FALSCHER_DIGEST)
        assert not isinstance(exc7.value, RevisionReconstructionMismatch)

    def test_t16_jede_der_zehn_klassen_ist_eigener_typ(self) -> None:
        klassen = [
            InvalidRevisionSchema,
            InvalidRevisionType,
            InvalidRevisionNormalization,
            InvalidSegmentOrder,
            InvalidProjectionVersion,
            UnknownProjectionVersion,
            ProjectionDefinitionUnavailable,
            ProjectionMismatch,
            RevisionReconstructionMismatch,
            RevisionHashMismatch,
        ]
        assert len(set(klassen)) == 10
        for k in klassen:
            assert issubclass(k, RevisionValidationError)
        assert issubclass(RevisionValidationError, ValueError)

    def test_t17_die_vier_positivvektoren_bauen_einen_revisionanchor(self) -> None:
        key = ArtifactKey(
            scope=Scope.RECORD, scope_id="SANDBOX-001", kind="transcript.revision", instance_id=None
        )
        for name in ("V1", "V2", "V3", "V5"):
            v = _v(name)
            anker = RevisionAnchor(
                artifact_key=key,
                revision_sha256=revision_sha256(v.revision()),
                projection_version=PROJECTION_VERSION,
            )
            assert anker.revision_sha256 == v.sha256
            assert anker.projection_version == "seg-join-lf.v1"
            assert RevisionAnchor.from_mapping(anker.to_mapping()) == anker

    def test_t18_artifactkey_und_revisionanchor_bleiben_unveraendert(self) -> None:
        key = ArtifactKey(
            scope=Scope.RECORD, scope_id="R1", kind="transcript.revision", instance_id=None
        )
        assert ArtifactKey.FIELDS == ("scope", "scope_id", "kind", "instance_id")
        assert RevisionAnchor.FIELDS == ("artifact_key", "revision_sha256", "projection_version")
        anker = RevisionAnchor(
            artifact_key=key, revision_sha256=_v("V2").sha256, projection_version=PROJECTION_VERSION
        )
        anders = RevisionAnchor(
            artifact_key=key, revision_sha256=_v("V1").sha256, projection_version=PROJECTION_VERSION
        )
        assert anders != anker
        assert anker.revision_sha256 == _v("V2").sha256


class TestT19BisT22TranscriptRevision:
    def test_t19_from_segments_nutzt_die_katalogprojektion_ohne_freien_joiner(self) -> None:
        """from_segments ist eine KONSTRUKTIONSHILFE, kein Beleg des S12-Tors."""
        import inspect

        sig = inspect.signature(TranscriptRevision.from_segments)
        assert "joiner" not in sig.parameters
        assert "projection_version" in sig.parameters
        rev = TranscriptRevision.from_segments(
            _v("V2").segments, projection_version=PROJECTION_VERSION, profile_id=_v("V2").profile_id
        )
        assert rev.text == _v("V2").fulltext
        assert canonical_revision_bytes(rev) == _v("V2").canon()

    def test_t20_revise_traegt_projection_version_zeichengenau(self) -> None:
        v = _v("V2").revision()
        neu = v.revise(new_text=v.text, note="durchgesehen")
        assert neu.projection_version == v.projection_version
        assert neu.projection_version == "seg-join-lf.v1"
        assert neu.text == v.text

    def test_t21_diagnostik_und_provenienz_beeinflussen_den_hash_nicht(self) -> None:
        v = _v("V2")
        a = _bestandsrevision()
        b = TranscriptRevision(
            text=v.fulltext,
            projection_version=v.projection_version,
            profile_id=a.profile_id,
            segments=v.segments,
            source_kind="asr",
            source_sha256="f" * 64,
            languages=("deu",),
            parent_sha256="e" * 64,
            note="andere Provenienz",
        )
        assert revision_sha256(a) == revision_sha256(b)
        assert canonical_revision_bytes(a) == canonical_revision_bytes(b)
        assert a.text_sha256 not in canonical_revision_bytes(a).decode("utf-8")
        assert a.structure_sha256 not in canonical_revision_bytes(a).decode("utf-8")

    def test_t22_verschiedene_felder_erzeugen_verschiedene_bytes(self) -> None:
        v1, v2 = _v("V1"), _v("V2")
        assert canonical_revision_bytes(v1.revision()) != canonical_revision_bytes(v2.revision())
        key = ArtifactKey(
            scope=Scope.RECORD, scope_id="R1", kind="transcript.revision", instance_id=None
        )
        alt = RevisionAnchor(
            artifact_key=key, revision_sha256=v1.sha256, projection_version=PROJECTION_VERSION
        )
        vorher = alt.to_mapping()
        RevisionAnchor(
            artifact_key=key, revision_sha256=v2.sha256, projection_version=PROJECTION_VERSION
        )
        assert alt.to_mapping() == vorher


class TestT23SrtDraftgrenze:
    def _srt(self, tmp_path, inhalt: str):
        from ohpipe.adapters.input.srt import load_srt

        p = tmp_path / "t.srt"
        p.write_text(inhalt, encoding="utf-8")
        return load_srt(p)

    MIT_SPRECHER = "1" + LF + "00:00:00,000 --> 00:00:01,500" + LF + "INTERVIEWER: Guten Tag." + LF
    OHNE_SPRECHER = "1" + LF + "00:00:00,000 --> 00:00:01,500" + LF + "Guten Tag." + LF

    def test_load_srt_erfindet_weder_speaker_noch_language(self, tmp_path) -> None:
        mit = self._srt(tmp_path, self.MIT_SPRECHER)
        assert mit.projection_version == PROJECTION_VERSION
        assert mit.segments[0].speaker == "INTERVIEWER"
        assert mit.segments[0].language is None
        assert mit.is_identity_draft is True

    def test_ohne_sprecherpraefix_bleibt_speaker_none(self, tmp_path) -> None:
        ohne = self._srt(tmp_path, self.OHNE_SPRECHER)
        assert ohne.segments[0].speaker is None
        assert ohne.segments[0].language is None
        assert ohne.is_identity_draft is True

    def test_der_draft_mit_sprecher_faellt_an_language(self, tmp_path) -> None:
        mit = self._srt(tmp_path, self.MIT_SPRECHER)
        for zugriff in (
            lambda: mit.revision_sha256,
            lambda: mit.sha256,
            lambda: canonical_revision_bytes(mit),
            lambda: revision_sha256(mit),
        ):
            with pytest.raises(InvalidRevisionType) as exc:
                zugriff()
            assert "language" in str(exc.value)
            assert "index 0" in str(exc.value) or "Segment 0" in str(exc.value)

    def test_der_draft_ohne_sprecher_faellt_bereits_an_speaker(self, tmp_path) -> None:
        ohne = self._srt(tmp_path, self.OHNE_SPRECHER)
        with pytest.raises(InvalidRevisionType) as exc:
            canonical_revision_bytes(ohne)
        assert "speaker" in str(exc.value)

    def test_im_draft_taucht_kein_ersatzwert_auf(self, tmp_path) -> None:
        for inhalt in (self.MIT_SPRECHER, self.OHNE_SPRECHER):
            draft = self._srt(tmp_path, inhalt)
            for s in draft.segments:
                assert s.language is None
                assert s.speaker != "unknown"
                assert s.speaker != ""
            assert draft.languages == ()
            with pytest.raises(InvalidRevisionType):
                draft.to_json()

    def test_gegenprobe_vervollstaendigte_drafts_gehen_durch(self, tmp_path) -> None:
        for inhalt in (self.MIT_SPRECHER, self.OHNE_SPRECHER):
            draft = self._srt(tmp_path, inhalt)
            voll = tuple(
                Segment(
                    index=s.index,
                    start_ms=s.start_ms,
                    end_ms=s.end_ms,
                    text=s.text,
                    speaker=s.speaker or "S1",
                    language="deu",
                )
                for s in draft.segments
            )
            fertig = TranscriptRevision(
                text=project_segments(voll, PROJECTION_VERSION),
                projection_version=PROJECTION_VERSION,
                profile_id=draft.profile_id,
                segments=voll,
            )
            assert fertig.is_identity_draft is False
            assert len(revision_sha256(fertig)) == 64


class TestT24ZweiHerkuenfte:
    def test_from_segments_belegt_das_tor_nicht(self) -> None:
        """Volltext und Segmente stammen hier aus DERSELBEN Quelle."""
        rev = TranscriptRevision.from_segments(
            _v("V2").segments, projection_version=PROJECTION_VERSION, profile_id=_v("V2").profile_id
        )
        assert rev.text == project_segments(rev.segments, PROJECTION_VERSION)
        assert "Konstruktionshilfe" in (TranscriptRevision.from_segments.__doc__ or "")

    def test_getrennt_vorgelegte_seiten_tragen_die_gesunde_gegenprobe(self) -> None:
        v = _v("V2")
        gleich = TranscriptRevision(
            text=v.fulltext,
            projection_version=v.projection_version,
            profile_id=v.profile_id,
            segments=v.segments,
        )
        validate_revision(gleich)
        assert canonical_revision_bytes(gleich) == v.canon()

    def test_eine_minimale_volltextabweichung_faellt_projection_mismatch(self) -> None:
        v = _v("V2")
        abweichend = TranscriptRevision(
            text=v.fulltext.replace(LF, " "),
            projection_version=v.projection_version,
            profile_id=v.profile_id,
            segments=v.segments,
        )
        with pytest.raises(ProjectionMismatch):
            validate_revision(abweichend)
        assert abweichend.text == v.fulltext.replace(LF, " ")


# --- Korrekturschliessungen B3a-1 bis B3a-9 ------------------------------
#
# Die folgenden Knoten schliessen die PRT-Befunde des abgelehnten Kandidaten
# 14640232 (Befundvermerk 79d01ae1). Sie sind der vollstaendige Zuwachs K
# gegenueber jenem Kandidaten; kein bestehender Knoten wurde geloescht oder
# umbenannt.

SURROGAT = chr(0xD800)


def _ein_segment(text: str, *, speaker: str = "S1", language: str = "deu") -> tuple[Segment, ...]:
    return (
        Segment(index=0, start_ms=0, end_ms=1000, text=text, speaker=speaker, language=language),
    )


def _eine_revision(
    text: str, *, profile_id: str = "dinoh-lux", **abw: object
) -> TranscriptRevision:
    daten: dict[str, object] = {
        "text": text,
        "projection_version": PROJECTION_VERSION,
        "profile_id": profile_id,
        "segments": _ein_segment(text),
    }
    daten.update(abw)
    return TranscriptRevision(**daten)  # type: ignore[arg-type]


class TestB3a1NfcFuerJedeZeichenkette:
    """B3a-1 · NFC gilt fuer JEDE Zeichenkette im Objekt, nicht nur fuer Text.

    Blieben `profile_id` und `speaker` ungeprueft, erzeugten zwei zeichen-
    verschiedene, aber kanonisch aequivalente Eingaben zwei verschiedene und
    beide akzeptierte Revisionsidentitaeten. Genau das schliesst die
    NFC-Zusage aus (Teil P, P4; Teil S, S5).
    """

    def test_b3a1_nicht_nfc_profile_id_faellt_als_normalisierung(self) -> None:
        zerlegt = "din" + "o" + KOMBI_TREMA + "h-lux"
        assert not unicodedata.is_normalized("NFC", zerlegt)
        with pytest.raises(InvalidRevisionNormalization) as exc:
            canonical_revision_bytes(_eine_revision("a", profile_id=zerlegt))
        assert "profile_id" in str(exc.value)
        assert "NFC" in str(exc.value)

    def test_b3a1_gegenprobe_komponierte_profile_id_geht_durch(self) -> None:
        komponiert = unicodedata.normalize("NFC", "din" + "o" + KOMBI_TREMA + "h-lux")
        assert unicodedata.is_normalized("NFC", komponiert)
        canon = canonical_revision_bytes(_eine_revision("a", profile_id=komponiert))
        assert komponiert.encode("utf-8") in canon

    def test_b3a1_nicht_nfc_speaker_faellt_als_normalisierung(self) -> None:
        zerlegt = "S" + "o" + KOMBI_TREMA
        assert not unicodedata.is_normalized("NFC", zerlegt)
        rev = TranscriptRevision(
            text="a",
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=_ein_segment("a", speaker=zerlegt),
        )
        with pytest.raises(InvalidRevisionNormalization) as exc:
            canonical_revision_bytes(rev)
        assert "speaker" in str(exc.value)
        assert "NFC" in str(exc.value)

    def test_b3a1_gegenprobe_komponierter_speaker_geht_durch(self) -> None:
        komponiert = unicodedata.normalize("NFC", "S" + "o" + KOMBI_TREMA)
        rev = TranscriptRevision(
            text="a",
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=_ein_segment("a", speaker=komponiert),
        )
        assert komponiert.encode("utf-8") in canonical_revision_bytes(rev)

    def test_b3a1_zwei_kanonisch_gleiche_eingaben_erzeugen_keine_zwei_identitaeten(self) -> None:
        """Der eigentliche Schaden: zwei Adressen fuer dieselbe Fassung."""
        zerlegt = "S" + "o" + KOMBI_TREMA
        komponiert = unicodedata.normalize("NFC", zerlegt)
        assert zerlegt != komponiert
        gesund = TranscriptRevision(
            text="a",
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=_ein_segment("a", speaker=komponiert),
        )
        kaputt = TranscriptRevision(
            text="a",
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=_ein_segment("a", speaker=zerlegt),
        )
        assert revision_sha256(gesund)
        with pytest.raises(InvalidRevisionNormalization):
            revision_sha256(kaputt)


class TestB3a2NegativerIndexIstReihenfolgefehler:
    """B3a-2 · `index < 0` ist ein Reihenfolgefehler, kein Typbruch.

    S13 ordnet `InvalidSegmentOrder` ausdruecklich auch dem **negativen**
    Index zu. Ein Konsument, der auf diese Klasse filtert, saehe den Fall
    sonst nicht.
    """

    def test_b3a2_index_minus_eins_faellt_als_segmentordnung(self) -> None:
        rev = TranscriptRevision(
            text="a",
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=(
                Segment(index=-1, start_ms=0, end_ms=1000, text="a", speaker="S1", language="deu"),
            ),
        )
        with pytest.raises(InvalidSegmentOrder) as exc:
            canonical_revision_bytes(rev)
        assert not isinstance(exc.value, InvalidRevisionType)
        assert "index" in str(exc.value)
        assert "-1" in str(exc.value)
        assert "Segment" in str(exc.value)

    def test_b3a2_gegenprobe_index_null_geht_durch(self) -> None:
        assert canonical_revision_bytes(_eine_revision("a"))

    def test_b3a2_index_bleibt_typgeprueft(self) -> None:
        """Die Typpruefung bleibt: ein `bool` oder `float` ist kein Index."""
        for falsch in (True, 1.0, None, "0"):
            rev = TranscriptRevision(
                text="a",
                projection_version=PROJECTION_VERSION,
                profile_id="dinoh-lux",
                segments=(
                    Segment(
                        index=falsch,  # type: ignore[arg-type]
                        start_ms=0,
                        end_ms=1000,
                        text="a",
                        speaker="S1",
                        language="deu",
                    ),
                ),
            )
            with pytest.raises(InvalidRevisionType):
                canonical_revision_bytes(rev)

    def test_b3a2_negative_zeitwerte_bleiben_typbruch(self) -> None:
        """Nur `index` wandert; `start_ms` und `end_ms` bleiben `InvalidRevisionType`."""
        rev = TranscriptRevision(
            text="a",
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=(
                Segment(index=0, start_ms=-1, end_ms=1000, text="a", speaker="S1", language="deu"),
            ),
        )
        with pytest.raises(InvalidRevisionType):
            canonical_revision_bytes(rev)

    def test_b3a2_doppelte_und_lueckenhafte_indizes_bleiben_segmentordnung(self) -> None:
        segs = (
            Segment(index=0, start_ms=0, end_ms=10, text="a", speaker="S1", language="deu"),
            Segment(index=0, start_ms=10, end_ms=20, text="b", speaker="S2", language="deu"),
        )
        rev = TranscriptRevision(
            text="a" + LF + "b",
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=segs,
        )
        with pytest.raises(InvalidSegmentOrder):
            canonical_revision_bytes(rev)


class TestB3a3ExakteTypenFuerVUndDomain:
    """B3a-3 · `v = true` und `v = 1.0` sind Typbrueche an Stufe 3.

    In Python gilt `True == 1` und `1.0 == 1`. Ein blosser Gleichheits-
    vergleich liesse beide Formen die Schemastufe passieren; sie fielen erst
    an Stufe 6 und traegen dort den falschen Namen
    `RevisionReconstructionMismatch`.
    """

    def _canon_mit(self, **abw: object) -> bytes:
        objekt = json.loads(_v("V1").canon().decode("utf-8"))
        objekt.update(abw)
        return json.dumps(objekt, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )

    @pytest.mark.parametrize(
        ("abweichung", "klasse"),
        [
            ({"v": True}, InvalidRevisionType),
            ({"v": 1.0}, InvalidRevisionType),
            ({"domain": 7}, InvalidRevisionType),
            ({"v": 2}, InvalidRevisionSchema),
            ({"domain": "andere_domain"}, InvalidRevisionSchema),
        ],
        ids=["v-true", "v-1.0", "domain-7", "v-2", "domain-falsche-zeichenkette"],
    )
    def test_b3a3_v_und_domain_fallen_an_stufe_drei(
        self, abweichung: dict[str, object], klasse: type[Exception]
    ) -> None:
        with pytest.raises(klasse) as exc:
            reconstruct_revision(self._canon_mit(**abweichung))
        assert type(exc.value) is klasse
        assert not isinstance(exc.value, RevisionReconstructionMismatch | RevisionHashMismatch)
        feld = next(iter(abweichung))
        assert feld in str(exc.value)

    def test_b3a3_gegenprobe_gesundes_schema_geht_durch(self) -> None:
        zurueck = reconstruct_revision(_v("V1").canon())
        assert canonical_revision_bytes(zurueck) == _v("V1").canon()

    def test_b3a3_keiner_dieser_faelle_erreicht_stufe_sechs(self) -> None:
        """Die Stufenordnung, negativ gemessen: Stufe 6 bleibt unerreicht."""
        for abw in ({"v": True}, {"v": 1.0}, {"v": 2}, {"domain": 7}, {"domain": "x"}):
            with pytest.raises(RevisionValidationError) as exc:
                reconstruct_revision(self._canon_mit(**abw))
            assert not isinstance(exc.value, RevisionReconstructionMismatch)
            assert not isinstance(exc.value, RevisionHashMismatch)


class TestB3a4ZeichengenaueAnkersicht:
    """B3a-4 · Der anker-sichtbare Text ist der zeichengenaue Revisionstext.

    Frueher ergaenzte `normalized` ein Abschluss-LF und entfernte
    rechtsseitigen Whitespace; `slice` las aus dieser zweiten Textgestalt und
    `Anchor.create` konnte die volle Spanne nicht mehr adressieren. Damit
    wichen CANON-`fulltext` und Ankersicht voneinander ab.
    """

    FAELLE = {"A-abc-ohne-schluss-lf": "abc", "B-folgender-whitespace": "  Rand  "}

    #: Ein im Bestand REGISTRIERTES Profil. Diese Klasse misst allein die
    #: Textgestalt; die Profilfrage ist Gegenstand von B3a-7 und darf hier
    #: nicht als Ursache dazwischentreten.
    PROFIL = "nfc-strict-v1"

    def _rev(self, text: str) -> TranscriptRevision:
        return _eine_revision(text, profile_id=self.PROFIL)

    @pytest.mark.parametrize("text", list(FAELLE.values()), ids=list(FAELLE))
    def test_b3a4_normalized_ist_zeichengleich_text(self, text: str) -> None:
        rev = self._rev(text)
        assert rev.normalized == rev.text
        assert rev.normalized == text
        assert not rev.normalized.endswith(LF) or text.endswith(LF)

    @pytest.mark.parametrize("text", list(FAELLE.values()), ids=list(FAELLE))
    def test_b3a4_slice_trifft_die_volle_spanne(self, text: str) -> None:
        rev = self._rev(text)
        assert rev.slice(0, len(rev.text)) == rev.text
        assert rev.slice(0, 1) == text[0]

    @pytest.mark.parametrize("text", list(FAELLE.values()), ids=list(FAELLE))
    def test_b3a4_anchor_create_traegt_die_volle_zeichenfolge(self, text: str) -> None:
        from ohpipe.domain.anchor import Anchor

        rev = self._rev(text)
        anker = Anchor.create(rev, 0, len(text))
        assert anker.quote == text
        assert (anker.start, anker.end) == (0, len(text))
        assert anker.transcript_sha256 == revision_sha256(rev)

    @pytest.mark.parametrize("text", list(FAELLE.values()), ids=list(FAELLE))
    def test_b3a4_canon_fulltext_ist_derselbe_text(self, text: str) -> None:
        rev = self._rev(text)
        wieder = reconstruct_revision(canonical_revision_bytes(rev))
        assert wieder.text == text
        assert wieder.normalized == text

    def test_b3a4_cr_und_nicht_nfc_fallen_weiterhin_vor_der_byteerzeugung(self) -> None:
        """Die zeichengenaue Sicht repariert nichts — sie zeigt nur nicht mehr um."""
        with pytest.raises(InvalidRevisionNormalization):
            canonical_revision_bytes(self._rev("a" + CR + LF + "b"))
        with pytest.raises(InvalidRevisionNormalization):
            canonical_revision_bytes(self._rev("o" + KOMBI_TREMA))

    def test_b3a4_der_anker_pfad_liest_kein_profilregister(self) -> None:
        from ohpipe.domain.anchor import Anchor

        rev = _eine_revision("abc", profile_id="dinoh-lux")
        assert Anchor.create(rev, 0, 3).quote == "abc"


class TestB3a5VollstaendigeDraftgrenze:
    """B3a-5 · `is_identity_draft` deckt alle neun S2-Pflichtstellen.

    Vier von neun meldeten frueher faelschlich `False`. Die Identitaet fiel
    zwar in jedem Fall fail-closed — es entstand kein falscher Hash —, aber
    die als Vorpruefung angebotene Eigenschaft trug ihre Zusage nicht.
    """

    def _mit(self, **abw: object) -> TranscriptRevision:
        daten: dict[str, object] = {
            "text": "a",
            "projection_version": PROJECTION_VERSION,
            "profile_id": "dinoh-lux",
            "segments": _ein_segment("a"),
        }
        daten.update(abw)
        return TranscriptRevision(**daten)  # type: ignore[arg-type]

    def _segment_ohne(self, feld: str) -> TranscriptRevision:
        werte: dict[str, object] = {
            "index": 0,
            "start_ms": 0,
            "end_ms": 1000,
            "text": "a",
            "speaker": "S1",
            "language": "deu",
        }
        werte[feld] = None
        return _eine_revision("a", segments=(Segment(**werte),))  # type: ignore[arg-type]

    def _fall(self, name: str) -> TranscriptRevision:
        if name == "1-leere-segmentliste":
            return self._mit(segments=())
        if name == "2-projection_version":
            return self._mit(projection_version=None)
        if name == "3-profile_id":
            return self._mit(profile_id=None)
        if name == "4-top-level-text":
            return self._mit(text=None)
        return self._segment_ohne(name.split("-", 1)[1])

    NEUN = [
        "1-leere-segmentliste",
        "2-projection_version",
        "3-profile_id",
        "4-top-level-text",
        "5-start_ms",
        "6-end_ms",
        "7-speaker",
        "8-language",
        "9-text",
    ]

    @pytest.mark.parametrize("fall", NEUN, ids=NEUN)
    def test_b3a5_jede_der_neun_pflichtstellen_meldet_draft(self, fall: str) -> None:
        assert self._fall(fall).is_identity_draft is True

    @pytest.mark.parametrize("fall", NEUN, ids=NEUN)
    def test_b3a5_kein_draft_erhaelt_identitaet(self, fall: str) -> None:
        rev = self._fall(fall)
        with pytest.raises(RevisionValidationError):
            _ = rev.revision_sha256
        with pytest.raises(RevisionValidationError):
            canonical_revision_bytes(rev)
        with pytest.raises(RevisionValidationError):
            _ = rev.sha256

    def test_b3a5_gegenprobe_die_vollstaendige_fassung_ist_kein_draft(self) -> None:
        rev = _eine_revision("a")
        assert rev.is_identity_draft is False
        assert canonical_revision_bytes(rev)
        assert len(rev.revision_sha256) == 64

    def test_b3a5_ein_vorhandener_regelwidriger_wert_ist_kein_draft(self) -> None:
        """Ein falscher Wert wird nicht durch die Draftanzeige gesundgeschrieben."""
        rev = _eine_revision("a", segments=_ein_segment("a", language="deutsch"))
        assert rev.is_identity_draft is False
        with pytest.raises(InvalidRevisionType):
            canonical_revision_bytes(rev)

    def test_b3a5_kein_draft_erhaelt_einen_revisionanchor(self) -> None:
        rev = self._fall("2-projection_version")
        with pytest.raises(RevisionValidationError):
            RevisionAnchor(
                artifact_key=ArtifactKey(
                    scope=Scope.RECORD, scope_id="R1", kind="transcript.revision", instance_id=None
                ),
                revision_sha256=rev.sha256,
                projection_version=PROJECTION_VERSION,
            )


class TestB3a6SurrogateImFehlervertrag:
    """B3a-6 · Ein isoliertes Surrogat verlaesst den Kern nicht als Fremdtyp.

    `json.loads` nimmt die Escapeform an; die Reserialisierung warf frueher
    einen rohen `UnicodeEncodeError`. Ein Aufrufer, der auf
    `RevisionValidationError` faengt, liess diesen Eingang unbehandelt durch.

    Alle Faelle hier sind **konsistente** Revisionen: der Volltext ist die
    Projektion der Segmente. Sonst faellt vorher das Konsistenztor, und der
    Test belegte nicht, was sein Name sagt.
    """

    def _canon_mit_surrogat(self) -> bytes:
        """V1-CANON mit `\\ud800` in fulltext UND im Segment-text — konsistent."""
        roh = _v("V1").canon().decode("utf-8")
        ersetzt = roh.replace('"Guten Tag."', '"\\ud800"')
        assert ersetzt.count("\\ud800") == 2, ersetzt
        return ersetzt.encode("utf-8")

    def test_b3a6_direktes_surrogat_faellt_im_vertrag(self) -> None:
        rev = TranscriptRevision(
            text=SURROGAT,
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=_ein_segment(SURROGAT),
        )
        with pytest.raises(InvalidRevisionNormalization) as exc:
            canonical_revision_bytes(rev)
        assert "text" in str(exc.value)
        assert "Surrogat" in str(exc.value)
        assert "Stufe 3" in str(exc.value)

    def test_b3a6_surrogat_allein_im_fulltext_faellt_vor_dem_konsistenztor(self) -> None:
        """Der Volltext wird VOR dem Tor auf Normalisierung geprueft."""
        rev = TranscriptRevision(
            text=SURROGAT,
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=_ein_segment("a"),
        )
        with pytest.raises(InvalidRevisionNormalization) as exc:
            canonical_revision_bytes(rev)
        assert "fulltext" in str(exc.value)
        assert not isinstance(exc.value, ProjectionMismatch)

    def test_b3a6_direktes_surrogat_im_speaker_faellt_im_vertrag(self) -> None:
        rev = TranscriptRevision(
            text="a",
            projection_version=PROJECTION_VERSION,
            profile_id="dinoh-lux",
            segments=_ein_segment("a", speaker=SURROGAT),
        )
        with pytest.raises(InvalidRevisionNormalization) as exc:
            canonical_revision_bytes(rev)
        assert "speaker" in str(exc.value)
        assert "Surrogat" in str(exc.value)

    def test_b3a6_direktes_surrogat_in_der_profile_id_faellt_im_vertrag(self) -> None:
        with pytest.raises(InvalidRevisionNormalization) as exc:
            canonical_revision_bytes(_eine_revision("a", profile_id="p" + SURROGAT))
        assert "profile_id" in str(exc.value)

    def test_b3a6_json_escapeform_faellt_im_vertrag(self) -> None:
        canon = self._canon_mit_surrogat()
        with pytest.raises(RevisionValidationError) as exc:
            reconstruct_revision(canon)
        assert isinstance(exc.value, InvalidRevisionNormalization)
        assert "Surrogat" in str(exc.value)
        assert not isinstance(exc.value, RevisionReconstructionMismatch)

    def test_b3a6_kein_roher_kodierfehler_verlaesst_den_kern(self) -> None:
        """Die eigentliche Zusage: die Fehleroberflaeche ist an dieser Stelle total."""
        canon = self._canon_mit_surrogat()
        try:
            reconstruct_revision(canon)
        except RevisionValidationError:
            pass
        except (UnicodeEncodeError, UnicodeDecodeError) as roh:  # pragma: no cover
            pytest.fail(f"roher Kodierfehler verlaesst den Kern: {roh!r}")
        else:  # pragma: no cover
            pytest.fail("die Surrogatform ging durch")

    def test_b3a6_gegenprobe_nicht_bmp_ohne_surrogat_geht_durch(self) -> None:
        emoji = chr(0x1F600)
        canon = canonical_revision_bytes(_eine_revision(emoji))
        assert emoji.encode("utf-8") in canon
        assert (chr(92) + "u").encode() not in canon


class TestB3a7ProfilgrenzeUndAnzeige:
    """B3a-7 · Eine nach Teil S gueltige Revision ist voll nutzbar.

    Der normative Vektor V1 traegt `profile_id` ``dinoh-lux`` — eine Kennung
    ohne entschiedene Transformationssemantik. Frueher fielen `to_json`,
    `normalized`, `slice` und `profile` saemtlich an ihr, obwohl Teil S fuer
    `profile_id` nur Nichtleere und NFC verlangt. Die Regieentscheidung des
    gesiegelten Korrekturauftrags trennt Identitaet und Anzeige von der
    ausdruecklichen Diagnoseprofil-Aufloesung.
    """

    TO_JSON_SCHLUESSEL = [
        "sha256",
        "projection_version",
        "profile_id",
        "source_kind",
        "source_sha256",
        "languages",
        "parent_sha256",
        "note",
        "n_segments",
        "n_chars",
    ]

    def test_b3a7_v1_mit_dinoh_lux_kann_alle_sechs_wege(self) -> None:
        from ohpipe.domain.anchor import Anchor

        v = _v("V1")
        rev = reconstruct_revision(v.canon())
        assert rev.profile_id == "dinoh-lux"
        assert rev.revision_sha256 == v.sha256
        assert canonical_revision_bytes(rev) == v.canon()
        assert rev.normalized == rev.text
        assert rev.slice(0, len(rev.text)) == rev.text
        assert rev.slice(0, 5) == rev.text[:5]
        assert rev.to_json()["sha256"] == v.sha256
        assert Anchor.create(rev, 0, 5).quote == rev.text[:5]

    @pytest.mark.parametrize(
        "profil", ["dinoh-lux", "nfc-strict-v1"], ids=["dinoh-lux", "nfc-strict-v1"]
    )
    def test_b3a7_to_json_hat_dieselbe_feste_gestalt(self, profil: str) -> None:
        anzeige = _eine_revision("abc", profile_id=profil).to_json()
        assert list(anzeige) == self.TO_JSON_SCHLUESSEL
        assert anzeige["profile_id"] == profil
        assert anzeige["languages"] == []
        assert anzeige["n_segments"] == 1
        assert anzeige["n_chars"] == 3
        assert len(anzeige["sha256"]) == 64

    @pytest.mark.parametrize(
        "profil", ["dinoh-lux", "nfc-strict-v1"], ids=["dinoh-lux", "nfc-strict-v1"]
    )
    def test_b3a7_to_json_fuehrt_keine_diagnostikschluessel(self, profil: str) -> None:
        anzeige = _eine_revision("abc", profile_id=profil).to_json()
        assert "text_sha256" not in anzeige
        assert "structure_sha256" not in anzeige
        assert None not in {anzeige["sha256"], anzeige["profile_id"], anzeige["projection_version"]}

    def test_b3a7_optionale_provenienz_darf_none_bleiben(self) -> None:
        anzeige = _eine_revision("abc").to_json()
        assert anzeige["source_sha256"] is None
        assert anzeige["parent_sha256"] is None

    def test_b3a7_nur_der_ausdrueckliche_diagnoseprofil_zugriff_faellt(self) -> None:
        """Der erwartete Diagnoseausgang, getrennt von der Kernoberflaeche."""
        rev = _eine_revision("abc", profile_id="dinoh-lux")
        for zugriff in ("profile", "text_sha256", "structure_sha256"):
            with pytest.raises(ValueError, match="Unbekanntes Normalisierungsprofil"):
                getattr(rev, zugriff)
        with pytest.raises(ValueError, match="Unbekanntes Normalisierungsprofil"):
            rev._compute_sha()
        assert rev.revision_sha256
        assert rev.to_json()["profile_id"] == "dinoh-lux"

    def test_b3a7_ein_draft_erhaelt_keine_teilweise_anzeige(self) -> None:
        rev = _eine_revision("a", projection_version=None)
        with pytest.raises(RevisionValidationError):
            rev.to_json()

    def test_b3a7_dinoh_lux_wird_nicht_als_profil_registriert(self) -> None:
        from ohpipe.domain.hashing import PROFILES

        assert "dinoh-lux" not in PROFILES
        assert sorted(PROFILES) == ["nfc-strict-v1"]

    def test_b3a7_die_normativen_vektoren_tragen_unveraendert_dinoh_lux(self) -> None:
        for name in ("V1", "V2", "V3", "V5"):
            assert _v(name).profile_id == "dinoh-lux"
            assert canonical_revision_bytes(_v(name).revision()) == _v(name).canon()


class TestB3a8UndB3a9Produktnorm:
    """B3a-8 und B3a-9 · Die Produktnorm sagt, was der Kern tut.

    Die Datei behauptet in ihrem Kopf, Teil P und Teil S ohne neue Wahl
    wiederzugeben. Eine Verengung der NFC-Reichweite waere eine neue Wahl
    gewesen und haette die Luecke der Umsetzung normativ zugedeckt.
    """

    @staticmethod
    def _norm() -> str:
        from pathlib import Path

        pfad = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "adr"
            / "0028B-S-revisionsserialisierung-und-P-projektionsvertrag.md"
        )
        return pfad.read_text(encoding="utf-8")

    @staticmethod
    def _abschnitt(text: str, ueberschrift: str) -> str:
        start = text.index(ueberschrift)
        rest = text[start + len(ueberschrift) :]
        ende = rest.find(chr(10) + "## ")
        return rest if ende < 0 else rest[:ende]

    def test_b3a8_p4_nennt_jede_zeichenkette(self) -> None:
        p4 = self._abschnitt(self._norm(), "### P4 ")
        assert "JEDE Zeichenkette im Objekt" in p4
        assert "profile_id" in p4 and "speaker" in p4
        assert "Jeder text und der fulltext sind NFC-normalisiert." not in p4

    def test_b3a8_s5_nennt_jede_zeichenkette(self) -> None:
        s5 = self._abschnitt(self._norm(), "### S5 ")
        assert "JEDE Zeichenkette im Objekt" in s5
        assert "profile_id" in s5 and "speaker" in s5

    def test_b3a8_die_ascii_syntax_ist_spezialisierung_keine_ausnahme(self) -> None:
        norm = self._norm()
        assert "SPEZIALISIERUNG dieser Regel, keine Ausnahme" in norm
        assert "strenger spezifiziert, nicht ausgenommen" in norm

    def test_b3a8_profile_id_und_speaker_stehen_im_objektschema_mit_nfc(self) -> None:
        s2 = self._abschnitt(self._norm(), "### S2 ")
        assert "profile_id          Zeichenkette, nichtleer, NFC" in s2
        assert "speaker     Zeichenkette, nichtleer, NFC" in s2

    def test_b3a9_ein_eigener_draftabschnitt_ist_vorhanden(self) -> None:
        norm = self._norm()
        assert "## Draftgrenze" in norm
        draft = self._abschnitt(norm, "## Draftgrenze")
        assert "is_identity_draft" in draft

    def test_b3a9_alle_neun_draft_pflichtstellen_sind_genannt(self) -> None:
        draft = self._abschnitt(self._norm(), "## Draftgrenze")
        for stelle in (
            "eine nichtleere Segmentliste",
            "projection_version",
            "profile_id",
            "Top-Level text",
            "je Segment start_ms",
            "je Segment end_ms",
            "je Segment speaker",
            "je Segment language",
            "je Segment text",
        ):
            assert stelle in draft, stelle
        assert "keinen RevisionAnchor" in draft or "keinen `RevisionAnchor`" in draft
        assert "erfindet weder" in draft

    def test_b3a9_die_anzeige_und_diagnostikgrenze_ist_sichtbar(self) -> None:
        grenze = self._abschnitt(self._norm(), "## Anzeige, Lesen und die Profilgrenze")
        assert "verlangen **keinen** Eintrag" in grenze
        assert "revision.normalized == revision.text" in grenze
        for schluessel in TestB3a7ProfilgrenzeUndAnzeige.TO_JSON_SCHLUESSEL:
            assert schluessel in grenze, schluessel
        assert "legacy Diagnostik" in grenze or "Legacy-Diagnostik" in grenze

    def test_b3a9_dinoh_lux_wird_nicht_als_lokales_profil_erfunden(self) -> None:
        grenze = self._abschnitt(self._norm(), "## Anzeige, Lesen und die Profilgrenze")
        assert "dinoh-lux wird NICHT still auf nfc-strict-v1 abgebildet." in grenze
        assert "Es wird kein neues Profil registriert und keine Profilsemantik erfunden." in grenze
        assert "hashing.py bleibt unveraendert" in grenze

    def test_b3a9_die_neuen_abschnitte_nennen_ihre_herkunft(self) -> None:
        norm = self._norm()
        assert norm.count("**Herkunft dieses Abschnitts.**") == 2
        assert norm.count("41ef874d") >= 3
        assert "Nicht Teil P, nicht Teil S." in norm

    def test_b3a9_sperre_tor_und_normvektoren_bleiben_stehen(self) -> None:
        norm = self._norm()
        assert "B3b" in norm and "transcript.confirm" in norm
        assert "Zwei-Herk" in norm
        assert "from_segments" in norm
        for v in (_v("V1"), _v("V2"), _v("V3"), _v("V5")):
            assert v.sha256 in norm
            assert str(v.n_bytes) in norm
        assert N6_SHA256 in norm
        assert N7_FALSCHER_DIGEST in norm

    def test_b3a9_kein_geschlossener_gesamtakt_wird_behauptet(self) -> None:
        norm = self._norm()
        assert "der Gesamtakt ADR 0028B bleibt offen" in norm
        assert "nicht, den Gesamtakt geschlossen zu haben" in norm
        assert "nicht** ADR 0028B ohne Teilaktkennzeichnung" in norm


# --- Korrekturschliessung B3a-12 ------------------------------------------
#
# B3a-12: ein falscher Laufzeittyp von projection_version ist ein Typbruch an
# Stufe 3 und keine Syntaxverletzung an Stufe 4. Der Vergleichskandidat
# 694d80d8 klassifizierte ihn als InvalidProjectionVersion; die angenommene
# Norm 8dc09e58 und der gesiegelte Bauauftrag dc353c07 verlangen
# InvalidRevisionType.

B3A12_FALSCHE_TYPEN = [None, True, 7, 1.0]
B3A12_IDS = ["null", "bool", "int", "float"]


class TestB3a12ProjectionVersionTypgrenze:
    """B3a-12 · Der falsche Typ faellt an Stufe 3, nicht an Stufe 4.

    Nur eine **Zeichenkette** kann die P1-Syntax oder die Laengengrenze
    verletzen; `null`, `bool`, `int` und `float` sind Typ- beziehungsweise
    null-Grenzbrueche und gehoeren nach S13 zu `InvalidRevisionType` an
    Stufe 3. Ein Konsument, der auf die Typklasse filtert, saehe den Fall
    sonst nicht — und die siebenstufige Prioritaet traege an dieser Stelle
    nicht.

    Die Stufe-4-Klassen bleiben unberuehrt: eine syntaktisch ungueltige
    Zeichenkette faellt weiterhin `InvalidProjectionVersion`, der
    syntaktisch gueltige, aber unbekannte Wert `seg-join-lf.v2` weiterhin
    `UnknownProjectionVersion`.
    """

    def _canon_mit(self, wert: object) -> bytes:
        """V1-CANON, nur der JSON-Wert von projection_version ersetzt.

        Die Bytefolge bleibt fuer jeden der vier Werte parsebar; Ausloeser ist
        ausschliesslich der falsche Feldtyp.
        """
        objekt = json.loads(_v("V1").canon().decode("utf-8"))
        objekt["projection_version"] = wert
        roh = json.dumps(objekt, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        assert json.loads(roh)["projection_version"] == wert or wert is None
        return roh.encode("utf-8")

    def _pruefe_meldung(self, exc: pytest.ExceptionInfo, wert: object) -> None:
        text = str(exc.value)
        assert type(exc.value) is InvalidRevisionType
        assert "projection_version" in text
        assert type(wert).__name__ in text
        assert "Stufe 3" in text
        assert not isinstance(
            exc.value,
            InvalidProjectionVersion
            | UnknownProjectionVersion
            | InvalidRevisionSchema
            | RevisionReconstructionMismatch,
        )

    @pytest.mark.parametrize("wert", B3A12_FALSCHE_TYPEN, ids=B3A12_IDS)
    def test_b3a12_direkter_falscher_typ_faellt_als_invalid_revision_type(
        self, wert: object
    ) -> None:
        """Der direkte Objektweg: eine sonst gueltige Revision, nur die Kennung falsch."""
        rev = _rev(projection_version=wert)

        with pytest.raises(InvalidRevisionType) as exc:
            canonical_revision_bytes(rev)
        self._pruefe_meldung(exc, wert)

        with pytest.raises(InvalidRevisionType):
            revision_sha256(rev)
        with pytest.raises(InvalidRevisionType):
            validate_revision(rev)

        # Keine stillschweigende Reparatur: der falsche Wert steht unveraendert
        # im Objekt, und es entsteht weder CANON noch ein Hash.
        assert rev.projection_version is wert
        assert type(rev.projection_version) is type(wert)

    @pytest.mark.parametrize("wert", B3A12_FALSCHE_TYPEN, ids=B3A12_IDS)
    def test_b3a12_canon_falscher_typ_faellt_als_invalid_revision_type(self, wert: object) -> None:
        """Der Rekonstruktionsweg: parsebares CANON, nur der Feldtyp falsch."""
        canon = self._canon_mit(wert)
        assert json.loads(canon.decode("utf-8"))["projection_version"] == wert

        with pytest.raises(InvalidRevisionType) as exc:
            reconstruct_revision(canon)
        self._pruefe_meldung(exc, wert)

        with pytest.raises(InvalidRevisionType):
            verify_revision(canon, _v("V1").sha256)

        # Keine stillschweigende Reparatur: die vorgelegten Bytes sind
        # unveraendert und tragen weiterhin den falschen Typ.
        assert json.loads(canon.decode("utf-8"))["projection_version"] == wert
