"""Das Transkript als erstklassiges Domänenobjekt.

Nicht eine `.clean.txt`, sondern eine unveränderliche, inhaltsadressierte
Fassung. Der Grund steht im DINOH-Coverage-Audit:

    "char_spans sind Offsets in das Transkript ZUM ZEITPUNKT DER KODIERUNG.
     Hätte sich eine .clean.txt seither geändert, wären alle Coverage-Zahlen
     Fiktion — ohne dass irgendetwas rot geworden wäre."

Genau das darf hier strukturell nicht mehr möglich sein: Eine Korrektur am
Transkript erzeugt eine NEUE Revision mit neuem Hash. Annotationen zeigen auf
eine Revision, nicht auf eine Datei.

**Die Identität kommt seit B3a aus der kanonischen Serialisierung.** Sie wird
in `src/ohpipe/domain/revision_serialization.py::canonical_revision_bytes`
gebildet, und `revision_sha256` ist ihr sha256 — nicht mehr eine
Verschachtelung von `text_sha256` und `structure_sha256`. Die beiden bleiben
als **Diagnostik** erhalten: sie sind keine Adresse, kein Teil der
Hashpräimage und kein Eingang des `RevisionAnchor`.

`projection_version` ist seit B3a ein identitätsbildendes, aus dem Objekt
ablesbares Pflichtfeld. Ohne es ist der Anker aus ADR 0028A nicht schreibbar.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from .hashing import NFC_STRICT, PROFILES, NormalizationProfile, sha256_json, sha256_text

__all__ = ["Segment", "Speaker", "TranscriptRevision"]


@dataclass(frozen=True)
class Speaker:
    """Sprecherrolle, nicht Person. Namen gehören nie ins Modell."""

    id: str
    role: str = "unknown"  # interviewer | narrator | third_party | unknown


@dataclass(frozen=True)
class Segment:
    """Ein Turn oder Untertitelblock.

    ``language`` sitzt am Segment, nicht am Interview: in Luxemburg wechselt
    die Sprache innerhalb eines Interviews (ADR 007).
    """

    index: int
    start_ms: int | None
    end_ms: int | None
    text: str
    speaker: str | None = None
    language: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "start_ms": self.start_ms,
            "end_ms": self.end_ms,
            "text": self.text,
            "speaker": self.speaker,
            "language": self.language,
        }


@dataclass(frozen=True)
class TranscriptRevision:
    """Eine unveränderliche Transkriptfassung.

    ``sha256`` ist seit B3a der sha256 über genau die kanonischen Bytes der
    Fassung (ADR 0028B-S, Teil S). Zwei Revisionen mit gleichem Hash sind
    dieselbe Fassung — auch wenn sie aus verschiedenen Quelldateien stammen
    und verschiedene Provenienzfelder tragen.

    ``projection_version`` ist Pflicht und identitätsbildend. Eine Fassung, der
    noch ein identitätsbildender Pflichtwert fehlt, darf als **Draft**
    existieren (``is_identity_draft``), erhält aber keine Identität: jeder
    identitätserzeugende Zugriff validiert zuerst und fällt fail-closed.

    **Die Profilgrenze, sichtbar im Vertrag.** ``profile_id`` ist ein
    getragener Identitätswert und **kein** Auftrag, ein Normalisierungsprofil
    nachzuladen. Identität, Rekonstruktion, ``normalized``, ``slice``,
    ``to_json`` und ``Anchor.create`` verlangen **keinen** Eintrag in
    `src/ohpipe/domain/hashing.py::PROFILES`. Nur die ausdrücklich
    aufgerufene legacy Diagnostik — ``profile``, ``text_sha256``,
    ``structure_sha256`` und ``_compute_sha`` — löst ein Profil auf und darf
    dabei sichtbar fail-closed fallen.
    """

    text: str
    projection_version: str
    profile_id: str = NFC_STRICT.id
    segments: tuple[Segment, ...] = ()
    source_kind: str = "unknown"  # srt | vtt | docx | txt | asr
    source_sha256: str | None = None
    languages: tuple[str, ...] = ()
    parent_sha256: str | None = None
    note: str = ""

    @property
    def profile(self) -> NormalizationProfile:
        """**Ausdrueckliche Diagnoseprofil-Aufloesung** — keine Anzeigevoraussetzung.

        Sie schlaegt im Profilregister `src/ohpipe/domain/hashing.py::PROFILES`
        nach und faellt fail-closed, wenn dort kein Eintrag steht. Das ist
        richtig: ein unbekanntes Profil wird **nicht** still ersetzt.

        Ihr Fehlschlag bedeutet **nicht**, dass die Revision nach Teil S
        unguelig waere. Teil S verlangt fuer ``profile_id`` nur Nichtleere und
        NFC; ein Profilregister ist nicht Gegenstand von Teil S. Der normative
        Vektor V1 traegt ``dinoh-lux`` — eine Kennung ohne entschiedene
        Transformationssemantik. Identitaet, Rekonstruktion, ``normalized``,
        ``slice``, ``to_json`` und der Anker lesen dieses Register deshalb
        **nicht**.
        """
        try:
            return PROFILES[self.profile_id]
        except KeyError as exc:  # fail-closed: unbekanntes Profil ist kein Default
            raise ValueError(f"Unbekanntes Normalisierungsprofil: {self.profile_id}") from exc

    @property
    def normalized(self) -> str:
        """Der zeichengenaue Revisionstext — **die** Sicht, die auch der Anker liest.

        Seit B3a gibt es hier keine zweite Textgestalt mehr. Frueher lief der
        Text durch `profile.apply`, das ein Abschluss-LF ergaenzte und
        rechtsseitigen Whitespace entfernte; damit wichen CANON-``fulltext``
        und anker-sichtbarer Text voneinander ab, und eine auf dem
        zeichengenauen Text gesetzte Fundstelle war ueber den Anker nicht mehr
        vollstaendig adressierbar.

        Es wird **nicht** getrimmt, **kein** CR/LF umgeschrieben und **kein**
        Abschluss-LF ergaenzt. ``U+000D`` und Nicht-NFC fallen weiterhin vor
        der Byteerzeugung im Revisionskern — sie werden hier nicht repariert.
        """
        return self.text

    @property
    def text_sha256(self) -> str:
        """**Diagnostik**, keine Adresse: nur der normalisierte Volltext.

        Seit B3a kein Teil der Hashpräimage und kein Eingang des
        `src/ohpipe/domain/revision_anchor.py::RevisionAnchor`. Sie ist auch
        **keine Anzeigevoraussetzung**: ``to_json`` ruft sie nicht auf. Sie
        wird nur ausdruecklich aufgerufen und darf bei einem unbekannten
        Diagnoseprofil sichtbar fail-closed fallen.
        """
        return sha256_text(self.text, self.profile)

    @property
    def structure_sha256(self) -> str:
        """**Diagnostik**, keine Adresse: Sprecher, Zeitcodes, Sprache, Grenzen.

        Für Oral History ist das kein Beiwerk. Zwei SRT-Fassungen mit gleichem
        Wortlaut, aber vertauschter Sprecherzuordnung sind verschiedene
        Quellen — und eine Bestätigung, die nur den Text bindet, würde beide
        decken.
        """
        return sha256_json(
            [
                {
                    "i": s.index,
                    "start_ms": s.start_ms,
                    "end_ms": s.end_ms,
                    "speaker": s.speaker,
                    "language": s.language,
                    "text": sha256_text(s.text, self.profile),
                }
                for s in self.segments
            ]
        )

    @property
    def revision_sha256(self) -> str:
        """Die Identität der Fassung: sha256 über genau die kanonischen Bytes.

        Validiert zuerst. Fehlt ein identitätsbildender Pflichtwert — ein
        Draft —, entsteht **kein** Hash, sondern ein fail-closed-Fehler, der
        Segmentindex und Feld benennt.
        """
        from .revision_serialization import revision_sha256

        return revision_sha256(self)

    @property
    def sha256(self) -> str:
        """Derselbe Wert wie ``revision_sha256`` — die eine Adresse der Fassung."""
        return self.revision_sha256

    def _compute_sha(self) -> str:
        """**Diagnostik**: der bis B3a gültige, inzwischen ERSETZTE Identitätsweg.

        `docs/adr/0028A-transkriptvertrag-was-transcript-confirm-bestaetigt.md
        § Folgen` misst an dieser Bauform, warum sie den Vertrag nicht trägt:
        ihr fehlt die `projection_version`, und Volltext wie Segmenttext gehen
        als Hash ein statt als Zeichen — drei Hashebenen statt einer
        kanonischen Serialisierung.

        Sie bleibt als Vergleichswert erreichbar und ist **keine Adresse**:
        weder `sha256` noch `revision_sha256` liefern sie, und sie ist kein
        Teil der Hashpräimage.
        """
        return sha256_json(
            {
                "profile_id": self.profile_id,
                "text_sha256": self.text_sha256,
                "structure_sha256": self.structure_sha256,
            }
        )

    @property
    def is_identity_draft(self) -> bool:
        """Abgeleitet, NICHT identitätsbildend: fehlt noch ein S2-Pflichtwert?

        Steht weder in CANON noch in der Hashpräimage und ist kein
        Revisionsfeld. Eine SRT-Eingangsfassung ohne ``language`` ist ein
        Draft — und bleibt es, bis jemand den Wert ausdrücklich setzt. Der
        Adapter erfindet ihn nicht.
        """
        if not self.segments:
            return True
        if self.projection_version is None or self.profile_id is None or self.text is None:
            return True
        return any(
            s.start_ms is None
            or s.end_ms is None
            or s.speaker is None
            or s.language is None
            or s.text is None
            for s in self.segments
        )

    def revise(
        self,
        new_text: str,
        note: str = "",
        segments: Sequence[Segment] | None = None,
    ) -> TranscriptRevision:
        """Eine Korrektur. Erzeugt eine neue Revision, mutiert nie.

        Der Rückgabewert kennt seinen Vorgänger — daraus ergibt sich die
        Kette, gegen die Anker neu aufgesetzt werden.
        """
        return TranscriptRevision(
            text=new_text,
            projection_version=self.projection_version,
            profile_id=self.profile_id,
            segments=tuple(segments) if segments is not None else self.segments,
            source_kind=self.source_kind,
            source_sha256=self.source_sha256,
            languages=self.languages,
            parent_sha256=self.sha256,
            note=note,
        )

    def slice(self, start: int, end: int) -> str:
        """Schneidet genau ``normalized``, und das ist zeichengleich ``text``.

        ``slice(0, len(self.text))`` liefert darum wieder ``self.text`` —
        auch bei fuehrendem oder folgendem Whitespace und ohne Abschluss-LF.
        """
        return self.normalized[start:end]

    def to_json(self) -> dict[str, Any]:
        """**Anzeige**, nicht die kanonische Serialisierung.

        Verlustbehaftet und nicht bytegleich zu CANON. Der verlustfreie Weg
        heißt `src/ohpipe/domain/revision_serialization.py::canonical_revision_bytes`.

        Die Schluesselgestalt ist **fest**: jede nach Teil S gueltige Revision
        liefert dieselben zehn Schluessel in dieser Reihenfolge, unabhaengig
        vom ``profile_id``. Es gibt keine bedingten Diagnostikschluessel und
        keinen profilabhaengigen Wechsel der Anzeigegestalt.

        Diese Anzeige liest **kein** Profilregister: weder ``profile`` noch
        ``text_sha256`` noch ``structure_sha256`` werden aufgerufen. Die beiden
        Diagnostiken sind **keine** Anzeigevoraussetzung und stehen deshalb
        nicht mehr im Ergebnis.

        Bei einem Draft laeuft zuerst die vollstaendige Teil-S-Validierung:
        der nach der siebenstufigen Ordnung massgebliche Fehler wird geworfen
        und es entsteht **kein** Mapping — insbesondere weder ``sha256=None``
        noch eine teilweise Anzeige.
        """
        digest = self.revision_sha256  # validiert vollstaendig; ein Draft faellt hier
        return {
            "sha256": digest,
            "projection_version": self.projection_version,
            "profile_id": self.profile_id,
            "source_kind": self.source_kind,
            "source_sha256": self.source_sha256,
            "languages": list(self.languages),
            "parent_sha256": self.parent_sha256,
            "note": self.note,
            "n_segments": len(self.segments),
            "n_chars": len(self.text),
        }

    @classmethod
    def from_segments(
        cls,
        segments: Sequence[Segment],
        *,
        projection_version: str,
        source_kind: str = "unknown",
        source_sha256: str | None = None,
        profile_id: str = NFC_STRICT.id,
    ) -> TranscriptRevision:
        """**Konstruktionshilfe**, kein Beleg des Zwei-Herkünfte-Konsistenztors.

        Der Volltext entsteht hier aus derselben Quelle wie die Segmente —
        deshalb belegt ein so gebautes Objekt für sich allein **nicht** die
        Konsistenzprüfung aus Teil S, Abschnitt S12. Ein Vergleich, dessen
        beide Seiten aus einer Quelle kommen, ist kein Vergleich. Die echte
        Gegenprobe legt Volltext und Segmente getrennt vor.

        Es gibt keinen frei wählbaren ``joiner`` mehr: die Verbindung folgt
        ausschliesslich der Definition des ausdrücklich übergebenen
        ``projection_version``-Werts aus dem geschlossenen Katalog.
        """
        from .revision_serialization import project_segments

        text = project_segments(segments, projection_version)
        langs = tuple(sorted({s.language for s in segments if s.language}))
        return cls(
            text=text,
            projection_version=projection_version,
            profile_id=profile_id,
            segments=tuple(segments),
            source_kind=source_kind,
            source_sha256=source_sha256,
            languages=langs,
        )
