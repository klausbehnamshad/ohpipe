# Transcript serialization and projection reference

This German technical reference preserves the historical projection, serialization,
draft and display contracts used by the compatibility tests. Historical identifiers
(including 41ef874d) identify development decisions, not project approvals or
certification of this preview. Private decision records are not distributed.

**Reichweite der technischen Referenz.** Diese Datei beschreibt Teil P und
Teil S; der Gesamtakt ADR 0028B bleibt offen. Sie behauptet ausdrücklich
nicht, den Gesamtakt geschlossen zu haben. Referenziert werden die benannten
Teilakte, **nicht** ADR 0028B ohne Teilaktkennzeichnung.

## Teil P — Projektionsvertrag

### P1 · `projection_version`

```text
Der eine Katalogwert   seg-join-lf.v1
Syntax                 ^[a-z0-9]+(-[a-z0-9]+)*\.v[1-9][0-9]*$
Laenge                 3 bis 64 ASCII-Zeichen
```

Der Wert wird **zeichengenau** getragen: nicht getrimmt, nicht kleingeschrieben,
nicht normalisiert, nicht abgeleitet.

### P2 · Die beobachtbare Projektion

```text
1. Ordne die Segmente aufsteigend nach index.
2. Nimm aus jedem Segment genau das Feld text, unveraendert.
3. Verbinde die Folge mit dem joiner aus P3.
4. Es wird nichts vorangestellt, nichts angehaengt, nichts entfernt.
```

Die Projektion liest **kein** anderes Segmentfeld. `speaker`, `language`,
`start_ms` und `end_ms` gehen nicht in den Volltext ein.

### P3 · Der `joiner` und die Segmentzahl

```text
joiner       U+000A LINE FEED · UTF-8 ein Byte · Hex 0a

0 Segmente   Projektion ist die leere Zeichenkette; eine Revision mit
             0 Segmenten ist dennoch ungueltig (InvalidRevisionSchema).
1 Segment    genau dessen text, kein joiner.
n Segmente   genau n-1 joiner, keiner vor dem ersten und keiner nach dem letzten.
```

### P4 · NFC, Zeilenenden, Whitespace, leere Segmente

```text
NFC            JEDE Zeichenkette im Objekt ist NFC-normalisiert — nicht nur
               text und fulltext, sondern ausdruecklich auch profile_id und
               speaker. Der Kern normalisiert NICHT nach; er prueft.
               projection_version und language tragen mit ihrer strengen
               ASCII-Syntax eine SPEZIALISIERUNG dieser Regel, keine Ausnahme:
               eine reine ASCII-Zeichenkette ist NFC-eindeutig. domain ist eine
               feste ASCII-Konstante.
Surrogate      Ein isolierter Surrogatcodepunkt ist kein UTF-8-Skalarwert. Er
               faellt vor der Byteerzeugung, nicht als roher Kodierfehler.
Zeilenenden    U+000A ist im Segmenttext zulaessig. U+000D ist unzulaessig,
               einzeln wie in CR LF. Es gibt KEINE Umschreibung von CR LF nach
               LF: die Eingabe wird zurueckgewiesen, nicht repariert.
Whitespace     Weder Segmenttext noch Volltext werden getrimmt. Fuehrender und
               folgender Whitespace ist identitaetsbildend.
Leerer text    Zulaessig. Er erzeugt eine leere Zeile und wird nicht
               uebersprungen und nicht entfernt.
```

### P5 · Ablesbarkeit und Bindung

`projection_version` ist ein identitätsbildendes Top-Level-Feld der Revision
und steht in CANON — damit ist sie **aus der Fassung ablesbar**, ohne dass
eine zweite Quelle befragt werden muss. Der `RevisionAnchor` trägt sie als
drittes Glied des Tripels `(artifact_key, revision_sha256, projection_version)`.

### P6 · Festlegungsform

```text
Ort            Dieser Normtext traegt Wortlaut und Fassung der Projektion.
Katalog        Der Produktcode fuehrt ein geschlossenes Vokabular mit genau
               einem Eintrag: seg-join-lf.v1.
Laden          Der Katalog wird NICHT aus Datei, Umgebung, Profil, Store oder
               Journal geladen und hat KEINEN Erweiterungshook.
Pruefen        Am Identitaetspfad wird Syntax, Katalogzugehoerigkeit und das
               Vorliegen einer Produktdefinition geprueft — fail-closed.
Unveraenderlich Eine bestaetigte Revision traegt ihre projection_version in
               ihren identitaetsbildenden Bytes. Eine Aenderung des Werts
               aendert den revision_sha256 und ist eine andere Revision.
```

### P7 · Änderungsregel

Jede Änderung an der Projektionsvorschrift oder am `joiner` verlangt einen
**neuen** `projection_version`-Wert. Ein vergebener Wert wird nie rückwärts
geändert, nicht zurückgezogen und nicht wiederverwendet. Eine geänderte
Projektion erzeugt eine neue Revision; Anker auf die alte bleiben gültig und
wandern nicht mit.

### P8 · Fail-closed

```text
Unbekannte Kennung        UnknownProjectionVersion
Syntaktisch ungueltig     InvalidProjectionVersion
Keine Produktdefinition   ProjectionDefinitionUnavailable
Volltext gegen Projektion ProjectionMismatch
```

In keinem dieser Fälle wird ein Wert ergänzt, ersetzt, getrimmt oder
umgeschrieben.

---

## Teil S — Serialisierungskern

### S1 · Eingabegegenstand

Gebunden sind ausschliesslich die identitätsbildenden Felder nach ADR 0028A:
`profile_id`, `projection_version`, der normalisierte Volltext und die
vollständigen Segmentdaten je Segment mit `index`, `start_ms`, `end_ms`,
`speaker`, `language` und dem Text.

**Nicht gebunden** und ohne Wirkung auf `revision_sha256`: `languages`
(abgeleitet), `source_kind`, `source_sha256`, `parent_sha256`, `note`. Die
Feldmenge aus ADR 0028A wird **nicht** wieder geöffnet; `domain` und `v` sind
keine Revisionsfelder, sondern Kennung und Version der Regel selbst.

### S2 · Objektschema

Sechs Top-Level-Schlüssel in kanonischer Ordnung:

```text
domain              Zeichenkette (type is str), konstant "transcript_revision"
fulltext            Zeichenkette; darf leer sein, wenn ein gueltiges Segment vorliegt
profile_id          Zeichenkette, nichtleer, NFC
projection_version  Zeichenkette, Syntax nach P1, im Katalog nach P6
segments            nichtleere Liste von Segmentobjekten
v                   Ganzzahl (type is int, kein bool, kein float), konstant 1
```

Sechs Segmentschlüssel in kanonischer Ordnung:

```text
end_ms      Ganzzahl >= 0 und >= start_ms
index       Ganzzahl >= 0
language    genau drei ASCII-Kleinbuchstaben (ISO-639-3-Code)
speaker     Zeichenkette, nichtleer, NFC
start_ms    Ganzzahl >= 0
text        Zeichenkette, NFC, ohne U+000D; darf leer sein
```

Genau zwei Ebenen. Alle zwölf Schlüssel sind Pflicht; ein fehlender oder
unbekannter Schlüssel fällt und wird nicht stillschweigend verworfen.

### S3 · Reihenfolge und Vorbedingungen

```text
Indizes           0 bis n-1, lueckenlos, eindeutig, streng aufsteigend in
                  Listenreihenfolge. Die Reihenfolge ist Teil der Byteform.
                  Ein NEGATIVER Index verletzt diese Reihenfolge und faellt
                  als InvalidSegmentOrder — nicht als Typbruch.
Zeiten            start_ms >= 0, end_ms >= start_ms. Nullintervalle sind
                  zulaessig. Intervalle duerfen ueberlappen und muessen nicht
                  lueckenfrei sein — hier wird keine Ueberlappungsregel gesetzt.
Konsistenz        fulltext ist die Projektion der Segmente nach Teil P.
```

### S4 · Objektschlüsselregel

Die Schlüssel stehen aufsteigend nach Unicode-Codepunkt — genau die sortierte
Schlüsselordnung aus `docs/ENTSCHEIDUNGEN_2026-08-05.md § E3`, unverändert
übernommen. Das ist eine Byteregel und keine Aussage über die Feldmenge.

### S5 · Strings, UTF-8, Escaping

```text
Kodierung      UTF-8 ohne BOM
Normalisierung JEDE Zeichenkette im Objekt ist NFC; NFC wird vorausgesetzt
               und geprueft, nicht hergestellt. Die Reichweite ist die aus P4:
               fulltext, profile_id, speaker und jeder Segment-text.
               projection_version und language sind durch ihre ASCII-Syntax
               strenger spezifiziert, nicht ausgenommen.
Surrogate      Ein isolierter Surrogatcodepunkt — direkt oder als parsebare
               JSON-Escapeform — ist kein zulaessiger Skalarwert und faellt an
               Stufe 3 als InvalidRevisionNormalization mit Feld und Grund.
               Kein roher UnicodeEncodeError verlaesst den Kern.
ensure_ascii   false — Nicht-ASCII steht als UTF-8-Bytes
Separatoren    genau ein Komma bzw. ein Doppelpunkt; KEIN Whitespace
               ausserhalb von Zeichenketten
Escaping       nur U+0022, U+005C und die Steuerzeichen unter U+0020
               (Kurzformen b, f, n, r, t; sonst vierstellig hexadezimal)
Kein Escape    U+002F bleibt unmaskiert
Nicht-BMP      steht als UTF-8, nie als Ersatzpaar
```

### S6 · Zahlen, boolesche Werte, `null`

```text
Zulaessig      ausschliesslich vorzeichenlose Dezimalganzzahlen ohne
               fuehrende Null ausser der 0 selbst
Unzulaessig    Gleitkomma, Exponent, fuehrende Null, Vorzeichen, NaN, Infinity
Boolesche Werte kommen im Schema NICHT vor und sind ausdruecklich ausgeschlossen
null           kommt im Schema NICHT vor; es gibt keine optionale und keine
               nullbare Feldform
```

### S7 · Abschlussbyte

```text
Es folgt KEIN Abschlussbyte.
CANON beginnt mit 7b und endet mit dem Byte 7d. Kein Zeilenvorschub, kein
Nullbyte, kein sonstiges Byte wird angehaengt.
```

Dieses Abschlussbyte ist getrennt von den Transport-Schlussbytes der
Registerdateien, die `0a` sind.

### S8 · Kennung und Version der Regel

```text
Name      transcript_revision   (Feld domain)
Version   1                     (Feld v)
```

Beide werden als Felder **im** serialisierten Objekt geführt, nach dem
E3-Formelmuster. Es gibt keine zweite Kennung daneben. Jede Änderung an S2 bis
S7 erhöht `v`; ein vorhandenes `(domain, v)`-Paar wird nie rückwärts umdefiniert.

### S9 · Hashformel

```text
CANON            = die kanonischen Serialisierungsbytes nach S2 bis S7
revision_sha256  = sha256(CANON)

Praeimage        = genau CANON
Bytes davor      = 0
Bytes danach     = 0
Trennregel       = entfaellt, weil nichts zu trennen ist
```

Es findet **keine** Verkettung statt: kein Präfix, kein Domain-String davor,
kein Trennbyte, keine Längenangabe, kein Suffix, kein Abschluss-LF und kein
Zwischenhash. Weil `domain` und `v` Felder im Objekt sind, ist die Domain Teil
der gehashten Bytes, ohne dass zwei Zeichenketten aneinandergefügt werden.

`revision_sha256` ist die Hexdarstellung: genau 64 Zeichen aus `0-9` und `a-f`,
durchgehend kleingeschrieben.

### S10 · Bedeutung und Bindung

`revision_sha256` identifiziert genau eine Revision über ihre
identitätsbildenden Felder. Dieselbe Fassung aus anderer Quelle bleibt dieselbe
Revision — Herkunft ist Provenienz, nicht Identität. Der Wert ist das zweite
Glied des Ankers. `ArtifactKey` und `RevisionAnchor` bleiben **unverändert**:
der Anker prüft weiterhin nur die Form des Hashs sowie Typ und Nichtleere der
Projektionskennung; Katalog- und Byteprüfung liegen im Revisionskern.

### S11 · Rekonstruktion, Round-trip und die sieben Stufen

```text
1  UTF-8-Gueltigkeit
2  JSON-Parse
3  Schema, Typen, null-Grenze, Normalisierung, Reihenfolge
4  projection_version: Syntax, Katalog, Produktdefinition
5  Konsistenztor Volltext gegen Segmentprojektion
6  bytegleiche kanonische Reserialisierung
7  erst danach: Vergleich des vorgelegten revision_sha256 mit dem berechneten
```

Die **erste verletzte Stufe** bestimmt den Ausgang; spätere Stufen werden nicht
mehr ausgeführt und deshalb auch nicht behauptet. Daraus folgt eindeutig:

```text
gueltig parsebar, aber nichtkanonisch  -> Stufe 6, RevisionReconstructionMismatch
                                          und NICHT InvalidRevisionSchema
ungueltiges JSON oder UTF-8            -> Stufe 1 oder 2; erreicht weder
                                          Reserialisierung noch Hashvergleich
kanonisch, aber falscher Digest        -> Stufe 7, RevisionHashMismatch
```

Zu jeder logischen Revision gibt es **genau eine** zulässige Byteform. Aus CANON
allein ist jedes identitätsbildende Feld wiederherstellbar; nicht
identitätsbildende Herkunftsfelder werden **nicht** aus CANON erfunden.

### S12 · Konsistenztor

Der Volltext wird der Bestätigung **vorgelegt**; er wird in ihr nicht erzeugt.
Das Tor hält einen vorgelegten Volltext gegen die aus den Segmenten berechnete
Projektion — nicht gegen einen Volltext, den dieselbe Projektion soeben erzeugt
hat. Bei Abweichung blockiert es mit `ProjectionMismatch`; der Volltext wird
**nicht** ersetzt und die Segmente werden **nicht** angepasst. Das Tor läuft
vor der Byteerzeugung.

Die Konstruktionshilfe `from_segments` erzeugt den Volltext aus den Segmenten
und belegt deshalb für sich allein **nicht** das Zwei-Herkünfte-Tor.

### S13 · Die zehn Fehlerklassen

| Klasse | Auslöser | Stufe |
|---|---|---|
| `InvalidRevisionSchema` | fehlendes oder unbekanntes Feld, leere Segmentliste, falsche `domain`/`v` — **nicht** für eine nur nichtkanonische Byteform | 3 |
| `InvalidRevisionType` | falscher Typ, `null`, `bool`, unzulässige Zahlform, leerer `speaker`, ungültige `language`, `end_ms < start_ms` | 3 |
| `InvalidRevisionNormalization` | Nicht-NFC oder `U+000D` im Text | 3 |
| `InvalidSegmentOrder` | negative, doppelte, lückenhafte oder ungeordnete Indizes | 3 |
| `InvalidProjectionVersion` | Syntax- oder Längenverstoss | 4 |
| `UnknownProjectionVersion` | syntaktisch gültig, nicht im Katalog | 4 |
| `ProjectionDefinitionUnavailable` | im Katalog, keine Produktdefinition | 4 |
| `ProjectionMismatch` | `fulltext` ist nicht die Projektion der Segmente | 5 |
| `RevisionReconstructionMismatch` | gültig parsebar, aber nicht die kanonische Byteform — **einzige** Klasse für N6 | 6 |
| `RevisionHashMismatch` | Stufen 1 bis 6 bestanden, Digest weicht ab — **einzige** Klasse für N7 | 7 |

`RevisionValidationError` ist ein `ValueError` und die gemeinsame Basis. Jede
Meldung nennt Feld und Grund und behauptet keine spätere Prüfung.

### S14 · Abgrenzung

Dieser Teilakt baut den **seiteneffektfreien Kern** und sonst nichts. Die
technische Implementierung von `transcript.confirm` — CLI, Store, Journal,
Eventkatalog, Receipt, Decision, `input_refs`, Actor-Register, Replay — ist
nicht Gegenstand und wird durch diese Datei **nicht** freigegeben.

---

## Draftgrenze — Fassungen ohne Identität

> **Herkunft dieses Abschnitts.** Produktgrenze aus dem gesiegelten
> Korrekturauftrag `41ef874d`, Schließung `B3a-9`. Nicht Teil P, nicht Teil S.

Eine Fassung, der noch ein nach S2 identitätsbildender Pflichtwert fehlt, darf
als **Draft** existieren. Sie ist ein Zwischenobjekt und **keine** Revision:
sie erhält kein `CANON`, keinen `revision_sha256`, kein
`TranscriptRevision.sha256` und keinen `RevisionAnchor`.

`src/ohpipe/domain/transcript.py::TranscriptRevision.is_identity_draft` ist
`True`, sobald **mindestens eine** dieser neun Pflichtstellen fehlt:

```text
1  eine nichtleere Segmentliste
2  projection_version
3  profile_id
4  Top-Level text
5  je Segment start_ms
6  je Segment end_ms
7  je Segment speaker
8  je Segment language
9  je Segment text
```

„Fehlen" heißt hier `None`, bei der Segmentliste: leer. Ein **vorhandener,
aber regelwidriger** Wert ist kein Draft, sondern ein Validierungsfehler; er
wird durch die Draftanzeige **nicht** gesundgeschrieben.

**Draftanzeige und Identitätsvalidierung sind getrennt.** `is_identity_draft`
ist eine abgeleitete, **nicht identitätsbildende** Vorprüfung: sie steht weder
in `CANON` noch in der Hashpräimage und ist kein Revisionsfeld. Unabhängig von
ihr fällt jede Identitätsfunktion fail-closed am ersten Feld der
siebenstufigen Ordnung aus S11.

**Keine erfundenen Ersatzwerte.** `src/ohpipe/adapters/input/srt.py::load_srt`
erfindet weder `speaker` noch `language`. Ein SRT ohne Sprecherpräfix trägt
`speaker = None`, ein SRT ohne Sprachangabe trägt `language = None`; beide
Fassungen sind sichtbar Draft und fallen bei jedem Identitätszugriff am
konkreten fehlenden Feld. Ein Default, ein Rateweg oder ein Platzhalter wäre
eine erfundene Identität.

Dieser Abschnitt gibt **weder** `B3b` **noch** einen Bestätigungs-, CLI- oder
Schreibpfad frei.

---

## Anzeige, Lesen und die Profilgrenze

> **Herkunft dieses Abschnitts.** Produktgrenze aus dem gesiegelten
> Korrekturauftrag `41ef874d`, Regieentscheid zu `B3a-7` und Schließungen
> `B3a-4` und `B3a-7`. Nicht Teil P, nicht Teil S.

**`profile_id` ist ein getragener Identitätswert, kein Ladeauftrag.** Teil S
verlangt für `profile_id` nur Nichtleere und NFC. Er verlangt **nicht**, dass
ein lokales Normalisierungsprofil dieses Namens existiert. Die normativen
Vektoren tragen `profile_id = "dinoh-lux"`; diese Kennung hat in den
gesiegelten Grundlagen **keine** entschiedene Transformationssemantik.

Daraus folgt verbindlich:

```text
dinoh-lux wird NICHT still auf nfc-strict-v1 abgebildet.
Es wird kein neues Profil registriert und keine Profilsemantik erfunden.
Die normativen Vektoren und ihre profile_id-Werte bleiben unveraendert.
src/ohpipe/domain/hashing.py bleibt unveraendert.
```

**Was kein Profilregister liest.** Identität, Rekonstruktion,
`TranscriptRevision.normalized`, `TranscriptRevision.slice`,
`TranscriptRevision.to_json` und `src/ohpipe/domain/anchor.py::Anchor.create`
verlangen **keinen** Eintrag in `src/ohpipe/domain/hashing.py::PROFILES`.

**Der anker-sichtbare Text ist der zeichengenaue Revisionstext.** Für jede
Revision gilt am Leseweg:

```text
revision.normalized == revision.text
revision.slice(0, len(revision.text)) == revision.text
```

Es wird **kein** Whitespace getrimmt und **kein** Abschluss-LF ergänzt.
`Anchor.create` liest über den bestehenden Ankerpfad genau `revision.text`;
Quote, `start` und `end` tragen dieselbe Zeichenfolge und dieselben Offsets.
`U+000D` und Nicht-NFC fallen weiterhin **vor** der Byteerzeugung und werden
nicht repariert.

**Die Anzeige hat eine feste Gestalt.** `to_json` liefert für jede nach Teil S
gültige Revision genau diese Schlüssel in dieser Reihenfolge:

```text
sha256
projection_version
profile_id
source_kind
source_sha256
languages
parent_sha256
note
n_segments
n_chars
```

`languages` steht als Liste, `n_segments` ist `len(segments)`, `n_chars` ist
`len(text)`, `sha256` ist der vollständig validierte `revision_sha256`. Es gibt
**keine** bedingten Diagnostikschlüssel und **keinen** profilabhängigen Wechsel
der Anzeigegestalt. `source_sha256` und `parent_sha256` dürfen weiterhin `None`
sein — das sind optionale Provenienzwerte, keine Identität.

Bei einem **Draft** führt `to_json` zuerst die vollständige Teil-S-Validierung
aus, wirft den nach S11 maßgeblichen Fehler und liefert **kein** Mapping:
weder `sha256 = None` noch eine teilweise Anzeige.

**Legacy-Diagnostik, ausdrücklich aufgerufen.** `profile`, `text_sha256`,
`structure_sha256` und `_compute_sha` bleiben erhalten. Sie sind **keine**
Anzeigevoraussetzung, **keine** Identität und **keine** Ankeradresse. Sie
lösen ein Diagnoseprofil auf und dürfen bei einer unbekannten Kennung —
`dinoh-lux` eingeschlossen — sichtbar fail-closed fallen. Ihr Fehlschlag
bedeutet **nicht**, dass die Revision nach Teil S ungültig ist.

---

## Normative Testvektoren

### V1

**Logische Eingabe**

```text
profile_id          "dinoh-lux"
projection_version  "seg-join-lf.v1"
fulltext            "Guten Tag."
segments
  index 0 · start_ms 0 · end_ms 1500 · speaker "S1" · language "deu" · text "Guten Tag."
```

**CANON, lesbar als UTF-8**

```text
{"domain":"transcript_revision","fulltext":"Guten Tag.","profile_id":"dinoh-lux","projection_version":"seg-join-lf.v1","segments":[{"end_ms":1500,"index":0,"language":"deu","speaker":"S1","start_ms":0,"text":"Guten Tag."}],"v":1}
```

**CANON vollständig als Hex**

```text
7b22646f6d61696e223a227472616e7363726970745f7265766973696f6e222c2266756c6c74
657874223a22477574656e205461672e222c2270726f66696c655f6964223a2264696e6f682d
6c7578222c2270726f6a656374696f6e5f76657273696f6e223a227365672d6a6f696e2d6c66
2e7631222c227365676d656e7473223a5b7b22656e645f6d73223a313530302c22696e646578
223a302c226c616e6775616765223a22646575222c22737065616b6572223a225331222c2273
746172745f6d73223a302c2274657874223a22477574656e205461672e227d5d2c2276223a31
7d
```

```text
Byteanzahl       229
Schlussbyte      7d
Hashpraeimage    genau CANON, 229 Byte; 0 Byte davor, 0 Byte danach
revision_sha256  181855bbe875290a5468e5e15713153c829b20f8a57c0f0203a4adac0f797fa5
Round-trip       reconstruct_revision(CANON) und erneute Serialisierung sind bytegleich
```

### V2

**Logische Eingabe**

```text
profile_id          "dinoh-lux"
projection_version  "seg-join-lf.v1"
fulltext            "Guten Tag.\nAuf Wiedersehen."
segments
  index 0 · start_ms 0 · end_ms 1500 · speaker "S1" · language "deu" · text "Guten Tag."
  index 1 · start_ms 1500 · end_ms 3200 · speaker "S2" · language "deu" · text "Auf Wiedersehen."
```

**CANON, lesbar als UTF-8**

```text
{"domain":"transcript_revision","fulltext":"Guten Tag.\nAuf Wiedersehen.","profile_id":"dinoh-lux","projection_version":"seg-join-lf.v1","segments":[{"end_ms":1500,"index":0,"language":"deu","speaker":"S1","start_ms":0,"text":"Guten Tag."},{"end_ms":3200,"index":1,"language":"deu","speaker":"S2","start_ms":1500,"text":"Auf Wiedersehen."}],"v":1}
```

**CANON vollständig als Hex**

```text
7b22646f6d61696e223a227472616e7363726970745f7265766973696f6e222c2266756c6c74
657874223a22477574656e205461672e5c6e41756620576965646572736568656e2e222c2270
726f66696c655f6964223a2264696e6f682d6c7578222c2270726f6a656374696f6e5f766572
73696f6e223a227365672d6a6f696e2d6c662e7631222c227365676d656e7473223a5b7b2265
6e645f6d73223a313530302c22696e646578223a302c226c616e6775616765223a2264657522
2c22737065616b6572223a225331222c2273746172745f6d73223a302c2274657874223a2247
7574656e205461672e227d2c7b22656e645f6d73223a333230302c22696e646578223a312c22
6c616e6775616765223a22646575222c22737065616b6572223a225332222c2273746172745f
6d73223a313530302c2274657874223a2241756620576965646572736568656e2e227d5d2c22
76223a317d
```

```text
Byteanzahl       347
Schlussbyte      7d
Hashpraeimage    genau CANON, 347 Byte; 0 Byte davor, 0 Byte danach
revision_sha256  6fb042f38df5fd2d9174f862b787cb49115d6c172e8485e1f6462394dbf8bf61
Round-trip       reconstruct_revision(CANON) und erneute Serialisierung sind bytegleich
```

### V3

**Logische Eingabe**

```text
profile_id          "dinoh-lux"
projection_version  "seg-join-lf.v1"
fulltext            "Straße in Köln\nCafé – précis"
segments
  index 0 · start_ms 0 · end_ms 2000 · speaker "S1" · language "deu" · text "Straße in Köln"
  index 1 · start_ms 2000 · end_ms 4000 · speaker "S2" · language "fra" · text "Café – précis"
```

**CANON, lesbar als UTF-8**

```text
{"domain":"transcript_revision","fulltext":"Straße in Köln\nCafé – précis","profile_id":"dinoh-lux","projection_version":"seg-join-lf.v1","segments":[{"end_ms":2000,"index":0,"language":"deu","speaker":"S1","start_ms":0,"text":"Straße in Köln"},{"end_ms":4000,"index":1,"language":"fra","speaker":"S2","start_ms":2000,"text":"Café – précis"}],"v":1}
```

**CANON vollständig als Hex**

```text
7b22646f6d61696e223a227472616e7363726970745f7265766973696f6e222c2266756c6c74
657874223a2253747261c39f6520696e204bc3b66c6e5c6e436166c3a920e28093207072c3a9
636973222c2270726f66696c655f6964223a2264696e6f682d6c7578222c2270726f6a656374
696f6e5f76657273696f6e223a227365672d6a6f696e2d6c662e7631222c227365676d656e74
73223a5b7b22656e645f6d73223a323030302c22696e646578223a302c226c616e6775616765
223a22646575222c22737065616b6572223a225331222c2273746172745f6d73223a302c2274
657874223a2253747261c39f6520696e204bc3b66c6e227d2c7b22656e645f6d73223a343030
302c22696e646578223a312c226c616e6775616765223a22667261222c22737065616b657222
3a225332222c2273746172745f6d73223a323030302c2274657874223a22436166c3a920e280
93207072c3a9636973227d5d2c2276223a317d
```

```text
Byteanzahl       361
Schlussbyte      7d
Hashpraeimage    genau CANON, 361 Byte; 0 Byte davor, 0 Byte danach
revision_sha256  7bf46e39eba41dec1f84315ae96e537f3c830b03efb16a986eebeeef34183074
Round-trip       reconstruct_revision(CANON) und erneute Serialisierung sind bytegleich
```

### V5

**Logische Eingabe**

```text
profile_id          "dinoh-lux"
projection_version  "seg-join-lf.v1"
fulltext            "\nhm"
segments
  index 0 · start_ms 0 · end_ms 0 · speaker "S1" · language "zxx" · text ""
  index 1 · start_ms 0 · end_ms 900 · speaker "S2" · language "und" · text "hm"
```

**CANON, lesbar als UTF-8**

```text
{"domain":"transcript_revision","fulltext":"\nhm","profile_id":"dinoh-lux","projection_version":"seg-join-lf.v1","segments":[{"end_ms":0,"index":0,"language":"zxx","speaker":"S1","start_ms":0,"text":""},{"end_ms":900,"index":1,"language":"und","speaker":"S2","start_ms":0,"text":"hm"}],"v":1}
```

**CANON vollständig als Hex**

```text
7b22646f6d61696e223a227472616e7363726970745f7265766973696f6e222c2266756c6c74
657874223a225c6e686d222c2270726f66696c655f6964223a2264696e6f682d6c7578222c22
70726f6a656374696f6e5f76657273696f6e223a227365672d6a6f696e2d6c662e7631222c22
7365676d656e7473223a5b7b22656e645f6d73223a302c22696e646578223a302c226c616e67
75616765223a227a7878222c22737065616b6572223a225331222c2273746172745f6d73223a
302c2274657874223a22227d2c7b22656e645f6d73223a3930302c22696e646578223a312c22
6c616e6775616765223a22756e64222c22737065616b6572223a225332222c2273746172745f
6d73223a302c2274657874223a22686d227d5d2c2276223a317d
```

```text
Byteanzahl       292
Schlussbyte      7d
Hashpraeimage    genau CANON, 292 Byte; 0 Byte davor, 0 Byte danach
revision_sha256  3c013489b62c6fe99a8c3d992ba7f6a2f1d9eb4be7b53eec0704b551b50de8f2
Round-trip       reconstruct_revision(CANON) und erneute Serialisierung sind bytegleich
```

### N6 — die nichtkanonische Byteform

In die sonst unveränderten 347 CANON-Bytes von V2 ist genau **ein** ASCII-Leerzeichen
(Hexwert `20`) unmittelbar nach dem ersten Doppelpunkt hinter `"domain"` eingefügt.

**Lesbar als UTF-8**

```text
{"domain": "transcript_revision","fulltext":"Guten Tag.\nAuf Wiedersehen.","profile_id":"dinoh-lux","projection_version":"seg-join-lf.v1","segments":[{"end_ms":1500,"index":0,"language":"deu","speaker":"S1","start_ms":0,"text":"Guten Tag."},{"end_ms":3200,"index":1,"language":"deu","speaker":"S2","start_ms":1500,"text":"Auf Wiedersehen."}],"v":1}
```

**Vollständig als Hex**

```text
7b22646f6d61696e223a20227472616e7363726970745f7265766973696f6e222c2266756c6c
74657874223a22477574656e205461672e5c6e41756620576965646572736568656e2e222c22
70726f66696c655f6964223a2264696e6f682d6c7578222c2270726f6a656374696f6e5f7665
7273696f6e223a227365672d6a6f696e2d6c662e7631222c227365676d656e7473223a5b7b22
656e645f6d73223a313530302c22696e646578223a302c226c616e6775616765223a22646575
222c22737065616b6572223a225331222c2273746172745f6d73223a302c2274657874223a22
477574656e205461672e227d2c7b22656e645f6d73223a333230302c22696e646578223a312c
226c616e6775616765223a22646575222c22737065616b6572223a225332222c227374617274
5f6d73223a313530302c2274657874223a2241756620576965646572736568656e2e227d5d2c
2276223a317d
```

```text
Byteanzahl                  348
sha256 der Bytefolge        b79c87c3f5554d152ec8735453ab6020bb120ce41bf93173e32254d4da17f68d
gueltiges JSON              ja, logisch gleich V2
kanonische Reserialisierung ergibt die unveraenderten 347 CANON-Bytes von V2
Fehlerklasse                RevisionReconstructionMismatch — und keine zweite
Abbruch                     Stufe 6; Stufe 7 wird nicht erreicht
```

### N7 — der unpassende vorgelegte Digest

```text
CANON                       unveraendert 347 Byte, Schlussbyte 7d
aus CANON berechnet         6fb042f38df5fd2d9174f862b787cb49115d6c172e8485e1f6462394dbf8bf61
vorgelegter Digest          7fb042f38df5fd2d9174f862b787cb49115d6c172e8485e1f6462394dbf8bf61
Form des vorgelegten Werts  64 Hexziffern, kleingeschrieben — formgueltig
Fehlerklasse                RevisionHashMismatch — und keine zweite
Abbruch                     Stufe 7, nach sechs bestandenen Vorstufen
```

### V4 — begründet entfallen

Das Schema kennt **keine** null- oder optionale Feldform (S6): kein Feld nimmt
`null`, alle zwölf Schlüssel sind Pflicht. Ein positiver V4 wird deshalb
**nicht erfunden**. Seine Grenzen — `null`, optionale Felder, leere
Segmentliste — sind durch negative Vektoren getragen; den zulässigen leeren
Segmenttext trägt V5.

### Die weiteren negativen Vektoren

| Vektor | Minimale Variation | Erwartete Klasse |
|---|---|---|
| `N1` | `fulltext` weicht von der Segmentprojektion ab | `ProjectionMismatch` |
| `N2` | `projection_version` `seg-join-lf.v2` — syntaktisch gültig, unbekannt | `UnknownProjectionVersion` |
| `N3` | nicht NFC-normalisierter String | `InvalidRevisionNormalization` |
| `N3b` | `U+000D` im Segmenttext | `InvalidRevisionNormalization` |
| `N4` | doppelte oder ungeordnete Segmentindizes | `InvalidSegmentOrder` |
| `N4b` | Lücke in den Segmentindizes | `InvalidSegmentOrder` |
| `N5` | falscher Typ | `InvalidRevisionType` |
| `N5b` | `null` | `InvalidRevisionType` |
| `N5c` | unbekannter Objektschlüssel | `InvalidRevisionSchema` |

### Klassenabdeckung — wahrheitsgemäss

Durch objektgenaue Vektoren belegt sind **acht von zehn** Fehlerklassen:
`InvalidRevisionSchema`, `InvalidRevisionType`, `InvalidRevisionNormalization`,
`InvalidSegmentOrder`, `UnknownProjectionVersion`, `ProjectionMismatch`,
`RevisionReconstructionMismatch`, `RevisionHashMismatch`.

Ohne eigenen normativen Pflichtvektor bleiben als **Regelklassen**:
`InvalidProjectionVersion` und `ProjectionDefinitionUnavailable`. Beide sind im
Produktcode und in Tests getragen — die erste für Syntax-, Längen- und
Nicht-ASCII-Abweichung, die zweite als Konsistenzwächter zwischen dem
geschlossenen Katalog und den vorhandenen Produktdefinitionen. Das ist **keine
Pflichtlücke**: der Normvorschlag führt N1 bis N7 und nicht einen eigenen
Vektor je Fehlerklasse. Es wird **nicht** behauptet, jede Fehlerklasse sei
durch einen normativen Vektor gemessen.

---

## Offen und NICHT durch diesen Teilakt geschlossen

Die drei an ADR 0028B delegierten Restgegenstände bleiben **offen**; dieser
Teilakt schlägt für sie keinen Detailwert vor und entscheidet sie nicht:

- **Formatdetails der `instance_id`** — Präfix, Länge, Trennzeichen,
  Serialisierung, Ableitungsformel. Der `ArtifactKey` geht nicht in die
  Revisionsserialisierung ein; die Byteform berührt das Format an keiner Stelle.
- **Ausgestaltung des maschinell prüfbaren Rebase-Belegs** — betrifft die
  Entwertung von Assignments im Kodierpfad, nicht die Revisionsidentität.
- **Abweichungs-Inbox** — ein Ablauf- und Ablagegegenstand, kein Format der
  Revisionsserialisierung.

## Ausserhalb dieses Teilakts offen oder gesondert

- **`E10`-Feldname und `E10`-Vokabular** — eine Nutzlast- und Vokabularfrage;
  die zweite Herkunftsachse ist nicht identitätsbildend und steht nicht in CANON.
- **Ablageformat des Instanzregisters und Actor-Prüfung** — das Register
  bestimmt, *wer* bestätigt; dieser Teilakt bestimmt, *was* serialisiert wird.
- **Gestalt des Bestätigungsartefakts** — nicht gebaut, nicht vorweggenommen.
- **Mechanismus und konkrete Setzung der journalfesten ISO-639-3-Release** —
  `language` wird hier allein auf die **Form** geprüft (drei ASCII-Kleinbuchstaben),
  nicht gegen eine Release.
- **Migration bestehender Revisionen und alter Hashes** — ein eigener Akt.
- **`transcript.confirm`, CLI, Store, Journal, Events, Receipt, Decision,
  Replay und B3b** — kein Schreibpfad ist Gegenstand dieses Teilakts.
- **Cutover, DINOH-Änderung und reale Records** — Governance, unberührt.

---

## Was diese Datei nicht ist

Sie ist **nicht** ADR 0028B ohne Teilaktkennzeichnung und trägt **nicht** den
Status eines vollständig geschlossenen 0028B-Gesamtakts. Sie gibt **B3b** nicht
frei und behauptet keinen freigegebenen realen Bestätigungspfad. Jeder
Folgeschritt bleibt einer neuen ausdrücklichen Operatorentscheidung vorbehalten.
