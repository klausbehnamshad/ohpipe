# Metadata Model — vendorte Fassung

Quelle: **IMM-Core v1.0**, DOI [10.5281/zenodo.20507329](https://doi.org/10.5281/zenodo.20507329),
CC-BY-4.0, Klaus Behnam Shad.

Im Projektgebrauch heißt es schlicht **Metadata Model** (oder kurz *Metadata*).
Der Publikationsname `IMM-Core` bleibt in der Zitation stehen — ein DOI lässt
sich nicht umbenennen —, taucht aber sonst nicht mehr auf. `LuxOH-CMDI` ist
in dieser Systematik ein *Implementation Profile* des Modells, kein eigenes
Schema.

## Was hier liegt und was gilt

| Datei | Rolle |
|---|---|
| `core.tap.csv` | **Single source of truth** (DCTAP). Bei Widerspruch gewinnt diese Datei. |
| `core.schema.json` | daraus abgeleiteter JSON-Schema-Spiegel |
| `consent_status.vocab.md` | empfohlenes Vokabular; Profile schränken ein |

`tests/test_metadata_model.py` prüft, dass der Spiegel nicht von der DCTAP
abgewichen ist. Eine vendorte Kopie, die still driftet, war im Vorgängersystem
ein realer Defekt — dort lag ein publiziertes Schema als Kopie im Repo und
niemand verglich.

## Zwei-Schichten-Architektur

Das Modell trennt **Core** und **Implementation Profile**. Das ist exakt die
Trennung, die `ohpipe` zwischen Kern und Projektprofil zieht (ADR 0009): Der
Core erzwingt zum Beispiel kein `record_id`-Muster, das Implementation Profile
schon. Ein ohpipe-Profil ist damit die Implementierungsseite eines
Implementation Profile — nicht ein zweiter, konkurrierender Begriff.

## Was das Modell (v1.0) noch nicht kann

* **Mehrsprachigkeit** — `language` ist ein einzelner ISO-639-3-Code, Block B.
  `ohpipe` führt Sprache am Segment, weil in Luxemburg innerhalb eines
  Interviews gewechselt wird. Der Export projiziert auf eine Hauptsprache; das
  ist ein **deklarierter Verlust**, kein Zufall (Phase 2 des Modells).
* **Mehrere Interviewende**, zusammengesetzte Daten, vollständige
  Sprecherkomponente, Block D (Preservation) — alle als Phase 2 markiert.

## Erzwingbare Invariante aus dem Vokabular

> `withdrawn` MUSS in jedem Profil gültig bleiben, und ein zurückgezogener
> Record MUSS `accessRights: "closed"` setzen.

Umgesetzt in `policies/metadata.py`, geprüft in `tests/test_metadata_model.py`.
Sie verbindet sich direkt mit dem `WITHDRAW`-Verdikt einer `Decision`.
