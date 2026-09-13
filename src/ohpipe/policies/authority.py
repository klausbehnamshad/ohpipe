"""Autorität setzt Authentizität voraus.

Der Fehler, den dieses Modul behebt, war kein Bug, sondern ein Denkfehler über
fünf Reviewrunden hinweg: Auf jede gefundene Fälschung folgte eine strengere
**Payload-Validierung**. Die nächste Runde brachte eine besser geformte
Fälschung. Das ist ein unendlicher Regress, denn:

    Eine wohlgeformte Fälschung ist per Konstruktion nicht von echter Evidenz
    zu unterscheiden, wenn die einzige Prüfung lautet „sieht die Nutzlast
    richtig aus?". Payload-Validierung ist keine Autorisierung.

Die Frage ist nicht, wie eine Zeile aussieht, sondern **wer sie schreiben
durfte**. Und das beantwortet nur eine authentifizierte Kette.

Daraus die Regel:

* **Unauthentifiziert** (kein Schlüssel): Das Journal ist ein Arbeitsprotokoll,
  keine Autoritätsquelle. Kein Artefakt erreicht ``READY``; keine Übergabe wird
  wirksam. Beides wird mit Begründung gemeldet, nicht stillschweigend gekappt.
* **Authentifiziert** (Schlüssel außerhalb der Datenwurzel): Wer anhängt, hatte
  den Schlüssel. Erst jetzt können Evidenz und Übergaben Wirkung entfalten.

Das schließt zugleich den Downgrade: Ein Profil mit ``key_required = true``
läuft ohne Schlüssel gar nicht erst — die Betriebsart steht damit außerhalb der
Datenwurzel fest und hängt nicht an einer vergessenen Umgebungsvariablen.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["CAP_REASON", "OWNERSHIP_REASON", "Authority"]


class Authority(str, Enum):
    AUTHENTICATED = "authenticated"
    UNAUTHENTICATED = "unauthenticated"

    @property
    def may_confer_ready(self) -> bool:
        return self is Authority.AUTHENTICATED

    @property
    def may_confer_ownership(self) -> bool:
        return self is Authority.AUTHENTICATED

    @property
    def may_confer_exclusion(self) -> bool:
        """Auch das Ausblenden ist Autorität.

        Die erste Fassung sperrte nur READY und Ownership. Ein frei erfundenes
        ``record.disabled`` wirkte weiter — jemand mit Schreibzugriff konnte ein
        Interview aus dem Betrieb nehmen. Ein negativer Akt ist genauso
        folgenreich wie ein positiver: Ein ausgeblendeter QDA-Fall verschwindet
        aus jeder Auswertung.
        """
        return self is Authority.AUTHENTICATED


CAP_REASON = (
    "Die Evidenzkette ist nicht authentifiziert. Wer sie schreiben darf, kann "
    "wohlgeformte Belege und Entscheidungen erzeugen — Nutzlastprüfung ist keine "
    "Autorisierung. Deshalb erreicht kein Artefakt READY. Für einen wirksamen "
    "Freigabepfad OHPIPE_JOURNAL_KEY auf eine Schlüsseldatei außerhalb der "
    "Datenwurzel setzen (ADR 0017)."
)

PROVISIONAL_REASON = (
    "Entscheidungen aus einer nicht authentifizierten Kette gelten als "
    "provisorisch: sie werden angezeigt, entfalten aber keine Wirkung — weder "
    "annehmend noch ausschließend (ADR 0017)."
)

OWNERSHIP_REASON = (
    "Übergaben aus einer nicht authentifizierten Kette werden nicht wirksam: "
    "ein angehängtes record.adopted wäre sonst ein Schreibrecht, das man sich "
    "selbst ausstellt (ADR 0017)."
)
