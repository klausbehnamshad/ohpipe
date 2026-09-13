#!/usr/bin/env bash
# Der Durchstich — die Kette, die am 23.09. vorgeführt wird.
#
# Gefahren wird die ausgelieferte Beispieldatei examples/synthetic/SANDBOX-001.srt,
# nicht irgendeine im Skript eingebaute Konstante. Genau diese Verwechslung hat den
# ersten Durchstich auf dem Rechner des Vorführenden abbrechen lassen: das Protokoll
# nannte 3 Cues, das Kommando las 5.
#
# Die Datenwurzel liegt unter /tmp und wird bei jedem Lauf neu angelegt. Das
# Repository wird nur gelesen; nach dem Lauf steht in ihm keine Datei mehr als
# vorher (die letzte Stufe prueft das).
#
#   examples/synthetic/durchstich.sh          # Datenwurzel in einem frischen /tmp-Verzeichnis
#   OHPIPE_DURCHSTICH_BEHALTEN=1 examples/…   # Datenwurzel nach dem Lauf stehen lassen
#
# Exitcodes des Werkzeugs: 0 READY · 1 STOP · 2 CONFIG · 3 ACTION_NEEDED. Drei
# Stufen enden planmaessig mit 3 — die Vorlage, weil die Sprachzellen noch leer
# sind, und die beiden `continue`, weil vor dem Modellschritt ein Mensch
# bestaetigt. Ein Skript mit `set -e` und ohne diese Unterscheidung braeche dort
# ab und meldete einen Fehler, wo der Vertrag arbeitet. Deshalb nennt jede Stufe
# ihren erwarteten Exitcode, und jeder andere ist ein echter Abbruch.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SRT="$REPO/examples/synthetic/SANDBOX-001.srt"
KORREKTUR="$REPO/examples/synthetic/SANDBOX-001-korrektur.srt"
RECORD="SANDBOX-001"

# Bewusst /tmp und nicht $TMPDIR: auf dem Mac zeigt $TMPDIR nach
# /var/folders/…, und die Datenwurzel der Vorfuehrung soll dort liegen, wo sie
# im Protokoll steht. Ueberschreibbar, falls /tmp nicht beschreibbar ist.
WURZEL="$(mktemp -d "${OHPIPE_DURCHSTICH_TMP:-/tmp}/ohpipe-durchstich-XXXXXX")"
ARBEIT="$WURZEL/arbeit"
mkdir -p "$ARBEIT"

export OHPIPE_DATA_ROOT="$WURZEL/daten"
export OHPIPE_JOURNAL_KEY="$WURZEL/journal.key"
"$REPO/.venv/bin/python" - <<'PY'
import os
import secrets
from pathlib import Path

key = Path(os.environ["OHPIPE_JOURNAL_KEY"])
key.write_bytes(secrets.token_bytes(32))
key.chmod(0o600)
PY

aufraeumen() {
  if [ "${OHPIPE_DURCHSTICH_BEHALTEN:-0}" = "1" ]; then
    printf '\nDatenwurzel bleibt stehen: %s\n' "$WURZEL"
  else
    rm -rf "$WURZEL"
  fi
}
trap aufraeumen EXIT

# Gefahren wird der Code DIESES Baums, nie ein Werkzeug vom PATH.
#
# Die frühere Fassung nahm das installierte Werkzeug, wenn eines auf dem PATH
# lag, und begründete das mit "beides ist derselbe Code". Diese Annahme hat den
# Durchstich am 05.09.2026 abbrechen lassen: auf dem Vorführrechner lag unter
# /opt/anaconda3/bin/ohpipe eine ältere Installation, deren Parser den
# Unterbefehl `instance` noch nicht kannte. Stufe 02 endete mit Exitcode 2 statt
# 0 — nicht weil das Produkt falsch gewesen wäre, sondern weil ein anderes
# Programm lief als das vorgeführte. Wer aus dem Baum vorführt, führt den Baum
# vor; was auf dem PATH liegt, ist eine Aussage über den Rechner, nicht über die
# Fassung.
export PYTHONPATH="$REPO/src${PYTHONPATH:+:$PYTHONPATH}"

# Die Projektumgebung enthält die im Schnellstart installierten Abhängigkeiten
# und hat deshalb Vorrang vor einem System-Python auf dem PATH.
# Welcher Interpreter — der Nachweis statt der Absicht. Gesucht wird der erste,
# der die CLI samt Abhängigkeiten AUS DIESEM BAUM lädt; gefragt wird er selbst, nicht
# seine Versionsnummer. Damit hängt die Vorführung weder am PATH-Eintrag
# `ohpipe` noch daran, welches python3 zuerst gefunden wird: ein 3.10 oder ein
# 3.9 fällt hier durch (src/ohpipe/__init__.py hält ab 3.11), und der nächste
# Kandidat kommt dran. Überschreibbar mit OHPIPE_DURCHSTICH_PYTHON.
PYTHON=""
LETZTER=""
for kandidat in "${OHPIPE_DURCHSTICH_PYTHON:-}" "$REPO/.venv/bin/python" python3 python3.13 python3.12 python3.11; do
  [ -n "$kandidat" ] || continue
  command -v "$kandidat" > /dev/null 2>&1 || continue
  if MODUL="$("$kandidat" -c 'import ohpipe.cli.main, pathlib; print(pathlib.Path(ohpipe.__file__).resolve().parent)' 2>&1)"; then
    PYTHON="$kandidat"
    break
  fi
  LETZTER="$kandidat: $MODUL"
done
if [ -z "$PYTHON" ]; then
  printf 'ABBRUCH: kein Interpreter gefunden, der ohpipe aus %s laden kann.\n%s\n' \
    "$REPO/src" "$LETZTER" >&2
  exit 1
fi

# Und geladen werden muss der Baum, nicht irgendein installiertes ohpipe, das
# derselbe Interpreter sonst gefunden hätte. Stimmt das nicht, bricht der Lauf
# hier ab und nicht in der Mitte der Kette.
BAUM="$("$PYTHON" -c 'import pathlib, sys; print(pathlib.Path(sys.argv[1]).resolve())' "$REPO/src/ohpipe")"
if [ "$MODUL" != "$BAUM" ]; then
  printf 'ABBRUCH: geladen würde %s, der Baum liegt in %s.\n' "$MODUL" "$BAUM" >&2
  exit 1
fi

WERKZEUG=("$PYTHON" -m ohpipe.cli.main)

STUFE=0
MARKE=0

# Eine Stufe ohne Werkzeugaufruf — sie zaehlt mit, damit die Nummern im
# Protokoll luecken- und widerspruchsfrei bleiben.
abschnitt() {
  STUFE=$((STUFE + 1))
  printf '\n=== %02d %s\n' "$STUFE" "$1"
}

# Ein Haltepunkt fuer den Vorfuehrenden. AUSGESCHALTET, solange
# OHPIPE_DURCHSTICH_HALT nicht auf 1 steht: der Lauf in der Testsuite und in der
# CI darf sich nicht aendern, nur weil das Skript vorfuehrbar geworden ist.
#
# Zweite Bedingung: eine nicht-interaktive Eingabe laeuft durch, statt zu
# warten. Ein Skript, das in einer Pipeline auf Enter wartet, haengt bis zum
# Timeout, und niemand sieht warum. `[ -t 0 ]` ist die Frage danach, ob
# ueberhaupt jemand da ist, der druecken koennte.
halt() {
  [ "${OHPIPE_DURCHSTICH_HALT:-0}" = "1" ] || return 0
  MARKE=$((MARKE + 1))
  # Die Marke steht VOR der Terminalfrage. Sie ist nicht fuer den, der drueckt,
  # sondern fuer den, der die Aufzeichnung spaeter schneidet: eine Zeile, die
  # sich als Kapitelmarke lesen laesst. Wer den Lauf mit gesetzter Variable in
  # eine Datei umleitet, bekommt damit das Kapitelverzeichnis zur Aufnahme.
  printf '\n--- MARKE %s: %s\n' "$MARKE" "$1"
  [ -t 0 ] || return 0
  printf '[Enter] weiter: %s\n' "$2"
  read -r _ || true
}

# Die Kopfzeile eines Demo-Moments. Sie steht IM PROTOKOLL und nicht nur im
# Skript: wer die Aufzeichnung vom 17.09. liest, soll sehen, welcher Satz aus
# dem ROADMAP hier gerade belegt wird. Sie zaehlt keine Stufe mit, sie
# beschriftet die naechste.
moment() {
  printf '\n########## Demo-Moment %s ##########\n' "$1"
  printf 'ROADMAP § 7: %s\n' "$2"
}

stufe() {
  local erwartet="$1"; shift
  local titel="$1"; shift
  STUFE=$((STUFE + 1))
  printf '\n=== %02d %s   [erwarteter Exitcode %s]\n' "$STUFE" "$titel" "$erwartet"
  local gezeigt=""
  local a
  for a in "$@"; do
    case "$a" in
      *[![:alnum:]/._=:-]*) gezeigt="$gezeigt \"$a\"" ;;
      *) gezeigt="$gezeigt $a" ;;
    esac
  done
  # Gezeigt wird die Nutzerform; gefahren wird der Baum (siehe Kopf).
  printf '$ ohpipe%s\n' "$gezeigt"
  set +e
  "${WERKZEUG[@]}" "$@"
  local code=$?
  set -e
  if [ "$code" != "$erwartet" ]; then
    printf '\nABBRUCH in Stufe %02d (%s): Exitcode %s, erwartet %s\n' \
      "$STUFE" "$titel" "$code" "$erwartet" >&2
    exit 1
  fi
  # Der TATSAECHLICHE Exitcode, ausgeschrieben. Der Abbruch oben macht ihn zwar
  # zwingend gleich dem erwarteten, aber ein Protokoll, das nur die Erwartung
  # nennt, verlangt vom Leser Vertrauen in eine Zeile, die er nicht sieht.
  printf 'Exitcode %s (erwartet %s)\n' "$code" "$erwartet"
}

VORHER="$(cd "$REPO" && git status --porcelain 2> /dev/null || true)"

printf 'ohpipe Durchstich\n'
# Der Baustand gehoert in den Kopf, nicht in eine Begleitmail: die
# Bildschirmaufzeichnung vom 17.09. muss ohne Rueckfrage einem Commit
# zuzuordnen sein. Ein unsauberer Arbeitsbaum wird dabei benannt und nicht
# verschwiegen; sonst zeigte der Kopf einen Commit, der nicht gelaufen ist.
BAUSTAND="$(cd "$REPO" && git rev-parse --short HEAD 2> /dev/null || echo 'kein git')"
if [ -n "$(cd "$REPO" && git status --porcelain 2> /dev/null)" ]; then
  BAUSTAND="$BAUSTAND + lokale Aenderungen"
fi

printf '  Baustand     : %s\n' "$BAUSTAND"
printf '  Zeitpunkt    : %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
printf '  Werkzeug     : %s\n' "Baum ($PYTHON -m ohpipe.cli.main)"
printf '  Modul        : %s\n' "$MODUL"
printf '  Repository   : %s\n' "$REPO"
# Ein `ohpipe` auf dem PATH wird nicht gefahren — aber die Zeilen unten zeigen
# die Nutzerform `ohpipe ...`, und wer eine davon abschreibt, träfe genau dieses
# Programm. Also wird es genannt.
if command -v ohpipe > /dev/null 2>&1; then
  printf '  Auf dem PATH : %s (wird NICHT gefahren)\n' "$(command -v ohpipe)"
fi
printf '  Datenwurzel  : %s\n' "$OHPIPE_DATA_ROOT"
printf '  Quelle       : %s (%s Bytes, %s Cues)\n' \
  "$SRT" "$(wc -c < "$SRT" | tr -d ' ')" "$(grep -c -- '-->' "$SRT")"
printf '  sha256       : %s\n' "$(shasum -a 256 "$SRT" 2> /dev/null || sha256sum "$SRT")"

# --------------------------------------------------------------- Arbeitsbereich
stufe 0 "Arbeitsbereich anlegen" init

# --------------------------------------------------------------- Selbstpruefung
# Genau der Befehl, den `init` als NEXT genannt hat. `doctor` ist read-only und
# prueft unter anderem die Kerninvariante am Ausgang: kein Modellpfad erreicht
# ein Artefakt, das das System verlaesst, ohne ein menschliches Tor dazwischen
# (ADR 0013). Geprueft wird der Graph DIESES Profils, nicht eine Modulkonstante.
stufe 0 "Selbstpruefung" doctor

abschnitt "Kein Modellpfad ohne menschliches Tor"
"${WERKZEUG[@]}" doctor --json > "$ARBEIT/doctor.json" || true
"$PYTHON" - "$ARBEIT/doctor.json" <<'TOR'
import json, sys
details = json.load(open(sys.argv[1]))["details"]
print(f"  Egresstore    : {details['egress_gates']}")
print(f"  Schritte      : {details['graph_steps']}")
if details["egress_gates"] != "geschlossen":
    print(f"ABBRUCH: {details.get('egress_violations')}", file=sys.stderr)
    raise SystemExit(1)
TOR

# --------------------------------------------------------------- Instanz
# Wer aufnimmt, steht vor dem, was aufgenommen wird. Ohne registrierte Instanz
# hat spaeter keine Zuordnung einen Urheber.
stufe 0 "Instanz registrieren" \
  instance register KLAUS --source mensch --label "Klaus Behnamshad" \
  --reference "DEMO-23-09" --confirm

# Eine zweite menschliche Instanz. Sie wird erst am Ende gebraucht (Moment 4),
# steht aber hier, weil das Register vor allem anderen kommt: wer freigibt,
# muss registriert sein, bevor es etwas freizugeben gibt.
stufe 0 "Zweite Instanz registrieren" \
  instance register ARCHIV --source mensch --label "Archivleitung" \
  --reference "DEMO-23-09" --confirm

# --------------------------------------------------------------- Wortschatz
# Der ISO-639-3-Wortschatz begrenzt, welche Sprachen ueberhaupt zuordenbar sind.
# deu, ltz, fra sind die drei des Beispiels; und/zxx verlangt das Format.
printf 'deu\nfra\nltz\nund\nzxx\n' > "$ARBEIT/iso6393.txt"
stufe 0 "ISO-639-3-Snapshot vorbereiten" \
  iso6393 prepare "$ARBEIT/iso6393.txt" --release iso.2025 \
  --reference "DEMO-23-09" --confirm

# --------------------------------------------------------------- Quelle
# Die Quelldatei kommt unveraendert in den Store. Was hier eingeht, ist noch
# keine Fassung — es ist das, woraus eine wird.
# Endet planmaessig mit ACTION_NEEDED: abgelegt und belegt ist nicht bestaetigt.
stufe 3 "Quelltranskript aufnehmen" ingest "$SRT" --record "$RECORD"

# --------------------------------------------------------------- Vorlage
# Endet planmaessig mit ACTION_NEEDED: die Sprachzellen sind leer, und leer
# lassen kann sie nur ein Mensch fuellen.
stufe 3 "Mappingvorlage erzeugen" \
  transcript language template "$SRT" --output "$ARBEIT/vorlage.tsv"

# --------------------------------------------------------------- Zuordnung
# Eine Sprache je Segment, nach der tatsaechlichen Sprache des Segments:
#   0 deu (INTERVIEWER, Frage)      3 fra (INTERVIEWER, Frage)
#   1 deu (ZEITZEUGIN)              4 deu (ZEITZEUGIN)
#   2 ltz (ZEITZEUGIN, mit deutschem Nachsatz — zugeordnet wird der erste Satz)
# Segment 2 ist der ehrliche Fall: das Interview wechselt innerhalb eines Cues
# die Sprache, das Format kennt aber genau eine je Segment. Die Grenze wird
# benannt und nicht durch Umschreiben des Transkripts versteckt.
abschnitt "Sprachen je Segment eintragen (deu deu ltz fra deu)"
awk 'BEGIN { FS = OFS = "\t"; split("deu deu ltz fra deu", s, " ") }
     NR == 1 { print; next }
     { $3 = s[NR - 1]; print }' "$ARBEIT/vorlage.tsv" > "$ARBEIT/zuordnung.tsv"
cat "$ARBEIT/zuordnung.tsv"

# --------------------------------------------------------------- Sprachen
stufe 0 "Segmentsprachen vorbereiten" \
  transcript language prepare "$RECORD" "$SRT" "$ARBEIT/zuordnung.tsv" \
  --actor KLAUS --reference "DEMO-23-09" --confirm

# --------------------------------------------------------------- Fassung
# Hier entsteht die kanonische Fassung (transcript.revision). Die Zuordnung wird
# dabei neu gerechnet, nicht geglaubt.
stufe 0 "Kanonische Fassung aufnehmen" \
  transcript ingest "$RECORD" "$SRT" "$ARBEIT/zuordnung.tsv" --confirm

# --------------------------------------------------------------- Volltext
# Der getrennt gelieferte Volltext — der Fall, in dem eine Redaktion neben dem
# SRT eine eigene Textfassung schickt. Er wird als Herkunft belegt, nicht als
# zweite Wahrheit neben die Fassung gestellt.
{
  printf 'INTERVIEWER: Erzaehlen Sie mir bitte, wie der Schulweg damals aussah.\n'
  printf 'ZEITZEUGIN: Wir sind jeden Morgen zu Fuss gegangen, auch im Winter.\n'
} > "$ARBEIT/volltext.txt"
stufe 0 "Getrennten Volltext belegen" \
  transcript fulltext prepare "$RECORD" "$ARBEIT/volltext.txt" \
  --reference "DEMO-23-09" --confirm

# --------------------------------------------------------------- Bestaetigung
# Das menschliche Tor. Danach traegt die Fassung Bindungsevidenz.
stufe 0 "Transcript bestaetigen" transcript confirm "$RECORD" --actor KLAUS --confirm

# --------------------------------------------------------------- Halt
halt "Moment 1, continue haelt" "der Halt mit Grund und naechstem Befehl"
moment 1 "ohpipe continue laeuft von selbst und HAELT — mit Grund und naechstem Befehl."
stufe 3 "continue — laeuft und haelt" continue "$RECORD"

# --------------------------------------------------------------- Modelllauf
halt "Moment 3, der Lauf scheitert" "der Modelllauf, der scheitern MUSS"
moment 3 "Ein Modelllauf schlaegt an die Token-Grenze und SCHEITERT, statt ein Teilergebnis zu liefern."
# Endet planmaessig mit STOP. Das ist der Beweis und nicht der Fehler: der
# aufgezeichnete Lauf endet mit finish_reason=length, und der Empfangsvertrag
# nimmt ihn NICHT an. Ein abgeschnittener Lauf als Teilergebnis haette die
# Luecke systematisch am Ende der dichtesten Passagen. Geschrieben wird nichts:
# der Beleg wird geprueft, bevor die Antwort gelesen wird.
stufe 1 "continue --confirm --fixture length — der Lauf scheitert" \
  continue "$RECORD" --confirm --fixture length

# Und dieselbe Kette mit dem aufgezeichneten Lauf, der sauber endet
# (finish_reason=stop). Derselbe Vertrag, andere Antwort.
stufe 3 "continue --confirm — der Modellschritt" continue "$RECORD" --confirm

# --------------------------------------------------------------- Adjudikation
# Das erste Katalog-Gate: die L1-Vorschlaege werden als Ganzes angenommen und
# die Entscheidung an die adjudizierten Bytes gebunden (Moment 4).
stufe 0 "L1 adjudizieren" l1 review "$RECORD" --actor KLAUS --confirm

# --------------------------------------------------------------- Metadaten
# continue leitet metadata.derive ab (billig, laeuft von selbst) und haelt vor
# der menschlichen Bestaetigung. Dieselbe Mechanik wie l1.review.
stufe 3 "continue — Metadaten ableiten, halten" continue "$RECORD"
stufe 0 "Metadaten bestaetigen" metadata confirm "$RECORD" --actor KLAUS --confirm

# --------------------------------------------------------------- Abstract
stufe 3 "continue — Abstract ableiten, halten" continue "$RECORD"
stufe 0 "Abstract bestaetigen" abstract confirm "$RECORD" --actor KLAUS --confirm

# --------------------------------------------------------------- Freigabe
# release.preview setzt Metadaten, Abstract und Adjudikation zusammen (ohne
# Analyse, ADR 0020); die Freigabe bindet an genau diese Bytes.
stufe 3 "continue — Katalogvorschau zusammensetzen, halten" continue "$RECORD"
stufe 0 "Katalog freigeben" release approve "$RECORD" --actor KLAUS --confirm

# --------------------------------------------------------------- Ausgang
# Der letzte Schritt der Kette. `continue` legt das Bundle von selbst ab: der
# Schritt ist billig und entscheidet nichts. Die Entscheidung ist die der
# Freigabe und wird geerbt — kein zweites Tor, keine erfundene Zustimmung.
stufe 3 "continue — Katalogbundle ablegen, dann halten" continue "$RECORD"

# Entstanden ist das Bundle damit im Store. Aus dem System heraus geht es erst,
# wenn jemand ein Ziel nennt.
stufe 0 "Bundle nach draussen schreiben" \
  export "$RECORD" --output "$ARBEIT/$RECORD.bundle.json" --confirm

abschnitt "Das Bundle"
cat "$ARBEIT/$RECORD.bundle.json"
printf '\n'

# --------------------------------------------------------------- Korrektur
# Demo-Moment 2, ROADMAP: "Eine Transkriptkorrektur macht Anker sichtbar
# ambiguous; die Maschine waehlt nicht."
#
# Die Korrektur traegt zwei Dinge nach, die eine Transkription regelmaessig
# verschluckt: den Satz, mit dem das Band anlaeuft, und dass die Eingangsfrage
# nach einer Unterbrechung ein zweites Mal gestellt wurde. Genau diese
# Wiederholung macht den Anker auf die Frage mehrdeutig — das Zitat steht
# danach zweimal da, und keiner der beiden Kontexte ist der urspruengliche.
#
# Die Stufe zeigt zwei Dinge und nur diese zwei: der Anker wird mehrdeutig,
# und das System verlangt dafuer einen Menschen.
halt "Korrekturblock" "eine Fassung, die es schon gibt, wird korrigiert"
stufe 3 "Korrekturvorlage erzeugen" \
  transcript language template "$KORREKTUR" --output "$ARBEIT/korrektur-vorlage.tsv"

abschnitt "Sprachen der Korrektur eintragen (deu deu deu deu ltz fra deu)"
awk 'BEGIN { FS = OFS = "\t"; split("deu deu deu deu ltz fra deu", s, " ") }
     NR == 1 { print; next }
     { $3 = s[NR - 1]; print }' "$ARBEIT/korrektur-vorlage.tsv" > "$ARBEIT/korrektur.tsv"
cat "$ARBEIT/korrektur.tsv"

stufe 0 "Korrigierte Sprachen vorbereiten" \
  transcript language prepare "$RECORD" "$KORREKTUR" "$ARBEIT/korrektur.tsv" \
  --actor KLAUS --reference "KORR-23-09" --confirm

stufe 0 "Korrigierte Fassung aufnehmen" \
  transcript ingest "$RECORD" "$KORREKTUR" "$ARBEIT/korrektur.tsv" --confirm

# Endet planmaessig mit ACTION_NEEDED: ein Anker ist mehrdeutig geworden. Das
# ist kein Fehler, sondern die Aussage. Die Maschine schliesst die vier
# eindeutigen Verschiebungen und legt fuer den mehrdeutigen die Kandidaten vor.
halt "Moment 2, Anker mehrdeutig" "der Ankerzustand nach der Korrektur"
moment 2 "Eine Transkriptkorrektur macht Anker sichtbar ambiguous; die Maschine waehlt nicht."
stufe 3 "Ankerzustand nach der Korrektur" transcript anchors "$RECORD"

# --------------------------------------------------------------- Uebersicht
# Endet planmaessig mit ACTION_NEEDED: der Katalogpfad steht bis export.bundle,
# der naechste Halt liegt im getrennten Analysepfad (ADR 0020, noch nicht gebaut).
# Ein Halt vor einem ungebauten Schritt ist kein Fehler.
stufe 3 "Uebersicht" status

# --------------------------------------------------------------- Kein Befund
# Die eigentliche Aussage des Durchstichs. Ein Record, der jeden Schritt sauber
# durchlaufen hat und trotzdem einen Befund traegt, ist genau der Zustand, gegen
# den L1-L4 gebaut wurde. Deshalb wird hier nicht das Auge gefragt, sondern die
# Maschine.
abschnitt "P3: Alte Ableitungen gesperrt, keine Journalbefunde"
"${WERKZEUG[@]}" status --json > "$ARBEIT/status.json" || true
"$PYTHON" - "$ARBEIT/status.json" <<'PRUEF'
import json, sys
record = json.load(open(sys.argv[1]))["details"]["records"][0]
befunde = record["findings"]
artefakte = {name: eintrag["status"] for name, eintrag in record["artifacts"].items()}
for name in sorted(artefakte):
    print(f"  {name:<24} {artefakte[name]}")
if befunde:
    print(f"ABBRUCH: {len(befunde)} Befund(e): {befunde}", file=sys.stderr)
    raise SystemExit(1)
for name in ("l1.adjudicated", "metadata.draft", "metadata.confirmed", "abstract.draft",
             "abstract.confirmed", "release.preview", "release.approved", "export.bundle"):
    if artefakte.get(name) == "READY":
        raise SystemExit(f"ABBRUCH P3: alte Ableitung weiterhin nutzbar: {name}")
print("  Befunde: keine")
PRUEF

# P3 / ADR 0027: Erst die vollständig erneuerte Kette darf wieder hinaus.
stufe 3 "P3: Ausgang vor Erneuerung gesperrt" \
  export "$RECORD" --output "$ARBEIT/gesperrt.bundle.json" --confirm
if [ -e "$ARBEIT/gesperrt.bundle.json" ]; then
  printf 'ABBRUCH P3: Ausgang trotz veralteter Herkunft\n' >&2
  exit 1
fi
stufe 0 "P3: Korrigierte Textfassung bestaetigen" \
  transcript confirm "$RECORD" --actor KLAUS --confirm
stufe 3 "P3: L1 und Coverage neu ableiten" continue "$RECORD" --confirm
stufe 0 "P3: Neue Vorschlaege adjudizieren" l1 review "$RECORD" --actor KLAUS --confirm
stufe 3 "P3: Metadaten neu ableiten" continue "$RECORD"
stufe 0 "P3: Neue Metadaten bestaetigen" metadata confirm "$RECORD" --actor KLAUS --confirm
stufe 3 "P3: Abstract neu ableiten" continue "$RECORD"
stufe 0 "P3: Neuen Abstract bestaetigen" abstract confirm "$RECORD" --actor KLAUS --confirm
stufe 3 "P3: Neue Freigabevorschau" continue "$RECORD"
stufe 0 "P3: Neue Kette freigeben" release approve "$RECORD" --actor KLAUS --confirm
stufe 0 "P3: Erneuerte Kette exportieren" \
  export "$RECORD" --output "$ARBEIT/erneuert.bundle.json" --confirm
"${WERKZEUG[@]}" status --json > "$ARBEIT/status-erneuert.json" || true
"$PYTHON" - "$ARBEIT/status-erneuert.json" <<'ERNEUERT'
import json, sys
record = json.load(open(sys.argv[1]))["details"]["records"][0]
assert not record["findings"], record["findings"]
assert all(a["status"] == "READY" for a in record["artifacts"].values()), record
print("P3: Vollstaendig erneuerte Kette READY")
ERNEUERT

# --------------------------------------------------------------- Entwertung
halt "Moment 4, Entwertung" "die Entwertung an der Ausgangsgrenze"
moment 4 "Eine Review-Entscheidung bindet an Bytes; eine Aenderung danach entwertet sie sichtbar."
# Gezeigt wird sie dort, wo sie heute wirklich wirkt: an der Ausgangsgrenze.
# Das Bundle traegt keine eigene Entscheidung, es ERBT die der Freigabe, und
# das Erben haelt die Belegeingabe gegen die aktuellen Bytes
# (src/ohpipe/application/replay.py::_inherit_egress_decision).
#
# Die Archivleitung gibt denselben Katalogentwurf ein zweites Mal frei. Das
# sind ANDERE Bytes — die Freigabe traegt ihren Akteur in sich —, und das
# Bundle haengt weiter an den alten. Nichts wurde geloescht, nichts
# ueberschrieben; die geerbte Zustimmung deckt das Bundle nur nicht mehr.
stufe 0 "Zweite Freigabe durch die Archivleitung" \
  release approve "$RECORD" --actor ARCHIV --confirm

abschnitt "Was die Entwertung sichtbar macht"
"${WERKZEUG[@]}" status --json > "$ARBEIT/status-danach.json" || true
"$PYTHON" - "$ARBEIT/status-danach.json" <<'ENTWERTUNG'
import json, sys
record = json.load(open(sys.argv[1]))["details"]["records"][0]
for name in ("release.approved", "export.bundle"):
    eintrag = record["artifacts"].get(name, {})
    print(
        f"  {name:<18} {eintrag.get('status'):<14} "
        f"Entscheidung {eintrag.get('decision_state')}"
    )
print(f"  Befunde: {record['findings'] or 'keine'}")
ENTWERTUNG

# Endet planmaessig mit ACTION_NEEDED. Die Statuszeile sagt den Grund in einem
# Satz, und das ist der Schluss der Vorfuehrung: der Katalogausgang steht nicht
# mehr auf einer Zustimmung, die ihn deckt.
stufe 3 "Uebersicht nach der Entwertung" status

# --------------------------------------------------------------- Der Baum
NACHHER="$(cd "$REPO" && git status --porcelain 2> /dev/null || true)"
abschnitt "Repository unveraendert"
if [ "$VORHER" != "$NACHHER" ]; then
  printf 'ABBRUCH: der Lauf hat den Baum veraendert.\n' >&2
  diff <(printf '%s\n' "$VORHER") <(printf '%s\n' "$NACHHER") >&2 || true
  exit 1
fi
printf 'git status unveraendert; alles Geschriebene liegt unter %s\n' "$OHPIPE_DATA_ROOT"

printf '\nDurchstich vollstaendig.\n'
