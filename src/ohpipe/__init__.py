"""ohpipe — Oral-History-Pipeline.

Kleiner generischer Kern, Projektprofile, klar abgegrenzte Adapter.
Reale Daten und Governance-Zustand liegen niemals im Repository.
"""

__version__ = "0.1.0.dev0"

import sys as _sys

if _sys.version_info < (3, 11):  # noqa: UP036  # pragma: no cover
    raise RuntimeError(
        f"ohpipe braucht Python 3.11 oder neuer (gefunden: "
        f"{_sys.version_info.major}.{_sys.version_info.minor}). "
        "Grund ist tomllib aus der Standardbibliothek. "
        "Ein ImportError mitten im Import ist die schlechtere Fehlermeldung."
    )
# UP036 will diesen Block entfernen, weil requires-python bereits 3.11 sagt.
# Genau darum geht es aber: Eine Deklaration in pyproject.toml hindert niemanden
# daran, das Paket mit einem aelteren Interpreter zu importieren.
