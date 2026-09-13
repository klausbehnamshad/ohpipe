#!/usr/bin/env python3
"""Neue private WALZ-Pilotablage; Realmodus bleibt bis zum Start-OK unbenutzt."""

import argparse
import json
import os
from pathlib import Path
import secrets

from ohpipe.domain.manual_context import PROFILES
from ohpipe.protected_store import canonical, digest, disjoint

REPO = Path(__file__).resolve().parents[1]
PROFILE = REPO / "src/ohpipe/profiles/walz-pilot-pseudo/profile.toml"
MODEL_DIGEST = "6577803aa9a036369e481d648a2baebb381ebc6e897f2bb9a766a2aa7bfbc1cf"
# Ausschließlich erfundene Testoberflächen; WALZ-9001 ist KEINE Pilotrecordauswahl.
RECORD = "WALZ-9001"
TEXT = "Testperson Zeta arbeitete 1950 im Testverein Nord am Testinstitut Süd in Teststadt. Kontakt test@example.invalid Kennung TEST-ID-42."
MARKS = [
    ("Testperson Zeta", "PERSON"),
    ("Testverein Nord", "ORGANISATION"),
    ("Testinstitut Süd", "INSTITUTION"),
    ("Teststadt", "LOCATION"),
    ("1950", "DATE"),
    ("test@example.invalid", "CONTACT"),
    ("TEST-ID-42", "IDENTIFIER"),
]


def model_text(host="http://127.0.0.1:11434", model_digest=MODEL_DIGEST):
    return f'''[model]
runtime = "ollama"
host = "{host}"
model = "mistral:7b-instruct"
model_digest = "{model_digest}"
temperature = 0.0
seed = 7
num_ctx = 8192
num_predict = 4096
max_chars = 12000
timeout_s = 600
repeat_probe = true
block_size = 64
'''


def prepare(root, *, real=False):
    root = Path(root)
    if not root.is_absolute() or root.is_symlink() or root.exists():
        raise ValueError("Neue absolute Pilotwurzel erforderlich; kein Überschreiben")
    root = root.resolve()
    for forbidden in (REPO, REPO.parent / "ohpipe", REPO.parent / "ohpipe-bau-16-09"):
        disjoint(root, forbidden)
    root.mkdir(mode=0o700)
    for name in (
        "secrets",
        "data",
        "protected",
        "protected/objects",
        "protected/sessions",
        "registry",
        "registry/objects",
        "source",
    ):
        (root / name).mkdir(mode=0o700)

    def write(name, raw):
        p = root / name
        with p.open("xb") as f:
            os.chmod(p, 0o600)
            f.write(raw)
        return str(p)

    keys = {
        k: write(f"secrets/{k}.key", secrets.token_bytes(32))
        for k in ("journal", "protection", "registry", "candidate")
    }
    protection = dict(
        v=1,
        root=str(root / "protected"),
        key_file=keys["protection"],
        key_id=secrets.token_hex(16),
        store_id=secrets.token_hex(16),
    )
    registry = dict(
        v=1,
        root=str(root / "registry"),
        workspace=digest(os.fsencode((root / "data").resolve())),
        profile="walz-pilot-pseudo",
        scope=PROFILES["walz-pilot-pseudo"][2],
        key_file=keys["registry"],
        key_id=secrets.token_hex(16),
        candidate_key_file=keys["candidate"],
        candidate_key_id=secrets.token_hex(16),
        registry_id=secrets.token_hex(16),
    )
    env = {
        "OHPIPE_JOURNAL_KEY": keys["journal"],
        "OHPIPE_PROTECTION_CONFIG": write("secrets/protection.json", canonical(protection)),
        "OHPIPE_REGISTRY_CONFIG": write("secrets/registry.json", canonical(registry)),
    }
    if not real:
        source = "1\n00:00:00,000 --> 00:00:10,000\nSYNTHETIC: " + TEXT + "\n"
        write("source/synthetic.srt", source.encode())
    write("source/iso.txt", b"deu\nfra\nltz\neng\nund\nzxx\n")
    if real:
        (root / "data/_governance").mkdir(mode=0o700)
        model_config = write("data/_governance/model.toml", model_text().encode())
    else:
        model_config = write("model.toml", model_text().encode())
    descriptor = dict(
        synthetic_only=not real,
        real_record_selected=False,
        root=str(root),
        profile=str(PROFILE),
        record=None if real else RECORD,
        environment=env,
        model_config=model_config,
    )
    descriptor_name = "real-setup.json" if real else "synthetic-setup.json"
    write(descriptor_name, canonical(descriptor))
    return descriptor


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--real",
        action="store_true",
        help="leere Realablage ohne Record- oder Quellauswahl erzeugen",
    )
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    result = prepare(args.root, real=args.real)
    descriptor = "real-setup.json" if args.real else "synthetic-setup.json"
    print(
        json.dumps(
            {"synthetic_only": result["synthetic_only"], "descriptor": str(args.root / descriptor)},
            indent=2,
        )
    )
