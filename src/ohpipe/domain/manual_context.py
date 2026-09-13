"""Geschlossene Manualdomänen: synthetischer Pfad und ausdrücklich beauftragter WALZ-Pilot."""

import re

PROFILES = {
    "spur-p-manual": ("SPURP", 3, "spur-p-synthetic", False),
    "walz-pilot-pseudo": ("WALZ", 4, "walz-pilot-pseudo", True),
}


def known(value):
    return isinstance(value, str) and value in PROFILES


def record(value, profile=None):
    if not isinstance(value, str):
        return False
    names = (profile,) if known(profile) else () if profile is not None else PROFILES
    return any(re.fullmatch(rf"{PROFILES[p][0]}-[0-9]{{{PROFILES[p][1]}}}", value) for p in names)


def enabled(profile):
    if not known(profile.id):
        return False
    prefix, digits, _, production = PROFILES[profile.id]
    return (
        profile.record_prefix == prefix
        and profile.record_digits == digits
        and profile.production is production
        and profile.key_required
        and profile.pseudonymisation_required
        and profile.pii_detection == "manual"
    )
