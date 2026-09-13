# Bundled profile examples

`sandbox` is the synthetic quickstart profile. `spur-p-manual` supports synthetic tests of the manual workflow. Other named configurations are retained for compatibility tests and do not authorize operational processing.

The `production` field selects stricter configuration requirements; it does not certify this preview as production-ready. `walz` has no pseudonymisation gate; `childlux` has an unimplemented model-based pseudonymisation path.

Project profiles can be supplied by file path. The manual runtime currently recognizes a closed set of profile identities, so arbitrary new manual profiles need implementation work. See `docs/PROFILES.md` in the source distribution.
