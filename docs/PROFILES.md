# Profiles and manual review

A profile defines identifiers, processing routes, model vocabulary and workflow requirements. Its presence in the package is a configuration example, not operational approval.

| Profile | Role in this preview |
|---|---|
| `sandbox` | Invented demonstration material and recorded responses. Pseudonymisation is not required. |
| `spur-p-manual` | Synthetic tests of manual marking, case review, entity resolution and final-text review. Requires a journal key and configured protected stores. |
| `walz-pilot-pseudo` | Historical configuration retained for compatibility tests of the manual path. Not a generic project setup. |
| `walz` | Legacy configuration without a pseudonymisation gate. Not recommended as a new-project template. |
| `childlux` | Legacy configuration with an unimplemented model-based pseudonymisation handler. Not an operational path. |

Generic profiles can be supplied with `--profile /path/to/profile.toml`. The manual implementation recognizes a closed set of profile identities; an arbitrary TOML file does not extend it. Generalizing this binding is future work.

The manual path separates four stages:

1. Mark material and review the markings.
2. Review cases and explicitly resolve entities. A suggested match is not an accepted identity.
3. Apply configured deterministic transformation rules.
4. Review the resulting text before descriptive processing.

Saving a session is not acceptance. Finalizing text is not its review. Registers and protected artifacts have configuration, integrity and recovery checks described in [Testing](TESTING.md).

Integration tests use invented names, random markers and temporary stores. They do not provide a production setup guide or evidence about identification accuracy. Explore the general workflow with the sandbox quickstart; assess operational configurations within the project's existing governance process.
