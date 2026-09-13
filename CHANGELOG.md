# Changelog

## 0.1.0a1 — public preview candidate, 2026-09-13

- Introduce a public checkout with a synthetic demonstration and documented scope.
- Prevent unauthenticated disposition events from conferring exclusion.
- Require previously produced artifact bytes before an anchor outcome can bind.
- Check artifact membership in the profile graph before record exclusion takes effect.
- Recheck the selected human, relevant selection history, transcript revision and intervening confirmations under the writer lock before confirmation effects.
- Add authenticated interleaving, competing-plan and storage-placement regression checks.
- Package the metadata model and attribution as resources usable outside the checkout.
- Replace a historical Git-object dependency with a portable graph/profile reference.

The full historical test suite still has known failures. This is not a fully validated production release; see [Testing](docs/TESTING.md).
