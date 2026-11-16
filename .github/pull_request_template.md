## Summary

<!-- What changed, and why? -->

## Change type

- [ ] Bug fix
- [ ] Feature
- [ ] Documentation
- [ ] Security hardening
- [ ] Refactor or test

## Checks

- [ ] `ruff check src/ tests/` passes
- [ ] `mypy src/` passes
- [ ] `pytest -q` passes
- [ ] `janus-auth demo --out-dir artifacts/demo/` succeeds
- [ ] No secrets or generated artifacts are committed

## Security and evidence

- [ ] The gatekeeper, redactor, Cedar cross-check, pair-preservation invariant, or Branch B control is unchanged, or the change is justified below.
- [ ] New external inputs are typed and validated.
- [ ] New behavior has a test that fails before the change.

## Notes

<!-- Spec deviations, follow-ups, or anything a reviewer should know. -->