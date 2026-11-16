# Contributing to Janus-Auth

Thanks for considering a contribution. Janus-Auth is a security tool, so the bar for changes is deliberately high: behavior must stay deterministic, evidence must stay pair-preserving, and every new claim needs a test.

## Before you start

- Read [`PROJECT_SPEC.md`](PROJECT_SPEC.md). It is the binding specification.
- Read [`docs/architecture.md`](docs/architecture.md) for the module boundaries.
- For security issues, do **not** open a public issue. Follow [`SECURITY.md`](SECURITY.md).

## Development setup

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e ".[dev]"
```

Run the gates:

```bash
.venv/bin/ruff check src/ tests/
.venv/bin/mypy src/
.venv/bin/pytest -q
```

The full demo is a good end-to-end check:

```bash
.venv/bin/janus-auth demo --out-dir artifacts/demo/
```

## Ground rules

1. **Do not weaken a security invariant to make a test pass.** The gatekeeper, redactor, Cedar cross-check, pair-preservation invariant, and Branch B control are load-bearing.
2. **Keep external inputs typed.** New manifests, OpenAPI fields, traces, or CLI inputs belong in a Pydantic model or a typed dataclass.
3. **Keep the modules separate.** Cedar evaluation, Z3 synthesis, HTTP execution, adjudication, and reporting should not become a single orchestration blob.
4. **No hidden network or filesystem work at import time.**
5. **No secrets in code, fixtures, reports, or generated witnesses.** Replay scripts read credentials from `os.environ`.
6. **Use parameterized SQL** and `yaml.safe_load()` after a size check.
7. **Write tests for behavior, not implementation.** Security tests should try to break the invariant, not restate the happy path.

## Tests

- Unit tests: `tests/unit/`
- Integration tests: `tests/integration/`
- Security tests: `tests/security/`

New behavior needs a test that fails before the change. New security behavior needs an adversarial test.

## Style

- Python 3.12+, strict type annotations on public functions.
- `ruff` with line length 100.
- `mypy src/` must pass.
- No `Any` where a Pydantic model or typed dataclass applies.
- Prefer small, pure functions.
- No comments unless the surrounding code clearly needs them; the codebase favors names and docstrings over inline narration.

## Commits

Use Conventional Commits:

```text
feat(compiler): ...
fix(security): ...
test(adjudicator): ...
docs(readme): ...
```

Keep the subject imperative and under about 70 characters. Describe the behavior change, not the file list.

## Pull requests

A PR should include:

- a short summary of the behavior change;
- the tests you added or updated;
- the commands you ran (ruff, mypy, pytest, demo);
- a note on any security or evidence-model impact;
- a note on any specification deviation.

Do not commit generated artifacts, trace databases, `.venv`, or local secrets. `artifacts/` is ignored for a reason.

## Review

Review is open. Expect questions about the evidence model, determinism, and the security boundary. A change that makes the tool more permissive needs a stronger justification than one that makes it more precise.

## License

By contributing, you agree that your contribution is licensed under the MIT license in [`LICENSE`](LICENSE).