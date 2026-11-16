# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes yet.

## [0.1.0] - 2026-11-16

First public MVP. The pipeline compiles counterfactual twin plans from a Cedar policy and a signed scope manifest, executes both branches against a reference target, adjudicates the difference with four-dimensional witnesses, and exports SARIF plus standalone pytest replay files.

### Added

- Typed Pydantic v2 artifact model and strict configuration.
- HMAC-SHA256 scope-manifest approval and verification.
- Gatekeeper with scheme, host, SSRF, redirect, budget, rate-limit, and destructive-method checks.
- Redactor and encrypted SQLite trace store with retention.
- Authoritative Cedar evaluator and typed policy-divergence errors.
- Z3 twin synthesizer with Hamming-distance-1 support, cedarpy cross-checks, and 48-cell coverage.
- Workflow compiler with deterministic plan IDs, a masked control, and a delegation-cascade realization.
- Heuristic operation mapper with a hard `approved: false` boundary.
- DocVault reference target with fifteen paths, sixteen operations, and seven enforcement modes.
- Isolated dual-branch executor with per-branch resets and epoch witnesses.
- Four-dimensional adjudicator covering conforms, confirmed violations, masked projections, access regressions, abstentions, invalid tests, and inverted enforcement.
- Pair-preserving ddmin minimizer.
- SARIF 2.1.0 exporter with six rules and standalone pytest replay codegen.
- Four-method benchmark with measured recall, false positives, silent-write detection, regression detection, coverage, selective error, and witness length.
- Typer CLI with `validate`, `propose-mapping`, `approve-manifest`, `compile`, `run`, `benchmark`, and `demo`.
- Static project landing page and README visual system.
- Unit, integration, and security test suites; ruff and mypy gates.

### Security

- No hardcoded production credentials; replay files read from the environment.
- Signed-manifest-only compilation and execution.
- All outbound requests, including reset, pass the gatekeeper.
- Traces are redacted and encrypted at rest.
- YAML is size-limited and parsed with `yaml.safe_load()`.
- SQLite uses parameterized statements.

### Known limitations

- The mapper is heuristic and non-authoritative.
- The optional Cedar AST fallback is not implemented; `cedarpy` is required.
- The benchmark covers one reference target.