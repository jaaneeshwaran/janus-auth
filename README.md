# Janus-Auth

**SMT-Guided Counterfactual Differential Compiler for API Authorization Lifecycles.**

Janus-Auth compiles an independently approved **Cedar** policy and an **OpenAPI 3.1 + operation-mapping
manifest** into minimal **Counterfactual Twin Workflows** using the **Z3 SMT solver**, executes both
branches against an authorized target, and adjudicates the outcome with a **4-dimensional differential
effect matrix**. It proves two things at once: that a revoked grant leaves **no residual access**, and
that the revocation did **not** break a legitimate surviving grant.

> **Status:** MVP complete (Phases 0–4). `PROJECT_SPEC.md` is the binding specification;
> `IMPLEMENTATION_PLAN.md` is the normalized execution plan. The Phase 5 landing page lives in
> `site/`.

---

## The problem

Black-box authorization scanners replay requests across identities and flag any `200 OK`. On real
multi-tenant APIs, access is composable: ownership, direct user shares, group grants, one-hop
delegations, and admin roles can all grant the same permission, with explicit denies overriding
them. A naive scanner cannot tell *legitimate surviving access* from *residual access after a
revocation*, so it produces false positives on shared resources and misses stale-cache and
incomplete-revocation bugs. It also misses "silent write" defects, where an endpoint returns
`403 Forbidden` **after** mutating state.

## Architecture

| Stage | Module | Responsibility |
|---|---|---|
| CLI | `janus_auth.cli` | `validate`, `propose-mapping`, `approve-manifest`, `compile`, `run`, `benchmark`, `demo`. |
| Compiler | `janus_auth.compiler` | Z3 synthesis of counterfactual twins + mapping of abstract pairs to concrete HTTP step sequences. |
| Oracle | `janus_auth.oracle` | Authoritative Cedar evaluation (`cedarpy`) and the 4D effect-witness adjudicator. |
| Runner | `janus_auth.runner` | Isolated dual-branch execution through the safety gate, plus the pair-preserving delta-debugging minimizer. |
| Security | `janus_auth.security` | `SafetyGatekeeper` (SSRF, host allowlist, budget, no-redirect), `Redactor`, encrypted `TraceStore`. |
| Reporting | `janus_auth.reporting` | SARIF 2.1.0 export and standalone, credential-free pytest replay witnesses. |
| Targets | `janus_auth.targets` | Self-contained `DocVault` FastAPI service with switchable lifecycle-bug modes. |
| Benchmark | `janus_auth.benchmark` | Head-to-head comparison against three baselines/ablations across all target modes. |

**The core idea.** For a target transition `e*` (revoke a direct share, remove a group member, revoke a
delegation, downgrade a role, transfer ownership, change tenant membership), Z3 solves for two initial
authorization states that differ by **exactly one support tuple** and that both grant access before
`e*`:

- **Branch A — last-grant:** `e*` removes the only remaining support, so access must be denied.
- **Branch B — surviving-grant:** one independent support survives `e*`, so access must still be allowed.

Both branches execute the **identical** transition and the **identical** probe against isolated,
resettable target instances. Verdicts are derived from canary-field projection, post-probe state
witnesses, and the surviving-grant control — never from HTTP status codes alone. When the policy or the
propagation bounds are underspecified, the tool abstains (`UNCERTAIN_ABSTAIN`) instead of guessing.

## Quickstart

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -c "import janus_auth; print(janus_auth.__version__)"   # 0.1.0
.venv/bin/janus-auth demo --out-dir artifacts/demo/
```

Quality gates (or equivalently `make lint`, `make typecheck`, `make test`):

```bash
.venv/bin/ruff check src/ tests/
.venv/bin/mypy src/
.venv/bin/pytest -v
```

## CLI surface

| Command | Purpose |
|---|---|
| `janus-auth validate` | Validate the OpenAPI spec, Cedar policy, and manifest signature. |
| `janus-auth propose-mapping` | Draft an operation mapping. Always emitted as `approved: false`. |
| `janus-auth approve-manifest` | Sign and approve a verified manifest (approval lock). |
| `janus-auth compile` | Compile counterfactual twin plans offline (Z3 synthesis, Cedar cross-check). |
| `janus-auth run` | Execute the twin suite against an authorized target and adjudicate the verdicts. |
| `janus-auth benchmark` | Compare Janus-Auth against three baselines/ablations over all target modes. |
| `janus-auth demo` | Run the complete end-to-end showcase in one command. |

## Security boundary

This is a defensive verification tool for systems you own or are explicitly authorized to test.

- **Scope.** Execution is restricted to `127.0.0.1`, `localhost`, and `testserver` unless a signed
  `ScopeManifest` explicitly allowlists a host, and every run requires an approved, signed manifest.
- **Gatekeeping.** Every outbound request passes `SafetyGatekeeper.validate_request()`: `http`/`https`
  only, allowlisted hostname, SSRF blocking for link-local metadata and multicast ranges, no redirect
  following, a hard request budget and rate limit, and `DELETE` permitted only on declared transition
  endpoints.
- **No real data.** Only synthetic principals (`ada`, `bea`, `carl`, `dana`) and synthetic canary markers
  are used. No credentials, personal data, or production endpoints are required.
- **No secret leakage.** Authorization headers, cookies, API keys, and JWT patterns are redacted from
  every persisted artifact; exported replay witnesses read tokens from `os.environ` only. Traces are
  encrypted at rest and purged after `JANUS_RETENTION_DAYS`.
- **Non-authoritative AI.** The optional mapping assistant never receives tokens or live responses, always
  emits `approved: false`, and the compiler refuses any manifest that is unapproved or badly signed.
- **Deterministic and offline.** The compiler, runner, adjudicator, and minimizer require no LLM API keys
  and no network access beyond the authorized target.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `JANUS_SIGNING_SECRET` | local development fallback (override in CI) | HMAC-SHA256 key used to sign and verify scope manifests. |
| `JANUS_TRACE_ENCRYPTION_KEY` | ephemeral per-session key | Fernet key for encrypted trace blobs. |
| `JANUS_RETENTION_DAYS` | `7` | Retention window for stored traces. |
| `JANUS_Z3_TIMEOUT_MS` | `5000` | Hard solver timeout per obligation. |
| `JANUS_MAX_REQUESTS` | `500` | Hard ceiling on HTTP requests per run. |

## Repository layout

```text
janus-auth/
├── configs/                 # Cedar policy, scope manifest, OpenAPI description
├── src/janus_auth/          # package root (security, oracle, compiler, runner, reporting, targets, benchmark)
└── tests/                   # unit/, integration/, security/
```

## License

MIT — see `LICENSE`.
