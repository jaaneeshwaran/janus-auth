# Spec-to-Code Compliance Report — Janus-Auth MVP

**Specification:** `PROJECT_SPEC.md` (binding), plus the normalized `IMPLEMENTATION_PLAN.md`
and rulings R1–R12 in `.superpowers/sdd/janus-auth/progress.md`.
**Code baseline:** `feat/janus-auth-mvp` after Tasks 7–13 and the polish pass.
**Method:** 32 atomic requirements extracted from §§9–13, 15 and the AGENTS charter. Each was
read against its enforcement path and its tests; two independent read-only audits covered the
security/CLI and pipeline halves, and every divergence they raised was re-checked in the code
before classification.

**Verdict counts:** implemented 27, partial 1, absent 2, stronger-than-spec 2, contradicted 0.

| ID | Requirement | Verdict | Evidence |
|---|---|---|---|
| S1 | Every runner request, including reset, passes `SafetyGatekeeper.validate_request()` before the client sees it. | implemented | `runner/executor.py` `_admit`/`_send`; executor refuses redirect-following clients. |
| S2 | Gatekeeper enforces http(s), host allowlist, metadata/link-local/multicast/unspecified blocking, budget, rate limit, and DELETE-only-on-declared endpoints. | implemented | `security/gatekeeper.py`; adversarial and unit tests. |
| S3 | YAML uses `yaml.safe_load()` after a 5 MiB ceiling; no `yaml.load`, `pickle`, `eval`, or `exec`. | implemented | `compiler/compiler.py`; `rg` over `src/` finds no banned calls (Z3 `model.eval` is the solver API). |
| S4 | Every SQLite statement is parameterized. | implemented | `security/store.py`; all values use `?`, only static DDL/PRAGMA are literal. |
| S5 | Compiler and runner refuse unapproved or badly signed manifests. | implemented | `compiler.py` `_require_approved_manifest`; `cli.py run` now checks `approved` and the HMAC. |
| S6 | `propose-mapping` always emits `approved: false`. | stronger-than-spec | Mapper returns false, the model validator rejects true, and the CLI reasserts false. |
| S7 | SARIF and replay witnesses contain no raw tokens; witnesses read credentials from `os.environ`. | implemented | `reporting/sarif.py`, `reporting/replay_codegen.py`, CLI artifact token test. |
| S8 | Traces are redacted, Fernet-encrypted, retained for `JANUS_RETENTION_DAYS`, and persisted by the CLI. | implemented | `security/store.py`; `cli.py run`/`demo` open `TraceStore`, record runs and verdicts; CLI test decrypts 12 verdicts. |
| S9 | Seven CLI commands with exit codes 0/1/2. | implemented | `cli.py`; CLI and adversarial tests. |
| S10 | `approve-manifest` records approver and expiry, signs, rewrites, then re-verifies. | implemented | `cli.py approve-manifest`; `ScopeManifest.sign/verify_signature`. |
| P1 | DocVault exposes 15 paths / 16 operations and seven modes. | implemented | `targets/docvault_app.py`; route and mode tests. |
| P2 | Each seeded mode injects one intended defect; clean mode has zero findings. | implemented | Mode tests; clean pipeline adjudicates only `CONFORMS`/`CONFORMS_MASKED`. |
| P3 | Executor resets before each branch, records epochs, and isolates placeholder contexts. | implemented | `runner/executor.py`; all 12 plans run from later Branch B epochs. |
| P4 | Adjudicator implements every §9.3.3 row, including inverted enforcement. | implemented | `oracle/adjudicator.py`; 15 unit tests plus real-pipeline mode tests. |
| P5 | Minimizer removes noise while preserving the verdict/subtype and Branch B control; essential steps are pinned. | implemented | `runner/minimizer.py`; unit and real silent-write tests (31 → 17 steps). |
| P6 | SARIF 2.1.0 with JANUS001–JANUS006, confirmed findings only, both branch summaries, policy/manifest locations. | implemented | `reporting/sarif.py`; SARIF tests. |
| P7 | Benchmark has four methods, seven modes plus masked/surviving controls, and the seven measured metrics. | implemented | `benchmark/`; coverage is now derived from per-method evidence availability, not hardcoded. |
| P8 | Z3 cross-checks every state through cedarpy and raises on divergence. | implemented | `z3_synthesizer.py`; compiler tests. |
| P9 | 10 feasible Hamming-1 pairs and 38 infeasible obligations (48 cells). | implemented | `z3_synthesizer.py`; 48-cell tests. |
| P10 | Demo runs clean + six modes, minimizes, exports SARIF/witnesses, and prints the benchmark table. | implemented | `cli.py demo`; demo artifact test. |
| M1 | External inputs use Pydantic v2 with `extra="forbid"` and strictness where applicable. | implemented | `models.py` `StrictModel`; request bodies. |
| M2 | `ruff check src/ tests/` and `mypy src/` pass with line length 100. | implemented | 264-test gate; clean on 26 source files. |
| M3 | No hardcoded secrets; only synthetic principals and canaries. | implemented | Tokens are synthetic test constants; signing secret comes from env with the documented dev fallback. |
| M4 | Default target allowlist is localhost/127.0.0.1/testserver. | implemented | `ScopeManifest.allowed_hosts` defaults; CLI SSRF test. |
| M5 | httpx clients use a 5 s timeout and never follow redirects. | implemented | `cli.py` live client; executor guard; redirect test. |
| M6 | `JANUS_MAX_REQUESTS` caps a run; the signed manifest also caps each gatekeeper. | implemented | CLI uses `Settings.max_requests` when `--budget` is omitted; gatekeeper enforces the manifest ceiling. |
| M7 | `JANUS_Z3_TIMEOUT_MS` bounds synthesis. | implemented | `cli.py _compile`/`demo` construct `Z3Synthesizer(timeout_ms=settings.z3_timeout_ms)`. |
| M8 | Retention purge runs on store open. | implemented | `TraceStore._purge_expired`. |
| M9 | GDPR/DPDP posture: synthetic data only, redacted headers, encrypted TTL traces. | implemented | Redactor + TraceStore + synthetic fixtures. |
| M10 | Expected: Phase 5 landing page in `site/`. | partial | Implemented in the final step of this plan; see `site/`. |
| M11 | Pinned `schemathesis==4.33.3` dev dependency. | absent | Present in `pyproject.toml`, not used by any test; the specification does not require a Schemathesis suite. Low-severity dependency drift. |
| M12 | Optional AST fallback if the cedarpy wheel is unavailable. | absent | No fallback evaluator exists; cedarpy is a hard dependency. Low-severity risk-mitigation gap (R-05). |
| M13 | README describes the delivered status. | implemented | Status updated to MVP complete; CLI table and env vars match the code. |
| M14 | Target behavior not mentioned in §9.4.2. | stronger-than-spec | `GET /api/v1/documents` list route exists in the OpenAPI file but not in the §9.4.2 operation table; benign and documented in the schema. |
| M15 | Reset isolation with UUID-namespaced resources (R-04). | stronger-than-spec | DocVault uses deterministic ids but resets state and verifies a monotonic epoch for every branch; isolation is proven by the epoch witness rather than UUIDs. |
| M16 | `consistency_bound_ms` supports asynchronous revocation delays (R-03). | implemented | Executor sleeps the declared bound immediately before the probe; post-transition witnesses are mandatory. |

## Divergences and disposition

1. **S5 — runner accepted signed-but-unapproved manifests (Important, fixed).** `cli.py run`
   now rejects `approved != true` before execution, and the adversarial test
   `test_run_rejects_a_signed_but_unapproved_manifest` covers it.
2. **P7 — `decision_coverage` was hardcoded (Important, fixed).** Baselines now expose
   `covers(evidence)`, and the evaluator measures coverage per case.
3. **P10 — demo did not print the benchmark table (Important, fixed).** `demo` now calls the
   same `_print_benchmark_table` helper as the `benchmark` command.
4. **S8 — CLI did not persist traces (Critical, fixed).** `run` and `demo` open a `TraceStore`,
   record one run row per mode, and write encrypted verdict traces. A CLI test decrypts the
   stored verdicts with the configured key.
5. **M7 / M8 / S10 — configuration wiring and approval expiry (Important, fixed).** Z3 timeout,
   trace retention/encryption, `JANUS_MAX_REQUESTS`, and a seven-day approval expiry are now
   wired and tested.
6. **M11 — unused Schemathesis dependency (Minor, documented).** No acceptance criterion
   depends on it; leave installed for future contract fuzzing, or remove it in a dependency
   cleanup commit.
7. **M12 — no AST fallback (Minor, documented).** The MVP requires cedarpy; a fallback evaluator
   would duplicate the authoritative Rust oracle and is deliberately out of scope.

## Gate evidence

```text
.venv/bin/pytest -q                264 passed
.venv/bin/ruff check src/ tests/   All checks passed
.venv/bin/mypy src/                Success: no issues found in 26 source files
janus-auth demo                    findings=15, minimization 31 -> 17, artifacts complete
```

## Reverse-direction findings

- `GET /api/v1/documents` (M14) and the reusable `TraceStore.fetch_run_ids` helper are code
  with no direct §9.4.2 mandate; both are documented and used.
- The benchmark records a per-case `coverage` map, which is a stronger artifact than the
  specification's single metric line.
