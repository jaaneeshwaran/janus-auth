# Janus-Auth — Normalized Implementation Plan (SDD Execution Copy)

**Binding specification:** `PROJECT_SPEC.md` (the authority where this plan differs). Every conflict is ruled on below.

**Repository:** this repository
**Runtime:** Python 3.12.2, local `.venv`, `pip install -e ".[dev]"`
**Execution mode:** continuous, 13 tasks, per-task review, hard phase gates, final whole-branch review, then the landing page.
**Hallmark:** landing page only (Phase 5), never for the Python CLI, SARIF, JSON, or Markdown artifacts.

## Global Constraints

- Python 3.12+ with strict annotations. `mypy src/` must pass with zero errors.
- `ruff check src/ tests/` must pass with zero errors; line length 100; Ruff security rules `S` enabled; ignore `S101` in tests.
- Every external input model uses Pydantic v2 `ConfigDict(extra="forbid", strict=True)` where the spec says so.
- No hardcoded credentials. Exported replay scripts read tokens from `os.environ`.
- Every outbound request passes `SafetyGatekeeper.validate_request()`.
- `httpx` clients use `follow_redirects=False` and a 5.0 s timeout.
- YAML only through `yaml.safe_load()` with a 5 MB ceiling. No `yaml.load`, `pickle`, `eval`, or `exec`.
- SQLite only through parameterized `?` queries.
- The compiler refuses any manifest with `approved != true` or an invalid HMAC signature.
- Never weaken the gatekeeper, redactor, Cedar cross-check, or an acceptance test to make a phase pass.
- Conventional Commits: `feat(compiler):`, `feat(oracle):`, `fix(security):`, `test(adjudicator):`, etc.
- The final landing page uses Hallmark. All other artifacts do not.
- "Stop after each phase" in the spec's AGENTS.md is superseded by the user's chosen continuous execution; phase gates still block progress on failure.

## Preflight Rulings

| # | Conflict | Ruling |
|---|---|---|
| R1 | Spec task IDs (`P0-T1`) break the SDD brief extractor, which reads only `P0`. | Keep the spec as authority; this plan uses `## Task 1` … `## Task 13` headings. |
| R2 | §9.5.1 `CounterfactualPairPlan` has no HTTP step lists; P1-T3 requires concrete sequences. | Add `CompiledTwinPlan` with `branch_a_steps` and `branch_b_steps`; leave the synthesis schema unchanged. |
| R3 | §9.3.1 defines raw-variable Hamming distance, but delegation revocation can toggle two flags. | Measure distance over the five support predicates (owner, direct, group, delegation, admin). Enforce exactly 1 for every feasible twin. `hamming_distance == 2` is allowed only for a documented abstention, never a normal twin. |
| R4 | §10 blocks DELETE on primary resource paths, which would block the three revocation transitions. | The signed manifest declares `transition_endpoints`; the gatekeeper permits DELETE only on those paths, and permits the reset endpoint only when declared. |
| R5 | Cedar default-denies, so a missing permit is DENY, not UNKNOWN. | UNKNOWN only when the action is outside the approved action catalogue or the policy uses a clause the encoder does not support. |
| R6 | The spec says masked public summaries exist but defines no trigger. | `GET /api/v1/documents/{doc_id}?masked=true` returns `200` with `secret_content: null`; the compiler emits a dedicated masked control plan. |
| R7 | `token_admin` uses `user_id=" ops_admin"` with a leading space. | Use `ops_admin`. |
| R8 | §15 pins `requires-python = ">=3.11"` while Assumption 1 says 3.12+. | Set `requires-python = ">=3.12"`; the local interpreter is 3.12.2. |
| R9 | The spec has no reset contract for live targets without `/admin/reset`. | The manifest declares `reset_endpoint`; if absent, each branch uses unique resources and the executor records `INVALID_TEST` when preconditions cannot be proven. DocVault always declares reset. |
| R10 | Z3 `Optimize` can return different optimal models across runs. | Two-stage deterministic optimization: first minimize support-predicate distance, then minimize the count of pre-state supports, then apply a fixed lexicographic tie-break over variable names. |
| R11 | AGENTS.md says stop after each phase; the user chose continuous execution. | Continuous with hard phase gates and a report after each phase; stop only on a genuine blocker. |
| R12 | Hallmark's global-skill rule could be read as applying to CLI/report work. | Hallmark applies only to the Phase 5 landing page. Security review uses spec-to-code compliance; testing uses pytest. |

## Execution Protocol

1. Init git at the repository root, copy the specification to `PROJECT_SPEC.md`, write `AGENTS.md`, create `.gitignore`, and make the initial commit.
2. Create the feature branch `feat/janus-auth-mvp`. Work there (a dedicated worktree is optional once the repo exists; do not implement on `main`).
3. Create `.venv`, install the pinned set, run the dependency smoke test.
4. For each task: record `BASE=$(git rev-parse HEAD)`, generate the task brief, dispatch one implementer, write the report file, package the diff, dispatch one task reviewer, run the fix loop, append the ledger, commit.
5. Never dispatch two implementers in parallel. Never let an implementer dispatch a reviewer. The controller owns review.
6. Phase gates: after Tasks 1–3, 4–6, 7, 8–10, and 11–13 run the phase test command plus `ruff` and `mypy`; a failing gate blocks the next phase.
7. Ledger: `.superpowers/sdd/janus-auth/progress.md` (the SDD ledger).
8. Final: whole-branch review on the strongest available model, then the spec-to-code compliance audit, then the landing page.

## Task 1: Repository Scaffolding, Packaging, and Tooling

**Spec:** §15, §16 Phase 0 / P0-T1, §17.
**Depends:** none.

**Files:** `pyproject.toml`, `Makefile`, `README.md`, `LICENSE`, `AGENTS.md`, `.gitignore`, `PROJECT_SPEC.md`, `src/janus_auth/__init__.py`, `tests/__init__.py`, `tests/conftest.py`.

**Requirements:**
- Create the full directory tree from §15, including `configs/`, `src/janus_auth/{security,oracle,compiler,runner,reporting,targets,benchmark}`, and `tests/{unit,integration,security}`.
- Pin the exact runtime dependencies from §15: `fastapi==0.163.0`, `uvicorn==0.54.0`, `pydantic==2.14.3`, `httpx==0.28.1`, `typer==0.29.1`, `rich==15.0.0`, `PyYAML==6.0.3`, `z3-solver==5.4.1.0`, `cedarpy==4.12.2`, `cryptography==50.0.2`, `networkx==3.7`.
- Dev extras: `pytest==9.2.0`, `ruff==0.17.5`, `mypy==2.4.1`, `schemathesis==4.33.3`.
- `requires-python = ">=3.12"`; script entry `janus-auth = "janus_auth.cli:app"`; MIT license.
- `[tool.ruff]` line-length 100, target py312, select `E,F,I,UP,B,S`, ignore `S101` in tests.
- `[tool.pytest.ini_options]` `pythonpath = ["src"]`.
- `AGENTS.md` copies §17, with R11 and R12 applied: continuous execution; Hallmark only for the landing page.
- `__version__ = "0.1.0"`.
- README states the architecture in one page, the quickstart, the security boundary, and the demo command. No invented benchmark numbers.

**Acceptance:** `pip install -e ".[dev]"` succeeds; `python -c "import janus_auth; print(janus_auth.__version__)"` prints `0.1.0`; `ruff check src/ tests/` passes; the package has no import-time network or filesystem side effects.

**Test command:** `.venv/bin/python -c "import janus_auth; print(janus_auth.__version__)" && .venv/bin/ruff check src/ tests/`

## Task 2: Strict Domain Models and Signed Configuration

**Spec:** §9.5, §10, §16 P0-T2.
**Depends:** Task 1.

**Files:** `src/janus_auth/models.py`, `src/janus_auth/config.py`, `tests/unit/test_models_and_security.py`.

**Requirements:**
- Enums: `Decision` (ALLOW, DENY, UNKNOWN); `TransitionFamily` (6 values from §9.5.1); `PrincipalClass` (`former_owner`, `same_tenant_peer`, `cross_tenant_principal`, `delegate_or_admin`); `ProbeType` (`protected_read`, `reversible_write`); `VerdictKind` (CONFIRMED_VIOLATION, CONFORMS, CONFORMS_MASKED, LEGITIMATE_ACCESS_REGRESSION, UNCERTAIN_ABSTAIN, INVALID_TEST); `ViolationSubtype` (NONE, BOLA_READ_LEAK, SILENT_WRITE_SIDE_EFFECT, STALE_GROUP_CACHE, FORMER_OWNER_RETENTION, BROKEN_DELEGATION_CASCADE, OVER_REVOCATION_REGRESSION, INVERTED_ENFORCEMENT).
- `SupportState` exactly as §9.5.1, with `extra="forbid"`.
- `CounterfactualPairPlan` exactly as §9.5.1.
- New `CompiledTwinPlan` (R2): `plan_id`, `synthesized: CounterfactualPairPlan`, `branch_a_steps: list[ApiStep]`, `branch_b_steps: list[ApiStep]`, `canary`, `probe_principal`, `probe_payload`, `masked_control: bool`.
- `ApiStep`: `step_id`, `method`, `path_template`, `principal_alias`, `json_body`, `query`, `extract` (mapping of placeholder to response JSON path), `expected_role` (`setup`, `pre_witness`, `transition`, `post_transition_witness`, `probe`, `effect_witness`), `reversible`.
- `StepObservation`, `BranchTrace`, `PairedExecutionEvidence`, `AdjudicationReport`, `ScopeManifest`, `MappingProposal`, `TransitionEndpoint`.
- `ScopeManifest` fields: `approved`, `approver`, `approved_at`, `policy_sha256`, `manifest_sha256`, `allowed_hosts` (default `["127.0.0.1", "localhost", "testserver"]`), `max_requests` (500), `rate_limit_rps` (50.0), `allow_destructive` (False), `reset_endpoint`, `transition_endpoints`, `principal_aliases`, `operations`, `expires_at`, `signature`.
- Canonical JSON: sorted keys, no whitespace, UTF-8. HMAC-SHA256 over the manifest without `signature`, keyed by `JANUS_SIGNING_SECRET`. `sign()` and `verify_signature()` use `hmac.compare_digest`. Reject tampered or expired manifests.
- `config.py`: typed settings for `JANUS_SIGNING_SECRET`, `JANUS_TRACE_ENCRYPTION_KEY`, `JANUS_RETENTION_DAYS` (7), `JANUS_Z3_TIMEOUT_MS` (5000), `JANUS_MAX_REQUESTS` (500).

**Acceptance:** Unknown keys raise `ValidationError`; a tampered manifest, a changed policy hash, an expired `expires_at`, or a bad signature fails verification; canonical signing is byte-stable.

**Test command:** `.venv/bin/pytest tests/unit/test_models_and_security.py -k "manifest or models" -v`

## Task 3: Safety Gatekeeper, Redactor, and Encrypted Trace Store

**Spec:** §10, §7.3, §16 P0-T3.
**Depends:** Task 2.

**Files:** `src/janus_auth/security/{__init__,gatekeeper,redactor,store}.py`, `tests/unit/test_models_and_security.py`.

**Requirements:**
- `SafetyGatekeeper` verifies the manifest signature before any request; permits only `http`/`https`; requires the hostname in `allowed_hosts`; resolves non-`testserver` hosts via `socket.getaddrinfo` and blocks `169.254.169.254`, link-local, multicast, and unspecified ranges; enforces a token-bucket rate limit and `max_requests`; raises `SSRFBlockedError`, `BudgetExhaustedError`, `RateLimitExceededError`, `ScopeViolationError`.
- DELETE policy (R4): permit DELETE only when the path matches a `transition_endpoints` entry or `allow_destructive=True`; permit the reset endpoint only when it matches `reset_endpoint`. Block all other destructive verbs on primary resource paths.
- `Redactor`: case-insensitive scrubbing of `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`; JWT regex `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`; recursive over dicts/lists/strings; idempotent.
- `TraceStore`: SQLite WAL, `runs` and `verdicts` tables exactly as §9.5.2; parameterized SQL; Fernet encryption of `encrypted_trace_blob`; ephemeral key with a warning when `JANUS_TRACE_ENCRYPTION_KEY` is unset; purge older than `JANUS_RETENTION_DAYS` on open; close cleanly.
- No secrets in logs, exceptions, or test output.

**Acceptance:** `http://169.254.169.254/latest/meta-data/`, `http://evil.example.com/api`, `file:///etc/passwd`, a redirect attempt, and a budget overrun are blocked before a socket is opened; a JWT or bearer token never appears in redacted output or plaintext SQLite; encrypted blobs round-trip with the configured key.

**Test command:** `.venv/bin/pytest tests/unit/test_models_and_security.py -v`

## Task 4: Authoritative Cedar Policy Oracle

**Spec:** §9.3.1, §11.1, §16 P1-T1.
**Depends:** Task 3.

**Files:** `configs/docvault.cedar`, `src/janus_auth/oracle/{__init__,cedar_engine}.py`, `tests/unit/test_cedar_oracle.py`.

**Requirements:**
- Cedar policy with explicit `forbid` when the principal is inactive, the tenant differs, or the principal is in `resource.explicit_denies`.
- Permit `Action::"protected_read"` and `Action::"reversible_write"` for: owner, direct grantee, active group grant, valid one-hop delegation, admin role.
- `CedarOracle.evaluate(support_state) -> Decision`: construct Cedar entities/request from `SupportState`; call `cedarpy.is_authorized`; return ALLOW/DENY. Return UNKNOWN only for an unapproved action or an unsupported clause (R5).
- Cross-check helper `evaluate_all(states)` used by the Z3 compiler.
- Start this task with a small API spike: inspect the installed `cedarpy` signature and entity schema; adapt the adapter without changing the oracle boundary. If the wheel is unavailable, implement the spec's R-05 fallback AST evaluator and record the ruling.

**Acceptance:** The full truth table passes: owner, direct, group, delegation, admin, inactive, cross-tenant, explicit deny override, missing action. A policy with a missing permit returns DENY, not UNKNOWN.

**Test command:** `.venv/bin/pytest tests/unit/test_cedar_oracle.py -v`

## Task 5: Z3 Minimum-Hamming-Distance Counterfactual Synthesizer

**Spec:** §9.3.1, §11.2, §16 P1-T2.
**Depends:** Task 4.

**Files:** `src/janus_auth/compiler/{__init__,z3_synthesizer}.py`, `tests/unit/test_z3_compiler.py`.

**Requirements:**
- Enumerate 6 transition families × 4 principal classes × 2 probe types = 48 obligations.
- Boolean variables for pre/post states of Branch A and Branch B; transition transformers: direct revoke clears `direct_grant`; group removal clears `group_grant`; delegation revoke clears `delegated_grant` and `parent_grant_valid`; role downgrade clears `admin_role`; ownership transfer clears `is_owner` for the former owner; tenant change clears `same_tenant`.
- Hard constraints: pre-state ALLOW via the targeted support in both branches; post-state A DENY; post-state B ALLOW; support-predicate distance exactly 1 (R3); B contains every A support plus the surviving support.
- Two-stage `Optimize` with `timeout=JANUS_Z3_TIMEOUT_MS` (5000 ms): minimize distance, then minimize pre-state support count, then a fixed lexicographic tie-break (R10).
- UNSAT handling: `tenant_change` and `cross_tenant_principal` may have no legal intra-tenant surviving support; record an applicability mask and, where the spec allows, a single-branch isolation obligation with a documented reason.
- Cross-check all four states (`A_pre`, `A_post`, `B_pre`, `B_post`) with `CedarOracle`; raise `PolicyEncodingDivergenceError` on disagreement.
- Every feasible pair has `hamming_distance == 1`.

**Acceptance:** All feasible pairs synthesize in under 2 seconds total; 100% pass the Cedar cross-check; infeasible obligations are explicit, not silently dropped; deterministic output across two runs.

**Test command:** `.venv/bin/pytest tests/unit/test_z3_compiler.py -v`

## Task 6: Operation Manifest, OpenAPI Spec, Mapper, and Workflow Compiler

**Spec:** §9.3.2, §9.4.2, §16 P1-T3.
**Depends:** Task 5.

**Files:** `configs/docvault_manifest.yaml`, `configs/docvault_openapi.json`, `src/janus_auth/compiler/{mapper,compiler}.py`, `tests/unit/test_z3_compiler.py`.

**Requirements:**
- OpenAPI 3.1 document covering all 16 DocVault endpoints from §9.4.2, with bearer auth and schemas.
- Manifest schema: `approved`, `approver`, `approved_at`, `policy_sha256`, `allowed_hosts`, `max_requests`, `rate_limit_rps`, `allow_destructive`, `reset_endpoint`, `transition_endpoints`, `principal_aliases` (`ada`, `bea`, `carl`, `dana`, `ops_admin`), `operations` (family → endpoint, probe paths, witness paths, masked query), `extractors`, `canary_field`, `expires_at`, `signature`.
- `HeuristicOperationMapper.propose_mapping(openapi_doc, cedar_text) -> MappingProposal` always emits `approved=False`; no LLM key and no network.
- `WorkflowCompiler.compile_suite(manifest, cedar_oracle) -> list[CompiledTwinPlan]`: refuse unapproved or bad-signature manifests; emit reset, resource creation with `JANUS_CANARY_<plan_id_hash>`, support setup, pre-transition witness, transition `e*`, post-transition permissions witness, probe `p`, post-probe owner effect witness.
- Branch A and Branch B execute the exact same transition and probe; only the single surviving-support setup step differs.
- Emit a masked control plan (`?masked=true`) for `protected_read`.

**Acceptance:** The suite compiles; every pair differs by exactly one setup step; a tampered manifest and an unapproved manifest are rejected; the generated OpenAPI validates as 3.1.

**Test command:** `.venv/bin/pytest tests/unit/test_z3_compiler.py -k "compile_suite or mapper" -v`

## Task 7: DocVault Multi-Mode Benchmark Target

**Spec:** §9.4.2, §16 P2-T1.
**Depends:** Task 6.

**Files:** `src/janus_auth/targets/{__init__,docvault_app}.py`, `tests/integration/test_docvault_modes.py`.

**Requirements:**
- FastAPI app with all 16 endpoints from §9.4.2, in-memory store, deterministic reset with an epoch counter.
- Tokens: `token_ada` (`ada`, `acme`, member), `token_bea` (`bea`, `acme`, member), `token_carl` (`carl`, `acme`, member), `token_dana` (`dana`, `globex`, member), `token_admin` (`ops_admin`, `acme`, admin).
- Document fields: `id`, `owner_id`, `tenant_id`, `title`, `public_summary`, `secret_content`; protected field is `secret_content`.
- Masked read: `GET /api/v1/documents/{doc_id}?masked=true` returns `200` with `secret_content: null` for a principal without full access (R6); full access returns the canary.
- Seven modes via `POST /api/v1/admin/reset`: `clean`, `vuln_stale_direct_cache`, `vuln_group_revocation_ignored`, `vuln_transfer_retains_owner`, `vuln_broken_delegation_cascade`, `vuln_silent_write_on_403`, `vuln_over_revocation_regression`, exactly as §16 P2-T1 describes.
- `clean` enforces owner/direct/group/delegation/admin, tenant isolation, explicit deny, no cache, authorization before mutation, and preserves surviving grants.
- Silent-write mode mutates `secret_content` before raising 403; over-revocation strips the user from groups on direct revoke; group-removal mode marks `pending_removal` and auth treats it as active; transfer mode keeps a legacy-owner allowlist; delegation mode ignores the parent's validity.
- Every mode is deterministic across resets.

**Acceptance:** All endpoints and all 7 modes pass deterministic tests via `httpx.ASGITransport`; `clean` has zero violations; each seeded mode exhibits its intended defect.

**Test command:** `.venv/bin/pytest tests/integration/test_docvault_modes.py -v`

## Task 8: Isolated Dual-Branch Sequence Executor

**Spec:** §9.2, §16 P3-T1.
**Depends:** Task 7.

**Files:** `src/janus_auth/runner/{__init__,executor}.py`, `tests/integration/test_docvault_modes.py`.

**Requirements:**
- Support live `httpx.Client(base_url=..., follow_redirects=False)` and in-process `httpx.ASGITransport(app=...)` with `base_url="http://testserver"`.
- Every request passes `SafetyGatekeeper.validate_request()`; no direct `httpx` call bypasses it.
- Resolve placeholders `{doc_id}`, `{group_id}`, `{delegation_id}`, `{canary}` from prior step responses via declared extractors.
- Execute Branch A from a clean reset; capture every `StepObservation` (status, parsed JSON, redacted headers, elapsed ms, canary presence, post-probe owner witness). Reset and execute Branch B identically. No cross-branch state.
- Verify the reset epoch before setup; if the reset or a precondition fails, mark the branch invalid.
- Store the redacted/encrypted trace in `TraceStore`; never store raw tokens.
- Enforce the request budget and rate limit.

**Acceptance:** Both branches of every compiled plan run without pollution; the gatekeeper is called on every request; a failed reset yields `INVALID_TEST`, not a false finding; traces decrypt and redact correctly.

**Test command:** `.venv/bin/pytest tests/integration/test_docvault_modes.py -k "executor" -v`

## Task 9: 4-Dimensional Differential Effect-Witness Adjudicator

**Spec:** §9.3.3, §16 P3-T2.
**Depends:** Task 8.

**Files:** `src/janus_auth/oracle/adjudicator.py`, `tests/unit/test_adjudicator.py`.

**Requirements:**
- Validity gate: setup, pre-transition witness, transition acknowledgement, and post-transition state witness must all succeed; otherwise INVALID_TEST.
- Uncertainty gate: UNKNOWN in either branch yields UNCERTAIN_ABSTAIN.
- Dimension 1 (read projection): Branch A `200` with canary when DENY is expected → CONFIRMED_VIOLATION (`BOLA_READ_LEAK`); Branch A `200` without canary and `secret_content is None` while Branch B has the canary → CONFORMS_MASKED.
- Dimension 2 (post-probe state mutation): for write probes, inspect the owner effect witness; if `secret_content == "MUTATED_BY_<principal>"` in Branch A when DENY is expected, CONFIRMED_VIOLATION (`SILENT_WRITE_SIDE_EFFECT` when the probe status is >= 400), regardless of the probe status.
- Dimension 3 (surviving-grant control): if Branch A denies but Branch B also denies despite `branch_b_expected == ALLOW`, LEGITIMATE_ACCESS_REGRESSION (`OVER_REVOCATION_REGRESSION`).
- Implement every row of §9.3.3, including `INVERTED_ENFORCEMENT` (A leaks, B rejects).
- Return a typed `AdjudicationReport` with `verdict`, `subtype`, `dimensions`, `evidence`, `reproduction_verified`.

**Acceptance:** 100% branch coverage over all verdicts and edge cases: clean, canary leak, silent write on 403, masked 200, access regression, abstain, invalid test, inverted enforcement.

**Test command:** `.venv/bin/pytest tests/unit/test_adjudicator.py -v`

## Task 10: Pair-Preserving Delta-Debugging Minimizer

**Spec:** §6.1(3), §16 P3-T3.
**Depends:** Task 9.

**Files:** `src/janus_auth/runner/minimizer.py`, `tests/unit/test_minimizer.py`.

**Requirements:**
- Identify essential steps: reset, resource constructor, transition, probe, post-probe witness. Candidate reducible steps: extra resources, redundant benign updates, unrelated user creations, noise steps.
- Zeller `ddmin` over reducible steps; accept a subset only when re-execution on a fresh reset reproduces the exact `VerdictKind` and `ViolationSubtype` and preserves the Branch B control.
- Record `original_step_count`, `minimized_step_count`, `reduction_ratio`, `reproduction_verified`.
- Never delete an essential structural step.

**Acceptance:** A plan with 6 injected noise steps is reduced by >= 35% while both Branch A's violation and Branch B's control still reproduce; a plan with no noise is unchanged; a candidate that breaks Branch B is rejected.

**Test command:** `.venv/bin/pytest tests/unit/test_minimizer.py -v`

## Task 11: SARIF 2.1.0 Exporter and Standalone Replay Code Generator

**Spec:** §9.1, §16 P4-T1.
**Depends:** Task 10.

**Files:** `src/janus_auth/reporting/{__init__,sarif,replay_codegen}.py`, `tests/integration/test_cli_end_to_end.py`.

**Requirements:**
- SARIF 2.1.0 with `$schema`, `version: "2.1.0"`, tool driver `janus-auth`, rules JANUS001–JANUS006 mapped to BOLA_READ_LEAK, SILENT_WRITE_SIDE_EFFECT, STALE_GROUP_CACHE, FORMER_OWNER_RETENTION, BROKEN_DELEGATION_CASCADE, OVER_REVOCATION_REGRESSION. `message.text` includes both branch summaries; locations point at the policy/manifest artifact.
- Redact all traces before export; no tokens or raw secrets.
- Replay codegen: `witness_<plan_id>.py` reads `JANUS_TOKEN_ADA`, `JANUS_TOKEN_BEA`, `JANUS_TOKEN_CARL`, `JANUS_TOKEN_DANA`, `JANUS_TOKEN_ADMIN`, and `JANUS_TARGET_URL` from `os.environ`; contains `test_branch_a_last_grant_revoked_must_deny()` and `test_branch_b_surviving_grant_must_allow()`; embeds steps, canary, and assertions; no raw credentials.
- Generated files pass `ast.parse()` and `ruff check`.

**Acceptance:** SARIF is structurally valid and contains both branches; generated witnesses parse and lint; a grep for known test tokens finds none; a witness reproduces against DocVault with env tokens.

**Test command:** `.venv/bin/pytest tests/integration/test_cli_end_to_end.py -k "sarif or replay" -v`

## Task 12: Comparative Benchmark and Ablation Evaluator

**Spec:** §5.3, §12.2, §16 P4-T2.
**Depends:** Task 11.

**Files:** `src/janus_auth/benchmark/{__init__,baselines,evaluator}.py`, `tests/integration/test_cli_end_to_end.py`.

**Requirements:**
- `StaticCrossUserReplayBaseline`: status-code/body-length heuristics after transition; no canary, no post-probe witness, no Branch B.
- `UnpairedSingleBranchAblation`: Branch A only with effect witnesses; no surviving-grant twin.
- `StatusCodeOnlyOracleAblation`: both branches, status codes only; no canary or state witness.
- Full system: Z3 twin compiler + 4D adjudicator.
- Run all 4 methods across 7 modes plus masked-200 controls under an identical request budget; compute `known_defect_recall` (6 seeded defects), `false_positive_rate_on_controls`, `silent_write_detection_rate`, `access_regression_detection_rate`, `decision_coverage`, `selective_error`, `average_witness_length`.
- Output JSON and Markdown. No hardcoded results; measure them.
- Keep the benchmark bounded (in-process ASGI; default budget 300).

**Acceptance:** The full system measures 1.00 recall on the 6 seeded defects and 0.00 false-positive rate on surviving-grant and masked-200 controls; each baseline is measurably worse on at least one axis; the report is reproducible across two runs.

**Test command:** `.venv/bin/pytest tests/integration/test_cli_end_to_end.py -k "benchmark" -v`

## Task 13: Full Typer CLI, Adversarial Tests, and End-to-End Demo

**Spec:** §9.4.1, §16 P4-T3, §18.
**Depends:** Task 12.

**Files:** `src/janus_auth/cli.py`, `tests/integration/test_cli_end_to_end.py`, `tests/security/test_adversarial_guardrails.py`.

**Requirements:**
- Commands: `validate`, `propose-mapping`, `approve-manifest`, `compile`, `run`, `benchmark`, `demo`.
- Exit codes: 0 conforms/benchmark complete; 2 confirmed violation or regression with `--fail-on-violation`; 1 validation/security error.
- Rich tables for plan summaries, verdicts, and benchmark metrics; deterministic output.
- `demo --out-dir artifacts/demo/`: compile, run clean + 6 modes + masked control, inject noise, minimize, export SARIF and replay witnesses, print the benchmark table.
- Adversarial tests: SSRF server URL, 302 redirect, unapproved manifest, tampered policy hash, oversized YAML, token redaction across SARIF/replay.
- `janus-auth run` against clean DocVault completes in under 30 seconds.

**Acceptance:** `pytest -v` passes all unit, integration, and security tests; `ruff` and `mypy` pass; `janus-auth demo` produces `compiled_plans.json`, SARIF, minimized witnesses, `janus_report.json`, and a benchmark table; no secret appears in any artifact.

**Test command:** `.venv/bin/pytest tests/ -v && .venv/bin/ruff check src/ tests/ && .venv/bin/mypy src/ && time .venv/bin/janus-auth run --target-url http://testserver --mode clean --budget 500`

## Phase 5: Hallmark Landing Page

**Runs after Task 13. Not an SDD task; a separate Hallmark run.**
**Location:** `site/index.html`, `site/styles.css`, `site/assets/` (static, no framework).

**Pre-flight:** no `design.md`, no brand spec. The product is the real Janus-Auth demo; no library photos needed. Material is the real CLI output, the measured benchmark table, the SARIF snippet, and the architecture. Absent: customer logos, quotes, customer counts, invented metrics.

**Hallmark flow:** read `references/flow.md` for OpenCode; pre-flight; confirm material/audience/use/tone (inferences below); shape; deal a theme (`modern-minimal` genre); load layout/anatomy/imagery/craft/genre/theme/gates; Picks block; scaffold; hero first; build; `sloplint --render`; finish review; material ask.

**Confirmed answers:** material = real demo artifacts (CLI transcripts, measured benchmark table, SARIF excerpt, architecture; no logos, quotes, or invented numbers); audience = AppSec engineers and staff backend engineers; use = try the CLI / read the repo; tone = technical and austere foundation with a sleek, dimensional, futuristic finish — "luxury" as restraint and craft, not ornament; anchor = cobalt on paper; vibe = "counterfactual proof, not guesswork"; genre = modern-minimal.

**Direction:** deal a theme at build time with the prompt carrying the confirmed tone and anchor; pick the theme whose material can carry cobalt-on-paper, technical/austere, and a dimensional finish. Report the deal and any swap in the Picks block. If no dealt theme can carry the brief, rule on a custom direction and say so.

**Content:** hero headline <= 7 words, one sentence <= 12 words, one action; one signature: the Branch A 403 vs Branch B 200-with-canary transcript, shown as real output; a real benchmark table; a real SARIF excerpt; the 7 modes; a quickstart; a footer. Cobalt is the single signal colour on a paper base; all colours and fonts go through `:root` tokens. No eyebrow labels, no tracking caps, no middle-dot meta strings, no invented proof. The hero must be complete at 1280×800. `sloplint --render` must be clean before shipping.

## Final Verification

1. `.venv/bin/pytest -v` green.
2. `.venv/bin/ruff check src/ tests/` green.
3. `.venv/bin/mypy src/` green.
4. `.venv/bin/janus-auth demo --out-dir artifacts/demo/` green; inspect every artifact.
5. `janus-auth run` clean under 30 seconds.
6. Spec-to-code compliance audit: extract ~40 atomic requirements from §§9–16, 17, 18; one checker per requirement; independent refutation of each divergence; write `spec-compliance/REPORT.md` with `implemented/partial/contradicted/absent/undecidable` verdicts and the reverse-direction findings.
7. Whole-branch final review on the strongest available model; fix wave; recapture.
8. Landing page: `sloplint --render` clean; Hallmark finish review; final Picks block updated with outcomes.

## Out of Scope

- v1 Docker Compose adapters for live Paperless-ngx/Gitea.
- The exact cache-TTL profiler.
- GraphQL/gRPC adapters.
- Multi-hop delegation beyond one hop.
- Any LLM API dependency.
- Any production deployment, hosted service, or real customer data.
