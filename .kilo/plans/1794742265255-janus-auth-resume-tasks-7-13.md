# Janus-Auth — Resume Plan: Finish Tasks 7–13, Verification, and Landing Page

**Repository:** `/home/Jaan/Documents/CYBER PROJECT 1/janus-auth`
**Branch:** `feat/janus-auth-mvp` (HEAD `dd7c19f`)
**Authority:** `PROJECT_SPEC.md` > `IMPLEMENTATION_PLAN.md` > binding rulings R1–R12 in
`.superpowers/sdd/janus-auth/progress.md`
**Execution mode:** continuous, one implementer at a time, controller-owned review, hard phase gates.

---

## 1. Where the build stopped

The OpenCode session (`janus-auth-architecture-spec.json`) ended on **2026-11-15** with
`provider.rate-limit` (free-models-per-day), not a code failure. The last event is the
Task 6 fix-round-1 **re-review subagent dying with a 429**, immediately after the controller
committed `dd7c19f` and updated the ledger.

Exact stopping point:

| Item | State |
|---|---|
| Tasks 1–5 | Complete, reviewed, committed |
| Task 6 | Implemented + fix round 1 committed (`dd7c19f`); **re-review pending**; not yet marked complete |
| Last full gate evidence | 201 passed; `ruff` clean; `mypy` clean on 17 source files (recorded after `dd7c19f`) |
| Tasks 4–6 phase gate | **Not run** |
| Task 7 | Brief written (`.superpowers/sdd/janus-auth/task-7-brief.md`), pre-dispatch rulings recorded, **not dispatched** |
| Tasks 8–13 | Briefs written; no implementation |
| Phase 5 landing page | Not started |

What exists in `src/janus_auth/`: `models.py`, `config.py`, `security/` (gatekeeper, redactor,
store), `oracle/cedar_engine.py`, `compiler/` (mapper, z3_synthesizer, compiler). Empty
placeholders: `targets/`, `runner/`, `reporting/`, `benchmark/`. No `cli.py`, so the
`janus-auth` console script does not resolve yet. `tests/integration/` and `tests/security/`
are empty.

Compiled catalog already produced by Task 6: 12 deterministic `CompiledTwinPlan`s —
10 feasible twin pairs + 1 delegation-cascade realization + 1 masked control. Surviving-grant
setup steps: `group-membership`, `direct-share`, `delegation`, `role-admin`.

---

## 2. Resume protocol (binding)

1. Continue on `feat/janus-auth-mvp`; never work on `main`.
2. Per task: record `BASE=$(git rev-parse HEAD)` → dispatch one implementer with the existing
   brief → write `task-N-report.md` → controller review (spec + quality) → fix loop (max 5) →
   append ledger → commit with Conventional Commits.
3. Provider-limit fallback: if a subagent is killed by the free-usage limit, the controller
   performs that role inline, states so in the report and ledger, and carries the same
   acceptance evidence. This is the precedent established for Task 6.
4. Never weaken the gatekeeper, redactor, Cedar cross-check, pair-preservation invariant, or a
   test to pass a gate.
5. Do not commit `janus-auth-architecture-spec.json` (session export). Add it to `.gitignore`
   in the Task 6 close-out commit.

---

## 3. Step 0 — Close out Task 6 and pass the Tasks 4–6 gate

1. **Scoped re-review** of fix commit `dd7c19f` against the two Important findings only:
   - signed-but-ignored manifest fields (`canary_field`, `extractors["doc_id"]`,
     `operations[family].masked_query`) now drive plan construction and fail closed;
   - reset mode remains pinned to `clean` with the contract documented.
   Confirm no new Critical/Important issues. If the reviewer cannot be dispatched, do this
   inline and record it.
2. Append `Task 6: complete (commits 81b7bc7..dd7c19f, review clean)` to the ledger.
3. Add `janus-auth-architecture-spec.json` to `.gitignore`; commit ledger + ignore change
   (`chore(sdd): close Task 6 review and ignore session export`).
4. **Hard phase gate (Tasks 4–6):**
   ```bash
   .venv/bin/pytest -q
   .venv/bin/ruff check src/ tests/
   .venv/bin/mypy src/
   ```
   Record exact counts in a `## Phase Gate — Tasks 4–6` ledger section. A failure blocks Task 7.

---

## 4. Step 1 — Task 7: DocVault Multi-Mode Benchmark Target

**Files:** `src/janus_auth/targets/{__init__,docvault_app}.py`,
`tests/integration/test_docvault_modes.py`

Implement a FastAPI app over the 15 paths / 16 operations in
`configs/docvault_openapi.json`, backed by an in-memory store:

- `/admin/reset` (POST), `/documents` (GET, POST), `/documents/{doc_id}` (GET, PATCH),
  `/documents/{doc_id}/permissions` (GET), `/documents/{doc_id}/shares` (POST),
  `/documents/{doc_id}/shares/{user_id}` (DELETE),
  `/groups/{group_id}/members` (POST), `/groups/{group_id}/members/{user_id}` (DELETE),
  `/documents/{doc_id}/group-shares` (POST), `/documents/{doc_id}/delegations` (POST),
  `/documents/{doc_id}/delegations/{to_user_id}` (DELETE), `/users/{user_id}/role` (POST),
  `/documents/{doc_id}/transfer` (POST), `/users/{user_id}/tenant` (POST),
  `/documents/{doc_id}/denies` (POST).

Semantics the compiler already depends on (do not deviate):

- Fixed synthetic tokens `token_ada`/`token_bea`/`token_carl`/`token_dana`/`token_admin`;
  principals `ada`, `bea`, `carl` (`acme`), `dana` (`globex`), `ops_admin` (`acme`, admin).
- Document fields: `id`, `owner_id`, `tenant_id`, `title`, `public_summary`,
  `secret_content`; protected field is `secret_content`.
- Masked read: `GET /documents/{doc_id}?masked=true` returns `200`, `secret_content: null`,
  public fields only; full access still returns the canary.
- Reset rebuilds state from a deep-copied immutable seed, increments a monotonic epoch, and
  echoes `{"status":"reset","mode":...,"epoch":n}`; mode is selected only by the reset body
  and stored per app instance.
- Group membership may be managed by the document owner; delegation creation is allowed by a
  current grant holder; role and tenant endpoints accept admin/owner-driven test setup.
- Seven modes exactly: `clean`, `vuln_stale_direct_cache`, `vuln_group_revocation_ignored`,
  `vuln_transfer_retains_owner`, `vuln_broken_delegation_cascade`,
  `vuln_silent_write_on_403`, `vuln_over_revocation_regression`.

Acceptance: all endpoints and all 7 modes deterministic through `httpx.ASGITransport`; `clean`
has zero violations; each seeded mode exhibits only its intended defect; reset epoch changes
every reset. Test command: `.venv/bin/pytest tests/integration/test_docvault_modes.py -v`.
Write `task-7-report.md`, review, ledger, commit `feat(targets): add DocVault multi-mode target`,
then run the **Task 7 phase gate** (full `pytest`, `ruff`, `mypy`).

---

## 5. Step 2 — Task 8: Isolated Dual-Branch Sequence Executor

**Files:** `src/janus_auth/runner/{__init__,executor}.py`,
`tests/integration/test_docvault_modes.py`

- Support live `httpx.Client(base_url=..., follow_redirects=False)` and in-process
  `httpx.ASGITransport(app=..., base_url="http://testserver")`.
- Every request (including reset) passes `SafetyGatekeeper.validate_request()`; no bypass.
- Resolve `{doc_id}`, `{group_id}`, `{delegation_id}`, `{canary}` from prior responses via
  `ScopeManifest.extractors`; fail the branch with `INVALID_TEST` evidence if a placeholder is
  unresolved.
- Execute Branch A from a fresh reset, capture every `StepObservation` (status, parsed JSON,
  redacted headers, elapsed, canary presence, owner effect witness), record the reset epoch;
  reset again and execute Branch B identically. No cross-branch state.
- The runner overrides the manifest mode to `clean` for compiled plans; with no declared
  reset endpoint, use unique resources per branch and mark `INVALID_TEST` when preconditions
  cannot be proven (R9).
- Persist redacted, encrypted traces through `TraceStore`; enforce `max_requests` and rate
  limit; never store raw tokens.
- Emit `PairedExecutionEvidence` with both branch traces and reset epochs.

Acceptance: both branches of every compiled plan run without pollution; gatekeeper called on
every request (spy test); failed reset yields invalid evidence, not a finding; traces decrypt
and redact correctly. Task 8 report/review/ledger, commit
`feat(runner): add isolated dual-branch executor`.

---

## 6. Step 3 — Task 9: 4D Differential Effect-Witness Adjudicator

**Files:** `src/janus_auth/oracle/adjudicator.py`, `tests/unit/test_adjudicator.py`

Implement §9.3.3 in full over `PairedExecutionEvidence` → `AdjudicationReport`:

- Validity gate: setup, pre-transition witness, transition acknowledgement, and
  post-transition state witness must all succeed; otherwise `INVALID_TEST`.
- Uncertainty gate: `UNKNOWN` in either branch → `UNCERTAIN_ABSTAIN`.
- Read projection: Branch A `200` with canary where DENY is expected →
  `CONFIRMED_VIOLATION` / `BOLA_READ_LEAK`; Branch A `200` without canary and
  `secret_content is None` while Branch B has it → `CONFORMS_MASKED`.
- Post-probe state mutation: `secret_content == "MUTATED_BY_<principal>"` in Branch A where
  DENY is expected → `CONFIRMED_VIOLATION` / `SILENT_WRITE_SIDE_EFFECT` when probe status ≥ 400,
  regardless of status code.
- Surviving-grant control: Branch A denies and Branch B also denies although
  `branch_b_expected == ALLOW` → `LEGITIMATE_ACCESS_REGRESSION` /
  `OVER_REVOCATION_REGRESSION`.
- Implement every §9.3.3 row including `INVERTED_ENFORCEMENT`; populate `dimensions`,
  `branch_a_summary`, `branch_b_summary`, `evidence`, `reproduction_verified`.

Acceptance: one test per verdict/subtype plus edge cases (clean, canary leak, silent write on
403, masked 200, access regression, abstain, invalid test, inverted enforcement). Commit
`feat(adjudicator): add 4D effect-witness adjudicator`.

---

## 7. Step 4 — Task 10: Pair-Preserving ddmin Minimizer

**Files:** `src/janus_auth/runner/minimizer.py`, `tests/unit/test_minimizer.py`

- Essential steps: reset, resource constructor, transition, probe, post-probe witness.
- Zeller `ddmin` over reducible steps; accept a subset only when re-execution on a fresh reset
  reproduces the exact `VerdictKind` and `ViolationSubtype` **and** preserves the Branch B
  control. Never delete an essential structural step.
- Record `original_step_count`, `minimized_step_count`, `reduction_ratio`,
  `reproduction_verified`.

Acceptance: 6 injected noise steps reduce ≥ 35% with both branches still reproducing; no-noise
plan unchanged; a candidate that breaks Branch B is rejected. Commit
`feat(runner): add pair-preserving ddmin minimizer`.

**Then run the Tasks 8–10 phase gate** (`pytest`, `ruff`, `mypy`) before Task 11.

---

## 8. Step 5 — Task 11: SARIF 2.1.0 Exporter + Replay Code Generator

**Files:** `src/janus_auth/reporting/{__init__,sarif,replay_codegen}.py`,
`tests/integration/test_cli_end_to_end.py`

- SARIF 2.1.0 with `$schema`, `version`, driver `janus-auth`, rules `JANUS001`–`JANUS006`
  mapped to `BOLA_READ_LEAK`, `SILENT_WRITE_SIDE_EFFECT`, `STALE_GROUP_CACHE`,
  `FORMER_OWNER_RETENTION`, `BROKEN_DELEGATION_CASCADE`, `OVER_REVOCATION_REGRESSION`;
  each result carries both branch summaries and points at the policy/manifest artifact.
- Redact all traces before export; no tokens, headers, or raw secrets.
- Replay codegen writes `witness_<plan_id>.py`: reads `JANUS_TOKEN_ADA`, `JANUS_TOKEN_BEA`,
  `JANUS_TOKEN_CARL`, `JANUS_TOKEN_DANA`, `JANUS_TOKEN_ADMIN`, `JANUS_TARGET_URL` from
  `os.environ`; contains `test_branch_a_last_grant_revoked_must_deny()` and
  `test_branch_b_surviving_grant_must_allow()`; embeds steps, canary, assertions.

Acceptance: SARIF structurally valid and includes both branches; generated files pass
`ast.parse()` and `ruff check`; grep for all known test tokens finds nothing; one witness
reproduces against DocVault with env tokens. Commit `feat(reporting): add SARIF exporter and
replay codegen`.

---

## 9. Step 6 — Task 12: Comparative Benchmark and Ablation Evaluator

**Files:** `src/janus_auth/benchmark/{__init__,baselines,evaluator}.py`,
`tests/integration/test_cli_end_to_end.py`

Implement four methods and run them across 7 modes + masked controls under an identical budget
(default 300, in-process ASGI):

1. `StaticCrossUserReplayBaseline` — status/body-length heuristics, no canary, no state witness,
   no Branch B.
2. `UnpairedSingleBranchAblation` — Branch A only, effect witnesses, no surviving-grant twin.
3. `StatusCodeOnlyOracleAblation` — both branches, status codes only.
4. Full system — Z3 twin compiler + 4D adjudicator.

Measure, never hardcode: `known_defect_recall` (6 seeded defects),
`false_positive_rate_on_controls`, `silent_write_detection_rate`,
`access_regression_detection_rate`, `decision_coverage`, `selective_error`,
`average_witness_length`. Emit JSON + Markdown.

Acceptance: full system measures 1.00 recall and 0.00 false-positive rate on surviving-grant
and masked-200 controls; every baseline is worse on at least one axis; two runs agree. Commit
`feat(benchmark): add comparative benchmark and ablations`.

---

## 10. Step 7 — Task 13: Typer CLI, Adversarial Tests, End-to-End Demo

**Files:** `src/janus_auth/cli.py`, `tests/integration/test_cli_end_to_end.py`,
`tests/security/test_adversarial_guardrails.py`

- Commands: `validate`, `propose-mapping`, `approve-manifest`, `compile`, `run`, `benchmark`,
  `demo`.
- Exit codes: `0` conforms/benchmark complete; `2` confirmed violation or regression with
  `--fail-on-violation`; `1` validation or security error.
- Add the `if __name__ == "__main__": app()` guard so `python3 -m janus_auth.cli` works and the
  `janus-auth` console script resolves.
- `approve-manifest` is the only path that signs; `propose-mapping` stays `approved: false`;
  `compile`/`run` refuse unapproved or bad-signature manifests.
- Rich tables for plans, verdicts, and benchmark metrics; deterministic output.
- `demo --out-dir artifacts/demo/`: compile → run clean + 6 modes + masked control → inject
  noise → minimize → export SARIF and replay witnesses → print benchmark table; produce
  `compiled_plans.json`, `janus_report.json`, SARIF, minimized witnesses.
- Adversarial tests: SSRF server URL, 302 redirect, unapproved manifest, tampered policy hash,
  oversized YAML (5 MB), token redaction across SARIF/replay.
- `janus-auth run` against clean DocVault completes in under 30 seconds.

Acceptance: `.venv/bin/pytest -v` fully green, `ruff`, `mypy`, demo artifacts all present, no
secret in any artifact. Commit `feat(cli): add Typer CLI, adversarial tests, and demo`.

---

## 11. Step 8 — Final verification, compliance audit, whole-branch review

1. Run and record:
   ```bash
   .venv/bin/pytest -v
   .venv/bin/ruff check src/ tests/
   .venv/bin/mypy src/
   .venv/bin/janus-auth demo --out-dir artifacts/demo/
   time .venv/bin/janus-auth run --target-url http://testserver --mode clean --budget 500
   ```
2. **Spec-to-code compliance audit** with the `spec-to-code-compliance` skill: extract ~40
   atomic requirements from `PROJECT_SPEC.md` §§9–16, 17, 18; one checker each; independent
   refutation of every divergence; write `spec-compliance/REPORT.md` with
   `implemented/partial/contradicted/absent/undecidable` verdicts plus reverse-direction
   findings (code with no spec backing).
3. **Whole-branch review** on the strongest available model; fix wave; re-run the full gate and
   recapture demo artifacts.
4. Merge readiness: branch is `feat/janus-auth-mvp`; do not merge to `main` without explicit
   instruction.

---

## 12. Step 9 — Parked-minors polish wave (before the whole-branch review)

Convert every "parked for final polish" item in `progress.md` into a checklist and fix the ones
that survive. Never weaken an acceptance test. Key items:

- **Security:** prefer rejecting `//`-prefixed paths instead of collapsing; narrow the
  2-element pair redaction heuristic; handle bare `Headers.get_list("set-cookie")` values;
  reject decoded `%00` in path segments.
- **Models/compiler:** `expires_at` never expires when absent; duplicate setup `step_id`s not
  rejected; pair invariant checks membership, not order; cascade keeps
  `synthesized.transition_family=DELEGATION_REVOKE` while realizing a parent-share revoke;
  mapper `generated_at` non-reproducible; stat/read TOCTOU on the 5 MB ceiling.
- **Oracle/synth:** non-owner sentinel `User::"__not_owner__"`; tautological
  `SUPPORTED_ACTIONS` test; fail-closed test for invalid Cedar text; `_infeasible` write-only
  dict; `unknown` vs `unsat` indistinct; Z3 timeout not wired to
  `Settings.z3_timeout_ms`; partial class-constraint assertions.
- **Packaging/docs:** narrow Python classifiers to 3.12 until 3.13/3.14 are tested; fix
  `make clean` to remove `src/*.egg-info`; use `python3.12` in `make setup`; add an
  import-purity regression test; align README phase/status text; correct stale citations and
  test-module docstrings.

Gate after the wave: full `pytest`, `ruff`, `mypy`; commit `chore: polish parked review minors`.

---

## 13. Step 10 — Phase 5: Hallmark landing page

Only after Task 13 and the whole-branch review. `site/index.html`, `site/styles.css`,
`site/assets/` (static). Follow the confirmed direction in `IMPLEMENTATION_PLAN.md`:
cobalt-on-paper, technical/austere with a dimensional finish; real demo artifacts only; no
invented metrics or logos. `sloplint --render` must be clean at 1280×800.

---

## 14. Risks / watch items

- **Provider rate limits** are the proven failure mode. Keep the inline-controller fallback
  explicit; do not leave a task in "review pending" without a ledger line.
- **DocVault/compiler contract:** Task 7 must match the compiled step bodies exactly
  (`doc_id` extractor, canary field, masked query, transition paths). Task 8 is the first test
  of that contract; expect it to surface mismatches.
- **Unapproved manifest:** the committed YAML is `approved: false` by design. Tests build a
  signed copy with a test-only secret; the demo must sign via `approve-manifest` with
  `JANUS_SIGNING_SECRET` from the environment. Never commit a real signing secret.
- **Pair preservation** is the system's core evidence claim. Any executor/minimizer change
  that could desynchronise Branch A/B must fail closed.
- **Determinism** (Z3, plan IDs, reset epochs, benchmark) must be pinned in tests; two-run
  comparisons are required by Tasks 5 and 12.

## 15. Open questions

None blocking. The specification, normalized plan, and rulings R1–R12 fully determine the
remaining work. The Task 6 re-review is the only open item and is resolved in Step 0.
