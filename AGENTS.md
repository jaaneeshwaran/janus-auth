# AGENTS.md — Engineering & Security Charter for Janus-Auth

## 1. Skill Use

Use a skill only when the task matches what that skill does.

- **Hallmark** is for the landing page in `site/` only. It is never used for the Python CLI, SARIF, JSON, Markdown, or test code.
- **spec-to-code-compliance** is for the post-build audit against `PROJECT_SPEC.md`.
- **subagent-driven-development** is the execution loop for the implementation plan in `IMPLEMENTATION_PLAN.md`.
- Testing is plain `pytest`; security review is the checklist in Section 4.

## 2. Project Overview

You are building **Janus-Auth**, an SMT-guided counterfactual differential compiler and 4D effect-witness adjudicator for API authorization lifecycles. `PROJECT_SPEC.md` is the binding specification. `IMPLEMENTATION_PLAN.md` is the normalized execution plan; where the two differ, the specification wins and the plan's preflight rulings (R1–R12) record every deliberate deviation.

## 3. Coding and Architecture Standards

- Python 3.12+ with strict type annotations on every function signature and class attribute. `mypy src/` must pass with zero errors.
- `ruff check src/ tests/` must pass. Line length is 100.
- All external inputs (manifests, OpenAPI specs, traces, verdicts) are validated with Pydantic v2 `BaseModel` and `ConfigDict(extra="forbid", strict=True)` where applicable.
- Prefer small, typed, pure functions. Keep Cedar evaluation, Z3 synthesis, HTTP execution, and adjudication in separate modules.
- No `Any` where a Pydantic model or typed dataclass applies.
- No hidden network or filesystem work at import time.

## 4. Non-Negotiable Security Rules

1. **No Hardcoded Secrets.** Never write API keys, bearer tokens, or signing secrets into source files, SARIF reports, generated replay scripts, or test fixtures. Replay scripts read credentials from `os.environ`.
2. **Mandatory Request Gatekeeping.** Every outbound HTTP request passes through `SafetyGatekeeper.validate_request()`, which enforces:
   - a valid `ScopeManifest` HMAC-SHA256 signature;
   - scheme `http` or `https` only;
   - hostname in `manifest.allowed_hosts`;
   - SSRF protection for `169.254.169.254`, link-local, multicast, and unspecified ranges;
   - `follow_redirects=False` on every `httpx` client;
   - the hard `max_requests` budget and rate limit;
   - DELETE only on declared transition endpoints, and reset only on the declared reset endpoint.
3. **Safe Deserialization and Parameterized SQL.** Use `yaml.safe_load()` after a 5 MB size check. Never use `yaml.load()`, `pickle`, `eval()`, or `exec()`. Every SQLite statement uses `?` parameters.
4. **Non-Authoritative AI Boundary.** `propose-mapping` always emits `approved: false`. The compiler and runner refuse any manifest where `approved != true` or the HMAC signature is invalid.
5. **Pair-Preserving Evidence.** Do not weaken the Cedar cross-check, the post-probe state witness, the surviving-grant control, or the redactor to make a test pass.

## 5. Tests and Quality Gates

```bash
.venv/bin/pytest tests/unit/ -v
.venv/bin/pytest tests/integration/ -v
.venv/bin/pytest tests/security/ -v
.venv/bin/pytest -v
.venv/bin/ruff check src/ tests/
.venv/bin/mypy src/
```

Phase gates are hard: a failing gate blocks the next phase. Do not skip, weaken, or rewrite an acceptance test to make a phase pass.

## 6. Commit Conventions and Workflow

- Conventional Commits: `feat(compiler): ...`, `feat(oracle): ...`, `fix(security): ...`, `test(adjudicator): ...`.
- Work on `feat/janus-auth-mvp`, never directly on `main`.
- Each task ends with a report, a review, and a commit. The controller owns review; implementers never dispatch subagents.
- Do not touch `.superpowers/` ledger state except through the SDD scripts.
- **When to stop:** only on a genuine blocker (destructive/security-sensitive action, an external side effect that needs consent, or a plan so broken that every path is a guess), or when the plan is complete. Continuous execution is intentional; do not pause for phase-by-phase human approval.
