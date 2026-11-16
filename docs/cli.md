# CLI reference

Janus-Auth exposes one Typer application, installed as `janus-auth`. Every command writes a human-readable summary and returns a deterministic exit code.

```bash
janus-auth --help
janus-auth <command> --help
```

## Commands

### `validate`

```bash
janus-auth validate \
  --policy configs/docvault.cedar \
  --manifest configs/docvault_manifest.yaml \
  --openapi configs/docvault_openapi.json
```

Checks that the policy is non-empty, the OpenAPI document has a `paths` object, and the manifest parses. If the manifest carries a signature, the signature and expiry are verified. An unsigned draft is reported as valid but unapproved.

**Exit:** `0` valid, `1` validation or security error.

### `propose-mapping`

```bash
janus-auth propose-mapping \
  --openapi configs/docvault_openapi.json \
  --policy configs/docvault.cedar \
  --out configs/draft_mapping.yaml
```

Reads only the static OpenAPI document and the Cedar policy. The output is always `approved: false`; it is a review aid, not an authorization decision.

**Exit:** `0` written, `1` error.

### `approve-manifest`

```bash
export JANUS_SIGNING_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
janus-auth approve-manifest \
  --manifest configs/docvault_manifest.yaml \
  --policy configs/docvault.cedar \
  --approver you@example.org \
  --expires-in-days 7
```

Verifies that the manifest's `policy_sha256` matches the supplied Cedar policy, records the approver and expiry, signs the manifest with the configured secret, writes it, and re-verifies the written file.

**Exit:** `0` approved and verified, `1` policy mismatch, signature error, or I/O error.

> The manifest is rewritten in place. Copy it first if you want to keep the unsigned draft.

### `compile`

```bash
janus-auth compile \
  --policy configs/docvault.cedar \
  --manifest configs/docvault_manifest.yaml \
  --out artifacts/compiled_plans.json
```

Compiles the approved manifest into twelve deterministic twin plans: ten feasible pairs, one delegation-cascade realization, and one masked control.

**Exit:** `0` compiled, `1` validation, signature, or synthesis error.

### `run`

```bash
janus-auth run \
  --plans artifacts/compiled_plans.json \
  --target-url http://testserver \
  --manifest configs/docvault_manifest.yaml \
  --mode all \
  --budget 500 \
  --sarif-out artifacts/janus_results.sarif.json \
  --report-out artifacts/janus_report.json \
  --witness-dir artifacts/witnesses \
  --trace-db janus_traces.sqlite3 \
  --fail-on-violation
```

Executes every plan, adjudicates both branches, and writes:

- SARIF 2.1.0 results;
- a JSON report containing every verdict and its evidence;
- one standalone pytest witness per finding, under `witness-dir/<mode>/`;
- an encrypted SQLite trace database.

`--mode` accepts one mode or `all`. The default is `clean`. `--budget` defaults to `JANUS_MAX_REQUESTS` (500). The budget is applied per mode.

For a live target, use an absolute URL whose host is in the signed manifest's `allowed_hosts`:

```bash
janus-auth run --target-url http://127.0.0.1:8000 --mode vuln_stale_direct_cache
```

**Exit:** `0` clean, `2` findings with `--fail-on-violation`, `1` validation or security error.

### `benchmark`

```bash
janus-auth benchmark \
  --runs 1 \
  --budget 300 \
  --out-dir artifacts/benchmark_results \
  --policy configs/docvault.cedar \
  --manifest configs/docvault_manifest.yaml
```

Runs the four-method benchmark and writes `benchmark_report.json` and `benchmark_report.md`. `--runs` repeats the evaluation and keeps the last report; the run is deterministic.

**Exit:** `0` complete, `1` error.

### `demo`

```bash
janus-auth demo --out-dir artifacts/demo/
```

Runs the complete showcase:

1. signs an in-memory approved copy of the reference manifest;
2. compiles the twelve plans;
3. executes clean and all six seeded modes;
4. adjudicates every plan;
5. injects noise into a silent-write witness and minimizes it;
6. writes SARIF, JSON, pytest witnesses, benchmark reports, and `demo_summary.json`.

**Exit:** `0` complete, `1` error.

## Environment variables

| Variable | Default | Used by |
|---|---|---|
| `JANUS_SIGNING_SECRET` | insecure development fallback | `approve-manifest`, `compile`, `run`, `benchmark`, `demo` |
| `JANUS_TRACE_ENCRYPTION_KEY` | ephemeral per-session key | trace storage |
| `JANUS_RETENTION_DAYS` | `7` | trace retention |
| `JANUS_Z3_TIMEOUT_MS` | `5000` | Z3 synthesis |
| `JANUS_MAX_REQUESTS` | `500` | default `run` budget |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, or a clean run with no findings |
| `1` | Validation, signature, configuration, or security error |
| `2` | Findings were produced and `--fail-on-violation` was set |

## Reproducing the demo

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/janus-auth demo --out-dir artifacts/demo/
```

Expected summary:

```text
demo complete plans=12 findings=15 requests=1484
minimized 31 -> 17 steps (0.45 reduction)
```

The exact request count is reported by the run; the plan count and the benchmark are deterministic for a fixed policy, manifest, target, and plan set.