# Benchmark methodology

The benchmark answers a narrow question: on the same paired evidence, what do the extra dimensions of Janus-Auth buy over a static replay, a single branch, or a status-code-only pair?

It is a diagnostic, not a universal leaderboard.

## Methods

| Method | What it sees | What it ignores |
|---|---|---|
| `static_cross_user_replay` | Branch A status after the transition | canary, effect witness, Branch B, tenant context |
| `unpaired_single_branch` | Branch A status, canary, and effect witness | Branch B surviving-grant control |
| `status_code_only` | Both branch status codes | canary, effect witness |
| `janus_full_system` | Full four-dimensional adjudication | nothing in the current evidence model |

All four methods receive the same `PairedExecutionEvidence`. No method gets a private execution or a different budget.

## Cases

The evaluator runs nine cases:

| Case | Mode | Expected |
|---|---|---|
| `clean-surviving-grant-read` | `clean` | no finding |
| `clean-surviving-grant-write` | `clean` | no finding |
| `clean-masked-200` | `clean` | no finding |
| `defect-stale-direct-cache` | `vuln_stale_direct_cache` | finding |
| `defect-group-revocation` | `vuln_group_revocation_ignored` | finding |
| `defect-transfer-retains-owner` | `vuln_transfer_retains_owner` | finding |
| `defect-broken-cascade` | `vuln_broken_delegation_cascade` | finding |
| `defect-silent-write` | `vuln_silent_write_on_403` | finding |
| `defect-over-revocation` | `vuln_over_revocation_regression` | finding |

The clean cases are controls. The masked-200 case is the key false-positive control: a `200` with no canary is a conforming public projection, not a leak.

## Metrics

- **Defect recall** — fraction of the six seeded defects detected.
- **False positives on controls** — fraction of the three clean controls flagged.
- **Silent-write detection** — whether the method catches a mutation behind a `403`.
- **Access-regression detection** — whether the method catches a Branch B denial despite a surviving grant.
- **Decision coverage** — fraction of cases for which the method had the evidence its decision requires.
- **Selective error** — fraction of all cases where the decision differs from the expected outcome.
- **Average witness length** — average number of executed steps behind the decision.

## Results

Recorded from a real demo run:

| Method | Defect recall | FP on controls | Silent write | Regression | Coverage | Selective error | Avg witness steps |
|---|---:|---:|---:|---:|---:|---:|---:|
| `static_cross_user_replay` | 0.67 | 0.33 | 0.00 | 0.00 | 1.00 | 0.33 | 8.8 |
| `unpaired_single_branch` | 0.83 | 0.33 | 1.00 | 0.00 | 1.00 | 0.22 | 8.8 |
| `status_code_only` | 0.83 | 0.33 | 0.00 | 1.00 | 1.00 | 0.22 | 18.6 |
| `janus_full_system` | 1.00 | 0.00 | 1.00 | 1.00 | 1.00 | 0.00 | 18.6 |

The full system is the only method with both perfect defect recall and zero control false positives. The baselines each miss at least one axis: static replay misses silent writes and regressions; the unpaired branch misses the surviving-grant control; the status-code pair cannot see a mutated document.

## Reproduce

```bash
.venv/bin/janus-auth benchmark --runs 1 --budget 300 --out-dir artifacts/benchmark_results/
```

Outputs:

```text
artifacts/benchmark_results/benchmark_report.json
artifacts/benchmark_results/benchmark_report.md
```

The benchmark is deterministic for a fixed policy, manifest, target app, and plan set. The request budget is enforced per case; the default of 300 is enough for the nine-case matrix.

## What this does not claim

- It does not claim that Janus-Auth finds every authorization bug.
- It does not compare against commercial scanners.
- It does not measure performance at scale.
- It covers one target with seven modes. The numbers are evidence about this matrix, not a universal benchmark.

Read the methodology before quoting the table.