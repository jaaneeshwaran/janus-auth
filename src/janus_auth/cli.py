"""Typer command-line interface for Janus-Auth."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Final, NoReturn

import httpx
import typer
import yaml
from fastapi.testclient import TestClient
from rich.console import Console
from rich.table import Table

from janus_auth.benchmark import BenchmarkEvaluator, BenchmarkReport
from janus_auth.compiler import (
    HeuristicOperationMapper,
    WorkflowCompiler,
    Z3Synthesizer,
    load_manifest,
)
from janus_auth.config import Settings
from janus_auth.models import (
    AdjudicationReport,
    ApiStep,
    CompiledTwinPlan,
    ExpectedRole,
    ScopeManifest,
    VerdictKind,
)
from janus_auth.oracle import CedarOracle
from janus_auth.oracle.adjudicator import Adjudicator, adjudicate
from janus_auth.reporting import build_sarif, write_replay_witness, write_sarif
from janus_auth.runner import (
    CounterfactualExecutor,
    MinimizationError,
    PairPreservingMinimizer,
)
from janus_auth.security.gatekeeper import SafetyGatekeeper, ScopeViolationError
from janus_auth.security.store import TraceStore
from janus_auth.targets.docvault_app import ALL_MODES, create_app

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="SMT-guided counterfactual differential authorization compiler.",
)

console = Console()
DEFAULT_POLICY: Final[Path] = Path("configs/docvault.cedar")
DEFAULT_MANIFEST: Final[Path] = Path("configs/docvault_manifest.yaml")
DEFAULT_OPENAPI: Final[Path] = Path("configs/docvault_openapi.json")
DEFAULT_PLANS: Final[Path] = Path("artifacts/compiled_plans.json")
_FINDING_VERDICTS: Final[frozenset[VerdictKind]] = frozenset(
    {
        VerdictKind.CONFIRMED_VIOLATION,
        VerdictKind.LEGITIMATE_ACCESS_REGRESSION,
    }
)


def _settings() -> Settings:
    return Settings.from_env()


def _load_policy(path: Path) -> str:
    if not path.is_file():
        raise FileNotFoundError(f"policy file not found: {path}")
    return path.read_text(encoding="utf-8")


def _load_openapi(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"OpenAPI file not found: {path}")
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("OpenAPI document must be a JSON object")
    return document


def _exit_error(message: str) -> NoReturn:
    console.print(f"[red]error:[/red] {message}")
    raise typer.Exit(code=1)


def _write_yaml(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


def _signed_demo_manifest(settings: Settings) -> ScopeManifest:
    manifest = load_manifest(DEFAULT_MANIFEST)
    manifest.approved = True
    manifest.approver = "janus-demo"
    manifest.approved_at = datetime.now(UTC)
    return manifest.sign(settings.signing_secret)


def _compile(
    policy_path: Path, manifest_path: Path, settings: Settings
) -> list[CompiledTwinPlan]:
    policy_text = _load_policy(policy_path)
    policy_sha = hashlib.sha256(policy_text.encode("utf-8")).hexdigest()
    manifest = load_manifest(manifest_path)
    oracle = CedarOracle.from_file(policy_path)
    compiler = WorkflowCompiler(
        oracle,
        signing_secret=settings.signing_secret,
        policy_sha256=policy_sha,
        synthesizer=Z3Synthesizer(oracle, timeout_ms=settings.z3_timeout_ms),
    )
    return compiler.compile_suite(manifest)


def _write_plans(path: Path, plans: Sequence[CompiledTwinPlan]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([plan.model_dump(mode="json") for plan in plans], indent=2)
        + "\n",
        encoding="utf-8",
    )


def _read_plans(path: Path) -> list[CompiledTwinPlan]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("compiled plans file must contain a JSON array")
    return [
        CompiledTwinPlan.model_validate_json(json.dumps(item)) for item in payload
    ]


def _client_for(target_url: str) -> httpx.Client:
    if target_url.rstrip("/") in {"http://testserver", "testserver"}:
        return TestClient(create_app(), follow_redirects=False)
    return httpx.Client(
        base_url=target_url, follow_redirects=False, timeout=5.0
    )


def _execute_mode(
    plans: Sequence[CompiledTwinPlan],
    manifest: ScopeManifest,
    settings: Settings,
    client: httpx.Client,
    mode: str,
    budget: int,
    requests_so_far: int,
    trace_store: TraceStore | None = None,
    run_id: str | None = None,
) -> tuple[list[tuple[CompiledTwinPlan, AdjudicationReport]], int]:
    reports: list[tuple[CompiledTwinPlan, AdjudicationReport]] = []
    used = requests_so_far
    adjudicator = (
        Adjudicator(trace_store, run_id=run_id)
        if trace_store is not None and run_id is not None
        else None
    )
    for plan in plans:
        gatekeeper = SafetyGatekeeper(manifest, secret=settings.signing_secret)
        executor = CounterfactualExecutor(client, gatekeeper, mode=mode)
        evidence = executor.execute(plan)
        report = (
            adjudicator.adjudicate(plan, evidence)
            if adjudicator is not None
            else adjudicate(plan, evidence)
        )
        report = report.model_copy(
            update={
                "evidence": {**report.evidence, "mode": mode},
            }
        )
        reports.append((plan, report))
        used += gatekeeper.requests_used
        if used > budget:
            raise RuntimeError(f"request budget of {budget} exhausted for mode {mode}")
    return reports, used


def _findings(
    reports: Sequence[tuple[CompiledTwinPlan, AdjudicationReport]],
) -> list[tuple[CompiledTwinPlan, AdjudicationReport]]:
    return [
        (plan, report)
        for plan, report in reports
        if report.verdict in _FINDING_VERDICTS
    ]


def _write_artifacts(
    reports: Sequence[tuple[CompiledTwinPlan, AdjudicationReport]],
    *,
    sarif_out: Path,
    report_out: Path,
    witness_dir: Path,
) -> int:
    findings = _findings(reports)
    write_sarif(sarif_out, build_sarif(findings))
    report_out.parent.mkdir(parents=True, exist_ok=True)
    report_out.write_text(
        json.dumps(
            [
                {
                    "mode": report.evidence.get("mode", ""),
                    "report": report.model_dump(mode="json"),
                }
                for _, report in reports
            ],
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    if witness_dir.exists():
        for stale in witness_dir.rglob("witness_*.py"):
            stale.unlink()
    witness_dir.mkdir(parents=True, exist_ok=True)
    for plan, report in findings:
        mode = str(report.evidence.get("mode", "unknown"))
        write_replay_witness(witness_dir / mode, plan, report)
    return len(findings)


def _print_verdict_table(
    reports: Sequence[tuple[CompiledTwinPlan, AdjudicationReport]]
) -> None:
    table = Table(title="Janus-Auth verdicts")
    table.add_column("Plan")
    table.add_column("Mode")
    table.add_column("Verdict")
    table.add_column("Subtype")
    for plan, report in reports:
        style = "red" if report.verdict in _FINDING_VERDICTS else "green"
        table.add_row(
            plan.plan_id,
            str(report.evidence.get("mode", "")),
            f"[{style}]{report.verdict.value}[/{style}]",
            report.subtype.value,
        )
    console.print(table)


def _trace_run_id(mode: str, started_at: datetime) -> str:
    return f"run-{mode}-{started_at.strftime('%Y%m%dT%H%M%S%f')}"


def _record_trace_run(
    store: TraceStore,
    manifest: ScopeManifest,
    run_id: str,
    target_url: str,
    requests_used: int,
) -> None:
    store.record_run(
        run_id,
        datetime.now(UTC),
        manifest.policy_sha256,
        manifest.manifest_sha256,
        target_url,
        total_requests=requests_used,
    )


def _noise_steps() -> list[ApiStep]:
    return [
        ApiStep(
            step_id=f"noise-{index}",
            method="GET",
            path_template="/api/v1/documents",
            principal_alias="ada",
            expected_role=ExpectedRole.SETUP,
            reversible=True,
        )
        for index in range(6)
    ]


def _minimize_demo_witness(
    plans: Sequence[CompiledTwinPlan],
    manifest: ScopeManifest,
    settings: Settings,
    client: TestClient,
    out_dir: Path,
) -> dict[str, Any] | None:
    target = next(
        (
            plan
            for plan in plans
            if plan.synthesized.probe_type.value == "reversible_write"
            and plan.plan_id.startswith("ct-direct_share_revoke")
        ),
        None,
    )
    if target is None:
        return None
    noise = _noise_steps()
    noisy = target.model_copy(
        update={
            "branch_a_steps": [*target.branch_a_steps, *noise],
            "branch_b_steps": [*target.branch_b_steps, *noise],
        }
    )

    def replay(candidate: CompiledTwinPlan) -> AdjudicationReport:
        gatekeeper = SafetyGatekeeper(manifest, secret=settings.signing_secret)
        executor = CounterfactualExecutor(
            client, gatekeeper, mode="vuln_silent_write_on_403"
        )
        return adjudicate(candidate, executor.execute(candidate))

    try:
        result = PairPreservingMinimizer(replay).minimize(noisy)
    except MinimizationError:
        return None
    minimized = result.plan
    witness_dir = out_dir / "witnesses" / "minimized"
    write_replay_witness(witness_dir, minimized, replay(minimized))
    (out_dir / "minimized_plan.json").write_text(
        json.dumps(minimized.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    return {
        "plan_id": minimized.plan_id,
        "original_step_count": result.original_step_count,
        "minimized_step_count": result.minimized_step_count,
        "reduction_ratio": result.reduction_ratio,
        "removed_step_ids": list(result.removed_step_ids),
        "verdict": result.verdict.value,
        "subtype": result.subtype.value,
        "reproduction_verified": result.reproduction_verified,
    }


def _print_benchmark_table(report: BenchmarkReport) -> None:
    table = Table(title="Janus-Auth benchmark")
    for column in (
        "Method",
        "Recall",
        "FP controls",
        "Silent write",
        "Regression",
        "Coverage",
        "Selective error",
    ):
        table.add_column(column)
    for metrics in report.methods.values():
        table.add_row(
            metrics.method,
            f"{metrics.known_defect_recall:.2f}",
            f"{metrics.false_positive_rate_on_controls:.2f}",
            f"{metrics.silent_write_detection_rate:.2f}",
            f"{metrics.access_regression_detection_rate:.2f}",
            f"{metrics.decision_coverage:.2f}",
            f"{metrics.selective_error:.2f}",
        )
    console.print(table)


@app.command()
def validate(
    policy: Annotated[Path, typer.Option()] = DEFAULT_POLICY,
    manifest: Annotated[Path, typer.Option()] = DEFAULT_MANIFEST,
    openapi: Annotated[Path, typer.Option()] = DEFAULT_OPENAPI,
) -> None:
    """Validate the OpenAPI document, Cedar policy, and manifest signature state."""
    try:
        policy_text = _load_policy(policy)
        document = _load_openapi(openapi)
        scope = load_manifest(manifest)
        if not isinstance(document.get("paths"), dict):
            raise ValueError("OpenAPI document has no paths object")
        if not policy_text.strip():
            raise ValueError("Cedar policy is empty")
        if scope.signature is not None and not scope.verify_signature(
            _settings().signing_secret
        ):
            raise ScopeViolationError("scope manifest signature is invalid or expired")
    except (OSError, ValueError, ScopeViolationError) as exc:
        _exit_error(str(exc))
    console.print(
        f"[green]valid[/green] policy={policy} manifest={manifest} "
        f"approved={scope.approved} paths={len(document['paths'])}"
    )


@app.command("propose-mapping")
def propose_mapping(
    openapi: Annotated[Path, typer.Option()] = DEFAULT_OPENAPI,
    policy: Annotated[Path, typer.Option()] = DEFAULT_POLICY,
    out: Annotated[Path, typer.Option()] = Path("configs/draft_mapping.yaml"),
) -> None:
    """Propose operation mappings; the output is always unapproved."""
    try:
        document = _load_openapi(openapi)
        policy_text = _load_policy(policy)
        proposal = HeuristicOperationMapper.propose_mapping(document, policy_text)
        payload = proposal.model_dump(mode="json")
        payload["approved"] = False
        _write_yaml(out, payload)
    except (OSError, ValueError, ScopeViolationError) as exc:
        _exit_error(str(exc))
    console.print(
        f"[green]wrote[/green] {out} families={len(proposal.proposed_operations)} "
        f"approved=false notes={len(proposal.notes)}"
    )


@app.command("approve-manifest")
def approve_manifest(
    manifest: Annotated[Path, typer.Option()] = DEFAULT_MANIFEST,
    policy: Annotated[Path, typer.Option()] = DEFAULT_POLICY,
    approver: Annotated[str, typer.Option()] = "sec-lead@example.org",
    expires_in_days: Annotated[int, typer.Option(min=1)] = 7,
) -> None:
    """Record a human approval and HMAC-sign the manifest in place."""
    try:
        policy_text = _load_policy(policy)
        policy_sha = hashlib.sha256(policy_text.encode("utf-8")).hexdigest()
        scope = load_manifest(manifest)
        if scope.policy_sha256 != policy_sha:
            raise ScopeViolationError(
                "manifest policy_sha256 does not match the supplied Cedar policy"
            )
        scope.approved = True
        scope.approver = approver
        scope.approved_at = datetime.now(UTC)
        scope.expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)
        scope.sign(_settings().signing_secret)
        _write_yaml(manifest, scope.model_dump(mode="json"))
        reloaded = load_manifest(manifest)
        if not reloaded.verify_signature(_settings().signing_secret):
            raise ScopeViolationError("signed manifest failed post-write verification")
    except (OSError, ValueError, ScopeViolationError) as exc:
        _exit_error(str(exc))
    console.print(
        f"[green]approved[/green] {manifest} approver={approver} "
        f"manifest_sha256={reloaded.manifest_sha256}"
    )


@app.command()
def compile(
    policy: Annotated[Path, typer.Option()] = DEFAULT_POLICY,
    manifest: Annotated[Path, typer.Option()] = DEFAULT_MANIFEST,
    out: Annotated[Path, typer.Option()] = DEFAULT_PLANS,
) -> None:
    """Compile the approved manifest into counterfactual twin plans."""
    try:
        plans = _compile(policy, manifest, _settings())
        _write_plans(out, plans)
    except (OSError, ValueError, ScopeViolationError) as exc:
        _exit_error(str(exc))
    console.print(f"[green]compiled[/green] {len(plans)} plans -> {out}")


@app.command()
def run(
    plans: Annotated[Path, typer.Option()] = DEFAULT_PLANS,
    target_url: Annotated[str, typer.Option()] = "http://testserver",
    manifest: Annotated[Path, typer.Option()] = DEFAULT_MANIFEST,
    mode: Annotated[str, typer.Option()] = "clean",
    budget: Annotated[int | None, typer.Option(min=1)] = None,
    sarif_out: Annotated[Path, typer.Option()] = Path("artifacts/janus_results.sarif.json"),
    report_out: Annotated[Path, typer.Option()] = Path("artifacts/janus_report.json"),
    witness_dir: Annotated[Path, typer.Option()] = Path("artifacts/witnesses"),
    trace_db: Annotated[Path, typer.Option()] = Path("janus_traces.sqlite3"),
    fail_on_violation: Annotated[bool, typer.Option()] = False,
) -> None:
    """Execute compiled plans, adjudicate, minimize, and export artifacts."""
    settings = _settings()
    effective_budget = budget if budget is not None else settings.max_requests
    try:
        scope = load_manifest(manifest)
        if not scope.approved:
            raise ScopeViolationError("run requires an approved manifest")
        if not scope.verify_signature(settings.signing_secret):
            raise ScopeViolationError("manifest is not signed by the configured secret")
        selected = [mode] if mode != "all" else list(ALL_MODES)
        unknown = [item for item in selected if item not in ALL_MODES]
        if unknown:
            raise ValueError(f"unknown mode(s): {', '.join(unknown)}")
        loaded = _read_plans(plans)
        client = _client_for(target_url)
        reports: list[tuple[CompiledTwinPlan, AdjudicationReport]] = []
        used = 0
        with (
            client,
            TraceStore(
                trace_db,
                encryption_key=settings.trace_encryption_key,
                retention_days=settings.retention_days,
            ) as store,
        ):
            for current_mode in selected:
                started_at = datetime.now(UTC)
                run_id = _trace_run_id(current_mode, started_at)
                mode_reports, mode_used = _execute_mode(
                    loaded,
                    scope,
                    settings,
                    client,
                    current_mode,
                    effective_budget,
                    0,
                    trace_store=store,
                    run_id=run_id,
                )
                _record_trace_run(
                    store, scope, run_id, target_url, mode_used
                )
                reports.extend(mode_reports)
                used += mode_used
        findings = _write_artifacts(
            reports,
            sarif_out=sarif_out,
            report_out=report_out,
            witness_dir=witness_dir,
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        ScopeViolationError,
    ) as exc:
        _exit_error(str(exc))
    _print_verdict_table(reports)
    console.print(
        f"[green]run complete[/green] requests={used} findings={findings} "
        f"sarif={sarif_out} report={report_out} witnesses={witness_dir}"
    )
    if findings and fail_on_violation:
        raise typer.Exit(code=2)


@app.command()
def benchmark(
    runs: Annotated[int, typer.Option(min=1)] = 1,
    budget: Annotated[int, typer.Option(min=1)] = 300,
    out_dir: Annotated[Path, typer.Option()] = Path("artifacts/benchmark_results"),
    policy: Annotated[Path, typer.Option()] = DEFAULT_POLICY,
    manifest: Annotated[Path, typer.Option()] = DEFAULT_MANIFEST,
) -> None:
    """Run the comparative benchmark against the three baselines/ablations."""
    settings = _settings()
    try:
        scope = load_manifest(manifest)
        if not scope.verify_signature(settings.signing_secret):
            raise ScopeViolationError("benchmark requires a signed manifest")
        compiled = _compile(policy, manifest, settings)
        report: BenchmarkReport | None = None
        for _ in range(runs):
            report = BenchmarkEvaluator(
                compiled, scope, signing_secret=settings.signing_secret, budget=budget
            ).run_full_evaluation()
        if report is None:
            raise RuntimeError("benchmark produced no report")
        report.write(out_dir)
    except (OSError, ValueError, RuntimeError, ScopeViolationError) as exc:
        _exit_error(str(exc))
    _print_benchmark_table(report)
    console.print(f"[green]benchmark complete[/green] -> {out_dir}")


@app.command()
def demo(
    out_dir: Annotated[Path, typer.Option()] = Path("artifacts/demo"),
) -> None:
    """Run the complete compile -> execute -> adjudicate -> minimize -> report showcase."""
    settings = _settings()
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        manifest = _signed_demo_manifest(settings)
        policy_text = _load_policy(DEFAULT_POLICY)
        compiler = WorkflowCompiler(
            CedarOracle.from_file(DEFAULT_POLICY),
            signing_secret=settings.signing_secret,
            policy_sha256=hashlib.sha256(policy_text.encode("utf-8")).hexdigest(),
            synthesizer=Z3Synthesizer(
                CedarOracle.from_file(DEFAULT_POLICY),
                timeout_ms=settings.z3_timeout_ms,
            ),
        )
        plans = compiler.compile_suite(manifest)
        _write_plans(out_dir / "compiled_plans.json", plans)

        client = TestClient(create_app(), follow_redirects=False)
        reports: list[tuple[CompiledTwinPlan, AdjudicationReport]] = []
        used = 0
        with (
            client,
            TraceStore(
                out_dir / "janus_traces.sqlite3",
                encryption_key=settings.trace_encryption_key,
                retention_days=settings.retention_days,
            ) as store,
        ):
            for mode in ALL_MODES:
                started_at = datetime.now(UTC)
                run_id = _trace_run_id(str(mode), started_at)
                mode_reports, mode_used = _execute_mode(
                    plans,
                    manifest,
                    settings,
                    client,
                    str(mode),
                    5000,
                    0,
                    trace_store=store,
                    run_id=run_id,
                )
                _record_trace_run(
                    store, manifest, run_id, "http://testserver", mode_used
                )
                reports.extend(mode_reports)
                used += mode_used
            minimized = _minimize_demo_witness(
                plans, manifest, settings, client, out_dir
            )
        findings = _write_artifacts(
            reports,
            sarif_out=out_dir / "janus_results.sarif.json",
            report_out=out_dir / "janus_report.json",
            witness_dir=out_dir / "witnesses",
        )
        benchmark_report = BenchmarkEvaluator(
            plans, manifest, signing_secret=settings.signing_secret, budget=500
        ).run_full_evaluation()
        benchmark_report.write(out_dir / "benchmark_results")
        _print_benchmark_table(benchmark_report)
        summary = {
            "plans": len(plans),
            "modes": len(ALL_MODES),
            "requests_used": used,
            "findings": findings,
            "minimization": minimized,
            "benchmark": benchmark_report.to_json()["methods"],
        }
        (out_dir / "demo_summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (
        OSError,
        ValueError,
        RuntimeError,
        ScopeViolationError,
    ) as exc:
        _exit_error(str(exc))
    _print_verdict_table(reports)
    console.print(
        f"[green]demo complete[/green] plans={len(plans)} findings={findings} "
        f"requests={used} out={out_dir}"
    )
    if minimized is not None:
        console.print(
            f"minimized {minimized['original_step_count']} -> "
            f"{minimized['minimized_step_count']} steps "
            f"({minimized['reduction_ratio']:.2f} reduction)"
        )


if __name__ == "__main__":
    app()
