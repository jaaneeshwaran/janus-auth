"""End-to-end tests for reporting artifacts and the CLI (Tasks 11-13)."""

from __future__ import annotations

import ast
import json
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
import uvicorn
import yaml
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from janus_auth.benchmark import BenchmarkEvaluator
from janus_auth.cli import app as cli_app
from janus_auth.compiler import WorkflowCompiler, load_manifest
from janus_auth.models import (
    AdjudicationReport,
    ApiStep,
    BranchSummary,
    CompiledTwinPlan,
    CounterfactualPairPlan,
    Decision,
    ExpectedRole,
    ProbeType,
    ScopeManifest,
    SupportState,
    TransitionFamily,
    VerdictKind,
    ViolationSubtype,
)
from janus_auth.oracle import CedarOracle
from janus_auth.oracle.adjudicator import adjudicate
from janus_auth.reporting.replay_codegen import (
    generate_replay_witness,
    witness_is_credential_free,
    write_replay_witness,
)
from janus_auth.reporting.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    build_sarif,
    write_sarif,
)
from janus_auth.runner import CounterfactualExecutor
from janus_auth.security.gatekeeper import SafetyGatekeeper
from janus_auth.security.store import TraceStore
from janus_auth.targets.docvault_app import create_app

CANARY = "JANUS_CANARY_reporting"
REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "configs" / "docvault.cedar"
MANIFEST_PATH = REPO_ROOT / "configs" / "docvault_manifest.yaml"
TEST_SIGNING_SECRET = "task-12-tests-only-secret"  # noqa: S105


def _support() -> SupportState:
    return SupportState(
        principal_id="bea",
        resource_id="doc_1",
        action=ProbeType.PROTECTED_READ,
    )


def _plan(*, masked: bool = False) -> CompiledTwinPlan:
    synthesized = CounterfactualPairPlan(
        plan_id="ct-report",
        transition_family=TransitionFamily.DIRECT_SHARE_REVOKE,
        probe_type=ProbeType.PROTECTED_READ,
        principal_role_class="same_tenant_peer",
        branch_a_pre=_support(),
        branch_a_post=_support(),
        branch_a_expected=Decision.DENY,
        branch_b_pre=_support(),
        branch_b_post=_support(),
        branch_b_expected=Decision.ALLOW,
        surviving_support_name="group",
        hamming_distance=1,
    )
    steps = [
        ApiStep(
            step_id="reset",
            method="POST",
            path_template="/api/v1/admin/reset",
            principal_alias="ops_admin",
            json_body={"vulnerability_mode": "clean"},
            expected_role=ExpectedRole.SETUP,
            reversible=False,
        ),
        ApiStep(
            step_id="probe",
            method="GET",
            path_template="/api/v1/documents/{doc_id}",
            principal_alias="bea",
            expected_role=ExpectedRole.PROBE,
            reversible=True,
        ),
        ApiStep(
            step_id="effect-witness",
            method="GET",
            path_template="/api/v1/documents/{doc_id}",
            principal_alias="ada",
            expected_role=ExpectedRole.EFFECT_WITNESS,
            reversible=True,
        ),
    ]
    return CompiledTwinPlan(
        plan_id="ct-report-protected_read",
        synthesized=synthesized,
        branch_a_steps=steps,
        branch_b_steps=steps,
        canary=CANARY,
        probe_principal="bea",
        masked_control=masked,
    )


def _report(
    verdict: VerdictKind,
    subtype: ViolationSubtype = ViolationSubtype.NONE,
    *,
    a_canary: bool = False,
) -> AdjudicationReport:
    return AdjudicationReport(
        plan_id="ct-report-protected_read",
        verdict=verdict,
        subtype=subtype,
        branch_a_summary=BranchSummary(
            branch="A",
            probe_status_code=200 if a_canary else 403,
            canary_present=a_canary,
            access_allowed=a_canary,
        ),
        branch_b_summary=BranchSummary(
            branch="B",
            probe_status_code=200,
            canary_present=True,
            access_allowed=True,
        ),
        reproduction_verified=True,
    )


def test_sarif_is_structurally_valid_and_contains_both_branches(tmp_path: Path) -> None:
    plan = _plan()
    findings = [
        (
            plan,
            _report(
                VerdictKind.CONFIRMED_VIOLATION,
                ViolationSubtype.BOLA_READ_LEAK,
                a_canary=True,
            ),
        ),
        (plan, _report(VerdictKind.CONFORMS)),
    ]
    sarif = build_sarif(findings)
    assert sarif["$schema"] == SARIF_SCHEMA
    assert sarif["version"] == SARIF_VERSION
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "janus-auth"
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        f"JANUS00{index}" for index in range(1, 7)
    ]
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "JANUS001"
    assert "Branch A:" in result["message"]["text"]
    assert "Branch B:" in result["message"]["text"]
    assert plan.plan_id in result["message"]["text"]
    uris = {
        location["physicalLocation"]["artifactLocation"]["uri"]
        for location in result["locations"]
    }
    assert uris == {"configs/docvault.cedar", "configs/docvault_manifest.yaml"}

    path = write_sarif(tmp_path / "results.sarif.json", sarif)
    reloaded = json.loads(path.read_text(encoding="utf-8"))
    assert reloaded == sarif


def test_sarif_exports_only_confirmed_findings() -> None:
    sarif = build_sarif([(_plan(), _report(VerdictKind.CONFORMS))])
    assert sarif["runs"][0]["results"] == []


def test_replay_witness_is_deterministic_parseable_and_credential_free(
    tmp_path: Path,
) -> None:
    plan = _plan()
    report = _report(
        VerdictKind.CONFIRMED_VIOLATION,
        ViolationSubtype.BOLA_READ_LEAK,
        a_canary=True,
    )
    first = generate_replay_witness(plan, report)
    second = generate_replay_witness(plan, report)
    assert first == second
    tree = ast.parse(first)
    assert tree is not None
    assert "test_branch_a_last_grant_revoked_must_deny()" in first
    assert "test_branch_b_surviving_grant_must_allow()" in first
    assert "JANUS_TOKEN_ADA" in first
    assert "JANUS_TARGET_URL" in first
    assert witness_is_credential_free(first)

    path = write_replay_witness(tmp_path, plan, report)
    assert path.name.startswith("witness_")
    assert path.read_text(encoding="utf-8") == first


def test_generated_witness_passes_ruff(tmp_path: Path) -> None:
    path = write_replay_witness(
        tmp_path,
        _plan(),
        _report(
            VerdictKind.CONFIRMED_VIOLATION,
            ViolationSubtype.BOLA_READ_LEAK,
            a_canary=True,
        ),
    )
    ruff = Path(sys.executable).parent / "ruff"
    completed = subprocess.run(  # noqa: S603 - fixed local ruff binary, no shell
        [
            str(ruff),
            "check",
            "--isolated",
            "--select",
            "E,F,I,UP,B,S",
            "--line-length",
            "100",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.fixture(scope="module")
def benchmark_inputs() -> tuple[list[CompiledTwinPlan], ScopeManifest]:
    manifest = load_manifest(MANIFEST_PATH)
    manifest.approved = True
    manifest.approver = "task-12-tests"
    manifest.approved_at = datetime.now(UTC)
    signed = manifest.sign(TEST_SIGNING_SECRET)
    compiler = WorkflowCompiler(
        CedarOracle.from_file(POLICY_PATH), signing_secret=TEST_SIGNING_SECRET
    )
    return compiler.compile_suite(signed), signed


def test_benchmark_full_system_meets_targets_and_beats_baselines(
    benchmark_inputs: tuple[list[CompiledTwinPlan], ScopeManifest],
    tmp_path: Path,
) -> None:
    plans, manifest = benchmark_inputs
    evaluator = BenchmarkEvaluator(
        plans, manifest, signing_secret=TEST_SIGNING_SECRET, budget=300
    )
    report = evaluator.run_full_evaluation()
    assert report.requests_used <= 300

    full = report.methods["janus_full_system"]
    assert full.known_defect_recall == 1.0
    assert full.false_positive_rate_on_controls == 0.0
    assert full.silent_write_detection_rate == 1.0
    assert full.access_regression_detection_rate == 1.0
    assert full.selective_error == 0.0

    for name, metrics in report.methods.items():
        if name == "janus_full_system":
            continue
        assert (
            metrics.known_defect_recall < full.known_defect_recall
            or metrics.false_positive_rate_on_controls
            > full.false_positive_rate_on_controls
            or metrics.silent_write_detection_rate
            < full.silent_write_detection_rate
            or metrics.access_regression_detection_rate
            < full.access_regression_detection_rate
        ), name

    json_path, markdown_path = report.write(tmp_path)
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["methods"]["janus_full_system"]["known_defect_recall"] == 1.0
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "janus_full_system" in markdown
    assert "static_cross_user_replay" in markdown


def test_benchmark_is_deterministic(
    benchmark_inputs: tuple[list[CompiledTwinPlan], ScopeManifest],
) -> None:
    plans, manifest = benchmark_inputs
    first = BenchmarkEvaluator(
        plans, manifest, signing_secret=TEST_SIGNING_SECRET, budget=300
    ).run_full_evaluation()
    second = BenchmarkEvaluator(
        plans, manifest, signing_secret=TEST_SIGNING_SECRET, budget=300
    ).run_full_evaluation()
    assert first.to_json() == second.to_json()


@pytest.fixture()
def cli_secret(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("JANUS_SIGNING_SECRET", TEST_SIGNING_SECRET)
    monkeypatch.setenv("JANUS_TRACE_ENCRYPTION_KEY", "task-13-trace-key")
    return TEST_SIGNING_SECRET


def _runner() -> CliRunner:
    return CliRunner()


def _approved_manifest(tmp_path: Path, secret: str) -> Path:
    target = tmp_path / "manifest.yaml"
    target.write_text(MANIFEST_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    result = _runner().invoke(
        cli_app,
        [
            "approve-manifest",
            "--manifest",
            str(target),
            "--policy",
            str(POLICY_PATH),
            "--approver",
            "cli-tests@example.org",
        ],
    )
    assert result.exit_code == 0, result.output
    assert secret
    return target


@pytest.fixture()
def approved_manifest_file(tmp_path: Path, cli_secret: str) -> Path:
    return _approved_manifest(tmp_path, cli_secret)


@pytest.fixture()
def compiled_plans_file(
    tmp_path: Path, approved_manifest_file: Path, cli_secret: str
) -> Path:
    target = tmp_path / "plans.json"
    result = _runner().invoke(
        cli_app,
        [
            "compile",
            "--policy",
            str(POLICY_PATH),
            "--manifest",
            str(approved_manifest_file),
            "--out",
            str(target),
        ],
    )
    assert result.exit_code == 0, result.output
    return target


def test_cli_validate_and_propose_mapping(tmp_path: Path, cli_secret: str) -> None:
    result = _runner().invoke(
        cli_app,
        [
            "validate",
            "--policy",
            str(POLICY_PATH),
            "--manifest",
            str(MANIFEST_PATH),
            "--openapi",
            str(MANIFEST_PATH.parent / "docvault_openapi.json"),
        ],
    )
    assert result.exit_code == 0, result.output

    draft = tmp_path / "draft.yaml"
    result = _runner().invoke(
        cli_app,
        [
            "propose-mapping",
            "--openapi",
            str(MANIFEST_PATH.parent / "docvault_openapi.json"),
            "--policy",
            str(POLICY_PATH),
            "--out",
            str(draft),
        ],
    )
    assert result.exit_code == 0, result.output
    payload = yaml.safe_load(draft.read_text(encoding="utf-8"))
    assert payload["approved"] is False
    assert set(payload["proposed_operations"]) == {
        "direct_share_revoke",
        "group_member_remove",
        "delegation_revoke",
        "role_downgrade",
        "ownership_transfer",
        "tenant_change",
    }


def test_cli_approve_and_compile(
    approved_manifest_file: Path, compiled_plans_file: Path, cli_secret: str
) -> None:
    reloaded = load_manifest(approved_manifest_file)
    assert reloaded.approved is True
    assert reloaded.verify_signature(cli_secret) is True
    plans = json.loads(compiled_plans_file.read_text(encoding="utf-8"))
    assert len(plans) == 12


def test_cli_run_clean_and_failing_violation(
    tmp_path: Path,
    approved_manifest_file: Path,
    compiled_plans_file: Path,
    cli_secret: str,
) -> None:
    out = tmp_path / "clean"
    result = _runner().invoke(
        cli_app,
        [
            "run",
            "--plans",
            str(compiled_plans_file),
            "--target-url",
            "http://testserver",
            "--manifest",
            str(approved_manifest_file),
            "--mode",
            "clean",
            "--budget",
            "500",
            "--sarif-out",
            str(out / "results.sarif.json"),
            "--report-out",
            str(out / "report.json"),
            "--witness-dir",
            str(out / "witnesses"),
            "--trace-db",
            str(out / "traces.sqlite3"),
        ],
    )
    assert result.exit_code == 0, result.output
    sarif = json.loads((out / "results.sarif.json").read_text(encoding="utf-8"))
    assert sarif["runs"][0]["results"] == []
    reports = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert len(reports) == 12
    with TraceStore(
        out / "traces.sqlite3",
        encryption_key="task-13-trace-key",
        retention_days=7,
    ) as store:
        run_ids = store.fetch_run_ids()
        assert len(run_ids) == 1
        verdicts = store.fetch_verdicts(run_ids[0])
        assert len(verdicts) == 12
        trace_text = json.dumps(verdicts)
        assert "token_ada" not in trace_text

    finding_out = tmp_path / "silent"
    result = _runner().invoke(
        cli_app,
        [
            "run",
            "--plans",
            str(compiled_plans_file),
            "--target-url",
            "http://testserver",
            "--manifest",
            str(approved_manifest_file),
            "--mode",
            "vuln_silent_write_on_403",
            "--budget",
            "500",
            "--sarif-out",
            str(finding_out / "results.sarif.json"),
            "--report-out",
            str(finding_out / "report.json"),
            "--witness-dir",
            str(finding_out / "witnesses"),
            "--trace-db",
            str(finding_out / "traces.sqlite3"),
            "--fail-on-violation",
        ],
    )
    assert result.exit_code == 2, result.output
    sarif = json.loads(
        (finding_out / "results.sarif.json").read_text(encoding="utf-8")
    )
    assert sarif["runs"][0]["results"]
    witnesses = list((finding_out / "witnesses").rglob("witness_*.py"))
    assert witnesses
    artifact_text = (
        (finding_out / "results.sarif.json").read_text(encoding="utf-8")
        + (finding_out / "report.json").read_text(encoding="utf-8")
        + "".join(witness.read_text(encoding="utf-8") for witness in witnesses)
    )
    for token in (
        "token_ada",
        "token_bea",
        "token_carl",
        "token_dana",
        "token_admin",
    ):
        assert token not in artifact_text


def test_cli_demo_generates_all_artifacts(
    tmp_path: Path, cli_secret: str
) -> None:
    out = tmp_path / "demo"
    result = _runner().invoke(cli_app, ["demo", "--out-dir", str(out)])
    assert result.exit_code == 0, result.output
    for artifact in (
        "compiled_plans.json",
        "janus_results.sarif.json",
        "janus_report.json",
        "demo_summary.json",
        "minimized_plan.json",
        "janus_traces.sqlite3",
        "benchmark_results/benchmark_report.json",
        "benchmark_results/benchmark_report.md",
    ):
        assert (out / artifact).is_file(), artifact
    summary = json.loads((out / "demo_summary.json").read_text(encoding="utf-8"))
    assert summary["plans"] == 12
    assert summary["findings"] >= 6
    assert summary["minimization"]["reproduction_verified"] is True
    assert summary["minimization"]["reduction_ratio"] >= 0.35
    assert any((out / "witnesses").rglob("witness_*.py"))


def test_generated_witness_reproduces_against_a_live_server(
    tmp_path: Path,
    benchmark_inputs: tuple[list[CompiledTwinPlan], ScopeManifest],
) -> None:
    plans, manifest = benchmark_inputs
    plan = next(
        item
        for item in plans
        if item.synthesized.probe_type is ProbeType.REVERSIBLE_WRITE
        and item.plan_id.startswith("ct-direct_share_revoke")
    )
    with TestClient(create_app(), follow_redirects=False) as client:
        executor = CounterfactualExecutor(
            client,
            SafetyGatekeeper(manifest, secret=TEST_SIGNING_SECRET),
            mode="vuln_silent_write_on_403",
        )
        report = adjudicate(plan, executor.execute(plan))
    assert report.verdict is VerdictKind.CONFIRMED_VIOLATION
    report = report.model_copy(
        update={
            "evidence": {
                **report.evidence,
                "mode": "vuln_silent_write_on_403",
            }
        }
    )
    witness = write_replay_witness(tmp_path, plan, report)

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = int(probe.getsockname()[1])
    config = uvicorn.Config(
        create_app(), host="127.0.0.1", port=port, log_level="error"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(500):
        if server.started:
            break
        time.sleep(0.01)
    assert server.started
    env = os.environ.copy()
    env.update(
        {
            "JANUS_TARGET_URL": f"http://127.0.0.1:{port}",
            "JANUS_TOKEN_ADA": "token_ada",
            "JANUS_TOKEN_BEA": "token_bea",
            "JANUS_TOKEN_CARL": "token_carl",
            "JANUS_TOKEN_DANA": "token_dana",
            "JANUS_TOKEN_ADMIN": "token_admin",
        }
    )
    try:
        completed = subprocess.run(  # noqa: S603 - fixed interpreter, no shell
            [sys.executable, "-m", "pytest", str(witness), "-q"],
            capture_output=True,
            text=True,
            env=env,
            cwd=tmp_path,
            check=False,
        )
    finally:
        server.should_exit = True
        thread.join(timeout=5)
    assert completed.returncode == 0, completed.stdout + completed.stderr

