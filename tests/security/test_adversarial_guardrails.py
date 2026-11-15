"""Adversarial guardrail tests for the CLI and its security boundaries."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from janus_auth.cli import app as cli_app
from janus_auth.compiler import load_manifest

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "configs" / "docvault.cedar"
MANIFEST_PATH = REPO_ROOT / "configs" / "docvault_manifest.yaml"
OPENAPI_PATH = REPO_ROOT / "configs" / "docvault_openapi.json"
TEST_SIGNING_SECRET = "task-13-adversarial-secret"  # noqa: S105


def _runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JANUS_SIGNING_SECRET", TEST_SIGNING_SECRET)


def _approved_manifest(tmp_path: Path) -> Path:
    manifest = load_manifest(MANIFEST_PATH)
    manifest.approved = True
    manifest.approver = "adversarial-tests"
    manifest.approved_at = datetime.now(UTC)
    manifest.sign(TEST_SIGNING_SECRET)
    target = tmp_path / "approved.yaml"
    target.write_text(
        yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    return target


def _compile(tmp_path: Path, manifest: Path) -> Path:
    plans = tmp_path / "plans.json"
    result = _runner().invoke(
        cli_app,
        [
            "compile",
            "--policy",
            str(POLICY_PATH),
            "--manifest",
            str(manifest),
            "--out",
            str(plans),
        ],
    )
    assert result.exit_code == 0, result.output
    return plans


def test_oversized_manifest_is_rejected_before_parsing(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.yaml"
    oversized.write_bytes(b"approved: false\n" + b"#" * (5 * 1024 * 1024 + 1))
    result = _runner().invoke(
        cli_app,
        [
            "validate",
            "--policy",
            str(POLICY_PATH),
            "--manifest",
            str(oversized),
            "--openapi",
            str(OPENAPI_PATH),
        ],
    )
    assert result.exit_code == 1
    assert "too large" in result.output.lower()


def test_unsigned_manifest_cannot_compile(tmp_path: Path) -> None:
    result = _runner().invoke(
        cli_app,
        [
            "compile",
            "--policy",
            str(POLICY_PATH),
            "--manifest",
            str(MANIFEST_PATH),
            "--out",
            str(tmp_path / "plans.json"),
        ],
    )
    assert result.exit_code == 1


def test_tampered_approved_manifest_cannot_compile(tmp_path: Path) -> None:
    approved = _approved_manifest(tmp_path)
    payload = yaml.safe_load(approved.read_text(encoding="utf-8"))
    payload["policy_sha256"] = "0" * 64
    approved.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    result = _runner().invoke(
        cli_app,
        [
            "compile",
            "--policy",
            str(POLICY_PATH),
            "--manifest",
            str(approved),
            "--out",
            str(tmp_path / "plans.json"),
        ],
    )
    assert result.exit_code == 1


def test_approve_manifest_rejects_a_policy_hash_mismatch(tmp_path: Path) -> None:
    draft = tmp_path / "draft.yaml"
    payload = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    payload["policy_sha256"] = "1" * 64
    draft.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    result = _runner().invoke(
        cli_app,
        [
            "approve-manifest",
            "--manifest",
            str(draft),
            "--policy",
            str(POLICY_PATH),
            "--approver",
            "attacker@example.org",
        ],
    )
    assert result.exit_code == 1


def test_run_rejects_an_ssrf_target(tmp_path: Path) -> None:
    approved = _approved_manifest(tmp_path)
    plans = _compile(tmp_path, approved)
    result = _runner().invoke(
        cli_app,
        [
            "run",
            "--plans",
            str(plans),
            "--target-url",
            "http://169.254.169.254",
            "--manifest",
            str(approved),
            "--mode",
            "clean",
            "--sarif-out",
            str(tmp_path / "out.sarif.json"),
            "--report-out",
            str(tmp_path / "out.json"),
            "--witness-dir",
            str(tmp_path / "witnesses"),
        ],
    )
    assert result.exit_code == 1
    assert "allowed_hosts" in result.output or "blocked" in result.output


def test_run_rejects_an_unsigned_manifest(tmp_path: Path) -> None:
    approved = _approved_manifest(tmp_path)
    plans = _compile(tmp_path, approved)
    result = _runner().invoke(
        cli_app,
        [
            "run",
            "--plans",
            str(plans),
            "--target-url",
            "http://testserver",
            "--manifest",
            str(MANIFEST_PATH),
            "--mode",
            "clean",
            "--sarif-out",
            str(tmp_path / "out.sarif.json"),
            "--report-out",
            str(tmp_path / "out.json"),
            "--witness-dir",
            str(tmp_path / "witnesses"),
        ],
    )
    assert result.exit_code == 1
