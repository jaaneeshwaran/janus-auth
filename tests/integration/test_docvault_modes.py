"""Integration tests for the DocVault target across all seven enforcement modes."""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from janus_auth.compiler import WorkflowCompiler, load_manifest
from janus_auth.models import ApiStep, CompiledTwinPlan, ExpectedRole, ScopeManifest
from janus_auth.oracle import CedarOracle
from janus_auth.runner import CounterfactualExecutor
from janus_auth.security.gatekeeper import SafetyGatekeeper, ScopeViolationError
from janus_auth.targets.docvault_app import ALL_MODES, Mode, create_app

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "configs" / "docvault.cedar"
MANIFEST_PATH = REPO_ROOT / "configs" / "docvault_manifest.yaml"
TEST_SIGNING_SECRET = "task-8-tests-only-secret"  # noqa: S105

CANARY = "JANUS_CANARY_testdoc"
MUTATED_BY_BEA = "MUTATED_BY_bea"  # noqa: S105 - synthetic probe payload, not a credential
ADA = {"Authorization": "Bearer token_ada"}
BEA = {"Authorization": "Bearer token_bea"}
CARL = {"Authorization": "Bearer token_carl"}
DANA = {"Authorization": "Bearer token_dana"}
ADMIN = {"Authorization": "Bearer token_admin"}


@pytest.fixture()
def client() -> Iterator[TestClient]:
    app = create_app()
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def _reset(client: TestClient, mode: Mode = "clean") -> dict[str, object]:
    response = client.post(
        "/api/v1/admin/reset", json={"vulnerability_mode": mode}
    )
    assert response.status_code == 200
    return dict(response.json())


def _create(client: TestClient, *, owner: dict[str, str] = ADA) -> str:
    response = client.post(
        "/api/v1/documents",
        headers=owner,
        json={
            "title": "Q4 Plan",
            "public_summary": "A quarterly plan",
            "secret_content": CANARY,
        },
    )
    assert response.status_code == 201
    return str(response.json()["id"])


def _share(client: TestClient, doc_id: str, user_id: str = "bea", permission: str = "read") -> None:
    response = client.post(
        f"/api/v1/documents/{doc_id}/shares",
        headers=ADA,
        json={"user_id": user_id, "permission": permission},
    )
    assert response.status_code == 200


def _group_share(client: TestClient, doc_id: str, permission: str = "read") -> None:
    response = client.post(
        f"/api/v1/documents/{doc_id}/group-shares",
        headers=ADA,
        json={"group_id": "eng_group", "permission": permission},
    )
    assert response.status_code == 200


def _join_group(client: TestClient, user_id: str = "bea") -> None:
    response = client.post(
        "/api/v1/groups/eng_group/members", headers=ADA, json={"user_id": user_id}
    )
    assert response.status_code == 200


def test_reset_is_deterministic_and_increments_the_epoch(client: TestClient) -> None:
    first = _reset(client, "clean")
    second = _reset(client, "clean")
    assert first == {"status": "reset", "mode": "clean", "epoch": 1}
    assert second == {"status": "reset", "mode": "clean", "epoch": 2}
    assert client.get("/api/v1/documents", headers=ADA).json() == []

    for mode in ALL_MODES:
        body = _reset(client, mode)
        assert body["mode"] == mode
        assert body["epoch"] == int(body["epoch"])


def test_all_sixteen_operations_are_registered(client: TestClient) -> None:
    routes = {
        (method, route.path)
        for route in client.app.routes
        for method in getattr(route, "methods", set())
        if route.path.startswith("/api/v1/")
    }
    expected = {
        ("POST", "/api/v1/admin/reset"),
        ("POST", "/api/v1/documents"),
        ("GET", "/api/v1/documents"),
        ("GET", "/api/v1/documents/{doc_id}"),
        ("PATCH", "/api/v1/documents/{doc_id}"),
        ("GET", "/api/v1/documents/{doc_id}/permissions"),
        ("POST", "/api/v1/documents/{doc_id}/shares"),
        ("DELETE", "/api/v1/documents/{doc_id}/shares/{user_id}"),
        ("POST", "/api/v1/groups/{group_id}/members"),
        ("DELETE", "/api/v1/groups/{group_id}/members/{user_id}"),
        ("POST", "/api/v1/documents/{doc_id}/group-shares"),
        ("POST", "/api/v1/documents/{doc_id}/delegations"),
        ("DELETE", "/api/v1/documents/{doc_id}/delegations/{to_user_id}"),
        ("POST", "/api/v1/users/{user_id}/role"),
        ("POST", "/api/v1/documents/{doc_id}/transfer"),
        ("POST", "/api/v1/users/{user_id}/tenant"),
        ("POST", "/api/v1/documents/{doc_id}/denies"),
    }
    assert expected <= routes


def test_clean_mode_enforces_every_support_path(client: TestClient) -> None:
    _reset(client)
    doc_id = _create(client)
    assert client.get(f"/api/v1/documents/{doc_id}", headers=ADA).status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 403

    _share(client, doc_id)
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 200

    group_doc = _create(client)
    _group_share(client, group_doc)
    _join_group(client)
    assert client.get(f"/api/v1/documents/{group_doc}", headers=BEA).status_code == 200

    delegated_doc = _create(client)
    response = client.post(
        f"/api/v1/documents/{delegated_doc}/delegations",
        headers=ADA,
        json={"from_user_id": "ada", "to_user_id": "bea", "permission": "read"},
    )
    assert response.status_code == 200
    assert client.get(f"/api/v1/documents/{delegated_doc}", headers=BEA).status_code == 200

    admin_doc = _create(client)
    response = client.post(
        "/api/v1/users/bea/role", headers=ADMIN, json={"role": "admin"}
    )
    assert response.status_code == 200
    assert client.get(f"/api/v1/documents/{admin_doc}", headers=BEA).status_code == 200


def test_tenant_isolation_and_explicit_deny_override(client: TestClient) -> None:
    _reset(client)
    doc_id = _create(client)
    _share(client, doc_id, "bea")
    assert client.get(f"/api/v1/documents/{doc_id}", headers=DANA).status_code == 403

    response = client.post(
        f"/api/v1/documents/{doc_id}/denies",
        headers=ADA,
        json={"user_id": "bea", "permission": "read"},
    )
    assert response.status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 403


def test_masked_read_returns_public_summary_without_the_canary(client: TestClient) -> None:
    _reset(client)
    doc_id = _create(client)
    denied = client.get(f"/api/v1/documents/{doc_id}?masked=true", headers=BEA)
    assert denied.status_code == 200
    assert denied.json()["secret_content"] is None
    assert denied.json()["title"] == "Q4 Plan"
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 403

    owner = client.get(f"/api/v1/documents/{doc_id}?masked=true", headers=ADA)
    assert owner.status_code == 200
    assert owner.json()["secret_content"] == CANARY


def test_vuln_stale_direct_cache_leaks_after_revocation(client: TestClient) -> None:
    _reset(client, "vuln_stale_direct_cache")
    doc_id = _create(client)
    _share(client, doc_id)
    assert client.delete(f"/api/v1/documents/{doc_id}/shares/bea", headers=ADA).status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 200

    _reset(client, "clean")
    doc_id = _create(client)
    _share(client, doc_id)
    assert client.delete(f"/api/v1/documents/{doc_id}/shares/bea", headers=ADA).status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 403


def test_vuln_group_revocation_ignored_keeps_pending_member_active(client: TestClient) -> None:
    _reset(client, "vuln_group_revocation_ignored")
    doc_id = _create(client)
    _group_share(client, doc_id)
    _join_group(client)
    response = client.delete("/api/v1/groups/eng_group/members/bea", headers=ADA)
    assert response.status_code == 200
    assert response.json()["status"] == "pending_removal"
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 200

    _reset(client, "clean")
    doc_id = _create(client)
    _group_share(client, doc_id)
    _join_group(client)
    assert client.delete("/api/v1/groups/eng_group/members/bea", headers=ADA).status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 403


def test_vuln_transfer_retains_the_former_owner(client: TestClient) -> None:
    _reset(client, "vuln_transfer_retains_owner")
    doc_id = _create(client)
    response = client.post(
        f"/api/v1/documents/{doc_id}/transfer",
        headers=ADA,
        json={"new_owner_id": "carl", "retain_old_owner_direct_share": False},
    )
    assert response.status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=ADA).status_code == 200

    _reset(client, "clean")
    doc_id = _create(client)
    response = client.post(
        f"/api/v1/documents/{doc_id}/transfer",
        headers=ADA,
        json={"new_owner_id": "carl", "retain_old_owner_direct_share": False},
    )
    assert response.status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=ADA).status_code == 403


def test_vuln_broken_delegation_cascade_ignores_the_parent_grant(client: TestClient) -> None:
    _reset(client, "vuln_broken_delegation_cascade")
    doc_id = _create(client)
    _share(client, doc_id, "carl")
    response = client.post(
        f"/api/v1/documents/{doc_id}/delegations",
        headers=ADA,
        json={"from_user_id": "carl", "to_user_id": "bea", "permission": "read"},
    )
    assert response.status_code == 200
    assert client.delete(f"/api/v1/documents/{doc_id}/shares/carl", headers=ADA).status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 200

    _reset(client, "clean")
    doc_id = _create(client)
    _share(client, doc_id, "carl")
    response = client.post(
        f"/api/v1/documents/{doc_id}/delegations",
        headers=ADA,
        json={"from_user_id": "carl", "to_user_id": "bea", "permission": "read"},
    )
    assert response.status_code == 200
    assert client.delete(f"/api/v1/documents/{doc_id}/shares/carl", headers=ADA).status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 403


def test_vuln_silent_write_mutates_before_the_403(client: TestClient) -> None:
    _reset(client, "vuln_silent_write_on_403")
    doc_id = _create(client)
    probe = client.patch(
        f"/api/v1/documents/{doc_id}",
        headers=BEA,
        json={"secret_content": "MUTATED_BY_bea"},
    )
    assert probe.status_code == 403
    witness = client.get(f"/api/v1/documents/{doc_id}", headers=ADA)
    assert witness.status_code == 200
    assert witness.json()["secret_content"] == MUTATED_BY_BEA

    _reset(client, "clean")
    doc_id = _create(client)
    probe = client.patch(
        f"/api/v1/documents/{doc_id}",
        headers=BEA,
        json={"secret_content": "MUTATED_BY_bea"},
    )
    assert probe.status_code == 403
    witness = client.get(f"/api/v1/documents/{doc_id}", headers=ADA)
    assert witness.json()["secret_content"] == CANARY


def test_vuln_over_revocation_strips_surviving_group_access(client: TestClient) -> None:
    _reset(client, "vuln_over_revocation_regression")
    doc_id = _create(client)
    _group_share(client, doc_id)
    _join_group(client)
    _share(client, doc_id)
    assert client.delete(f"/api/v1/documents/{doc_id}/shares/bea", headers=ADA).status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 403

    _reset(client, "clean")
    doc_id = _create(client)
    _group_share(client, doc_id)
    _join_group(client)
    _share(client, doc_id)
    assert client.delete(f"/api/v1/documents/{doc_id}/shares/bea", headers=ADA).status_code == 200
    assert client.get(f"/api/v1/documents/{doc_id}", headers=BEA).status_code == 200


def test_read_grant_does_not_authorize_write(client: TestClient) -> None:
    _reset(client)
    doc_id = _create(client)
    _share(client, doc_id, "bea", "read")
    response = client.patch(
        f"/api/v1/documents/{doc_id}",
        headers=BEA,
        json={"secret_content": "MUTATED_BY_bea"},
    )
    assert response.status_code == 403

    _share(client, doc_id, "bea", "write")
    response = client.patch(
        f"/api/v1/documents/{doc_id}",
        headers=BEA,
        json={"secret_content": "MUTATED_BY_bea"},
    )
    assert response.status_code == 200
    assert response.json()["secret_content"] == MUTATED_BY_BEA


def test_permissions_witness_and_administration_endpoints(client: TestClient) -> None:
    _reset(client)
    doc_id = _create(client)
    _share(client, doc_id)
    permissions = client.get(
        f"/api/v1/documents/{doc_id}/permissions", headers=ADA
    )
    assert permissions.status_code == 200
    assert permissions.json()["owner_id"] == "ada"
    assert permissions.json()["direct_users"] == ["bea"]
    assert client.get(f"/api/v1/documents/{doc_id}/permissions", headers=CARL).status_code == 403

    assert client.post(
        "/api/v1/users/bea/role", headers=BEA, json={"role": "admin"}
    ).status_code == 403
    tenant = client.post(
        "/api/v1/users/dana/tenant",
        headers=ADMIN,
        json={"tenant_id": "acme", "active": True},
    )
    assert tenant.status_code == 200
    assert tenant.json()["tenant_id"] == "acme"


def test_authentication_and_not_found_paths(client: TestClient) -> None:
    _reset(client)
    assert client.get("/api/v1/documents").status_code == 401
    assert client.get(
        "/api/v1/documents/doc_missing", headers=ADA
    ).status_code == 404
    assert client.post(
        "/api/v1/admin/reset", json={"vulnerability_mode": "not_a_mode"}
    ).status_code == 422


class CountingGatekeeper(SafetyGatekeeper):
    """Gatekeeper that counts every admitted request for the executor tests."""

    def __init__(self, manifest: ScopeManifest, *, secret: str | None = None) -> None:
        super().__init__(manifest, secret=secret)
        self.calls = 0

    def validate_request(self, url: str, method: str = "GET") -> None:
        self.calls += 1
        super().validate_request(url, method)


def _signed_manifest() -> ScopeManifest:
    manifest = load_manifest(MANIFEST_PATH)
    manifest.approved = True
    manifest.approver = "task-8-tests"
    manifest.approved_at = datetime.now(UTC)
    return manifest.sign(TEST_SIGNING_SECRET)


@pytest.fixture(scope="module")
def signed_manifest() -> ScopeManifest:
    return _signed_manifest()


@pytest.fixture(scope="module")
def compiled_plans(signed_manifest: ScopeManifest) -> list[CompiledTwinPlan]:
    oracle = CedarOracle.from_file(POLICY_PATH)
    compiler = WorkflowCompiler(oracle, signing_secret=TEST_SIGNING_SECRET)
    return compiler.compile_suite(signed_manifest)


@pytest.fixture()
def executor(
    client: TestClient, signed_manifest: ScopeManifest
) -> tuple[CounterfactualExecutor, CountingGatekeeper]:
    gatekeeper = CountingGatekeeper(signed_manifest, secret=TEST_SIGNING_SECRET)
    return (
        CounterfactualExecutor(client, gatekeeper, mode="clean"),
        gatekeeper,
    )


def test_executor_runs_every_compiled_plan_from_isolated_resets(
    executor: tuple[CounterfactualExecutor, CountingGatekeeper],
    compiled_plans: list[CompiledTwinPlan],
) -> None:
    runner, gatekeeper = executor
    for plan in compiled_plans:
        evidence = runner.execute(plan)
        assert evidence.branch_a.valid, plan.plan_id
        assert evidence.branch_b.valid, plan.plan_id
        assert evidence.branch_a_reset_epoch >= 1
        assert evidence.branch_b_reset_epoch > evidence.branch_a_reset_epoch
        assert evidence.branch_a.plan_id == plan.plan_id
        assert evidence.branch_b.plan_id == plan.plan_id
    assert gatekeeper.requests_used == sum(
        len(plan.branch_a_steps) + len(plan.branch_b_steps)
        for plan in compiled_plans
    )


def test_executor_redacts_credentials_from_paired_evidence(
    executor: tuple[CounterfactualExecutor, CountingGatekeeper],
    compiled_plans: list[CompiledTwinPlan],
) -> None:
    runner, _ = executor
    evidence = runner.execute(compiled_plans[0])
    serialized = json.dumps(evidence.model_dump(mode="json"))
    for token in ("token_ada", "token_bea", "token_carl", "token_dana", "token_admin"):
        assert token not in serialized
    assert "authorization" not in serialized.lower()


def test_executor_records_silent_write_evidence(
    client: TestClient,
    signed_manifest: ScopeManifest,
    compiled_plans: list[CompiledTwinPlan],
) -> None:
    plan = next(
        plan
        for plan in compiled_plans
        if plan.synthesized.probe_type.value == "reversible_write"
        and plan.plan_id.startswith("ct-direct_share_revoke")
    )
    clean_runner = CounterfactualExecutor(
        client,
        SafetyGatekeeper(signed_manifest, secret=TEST_SIGNING_SECRET),
        mode="clean",
    )
    clean = clean_runner.execute(plan)
    assert clean.branch_a.probe is not None
    assert clean.branch_a.effect_witness is not None
    assert clean.branch_a.probe.status_code == 403
    assert clean.branch_a.effect_witness.parsed_json["secret_content"] != MUTATED_BY_BEA

    vuln_runner = CounterfactualExecutor(
        client,
        SafetyGatekeeper(signed_manifest, secret=TEST_SIGNING_SECRET),
        mode="vuln_silent_write_on_403",
    )
    vuln = vuln_runner.execute(plan)
    assert vuln.branch_a.valid
    assert vuln.branch_a.probe is not None
    assert vuln.branch_a.effect_witness is not None
    assert vuln.branch_a.probe.status_code == 403
    assert vuln.branch_a.effect_witness.parsed_json["secret_content"] == MUTATED_BY_BEA


def test_executor_marks_a_branch_invalid_when_a_placeholder_is_unresolved(
    executor: tuple[CounterfactualExecutor, CountingGatekeeper],
    compiled_plans: list[CompiledTwinPlan],
) -> None:
    runner, _ = executor
    plan = compiled_plans[0]
    broken = ApiStep(
        step_id="broken-effect-witness",
        method="GET",
        path_template="/api/v1/documents/{missing_placeholder}",
        principal_alias="ada",
        expected_role=ExpectedRole.EFFECT_WITNESS,
        reversible=False,
    )
    tampered = plan.model_copy(
        update={"branch_b_steps": [*plan.branch_b_steps, broken]}
    )
    evidence = runner.execute(tampered)
    assert evidence.branch_a.valid
    assert not evidence.branch_b.valid


def test_executor_refuses_a_host_outside_the_signed_allowlist(
    client: TestClient,
    signed_manifest: ScopeManifest,
    compiled_plans: list[CompiledTwinPlan],
) -> None:
    runner = CounterfactualExecutor(
        client,
        SafetyGatekeeper(signed_manifest, secret=TEST_SIGNING_SECRET),
        base_url="http://evil.example.com",
        mode="clean",
    )
    with pytest.raises(ScopeViolationError, match="allowed_hosts"):
        runner.execute(compiled_plans[0])
