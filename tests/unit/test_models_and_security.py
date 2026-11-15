"""Unit tests for strict domain models, signed manifests, and typed settings (Task 2)."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from janus_auth.config import (
    DEFAULT_MAX_REQUESTS,
    DEFAULT_RETENTION_DAYS,
    DEFAULT_Z3_TIMEOUT_MS,
    INSECURE_DEV_ONLY_SIGNING_SECRET,
    Settings,
)
from janus_auth.models import (
    AdjudicationReport,
    ApiStep,
    BranchSummary,
    BranchTrace,
    CompiledTwinPlan,
    CounterfactualPairPlan,
    Decision,
    DimensionFinding,
    ExpectedRole,
    MappingProposal,
    OperationMap,
    PairedExecutionEvidence,
    PrincipalClass,
    ProbeType,
    ScopeManifest,
    StepObservation,
    SupportState,
    TransitionEndpoint,
    TransitionFamily,
    VerdictKind,
    ViolationSubtype,
)

SECRET = "test-signing-secret"  # noqa: S105 - test-only value
POLICY_TEXT = 'permit(principal, action, resource);'
POLICY_SHA = hashlib.sha256(POLICY_TEXT.encode("utf-8")).hexdigest()
FAR_FUTURE = datetime.now(UTC) + timedelta(days=30)


def make_support_state(**overrides: object) -> SupportState:
    values: dict[str, object] = {
        "principal_id": "bea",
        "resource_id": "doc_101",
        "action": ProbeType.PROTECTED_READ,
        "direct_grant": True,
    }
    values.update(overrides)
    return SupportState.model_validate(values)


def make_pair_plan(**overrides: object) -> CounterfactualPairPlan:
    values: dict[str, object] = {
        "plan_id": "plan-001",
        "transition_family": TransitionFamily.DIRECT_SHARE_REVOKE,
        "probe_type": ProbeType.PROTECTED_READ,
        "principal_role_class": PrincipalClass.SAME_TENANT_PEER.value,
        "branch_a_pre": make_support_state(),
        "branch_a_post": make_support_state(direct_grant=False),
        "branch_a_expected": Decision.DENY,
        "branch_b_pre": make_support_state(group_grant=True),
        "branch_b_post": make_support_state(direct_grant=False, group_grant=True),
        "branch_b_expected": Decision.ALLOW,
        "surviving_support_name": "group_grant",
        "hamming_distance": 1,
    }
    values.update(overrides)
    return CounterfactualPairPlan.model_validate(values)


def make_api_step(**overrides: object) -> ApiStep:
    values: dict[str, object] = {
        "step_id": "a1",
        "method": "POST",
        "path_template": "/api/v1/documents",
        "principal_alias": "ada",
        "json_body": {"title": "Q4 Plan"},
        "extract": {"doc_id": "id"},
        "expected_role": ExpectedRole.SETUP,
        "reversible": True,
    }
    values.update(overrides)
    return ApiStep.model_validate(values)


def make_operation_map(**overrides: object) -> OperationMap:
    values: dict[str, object] = {
        "family": TransitionFamily.DIRECT_SHARE_REVOKE,
        "method": "DELETE",
        "path_template": "/api/v1/documents/{doc_id}/shares/{user_id}",
        "probe_method": "GET",
        "probe_path_template": "/api/v1/documents/{doc_id}",
        "witness_method": "GET",
        "witness_path_template": "/api/v1/documents/{doc_id}/permissions",
    }
    values.update(overrides)
    return OperationMap.model_validate(values)


def make_manifest(**overrides: object) -> ScopeManifest:
    values: dict[str, object] = {
        "approved": True,
        "approver": "sec-lead@example.org",
        "approved_at": datetime(2026, 11, 15, 12, 0, tzinfo=UTC),
        "policy_sha256": POLICY_SHA,
        "reset_endpoint": "/api/v1/admin/reset",
        "transition_endpoints": [
            TransitionEndpoint(
                family=TransitionFamily.DIRECT_SHARE_REVOKE,
                method="DELETE",
                path_template="/api/v1/documents/{doc_id}/shares/{user_id}",
            )
        ],
        "principal_aliases": {"ada": "JANUS_TOKEN_ADA", "bea": "JANUS_TOKEN_BEA"},
        "operations": {"direct_share_revoke": make_operation_map()},
        "expires_at": FAR_FUTURE,
    }
    values.update(overrides)
    return ScopeManifest.model_validate(values)


# ---------------------------------------------------------------------------
# Enums and strict model validation
# ---------------------------------------------------------------------------


def test_models_enum_values_match_spec() -> None:
    assert [member.value for member in Decision] == ["ALLOW", "DENY", "UNKNOWN"]
    assert [member.value for member in TransitionFamily] == [
        "direct_share_revoke",
        "group_member_remove",
        "delegation_revoke",
        "role_downgrade",
        "ownership_transfer",
        "tenant_change",
    ]
    assert [member.value for member in PrincipalClass] == [
        "former_owner",
        "same_tenant_peer",
        "cross_tenant_principal",
        "delegate_or_admin",
    ]
    assert [member.value for member in ProbeType] == ["protected_read", "reversible_write"]
    assert [member.value for member in VerdictKind] == [
        "CONFIRMED_VIOLATION",
        "CONFORMS",
        "CONFORMS_MASKED",
        "LEGITIMATE_ACCESS_REGRESSION",
        "UNCERTAIN_ABSTAIN",
        "INVALID_TEST",
    ]
    assert [member.value for member in ViolationSubtype] == [
        "NONE",
        "BOLA_READ_LEAK",
        "SILENT_WRITE_SIDE_EFFECT",
        "STALE_GROUP_CACHE",
        "FORMER_OWNER_RETENTION",
        "BROKEN_DELEGATION_CASCADE",
        "OVER_REVOCATION_REGRESSION",
        "INVERTED_ENFORCEMENT",
    ]
    assert [member.value for member in ExpectedRole] == [
        "setup",
        "pre_witness",
        "transition",
        "post_transition_witness",
        "probe",
        "effect_witness",
    ]


@pytest.mark.parametrize(
    "factory",
    [make_support_state, make_api_step, make_manifest],
)
def test_models_reject_unknown_keys(factory: Callable[..., object]) -> None:
    with pytest.raises(ValidationError):
        factory(unexpected_key="boom")


def test_models_support_state_matches_section_9_5_1() -> None:
    state = make_support_state()
    dumped = state.model_dump()
    assert dumped == {
        "principal_id": "bea",
        "resource_id": "doc_101",
        "action": ProbeType.PROTECTED_READ,
        "active_principal": True,
        "same_tenant": True,
        "is_owner": False,
        "direct_grant": True,
        "group_grant": False,
        "delegated_grant": False,
        "parent_grant_valid": False,
        "admin_role": False,
        "explicit_deny": False,
    }


def test_models_support_state_rejects_unknown_action() -> None:
    with pytest.raises(ValidationError):
        make_support_state(action="delete_everything")


def test_models_counterfactual_pair_plan_hamming_bounds() -> None:
    assert make_pair_plan(hamming_distance=1).hamming_distance == 1
    assert make_pair_plan(hamming_distance=2).hamming_distance == 2
    with pytest.raises(ValidationError):
        make_pair_plan(hamming_distance=0)
    with pytest.raises(ValidationError):
        make_pair_plan(hamming_distance=3)


def test_models_counterfactual_pair_plan_rejects_negative_consistency_bound() -> None:
    with pytest.raises(ValidationError):
        make_pair_plan(consistency_bound_ms=-1)


def test_models_compiled_twin_plan_round_trips_through_json() -> None:
    plan = CompiledTwinPlan(
        plan_id="plan-001",
        synthesized=make_pair_plan(),
        branch_a_steps=[make_api_step()],
        branch_b_steps=[
            make_api_step(
                step_id="b0",
                method="POST",
                path_template="/api/v1/groups/eng/members",
                expected_role=ExpectedRole.SETUP,
            )
        ],
        canary="JANUS_CANARY_deadbeef",
        probe_principal="bea",
        probe_payload={"secret_content": "MUTATED_BY_BEA"},
        masked_control=True,
    )
    restored = CompiledTwinPlan.model_validate_json(plan.model_dump_json())
    assert restored == plan
    assert restored.branch_a_steps[0].expected_role is ExpectedRole.SETUP
    assert restored.masked_control is True


def test_models_api_step_requires_known_role_and_method() -> None:
    with pytest.raises(ValidationError):
        make_api_step(expected_role="do_something")
    with pytest.raises(ValidationError):
        make_api_step(method="TRACE")
    with pytest.raises(ValidationError):
        make_api_step(query={"masked": True})


def test_models_execution_evidence_and_report_round_trip() -> None:
    observation = StepObservation(
        step_id="a7",
        method="GET",
        path="/api/v1/documents/doc_101",
        principal_alias="bea",
        status_code=200,
        parsed_json={"id": "doc_101", "secret_content": None},
        headers={"content-type": "application/json"},
        elapsed_ms=12.5,
        canary_present=False,
    )
    trace_a = BranchTrace(
        branch="A",
        plan_id="plan-001",
        steps=[observation],
        pre_witness_ok=True,
        post_transition_witness_ok=True,
        probe=observation,
        effect_witness=None,
        canary="JANUS_CANARY_deadbeef",
        valid=True,
    )
    trace_b = trace_a.model_copy(update={"branch": "B"})
    evidence = PairedExecutionEvidence(
        plan_id="plan-001",
        branch_a=trace_a,
        branch_b=trace_b,
        branch_a_reset_epoch=1,
        branch_b_reset_epoch=2,
    )
    report = AdjudicationReport(
        plan_id="plan-001",
        verdict=VerdictKind.CONFORMS_MASKED,
        subtype=ViolationSubtype.NONE,
        dimensions=[
            DimensionFinding(
                name="read_projection",
                passed=False,
                detail="masked public summary",
                evidence_step_ids=["a7"],
            )
        ],
        evidence={"branch_a_probe": "a7"},
        reproduction_verified=True,
        branch_a_summary=BranchSummary(branch="A", probe_status_code=200),
        branch_b_summary=BranchSummary(
            branch="B", probe_status_code=200, canary_present=True, access_allowed=True
        ),
    )
    restored = AdjudicationReport.model_validate_json(report.model_dump_json())
    assert restored == report
    assert evidence.branch_a.valid is True
    assert evidence.branch_a_reset_epoch == 1


def test_models_mapping_proposal_is_unapproved_by_default() -> None:
    proposal = MappingProposal(
        policy_sha256=POLICY_SHA,
        proposed_operations={"direct_share_revoke": make_operation_map()},
        notes=["heuristic draft"],
        generated_at=datetime.now(UTC),
    )
    assert proposal.approved is False
    with pytest.raises(ValidationError):
        MappingProposal(
            policy_sha256=POLICY_SHA,
            proposed_operations={},
            notes=[],
            generated_at=datetime.now(UTC),
            approved="yes",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# ScopeManifest canonical signing
# ---------------------------------------------------------------------------


def test_models_manifest_defaults_match_spec() -> None:
    manifest = ScopeManifest(policy_sha256=POLICY_SHA)
    assert manifest.allowed_hosts == ["127.0.0.1", "localhost", "testserver"]
    assert manifest.max_requests == 500
    assert manifest.rate_limit_rps == 50.0
    assert manifest.allow_destructive is False
    assert manifest.approved is False
    assert manifest.signature is None
    assert manifest.manifest_sha256 is None


def test_manifest_canonical_body_is_sorted_compact_utf8() -> None:
    manifest = make_manifest(approver="señor-approver")
    body = manifest.canonical_body_bytes()
    parsed = json.loads(body)
    expected = json.dumps(
        parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    assert body == expected
    assert b" " not in body
    assert "señor-approver".encode() in body
    assert b'"signature"' not in body


def test_manifest_hash_excludes_signature_and_manifest_hash_by_rule() -> None:
    manifest = make_manifest()
    hash_body = json.loads(manifest.canonical_body_bytes(include_manifest_sha256=False))
    signed_body = json.loads(manifest.canonical_body_bytes(include_manifest_sha256=True))
    assert "signature" not in hash_body
    assert "manifest_sha256" not in hash_body
    assert "signature" not in signed_body
    assert signed_body["manifest_sha256"] is None  # not yet computed on an unsigned draft

    signed = manifest.sign(SECRET)
    signed_body = json.loads(signed.canonical_body_bytes(include_manifest_sha256=True))
    assert "signature" not in signed_body
    assert signed_body["manifest_sha256"] == signed.manifest_sha256


def test_manifest_sign_populates_hashes_and_verifies() -> None:
    manifest = make_manifest()
    signed = manifest.sign(SECRET)

    assert signed is manifest
    assert signed.manifest_sha256 is not None
    assert len(signed.manifest_sha256) == 64
    assert signed.signature is not None
    assert len(signed.signature) == 64
    assert signed.verify_integrity() is True
    assert signed.verify_signature(SECRET) is True
    assert make_manifest().verify_signature(SECRET) is False


def test_manifest_signature_follows_documented_exclusion_rule() -> None:
    signed = make_manifest().sign(SECRET)
    assert signed.manifest_sha256 == hashlib.sha256(
        signed.canonical_body_bytes(include_manifest_sha256=False)
    ).hexdigest()
    expected = hmac.new(
        SECRET.encode("utf-8"),
        signed.canonical_body_bytes(include_manifest_sha256=True),
        hashlib.sha256,
    ).hexdigest()
    assert signed.signature == expected


def test_manifest_canonical_signing_is_byte_stable() -> None:
    first = make_manifest()
    second = make_manifest(
        principal_aliases={"bea": "JANUS_TOKEN_BEA", "ada": "JANUS_TOKEN_ADA"}
    )
    signed_first = first.sign(SECRET)
    signed_second = second.sign(SECRET)
    assert signed_first.canonical_body_bytes() == signed_second.canonical_body_bytes()
    assert signed_first.manifest_sha256 == signed_second.manifest_sha256
    assert signed_first.signature == signed_second.signature

    reparsed = ScopeManifest.model_validate_json(signed_first.model_dump_json())
    resigned = reparsed.sign(SECRET)
    assert resigned.model_dump() == signed_first.model_dump()
    assert resigned.canonical_body_bytes() == signed_first.canonical_body_bytes()
    assert resigned.signature == signed_first.signature


def test_manifest_tampered_body_fails_verification() -> None:
    signed = make_manifest().sign(SECRET)
    tampered = signed.model_copy(update={"max_requests": 9999})
    assert tampered.verify_integrity() is False
    assert tampered.verify_signature(SECRET) is False


def test_manifest_changed_policy_hash_fails_verification() -> None:
    signed = make_manifest().sign(SECRET)
    tampered = signed.model_copy(update={"policy_sha256": "0" * 64})
    assert tampered.verify_integrity() is False
    assert tampered.verify_signature(SECRET) is False


def test_manifest_changed_host_allowlist_fails_verification() -> None:
    signed = make_manifest().sign(SECRET)
    tampered = signed.model_copy(update={"allowed_hosts": ["evil.example.com"]})
    assert tampered.verify_signature(SECRET) is False


def test_manifest_bad_signature_and_wrong_secret_fail_verification() -> None:
    signed = make_manifest().sign(SECRET)
    assert signed.verify_signature("different-secret") is False

    replacement = "0" if signed.signature is not None and signed.signature[0] != "0" else "1"
    corrupted = signed.model_copy(update={"signature": replacement + (signed.signature or "")[1:]})
    assert corrupted.verify_integrity() is True
    assert corrupted.verify_signature(SECRET) is False

    unsigned = signed.model_copy(update={"signature": None})
    assert unsigned.verify_signature(SECRET) is False


def test_manifest_missing_hash_fails_verification() -> None:
    signed = make_manifest().sign(SECRET)
    stripped = signed.model_copy(update={"manifest_sha256": None})
    assert stripped.verify_integrity() is False
    assert stripped.verify_signature(SECRET) is False


def test_manifest_expired_fails_verification_even_with_valid_signature() -> None:
    expired = make_manifest(expires_at=datetime.now(UTC) - timedelta(seconds=1)).sign(SECRET)
    assert expired.is_expired() is True
    assert expired.verify_integrity() is True
    assert expired.verify_signature(SECRET) is False


def test_manifest_future_expiry_passes_verification() -> None:
    signed = make_manifest(expires_at=datetime.now(UTC) + timedelta(hours=1)).sign(SECRET)
    assert signed.is_expired() is False
    assert signed.verify_signature(SECRET) is True


def test_manifest_naive_expiry_is_treated_as_utc() -> None:
    naive_past = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=1)
    assert make_manifest(expires_at=naive_past).is_expired() is True
    naive_future = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=1)
    assert make_manifest(expires_at=naive_future).is_expired() is False


def test_manifest_verification_does_not_grant_approval() -> None:
    signed = make_manifest(approved=False).sign(SECRET)
    assert signed.verify_signature(SECRET) is True
    assert signed.approved is False


def test_manifest_sign_uses_settings_secret_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JANUS_SIGNING_SECRET", "env-provided-secret")
    signed = make_manifest().sign()
    assert signed.verify_signature() is True
    assert signed.verify_signature("env-provided-secret") is True
    assert signed.verify_signature(SECRET) is False


def test_manifest_empty_secret_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        make_manifest().sign("")


def test_manifest_sign_without_env_warns_and_uses_dev_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("JANUS_SIGNING_SECRET", raising=False)
    with pytest.warns(UserWarning, match="development-only"):
        signed = make_manifest().sign()
    assert signed.verify_signature(INSECURE_DEV_ONLY_SIGNING_SECRET) is True


# ---------------------------------------------------------------------------
# Typed configuration
# ---------------------------------------------------------------------------


def test_config_defaults_and_dev_secret_warning() -> None:
    with pytest.warns(UserWarning, match="development-only"):
        settings = Settings.from_env({})
    assert settings.signing_secret == INSECURE_DEV_ONLY_SIGNING_SECRET
    assert settings.trace_encryption_key is None
    assert settings.retention_days == DEFAULT_RETENTION_DAYS == 7
    assert settings.z3_timeout_ms == DEFAULT_Z3_TIMEOUT_MS == 5000
    assert settings.max_requests == DEFAULT_MAX_REQUESTS == 500


def test_config_reads_all_environment_values() -> None:
    environ = {
        "JANUS_SIGNING_SECRET": "  env-secret  ",
        "JANUS_TRACE_ENCRYPTION_KEY": "fernet-key",
        "JANUS_RETENTION_DAYS": "3",
        "JANUS_Z3_TIMEOUT_MS": "750",
        "JANUS_MAX_REQUESTS": "42",
    }
    settings = Settings.from_env(environ)
    assert settings == Settings(
        signing_secret="env-secret",  # noqa: S106 - test-only value
        trace_encryption_key="fernet-key",
        retention_days=3,
        z3_timeout_ms=750,
        max_requests=42,
    )


def test_config_blank_values_fall_back_to_defaults_with_warning() -> None:
    with pytest.warns(UserWarning, match="development-only"):
        settings = Settings.from_env(
            {
                "JANUS_SIGNING_SECRET": "   ",
                "JANUS_TRACE_ENCRYPTION_KEY": "  ",
                "JANUS_RETENTION_DAYS": " ",
                "JANUS_Z3_TIMEOUT_MS": "",
                "JANUS_MAX_REQUESTS": "",
            }
        )
    assert settings.signing_secret == INSECURE_DEV_ONLY_SIGNING_SECRET
    assert settings.trace_encryption_key is None
    assert settings.retention_days == 7
    assert settings.z3_timeout_ms == 5000
    assert settings.max_requests == 500


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("JANUS_RETENTION_DAYS", "0"),
        ("JANUS_RETENTION_DAYS", "-1"),
        ("JANUS_RETENTION_DAYS", "seven"),
        ("JANUS_Z3_TIMEOUT_MS", "0"),
        ("JANUS_Z3_TIMEOUT_MS", "1.5"),
        ("JANUS_MAX_REQUESTS", "0"),
        ("JANUS_MAX_REQUESTS", "-500"),
        ("JANUS_MAX_REQUESTS", "lots"),
    ],
)
def test_config_rejects_invalid_positive_integers(name: str, value: str) -> None:
    with pytest.raises(ValueError, match=name):
        Settings.from_env({"JANUS_SIGNING_SECRET": "env-secret", name: value})


def test_config_dataclass_is_frozen() -> None:
    settings = Settings(signing_secret="env-secret")  # noqa: S106 - test-only value
    with pytest.raises(FrozenInstanceError):
        settings.max_requests = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"signing_secret": ""},
        {"signing_secret": "   "},
        {"signing_secret": "env-secret", "retention_days": 0},
        {"signing_secret": "env-secret", "z3_timeout_ms": -1},
        {"signing_secret": "env-secret", "max_requests": 0},
        {"signing_secret": "env-secret", "trace_encryption_key": " "},
    ],
)
def test_config_direct_construction_validates(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        Settings(**kwargs)  # type: ignore[arg-type]
