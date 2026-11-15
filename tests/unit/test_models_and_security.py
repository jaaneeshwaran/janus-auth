"""Unit tests for strict domain models, signed manifests, and typed settings (Task 2)."""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import sqlite3
from collections.abc import Callable, Sequence
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
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
from janus_auth.security import (
    BudgetExhaustedError,
    RateLimitExceededError,
    Redactor,
    SafetyGatekeeper,
    ScopeViolationError,
    SSRFBlockedError,
    TraceStore,
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


def test_models_strict_mode_rejects_raw_scalars() -> None:
    with pytest.raises(ValidationError):
        SupportState(
            principal_id="bea",
            resource_id="doc_101",
            action="protected_read",  # type: ignore[arg-type]
        )
    with pytest.raises(ValidationError):
        ScopeManifest(policy_sha256=POLICY_SHA, max_requests="500")  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        ScopeManifest(policy_sha256=POLICY_SHA, approved="true")  # type: ignore[arg-type]

    state = SupportState(
        principal_id="bea",
        resource_id="doc_101",
        action=ProbeType.PROTECTED_READ,
    )
    assert state.action is ProbeType.PROTECTED_READ


def test_models_nested_unknown_keys_rejected() -> None:
    with pytest.raises(ValidationError):
        ScopeManifest.model_validate(
            {
                "policy_sha256": POLICY_SHA,
                "transition_endpoints": [
                    {
                        "family": TransitionFamily.DIRECT_SHARE_REVOKE,
                        "method": "DELETE",
                        "path_template": "/api/v1/documents/{doc_id}/shares/{user_id}",
                        "unexpected": True,
                    }
                ],
            }
        )

    payload = {
        "plan_id": "plan-001",
        "synthesized": {**make_pair_plan().model_dump(), "unexpected": True},
        "branch_a_steps": [],
        "branch_b_steps": [],
        "canary": "JANUS_CANARY_deadbeef",
        "probe_principal": "bea",
    }
    with pytest.raises(ValidationError):
        CompiledTwinPlan.model_validate(payload)


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
    with pytest.raises(ValidationError, match="always unapproved"):
        MappingProposal(
            policy_sha256=POLICY_SHA,
            proposed_operations={},
            notes=[],
            generated_at=datetime.now(UTC),
            approved=True,
        )
    with pytest.raises(ValidationError):
        MappingProposal(
            policy_sha256="not-a-hash",
            proposed_operations={},
            notes=[],
            generated_at=datetime.now(UTC),
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


def test_manifest_constrains_digest_fields_at_parse() -> None:
    base = make_manifest().model_dump(mode="json")
    malformed_values = [
        ("policy_sha256", "0" * 63),
        ("policy_sha256", "é" * 64),
        ("manifest_sha256", "A" * 64),
        ("manifest_sha256", "zz" * 32),
        ("signature", "not-a-digest"),
        ("signature", "é" * 64),
    ]
    for field, value in malformed_values:
        with pytest.raises(ValidationError):
            ScopeManifest.model_validate_json(json.dumps({**base, field: value}))

    valid = ScopeManifest.model_validate_json(json.dumps({**base, "policy_sha256": "a" * 64}))
    assert valid.policy_sha256 == "a" * 64


def test_manifest_malformed_digests_return_false_instead_of_raising() -> None:
    signed = make_manifest().sign(SECRET)
    for field in ("signature", "manifest_sha256"):
        for value in ("é" * 64, "zz" * 32, 12345):
            malformed = signed.model_copy(update={field: value})
            assert malformed.verify_signature(SECRET) is False, (field, value)

    assert signed.model_copy(update={"signature": "é" * 64}).verify_integrity() is True
    assert signed.model_copy(update={"manifest_sha256": "é" * 64}).verify_integrity() is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("max_requests", 0),
        ("max_requests", -1),
        ("rate_limit_rps", 0.0),
        ("rate_limit_rps", -1.0),
    ],
)
def test_manifest_rejects_nonpositive_limits(field: str, value: int | float) -> None:
    with pytest.raises(ValidationError):
        make_manifest(**{field: value})


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


# ---------------------------------------------------------------------------
# Safety gatekeeper (Task 3)
# ---------------------------------------------------------------------------

SAMPLE_JWT = (  # noqa: S105 - synthetic test-only token
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiZWEifQ.c2lnbmF0dXJl"
)
BEARER_TOKEN = "opaque-test-bearer-value"  # noqa: S105 - test-only value
TRACE_PASSPHRASE = "test-trace-passphrase"  # noqa: S105 - test-only value


def make_signed_manifest(**overrides: object) -> ScopeManifest:
    return make_manifest(**overrides).sign(SECRET)


def fixed_resolver(*addresses: str) -> Callable[[str], Sequence[str]]:
    def resolve(_host: str) -> Sequence[str]:
        return addresses

    return resolve


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _fail_socket(*args: object, **kwargs: object) -> None:
    raise AssertionError("network socket opened before gatekeeper rejection")


def test_gatekeeper_requires_valid_signature_and_never_leaks_secret() -> None:
    with pytest.raises(ScopeViolationError) as exc_info:
        SafetyGatekeeper(make_manifest(), secret=SECRET)
    assert SECRET not in str(exc_info.value)

    with pytest.raises(ScopeViolationError) as exc_info:
        SafetyGatekeeper(make_signed_manifest(), secret="wrong-secret")  # noqa: S106
    assert SECRET not in str(exc_info.value)

    with pytest.raises(ScopeViolationError):
        SafetyGatekeeper(make_signed_manifest(), secret="")


def test_gatekeeper_rejects_expired_manifest() -> None:
    expired = make_manifest(expires_at=datetime.now(UTC) - timedelta(seconds=1)).sign(SECRET)
    with pytest.raises(ScopeViolationError):
        SafetyGatekeeper(expired, secret=SECRET)


def test_gatekeeper_accepts_signed_manifest_without_enforcing_approval() -> None:
    # Approval is a compiler/runner gate; the gatekeeper only verifies the signature.
    manifest = make_signed_manifest(approved=False)
    gatekeeper = SafetyGatekeeper(
        manifest, secret=SECRET, resolver=fixed_resolver("127.0.0.1")
    )
    assert gatekeeper.manifest.approved is False
    gatekeeper.validate_url("http://127.0.0.1/health")


@pytest.mark.parametrize(
    ("url", "allowed_hosts"),
    [
        (
            "http://169.254.169.254/latest/meta-data/",
            ["127.0.0.1", "localhost", "testserver", "169.254.169.254"],
        ),
        ("http://evil.example.com/api", ["127.0.0.1", "localhost", "testserver"]),
        ("file:///etc/passwd", ["127.0.0.1", "localhost", "testserver"]),
    ],
)
def test_gatekeeper_blocks_acceptance_urls_before_socket(
    monkeypatch: pytest.MonkeyPatch,
    url: str,
    allowed_hosts: list[str],
) -> None:
    manifest = make_signed_manifest(allowed_hosts=allowed_hosts)
    gatekeeper = SafetyGatekeeper(
        manifest,
        secret=SECRET,
        resolver=fixed_resolver("169.254.169.254"),
    )
    monkeypatch.setattr(socket, "socket", _fail_socket)
    with pytest.raises(ScopeViolationError):
        gatekeeper.validate_request(url)


def test_gatekeeper_blocks_allowlisted_metadata_ip_at_ssrf_layer() -> None:
    manifest = make_signed_manifest(
        allowed_hosts=["127.0.0.1", "localhost", "testserver", "169.254.169.254"]
    )
    gatekeeper = SafetyGatekeeper(
        manifest,
        secret=SECRET,
        resolver=fixed_resolver("169.254.169.254"),
    )
    with pytest.raises(SSRFBlockedError):
        gatekeeper.validate_url("http://169.254.169.254/latest/meta-data/")


@pytest.mark.parametrize(
    "address",
    [
        "169.254.169.254",
        "169.254.10.10",
        "224.0.0.1",
        "0.0.0.0",  # noqa: S104 - assertion that the unspecified range is blocked
        "::",
        "::ffff:169.254.169.254",
    ],
)
def test_gatekeeper_blocks_link_local_multicast_and_unspecified(address: str) -> None:
    manifest = make_signed_manifest(
        allowed_hosts=["127.0.0.1", "localhost", "testserver", "internal.example"]
    )
    gatekeeper = SafetyGatekeeper(
        manifest, secret=SECRET, resolver=fixed_resolver(address)
    )
    with pytest.raises(SSRFBlockedError):
        gatekeeper.validate_url("http://internal.example/resource")


@pytest.mark.parametrize("url", ["ftp://example.com/x", "gopher://example.com/x"])
def test_gatekeeper_rejects_non_http_schemes(url: str) -> None:
    gatekeeper = SafetyGatekeeper(
        make_signed_manifest(), secret=SECRET, resolver=fixed_resolver("127.0.0.1")
    )
    with pytest.raises(ScopeViolationError):
        gatekeeper.validate_url(url)


def test_gatekeeper_allows_loopback() -> None:
    gatekeeper = SafetyGatekeeper(
        make_signed_manifest(), secret=SECRET, resolver=fixed_resolver("127.0.0.1")
    )
    gatekeeper.validate_url("http://127.0.0.1:8080/health")


def test_gatekeeper_skips_resolution_for_testserver() -> None:
    def exploding_resolver(_host: str) -> Sequence[str]:
        raise AssertionError("testserver must not be resolved")

    gatekeeper = SafetyGatekeeper(
        make_signed_manifest(), secret=SECRET, resolver=exploding_resolver
    )
    gatekeeper.validate_url("http://testserver/api/v1/documents")


def test_gatekeeper_resolution_failure_is_ssrf_blocked() -> None:
    def failing_resolver(_host: str) -> Sequence[str]:
        raise OSError("no such host")

    gatekeeper = SafetyGatekeeper(
        make_signed_manifest(allowed_hosts=["internal.example"]),
        secret=SECRET,
        resolver=failing_resolver,
    )
    with pytest.raises(SSRFBlockedError):
        gatekeeper.validate_url("http://internal.example/api")


@pytest.mark.parametrize(
    ("method", "path", "allowed"),
    [
        ("DELETE", "/api/v1/documents/doc_1/shares/bea", True),
        ("DELETE", "/api/v1/documents/doc_1/shares/bea/", True),
        ("DELETE", "/api/v1/documents/doc_1/shares/bea?masked=1", True),
        ("DELETE", "/api/v1/admin/reset", True),
        ("DELETE", "/api/v1/documents/doc_1", False),
        ("DELETE", "/api/v1/documents/doc_1/shares/bea/extra", False),
        ("DELETE", "/api/v1/documents/doc_1/shares", False),
        ("PUT", "/api/v1/documents/doc_1", True),
        ("PATCH", "/api/v1/documents/doc_1", True),
        ("POST", "/api/v1/documents/doc_1", True),
        ("GET", "/api/v1/documents/doc_1", True),
    ],
)
def test_gatekeeper_delete_policy_truth_table(
    method: str, path: str, allowed: bool
) -> None:
    manifest = make_signed_manifest(
        transition_endpoints=[
            TransitionEndpoint(
                family=TransitionFamily.DIRECT_SHARE_REVOKE,
                method="DELETE",
                path_template="/api/v1/documents/{doc_id}/shares/{user_id}",
            )
        ],
        reset_endpoint="/api/v1/admin/reset",
    )
    gatekeeper = SafetyGatekeeper(
        manifest, secret=SECRET, resolver=fixed_resolver("127.0.0.1")
    )
    url = "http://testserver" + path
    if allowed:
        gatekeeper.validate_url(url, method)
    else:
        with pytest.raises(ScopeViolationError):
            gatekeeper.validate_url(url, method)


def test_gatekeeper_delete_policy_requires_transition_method_match() -> None:
    manifest = make_signed_manifest(
        transition_endpoints=[
            TransitionEndpoint(
                family=TransitionFamily.DIRECT_SHARE_REVOKE,
                method="POST",
                path_template="/api/v1/documents/{doc_id}/shares/{user_id}",
            )
        ],
        reset_endpoint=None,
    )
    gatekeeper = SafetyGatekeeper(
        manifest, secret=SECRET, resolver=fixed_resolver("127.0.0.1")
    )
    with pytest.raises(ScopeViolationError):
        gatekeeper.validate_url(
            "http://testserver/api/v1/documents/doc_1/shares/bea", "DELETE"
        )


def test_gatekeeper_allows_destructive_when_declared() -> None:
    manifest = make_signed_manifest(allow_destructive=True, reset_endpoint=None)
    gatekeeper = SafetyGatekeeper(
        manifest, secret=SECRET, resolver=fixed_resolver("127.0.0.1")
    )
    gatekeeper.validate_url("http://testserver/api/v1/documents/doc_1", "DELETE")


def test_gatekeeper_matches_absolute_reset_endpoint() -> None:
    manifest = make_signed_manifest(
        reset_endpoint="http://testserver/api/v1/admin/reset?scope=all"
    )
    gatekeeper = SafetyGatekeeper(
        manifest, secret=SECRET, resolver=fixed_resolver("127.0.0.1")
    )
    gatekeeper.validate_url("http://testserver/api/v1/admin/reset", "DELETE")


def test_gatekeeper_rate_limit_uses_injected_clock() -> None:
    clock = FakeClock()
    manifest = make_signed_manifest(rate_limit_rps=2.0, max_requests=100)
    gatekeeper = SafetyGatekeeper(
        manifest,
        secret=SECRET,
        clock=clock,
        resolver=fixed_resolver("127.0.0.1"),
    )
    url = "http://127.0.0.1/resource"
    gatekeeper.validate_request(url)
    gatekeeper.validate_request(url)
    with pytest.raises(RateLimitExceededError):
        gatekeeper.validate_request(url)

    clock.now = 0.5
    gatekeeper.validate_request(url)
    with pytest.raises(RateLimitExceededError):
        gatekeeper.validate_request(url)


def test_gatekeeper_enforces_budget_after_url_checks_and_before_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = FakeClock()
    manifest = make_signed_manifest(max_requests=2, rate_limit_rps=1000.0)
    gatekeeper = SafetyGatekeeper(
        manifest,
        secret=SECRET,
        clock=clock,
        resolver=fixed_resolver("127.0.0.1"),
    )
    url = "http://127.0.0.1/resource"
    for _ in range(10):
        gatekeeper.validate_url(url)
    assert gatekeeper.requests_used == 0

    gatekeeper.validate_request(url)
    gatekeeper.validate_request(url)
    assert gatekeeper.requests_used == 2

    monkeypatch.setattr(socket, "socket", _fail_socket)
    with pytest.raises(BudgetExhaustedError):
        gatekeeper.validate_request(url)


def test_gatekeeper_rejected_request_does_not_consume_budget() -> None:
    gatekeeper = SafetyGatekeeper(
        make_signed_manifest(max_requests=1),
        secret=SECRET,
        resolver=fixed_resolver("127.0.0.1"),
    )
    with pytest.raises(ScopeViolationError):
        gatekeeper.validate_request("http://evil.example.com/api")
    assert gatekeeper.requests_used == 0
    gatekeeper.validate_request("http://127.0.0.1/resource")
    assert gatekeeper.requests_used == 1


def test_gatekeeper_and_client_do_not_follow_redirects() -> None:
    gatekeeper = SafetyGatekeeper(
        make_signed_manifest(), secret=SECRET, resolver=fixed_resolver("127.0.0.1")
    )
    redirect_target = "http://evil.example.com/api"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("http://testserver/api")
        return httpx.Response(302, headers={"location": redirect_target})

    transport = httpx.MockTransport(handler)
    with httpx.Client(transport=transport, follow_redirects=False) as client:
        gatekeeper.validate_request("http://testserver/api")
        response = client.get("http://testserver/api")

    assert response.status_code == 302
    assert response.headers["location"] == redirect_target
    # If the redirect were followed, the gatekeeper would reject the new host.
    with pytest.raises(ScopeViolationError):
        gatekeeper.validate_url(redirect_target)


# ---------------------------------------------------------------------------
# Redactor (Task 3)
# ---------------------------------------------------------------------------


def test_redactor_scrubs_sensitive_headers_case_insensitively() -> None:
    payload: dict[str, object] = {
        "Authorization": f"Bearer {SAMPLE_JWT}",
        "authorization": BEARER_TOKEN,
        "Proxy-Authorization": "basic abc",
        "Cookie": "session=abc",
        "SET-COOKIE": "session=def",
        "X-Api-Key": "key-value",
        "Content-Type": "application/json",
    }
    sanitized = Redactor.sanitize_trace(payload)

    for key in (
        "Authorization",
        "authorization",
        "Proxy-Authorization",
        "Cookie",
        "SET-COOKIE",
        "X-Api-Key",
    ):
        assert sanitized[key] == "Bearer [REDACTED]"
    assert sanitized["Content-Type"] == "application/json"


def test_redactor_scrubs_jwts_and_bearer_tokens_recursively() -> None:
    payload: dict[str, object] = {
        "body": {"note": f"jwt={SAMPLE_JWT}", "auth": f"Bearer {BEARER_TOKEN}"},
        "items": [SAMPLE_JWT, ("tuple", f"Bearer {BEARER_TOKEN}")],
        "safe": "no credentials here",
    }
    sanitized = Redactor.sanitize_trace(payload)

    rendered = json.dumps(sanitized)
    assert SAMPLE_JWT not in rendered
    assert BEARER_TOKEN not in rendered
    assert "Bearer [REDACTED]" in rendered
    assert isinstance(sanitized["items"][1], tuple)
    assert sanitized["safe"] == "no credentials here"


def test_redactor_is_idempotent() -> None:
    payload = {
        "headers": {"Authorization": f"Bearer {SAMPLE_JWT}"},
        "note": f"token {SAMPLE_JWT}",
        "opaque": f"Bearer {BEARER_TOKEN}",
    }
    once = Redactor.sanitize_trace(payload)
    twice = Redactor.sanitize_trace(once)
    assert twice == once
    assert once["headers"]["Authorization"] == "Bearer [REDACTED]"

    # A bare "Bearer <JWT>" inside a non-header field must also stabilise after one pass.
    bare_bearer = Redactor.sanitize_trace({"note": f"Bearer {SAMPLE_JWT}"})
    assert bare_bearer == {"note": "Bearer [REDACTED]"}
    assert Redactor.sanitize_trace(bare_bearer) == bare_bearer


def test_redactor_header_helper() -> None:
    redacted = Redactor.redact_headers(
        {
            "Authorization": f"Bearer {SAMPLE_JWT}",
            "X-Api-Key": "secret-key-value",
            "Accept": "application/json",
        }
    )
    assert redacted == {
        "Authorization": "Bearer [REDACTED]",
        "X-Api-Key": "Bearer [REDACTED]",
        "Accept": "application/json",
    }


# ---------------------------------------------------------------------------
# Encrypted trace store (Task 3)
# ---------------------------------------------------------------------------


def make_trace() -> dict[str, object]:
    return {
        "request": {
            "headers": {"Authorization": f"Bearer {SAMPLE_JWT}"},
            "body": f"jwt={SAMPLE_JWT}",
        },
        "response": {"note": f"seen Bearer {BEARER_TOKEN}"},
    }


def test_trace_store_round_trips_redacted_encrypted_trace(tmp_path: Path) -> None:
    db_path = tmp_path / "janus_traces.sqlite3"
    with TraceStore(
        db_path, encryption_key=TRACE_PASSPHRASE, retention_days=7
    ) as store:
        store.record_run(
            "run-1",
            "2026-11-15T00:00:00+00:00",
            POLICY_SHA,
            None,
            "http://testserver",
            total_requests=3,
        )
        store.record_verdict(
            "verdict-1",
            "run-1",
            "plan-1",
            TransitionFamily.DIRECT_SHARE_REVOKE,
            ProbeType.PROTECTED_READ,
            VerdictKind.CONFIRMED_VIOLATION,
            ViolationSubtype.BOLA_READ_LEAK,
            make_trace(),
        )
        row = store.get_verdict("verdict-1")
        assert row is not None
        assert row["run_id"] == "run-1"
        assert row["transition_family"] == "direct_share_revoke"
        assert row["probe_type"] == "protected_read"
        assert row["verdict"] == "CONFIRMED_VIOLATION"
        assert row["violation_subtype"] == "BOLA_READ_LEAK"
        trace = row["trace"]
        assert isinstance(trace, dict)
        assert SAMPLE_JWT not in json.dumps(trace)
        assert BEARER_TOKEN not in json.dumps(trace)
        assert trace["request"]["headers"]["Authorization"] == "Bearer [REDACTED]"

    with sqlite3.connect(db_path) as connection:
        raw_blob = connection.execute(
            "SELECT encrypted_trace_blob FROM verdicts WHERE verdict_id = ?",
            ("verdict-1",),
        ).fetchone()[0]
    assert isinstance(raw_blob, bytes)
    assert SAMPLE_JWT.encode() not in raw_blob
    assert BEARER_TOKEN.encode() not in raw_blob
    assert b"Authorization" not in raw_blob

    all_bytes = b"".join(
        path.read_bytes() for path in sorted(tmp_path.iterdir()) if path.is_file()
    )
    assert SAMPLE_JWT.encode() not in all_bytes
    assert BEARER_TOKEN.encode() not in all_bytes
    assert b"Bearer [REDACTED]" not in all_bytes


def test_trace_store_reopens_with_configured_key(tmp_path: Path) -> None:
    db_path = tmp_path / "janus_traces.sqlite3"
    with TraceStore(db_path, encryption_key=TRACE_PASSPHRASE) as store:
        store.record_verdict(
            "verdict-1",
            "run-1",
            "plan-1",
            TransitionFamily.DIRECT_SHARE_REVOKE,
            ProbeType.PROTECTED_READ,
            VerdictKind.CONFORMS,
            ViolationSubtype.NONE,
            make_trace(),
        )

    with TraceStore(db_path, encryption_key=TRACE_PASSPHRASE) as store:
        row = store.get_verdict("verdict-1")
    assert row is not None
    assert row["verdict"] == "CONFORMS"
    assert SAMPLE_JWT not in json.dumps(row["trace"])


def test_trace_store_warns_on_ephemeral_key(tmp_path: Path) -> None:
    db_path = tmp_path / "janus_traces.sqlite3"
    with pytest.warns(UserWarning, match="JANUS_TRACE_ENCRYPTION_KEY"):
        store = TraceStore(db_path)

    with store:
        store.record_verdict(
            "verdict-1",
            "run-1",
            "plan-1",
            TransitionFamily.DIRECT_SHARE_REVOKE,
            ProbeType.PROTECTED_READ,
            VerdictKind.CONFORMS,
            ViolationSubtype.NONE,
            make_trace(),
        )
        row = store.get_verdict("verdict-1")
    assert row is not None
    assert SAMPLE_JWT not in json.dumps(row["trace"])


def test_trace_store_purges_verdicts_older_than_retention(tmp_path: Path) -> None:
    db_path = tmp_path / "janus_traces.sqlite3"
    old_timestamp = (datetime.now(UTC) - timedelta(days=30)).isoformat(
        timespec="microseconds"
    )
    recent_timestamp = datetime.now(UTC).isoformat(timespec="microseconds")

    with TraceStore(
        db_path, encryption_key=TRACE_PASSPHRASE, retention_days=7
    ) as store:
        for verdict_id, created_at in (
            ("old", old_timestamp),
            ("recent", recent_timestamp),
        ):
            store.record_verdict(
                verdict_id,
                "run-1",
                "plan-1",
                TransitionFamily.DIRECT_SHARE_REVOKE,
                ProbeType.PROTECTED_READ,
                VerdictKind.CONFORMS,
                ViolationSubtype.NONE,
                make_trace(),
                created_at=created_at,
            )

    with TraceStore(
        db_path, encryption_key=TRACE_PASSPHRASE, retention_days=7
    ) as store:
        assert store.get_verdict("old") is None
        assert store.get_verdict("recent") is not None


def test_trace_store_schema_matches_spec(tmp_path: Path) -> None:
    db_path = tmp_path / "janus_traces.sqlite3"
    with TraceStore(db_path, encryption_key=TRACE_PASSPHRASE):
        pass

    with sqlite3.connect(db_path) as connection:
        run_columns = [
            row[1] for row in connection.execute("PRAGMA table_info(runs)")
        ]
        verdict_columns = [
            row[1] for row in connection.execute("PRAGMA table_info(verdicts)")
        ]
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]

    assert run_columns == [
        "run_id",
        "started_at",
        "policy_sha256",
        "manifest_sha256",
        "target_url",
        "total_requests",
    ]
    assert verdict_columns == [
        "verdict_id",
        "run_id",
        "plan_id",
        "transition_family",
        "probe_type",
        "verdict",
        "violation_subtype",
        "encrypted_trace_blob",
        "created_at",
    ]
    assert journal_mode.lower() == "wal"


def test_trace_store_uses_parameterized_sql(tmp_path: Path) -> None:
    db_path = tmp_path / "janus_traces.sqlite3"
    hostile_run_id = "run-1'); DROP TABLE verdicts; --"
    with TraceStore(db_path, encryption_key=TRACE_PASSPHRASE) as store:
        store.record_run(
            hostile_run_id,
            "2026-11-15T00:00:00+00:00",
            POLICY_SHA,
            None,
            "http://testserver",
        )
        store.record_verdict(
            "verdict-1",
            hostile_run_id,
            "plan-1",
            TransitionFamily.DIRECT_SHARE_REVOKE,
            ProbeType.PROTECTED_READ,
            VerdictKind.CONFORMS,
            ViolationSubtype.NONE,
            make_trace(),
        )
        assert store.get_verdict("verdict-1")["run_id"] == hostile_run_id
        fetched = store.fetch_verdicts(hostile_run_id)
        assert [row["verdict_id"] for row in fetched] == ["verdict-1"]

    with sqlite3.connect(db_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM verdicts").fetchone()[0]
    assert count == 1


def test_trace_store_close_is_idempotent(tmp_path: Path) -> None:
    store = TraceStore(tmp_path / "janus_traces.sqlite3", encryption_key=TRACE_PASSPHRASE)
    store.close()
    store.close()
    with pytest.raises(RuntimeError, match="closed"):
        store.get_verdict("verdict-1")


# ---------------------------------------------------------------------------
# Task 3 review fixes
# ---------------------------------------------------------------------------


def test_gatekeeper_does_not_resolve_urls_rejected_by_early_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def spy_getaddrinfo(
        host: str, port: object, *args: object, **kwargs: object
    ) -> object:
        calls.append(host)
        raise AssertionError("getaddrinfo must not run for a rejected URL")

    monkeypatch.setattr(socket, "getaddrinfo", spy_getaddrinfo)
    gatekeeper = SafetyGatekeeper(make_signed_manifest(), secret=SECRET)
    for url in ("file:///etc/passwd", "http://evil.example.com/api"):
        with pytest.raises(ScopeViolationError):
            gatekeeper.validate_request(url)
    assert calls == []


def test_gatekeeper_resolves_through_real_getaddrinfo_branch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def fake_getaddrinfo(
        host: str, port: object, *args: object, **kwargs: object
    ) -> list[tuple[object, ...]]:
        calls.append(host)
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 0),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    gatekeeper = SafetyGatekeeper(make_signed_manifest(), secret=SECRET)
    gatekeeper.validate_url("http://localhost/health")
    assert calls == ["localhost"]


def test_gatekeeper_real_getaddrinfo_numeric_loopback() -> None:
    gatekeeper = SafetyGatekeeper(make_signed_manifest(), secret=SECRET)
    gatekeeper.validate_url("http://127.0.0.1/health")


def test_gatekeeper_getaddrinfo_oserror_is_ssrf_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing_getaddrinfo(
        host: str, port: object, *args: object, **kwargs: object
    ) -> object:
        raise socket.gaierror("dns failure")

    monkeypatch.setattr(socket, "getaddrinfo", failing_getaddrinfo)
    gatekeeper = SafetyGatekeeper(make_signed_manifest(), secret=SECRET)
    with pytest.raises(SSRFBlockedError):
        gatekeeper.validate_url("http://localhost/health")


def make_delete_policy_gatekeeper() -> SafetyGatekeeper:
    manifest = make_signed_manifest(
        transition_endpoints=[
            TransitionEndpoint(
                family=TransitionFamily.DIRECT_SHARE_REVOKE,
                method="DELETE",
                path_template="/api/v1/documents/{doc_id}/shares/{user_id}",
            )
        ],
        reset_endpoint="/api/v1/admin/reset",
    )
    return SafetyGatekeeper(
        manifest, secret=SECRET, resolver=fixed_resolver("127.0.0.1")
    )


def test_gatekeeper_keeps_legitimate_transition_delete_allowed() -> None:
    gatekeeper = make_delete_policy_gatekeeper()
    gatekeeper.validate_url(
        "http://testserver/api/v1/documents/doc_1/shares/bea", "DELETE"
    )


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/documents/doc_1/shares/..%2F..%2Fdoc_1",
        "/api/v1/documents/doc_1/shares/bea%2F..%2F..%2Fdoc_1",
        "/api/v1/documents/doc_1/shares/%2e%2e/%2e%2e/doc_1",
        "/api/v1/documents/doc_1/shares/../../doc_1",
        "/api/v1/documents/doc_1/shares/bea/../../../doc_1",
        "/api/v1/documents/doc_1/shares/..%5C..%5Cdoc_1",
        "//api/v1/documents/doc_1",
    ],
)
def test_gatekeeper_blocks_delete_path_traversal(path: str) -> None:
    gatekeeper = make_delete_policy_gatekeeper()
    with pytest.raises(ScopeViolationError):
        gatekeeper.validate_url("http://testserver" + path, "DELETE")


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/admin/reset/../../../documents/doc_1",
        "/api/v1/admin/%2e%2e/admin/reset",
        "/api/v1/admin/reset%2F..%2F..%2Fdocuments%2Fdoc_1",
    ],
)
def test_gatekeeper_blocks_reset_endpoint_path_traversal(path: str) -> None:
    gatekeeper = make_delete_policy_gatekeeper()
    with pytest.raises(ScopeViolationError):
        gatekeeper.validate_url("http://testserver" + path, "DELETE")


def test_gatekeeper_normalizes_reset_path_dot_segments() -> None:
    # The path resolves to the declared reset endpoint, so it remains permitted.
    gatekeeper = make_delete_policy_gatekeeper()
    gatekeeper.validate_url("http://testserver/api/v1/admin/x/../reset", "DELETE")


def test_gatekeeper_collapses_repeated_slashes_for_delete_policy() -> None:
    gatekeeper = make_delete_policy_gatekeeper()
    gatekeeper.validate_url(
        "http://testserver//api/v1/documents/doc_1/shares/bea", "DELETE"
    )
    with pytest.raises(ScopeViolationError):
        gatekeeper.validate_url("http://testserver//api/v1/documents/doc_1", "DELETE")


def test_redactor_scrubs_httpx_headers_mapping() -> None:
    headers = httpx.Headers(
        {
            "Authorization": "Basic dXNlcjpwYXNz",
            "X-Api-Key": "secret-key-value",
            "Content-Type": "application/json",
        }
    )
    sanitized = Redactor.sanitize_trace({"headers": headers})

    assert isinstance(sanitized["headers"], dict)
    header_map = {key.lower(): value for key, value in sanitized["headers"].items()}
    assert header_map["authorization"] == "Bearer [REDACTED]"
    assert header_map["x-api-key"] == "Bearer [REDACTED]"
    assert header_map["content-type"] == "application/json"

    rendered = json.dumps(sanitized)
    assert "dXNlcjpwYXNz" not in rendered
    assert "secret-key-value" not in rendered


def test_redactor_scrubs_multi_items_pairs() -> None:
    headers = httpx.Headers(
        [
            ("authorization", "Basic dXNlcjpwYXNz"),
            ("x-api-key", "secret-key-value"),
            ("set-cookie", "a=1"),
            ("set-cookie", "b=2"),
            ("content-type", "application/json"),
        ]
    )
    sanitized = Redactor.sanitize_trace({"headers": headers.multi_items()})

    pairs = sanitized["headers"]
    assert isinstance(pairs, list)
    redacted_names = {
        name.lower()
        for name, value in pairs
        if value == "Bearer [REDACTED]"
    }
    assert {"authorization", "x-api-key", "set-cookie"} <= redacted_names

    rendered = json.dumps(sanitized)
    assert "dXNlcjpwYXNz" not in rendered
    assert "secret-key-value" not in rendered
    assert "a=1" not in rendered
    assert "b=2" not in rendered


def test_redactor_scrubs_two_element_sequences() -> None:
    assert Redactor.sanitize_trace(("authorization", "Basic dXNlcjpwYXNz")) == (
        "authorization",
        "Bearer [REDACTED]",
    )
    assert Redactor.sanitize_trace(["X-Api-Key", "secret-key-value"]) == [
        "X-Api-Key",
        "Bearer [REDACTED]",
    ]


def test_redactor_rejects_non_json_leaves() -> None:
    with pytest.raises(TypeError, match="non-JSON"):
        Redactor.sanitize_trace({"bad": object()})
    with pytest.raises(TypeError, match="non-JSON"):
        Redactor.sanitize_trace({"bad": b"raw-bytes"})


def test_trace_store_redacts_httpx_headers(tmp_path: Path) -> None:
    db_path = tmp_path / "janus_traces.sqlite3"
    headers = httpx.Headers(
        {
            "Authorization": "Basic dXNlcjpwYXNz",
            "X-Api-Key": "secret-key-value",
        }
    )
    with TraceStore(db_path, encryption_key=TRACE_PASSPHRASE) as store:
        store.record_verdict(
            "verdict-1",
            "run-1",
            "plan-1",
            TransitionFamily.DIRECT_SHARE_REVOKE,
            ProbeType.PROTECTED_READ,
            VerdictKind.CONFORMS,
            ViolationSubtype.NONE,
            {"headers": headers},
        )
        row = store.get_verdict("verdict-1")

    assert row is not None
    trace = row["trace"]
    header_map = {key.lower(): value for key, value in trace["headers"].items()}
    assert header_map["authorization"] == "Bearer [REDACTED]"
    assert header_map["x-api-key"] == "Bearer [REDACTED]"
    rendered = json.dumps(trace)
    assert "dXNlcjpwYXNz" not in rendered
    assert "secret-key-value" not in rendered


def test_trace_store_normalizes_caller_timestamps(tmp_path: Path) -> None:
    db_path = tmp_path / "janus_traces.sqlite3"
    with TraceStore(db_path, encryption_key=TRACE_PASSPHRASE) as store:
        store.record_verdict(
            "verdict-1",
            "run-1",
            "plan-1",
            TransitionFamily.DIRECT_SHARE_REVOKE,
            ProbeType.PROTECTED_READ,
            VerdictKind.CONFORMS,
            ViolationSubtype.NONE,
            make_trace(),
            created_at="2026-11-15T10:00:00+02:00",
        )
        row = store.get_verdict("verdict-1")
        assert row is not None
        assert row["created_at"] == "2026-11-15T08:00:00.000000+00:00"

        with pytest.raises(ValueError, match="ISO-8601"):
            store.record_verdict(
                "verdict-2",
                "run-1",
                "plan-1",
                TransitionFamily.DIRECT_SHARE_REVOKE,
                ProbeType.PROTECTED_READ,
                VerdictKind.CONFORMS,
                ViolationSubtype.NONE,
                make_trace(),
                created_at="not-a-timestamp",
            )


def test_trace_store_retention_normalizes_offset_timestamps(tmp_path: Path) -> None:
    db_path = tmp_path / "janus_traces.sqlite3"
    with TraceStore(
        db_path, encryption_key=TRACE_PASSPHRASE, retention_days=7
    ) as store:
        store.record_verdict(
            "old",
            "run-1",
            "plan-1",
            TransitionFamily.DIRECT_SHARE_REVOKE,
            ProbeType.PROTECTED_READ,
            VerdictKind.CONFORMS,
            ViolationSubtype.NONE,
            make_trace(),
            created_at="2020-01-01T00:00:00+05:00",
        )
        row = store.get_verdict("old")
        assert row is not None
        assert row["created_at"] == "2019-12-31T19:00:00.000000+00:00"

    with TraceStore(
        db_path, encryption_key=TRACE_PASSPHRASE, retention_days=7
    ) as store:
        assert store.get_verdict("old") is None
