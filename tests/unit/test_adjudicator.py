"""Unit tests for the 4D differential effect-witness adjudicator."""

from __future__ import annotations

from typing import Any

from janus_auth.models import (
    BranchTrace,
    CompiledTwinPlan,
    CounterfactualPairPlan,
    Decision,
    PairedExecutionEvidence,
    ProbeType,
    StepObservation,
    SupportState,
    TransitionFamily,
    VerdictKind,
    ViolationSubtype,
)
from janus_auth.oracle.adjudicator import Adjudicator, adjudicate
from janus_auth.security.store import TraceStore

CANARY = "JANUS_CANARY_adjudicator"
MUTATED = "MUTATED_BY_bea"


def _support_state(action: ProbeType) -> SupportState:
    return SupportState(
        principal_id="bea",
        resource_id="doc_1",
        action=action,
        active_principal=True,
        same_tenant=True,
        direct_grant=True,
    )


def _plan(
    *,
    family: TransitionFamily = TransitionFamily.DIRECT_SHARE_REVOKE,
    probe_type: ProbeType = ProbeType.PROTECTED_READ,
    a_expected: Decision = Decision.DENY,
    b_expected: Decision = Decision.ALLOW,
) -> CompiledTwinPlan:
    synthesized = CounterfactualPairPlan(
        plan_id="ct-test",
        transition_family=family,
        probe_type=probe_type,
        principal_role_class="same_tenant_peer",
        branch_a_pre=_support_state(probe_type),
        branch_a_post=_support_state(probe_type),
        branch_a_expected=a_expected,
        branch_b_pre=_support_state(probe_type),
        branch_b_post=_support_state(probe_type),
        branch_b_expected=b_expected,
        surviving_support_name="group",
        hamming_distance=1,
    )
    return CompiledTwinPlan(
        plan_id="ct-test",
        synthesized=synthesized,
        branch_a_steps=[],
        branch_b_steps=[],
        canary=CANARY,
        probe_principal="bea",
    )


def _observation(
    step_id: str,
    status: int,
    *,
    body: dict[str, Any] | None = None,
    canary: bool = False,
) -> StepObservation:
    return StepObservation(
        step_id=step_id,
        method="PATCH" if "probe" == step_id and body is not None else "GET",
        path="/api/v1/documents/doc_1",
        principal_alias="bea",
        status_code=status,
        parsed_json=body,
        canary_present=canary,
    )


def _branch(
    label: str,
    *,
    probe: StepObservation,
    effect: StepObservation,
    valid: bool = True,
    pre: bool = True,
    post: bool = True,
) -> BranchTrace:
    return BranchTrace(
        branch=label,  # type: ignore[arg-type]
        plan_id="ct-test",
        steps=[],
        pre_witness_ok=pre,
        post_transition_witness_ok=post,
        probe=probe,
        effect_witness=effect,
        canary=CANARY,
        valid=valid,
    )


def _evidence(a: BranchTrace, b: BranchTrace) -> PairedExecutionEvidence:
    return PairedExecutionEvidence(
        plan_id="ct-test",
        branch_a=a,
        branch_b=b,
        branch_a_reset_epoch=1,
        branch_b_reset_epoch=2,
    )


def _read_branches(
    a_status: int,
    *,
    a_secret: object = None,
    b_status: int = 200,
    b_secret: object = CANARY,
    a_valid: bool = True,
) -> PairedExecutionEvidence:
    a_probe = _observation(
        "probe",
        a_status,
        body={"secret_content": a_secret} if a_status == 200 else {"detail": "denied"},
        canary=a_secret == CANARY,
    )
    b_probe = _observation(
        "probe",
        b_status,
        body={"secret_content": b_secret} if b_status == 200 else {"detail": "denied"},
        canary=b_secret == CANARY,
    )
    a_effect = _observation("effect-witness", 200, body={"secret_content": CANARY}, canary=True)
    b_effect = _observation("effect-witness", 200, body={"secret_content": CANARY}, canary=True)
    return _evidence(
        _branch("A", probe=a_probe, effect=a_effect, valid=a_valid),
        _branch("B", probe=b_probe, effect=b_effect),
    )


def _write_branches(
    a_status: int,
    *,
    a_mutated: bool,
    b_status: int = 200,
    b_mutated: bool = True,
) -> PairedExecutionEvidence:
    a_probe = _observation("probe", a_status, body={"detail": "probe"})
    b_probe = _observation("probe", b_status, body={"detail": "probe"})
    a_effect = _observation(
        "effect-witness",
        200,
        body={"secret_content": MUTATED if a_mutated else CANARY},
        canary=not a_mutated,
    )
    b_effect = _observation(
        "effect-witness",
        200,
        body={"secret_content": MUTATED if b_mutated else CANARY},
        canary=not b_mutated,
    )
    return _evidence(
        _branch("A", probe=a_probe, effect=a_effect),
        _branch("B", probe=b_probe, effect=b_effect),
    )


def test_clean_read_conforms() -> None:
    report = adjudicate(_plan(), _read_branches(403))
    assert report.verdict is VerdictKind.CONFORMS
    assert report.subtype is ViolationSubtype.NONE
    assert report.reproduction_verified is True
    assert len(report.dimensions) == 4


def test_read_leak_is_a_confirmed_violation() -> None:
    report = adjudicate(_plan(), _read_branches(200, a_secret=CANARY))
    assert report.verdict is VerdictKind.CONFIRMED_VIOLATION
    assert report.subtype is ViolationSubtype.BOLA_READ_LEAK


def test_family_specific_read_subtypes() -> None:
    group = adjudicate(
        _plan(family=TransitionFamily.GROUP_MEMBER_REMOVE),
        _read_branches(200, a_secret=CANARY),
    )
    assert group.subtype is ViolationSubtype.STALE_GROUP_CACHE

    delegation = adjudicate(
        _plan(family=TransitionFamily.DELEGATION_REVOKE),
        _read_branches(200, a_secret=CANARY),
    )
    assert delegation.subtype is ViolationSubtype.BROKEN_DELEGATION_CASCADE

    transfer = adjudicate(
        _plan(family=TransitionFamily.OWNERSHIP_TRANSFER),
        _read_branches(200, a_secret=CANARY),
    )
    assert transfer.subtype is ViolationSubtype.FORMER_OWNER_RETENTION


def test_masked_200_is_a_conforming_projection() -> None:
    report = adjudicate(_plan(), _read_branches(200, a_secret=None))
    assert report.verdict is VerdictKind.CONFORMS_MASKED
    assert report.subtype is ViolationSubtype.NONE


def test_branch_b_denial_is_a_legitimate_access_regression() -> None:
    report = adjudicate(_plan(), _read_branches(403, b_status=403))
    assert report.verdict is VerdictKind.LEGITIMATE_ACCESS_REGRESSION
    assert report.subtype is ViolationSubtype.OVER_REVOCATION_REGRESSION


def test_inverted_enforcement_on_reads() -> None:
    report = adjudicate(_plan(), _read_branches(200, a_secret=CANARY, b_status=403))
    assert report.verdict is VerdictKind.CONFIRMED_VIOLATION
    assert report.subtype is ViolationSubtype.INVERTED_ENFORCEMENT


def test_silent_write_on_403_is_detected_from_the_effect_witness() -> None:
    report = adjudicate(
        _plan(probe_type=ProbeType.REVERSIBLE_WRITE),
        _write_branches(403, a_mutated=True),
    )
    assert report.verdict is VerdictKind.CONFIRMED_VIOLATION
    assert report.subtype is ViolationSubtype.SILENT_WRITE_SIDE_EFFECT


def test_unauthorized_200_write_uses_the_family_subtype() -> None:
    report = adjudicate(
        _plan(
            family=TransitionFamily.GROUP_MEMBER_REMOVE,
            probe_type=ProbeType.REVERSIBLE_WRITE,
        ),
        _write_branches(200, a_mutated=True),
    )
    assert report.verdict is VerdictKind.CONFIRMED_VIOLATION
    assert report.subtype is ViolationSubtype.STALE_GROUP_CACHE


def test_clean_write_conforms() -> None:
    report = adjudicate(
        _plan(probe_type=ProbeType.REVERSIBLE_WRITE),
        _write_branches(403, a_mutated=False),
    )
    assert report.verdict is VerdictKind.CONFORMS


def test_inverted_write_enforcement() -> None:
    report = adjudicate(
        _plan(probe_type=ProbeType.REVERSIBLE_WRITE),
        _write_branches(403, a_mutated=True, b_status=403, b_mutated=False),
    )
    assert report.verdict is VerdictKind.CONFIRMED_VIOLATION
    assert report.subtype is ViolationSubtype.INVERTED_ENFORCEMENT


def test_write_access_regression() -> None:
    report = adjudicate(
        _plan(probe_type=ProbeType.REVERSIBLE_WRITE),
        _write_branches(403, a_mutated=False, b_status=403, b_mutated=False),
    )
    assert report.verdict is VerdictKind.LEGITIMATE_ACCESS_REGRESSION


def test_invalid_test_wins_over_every_observation() -> None:
    report = adjudicate(_plan(), _read_branches(200, a_secret=CANARY, a_valid=False))
    assert report.verdict is VerdictKind.INVALID_TEST
    assert report.reproduction_verified is False


def test_unknown_expectation_abstains() -> None:
    report = adjudicate(
        _plan(a_expected=Decision.UNKNOWN),
        _read_branches(200, a_secret=CANARY),
    )
    assert report.verdict is VerdictKind.UNCERTAIN_ABSTAIN


def test_ambiguous_observations_abstain() -> None:
    report = adjudicate(_plan(), _read_branches(500, b_status=500))
    assert report.verdict is VerdictKind.UNCERTAIN_ABSTAIN


def test_adjudicator_records_an_encrypted_verdict_trace() -> None:
    with TraceStore(":memory:") as store:
        adjudicator = Adjudicator(store, run_id="run-adjudicator")
        report = adjudicator.adjudicate(
            _plan(), _read_branches(200, a_secret=CANARY)
        )
        assert report.verdict is VerdictKind.CONFIRMED_VIOLATION
        stored = store.fetch_verdicts("run-adjudicator")
        assert len(stored) == 1
        assert stored[0]["verdict"] == VerdictKind.CONFIRMED_VIOLATION.value
        assert "secret_content" in str(stored[0]["trace"])
