"""Unit tests for the pair-preserving delta-debugging minimizer."""

from __future__ import annotations

import pytest

from janus_auth.models import (
    AdjudicationReport,
    ApiStep,
    BranchSummary,
    CompiledTwinPlan,
    CounterfactualPairPlan,
    Decision,
    ExpectedRole,
    ProbeType,
    SupportState,
    TransitionFamily,
    VerdictKind,
    ViolationSubtype,
)
from janus_auth.runner.minimizer import (
    MinimizationError,
    PairPreservingMinimizer,
)

ESSENTIAL_IDS = {
    "reset",
    "create-doc",
    "pre-witness",
    "transition",
    "post-transition-witness",
    "probe",
    "effect-witness",
}


def _step(
    step_id: str,
    role: ExpectedRole,
    *,
    method: str = "POST",
    path: str = "/api/v1/noise",
    reversible: bool = True,
) -> ApiStep:
    return ApiStep(
        step_id=step_id,
        method=method,  # type: ignore[arg-type]
        path_template=path,
        principal_alias="ada",
        expected_role=role,
        reversible=reversible,
    )


def _essential_steps() -> list[ApiStep]:
    return [
        _step("reset", ExpectedRole.SETUP, path="/api/v1/admin/reset", reversible=False),
        _step("create-doc", ExpectedRole.SETUP, path="/api/v1/documents"),
        _step("pre-witness", ExpectedRole.PRE_WITNESS, method="GET", path="/doc"),
        _step("transition", ExpectedRole.TRANSITION, method="DELETE", reversible=False),
        _step(
            "post-transition-witness",
            ExpectedRole.POST_TRANSITION_WITNESS,
            method="GET",
            path="/permissions",
        ),
        _step("probe", ExpectedRole.PROBE, method="GET", path="/doc"),
        _step(
            "effect-witness",
            ExpectedRole.EFFECT_WITNESS,
            method="GET",
            path="/doc",
        ),
    ]


def _support() -> SupportState:
    return SupportState(principal_id="bea", resource_id="doc_1", action=ProbeType.PROTECTED_READ)


def _plan(noise: int, *, poison: bool = False) -> CompiledTwinPlan:
    synthesized = CounterfactualPairPlan(
        plan_id="ct-min",
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
    shared = _essential_steps()
    noise_steps = [
        _step(f"noise-{index}", ExpectedRole.SETUP, path=f"/api/v1/noise/{index}")
        for index in range(noise)
    ]
    poison_steps = [_step("poison", ExpectedRole.SETUP, path="/api/v1/poison")] if poison else []
    branch_b_only = [_step("group-membership", ExpectedRole.SETUP, path="/groups/members")]
    return CompiledTwinPlan(
        plan_id="ct-min",
        synthesized=synthesized,
        branch_a_steps=[*shared, *noise_steps, *poison_steps],
        branch_b_steps=[*shared, *noise_steps, *poison_steps, *branch_b_only],
        canary="JANUS_CANARY_min",
        probe_principal="bea",
    )


def _report(
    verdict: VerdictKind,
    subtype: ViolationSubtype = ViolationSubtype.NONE,
) -> AdjudicationReport:
    control = verdict is VerdictKind.CONFORMS
    return AdjudicationReport(
        plan_id="ct-min",
        verdict=verdict,
        subtype=subtype,
        branch_b_summary=BranchSummary(
            branch="B",
            access_allowed=control,
            state_mutated=False,
        ),
    )


def _replay_factory(poison: bool):
    def replay(candidate: CompiledTwinPlan) -> AdjudicationReport:
        a_ids = {step.step_id for step in candidate.branch_a_steps}
        b_ids = {step.step_id for step in candidate.branch_b_steps}
        if not ESSENTIAL_IDS <= a_ids or not ESSENTIAL_IDS <= b_ids:
            return _report(VerdictKind.INVALID_TEST)
        if "group-membership" not in b_ids:
            return _report(
                VerdictKind.LEGITIMATE_ACCESS_REGRESSION,
                ViolationSubtype.OVER_REVOCATION_REGRESSION,
            )
        if poison and "poison" not in a_ids:
            return _report(
                VerdictKind.LEGITIMATE_ACCESS_REGRESSION,
                ViolationSubtype.OVER_REVOCATION_REGRESSION,
            )
        return _report(VerdictKind.CONFORMS)

    return replay


def test_six_noise_steps_are_removed_without_breaking_the_pair() -> None:
    plan = _plan(6)
    result = PairPreservingMinimizer(_replay_factory(False)).minimize(plan)
    assert result.reproduction_verified is True
    assert result.verdict is VerdictKind.CONFORMS
    assert result.reduction_ratio >= 0.35
    assert result.removed_step_ids == tuple(f"noise-{index}" for index in range(6))
    assert "group-membership" in {
        step.step_id for step in result.plan.branch_b_steps
    }


def test_a_plan_without_noise_is_unchanged() -> None:
    plan = _plan(0)
    result = PairPreservingMinimizer(_replay_factory(False)).minimize(plan)
    assert result.removed_step_ids == ()
    assert result.reduction_ratio == 0.0
    assert result.minimized_step_count == result.original_step_count


def test_essential_structural_steps_are_never_removed() -> None:
    plan = _plan(6)
    result = PairPreservingMinimizer(_replay_factory(False)).minimize(plan)
    for branch in (result.plan.branch_a_steps, result.plan.branch_b_steps):
        assert ESSENTIAL_IDS <= {step.step_id for step in branch}


def test_a_step_required_for_branch_b_control_is_retained() -> None:
    plan = _plan(6, poison=True)
    result = PairPreservingMinimizer(_replay_factory(True)).minimize(plan)
    assert "poison" not in result.removed_step_ids
    assert result.reproduction_verified is True
    assert "poison" in {step.step_id for step in result.plan.branch_a_steps}


def test_an_invalid_original_plan_is_rejected() -> None:
    plan = _plan(0)
    with pytest.raises(MinimizationError):
        PairPreservingMinimizer(
            lambda candidate: _report(VerdictKind.INVALID_TEST)
        ).minimize(plan)
