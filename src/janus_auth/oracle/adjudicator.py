"""4-dimensional differential effect-witness adjudicator.

The adjudicator consumes paired evidence produced from independent resets and applies the
truth table in ``PROJECT_SPEC.md`` section 9.3.3.  It never trusts a status code alone: read
verdicts require canary projections, write verdicts require the post-probe owner witness, and
every verdict is conditioned on the Branch B surviving-grant control.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from janus_auth.models import (
    AdjudicationReport,
    BranchSummary,
    BranchTrace,
    CompiledTwinPlan,
    Decision,
    DimensionFinding,
    PairedExecutionEvidence,
    ProbeType,
    StepObservation,
    TransitionFamily,
    VerdictKind,
    ViolationSubtype,
)
from janus_auth.security.store import TraceStore

_FAMILY_SUBTYPE: Final[dict[TransitionFamily, ViolationSubtype]] = {
    TransitionFamily.DIRECT_SHARE_REVOKE: ViolationSubtype.BOLA_READ_LEAK,
    TransitionFamily.GROUP_MEMBER_REMOVE: ViolationSubtype.STALE_GROUP_CACHE,
    TransitionFamily.DELEGATION_REVOKE: ViolationSubtype.BROKEN_DELEGATION_CASCADE,
    TransitionFamily.ROLE_DOWNGRADE: ViolationSubtype.BOLA_READ_LEAK,
    TransitionFamily.OWNERSHIP_TRANSFER: ViolationSubtype.FORMER_OWNER_RETENTION,
    TransitionFamily.TENANT_CHANGE: ViolationSubtype.BOLA_READ_LEAK,
}

_MUTATION_PREFIX: Final[str] = "MUTATED_BY_"
_DENIED_STATUSES: Final[frozenset[int]] = frozenset({401, 403, 404})


def _secret_of(observation: StepObservation | None) -> object:
    if observation is None or not isinstance(observation.parsed_json, dict):
        return None
    return observation.parsed_json.get("secret_content")


def _read_leak(observation: StepObservation | None, canary: str) -> bool:
    if observation is None or observation.status_code != 200:
        return False
    return observation.canary_present or _secret_of(observation) == canary


def _masked_projection(observation: StepObservation | None) -> bool:
    if observation is None or observation.status_code != 200:
        return False
    return _secret_of(observation) is None


def _state_mutated(observation: StepObservation | None) -> bool:
    secret = _secret_of(observation)
    return isinstance(secret, str) and secret.startswith(_MUTATION_PREFIX)


def _denied(observation: StepObservation | None) -> bool:
    return observation is None or observation.status_code in _DENIED_STATUSES


def _probe_observation(trace: BranchTrace) -> StepObservation | None:
    return trace.probe


def _branch_summary(trace: BranchTrace) -> BranchSummary:
    probe = trace.probe
    return BranchSummary(
        branch=trace.branch,
        probe_status_code=probe.status_code if probe is not None else None,
        canary_present=probe.canary_present if probe is not None else False,
        access_allowed=probe is not None and probe.status_code < 400,
        state_mutated=_state_mutated(trace.effect_witness),
    )


class Adjudicator:
    """Apply the 4D truth table and optionally persist the encrypted verdict trace."""

    def __init__(
        self,
        trace_store: TraceStore | None = None,
        *,
        run_id: str | None = None,
    ) -> None:
        if trace_store is not None and not run_id:
            raise ValueError("run_id is required when a TraceStore is provided")
        self._trace_store = trace_store
        self._run_id = run_id

    def adjudicate(
        self,
        plan: CompiledTwinPlan,
        evidence: PairedExecutionEvidence,
    ) -> AdjudicationReport:
        report = adjudicate(plan, evidence)
        if self._trace_store is not None and self._run_id is not None:
            self._trace_store.record_verdict(
                verdict_id=f"{self._run_id}-{plan.plan_id}",
                run_id=self._run_id,
                plan_id=plan.plan_id,
                transition_family=plan.synthesized.transition_family,
                probe_type=plan.synthesized.probe_type,
                verdict=report.verdict,
                violation_subtype=report.subtype,
                trace=evidence.model_dump(mode="json"),
                created_at=datetime.now(UTC),
            )
        return report


def adjudicate(
    plan: CompiledTwinPlan,
    evidence: PairedExecutionEvidence,
) -> AdjudicationReport:
    """Return the verdict for one counterfactual pair without side effects."""
    synthesized = plan.synthesized
    a = evidence.branch_a
    b = evidence.branch_b
    a_probe = _probe_observation(a)
    b_probe = _probe_observation(b)
    canary = plan.canary

    validity = _validity_finding(a, b)
    uncertainty = _uncertainty_finding(synthesized.branch_a_expected, synthesized.branch_b_expected)

    if not validity.passed:
        return _report(
            plan,
            evidence,
            VerdictKind.INVALID_TEST,
            ViolationSubtype.NONE,
            [validity, uncertainty],
        )
    if not uncertainty.passed:
        return _report(
            plan,
            evidence,
            VerdictKind.UNCERTAIN_ABSTAIN,
            ViolationSubtype.NONE,
            [validity, uncertainty],
        )

    if synthesized.probe_type is ProbeType.PROTECTED_READ:
        return _read_verdict(plan, evidence, validity, uncertainty, canary)
    return _write_verdict(plan, evidence, validity, uncertainty, a_probe, b_probe)


def _validity_finding(a: BranchTrace, b: BranchTrace) -> DimensionFinding:
    passed = (
        a.valid
        and b.valid
        and a.pre_witness_ok
        and b.pre_witness_ok
        and a.post_transition_witness_ok
        and b.post_transition_witness_ok
    )
    return DimensionFinding(
        name="validity_gate",
        passed=passed,
        detail="setup, reset, pre-witness, transition, and post-witness must all hold",
        evidence_step_ids=["pre-witness", "transition", "post-transition-witness"],
    )


def _uncertainty_finding(a_expected: Decision, b_expected: Decision) -> DimensionFinding:
    passed = a_expected is not Decision.UNKNOWN and b_expected is not Decision.UNKNOWN
    return DimensionFinding(
        name="uncertainty_gate",
        passed=passed,
        detail="UNKNOWN expectations abstain rather than guess",
        evidence_step_ids=[],
    )


def _read_verdict(
    plan: CompiledTwinPlan,
    evidence: PairedExecutionEvidence,
    validity: DimensionFinding,
    uncertainty: DimensionFinding,
    canary: str,
) -> AdjudicationReport:
    synthesized = plan.synthesized
    a = evidence.branch_a
    b = evidence.branch_b
    a_probe = _probe_observation(a)
    b_probe = _probe_observation(b)
    a_leak = _read_leak(a_probe, canary)
    a_masked = _masked_projection(a_probe)
    a_denied = _denied(a_probe)
    b_allowed = _read_leak(b_probe, canary)
    b_denied = _denied(b_probe)

    read_finding = DimensionFinding(
        name="read_projection",
        passed=not a_leak,
        detail=(
            f"branch A status={_status(a_probe)} canary={a_leak} masked={a_masked}; "
            f"branch B canary={b_allowed}"
        ),
        evidence_step_ids=["probe"],
    )
    control_finding = DimensionFinding(
        name="surviving_grant_control",
        passed=b_allowed or synthesized.branch_b_expected is not Decision.ALLOW,
        detail=f"branch B surviving-grant probe canary={b_allowed}",
        evidence_step_ids=["probe"],
    )
    dimensions = [validity, uncertainty, read_finding, control_finding]

    if synthesized.branch_a_expected is Decision.ALLOW:
        if a_leak and b_allowed:
            return _report(plan, evidence, VerdictKind.CONFORMS, ViolationSubtype.NONE, dimensions)
        return _report(
            plan, evidence, VerdictKind.UNCERTAIN_ABSTAIN, ViolationSubtype.NONE, dimensions
        )

    if a_leak:
        if synthesized.branch_b_expected is Decision.ALLOW and b_denied:
            return _report(
                plan,
                evidence,
                VerdictKind.CONFIRMED_VIOLATION,
                ViolationSubtype.INVERTED_ENFORCEMENT,
                dimensions,
            )
        return _report(
            plan,
            evidence,
            VerdictKind.CONFIRMED_VIOLATION,
            _FAMILY_SUBTYPE[synthesized.transition_family],
            dimensions,
        )
    if a_masked and b_allowed:
        return _report(
            plan, evidence, VerdictKind.CONFORMS_MASKED, ViolationSubtype.NONE, dimensions
        )
    if a_denied and b_allowed:
        return _report(plan, evidence, VerdictKind.CONFORMS, ViolationSubtype.NONE, dimensions)
    if (
        a_denied
        and b_denied
        and synthesized.branch_b_expected is Decision.ALLOW
    ):
        return _report(
            plan,
            evidence,
            VerdictKind.LEGITIMATE_ACCESS_REGRESSION,
            ViolationSubtype.OVER_REVOCATION_REGRESSION,
            dimensions,
        )
    return _report(
        plan, evidence, VerdictKind.UNCERTAIN_ABSTAIN, ViolationSubtype.NONE, dimensions
    )


def _write_verdict(
    plan: CompiledTwinPlan,
    evidence: PairedExecutionEvidence,
    validity: DimensionFinding,
    uncertainty: DimensionFinding,
    a_probe: StepObservation | None,
    b_probe: StepObservation | None,
) -> AdjudicationReport:
    synthesized = plan.synthesized
    a = evidence.branch_a
    b = evidence.branch_b
    a_mutated = _state_mutated(a.effect_witness)
    b_mutated = _state_mutated(b.effect_witness)

    mutation_finding = DimensionFinding(
        name="post_probe_state_mutation",
        passed=not a_mutated,
        detail=(
            f"branch A mutated={a_mutated} status={_status(a_probe)}; "
            f"branch B mutated={b_mutated}"
        ),
        evidence_step_ids=["probe", "effect-witness"],
    )
    control_finding = DimensionFinding(
        name="surviving_grant_control",
        passed=b_mutated or synthesized.branch_b_expected is not Decision.ALLOW,
        detail=f"branch B surviving-grant mutation={b_mutated}",
        evidence_step_ids=["probe", "effect-witness"],
    )
    dimensions = [validity, uncertainty, mutation_finding, control_finding]

    if synthesized.branch_a_expected is Decision.ALLOW:
        if a_mutated and b_mutated:
            return _report(plan, evidence, VerdictKind.CONFORMS, ViolationSubtype.NONE, dimensions)
        return _report(
            plan, evidence, VerdictKind.UNCERTAIN_ABSTAIN, ViolationSubtype.NONE, dimensions
        )

    if a_mutated:
        if synthesized.branch_b_expected is Decision.ALLOW and not b_mutated:
            return _report(
                plan,
                evidence,
                VerdictKind.CONFIRMED_VIOLATION,
                ViolationSubtype.INVERTED_ENFORCEMENT,
                dimensions,
            )
        status = a_probe.status_code if a_probe is not None else 0
        subtype = (
            ViolationSubtype.SILENT_WRITE_SIDE_EFFECT
            if status >= 400
            else _FAMILY_SUBTYPE[synthesized.transition_family]
        )
        return _report(
            plan, evidence, VerdictKind.CONFIRMED_VIOLATION, subtype, dimensions
        )
    if b_mutated:
        return _report(plan, evidence, VerdictKind.CONFORMS, ViolationSubtype.NONE, dimensions)
    if _denied(a_probe) and synthesized.branch_b_expected is Decision.ALLOW:
        return _report(
            plan,
            evidence,
            VerdictKind.LEGITIMATE_ACCESS_REGRESSION,
            ViolationSubtype.OVER_REVOCATION_REGRESSION,
            dimensions,
        )
    return _report(
        plan, evidence, VerdictKind.UNCERTAIN_ABSTAIN, ViolationSubtype.NONE, dimensions
    )


def _status(observation: StepObservation | None) -> int | None:
    return observation.status_code if observation is not None else None


def _report(
    plan: CompiledTwinPlan,
    evidence: PairedExecutionEvidence,
    verdict: VerdictKind,
    subtype: ViolationSubtype,
    dimensions: list[DimensionFinding],
) -> AdjudicationReport:
    return AdjudicationReport(
        plan_id=plan.plan_id,
        verdict=verdict,
        subtype=subtype,
        dimensions=dimensions,
        evidence={
            "transition_family": plan.synthesized.transition_family.value,
            "probe_type": plan.synthesized.probe_type.value,
            "branch_a_reset_epoch": str(evidence.branch_a_reset_epoch),
            "branch_b_reset_epoch": str(evidence.branch_b_reset_epoch),
        },
        branch_a_summary=_branch_summary(evidence.branch_a),
        branch_b_summary=_branch_summary(evidence.branch_b),
        reproduction_verified=evidence.branch_a.valid and evidence.branch_b.valid,
    )


__all__ = ["Adjudicator", "adjudicate"]
