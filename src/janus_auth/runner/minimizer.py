"""Pair-preserving delta-debugging minimizer.

The minimizer removes redundant setup/noise steps from a compiled twin plan while requiring
that a fresh replay reproduces the exact verdict and subtype *and* preserves the Branch B
surviving-grant control.  Essential structural steps can never be candidates.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from janus_auth.models import (
    AdjudicationReport,
    BranchSummary,
    CompiledTwinPlan,
    ExpectedRole,
    ProbeType,
    VerdictKind,
    ViolationSubtype,
)

Replay = Callable[[CompiledTwinPlan], AdjudicationReport]

_ESSENTIAL_STEP_IDS: Final[frozenset[str]] = frozenset(
    {
        "reset",
        "create-doc",
        "pre-witness",
        "transition",
        "post-transition-witness",
        "probe",
        "effect-witness",
    }
)
_ESSENTIAL_ROLES: Final[frozenset[ExpectedRole]] = frozenset(
    {
        ExpectedRole.PRE_WITNESS,
        ExpectedRole.TRANSITION,
        ExpectedRole.POST_TRANSITION_WITNESS,
        ExpectedRole.PROBE,
        ExpectedRole.EFFECT_WITNESS,
    }
)


class MinimizationError(RuntimeError):
    """Raised when the original plan does not reproduce a minimizable verdict."""


@dataclass(frozen=True, slots=True)
class MinimizationResult:
    plan: CompiledTwinPlan
    original_step_count: int
    minimized_step_count: int
    reduction_ratio: float
    removed_step_ids: tuple[str, ...]
    verdict: VerdictKind
    subtype: ViolationSubtype
    reproduction_verified: bool


def _is_essential(step_id: str, role: ExpectedRole, reversible: bool) -> bool:
    return (
        step_id in _ESSENTIAL_STEP_IDS
        or role in _ESSENTIAL_ROLES
        or not reversible
    )


def _shared_step_ids(plan: CompiledTwinPlan) -> list[str]:
    branch_a = {step.step_id: step for step in plan.branch_a_steps}
    branch_b = {step.step_id: step for step in plan.branch_b_steps}
    candidates: list[str] = []
    for step_id, step in branch_a.items():
        other = branch_b.get(step_id)
        if other is None or step != other:
            continue
        if _is_essential(step.step_id, step.expected_role, step.reversible):
            continue
        candidates.append(step_id)
    return candidates


def _project(plan: CompiledTwinPlan, removed: frozenset[str]) -> CompiledTwinPlan:
    return plan.model_copy(
        update={
            "branch_a_steps": [
                step for step in plan.branch_a_steps if step.step_id not in removed
            ],
            "branch_b_steps": [
                step for step in plan.branch_b_steps if step.step_id not in removed
            ],
        }
    )


def _control_outcome(report: AdjudicationReport, probe_type: ProbeType) -> bool | None:
    summary: BranchSummary | None = report.branch_b_summary
    if summary is None:
        return None
    if probe_type is ProbeType.PROTECTED_READ:
        return summary.access_allowed
    return summary.state_mutated


def _same_outcome(
    report: AdjudicationReport,
    target: AdjudicationReport,
    probe_type: ProbeType,
) -> bool:
    if report.verdict is not target.verdict or report.subtype is not target.subtype:
        return False
    return _control_outcome(report, probe_type) == _control_outcome(target, probe_type)


def _split(candidates: Sequence[str], parts: int) -> list[list[str]]:
    size = len(candidates)
    chunk = (size + parts - 1) // parts
    return [list(candidates[index : index + chunk]) for index in range(0, size, chunk)]


class PairPreservingMinimizer:
    """Zeller-style ddmin over shared setup steps with a replay oracle."""

    def __init__(self, replay: Replay) -> None:
        self._replay = replay

    def minimize(self, plan: CompiledTwinPlan) -> MinimizationResult:
        original_count = len(plan.branch_a_steps) + len(plan.branch_b_steps)
        target = self._replay(plan)
        if target.verdict is VerdictKind.INVALID_TEST:
            raise MinimizationError("the original plan does not reproduce a valid verdict")

        probe_type = plan.synthesized.probe_type
        candidates = _shared_step_ids(plan)

        def reproduces(removed: frozenset[str]) -> bool:
            trial = _project(plan, removed)
            report = self._replay(trial)
            return _same_outcome(report, target, probe_type)

        removed: set[str] = set()
        active = candidates
        granularity = 2
        while len(active) >= 2:
            chunks = _split(active, granularity)
            reduced = False
            for chunk in chunks:
                trial_removed = removed | frozenset(chunk)
                if reproduces(frozenset(trial_removed)):
                    removed = trial_removed
                    active = [item for item in active if item not in chunk]
                    granularity = max(granularity - 1, 2)
                    reduced = True
                    break
            if not reduced:
                if granularity >= len(active):
                    break
                granularity = min(granularity * 2, len(active))

        for step_id in list(active):
            trial_removed = removed | {step_id}
            if reproduces(frozenset(trial_removed)):
                removed = trial_removed
                active.remove(step_id)

        minimized = _project(plan, frozenset(removed))
        final = self._replay(minimized)
        verified = _same_outcome(final, target, probe_type)
        minimized_count = len(minimized.branch_a_steps) + len(minimized.branch_b_steps)
        return MinimizationResult(
            plan=minimized,
            original_step_count=original_count,
            minimized_step_count=minimized_count,
            reduction_ratio=(
                0.0
                if original_count == 0
                else (original_count - minimized_count) / original_count
            ),
            removed_step_ids=tuple(sorted(removed)),
            verdict=final.verdict,
            subtype=final.subtype,
            reproduction_verified=verified,
        )


__all__ = ["MinimizationError", "MinimizationResult", "PairPreservingMinimizer"]
