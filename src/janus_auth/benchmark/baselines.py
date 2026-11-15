"""Baselines and ablations for the comparative benchmark.

All methods receive the same paired evidence.  The baselines deliberately omit one or more
of the four effect-witness dimensions; the full system applies the complete adjudicator.
"""

from __future__ import annotations

from janus_auth.models import (
    CompiledTwinPlan,
    PairedExecutionEvidence,
    ProbeType,
    VerdictKind,
)
from janus_auth.oracle.adjudicator import adjudicate

_FINDING_VERDICTS = frozenset(
    {
        VerdictKind.CONFIRMED_VIOLATION,
        VerdictKind.LEGITIMATE_ACCESS_REGRESSION,
    }
)


def _a_probe_status(evidence: PairedExecutionEvidence) -> int:
    probe = evidence.branch_a.probe
    return probe.status_code if probe is not None else 0


def _b_probe_status(evidence: PairedExecutionEvidence) -> int:
    probe = evidence.branch_b.probe
    return probe.status_code if probe is not None else 0


def _a_mutated(evidence: PairedExecutionEvidence) -> bool:
    witness = evidence.branch_a.effect_witness
    if witness is None or not isinstance(witness.parsed_json, dict):
        return False
    secret = witness.parsed_json.get("secret_content")
    return isinstance(secret, str) and secret.startswith("MUTATED_BY_")


class StaticCrossUserReplayBaseline:
    """AuthProbe/Autorize-style replay: any 200 after the transition is a finding."""

    name = "static_cross_user_replay"
    covers_both_branches = False

    def evaluate(
        self, plan: CompiledTwinPlan, evidence: PairedExecutionEvidence
    ) -> bool:
        return _a_probe_status(evidence) == 200

    def covers(self, evidence: PairedExecutionEvidence) -> bool:
        return evidence.branch_a.probe is not None


class UnpairedSingleBranchAblation:
    """Branch A only, with canary/effect witnesses but no surviving-grant twin."""

    name = "unpaired_single_branch"
    covers_both_branches = False

    def evaluate(
        self, plan: CompiledTwinPlan, evidence: PairedExecutionEvidence
    ) -> bool:
        if plan.synthesized.probe_type is ProbeType.PROTECTED_READ:
            return _a_probe_status(evidence) == 200
        return _a_mutated(evidence)

    def covers(self, evidence: PairedExecutionEvidence) -> bool:
        return (
            evidence.branch_a.probe is not None
            and evidence.branch_a.effect_witness is not None
        )


class StatusCodeOnlyOracleAblation:
    """Both branches, but only HTTP status codes; no canary or state witness."""

    name = "status_code_only"
    covers_both_branches = True

    def evaluate(
        self, plan: CompiledTwinPlan, evidence: PairedExecutionEvidence
    ) -> bool:
        a_status = _a_probe_status(evidence)
        b_status = _b_probe_status(evidence)
        if a_status == 200:
            return True
        return a_status in {401, 403, 404} and b_status in {401, 403, 404}

    def covers(self, evidence: PairedExecutionEvidence) -> bool:
        return (
            evidence.branch_a.probe is not None
            and evidence.branch_b.probe is not None
        )


class FullSystemMethod:
    """Z3 twin compiler plus the complete 4D adjudicator."""

    name = "janus_full_system"
    covers_both_branches = True

    def evaluate(
        self, plan: CompiledTwinPlan, evidence: PairedExecutionEvidence
    ) -> bool:
        return adjudicate(plan, evidence).verdict in _FINDING_VERDICTS

    def covers(self, evidence: PairedExecutionEvidence) -> bool:
        return (
            evidence.branch_a.valid
            and evidence.branch_b.valid
            and evidence.branch_a.effect_witness is not None
            and evidence.branch_b.effect_witness is not None
        )


__all__ = [
    "FullSystemMethod",
    "StaticCrossUserReplayBaseline",
    "StatusCodeOnlyOracleAblation",
    "UnpairedSingleBranchAblation",
]
