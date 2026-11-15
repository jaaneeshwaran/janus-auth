"""Comparative benchmark and ablation evaluator.

The evaluator executes one representative plan per lifecycle mode, adjudicates the shared
paired evidence with the full system, and lets every baseline decide from the same evidence.
Metrics are computed from observations, never hardcoded.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean
from typing import Any, Final, Protocol

from fastapi import FastAPI
from fastapi.testclient import TestClient

from janus_auth.benchmark.baselines import (
    FullSystemMethod,
    StaticCrossUserReplayBaseline,
    StatusCodeOnlyOracleAblation,
    UnpairedSingleBranchAblation,
)
from janus_auth.models import (
    CompiledTwinPlan,
    PairedExecutionEvidence,
    ProbeType,
    ScopeManifest,
    TransitionFamily,
)
from janus_auth.runner import CounterfactualExecutor
from janus_auth.security.gatekeeper import SafetyGatekeeper
from janus_auth.targets.docvault_app import create_app

_CONTROL_CATEGORIES: Final[frozenset[str]] = frozenset(
    {"control_surviving_grant", "control_masked_200"}
)


class BaselineMethod(Protocol):
    """Structural contract shared by baselines and the full system."""

    name: str
    covers_both_branches: bool

    def evaluate(
        self, plan: CompiledTwinPlan, evidence: PairedExecutionEvidence
    ) -> bool: ...


class BenchmarkBudgetError(RuntimeError):
    """Raised when evidence collection exceeds the declared request budget."""


@dataclass(frozen=True, slots=True)
class CaseSpec:
    case_id: str
    mode: str
    family: TransitionFamily
    probe: ProbeType
    category: str
    expected_detection: bool
    masked: bool = False
    suffix: str | None = None


_CASES: Final[tuple[CaseSpec, ...]] = (
    CaseSpec(
        "clean-surviving-grant-read",
        "clean",
        TransitionFamily.DIRECT_SHARE_REVOKE,
        ProbeType.PROTECTED_READ,
        "control_surviving_grant",
        False,
    ),
    CaseSpec(
        "clean-surviving-grant-write",
        "clean",
        TransitionFamily.DIRECT_SHARE_REVOKE,
        ProbeType.REVERSIBLE_WRITE,
        "control_surviving_grant",
        False,
    ),
    CaseSpec(
        "clean-masked-200",
        "clean",
        TransitionFamily.DIRECT_SHARE_REVOKE,
        ProbeType.PROTECTED_READ,
        "control_masked_200",
        False,
        masked=True,
    ),
    CaseSpec(
        "defect-stale-direct-cache",
        "vuln_stale_direct_cache",
        TransitionFamily.DIRECT_SHARE_REVOKE,
        ProbeType.PROTECTED_READ,
        "defect_stale_direct_cache",
        True,
    ),
    CaseSpec(
        "defect-group-revocation",
        "vuln_group_revocation_ignored",
        TransitionFamily.GROUP_MEMBER_REMOVE,
        ProbeType.PROTECTED_READ,
        "defect_group_revocation",
        True,
    ),
    CaseSpec(
        "defect-transfer-retains-owner",
        "vuln_transfer_retains_owner",
        TransitionFamily.OWNERSHIP_TRANSFER,
        ProbeType.PROTECTED_READ,
        "defect_transfer_retains_owner",
        True,
    ),
    CaseSpec(
        "defect-broken-cascade",
        "vuln_broken_delegation_cascade",
        TransitionFamily.DELEGATION_REVOKE,
        ProbeType.PROTECTED_READ,
        "defect_broken_cascade",
        True,
        suffix="-cascade",
    ),
    CaseSpec(
        "defect-silent-write",
        "vuln_silent_write_on_403",
        TransitionFamily.DIRECT_SHARE_REVOKE,
        ProbeType.REVERSIBLE_WRITE,
        "defect_silent_write",
        True,
    ),
    CaseSpec(
        "defect-over-revocation",
        "vuln_over_revocation_regression",
        TransitionFamily.DIRECT_SHARE_REVOKE,
        ProbeType.PROTECTED_READ,
        "defect_over_revocation",
        True,
    ),
)


@dataclass(frozen=True, slots=True)
class CaseResult:
    case_id: str
    mode: str
    plan_id: str
    category: str
    expected_detection: bool
    detections: dict[str, bool]
    branch_a_steps: int
    branch_b_steps: int

    def witness_length(self, method: str, covers_both: bool) -> int:
        return self.branch_a_steps + (self.branch_b_steps if covers_both else 0)


@dataclass(frozen=True, slots=True)
class MethodMetrics:
    method: str
    known_defect_recall: float
    false_positive_rate_on_controls: float
    silent_write_detection_rate: float
    access_regression_detection_rate: float
    decision_coverage: float
    selective_error: float
    average_witness_length: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "known_defect_recall": self.known_defect_recall,
            "false_positive_rate_on_controls": self.false_positive_rate_on_controls,
            "silent_write_detection_rate": self.silent_write_detection_rate,
            "access_regression_detection_rate": self.access_regression_detection_rate,
            "decision_coverage": self.decision_coverage,
            "selective_error": self.selective_error,
            "average_witness_length": self.average_witness_length,
        }


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    cases: tuple[CaseResult, ...]
    methods: dict[str, MethodMetrics]
    budget: int
    requests_used: int

    def to_json(self) -> dict[str, Any]:
        return {
            "budget": self.budget,
            "requests_used": self.requests_used,
            "cases": [
                {
                    "case_id": case.case_id,
                    "mode": case.mode,
                    "plan_id": case.plan_id,
                    "category": case.category,
                    "expected_detection": case.expected_detection,
                    "detections": case.detections,
                    "branch_a_steps": case.branch_a_steps,
                    "branch_b_steps": case.branch_b_steps,
                }
                for case in self.cases
            ],
            "methods": {
                name: metrics.as_dict() for name, metrics in self.methods.items()
            },
        }

    def to_markdown(self) -> str:
        lines = [
            "# Janus-Auth Comparative Benchmark",
            "",
            f"Request budget: {self.budget}; requests used: {self.requests_used}",
            "",
            "| Method | Defect recall | FP on controls | Silent-write detection | "
            "Access-regression detection | Coverage | Selective error | Avg witness steps |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for metrics in self.methods.values():
            lines.append(
                f"| {metrics.method} | "
                f"{metrics.known_defect_recall:.2f} | "
                f"{metrics.false_positive_rate_on_controls:.2f} | "
                f"{metrics.silent_write_detection_rate:.2f} | "
                f"{metrics.access_regression_detection_rate:.2f} | "
                f"{metrics.decision_coverage:.2f} | "
                f"{metrics.selective_error:.2f} | "
                f"{metrics.average_witness_length:.1f} |"
            )
        return "\n".join(lines) + "\n"

    def write(self, out_dir: str | Path) -> tuple[Path, Path]:
        directory = Path(out_dir)
        directory.mkdir(parents=True, exist_ok=True)
        json_path = directory / "benchmark_report.json"
        markdown_path = directory / "benchmark_report.md"
        json_path.write_text(
            json.dumps(self.to_json(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        markdown_path.write_text(self.to_markdown(), encoding="utf-8")
        return json_path, markdown_path


class BenchmarkEvaluator:
    """Run the four methods over the fixed case matrix."""

    def __init__(
        self,
        plans: Sequence[CompiledTwinPlan],
        manifest: ScopeManifest,
        *,
        signing_secret: str,
        budget: int = 300,
        app_factory: Callable[[], FastAPI] = create_app,
    ) -> None:
        if budget <= 0:
            raise ValueError("budget must be a positive integer")
        self._plans = list(plans)
        self._manifest = manifest
        self._signing_secret = signing_secret
        self._budget = budget
        self._app_factory = app_factory
        self._methods = (
            StaticCrossUserReplayBaseline(),
            UnpairedSingleBranchAblation(),
            StatusCodeOnlyOracleAblation(),
            FullSystemMethod(),
        )

    def _select(self, spec: CaseSpec) -> CompiledTwinPlan:
        for plan in self._plans:
            if plan.synthesized.transition_family is not spec.family:
                continue
            if plan.synthesized.probe_type is not spec.probe:
                continue
            if plan.masked_control is not spec.masked:
                continue
            if spec.suffix is not None and not plan.plan_id.endswith(spec.suffix):
                continue
            if spec.suffix is None and plan.plan_id.endswith("-cascade"):
                continue
            return plan
        raise LookupError(f"no compiled plan matches {spec.case_id}")

    def run_full_evaluation(self) -> BenchmarkReport:
        results: list[CaseResult] = []
        requests_used = 0
        app = self._app_factory()
        with TestClient(app, follow_redirects=False) as client:
            for spec in _CASES:
                plan = self._select(spec)
                gatekeeper = SafetyGatekeeper(
                    self._manifest, secret=self._signing_secret
                )
                executor = CounterfactualExecutor(
                    client, gatekeeper, mode=spec.mode
                )
                evidence = executor.execute(plan)
                requests_used += gatekeeper.requests_used
                if requests_used > self._budget:
                    raise BenchmarkBudgetError(
                        f"benchmark exceeded its {self._budget}-request budget"
                    )
                results.append(
                    CaseResult(
                        case_id=spec.case_id,
                        mode=spec.mode,
                        plan_id=plan.plan_id,
                        category=spec.category,
                        expected_detection=spec.expected_detection,
                        detections={
                            method.name: method.evaluate(plan, evidence)
                            for method in self._methods
                        },
                        branch_a_steps=len(evidence.branch_a.steps),
                        branch_b_steps=len(evidence.branch_b.steps),
                    )
                )

        cases = tuple(results)
        metrics = {
            method.name: self._metrics(method, cases)
            for method in self._methods
        }
        return BenchmarkReport(
            cases=cases,
            methods=metrics,
            budget=self._budget,
            requests_used=requests_used,
        )

    def _metrics(
        self, method: BaselineMethod, cases: tuple[CaseResult, ...]
    ) -> MethodMetrics:
        defect_cases = [case for case in cases if case.category.startswith("defect_")]
        control_cases = [case for case in cases if case.category in _CONTROL_CATEGORIES]
        detected_defects = sum(
            1 for case in defect_cases if case.detections[method.name]
        )
        false_positives = sum(
            1 for case in control_cases if case.detections[method.name]
        )
        silent = next(
            case for case in cases if case.category == "defect_silent_write"
        )
        regression = next(
            case for case in cases if case.category == "defect_over_revocation"
        )
        errors = sum(
            1
            for case in cases
            if case.detections[method.name] != case.expected_detection
        )
        return MethodMetrics(
            method=method.name,
            known_defect_recall=detected_defects / len(defect_cases),
            false_positive_rate_on_controls=false_positives / len(control_cases),
            silent_write_detection_rate=float(silent.detections[method.name]),
            access_regression_detection_rate=float(
                regression.detections[method.name]
            ),
            decision_coverage=1.0 if method.covers_both_branches else 0.5,
            selective_error=errors / len(cases),
            average_witness_length=fmean(
                case.witness_length(method.name, method.covers_both_branches)
                for case in cases
            ),
        )


__all__ = [
    "BenchmarkBudgetError",
    "BenchmarkEvaluator",
    "BenchmarkReport",
    "CaseResult",
    "MethodMetrics",
]
