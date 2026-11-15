"""SARIF 2.1.0 export for confirmed counterfactual findings."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final

from janus_auth.models import (
    AdjudicationReport,
    BranchSummary,
    CompiledTwinPlan,
    VerdictKind,
    ViolationSubtype,
)

SARIF_SCHEMA: Final[str] = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION: Final[str] = "2.1.0"
TOOL_NAME: Final[str] = "janus-auth"
TOOL_VERSION: Final[str] = "0.1.0"

_RULE_BY_SUBTYPE: Final[dict[ViolationSubtype, str]] = {
    ViolationSubtype.BOLA_READ_LEAK: "JANUS001",
    ViolationSubtype.SILENT_WRITE_SIDE_EFFECT: "JANUS002",
    ViolationSubtype.STALE_GROUP_CACHE: "JANUS003",
    ViolationSubtype.FORMER_OWNER_RETENTION: "JANUS004",
    ViolationSubtype.BROKEN_DELEGATION_CASCADE: "JANUS005",
    ViolationSubtype.OVER_REVOCATION_REGRESSION: "JANUS006",
    ViolationSubtype.INVERTED_ENFORCEMENT: "JANUS001",
}

_RULES: Final[list[dict[str, Any]]] = [
    {
        "id": "JANUS001",
        "name": "BolaReadLeak",
        "shortDescription": {"text": "Protected canary leaked after a revoked grant"},
        "help": {"text": "Branch A returned the protected canary when DENY was expected."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "JANUS002",
        "name": "SilentWriteSideEffect",
        "shortDescription": {"text": "Unauthorized write mutated protected state"},
        "help": {"text": "The post-probe owner witness shows MUTATED_BY_<principal>."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "JANUS003",
        "name": "StaleGroupCache",
        "shortDescription": {"text": "Revoked group membership still authorizes access"},
        "help": {"text": "A pending-removal member retained group-derived access."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "JANUS004",
        "name": "FormerOwnerRetention",
        "shortDescription": {"text": "Former owner retained access after transfer"},
        "help": {"text": "The legacy-owner allowlist survived ownership transfer."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "JANUS005",
        "name": "BrokenDelegationCascade",
        "shortDescription": {"text": "Delegation survived revocation of the parent grant"},
        "help": {"text": "The delegator's revoked authority no longer backs the delegation."},
        "defaultConfiguration": {"level": "error"},
    },
    {
        "id": "JANUS006",
        "name": "OverRevocationRegression",
        "shortDescription": {"text": "Surviving grant was destroyed by a broad revocation"},
        "help": {"text": "Branch B's surviving-grant control was rejected."},
        "defaultConfiguration": {"level": "error"},
    },
]

_FINDING_VERDICTS: Final[frozenset[VerdictKind]] = frozenset(
    {
        VerdictKind.CONFIRMED_VIOLATION,
        VerdictKind.LEGITIMATE_ACCESS_REGRESSION,
    }
)


def _summary_text(summary: BranchSummary | None) -> str:
    if summary is None:
        return "branch summary unavailable"
    return (
        f"status={summary.probe_status_code} canary={summary.canary_present} "
        f"access={summary.access_allowed} state_mutated={summary.state_mutated}"
    )


def _rule_id(subtype: ViolationSubtype) -> str:
    return _RULE_BY_SUBTYPE.get(subtype, "JANUS001")


def build_sarif(
    findings: Sequence[tuple[CompiledTwinPlan, AdjudicationReport]],
    *,
    policy_uri: str = "configs/docvault.cedar",
    manifest_uri: str = "configs/docvault_manifest.yaml",
) -> dict[str, Any]:
    """Return a SARIF 2.1.0 document for confirmed findings only."""
    results: list[dict[str, Any]] = []
    for plan, report in findings:
        if report.verdict not in _FINDING_VERDICTS:
            continue
        rule_id = _rule_id(report.subtype)
        message = (
            f"{report.verdict.value} ({report.subtype.value}) for plan {plan.plan_id}. "
            f"Branch A: {_summary_text(report.branch_a_summary)}. "
            f"Branch B: {_summary_text(report.branch_b_summary)}."
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": "error",
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": policy_uri},
                            "region": {"startLine": 1},
                        }
                    },
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": manifest_uri},
                            "region": {"startLine": 1},
                        }
                    },
                ],
                "properties": {
                    "plan_id": plan.plan_id,
                    "mode": report.evidence.get("mode", ""),
                    "transition_family": plan.synthesized.transition_family.value,
                    "probe_type": plan.synthesized.probe_type.value,
                    "verdict": report.verdict.value,
                    "subtype": report.subtype.value,
                },
            }
        )
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/janus-auth/janus-auth",
                        "rules": _RULES,
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(path: str | Path, sarif: dict[str, Any]) -> Path:
    """Write a SARIF document with deterministic JSON formatting."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(sarif, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


__all__ = ["SARIF_SCHEMA", "SARIF_VERSION", "TOOL_NAME", "build_sarif", "write_sarif"]
