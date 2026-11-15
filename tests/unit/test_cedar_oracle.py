"""Unit tests for the authoritative Cedar policy oracle (Task 4).

These tests exercise the real ``cedarpy`` engine against ``configs/docvault.cedar``; the
truth table here is the reference for the Z3 synthesizer's cross-check in Task 5.
"""

from __future__ import annotations

import itertools
from pathlib import Path

import cedarpy
import pytest

from janus_auth.models import Decision, ProbeType, SupportState
from janus_auth.oracle import (
    SUPPORTED_ACTIONS,
    CedarOracle,
    map_cedar_decision,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "configs" / "docvault.cedar"

#: Deliberately incomplete policy: no permit for ``reversible_write`` at all.
INCOMPLETE_POLICY = """
permit (
    principal,
    action == Action::"protected_read",
    resource
);
"""


def make_state(
    *,
    action: ProbeType = ProbeType.PROTECTED_READ,
    principal_id: str = "bea",
    resource_id: str = "doc_1",
    active_principal: bool = True,
    same_tenant: bool = True,
    is_owner: bool = False,
    direct_grant: bool = False,
    group_grant: bool = False,
    delegated_grant: bool = False,
    parent_grant_valid: bool = False,
    admin_role: bool = False,
    explicit_deny: bool = False,
) -> SupportState:
    """Build a strict :class:`SupportState` with explicit support variables."""
    return SupportState(
        principal_id=principal_id,
        resource_id=resource_id,
        action=action,
        active_principal=active_principal,
        same_tenant=same_tenant,
        is_owner=is_owner,
        direct_grant=direct_grant,
        group_grant=group_grant,
        delegated_grant=delegated_grant,
        parent_grant_valid=parent_grant_valid,
        admin_role=admin_role,
        explicit_deny=explicit_deny,
    )


@pytest.fixture(scope="module")
def oracle() -> CedarOracle:
    return CedarOracle.from_file(POLICY_PATH)


#: ``(label, support overrides, expected decision)`` for the approved policy.
TRUTH_TABLE: list[tuple[str, dict[str, bool], Decision]] = [
    ("owner", {"is_owner": True}, Decision.ALLOW),
    ("direct_grant", {"direct_grant": True}, Decision.ALLOW),
    ("group_grant", {"group_grant": True}, Decision.ALLOW),
    (
        "valid_delegation",
        {"delegated_grant": True, "parent_grant_valid": True},
        Decision.ALLOW,
    ),
    (
        "invalid_parent_delegation",
        {"delegated_grant": True, "parent_grant_valid": False},
        Decision.DENY,
    ),
    ("admin_role", {"admin_role": True}, Decision.ALLOW),
    (
        "inactive_principal",
        {"is_owner": True, "active_principal": False},
        Decision.DENY,
    ),
    ("cross_tenant", {"is_owner": True, "same_tenant": False}, Decision.DENY),
    ("explicit_deny", {"is_owner": True, "explicit_deny": True}, Decision.DENY),
    ("no_support", {}, Decision.DENY),
]


@pytest.mark.parametrize("action", list(ProbeType), ids=[probe.value for probe in ProbeType])
@pytest.mark.parametrize(
    ("overrides", "expected"),
    [(overrides, expected) for _, overrides, expected in TRUTH_TABLE],
    ids=[label for label, _, _ in TRUTH_TABLE],
)
def test_truth_table(
    oracle: CedarOracle,
    action: ProbeType,
    overrides: dict[str, bool],
    expected: Decision,
) -> None:
    state = make_state(action=action, **overrides)
    assert oracle.evaluate(state) is expected


@pytest.mark.parametrize(
    "denial",
    [
        {"active_principal": False},
        {"same_tenant": False},
        {"explicit_deny": True},
    ],
    ids=["inactive", "cross_tenant", "explicit_deny"],
)
def test_forbid_overrides_every_support_path(
    oracle: CedarOracle, denial: dict[str, bool]
) -> None:
    state = make_state(
        is_owner=True,
        direct_grant=True,
        group_grant=True,
        delegated_grant=True,
        parent_grant_valid=True,
        admin_role=True,
        **denial,
    )
    for action in ProbeType:
        assert oracle.evaluate_action(state, action.value) is Decision.DENY


@pytest.mark.parametrize("action", list(ProbeType), ids=[probe.value for probe in ProbeType])
def test_delegation_requires_a_valid_parent_grant(
    oracle: CedarOracle, action: ProbeType
) -> None:
    valid_parent = make_state(
        action=action, delegated_grant=True, parent_grant_valid=True
    )
    invalid_parent = make_state(
        action=action, delegated_grant=True, parent_grant_valid=False
    )
    assert oracle.evaluate(valid_parent) is Decision.ALLOW
    assert oracle.evaluate(invalid_parent) is Decision.DENY


def test_evaluate_all_preserves_order(oracle: CedarOracle) -> None:
    states = [
        make_state(is_owner=True),
        make_state(),
        make_state(group_grant=True),
        make_state(active_principal=False, is_owner=True),
    ]
    expected = [Decision.ALLOW, Decision.DENY, Decision.ALLOW, Decision.DENY]

    assert oracle.evaluate_all(states) == expected
    assert oracle.evaluate_all(iter(states)) == expected
    assert oracle.evaluate_all(state for state in states) == expected


@pytest.mark.parametrize(
    "action_name",
    ["delete_document", "admin_read", "PROTECTED_READ", "protected_read ", ""],
)
def test_unsupported_action_returns_unknown(
    oracle: CedarOracle, action_name: str
) -> None:
    state = make_state(is_owner=True)
    assert oracle.evaluate_action(state, action_name) is Decision.UNKNOWN


def test_supported_actions_match_probe_types() -> None:
    assert SUPPORTED_ACTIONS == {probe.value for probe in ProbeType}


def test_supported_actions_never_return_unknown(oracle: CedarOracle) -> None:
    support_flags = [
        "active_principal",
        "same_tenant",
        "is_owner",
        "direct_grant",
        "group_grant",
        "delegated_grant",
        "parent_grant_valid",
        "admin_role",
        "explicit_deny",
    ]
    for combination in itertools.product([False, True], repeat=len(support_flags)):
        overrides = dict(zip(support_flags, combination, strict=True))
        for action in ProbeType:
            decision = oracle.evaluate(make_state(action=action, **overrides))
            assert decision is not Decision.UNKNOWN


def test_missing_permit_for_supported_action_returns_deny() -> None:
    incomplete = CedarOracle(INCOMPLETE_POLICY)

    assert incomplete.evaluate(make_state(is_owner=True)) is Decision.ALLOW
    assert (
        incomplete.evaluate(
            make_state(action=ProbeType.REVERSIBLE_WRITE, is_owner=True)
        )
        is Decision.DENY
    )


def test_from_file_matches_inline_policy_and_truth_table() -> None:
    from_file = CedarOracle.from_file(POLICY_PATH)
    inline = CedarOracle(POLICY_PATH.read_text(encoding="utf-8"))

    states = [
        make_state(action=action, **overrides)
        for action in ProbeType
        for _, overrides, _ in TRUTH_TABLE
    ]
    expected = [
        expected for _ in ProbeType for _, _, expected in TRUTH_TABLE
    ]

    assert from_file.evaluate_all(states) == inline.evaluate_all(states)
    assert from_file.evaluate_all(states) == expected


def test_from_file_accepts_a_string_path() -> None:
    oracle = CedarOracle.from_file(str(POLICY_PATH))
    assert oracle.evaluate(make_state(is_owner=True)) is Decision.ALLOW


def test_map_cedar_decision_translates_allow_and_deny() -> None:
    assert map_cedar_decision(cedarpy.Decision.Allow) is Decision.ALLOW
    assert map_cedar_decision(cedarpy.Decision.Deny) is Decision.DENY


def test_map_cedar_decision_rejects_unexpected_decision() -> None:
    with pytest.raises(ValueError, match="unsupported decision"):
        map_cedar_decision(cedarpy.Decision.NoDecision)
