"""Unit tests for the Z3 minimum-Hamming-distance synthesizer (Task 5).

The synthesizer is exercised against the real ``z3-solver`` and the real
``cedarpy``-backed :class:`~janus_auth.oracle.CedarOracle`.  Only the deliberate
divergence test replaces an oracle method, and it replaces the *authoritative*
evaluation rather than Z3.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from janus_auth.compiler import (
    InfeasibleObligation,
    PolicyEncodingDivergenceError,
    SynthesisReport,
    Z3Synthesizer,
)
from janus_auth.models import (
    CounterfactualPairPlan,
    Decision,
    PrincipalClass,
    ProbeType,
    SupportState,
    TransitionFamily,
)
from janus_auth.oracle import CedarOracle

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = REPO_ROOT / "configs" / "docvault.cedar"

SUPPORT_NAMES = ("owner", "direct", "group", "delegation", "admin")

#: Regression pin: the only cells the binding encoding can satisfy.
EXPECTED_FEASIBLE: set[tuple[TransitionFamily, PrincipalClass, ProbeType]] = (
    {
        (family, principal_class, probe_type)
        for family in (
            TransitionFamily.DIRECT_SHARE_REVOKE,
            TransitionFamily.GROUP_MEMBER_REMOVE,
        )
        for principal_class in (PrincipalClass.SAME_TENANT_PEER,)
        for probe_type in ProbeType
    }
    | {
        (TransitionFamily.DELEGATION_REVOKE, PrincipalClass.DELEGATE_OR_ADMIN, probe)
        for probe in ProbeType
    }
    | {
        (TransitionFamily.ROLE_DOWNGRADE, PrincipalClass.DELEGATE_OR_ADMIN, probe)
        for probe in ProbeType
    }
    | {
        (TransitionFamily.OWNERSHIP_TRANSFER, PrincipalClass.FORMER_OWNER, probe)
        for probe in ProbeType
    }
)

#: Regression pin for the deterministic objective tie-break.
EXPECTED_SURVIVING_SUPPORT: dict[tuple[TransitionFamily, PrincipalClass], str] = {
    (
        TransitionFamily.DIRECT_SHARE_REVOKE,
        PrincipalClass.SAME_TENANT_PEER,
    ): "group",
    (
        TransitionFamily.GROUP_MEMBER_REMOVE,
        PrincipalClass.SAME_TENANT_PEER,
    ): "direct",
    (
        TransitionFamily.DELEGATION_REVOKE,
        PrincipalClass.DELEGATE_OR_ADMIN,
    ): "admin",
    (
        TransitionFamily.ROLE_DOWNGRADE,
        PrincipalClass.DELEGATE_OR_ADMIN,
    ): "delegation",
    (
        TransitionFamily.OWNERSHIP_TRANSFER,
        PrincipalClass.FORMER_OWNER,
    ): "admin",
}

ALL_CELLS: list[tuple[TransitionFamily, PrincipalClass, ProbeType]] = [
    (family, principal_class, probe_type)
    for family in TransitionFamily
    for principal_class in PrincipalClass
    for probe_type in ProbeType
]


@pytest.fixture(scope="module")
def oracle() -> CedarOracle:
    return CedarOracle.from_file(POLICY_PATH)


@pytest.fixture(scope="module")
def synthesizer(oracle: CedarOracle) -> Z3Synthesizer:
    return Z3Synthesizer(oracle)


@pytest.fixture(scope="module")
def report(synthesizer: Z3Synthesizer) -> SynthesisReport:
    return synthesizer.synthesize_all()


def support_set(state: SupportState) -> set[str]:
    """Return the active support predicates of a concrete state."""
    active = {
        "owner": state.is_owner,
        "direct": state.direct_grant,
        "group": state.group_grant,
        "delegation": state.delegated_grant and state.parent_grant_valid,
        "admin": state.admin_role,
    }
    return {name for name, enabled in active.items() if enabled}


def cell_of_pair(
    pair: CounterfactualPairPlan,
) -> tuple[TransitionFamily, PrincipalClass, ProbeType]:
    """Return the typed grid coordinates of a plan."""
    return (
        pair.transition_family,
        PrincipalClass(pair.principal_role_class),
        pair.probe_type,
    )


def cell_of_infeasible(
    obligation: InfeasibleObligation,
) -> tuple[TransitionFamily, PrincipalClass, ProbeType]:
    """Return the typed grid coordinates of an infeasibility record."""
    return (
        obligation.transition_family,
        PrincipalClass(obligation.principal_role_class),
        obligation.probe_type,
    )


def test_all_48_obligations_are_reported_exactly_once(
    report: SynthesisReport,
) -> None:
    assert len(report.pairs) == 10
    assert len(report.infeasible) == 38

    pair_cells = [cell_of_pair(pair) for pair in report.pairs]
    infeasible_cells = [cell_of_infeasible(item) for item in report.infeasible]
    reported_cells = pair_cells + infeasible_cells

    assert len(reported_cells) == 48
    assert len(set(reported_cells)) == 48
    assert set(reported_cells) == set(ALL_CELLS)

    expected_pair_order = [cell for cell in ALL_CELLS if cell in EXPECTED_FEASIBLE]
    expected_infeasible_order = [cell for cell in ALL_CELLS if cell not in EXPECTED_FEASIBLE]
    assert pair_cells == expected_pair_order
    assert infeasible_cells == expected_infeasible_order

    assert all(item.reason.strip() for item in report.infeasible)


def test_expected_feasible_cells_are_pinned(report: SynthesisReport) -> None:
    pair_cells = {cell_of_pair(pair) for pair in report.pairs}
    infeasible_cells = {cell_of_infeasible(item) for item in report.infeasible}

    assert pair_cells == EXPECTED_FEASIBLE
    assert infeasible_cells == set(ALL_CELLS) - EXPECTED_FEASIBLE
    assert pair_cells.isdisjoint(infeasible_cells)

    for pair in report.pairs:
        key = (pair.transition_family, PrincipalClass(pair.principal_role_class))
        assert pair.surviving_support_name == EXPECTED_SURVIVING_SUPPORT[key]


def test_every_feasible_pair_has_the_required_shape(
    report: SynthesisReport,
) -> None:
    for pair in report.pairs:
        expected_cell = (
            pair.transition_family,
            PrincipalClass(pair.principal_role_class),
            pair.probe_type,
        )
        assert cell_of_pair(pair) == expected_cell
        assert pair.plan_id == (
            f"ct-{pair.transition_family.value}-{pair.principal_role_class}-{pair.probe_type.value}"
        )
        assert pair.plan_id.isascii()
        assert " " not in pair.plan_id

        assert pair.branch_a_expected is Decision.DENY
        assert pair.branch_b_expected is Decision.ALLOW
        assert pair.hamming_distance == 1
        assert pair.consistency_bound_ms == 0

        a_supports = support_set(pair.branch_a_pre)
        b_supports = support_set(pair.branch_b_pre)
        assert len(a_supports) == 1
        assert a_supports < b_supports
        assert b_supports - a_supports == {pair.surviving_support_name}
        assert pair.surviving_support_name in SUPPORT_NAMES
        assert len(a_supports ^ b_supports) == pair.hamming_distance

        expected_principal = (
            "ada"
            if PrincipalClass(pair.principal_role_class) is PrincipalClass.FORMER_OWNER
            else "bea"
        )
        for state in (
            pair.branch_a_pre,
            pair.branch_a_post,
            pair.branch_b_pre,
            pair.branch_b_post,
        ):
            assert state.principal_id == expected_principal
            assert state.resource_id == "doc_101"
            assert state.action is pair.probe_type

        for pre_state in (pair.branch_a_pre, pair.branch_b_pre):
            assert pre_state.active_principal is True
            assert pre_state.explicit_deny is False
            assert pre_state.is_owner is (
                PrincipalClass(pair.principal_role_class) is PrincipalClass.FORMER_OWNER
            )


def test_every_feasible_pair_passes_the_cedar_cross_check(
    report: SynthesisReport, oracle: CedarOracle
) -> None:
    for pair in report.pairs:
        decisions = oracle.evaluate_all(
            [
                pair.branch_a_pre,
                pair.branch_a_post,
                pair.branch_b_pre,
                pair.branch_b_post,
            ]
        )
        assert decisions == [
            Decision.ALLOW,
            Decision.DENY,
            Decision.ALLOW,
            Decision.ALLOW,
        ]


def test_transition_transformers_clear_exactly_the_family_fields(
    report: SynthesisReport,
) -> None:
    cleared_by_family: dict[TransitionFamily, set[str]] = {
        TransitionFamily.DIRECT_SHARE_REVOKE: {"direct_grant"},
        TransitionFamily.GROUP_MEMBER_REMOVE: {"group_grant"},
        TransitionFamily.DELEGATION_REVOKE: {
            "delegated_grant",
            "parent_grant_valid",
        },
        TransitionFamily.ROLE_DOWNGRADE: {"admin_role"},
        TransitionFamily.OWNERSHIP_TRANSFER: {"is_owner", "direct_grant"},
        TransitionFamily.TENANT_CHANGE: {"same_tenant"},
    }
    bool_fields = (
        "active_principal",
        "same_tenant",
        "is_owner",
        "direct_grant",
        "group_grant",
        "delegated_grant",
        "parent_grant_valid",
        "admin_role",
        "explicit_deny",
    )

    for pair in report.pairs:
        cleared = cleared_by_family[pair.transition_family]
        for pre_state, post_state in (
            (pair.branch_a_pre, pair.branch_a_post),
            (pair.branch_b_pre, pair.branch_b_post),
        ):
            for field in bool_fields:
                post_value = getattr(post_state, field)
                if field in cleared:
                    assert post_value is False
                else:
                    assert post_value is getattr(pre_state, field)


@pytest.mark.parametrize(
    ("family", "principal_class", "expected_reason"),
    [
        (
            TransitionFamily.DIRECT_SHARE_REVOKE,
            PrincipalClass.CROSS_TENANT_PRINCIPAL,
            "cross-tenant pre-state cannot satisfy policy",
        ),
        (
            TransitionFamily.TENANT_CHANGE,
            PrincipalClass.SAME_TENANT_PEER,
            "tenant boundary makes post-ALLOW impossible",
        ),
        (
            TransitionFamily.DIRECT_SHARE_REVOKE,
            PrincipalClass.FORMER_OWNER,
            "owner support survives the transition",
        ),
        (
            TransitionFamily.DELEGATION_REVOKE,
            PrincipalClass.SAME_TENANT_PEER,
            "targeted support contradicts principal class",
        ),
    ],
)
def test_infeasible_reasons_are_specific_and_deterministic(
    report: SynthesisReport,
    family: TransitionFamily,
    principal_class: PrincipalClass,
    expected_reason: str,
) -> None:
    matching = [
        item
        for item in report.infeasible
        if item.transition_family is family
        and PrincipalClass(item.principal_role_class) is principal_class
    ]
    assert len(matching) == len(ProbeType)
    assert {item.reason for item in matching} == {expected_reason}


def test_synthesize_all_is_deterministic(synthesizer: Z3Synthesizer) -> None:
    first = synthesizer.synthesize_all().model_dump(mode="json")
    second = synthesizer.synthesize_all().model_dump(mode="json")

    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_synthesize_returns_none_for_infeasible_without_duplicating(
    synthesizer: Z3Synthesizer,
) -> None:
    result = synthesizer.synthesize(
        TransitionFamily.TENANT_CHANGE,
        PrincipalClass.DELEGATE_OR_ADMIN,
        ProbeType.PROTECTED_READ,
    )
    assert result is None

    report = synthesizer.synthesize_all()
    assert len(report.infeasible) == 38
    cells = [cell_of_infeasible(item) for item in report.infeasible]
    assert len(cells) == len(set(cells)) == 38


def test_synthesize_returns_a_pair_for_a_feasible_cell(
    synthesizer: Z3Synthesizer,
) -> None:
    pair = synthesizer.synthesize(
        TransitionFamily.DIRECT_SHARE_REVOKE,
        PrincipalClass.SAME_TENANT_PEER,
        ProbeType.REVERSIBLE_WRITE,
    )
    assert pair is not None
    assert pair.plan_id == ("ct-direct_share_revoke-same_tenant_peer-reversible_write")
    assert pair.hamming_distance == 1


def test_broken_cross_check_raises_policy_encoding_divergence(
    oracle: CedarOracle, monkeypatch: pytest.MonkeyPatch
) -> None:
    unexpected = [
        Decision.ALLOW,
        Decision.ALLOW,
        Decision.ALLOW,
        Decision.ALLOW,
    ]
    monkeypatch.setattr(
        oracle,
        "evaluate_all",
        lambda states: list(unexpected),
    )
    synthesizer = Z3Synthesizer(oracle)

    with pytest.raises(PolicyEncodingDivergenceError) as excinfo:
        synthesizer.synthesize(
            TransitionFamily.DIRECT_SHARE_REVOKE,
            PrincipalClass.SAME_TENANT_PEER,
            ProbeType.PROTECTED_READ,
        )

    error = excinfo.value
    assert error.plan_id == ("ct-direct_share_revoke-same_tenant_peer-protected_read")
    assert error.decisions == tuple(unexpected)
    assert error.plan_id in str(error)
    assert "ALLOW" in str(error)
    assert "DENY" in str(error)


def test_full_synthesis_completes_under_two_seconds(
    synthesizer: Z3Synthesizer,
) -> None:
    started = time.perf_counter()
    report = synthesizer.synthesize_all()
    elapsed = time.perf_counter() - started

    assert len(report.pairs) == 10
    assert len(report.infeasible) == 38
    assert elapsed < 2.0
