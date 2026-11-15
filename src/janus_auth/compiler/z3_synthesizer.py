"""Z3 minimum-Hamming-distance counterfactual twin synthesis.

The synthesizer encodes the five DocVault support paths from
``PROJECT_SPEC.md`` section 9.3.1 as boolean formulas over two symbolic
pre-transition states, ``A_pre`` (last-grant branch) and ``B_pre``
(surviving-grant branch), and their deterministic post-transition images.

Support predicates
------------------
``owner = is_owner``, ``direct = direct_grant``, ``group = group_grant``,
``delegation = delegated_grant AND parent_grant_valid``, and
``admin = admin_role``.  Policy evaluation is::

    ALLOW(s) = active_principal AND same_tenant AND NOT explicit_deny
               AND (owner OR direct OR group OR delegation OR admin)

which mirrors ``configs/docvault.cedar`` exactly.  The support-level Hamming
distance (R3) is measured over those five predicates, never over raw booleans.

Transition transformers
-----------------------
Each family clears the support variables named in :data:`_TRANSITION_CLEARS`
and leaves every other boolean unchanged.  ``ownership_transfer`` also clears
``direct_grant`` so the old owner's concrete direct share cannot survive the
transfer (the transfer uses ``retain_old_owner_direct_share=false``).

Determinism
-----------
Every cell is solved by a fresh ``z3.Optimize`` instance with a fixed timeout.
Objectives are added in the binding order: (1) support distance, (2) the number
of true supports in ``A_pre``, (3) the weighted ``A_pre`` support vector, and
(4) the weighted ``B_pre`` support vector (R10).  A final fixed lexicographic
tie-break minimizes the raw pre-state boolean vectors themselves, which removes
Z3 model-completion freedom for flags such as ``parent_grant_valid`` when
``delegated_grant`` is false.  Enumeration follows the enum declaration order,
so two runs produce identical reports.

Every satisfiable model is cross-checked against the authoritative
:class:`~janus_auth.oracle.CedarOracle`; any disagreement raises
:class:`PolicyEncodingDivergenceError` rather than returning a guessed pair.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

import z3

from janus_auth.config import DEFAULT_Z3_TIMEOUT_MS
from janus_auth.models import (
    CounterfactualPairPlan,
    Decision,
    PrincipalClass,
    ProbeType,
    StrictModel,
    SupportState,
    TransitionFamily,
)
from janus_auth.oracle import CedarOracle

#: Support predicates in the order used for distance and tie-break sums.
_SUPPORT_NAMES: Final[tuple[str, ...]] = (
    "owner",
    "direct",
    "group",
    "delegation",
    "admin",
)

#: Fixed lexicographic weights from the binding synthesis ruling.
_SUPPORT_WEIGHTS: Final[dict[str, int]] = {
    "owner": 16,
    "direct": 8,
    "group": 4,
    "delegation": 2,
    "admin": 1,
}

#: Raw boolean fields carried by :class:`~janus_auth.models.SupportState`.
_BOOL_FIELDS: Final[tuple[str, ...]] = (
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

#: Binary weights that make the final raw-variable minimization lexicographic.
_RAW_FIELD_WEIGHTS: Final[dict[str, int]] = {
    field: 1 << (len(_BOOL_FIELDS) - index - 1) for index, field in enumerate(_BOOL_FIELDS)
}

#: Raw fields cleared by each transition family.
_TRANSITION_CLEARS: Final[dict[TransitionFamily, tuple[str, ...]]] = {
    TransitionFamily.DIRECT_SHARE_REVOKE: ("direct_grant",),
    TransitionFamily.GROUP_MEMBER_REMOVE: ("group_grant",),
    TransitionFamily.DELEGATION_REVOKE: ("delegated_grant", "parent_grant_valid"),
    TransitionFamily.ROLE_DOWNGRADE: ("admin_role",),
    TransitionFamily.OWNERSHIP_TRANSFER: ("is_owner", "direct_grant"),
    TransitionFamily.TENANT_CHANGE: ("same_tenant",),
}

#: Support path targeted by each family.  ``tenant_change`` targets no grant.
_TARGET_SUPPORT: Final[dict[TransitionFamily, str | None]] = {
    TransitionFamily.DIRECT_SHARE_REVOKE: "direct",
    TransitionFamily.GROUP_MEMBER_REMOVE: "group",
    TransitionFamily.DELEGATION_REVOKE: "delegation",
    TransitionFamily.ROLE_DOWNGRADE: "admin",
    TransitionFamily.OWNERSHIP_TRANSFER: "owner",
    TransitionFamily.TENANT_CHANGE: None,
}

#: Required Cedar decisions for ``[A_pre, A_post, B_pre, B_post]``.
_EXPECTED_DECISIONS: Final[tuple[Decision, ...]] = (
    Decision.ALLOW,
    Decision.DENY,
    Decision.ALLOW,
    Decision.ALLOW,
)


class InfeasibleObligation(StrictModel):
    """One fixed-grid obligation for which no minimal twin pair exists."""

    transition_family: TransitionFamily
    principal_role_class: str
    probe_type: ProbeType
    reason: str


class SynthesisReport(StrictModel):
    """Complete applicability result for the 6 x 4 x 2 obligation grid."""

    pairs: list[CounterfactualPairPlan]
    infeasible: list[InfeasibleObligation]


class PolicyEncodingDivergenceError(RuntimeError):
    """Raised when the Z3 encoding and the authoritative Cedar oracle disagree."""

    def __init__(self, plan_id: str, decisions: Sequence[Decision]) -> None:
        self.plan_id = plan_id
        self.decisions: tuple[Decision, ...] = tuple(decisions)
        expected = ", ".join(decision.value for decision in _EXPECTED_DECISIONS)
        actual = ", ".join(decision.value for decision in self.decisions) or "<empty>"
        super().__init__(
            f"policy encoding divergence for {plan_id}: expected [{expected}], got [{actual}]"
        )


@dataclass(frozen=True, slots=True)
class _StateVars:
    """Boolean variables for one symbolic pre-transition state."""

    active_principal: z3.BoolRef
    same_tenant: z3.BoolRef
    is_owner: z3.BoolRef
    direct_grant: z3.BoolRef
    group_grant: z3.BoolRef
    delegated_grant: z3.BoolRef
    parent_grant_valid: z3.BoolRef
    admin_role: z3.BoolRef
    explicit_deny: z3.BoolRef


def _make_state_vars(prefix: str) -> _StateVars:
    """Create the nine boolean variables for the state named ``prefix``."""
    return _StateVars(
        active_principal=z3.Bool(f"{prefix}_active_principal"),
        same_tenant=z3.Bool(f"{prefix}_same_tenant"),
        is_owner=z3.Bool(f"{prefix}_is_owner"),
        direct_grant=z3.Bool(f"{prefix}_direct_grant"),
        group_grant=z3.Bool(f"{prefix}_group_grant"),
        delegated_grant=z3.Bool(f"{prefix}_delegated_grant"),
        parent_grant_valid=z3.Bool(f"{prefix}_parent_grant_valid"),
        admin_role=z3.Bool(f"{prefix}_admin_role"),
        explicit_deny=z3.Bool(f"{prefix}_explicit_deny"),
    )


def _support_expr(state: _StateVars, name: str) -> z3.BoolRef:
    """Return the boolean expression for one of the five support predicates."""
    if name == "owner":
        return state.is_owner
    if name == "direct":
        return state.direct_grant
    if name == "group":
        return state.group_grant
    if name == "delegation":
        return z3.And(state.delegated_grant, state.parent_grant_valid)
    if name == "admin":
        return state.admin_role
    raise ValueError(f"unknown support predicate: {name!r}")


def _allow_expr(state: _StateVars) -> z3.BoolRef:
    """Encode the approved DocVault ALLOW formula for one state."""
    supports = z3.Or(*[_support_expr(state, name) for name in _SUPPORT_NAMES])
    return z3.And(
        state.active_principal,
        state.same_tenant,
        z3.Not(state.explicit_deny),
        supports,
    )


def _post_state(state: _StateVars, family: TransitionFamily) -> _StateVars:
    """Apply the family's deterministic transformer to a pre-state."""
    cleared = _TRANSITION_CLEARS[family]
    return _StateVars(
        active_principal=state.active_principal,
        same_tenant=(z3.BoolVal(False) if "same_tenant" in cleared else state.same_tenant),
        is_owner=z3.BoolVal(False) if "is_owner" in cleared else state.is_owner,
        direct_grant=(z3.BoolVal(False) if "direct_grant" in cleared else state.direct_grant),
        group_grant=(z3.BoolVal(False) if "group_grant" in cleared else state.group_grant),
        delegated_grant=(
            z3.BoolVal(False) if "delegated_grant" in cleared else state.delegated_grant
        ),
        parent_grant_valid=(
            z3.BoolVal(False) if "parent_grant_valid" in cleared else state.parent_grant_valid
        ),
        admin_role=z3.BoolVal(False) if "admin_role" in cleared else state.admin_role,
        explicit_deny=state.explicit_deny,
    )


def _class_constraints(state: _StateVars, principal_class: PrincipalClass) -> list[z3.BoolRef]:
    """Return the hard principal-class constraints for one pre-state."""
    if principal_class is PrincipalClass.FORMER_OWNER:
        return [state.is_owner]
    if principal_class is PrincipalClass.SAME_TENANT_PEER:
        return [
            state.same_tenant,
            z3.Not(state.is_owner),
            z3.Not(state.delegated_grant),
            z3.Not(state.admin_role),
        ]
    if principal_class is PrincipalClass.CROSS_TENANT_PRINCIPAL:
        return [z3.Not(state.same_tenant), z3.Not(state.is_owner)]
    if principal_class is PrincipalClass.DELEGATE_OR_ADMIN:
        return [
            z3.Not(state.is_owner),
            z3.Or(_support_expr(state, "delegation"), state.admin_role),
        ]
    raise ValueError(f"unsupported principal class: {principal_class!r}")


def _infeasibility_reason(family: TransitionFamily, principal_class: PrincipalClass) -> str:
    """Return the deterministic applicability-mask reason for an UNSAT cell."""
    if principal_class is PrincipalClass.CROSS_TENANT_PRINCIPAL:
        return "cross-tenant pre-state cannot satisfy policy"
    if family is TransitionFamily.TENANT_CHANGE:
        return "tenant boundary makes post-ALLOW impossible"
    if principal_class is PrincipalClass.FORMER_OWNER:
        return "owner support survives the transition"
    if family in (
        TransitionFamily.DIRECT_SHARE_REVOKE,
        TransitionFamily.GROUP_MEMBER_REMOVE,
    ):
        return "principal-class support survives the transition"
    return "targeted support contradicts principal class"


def _raw_tiebreak_expr(state: _StateVars) -> z3.ArithRef:
    """Return a binary-weighted sum of the raw pre-state booleans.

    Minimizing this after the support objectives gives a unique canonical raw
    assignment without changing any support predicate or policy decision.
    """
    return z3.Sum(
        [z3.If(getattr(state, field), _RAW_FIELD_WEIGHTS[field], 0) for field in _BOOL_FIELDS]
    )


def _model_bool(model: z3.ModelRef, expression: z3.BoolRef) -> bool:
    """Evaluate a boolean expression in a model, completing omitted values."""
    return bool(z3.is_true(model.eval(expression, model_completion=True)))


def _model_support_values(model: z3.ModelRef, state: _StateVars) -> dict[str, bool]:
    """Return the five support-predicate values from a model."""
    return {name: _model_bool(model, _support_expr(state, name)) for name in _SUPPORT_NAMES}


def _build_support_state(
    *,
    principal_id: str,
    resource_id: str,
    probe_type: ProbeType,
    state: _StateVars,
    model: z3.ModelRef,
) -> SupportState:
    """Build the strict Pydantic state from the solved model."""
    return SupportState(
        principal_id=principal_id,
        resource_id=resource_id,
        action=probe_type,
        active_principal=_model_bool(model, state.active_principal),
        same_tenant=_model_bool(model, state.same_tenant),
        is_owner=_model_bool(model, state.is_owner),
        direct_grant=_model_bool(model, state.direct_grant),
        group_grant=_model_bool(model, state.group_grant),
        delegated_grant=_model_bool(model, state.delegated_grant),
        parent_grant_valid=_model_bool(model, state.parent_grant_valid),
        admin_role=_model_bool(model, state.admin_role),
        explicit_deny=_model_bool(model, state.explicit_deny),
    )


def _plan_id(
    family: TransitionFamily,
    principal_class: PrincipalClass,
    probe_type: ProbeType,
) -> str:
    """Return the deterministic ASCII plan identifier for one obligation."""
    return f"ct-{family.value}-{principal_class.value}-{probe_type.value}"


class Z3Synthesizer:
    """Synthesize minimal counterfactual twin pairs against a Cedar oracle.

    The fixed obligation grid is the Cartesian product of
    :class:`~janus_auth.models.TransitionFamily`,
    :class:`~janus_auth.models.PrincipalClass`, and
    :class:`~janus_auth.models.ProbeType` in enum declaration order.
    """

    def __init__(
        self,
        oracle: CedarOracle,
        *,
        timeout_ms: int = DEFAULT_Z3_TIMEOUT_MS,
    ) -> None:
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be a positive integer")
        self._oracle = oracle
        self._timeout_ms = timeout_ms
        self._infeasible: dict[
            tuple[TransitionFamily, PrincipalClass, ProbeType],
            InfeasibleObligation,
        ] = {}

    def synthesize(
        self,
        family: TransitionFamily,
        principal_class: PrincipalClass,
        probe_type: ProbeType,
    ) -> CounterfactualPairPlan | None:
        """Synthesize one obligation, or return ``None`` when it is infeasible.

        Infeasible obligations are recorded in the synthesizer's applicability
        mask so a later :meth:`synthesize_all` reports them exactly once.
        """
        outcome = self._attempt(family, principal_class, probe_type)
        if isinstance(outcome, InfeasibleObligation):
            self._infeasible[(family, principal_class, probe_type)] = outcome
            return None
        return outcome

    def synthesize_all(self) -> SynthesisReport:
        """Synthesize every obligation and return the complete applicability mask."""
        pairs: list[CounterfactualPairPlan] = []
        infeasible: list[InfeasibleObligation] = []
        for family in TransitionFamily:
            for principal_class in PrincipalClass:
                for probe_type in ProbeType:
                    outcome = self._attempt(family, principal_class, probe_type)
                    if isinstance(outcome, InfeasibleObligation):
                        infeasible.append(outcome)
                        self._infeasible[(family, principal_class, probe_type)] = outcome
                    else:
                        pairs.append(outcome)
        return SynthesisReport(pairs=pairs, infeasible=infeasible)

    def _attempt(
        self,
        family: TransitionFamily,
        principal_class: PrincipalClass,
        probe_type: ProbeType,
    ) -> CounterfactualPairPlan | InfeasibleObligation:
        """Solve one obligation and build either a pair or an infeasibility record."""
        optimizer = z3.Optimize()
        optimizer.set(timeout=self._timeout_ms)

        a_pre = _make_state_vars("a_pre")
        b_pre = _make_state_vars("b_pre")
        a_post = _post_state(a_pre, family)
        b_post = _post_state(b_pre, family)

        for pre_state in (a_pre, b_pre):
            optimizer.add(pre_state.active_principal)
            optimizer.add(z3.Not(pre_state.explicit_deny))
            optimizer.add(*_class_constraints(pre_state, principal_class))

        target = _TARGET_SUPPORT[family]
        if target is not None:
            optimizer.add(_support_expr(a_pre, target))
            optimizer.add(_support_expr(b_pre, target))
        if family is TransitionFamily.TENANT_CHANGE:
            optimizer.add(a_pre.same_tenant)
            optimizer.add(b_pre.same_tenant)

        optimizer.add(_allow_expr(a_pre))
        optimizer.add(_allow_expr(b_pre))
        optimizer.add(z3.Not(_allow_expr(a_post)))
        optimizer.add(_allow_expr(b_post))

        for field in _BOOL_FIELDS:
            optimizer.add(z3.Implies(getattr(a_pre, field), getattr(b_pre, field)))

        distance = z3.Sum(
            [
                z3.If(
                    z3.Xor(
                        _support_expr(a_pre, name),
                        _support_expr(b_pre, name),
                    ),
                    1,
                    0,
                )
                for name in _SUPPORT_NAMES
            ]
        )
        optimizer.add(distance == 1)
        optimizer.minimize(distance)

        a_support_count = z3.Sum(
            [z3.If(_support_expr(a_pre, name), 1, 0) for name in _SUPPORT_NAMES]
        )
        optimizer.minimize(a_support_count)

        optimizer.minimize(
            z3.Sum(
                [
                    z3.If(
                        _support_expr(a_pre, name),
                        _SUPPORT_WEIGHTS[name],
                        0,
                    )
                    for name in _SUPPORT_NAMES
                ]
            )
        )
        optimizer.minimize(
            z3.Sum(
                [
                    z3.If(
                        _support_expr(b_pre, name),
                        _SUPPORT_WEIGHTS[name],
                        0,
                    )
                    for name in _SUPPORT_NAMES
                ]
            )
        )
        optimizer.minimize(_raw_tiebreak_expr(a_pre))
        optimizer.minimize(_raw_tiebreak_expr(b_pre))

        result = optimizer.check()
        if result == z3.unsat:
            return InfeasibleObligation(
                transition_family=family,
                principal_role_class=principal_class.value,
                probe_type=probe_type,
                reason=_infeasibility_reason(family, principal_class),
            )
        if result == z3.unknown:
            return InfeasibleObligation(
                transition_family=family,
                principal_role_class=principal_class.value,
                probe_type=probe_type,
                reason="solver timeout",
            )
        if result != z3.sat:
            raise RuntimeError(
                "unexpected Z3 result for "
                f"{family.value}/{principal_class.value}/{probe_type.value}: "
                f"{result!r}"
            )

        plan = self._build_plan(
            family=family,
            principal_class=principal_class,
            probe_type=probe_type,
            model=optimizer.model(),
            a_pre=a_pre,
            a_post=a_post,
            b_pre=b_pre,
            b_post=b_post,
        )
        self._cross_check(plan)
        return plan

    def _build_plan(
        self,
        *,
        family: TransitionFamily,
        principal_class: PrincipalClass,
        probe_type: ProbeType,
        model: z3.ModelRef,
        a_pre: _StateVars,
        a_post: _StateVars,
        b_pre: _StateVars,
        b_post: _StateVars,
    ) -> CounterfactualPairPlan:
        """Turn an optimal model into a strict typed twin plan."""
        plan_id = _plan_id(family, principal_class, probe_type)
        principal_id = "ada" if principal_class is PrincipalClass.FORMER_OWNER else "bea"
        a_support = _model_support_values(model, a_pre)
        b_support = _model_support_values(model, b_pre)
        surviving = [name for name in _SUPPORT_NAMES if b_support[name] and not a_support[name]]
        if len(surviving) != 1:
            raise RuntimeError(f"Z3 model for {plan_id} has {len(surviving)} surviving supports")
        distance = sum(1 for name in _SUPPORT_NAMES if a_support[name] != b_support[name])
        if distance != 1:
            raise RuntimeError(
                f"Z3 model for {plan_id} has support distance {distance}, expected 1"
            )

        return CounterfactualPairPlan(
            plan_id=plan_id,
            transition_family=family,
            probe_type=probe_type,
            principal_role_class=principal_class.value,
            branch_a_pre=_build_support_state(
                principal_id=principal_id,
                resource_id="doc_101",
                probe_type=probe_type,
                state=a_pre,
                model=model,
            ),
            branch_a_post=_build_support_state(
                principal_id=principal_id,
                resource_id="doc_101",
                probe_type=probe_type,
                state=a_post,
                model=model,
            ),
            branch_a_expected=Decision.DENY,
            branch_b_pre=_build_support_state(
                principal_id=principal_id,
                resource_id="doc_101",
                probe_type=probe_type,
                state=b_pre,
                model=model,
            ),
            branch_b_post=_build_support_state(
                principal_id=principal_id,
                resource_id="doc_101",
                probe_type=probe_type,
                state=b_post,
                model=model,
            ),
            branch_b_expected=Decision.ALLOW,
            surviving_support_name=surviving[0],
            hamming_distance=distance,
            consistency_bound_ms=0,
        )

    def _cross_check(self, plan: CounterfactualPairPlan) -> None:
        """Verify the four states against the authoritative Cedar oracle."""
        decisions = self._oracle.evaluate_all(
            [
                plan.branch_a_pre,
                plan.branch_a_post,
                plan.branch_b_pre,
                plan.branch_b_post,
            ]
        )
        if list(decisions) != list(_EXPECTED_DECISIONS):
            raise PolicyEncodingDivergenceError(plan.plan_id, decisions)


__all__ = [
    "InfeasibleObligation",
    "PolicyEncodingDivergenceError",
    "SynthesisReport",
    "Z3Synthesizer",
]
