"""DocVault scope-manifest loading and pair-preserving workflow compilation.

The compiler turns each Z3-synthesized :class:`~janus_auth.models.CounterfactualPairPlan`
into two concrete HTTP sequences (Branch A and Branch B) that differ by exactly one setup
step: the step that establishes the *surviving* grant in Branch B.  The transition and the
probe are byte-identical across the two branches, which is the pair-preservation invariant
(R2) that makes the differential verdict meaningful.

Manifests are untrusted input until the HMAC signature verifies.  :func:`load_manifest`
therefore enforces a hard size ceiling *before* parsing YAML and validates through
``model_validate_json`` so the strict domain models see JSON-native scalar types.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Final

import yaml

from janus_auth.compiler.z3_synthesizer import SynthesisReport, Z3Synthesizer
from janus_auth.models import (
    ApiStep,
    CompiledTwinPlan,
    CounterfactualPairPlan,
    ExpectedRole,
    HttpMethod,
    OperationMap,
    PrincipalClass,
    ProbeType,
    ScopeManifest,
    TransitionFamily,
)
from janus_auth.oracle.cedar_engine import CedarOracle
from janus_auth.security.gatekeeper import ScopeViolationError

#: Hard ceiling for an operator-supplied manifest file, in bytes (5 MiB).
MAX_MANIFEST_BYTES: Final[int] = 5_242_880

_CANARY_PREFIX: Final[str] = "JANUS_CANARY_"
_OWNER: Final[str] = "ada"
_PEER: Final[str] = "bea"
_DELEGATOR: Final[str] = "carl"
_ADMIN: Final[str] = "ops_admin"
_GROUP_ID: Final[str] = "eng_group"
_CANARY_FIELD_SUFFIX: Final[int] = 8


class PairPreservationError(RuntimeError):
    """Raised when a compiled twin violates the pair-preservation invariant (R2)."""


def load_manifest(path: str | Path) -> ScopeManifest:
    """Load and validate one scope manifest without trusting its contents.

    The size ceiling is checked from ``stat()`` before the file is read, so an oversized
    (or maliciously large) manifest never reaches the YAML parser.
    """
    manifest_path = Path(path)
    size = manifest_path.stat().st_size
    if size > MAX_MANIFEST_BYTES:
        raise ValueError(
            f"scope manifest is too large: {size} bytes exceeds "
            f"the {MAX_MANIFEST_BYTES}-byte ceiling"
        )
    text = manifest_path.read_text(encoding="utf-8")
    loaded = yaml.safe_load(text)
    if not isinstance(loaded, dict):
        raise ValueError("scope manifest must be a YAML mapping at the top level")
    # Strict models reject enum values that arrive as raw YAML strings, so round-trip
    # through JSON text (JSON mode accepts enum value strings with strict=True).
    return ScopeManifest.model_validate_json(json.dumps(loaded, default=str))


def canary_for(plan_id: str) -> str:
    """Return the deterministic canary marker for ``plan_id``."""
    digest = hashlib.sha256(plan_id.encode("utf-8")).hexdigest()
    return f"{_CANARY_PREFIX}{digest[:_CANARY_FIELD_SUFFIX]}"


def assert_pair_preserved(plan: CompiledTwinPlan) -> None:
    """Enforce R2 on a compiled plan.

    Every non-setup step must be identical across the branches, and the setup sets must
    differ by exactly one ``step_id`` (the surviving-grant step).
    """
    branch_a = plan.branch_a_steps
    branch_b = plan.branch_b_steps

    for role in (
        ExpectedRole.PRE_WITNESS,
        ExpectedRole.TRANSITION,
        ExpectedRole.POST_TRANSITION_WITNESS,
        ExpectedRole.PROBE,
        ExpectedRole.EFFECT_WITNESS,
    ):
        steps_a = [step for step in branch_a if step.expected_role is role]
        steps_b = [step for step in branch_b if step.expected_role is role]
        if len(steps_a) != 1 or len(steps_b) != 1:
            raise PairPreservationError(
                f"{plan.plan_id}: expected exactly one {role.value} step per branch"
            )
        if steps_a[0].model_dump() != steps_b[0].model_dump():
            raise PairPreservationError(
                f"{plan.plan_id}: {role.value} step differs across branches"
            )

    setup_a = {step.step_id: step for step in branch_a if step.expected_role is ExpectedRole.SETUP}
    setup_b = {step.step_id: step for step in branch_b if step.expected_role is ExpectedRole.SETUP}
    differing = set(setup_a) ^ set(setup_b)
    if len(differing) != 1:
        raise PairPreservationError(
            f"{plan.plan_id}: expected exactly one differing setup step, "
            f"found {sorted(differing)}"
        )
    for step_id in set(setup_a) & set(setup_b):
        if setup_a[step_id].model_dump() != setup_b[step_id].model_dump():
            raise PairPreservationError(
                f"{plan.plan_id}: shared setup step {step_id!r} differs across branches"
            )


def _operation(manifest: ScopeManifest, family: TransitionFamily) -> OperationMap:
    try:
        return manifest.operations[family.value]
    except KeyError as exc:  # pragma: no cover - manifest validation catches this first
        raise ScopeViolationError(
            f"scope manifest declares no operation mapping for {family.value}"
        ) from exc


def _doc_path(manifest: ScopeManifest, family: TransitionFamily) -> str:
    return _operation(manifest, family).probe_path_template


def _witness_path(manifest: ScopeManifest, family: TransitionFamily) -> str:
    return _operation(manifest, family).witness_path_template


def _reset_path(manifest: ScopeManifest) -> str:
    if manifest.reset_endpoint is None:
        raise ScopeViolationError("scope manifest declares no reset endpoint")
    return manifest.reset_endpoint


def _resolve_transition_path(template: str) -> str:
    """Fill the catalog's constant placeholders, keeping ``{doc_id}`` for the runner."""
    resolved = template
    for name, value in (
        ("user_id", _PEER),
        ("to_user_id", _PEER),
        ("group_id", _GROUP_ID),
    ):
        resolved = resolved.replace("{" + name + "}", value)
    if "{" in resolved.replace("{doc_id}", ""):
        raise PairPreservationError(
            f"unresolved placeholder in transition path template: {template!r}"
        )
    return resolved


def _step(
    step_id: str,
    method: HttpMethod,
    path_template: str,
    principal_alias: str,
    expected_role: ExpectedRole,
    *,
    json_body: dict[str, Any] | None = None,
    query: dict[str, str] | None = None,
    extract: dict[str, str] | None = None,
    reversible: bool = True,
) -> ApiStep:
    return ApiStep(
        step_id=step_id,
        method=method,
        path_template=path_template,
        principal_alias=principal_alias,
        json_body=json_body,
        query=query or {},
        extract=extract or {},
        expected_role=expected_role,
        reversible=reversible,
    )


def _select_pair(
    report: SynthesisReport,
    family: TransitionFamily,
    probe_type: ProbeType,
) -> CounterfactualPairPlan:
    for pair in report.pairs:
        if pair.transition_family is family and pair.probe_type is probe_type:
            return pair
    raise PairPreservationError(
        f"synthesizer produced no {family.value}/{probe_type.value} pair"
    )


class WorkflowCompiler:
    """Compile an approved manifest into deterministic, pair-preserving twin plans."""

    def __init__(
        self,
        oracle: CedarOracle,
        *,
        signing_secret: str | None = None,
        policy_sha256: str | None = None,
        synthesizer: Z3Synthesizer | None = None,
    ) -> None:
        self._signing_secret = signing_secret
        self._policy_sha256 = policy_sha256
        self._synthesizer = synthesizer if synthesizer is not None else Z3Synthesizer(oracle)

    def compile_suite(self, manifest: ScopeManifest) -> list[CompiledTwinPlan]:
        """Return the 10 synthesized plans, the cascade realization, and the masked control.

        Every reset step pins ``vulnerability_mode="clean"``; the runner replaces that
        body with the mode under test while keeping the compiled sequence unchanged.
        """
        self._require_approved_manifest(manifest)
        report = self._synthesizer.synthesize_all()
        plans = [self.compile_pair(manifest, pair) for pair in report.pairs]
        delegation_pair = _select_pair(
            report, TransitionFamily.DELEGATION_REVOKE, ProbeType.PROTECTED_READ
        )
        plans.append(self._compile_cascade(manifest, delegation_pair))
        masked_pair = _select_pair(
            report, TransitionFamily.DIRECT_SHARE_REVOKE, ProbeType.PROTECTED_READ
        )
        plans.append(self._compile_masked(manifest, masked_pair))
        return sorted(plans, key=lambda plan: plan.plan_id)

    def compile_pair(
        self,
        manifest: ScopeManifest,
        pair: CounterfactualPairPlan,
    ) -> CompiledTwinPlan:
        """Compile one synthesized pair into its concrete dual-branch sequence."""
        return self._compile(manifest, pair, pair.plan_id)

    def _require_approved_manifest(self, manifest: ScopeManifest) -> None:
        if not manifest.verify_signature(self._signing_secret):
            raise ScopeViolationError(
                "scope manifest failed signature verification (unsigned, tampered, "
                "wrong secret, or expired)"
            )
        if not manifest.approved:
            raise ScopeViolationError("scope manifest is signed but not approved")
        if self._policy_sha256 is not None and self._policy_sha256 != manifest.policy_sha256:
            raise ScopeViolationError(
                "approved Cedar policy hash does not match the manifest policy digest"
            )

    def _compile(
        self,
        manifest: ScopeManifest,
        pair: CounterfactualPairPlan,
        plan_id: str,
        *,
        masked: bool = False,
    ) -> CompiledTwinPlan:
        family = pair.transition_family
        canary = canary_for(plan_id)
        probe_principal = (
            _OWNER
            if family is TransitionFamily.OWNERSHIP_TRANSFER
            and pair.principal_role_class == PrincipalClass.FORMER_OWNER.value
            else _PEER
        )
        owner_after = _DELEGATOR if family is TransitionFamily.OWNERSHIP_TRANSFER else _OWNER

        shared_setup, branch_b_setup = self._family_setup_steps(manifest, pair)
        prefix = [
            _step(
                "reset",
                "POST",
                _reset_path(manifest),
                _ADMIN,
                ExpectedRole.SETUP,
                json_body={"vulnerability_mode": "clean"},
                reversible=False,
            ),
            self._constructor_step(manifest, canary),
        ]
        probe = self._probe_step(manifest, pair, probe_principal, masked=masked)
        suffix = [
            _step(
                "pre-witness",
                "GET",
                _doc_path(manifest, family),
                probe_principal,
                ExpectedRole.PRE_WITNESS,
            ),
            self._transition_step(manifest, pair),
            _step(
                "post-transition-witness",
                "GET",
                _witness_path(manifest, family),
                owner_after,
                ExpectedRole.POST_TRANSITION_WITNESS,
            ),
            probe,
            _step(
                "effect-witness",
                "GET",
                _doc_path(manifest, family),
                owner_after,
                ExpectedRole.EFFECT_WITNESS,
            ),
        ]
        branch_a = [*prefix, *shared_setup, *suffix]
        branch_b = [*prefix, *shared_setup, *branch_b_setup, *suffix]

        plan = CompiledTwinPlan(
            plan_id=plan_id,
            synthesized=pair,
            branch_a_steps=branch_a,
            branch_b_steps=branch_b,
            canary=canary,
            probe_principal=probe_principal,
            probe_payload=probe.json_body,
            masked_control=masked,
        )
        assert_pair_preserved(plan)
        return plan

    def _compile_cascade(
        self,
        manifest: ScopeManifest,
        pair: CounterfactualPairPlan,
    ) -> CompiledTwinPlan:
        """Realize the broken-delegation cascade: revoke the delegator's parent grant."""
        family = TransitionFamily.DELEGATION_REVOKE
        plan_id = f"{pair.plan_id}-cascade"
        canary = canary_for(plan_id)
        doc_path = _doc_path(manifest, family)
        permission = "write" if pair.probe_type is ProbeType.REVERSIBLE_WRITE else "read"
        shared_setup = [
            self._direct_share_step(doc_path, _DELEGATOR, permission),
            self._delegation_step(doc_path, _DELEGATOR, _PEER, permission),
        ]
        branch_b_setup = [self._role_step(_PEER, "admin")]
        prefix = [
            _step(
                "reset",
                "POST",
                _reset_path(manifest),
                _ADMIN,
                ExpectedRole.SETUP,
                json_body={"vulnerability_mode": "clean"},
                reversible=False,
            ),
            self._constructor_step(manifest, canary),
        ]
        suffix = [
            _step(
                "pre-witness",
                "GET",
                doc_path,
                _PEER,
                ExpectedRole.PRE_WITNESS,
            ),
            _step(
                "transition",
                "DELETE",
                f"/api/v1/documents/{{doc_id}}/shares/{_DELEGATOR}",
                _OWNER,
                ExpectedRole.TRANSITION,
                reversible=False,
            ),
            _step(
                "post-transition-witness",
                "GET",
                _witness_path(manifest, family),
                _OWNER,
                ExpectedRole.POST_TRANSITION_WITNESS,
            ),
            self._probe_step(manifest, pair, _PEER, masked=False),
            _step(
                "effect-witness",
                "GET",
                doc_path,
                _OWNER,
                ExpectedRole.EFFECT_WITNESS,
            ),
        ]
        plan = CompiledTwinPlan(
            plan_id=plan_id,
            synthesized=pair,
            branch_a_steps=[*prefix, *shared_setup, *suffix],
            branch_b_steps=[*prefix, *shared_setup, *branch_b_setup, *suffix],
            canary=canary,
            probe_principal=_PEER,
            probe_payload=None,
            masked_control=False,
        )
        assert_pair_preserved(plan)
        return plan

    def _compile_masked(
        self,
        manifest: ScopeManifest,
        pair: CounterfactualPairPlan,
    ) -> CompiledTwinPlan:
        """Build the masked-200 control from the direct-share-revoke read pair."""
        return self._compile(manifest, pair, f"{pair.plan_id}-masked", masked=True)

    def _constructor_step(self, manifest: ScopeManifest, canary: str) -> ApiStep:
        """Build the document-constructor step from the signed canary/extractor fields."""
        if not manifest.canary_field:
            raise ScopeViolationError("scope manifest declares an empty canary field")
        doc_id_extractor = manifest.extractors.get("doc_id")
        if not doc_id_extractor:
            raise ScopeViolationError(
                "scope manifest declares no doc_id response extractor"
            )
        return _step(
            "create-doc",
            "POST",
            "/api/v1/documents",
            _OWNER,
            ExpectedRole.SETUP,
            json_body={
                "title": "Q4 Plan",
                "public_summary": "A quarterly plan",
                manifest.canary_field: canary,
            },
            extract={"doc_id": doc_id_extractor},
        )

    def _family_setup_steps(
        self,
        manifest: ScopeManifest,
        pair: CounterfactualPairPlan,
    ) -> tuple[list[ApiStep], list[ApiStep]]:
        """Return (shared setup, Branch-B-only surviving-grant setup)."""
        family = pair.transition_family
        permission = "write" if pair.probe_type is ProbeType.REVERSIBLE_WRITE else "read"
        doc_path = _doc_path(manifest, family)

        if family is TransitionFamily.DIRECT_SHARE_REVOKE:
            shared = [
                self._group_share_step(doc_path, permission),
                self._direct_share_step(doc_path, _PEER, permission),
            ]
            branch_b = [self._group_membership_step(_PEER)]
        elif family is TransitionFamily.GROUP_MEMBER_REMOVE:
            shared = [
                self._group_share_step(doc_path, permission),
                self._group_membership_step(_PEER),
            ]
            branch_b = [self._direct_share_step(doc_path, _PEER, permission)]
        elif family is TransitionFamily.DELEGATION_REVOKE:
            shared = [
                self._delegation_step(doc_path, _OWNER, _PEER, permission)
            ]
            branch_b = [self._role_step(_PEER, "admin")]
        elif family is TransitionFamily.ROLE_DOWNGRADE:
            shared = [self._role_step(_PEER, "admin")]
            branch_b = [
                self._delegation_step(doc_path, _OWNER, _PEER, permission)
            ]
        elif family is TransitionFamily.OWNERSHIP_TRANSFER:
            shared = []
            branch_b = [self._role_step(_OWNER, "admin")]
        else:  # pragma: no cover - no synthesized plan can reach this branch
            raise PairPreservationError(
                f"no concrete setup template for {family.value}"
            )
        return shared, branch_b

    def _group_share_step(
        self,
        doc_path: str,
        permission: str,
    ) -> ApiStep:
        return _step(
            "group-share",
            "POST",
            f"{doc_path}/group-shares",
            _OWNER,
            ExpectedRole.SETUP,
            json_body={"group_id": _GROUP_ID, "permission": permission},
        )

    def _direct_share_step(
        self,
        doc_path: str,
        user_id: str,
        permission: str,
    ) -> ApiStep:
        return _step(
            "direct-share",
            "POST",
            f"{doc_path}/shares",
            _OWNER,
            ExpectedRole.SETUP,
            json_body={"user_id": user_id, "permission": permission},
        )

    def _group_membership_step(self, user_id: str) -> ApiStep:
        return _step(
            "group-membership",
            "POST",
            f"/api/v1/groups/{_GROUP_ID}/members",
            _OWNER,
            ExpectedRole.SETUP,
            json_body={"user_id": user_id},
        )

    def _delegation_step(
        self,
        doc_path: str,
        from_user: str,
        to_user: str,
        permission: str,
    ) -> ApiStep:
        return _step(
            "delegation",
            "POST",
            f"{doc_path}/delegations",
            _OWNER,
            ExpectedRole.SETUP,
            json_body={
                "from_user_id": from_user,
                "to_user_id": to_user,
                "permission": permission,
            },
            extract={"delegation_id": "id"},
        )

    def _role_step(
        self,
        user_id: str,
        role: str,
    ) -> ApiStep:
        return _step(
            "role-admin",
            "POST",
            f"/api/v1/users/{user_id}/role",
            _ADMIN,
            ExpectedRole.SETUP,
            json_body={"role": role},
        )

    def _transition_step(
        self,
        manifest: ScopeManifest,
        pair: CounterfactualPairPlan,
    ) -> ApiStep:
        family = pair.transition_family
        operation = _operation(manifest, family)
        body: dict[str, Any] | None
        if family is TransitionFamily.DIRECT_SHARE_REVOKE:
            body = None
        elif family is TransitionFamily.GROUP_MEMBER_REMOVE:
            body = None
        elif family is TransitionFamily.DELEGATION_REVOKE:
            body = None
        elif family is TransitionFamily.ROLE_DOWNGRADE:
            body = {"role": "member"}
        elif family is TransitionFamily.OWNERSHIP_TRANSFER:
            body = {"new_owner_id": _DELEGATOR, "retain_old_owner_direct_share": False}
        else:  # pragma: no cover - no synthesized pair reaches this branch
            raise PairPreservationError(
                f"no concrete transition body for {family.value}"
            )
        actor = _ADMIN if family is TransitionFamily.ROLE_DOWNGRADE else _OWNER
        return _step(
            "transition",
            operation.method,
            _resolve_transition_path(operation.path_template),
            actor,
            ExpectedRole.TRANSITION,
            json_body=body,
            reversible=False,
        )

    def _probe_step(
        self,
        manifest: ScopeManifest,
        pair: CounterfactualPairPlan,
        probe_principal: str,
        *,
        masked: bool,
    ) -> ApiStep:
        path = _doc_path(manifest, pair.transition_family)
        if pair.probe_type is ProbeType.PROTECTED_READ:
            query: dict[str, str] = {}
            if masked:
                masked_query = _operation(manifest, pair.transition_family).masked_query
                if not masked_query:
                    raise ScopeViolationError(
                        "scope manifest declares no masked query parameter"
                    )
                query = {masked_query: "true"}
            return _step(
                "probe",
                "GET",
                path,
                probe_principal,
                ExpectedRole.PROBE,
                query=query,
            )
        return _step(
            "probe",
            "PATCH",
            path,
            probe_principal,
            ExpectedRole.PROBE,
            json_body={"secret_content": f"MUTATED_BY_{probe_principal}"},
        )


__all__ = [
    "MAX_MANIFEST_BYTES",
    "PairPreservationError",
    "WorkflowCompiler",
    "assert_pair_preserved",
    "canary_for",
    "load_manifest",
]
