"""Strict Pydantic v2 domain models for Janus-Auth.

Every model forbids unknown fields (``extra="forbid"``) so that malformed manifests,
plans, traces, and verdicts fail closed instead of silently dropping security-relevant
data.

Signed scope manifests
----------------------
A :class:`ScopeManifest` is sealed with two values:

* ``manifest_sha256`` is the SHA-256 hex digest of the *canonical manifest body excluding*
  ``signature`` and ``manifest_sha256``.
* ``signature`` is the HMAC-SHA256 hex digest, keyed by ``JANUS_SIGNING_SECRET``, over the
  *canonical manifest body excluding only* ``signature``.  The signed body therefore
  covers ``manifest_sha256``.

The canonical encoding is UTF-8 JSON produced by :func:`canonical_json_bytes`: sorted keys,
``","``/``":"`` separators with no insignificant whitespace, and non-ASCII characters
preserved (``ensure_ascii=False``).  Signing the same logical manifest twice is
byte-stable.

:meth:`ScopeManifest.verify_signature` rejects an unsigned manifest, a body that no longer
matches ``manifest_sha256``, a wrong or tampered signature, and a manifest whose
``expires_at`` is in the past.  It does **not** enforce ``approved``: approval is a
separate human gate checked by the compiler and runner.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

HttpMethod = Literal["GET", "POST", "PATCH", "PUT", "DELETE"]
BranchLabel = Literal["A", "B"]


class StrictModel(BaseModel):
    """Base model: unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


class TransitionFamily(StrEnum):
    DIRECT_SHARE_REVOKE = "direct_share_revoke"
    GROUP_MEMBER_REMOVE = "group_member_remove"
    DELEGATION_REVOKE = "delegation_revoke"
    ROLE_DOWNGRADE = "role_downgrade"
    OWNERSHIP_TRANSFER = "ownership_transfer"
    TENANT_CHANGE = "tenant_change"


class PrincipalClass(StrEnum):
    FORMER_OWNER = "former_owner"
    SAME_TENANT_PEER = "same_tenant_peer"
    CROSS_TENANT_PRINCIPAL = "cross_tenant_principal"
    DELEGATE_OR_ADMIN = "delegate_or_admin"


class ProbeType(StrEnum):
    PROTECTED_READ = "protected_read"
    REVERSIBLE_WRITE = "reversible_write"


class VerdictKind(StrEnum):
    CONFIRMED_VIOLATION = "CONFIRMED_VIOLATION"
    CONFORMS = "CONFORMS"
    CONFORMS_MASKED = "CONFORMS_MASKED"
    LEGITIMATE_ACCESS_REGRESSION = "LEGITIMATE_ACCESS_REGRESSION"
    UNCERTAIN_ABSTAIN = "UNCERTAIN_ABSTAIN"
    INVALID_TEST = "INVALID_TEST"


class ViolationSubtype(StrEnum):
    NONE = "NONE"
    BOLA_READ_LEAK = "BOLA_READ_LEAK"
    SILENT_WRITE_SIDE_EFFECT = "SILENT_WRITE_SIDE_EFFECT"
    STALE_GROUP_CACHE = "STALE_GROUP_CACHE"
    FORMER_OWNER_RETENTION = "FORMER_OWNER_RETENTION"
    BROKEN_DELEGATION_CASCADE = "BROKEN_DELEGATION_CASCADE"
    OVER_REVOCATION_REGRESSION = "OVER_REVOCATION_REGRESSION"
    INVERTED_ENFORCEMENT = "INVERTED_ENFORCEMENT"


class ExpectedRole(StrEnum):
    SETUP = "setup"
    PRE_WITNESS = "pre_witness"
    TRANSITION = "transition"
    POST_TRANSITION_WITNESS = "post_transition_witness"
    PROBE = "probe"
    EFFECT_WITNESS = "effect_witness"


class SupportState(StrictModel):
    """Boolean/ABAC support tuple from PROJECT_SPEC.md section 9.5.1."""

    principal_id: str
    resource_id: str
    action: ProbeType
    active_principal: bool = True
    same_tenant: bool = True
    is_owner: bool = False
    direct_grant: bool = False
    group_grant: bool = False
    delegated_grant: bool = False
    parent_grant_valid: bool = False
    admin_role: bool = False
    explicit_deny: bool = False


class CounterfactualPairPlan(StrictModel):
    """Z3-synthesized counterfactual twin before HTTP steps are compiled."""

    plan_id: str
    transition_family: TransitionFamily
    probe_type: ProbeType
    principal_role_class: str
    branch_a_pre: SupportState
    branch_a_post: SupportState
    branch_a_expected: Decision
    branch_b_pre: SupportState
    branch_b_post: SupportState
    branch_b_expected: Decision
    surviving_support_name: str
    hamming_distance: int = Field(ge=1, le=2)
    consistency_bound_ms: int = Field(default=0, ge=0)


class ApiStep(StrictModel):
    """One concrete HTTP request in a compiled branch.

    ``extract`` maps a placeholder name to a dotted response-JSON path, for example
    ``{"doc_id": "id"}``.  ``expected_role`` records why the step exists so the runner
    and adjudicator can validate the effect-witness chain.
    """

    step_id: str
    method: HttpMethod
    path_template: str
    principal_alias: str
    json_body: dict[str, Any] | None = None
    query: dict[str, str] = Field(default_factory=dict)
    extract: dict[str, str] = Field(default_factory=dict)
    expected_role: ExpectedRole
    reversible: bool


class CompiledTwinPlan(StrictModel):
    """A synthesized pair plus its two concrete, pair-preserving HTTP sequences (R2)."""

    plan_id: str
    synthesized: CounterfactualPairPlan
    branch_a_steps: list[ApiStep]
    branch_b_steps: list[ApiStep]
    canary: str
    probe_principal: str
    probe_payload: dict[str, Any] | None = None
    masked_control: bool = False


class StepObservation(StrictModel):
    """Redacted record of one executed API step."""

    step_id: str
    method: HttpMethod
    path: str
    principal_alias: str
    status_code: int = Field(ge=0, le=599)
    parsed_json: Any = None
    headers: dict[str, str] = Field(default_factory=dict)
    elapsed_ms: float = Field(default=0.0, ge=0.0)
    canary_present: bool = False
    error: str | None = None


class BranchTrace(StrictModel):
    """Observations and witness outcomes for one branch of a counterfactual pair."""

    branch: BranchLabel
    plan_id: str
    steps: list[StepObservation] = Field(default_factory=list)
    pre_witness_ok: bool
    post_transition_witness_ok: bool
    probe: StepObservation | None = None
    effect_witness: StepObservation | None = None
    canary: str
    valid: bool


class PairedExecutionEvidence(StrictModel):
    """A pair-preserving record of both branches and their independent reset epochs."""

    plan_id: str
    branch_a: BranchTrace
    branch_b: BranchTrace
    branch_a_reset_epoch: int = Field(ge=0)
    branch_b_reset_epoch: int = Field(ge=0)


class DimensionFinding(StrictModel):
    """Outcome of one differential effect-witness dimension."""

    name: str
    passed: bool
    detail: str = ""
    evidence_step_ids: list[str] = Field(default_factory=list)


class BranchSummary(StrictModel):
    """Compact adjudication summary for one branch."""

    branch: BranchLabel
    probe_status_code: int | None = Field(default=None, ge=0, le=599)
    canary_present: bool = False
    access_allowed: bool = False
    state_mutated: bool = False


class AdjudicationReport(StrictModel):
    """Typed 4D effect-witness verdict for one counterfactual pair."""

    plan_id: str
    verdict: VerdictKind
    subtype: ViolationSubtype = ViolationSubtype.NONE
    dimensions: list[DimensionFinding] = Field(default_factory=list)
    evidence: dict[str, str] = Field(default_factory=dict)
    reproduction_verified: bool = False
    branch_a_summary: BranchSummary | None = None
    branch_b_summary: BranchSummary | None = None


class TransitionEndpoint(StrictModel):
    """Declared mutation endpoint for one transition family."""

    family: TransitionFamily
    method: HttpMethod
    path_template: str


class OperationMap(StrictModel):
    """Approved mapping from one transition family to its DocVault operations."""

    family: TransitionFamily
    method: HttpMethod
    path_template: str
    probe_method: HttpMethod
    probe_path_template: str
    witness_method: HttpMethod
    witness_path_template: str
    masked_query: str | None = "masked"


class ScopeManifest(StrictModel):
    """Human-approved authorization scope for a Janus-Auth run.

    See the module docstring for the exact canonical-signing exclusion rules.
    """

    approved: bool = False
    approver: str | None = None
    approved_at: datetime | None = None
    policy_sha256: str
    manifest_sha256: str | None = None
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["127.0.0.1", "localhost", "testserver"]
    )
    max_requests: int = 500
    rate_limit_rps: float = 50.0
    allow_destructive: bool = False
    reset_endpoint: str | None = None
    transition_endpoints: list[TransitionEndpoint] = Field(default_factory=list)
    principal_aliases: dict[str, str] = Field(default_factory=dict)
    operations: dict[str, OperationMap] = Field(default_factory=dict)
    expires_at: datetime | None = None
    signature: str | None = None

    def canonical_body_bytes(self, *, include_manifest_sha256: bool = True) -> bytes:
        """Return the canonical UTF-8 JSON body used for hashing and signing.

        ``signature`` is always excluded.  ``manifest_sha256`` is excluded only when
        computing the manifest hash itself.
        """
        excluded = {"signature"} if include_manifest_sha256 else {"signature", "manifest_sha256"}
        payload = self.model_dump(mode="json", exclude=excluded)
        return canonical_json_bytes(payload)

    def compute_manifest_sha256(self) -> str:
        """SHA-256 of the canonical body excluding ``signature`` and ``manifest_sha256``."""
        return hashlib.sha256(
            self.canonical_body_bytes(include_manifest_sha256=False)
        ).hexdigest()

    def _signing_key(self, secret: str | None) -> bytes:
        if secret is None:
            from janus_auth.config import Settings

            secret = Settings.from_env().signing_secret
        if not secret:
            raise ValueError("signing secret must be a non-empty string")
        return secret.encode("utf-8")

    def sign(self, secret: str | None = None) -> ScopeManifest:
        """Seal this manifest in place and return it.

        Populates ``manifest_sha256`` and ``signature``.  Returning ``self`` makes both
        ``signed = manifest.sign(secret)`` and ``manifest.sign(secret)`` safe call patterns.
        The signature is computed only after the manifest hash is written, so it covers
        ``manifest_sha256``.
        """
        key = self._signing_key(secret)
        self.manifest_sha256 = self.compute_manifest_sha256()
        self.signature = hmac.new(
            key,
            self.canonical_body_bytes(include_manifest_sha256=True),
            hashlib.sha256,
        ).hexdigest()
        return self

    def verify_integrity(self) -> bool:
        """Return ``True`` when the stored ``manifest_sha256`` matches the body."""
        if self.manifest_sha256 is None:
            return False
        return hmac.compare_digest(self.manifest_sha256, self.compute_manifest_sha256())

    def is_expired(self, *, now: datetime | None = None) -> bool:
        """Return ``True`` when ``expires_at`` has been reached."""
        if self.expires_at is None:
            return False
        current = now if now is not None else datetime.now(UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        return expires_at <= current

    def verify_signature(self, secret: str | None = None) -> bool:
        """Verify integrity, HMAC, and expiry.  Unsigned or expired manifests fail."""
        if self.signature is None or self.manifest_sha256 is None:
            return False
        if self.is_expired():
            return False
        if not self.verify_integrity():
            return False
        key = self._signing_key(secret)
        expected = hmac.new(
            key,
            self.canonical_body_bytes(include_manifest_sha256=True),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, self.signature)


class MappingProposal(StrictModel):
    """Unapproved operation-mapping draft produced by the optional mapper.

    ``approved`` is pinned to ``False``: the non-authoritative mapping boundary means an
    operation proposal can never approve itself.  Approval happens by signing a
    :class:`ScopeManifest` through the human ``approve-manifest`` workflow.
    """

    approved: bool = False
    policy_sha256: str
    proposed_operations: dict[str, OperationMap]
    notes: list[str]
    generated_at: datetime

    @field_validator("approved")
    @classmethod
    def _proposal_must_be_unapproved(cls, value: bool) -> bool:
        if value:
            raise ValueError("MappingProposal is always unapproved; sign a ScopeManifest instead")
        return value


def canonical_json_bytes(payload: Mapping[str, Any]) -> bytes:
    """Encode ``payload`` as canonical UTF-8 JSON (sorted keys, no whitespace)."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return encoded.encode("utf-8")


__all__ = [
    "AdjudicationReport",
    "ApiStep",
    "BranchLabel",
    "BranchSummary",
    "BranchTrace",
    "CompiledTwinPlan",
    "CounterfactualPairPlan",
    "Decision",
    "DimensionFinding",
    "ExpectedRole",
    "HttpMethod",
    "MappingProposal",
    "OperationMap",
    "PairedExecutionEvidence",
    "PrincipalClass",
    "ProbeType",
    "ScopeManifest",
    "StepObservation",
    "StrictModel",
    "SupportState",
    "TransitionEndpoint",
    "TransitionFamily",
    "VerdictKind",
    "ViolationSubtype",
    "canonical_json_bytes",
]
