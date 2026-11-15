"""Authoritative Cedar policy oracle for Janus-Auth.

The oracle is the policy truth that the Z3 synthesizer in Task 5 is cross-checked
against.  :class:`CedarOracle` parses the approved Cedar policy set exactly once at
construction and then evaluates typed :class:`~janus_auth.models.SupportState` tuples by
mapping them to Cedar entities and calling ``cedarpy.is_authorized``.

Mapping rules (fixed by PROJECT_SPEC.md section 9.3.1):

* one ``User`` principal and one ``Document`` resource are built per evaluation;
* the principal tenant is ``acme`` when ``same_tenant`` is true, else ``globex``;
* the principal role is ``admin`` when ``admin_role`` is true, else ``member``;
* ``has_valid_delegation`` is only true when the delegation exists *and* its parent
  grant is currently valid;
* the resource owner is the principal when ``is_owner`` is true, otherwise the reserved
  sentinel id ``__not_owner__``;
* the principal is listed in ``direct_grantees`` / ``explicit_denies`` only when the
  corresponding support variable is true.

Only the two probe actions declared in :data:`SUPPORTED_ACTIONS` are evaluated.  An
unapproved action name returns :attr:`~janus_auth.models.Decision.UNKNOWN` (R5) instead
of guessing; a supported action that the policy does not permit returns
:attr:`~janus_auth.models.Decision.DENY`.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

import cedarpy

from janus_auth.models import Decision, ProbeType, SupportState

#: Cedar actions covered by the approved DocVault policy set.
SUPPORTED_ACTIONS: Final[frozenset[str]] = frozenset(
    {ProbeType.PROTECTED_READ.value, ProbeType.REVERSIBLE_WRITE.value}
)

_PRINCIPAL_TYPE: Final[str] = "User"
_RESOURCE_TYPE: Final[str] = "Document"
_ACTION_TYPE: Final[str] = "Action"

#: Tenant used for both the principal and the resource in the local scope.
_LOCAL_TENANT: Final[str] = "acme"
#: Tenant attributed to a principal when ``same_tenant`` is false.
_FOREIGN_TENANT: Final[str] = "globex"

#: Reserved owner id used when the principal does not own the resource.  DocVault
#: principal identifiers come from approved manifests, so this sentinel never names a
#: real principal in the evaluated scope.
_NOT_OWNER_ID: Final[str] = "__not_owner__"

EntityDict = dict[str, Any]


def _entity_uid(entity_type: str, entity_id: str) -> dict[str, str]:
    """Return a Cedar entity-reference dict for ``entity_type`` / ``entity_id``."""
    return {"type": entity_type, "id": entity_id}


def _principal_ref(state: SupportState) -> dict[str, str]:
    return _entity_uid(_PRINCIPAL_TYPE, state.principal_id)


def _document_ref(state: SupportState) -> dict[str, str]:
    return _entity_uid(_RESOURCE_TYPE, state.resource_id)


def _principal_entity(state: SupportState) -> EntityDict:
    """Map the support state onto the ``User`` entity consumed by the policy."""
    return {
        "uid": _principal_ref(state),
        "attrs": {
            "active": state.active_principal,
            "tenant": _LOCAL_TENANT if state.same_tenant else _FOREIGN_TENANT,
            "role": "admin" if state.admin_role else "member",
            "has_group_grant": state.group_grant,
            "has_valid_delegation": state.delegated_grant and state.parent_grant_valid,
        },
        "parents": [],
    }


def _document_entity(state: SupportState) -> EntityDict:
    """Map the support state onto the ``Document`` resource entity."""
    principal = _entity_uid(_PRINCIPAL_TYPE, state.principal_id)
    owner = (
        principal
        if state.is_owner
        else _entity_uid(_PRINCIPAL_TYPE, _NOT_OWNER_ID)
    )
    return {
        "uid": _document_ref(state),
        "attrs": {
            "owner": {"__entity": owner},
            "tenant": _LOCAL_TENANT,
            "direct_grantees": [{"__entity": principal}] if state.direct_grant else [],
            "explicit_denies": [{"__entity": principal}] if state.explicit_deny else [],
        },
        "parents": [],
    }


def _entities(state: SupportState) -> list[EntityDict]:
    """Return the two-entity Cedar store for one support state."""
    return [_principal_entity(state), _document_entity(state)]


def _request(state: SupportState, action_name: str) -> EntityDict:
    """Return the Cedar request for ``action_name`` against the state's resource."""
    return {
        "principal": _principal_ref(state),
        "action": _entity_uid(_ACTION_TYPE, action_name),
        "resource": _document_ref(state),
        "context": {},
    }


def map_cedar_decision(decision: cedarpy.Decision) -> Decision:
    """Translate a ``cedarpy`` decision into the Janus-Auth :class:`Decision` enum.

    Anything other than ``Allow``/``Deny`` is outside the oracle's contract and raises
    :class:`ValueError` rather than being coerced into a guess.
    """
    if decision is cedarpy.Decision.Allow:
        return Decision.ALLOW
    if decision is cedarpy.Decision.Deny:
        return Decision.DENY
    raise ValueError(f"cedarpy returned an unsupported decision: {decision!r}")


class CedarOracle:
    """Authoritative policy oracle backed by the real Cedar engine.

    The policy set is parsed once in the constructor; :meth:`from_file` reads the UTF-8
    policy file once at that point.  No filesystem or network work happens at import time,
    and the policy text is never mutated afterwards.
    """

    def __init__(self, policy_text: str) -> None:
        self._policy_set = cedarpy.PolicySet.from_str(policy_text)

    @classmethod
    def from_file(cls, path: str | Path) -> CedarOracle:
        """Load the Cedar policy set from a UTF-8 file at construction time."""
        return cls(Path(path).read_text(encoding="utf-8"))

    def evaluate(self, support_state: SupportState) -> Decision:
        """Evaluate the state's own typed action.

        The typed action is always one of :data:`SUPPORTED_ACTIONS`, so this method never
        returns ``UNKNOWN``; a policy missing the matching permit returns ``DENY``.
        """
        return self.evaluate_action(support_state, support_state.action.value)

    def evaluate_action(self, support_state: SupportState, action_name: str) -> Decision:
        """Evaluate ``support_state`` against ``action_name``.

        ``UNKNOWN`` is returned only when ``action_name`` is not an approved probe action
        (R5).  Otherwise the Cedar engine decides, and the result is mapped strictly.
        """
        if action_name not in SUPPORTED_ACTIONS:
            return Decision.UNKNOWN
        result = cedarpy.is_authorized(
            _request(support_state, action_name),
            self._policy_set,
            _entities(support_state),
        )
        return map_cedar_decision(result.decision)

    def evaluate_all(self, states: Iterable[SupportState]) -> list[Decision]:
        """Evaluate every state in iteration order and return the decisions in order."""
        return [self.evaluate(state) for state in states]


__all__ = ["SUPPORTED_ACTIONS", "CedarOracle", "map_cedar_decision"]
