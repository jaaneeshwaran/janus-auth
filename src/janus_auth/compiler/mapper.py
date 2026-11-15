"""Deterministic, non-authoritative heuristic operation mapper.

The mapper inspects a static OpenAPI document and the approved Cedar policy text and
proposes one :class:`~janus_auth.models.OperationMap` per DocVault transition family.  It
is deliberately *non-authoritative*: it never receives bearer tokens or live response
data, performs no network I/O, and always returns a
:class:`~janus_auth.models.MappingProposal` with ``approved=False``.  A human must sign a
:class:`~janus_auth.models.ScopeManifest` before the compiler will honour a mapping.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Final

from janus_auth.models import MappingProposal, OperationMap, TransitionFamily

#: HTTP methods that may appear as path-item operations in an OpenAPI document.
_HTTP_METHODS: Final[frozenset[str]] = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)

#: Default DocVault probe path used when the OpenAPI document does not declare one.
_DEFAULT_PROBE_PATH: Final[str] = "/api/v1/documents/{doc_id}"
#: Default DocVault permissions witness path.
_DEFAULT_WITNESS_PATH: Final[str] = "/api/v1/documents/{doc_id}/permissions"
#: DocVault's masked-response query parameter.
_DEFAULT_MASKED_QUERY: Final[str] = "masked"

#: Normalised segment shape of the two auxiliary DocVault paths.
_PROBE_SEGMENTS: Final[tuple[str, ...]] = ("api", "v1", "documents", "{}")
_WITNESS_SEGMENTS: Final[tuple[str, ...]] = (
    "api",
    "v1",
    "documents",
    "{}",
    "permissions",
)

#: Binding transition-family path shapes.  ``{}`` stands for any path parameter.
_FAMILY_SHAPES: Final[dict[TransitionFamily, tuple[str, tuple[str, ...]]]] = {
    TransitionFamily.DIRECT_SHARE_REVOKE: (
        "delete",
        ("api", "v1", "documents", "{}", "shares", "{}"),
    ),
    TransitionFamily.GROUP_MEMBER_REMOVE: (
        "delete",
        ("api", "v1", "groups", "{}", "members", "{}"),
    ),
    TransitionFamily.DELEGATION_REVOKE: (
        "delete",
        ("api", "v1", "documents", "{}", "delegations", "{}"),
    ),
    TransitionFamily.ROLE_DOWNGRADE: (
        "post",
        ("api", "v1", "users", "{}", "role"),
    ),
    TransitionFamily.OWNERSHIP_TRANSFER: (
        "post",
        ("api", "v1", "documents", "{}", "transfer"),
    ),
    TransitionFamily.TENANT_CHANGE: (
        "post",
        ("api", "v1", "users", "{}", "tenant"),
    ),
}


def _normalise_path(path: str) -> tuple[str, ...]:
    """Return path segments with every ``{parameter}`` collapsed to ``"{}"``."""
    segments = [segment for segment in path.split("/") if segment]
    return tuple(
        "{}" if segment.startswith("{") and segment.endswith("}") else segment
        for segment in segments
    )


def _operations(openapi_doc: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    """Return the OpenAPI path map, tolerating a missing or malformed ``paths`` value."""
    paths = openapi_doc.get("paths")
    if not isinstance(paths, Mapping):
        return {}
    concrete: dict[str, Mapping[str, Any]] = {}
    for path, item in paths.items():
        if isinstance(path, str) and isinstance(item, Mapping):
            concrete[path] = item
    return concrete


def _find_operation(
    operations: Mapping[str, Mapping[str, Any]],
    method: str,
    shape: tuple[str, ...],
) -> str | None:
    """Return the first sorted path whose operation matches ``method`` and ``shape``."""
    for path in sorted(operations):
        item = operations[path]
        if method not in item or not isinstance(item[method], Mapping):
            continue
        if _normalise_path(path) == shape:
            return path
    return None


def _find_auxiliary_path(
    operations: Mapping[str, Mapping[str, Any]],
    shape: tuple[str, ...],
    fallback: str,
) -> str:
    """Return the declared ``GET`` path with ``shape``, or the DocVault default."""
    match = _find_operation(operations, "get", shape)
    return match if match is not None else fallback


class HeuristicOperationMapper:
    """Propose DocVault operation mappings from static inputs only.

    The mapper is intentionally stateless.  It matches transition endpoints by their
    path shape and HTTP method, reuses the canonical DocVault probe and permissions
    witness paths, and records a note for every family the document does not cover.
    """

    @staticmethod
    def propose_mapping(
        openapi_doc: Mapping[str, Any], cedar_text: str
    ) -> MappingProposal:
        """Return an unapproved :class:`MappingProposal` for ``openapi_doc``.

        ``policy_sha256`` is the SHA-256 of the supplied Cedar text, so a reviewer can
        verify the proposal was derived from exactly the policy they inspected.
        """
        operations = _operations(openapi_doc)
        probe_path = _find_auxiliary_path(
            operations, _PROBE_SEGMENTS, _DEFAULT_PROBE_PATH
        )
        witness_path = _find_auxiliary_path(
            operations, _WITNESS_SEGMENTS, _DEFAULT_WITNESS_PATH
        )

        proposed: dict[str, OperationMap] = {}
        notes: list[str] = []
        for family in TransitionFamily:
            method, shape = _FAMILY_SHAPES[family]
            path = _find_operation(operations, method, shape)
            if path is None:
                notes.append(
                    f"{family.value}: no {method.upper()} endpoint matching "
                    f"/{'/'.join(shape)} was found in the OpenAPI paths"
                )
                continue
            proposed[family.value] = OperationMap(
                family=family,
                method=method.upper(),  # type: ignore[arg-type]
                path_template=path,
                probe_method="GET",
                probe_path_template=probe_path,
                witness_method="GET",
                witness_path_template=witness_path,
                masked_query=_DEFAULT_MASKED_QUERY,
            )

        return MappingProposal(
            approved=False,
            policy_sha256=hashlib.sha256(cedar_text.encode("utf-8")).hexdigest(),
            proposed_operations=proposed,
            notes=notes,
            generated_at=datetime.now(UTC),
        )


__all__ = ["HeuristicOperationMapper"]
