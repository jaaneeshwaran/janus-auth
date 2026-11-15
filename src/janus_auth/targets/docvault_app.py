"""DocVault: a multi-tenant document service with seven switchable enforcement modes.

The app is the reference target for the counterfactual differential pipeline.  It models
ownership, direct and group grants, one-hop delegations, admin roles, tenant isolation, and
explicit denies.  ``clean`` implements the Cedar-equivalent authorization contract; the six
``vuln_*`` modes each seed exactly one authorization-lifecycle defect.

Every reset rebuilds the state from an immutable seed and increments a monotonic epoch so a
runner can prove that Branch A and Branch B started from independent state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Annotated, Any, Final, Literal, cast

from fastapi import FastAPI, HTTPException, Query, Request

from janus_auth.models import StrictModel

Mode = Literal[
    "clean",
    "vuln_stale_direct_cache",
    "vuln_group_revocation_ignored",
    "vuln_transfer_retains_owner",
    "vuln_broken_delegation_cascade",
    "vuln_silent_write_on_403",
    "vuln_over_revocation_regression",
]

ALL_MODES: Final[tuple[Mode, ...]] = (
    "clean",
    "vuln_stale_direct_cache",
    "vuln_group_revocation_ignored",
    "vuln_transfer_retains_owner",
    "vuln_broken_delegation_cascade",
    "vuln_silent_write_on_403",
    "vuln_over_revocation_regression",
)

_TOKEN_TO_USER: Final[dict[str, str]] = {
    "token_ada": "ada",
    "token_bea": "bea",
    "token_carl": "carl",
    "token_dana": "dana",
    "token_admin": "ops_admin",
}

_GROUP_ID: Final[str] = "eng_group"
_SEED_USERS: Final[tuple[tuple[str, str, str], ...]] = (
    ("ada", "acme", "member"),
    ("bea", "acme", "member"),
    ("carl", "acme", "member"),
    ("dana", "globex", "member"),
    ("ops_admin", "acme", "admin"),
)

Permission = Literal["read", "write"]


@dataclass(slots=True)
class User:
    user_id: str
    tenant_id: str
    role: str = "member"
    active: bool = True


@dataclass(slots=True)
class Group:
    group_id: str
    tenant_id: str
    members: set[str] = field(default_factory=set)
    pending_removal: set[str] = field(default_factory=set)


@dataclass(slots=True)
class Delegation:
    delegation_id: str
    from_user_id: str
    to_user_id: str
    permission: str


@dataclass(slots=True)
class Document:
    doc_id: str
    owner_id: str
    tenant_id: str
    title: str
    public_summary: str
    secret_content: str
    direct_users: dict[str, str] = field(default_factory=dict)
    group_shares: dict[str, str] = field(default_factory=dict)
    delegations: list[Delegation] = field(default_factory=list)
    explicit_denies: set[str] = field(default_factory=set)
    legacy_owners: set[str] = field(default_factory=set)


@dataclass(slots=True)
class VaultState:
    mode: Mode
    epoch: int
    users: dict[str, User]
    groups: dict[str, Group]
    documents: dict[str, Document]
    direct_share_cache: dict[str, dict[str, str]]
    sequence: int = 0


class ResetBody(StrictModel):
    vulnerability_mode: Mode = "clean"


class CreateDocumentBody(StrictModel):
    title: str
    public_summary: str
    secret_content: str


class PatchDocumentBody(StrictModel):
    secret_content: str | None = None
    title: str | None = None


class ShareBody(StrictModel):
    user_id: str
    permission: Permission


class GroupShareBody(StrictModel):
    group_id: str
    permission: Permission


class MembershipBody(StrictModel):
    user_id: str


class DelegationBody(StrictModel):
    from_user_id: str
    to_user_id: str
    permission: Permission


class RoleBody(StrictModel):
    role: Literal["member", "admin"]


class TransferBody(StrictModel):
    new_owner_id: str
    retain_old_owner_direct_share: bool = False


class TenantBody(StrictModel):
    tenant_id: str
    active: bool = True


class DenyBody(StrictModel):
    user_id: str
    permission: Permission


def _seed_state(mode: Mode, epoch: int) -> VaultState:
    users = {
        user_id: User(user_id=user_id, tenant_id=tenant_id, role=role)
        for user_id, tenant_id, role in _SEED_USERS
    }
    groups = {_GROUP_ID: Group(group_id=_GROUP_ID, tenant_id="acme")}
    return VaultState(
        mode=mode,
        epoch=epoch,
        users=users,
        groups=groups,
        documents={},
        direct_share_cache={},
    )


def _state(request: Request) -> VaultState:
    return cast(VaultState, request.app.state.vault)


def _authenticate(request: Request) -> User:
    header = request.headers.get("authorization", "")
    token = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
    user_id = _TOKEN_TO_USER.get(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="missing or invalid bearer token")
    user = _state(request).users.get(user_id)
    if user is None or not user.active:
        raise HTTPException(status_code=403, detail="principal is not active")
    return user


def _permits(granted: str, needed: str) -> bool:
    return granted == "write" or needed == "read"


def _delegator_holds_grant(
    state: VaultState, doc: Document, user_id: str, permission: str
) -> bool:
    user = state.users.get(user_id)
    if user is None or not user.active:
        return False
    if user.tenant_id != doc.tenant_id:
        return False
    if user_id in doc.explicit_denies:
        return False
    if doc.owner_id == user_id:
        return True
    direct = doc.direct_users.get(user_id)
    if direct is not None and _permits(direct, permission):
        return True
    for group_id, grant in doc.group_shares.items():
        group = state.groups.get(group_id)
        if group is None:
            continue
        members = group.members | group.pending_removal
        if user_id in members and _permits(grant, permission):
            return True
    return user.role == "admin"


def _has_access(state: VaultState, user: User, doc: Document, permission: str) -> bool:
    if not user.active:
        return False
    if user.tenant_id != doc.tenant_id:
        return False
    if user.user_id in doc.explicit_denies:
        return False
    if doc.owner_id == user.user_id:
        return True
    if (
        state.mode == "vuln_transfer_retains_owner"
        and user.user_id in doc.legacy_owners
    ):
        return True
    direct = doc.direct_users.get(user.user_id)
    if direct is None and state.mode == "vuln_stale_direct_cache":
        direct = state.direct_share_cache.get(doc.doc_id, {}).get(user.user_id)
    if direct is not None and _permits(direct, permission):
        return True
    for group_id, grant in doc.group_shares.items():
        group = state.groups.get(group_id)
        if group is None:
            continue
        members = group.members
        if state.mode == "vuln_group_revocation_ignored":
            members = members | group.pending_removal
        if user.user_id in members and _permits(grant, permission):
            return True
    for delegation in doc.delegations:
        if delegation.to_user_id != user.user_id:
            continue
        if not _permits(delegation.permission, permission):
            continue
        if state.mode == "vuln_broken_delegation_cascade" or _delegator_holds_grant(
            state, doc, delegation.from_user_id, permission
        ):
            return True
    return user.role == "admin"


def _require_document(state: VaultState, doc_id: str) -> Document:
    document = state.documents.get(doc_id)
    if document is None:
        raise HTTPException(status_code=404, detail="document not found")
    return document


def _require_owner_or_admin(state: VaultState, user: User, doc: Document) -> None:
    if doc.owner_id != user.user_id and user.role != "admin":
        raise HTTPException(status_code=403, detail="owner or admin required")


def _doc_payload(doc: Document, *, include_secret: bool) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": doc.doc_id,
        "owner_id": doc.owner_id,
        "tenant_id": doc.tenant_id,
        "title": doc.title,
        "public_summary": doc.public_summary,
    }
    payload["secret_content"] = doc.secret_content if include_secret else None
    return payload


def _permissions_payload(doc: Document) -> dict[str, Any]:
    return {
        "owner_id": doc.owner_id,
        "tenant_id": doc.tenant_id,
        "direct_users": sorted(doc.direct_users),
        "groups": sorted(doc.group_shares),
        "delegations": [
            {
                "id": delegation.delegation_id,
                "from_user_id": delegation.from_user_id,
                "to_user_id": delegation.to_user_id,
                "permission": delegation.permission,
            }
            for delegation in doc.delegations
        ],
        "explicit_denies": sorted(doc.explicit_denies),
    }


def _next_id(state: VaultState, prefix: str) -> str:
    state.sequence += 1
    return f"{prefix}_{state.sequence}"


def create_app() -> FastAPI:
    app = FastAPI(title="DocVault", version="1.0.0")
    app.state.vault = _seed_state("clean", 0)

    @app.post("/api/v1/admin/reset")
    def reset(body: ResetBody, request: Request) -> dict[str, Any]:
        current = _state(request)
        request.app.state.vault = _seed_state(body.vulnerability_mode, current.epoch + 1)
        state = _state(request)
        return {"status": "reset", "mode": state.mode, "epoch": state.epoch}

    @app.post("/api/v1/documents", status_code=201)
    def create_document(body: CreateDocumentBody, request: Request) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        doc_id = _next_id(state, "doc")
        document = Document(
            doc_id=doc_id,
            owner_id=user.user_id,
            tenant_id=user.tenant_id,
            title=body.title,
            public_summary=body.public_summary,
            secret_content=body.secret_content,
        )
        state.documents[doc_id] = document
        return _doc_payload(document, include_secret=True)

    @app.get("/api/v1/documents")
    def list_documents(request: Request) -> list[dict[str, Any]]:
        user = _authenticate(request)
        state = _state(request)
        return [
            _doc_payload(
                document,
                include_secret=_has_access(state, user, document, "read"),
            )
            for document in state.documents.values()
        ]

    @app.get("/api/v1/documents/{doc_id}")
    def read_document(
        doc_id: str,
        request: Request,
        masked: Annotated[bool, Query()] = False,
    ) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        if masked:
            if _has_access(state, user, document, "read"):
                return _doc_payload(document, include_secret=True)
            return _doc_payload(document, include_secret=False)
        if not _has_access(state, user, document, "read"):
            raise HTTPException(status_code=403, detail="read denied")
        return _doc_payload(document, include_secret=True)

    @app.patch("/api/v1/documents/{doc_id}")
    def write_document(
        doc_id: str, body: PatchDocumentBody, request: Request
    ) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        if state.mode == "vuln_silent_write_on_403":
            if body.secret_content is not None:
                document.secret_content = body.secret_content
            if body.title is not None:
                document.title = body.title
            if not _has_access(state, user, document, "write"):
                raise HTTPException(status_code=403, detail="write denied")
            return _doc_payload(document, include_secret=True)
        if not _has_access(state, user, document, "write"):
            raise HTTPException(status_code=403, detail="write denied")
        if body.secret_content is not None:
            document.secret_content = body.secret_content
        if body.title is not None:
            document.title = body.title
        return _doc_payload(document, include_secret=True)

    @app.get("/api/v1/documents/{doc_id}/permissions")
    def read_permissions(doc_id: str, request: Request) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        _require_owner_or_admin(state, user, document)
        return _permissions_payload(document)

    @app.post("/api/v1/documents/{doc_id}/shares")
    def grant_direct_share(
        doc_id: str, body: ShareBody, request: Request
    ) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        _require_owner_or_admin(state, user, document)
        if body.user_id not in state.users:
            raise HTTPException(status_code=404, detail="user not found")
        document.direct_users[body.user_id] = body.permission
        if state.mode == "vuln_stale_direct_cache":
            state.direct_share_cache.setdefault(document.doc_id, {})[
                body.user_id
            ] = body.permission
        return {
            "status": "granted",
            "user_id": body.user_id,
            "permission": body.permission,
        }

    @app.delete("/api/v1/documents/{doc_id}/shares/{user_id}")
    def revoke_direct_share(
        doc_id: str, user_id: str, request: Request
    ) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        _require_owner_or_admin(state, user, document)
        document.direct_users.pop(user_id, None)
        if state.mode != "vuln_stale_direct_cache":
            state.direct_share_cache.get(document.doc_id, {}).pop(user_id, None)
        if state.mode == "vuln_over_revocation_regression":
            for group_id in document.group_shares:
                group = state.groups.get(group_id)
                if group is not None:
                    group.members.discard(user_id)
                    group.pending_removal.discard(user_id)
        return {"status": "revoked", "user_id": user_id}

    @app.post("/api/v1/groups/{group_id}/members")
    def add_group_member(
        group_id: str, body: MembershipBody, request: Request
    ) -> dict[str, Any]:
        _authenticate(request)
        state = _state(request)
        group = state.groups.get(group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="group not found")
        if body.user_id not in state.users:
            raise HTTPException(status_code=404, detail="user not found")
        group.members.add(body.user_id)
        group.pending_removal.discard(body.user_id)
        return {"status": "added", "group_id": group_id, "user_id": body.user_id}

    @app.delete("/api/v1/groups/{group_id}/members/{user_id}")
    def remove_group_member(
        group_id: str, user_id: str, request: Request
    ) -> dict[str, Any]:
        _authenticate(request)
        state = _state(request)
        group = state.groups.get(group_id)
        if group is None:
            raise HTTPException(status_code=404, detail="group not found")
        if state.mode == "vuln_group_revocation_ignored":
            if user_id in group.members:
                group.members.discard(user_id)
                group.pending_removal.add(user_id)
            return {"status": "pending_removal", "group_id": group_id, "user_id": user_id}
        group.members.discard(user_id)
        group.pending_removal.discard(user_id)
        return {"status": "removed", "group_id": group_id, "user_id": user_id}

    @app.post("/api/v1/documents/{doc_id}/group-shares")
    def grant_group_share(
        doc_id: str, body: GroupShareBody, request: Request
    ) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        _require_owner_or_admin(state, user, document)
        if body.group_id not in state.groups:
            raise HTTPException(status_code=404, detail="group not found")
        document.group_shares[body.group_id] = body.permission
        return {"status": "granted", "group_id": body.group_id}

    @app.post("/api/v1/documents/{doc_id}/delegations")
    def create_delegation(
        doc_id: str, body: DelegationBody, request: Request
    ) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        if body.from_user_id not in state.users or body.to_user_id not in state.users:
            raise HTTPException(status_code=404, detail="user not found")
        if (
            user.user_id != body.from_user_id
            and document.owner_id != user.user_id
            and user.role != "admin"
        ):
            raise HTTPException(status_code=403, detail="delegation not permitted")
        delegation_id = _next_id(state, "del")
        document.delegations.append(
            Delegation(
                delegation_id=delegation_id,
                from_user_id=body.from_user_id,
                to_user_id=body.to_user_id,
                permission=body.permission,
            )
        )
        return {"id": delegation_id, "status": "active"}

    @app.delete("/api/v1/documents/{doc_id}/delegations/{to_user_id}")
    def revoke_delegation(
        doc_id: str, to_user_id: str, request: Request
    ) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        _require_owner_or_admin(state, user, document)
        document.delegations = [
            delegation
            for delegation in document.delegations
            if delegation.to_user_id != to_user_id
        ]
        return {"status": "revoked", "to_user_id": to_user_id}

    @app.post("/api/v1/users/{user_id}/role")
    def change_role(user_id: str, body: RoleBody, request: Request) -> dict[str, Any]:
        user = _authenticate(request)
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="admin required")
        state = _state(request)
        target = state.users.get(user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")
        target.role = body.role
        return {"user_id": user_id, "role": target.role}

    @app.post("/api/v1/documents/{doc_id}/transfer")
    def transfer_ownership(
        doc_id: str, body: TransferBody, request: Request
    ) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        if document.owner_id != user.user_id:
            raise HTTPException(status_code=403, detail="owner required")
        new_owner = state.users.get(body.new_owner_id)
        if new_owner is None:
            raise HTTPException(status_code=404, detail="user not found")
        if new_owner.tenant_id != document.tenant_id:
            raise HTTPException(status_code=403, detail="cross-tenant transfer denied")
        previous_owner = document.owner_id
        document.owner_id = body.new_owner_id
        if body.retain_old_owner_direct_share:
            document.direct_users[previous_owner] = "write"
        else:
            document.direct_users.pop(previous_owner, None)
        if state.mode == "vuln_transfer_retains_owner":
            document.legacy_owners.add(previous_owner)
        return {"doc_id": doc_id, "new_owner_id": body.new_owner_id}

    @app.post("/api/v1/users/{user_id}/tenant")
    def change_tenant(user_id: str, body: TenantBody, request: Request) -> dict[str, Any]:
        user = _authenticate(request)
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="admin required")
        state = _state(request)
        target = state.users.get(user_id)
        if target is None:
            raise HTTPException(status_code=404, detail="user not found")
        target.tenant_id = body.tenant_id
        target.active = body.active
        return {"user_id": user_id, "tenant_id": target.tenant_id, "active": target.active}

    @app.post("/api/v1/documents/{doc_id}/denies")
    def add_explicit_deny(
        doc_id: str, body: DenyBody, request: Request
    ) -> dict[str, Any]:
        user = _authenticate(request)
        state = _state(request)
        document = _require_document(state, doc_id)
        _require_owner_or_admin(state, user, document)
        if body.user_id not in state.users:
            raise HTTPException(status_code=404, detail="user not found")
        document.explicit_denies.add(body.user_id)
        return {"status": "deny_added", "user_id": body.user_id}

    return app


app = create_app()

__all__ = ["ALL_MODES", "Mode", "create_app", "app"]
