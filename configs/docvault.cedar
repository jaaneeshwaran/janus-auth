// Janus-Auth DocVault policy (5 support paths, explicit-deny override).
permit (
    principal,
    action in [Action::"protected_read", Action::"reversible_write"],
    resource
)
when {
    principal == resource.owner ||
    principal in resource.direct_grantees ||
    principal.has_group_grant ||
    principal.has_valid_delegation ||
    principal.role == "admin"
};

forbid (
    principal,
    action,
    resource
)
when {
    !principal.active ||
    principal.tenant != resource.tenant ||
    principal in resource.explicit_denies
};
