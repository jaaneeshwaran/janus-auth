# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `0.1.x` | Yes, until the next minor release |
| `main` | Yes, best effort |

This is an MVP. There are no long-term support branches yet.

## Reporting a vulnerability

Do not open a public issue for a security problem.

Use GitHub's private vulnerability reporting for this repository, or contact the maintainers through the repository's private contact channel. Include:

- the affected version and commit;
- a minimal reproduction, ideally a command and a manifest;
- the impact you observed;
- any logs or artifacts, with secrets removed.

Please do not include real credentials, production tokens, or customer data in a report. Janus-Auth uses synthetic principals and canaries for exactly this reason.

We aim to acknowledge a report within a few working days. Please give us a reasonable window to investigate before public disclosure.

## Scope

In scope:

- bypasses of the gatekeeper, manifest approval, or signature verification;
- credential leakage through SARIF, replay files, logs, or trace storage;
- deserialization or injection issues in the CLI or target;
- authorization logic in the reference target that could hide a real defect;
- denial of service through the request budget, rate limit, or parser.

Out of scope:

- vulnerabilities in dependencies, unless they affect Janus-Auth's guarantees;
- findings against a target you do not own or are not authorized to test;
- social engineering or physical attacks;
- missing hardening that is explicitly documented as an MVP limitation.

## Hardening notes

Janus-Auth is built to make misuse harder:

- **Signed scope only.** The compiler and runner refuse manifests that are not approved and correctly signed.
- **Every request is gated.** The gatekeeper checks scheme, hostname allowlist, SSRF ranges, redirects, budget, and rate limit.
- **No hardcoded secrets.** Replay scripts and reports read credentials from `os.environ`.
- **Redaction and encryption.** Traces are redacted and encrypted; expired rows are purged.
- **Safe deserialization.** YAML uses `yaml.safe_load()` after a 5 MB ceiling. SQLite uses `?` parameters.
- **Non-authoritative AI boundary.** `propose-mapping` always emits `approved: false`.

If you are running Janus-Auth against a live service, set a strong `JANUS_SIGNING_SECRET` and a stable `JANUS_TRACE_ENCRYPTION_KEY`. The development fallback is loud for a reason.

## Audit trail

The repository includes a requirement-by-requirement compliance audit at [`spec-compliance/REPORT.md`](spec-compliance/REPORT.md). It records implemented, partial, absent, and stronger-than-spec requirements, plus the divergences that were fixed during the build.

## Disclosure

We support coordinated disclosure. If a fix is released, we will credit reporters who want credit and publish an advisory with the affected versions and the remediation.