"""Deterministic, idempotent token and header redaction.

Raw HTTP traces must pass through :class:`Redactor` before they are written anywhere
(logs, SARIF, replay files, or the encrypted SQLite trace store).  The redactor never
keeps or logs the original value of a sensitive header, and every redacted value is the
fixed sentinel ``"Bearer [REDACTED]"``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, cast

REDACTED_VALUE = "Bearer [REDACTED]"

SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
    }
)

JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# Defence in depth for opaque bearer tokens that are not JWTs.  The negative lookahead
# keeps repeated sanitisation idempotent by not matching the sentinel itself.
_BEARER_PATTERN = re.compile(
    r"(?i)\bBearer\s+(?!\[REDACTED\])[A-Za-z0-9\-._~+/]+=*"
)


def _scrub_string(value: str) -> str:
    # Match the whole "Bearer <token>" form first so a JWT payload is not expanded into
    # a second "Bearer " prefix, which would make repeated sanitisation non-idempotent.
    scrubbed = _BEARER_PATTERN.sub(REDACTED_VALUE, value)
    return JWT_PATTERN.sub(REDACTED_VALUE, scrubbed)


class Redactor:
    """Stateless recursive redactor for trace-like Python values."""

    @staticmethod
    def sanitize_trace(value: Any) -> Any:
        """Recursively redact sensitive keys and JWT/bearer tokens.

        Dicts, lists, tuples, and strings are traversed.  Sensitive header keys are
        matched case-insensitively and their values replaced wholesale.  Other scalars
        are returned unchanged.  Calling this function twice yields the same result.
        """
        if isinstance(value, dict):
            sanitized: dict[Any, Any] = {}
            for key, item in value.items():
                if isinstance(key, str) and key.lower() in SENSITIVE_HEADERS:
                    sanitized[key] = REDACTED_VALUE
                else:
                    sanitized[key] = Redactor.sanitize_trace(item)
            return sanitized
        if isinstance(value, list):
            return [Redactor.sanitize_trace(item) for item in value]
        if isinstance(value, tuple):
            return tuple(Redactor.sanitize_trace(item) for item in value)
        if isinstance(value, str):
            return _scrub_string(value)
        return value

    @staticmethod
    def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
        """Return a new header mapping with sensitive values redacted."""
        sanitized = Redactor.sanitize_trace(dict(headers))
        return cast(dict[str, str], sanitized)


__all__ = [
    "JWT_PATTERN",
    "REDACTED_VALUE",
    "SENSITIVE_HEADERS",
    "Redactor",
]
