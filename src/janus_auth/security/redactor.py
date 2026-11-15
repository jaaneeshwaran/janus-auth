"""Deterministic, idempotent token and header redaction.

Raw HTTP traces must pass through :class:`Redactor` before they are written anywhere
(logs, SARIF, replay files, or the encrypted SQLite trace store).  The redactor never
keeps or logs the original value of a sensitive header, and every redacted value is the
fixed sentinel ``"Bearer [REDACTED]"``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

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


def _is_sensitive_pair(value: Sequence[Any]) -> bool:
    """Return True for a two-element ``(header-name, value)`` pair."""
    return (
        len(value) == 2
        and isinstance(value[0], str)
        and value[0].lower() in SENSITIVE_HEADERS
    )


class Redactor:
    """Stateless recursive redactor for trace-like Python values."""

    @staticmethod
    def sanitize_trace(value: Any) -> Any:
        """Recursively redact sensitive keys and JWT/bearer tokens.

        Any :class:`~collections.abc.Mapping` (including ``httpx.Headers``) is treated
        as a key/value container, and two-element sequence pairs such as the output of
        ``httpx.Headers.multi_items()`` are redacted when their first element names a
        sensitive header.  Dicts, lists, tuples, and strings are traversed.  Sensitive
        header keys are matched case-insensitively and their values replaced wholesale.
        Other JSON scalars are returned unchanged; non-JSON leaves raise ``TypeError``
        instead of being silently carried into an encrypted trace.  Calling this
        function twice yields the same result.
        """
        if isinstance(value, Mapping):
            sanitized: dict[Any, Any] = {}
            for key, item in value.items():
                if isinstance(key, str) and key.lower() in SENSITIVE_HEADERS:
                    sanitized[key] = REDACTED_VALUE
                else:
                    sanitized[key] = Redactor.sanitize_trace(item)
            return sanitized
        if isinstance(value, list):
            if _is_sensitive_pair(value):
                return [value[0], REDACTED_VALUE]
            return [Redactor.sanitize_trace(item) for item in value]
        if isinstance(value, tuple):
            if _is_sensitive_pair(value):
                return (value[0], REDACTED_VALUE)
            return tuple(Redactor.sanitize_trace(item) for item in value)
        if isinstance(value, str):
            return _scrub_string(value)
        if value is None or isinstance(value, (bool, int, float)):
            return value
        raise TypeError(
            f"cannot redact non-JSON trace value of type {type(value).__name__}"
        )

    @staticmethod
    def redact_headers(headers: Mapping[str, str]) -> dict[str, str]:
        """Return a new header mapping with sensitive values redacted."""
        return {
            key: (
                REDACTED_VALUE
                if key.lower() in SENSITIVE_HEADERS
                else _scrub_string(raw_value)
            )
            for key, raw_value in headers.items()
        }


__all__ = [
    "JWT_PATTERN",
    "REDACTED_VALUE",
    "SENSITIVE_HEADERS",
    "Redactor",
]
