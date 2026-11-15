"""Typed runtime configuration for Janus-Auth.

Configuration is read once from the process environment by :meth:`Settings.from_env`.
Importing this module performs no environment reads and no filesystem work.

The signing-secret fallback below is mandated by ``PROJECT_SPEC.md`` section 15 for local
development.  It is deliberately named with ``INSECURE_DEV_ONLY`` so that no caller can
mistake it for a production credential; :meth:`Settings.from_env` emits a warning whenever
it is used.
"""

from __future__ import annotations

import os
import warnings
from collections.abc import Mapping
from dataclasses import dataclass

#: Development-only fallback from PROJECT_SPEC.md.  Never use this outside local testing.
INSECURE_DEV_ONLY_SIGNING_SECRET = (
    "janus-local-dev-signing-key-change-in-ci"  # noqa: S105 - mandated dev-only fallback
)

DEFAULT_RETENTION_DAYS = 7
DEFAULT_Z3_TIMEOUT_MS = 5000
DEFAULT_MAX_REQUESTS = 500

_INSECURE_KEY_WARNING = (
    "JANUS_SIGNING_SECRET is not set; falling back to the insecure development-only "
    "signing key. Set JANUS_SIGNING_SECRET to a strong random value outside local testing."
)


def _read_env(environ: Mapping[str, str], name: str) -> str | None:
    """Return a stripped environment value, treating empty strings as unset."""
    raw = environ.get(name)
    if raw is None:
        return None
    stripped = raw.strip()
    return stripped or None


def _parse_positive_int(name: str, raw: str | None, default: int) -> int:
    """Parse a positive integer environment variable with a clear error message."""
    if raw is None:
        return default
    try:
        value = int(raw, 10)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer, got {value}")
    return value


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable, validated Janus-Auth settings.

    ``trace_encryption_key`` is optional because the trace store generates an ephemeral
    per-session Fernet key when ``JANUS_TRACE_ENCRYPTION_KEY`` is unset.
    """

    signing_secret: str
    trace_encryption_key: str | None = None
    retention_days: int = DEFAULT_RETENTION_DAYS
    z3_timeout_ms: int = DEFAULT_Z3_TIMEOUT_MS
    max_requests: int = DEFAULT_MAX_REQUESTS

    def __post_init__(self) -> None:
        if not self.signing_secret or not self.signing_secret.strip():
            raise ValueError("signing_secret must be a non-empty string")
        if self.retention_days <= 0:
            raise ValueError("retention_days must be a positive integer")
        if self.z3_timeout_ms <= 0:
            raise ValueError("z3_timeout_ms must be a positive integer")
        if self.max_requests <= 0:
            raise ValueError("max_requests must be a positive integer")
        if self.trace_encryption_key is not None and not self.trace_encryption_key.strip():
            raise ValueError("trace_encryption_key must be a non-empty string when provided")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        """Build settings from ``environ`` (defaults to :data:`os.environ`)."""
        source: Mapping[str, str] = os.environ if environ is None else environ

        signing_secret = _read_env(source, "JANUS_SIGNING_SECRET")
        if signing_secret is None:
            warnings.warn(_INSECURE_KEY_WARNING, UserWarning, stacklevel=2)
            signing_secret = INSECURE_DEV_ONLY_SIGNING_SECRET

        return cls(
            signing_secret=signing_secret,
            trace_encryption_key=_read_env(source, "JANUS_TRACE_ENCRYPTION_KEY"),
            retention_days=_parse_positive_int(
                "JANUS_RETENTION_DAYS",
                _read_env(source, "JANUS_RETENTION_DAYS"),
                DEFAULT_RETENTION_DAYS,
            ),
            z3_timeout_ms=_parse_positive_int(
                "JANUS_Z3_TIMEOUT_MS",
                _read_env(source, "JANUS_Z3_TIMEOUT_MS"),
                DEFAULT_Z3_TIMEOUT_MS,
            ),
            max_requests=_parse_positive_int(
                "JANUS_MAX_REQUESTS",
                _read_env(source, "JANUS_MAX_REQUESTS"),
                DEFAULT_MAX_REQUESTS,
            ),
        )


__all__ = [
    "DEFAULT_MAX_REQUESTS",
    "DEFAULT_RETENTION_DAYS",
    "DEFAULT_Z3_TIMEOUT_MS",
    "INSECURE_DEV_ONLY_SIGNING_SECRET",
    "Settings",
]
