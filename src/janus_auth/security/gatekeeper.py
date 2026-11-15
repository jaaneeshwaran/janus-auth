"""Outbound-request safety gatekeeper for Janus-Auth.

Every outbound HTTP request must pass through :meth:`SafetyGatekeeper.validate_request`
before a socket is opened.  The gatekeeper enforces the signed scope manifest, the host
allowlist, DNS/IP SSRF protections, a token-bucket rate limit, the hard request budget,
and the destructive-verb (DELETE) policy from ``PROJECT_SPEC.md`` section 10 and plan
ruling R4.

The gatekeeper never opens a network socket: for non-``testserver`` hosts it only calls
``socket.getaddrinfo`` (or an injected resolver) and inspects the returned addresses.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from collections.abc import Callable, Sequence
from urllib.parse import urlsplit

from janus_auth.models import ScopeManifest

Clock = Callable[[], float]
Resolver = Callable[[str], Sequence[str]]

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_TEST_HOST = "testserver"
_METADATA_IP = ipaddress.ip_address("169.254.169.254")
_PLACEHOLDER = re.compile(r"\{[^{}/]+\}")


class ScopeViolationError(Exception):
    """Base error for any request rejected by the safety gatekeeper.

    Messages never contain signing secrets, bearer tokens, or request credentials.
    """


class SSRFBlockedError(ScopeViolationError):
    """Raised when a host resolves to a link-local, multicast, or unspecified address."""


class BudgetExhaustedError(ScopeViolationError):
    """Raised when the manifest's hard ``max_requests`` budget is exhausted."""


class RateLimitExceededError(ScopeViolationError):
    """Raised when the manifest's token-bucket rate limit would be exceeded."""


class _TokenBucket:
    """Deterministic token bucket driven by an injected monotonic clock.

    The bucket starts full and refills at ``rate`` tokens per second up to ``capacity``.
    A request costs exactly one token.  Testing injects a fake clock, so this class never
    sleeps and never reads wall-clock time in tests.
    """

    def __init__(self, *, rate: float, capacity: float, clock: Clock) -> None:
        if rate <= 0.0:
            raise ValueError("rate must be positive")
        if capacity <= 0.0:
            raise ValueError("capacity must be positive")
        self._rate = rate
        self._capacity = capacity
        self._clock = clock
        self._tokens = capacity
        self._last_refill = clock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last_refill
        if elapsed <= 0.0:
            # A non-monotonic injected clock must never mint free tokens.
            self._last_refill = now
            return
        self._tokens = min(self._capacity, self._tokens + elapsed * self._rate)
        self._last_refill = now

    def consume(self) -> None:
        """Spend one token or raise :class:`RateLimitExceededError`."""
        self._refill()
        if self._tokens < 1.0:
            raise RateLimitExceededError(
                "rate limit exceeded: wait before sending another request"
            )
        self._tokens -= 1.0


def _normalise_path(path: str) -> str:
    """Strip trailing slashes (except the root) without touching placeholders."""
    if not path:
        return "/"
    if len(path) > 1 and path.endswith("/"):
        stripped = path.rstrip("/")
        return stripped or "/"
    return path


def _normalise_declared_path(value: str) -> str:
    """Return a comparable path for a declared path template or endpoint.

    ``value`` may be an absolute URL or a bare path.  Query strings and fragments are
    ignored, exactly as they are for the request URL.
    """
    parsed = urlsplit(value)
    path = parsed.path
    if not path:
        path = parsed.netloc
    if not path:
        path = value
    if not path.startswith("/"):
        path = "/" + path
    return _normalise_path(path)


def _template_regex(template: str) -> re.Pattern[str]:
    """Compile a path template, mapping each ``{name}`` placeholder to one segment."""
    parts = _PLACEHOLDER.split(template)
    placeholders = _PLACEHOLDER.findall(template)
    pattern_parts: list[str] = []
    for index, literal in enumerate(parts):
        pattern_parts.append(re.escape(literal))
        if index < len(placeholders):
            pattern_parts.append(r"[^/]+")
    return re.compile("".join(pattern_parts))


def _is_forbidden_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return (
        address == _METADATA_IP
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
    )


class SafetyGatekeeper:
    """Verifies and enforces one signed :class:`ScopeManifest` for a run.

    The manifest signature is verified exactly once in ``__init__``.  Callers pass the
    signing secret explicitly (``Settings.from_env().signing_secret``) so the gatekeeper
    never re-reads process environment per request.
    """

    def __init__(
        self,
        manifest: ScopeManifest,
        *,
        secret: str | None = None,
        clock: Clock = time.monotonic,
        resolver: Resolver | None = None,
    ) -> None:
        try:
            signature_valid = manifest.verify_signature(secret)
        except ValueError:
            signature_valid = False
        if not signature_valid:
            raise ScopeViolationError(
                "scope manifest failed signature verification (unsigned, tampered, "
                "wrong secret, or expired)"
            )
        self._manifest = manifest
        self._resolver = resolver
        self._requests_used = 0
        capacity = max(1.0, float(manifest.rate_limit_rps))
        self._bucket = _TokenBucket(
            rate=float(manifest.rate_limit_rps),
            capacity=capacity,
            clock=clock,
        )

    @property
    def manifest(self) -> ScopeManifest:
        """The verified manifest this gatekeeper enforces."""
        return self._manifest

    @property
    def requests_used(self) -> int:
        """Number of requests admitted by :meth:`validate_request` so far."""
        return self._requests_used

    def validate_url(self, url: str, method: str = "GET") -> None:
        """Run every pure URL/host/SSRF/destructive check without spending budget."""
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise ScopeViolationError("malformed request URL") from exc

        scheme = parsed.scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            raise ScopeViolationError(
                f"scheme {scheme or '<empty>'!r} is not permitted; use http or https"
            )

        hostname = parsed.hostname
        if not hostname:
            raise ScopeViolationError("request URL has no hostname")

        normalised_host = hostname.rstrip(".").lower()
        allowed_hosts = {
            host.rstrip(".").lower() for host in self._manifest.allowed_hosts
        }
        if normalised_host not in allowed_hosts:
            raise ScopeViolationError(
                f"host {normalised_host!r} is not in the signed allowed_hosts list"
            )

        self._check_resolved_addresses(normalised_host)

        method_upper = method.upper()
        if method_upper == "DELETE" and not self._delete_is_allowed(parsed.path):
            raise ScopeViolationError(
                "DELETE is only permitted on declared transition endpoints, the declared "
                "reset endpoint, or when allow_destructive is true"
            )

    def validate_request(self, method: str, url: str) -> None:
        """Admit one outbound request or raise before any socket work is attempted."""
        self.validate_url(url, method)

        if self._requests_used >= self._manifest.max_requests:
            raise BudgetExhaustedError(
                f"request budget exhausted after {self._requests_used} requests"
            )

        self._bucket.consume()
        self._requests_used += 1

    def _check_resolved_addresses(self, hostname: str) -> None:
        if hostname == _TEST_HOST:
            # The in-process ASGITransport testserver never touches the network.
            return

        addresses = self._resolve(hostname)
        for raw_address in addresses:
            try:
                address = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise SSRFBlockedError(
                    f"host {hostname!r} resolved to an unusable address"
                ) from exc
            if _is_forbidden_address(address):
                raise SSRFBlockedError(
                    f"host {hostname!r} resolves to a blocked address range"
                )

    def _resolve(self, hostname: str) -> Sequence[str]:
        if self._resolver is not None:
            try:
                return self._resolver(hostname)
            except (OSError, ValueError) as exc:
                raise SSRFBlockedError(
                    f"host {hostname!r} could not be resolved safely"
                ) from exc

        try:
            infos = socket.getaddrinfo(hostname, None)
        except (OSError, UnicodeError) as exc:
            raise SSRFBlockedError(
                f"host {hostname!r} could not be resolved safely"
            ) from exc
        return [str(info[4][0]) for info in infos]

    def _delete_is_allowed(self, request_path: str) -> bool:
        if self._manifest.allow_destructive:
            return True

        path = _normalise_path(request_path or "/")

        for endpoint in self._manifest.transition_endpoints:
            if endpoint.method != "DELETE":
                continue
            template = _normalise_declared_path(endpoint.path_template)
            if _template_regex(template).fullmatch(path):
                return True

        reset_endpoint = self._manifest.reset_endpoint
        if reset_endpoint is not None:
            if _normalise_declared_path(reset_endpoint) == path:
                return True

        return False


__all__ = [
    "BudgetExhaustedError",
    "RateLimitExceededError",
    "SSRFBlockedError",
    "SafetyGatekeeper",
    "ScopeViolationError",
]
