"""Fernet-encrypted, redacted SQLite trace store.

The schema is exactly the two tables from ``PROJECT_SPEC.md`` section 9.5.2.  Every SQL
statement uses ``?`` parameters.  Trace payloads are redacted with :class:`Redactor` and
encrypted with ``cryptography.fernet.Fernet`` before they are written; the Fernet key is
derived from the configured passphrase with SHA-256.  When no passphrase is configured an
ephemeral per-session key is generated and a :class:`UserWarning` is emitted.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import warnings
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import TracebackType
from typing import cast

from cryptography.fernet import Fernet

from janus_auth.models import ProbeType, TransitionFamily, VerdictKind, ViolationSubtype
from janus_auth.security.redactor import Redactor

_EPHEMERAL_KEY_WARNING = (
    "JANUS_TRACE_ENCRYPTION_KEY is not set; generating an ephemeral per-session Fernet "
    "key. Traces written now cannot be decrypted in a later process."
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    started_at TEXT,
    policy_sha256 TEXT,
    manifest_sha256 TEXT,
    target_url TEXT,
    total_requests INTEGER
);

CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id TEXT PRIMARY KEY,
    run_id TEXT,
    plan_id TEXT,
    transition_family TEXT,
    probe_type TEXT,
    verdict TEXT,
    violation_subtype TEXT,
    encrypted_trace_blob BLOB,
    created_at TEXT
);
"""


def derive_fernet_key(passphrase: str) -> bytes:
    """Derive a stable URL-safe-base64 Fernet key from a passphrase."""
    if not passphrase:
        raise ValueError("trace encryption passphrase must be a non-empty string")
    digest = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _timestamp(value: datetime | str | None) -> str:
    """Return the canonical microsecond ISO-8601 UTC timestamp used for retention."""
    if value is None:
        return datetime.now(UTC).isoformat(timespec="microseconds")
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("timestamp must be ISO-8601 text") from exc
    else:
        parsed = value
    moment = parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return moment.astimezone(UTC).isoformat(timespec="microseconds")


def _row_value(row: sqlite3.Row, column: str) -> object:
    return cast(object, row[column])


class TraceStore:
    """Context-managed SQLite trace store with encryption at rest.

    ``encryption_key`` is a passphrase, not necessarily a pre-generated Fernet key.
    """

    def __init__(
        self,
        db_path: str | Path,
        *,
        encryption_key: str | None = None,
        retention_days: int = 7,
    ) -> None:
        if retention_days <= 0:
            raise ValueError("retention_days must be a positive integer")

        self._db_path = Path(db_path)
        self._retention_days = retention_days
        self._fernet = self._build_fernet(encryption_key)

        if str(self._db_path) != ":memory:":
            self._db_path.parent.mkdir(parents=True, exist_ok=True)

        connection = sqlite3.connect(str(self._db_path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=NORMAL")
        self._connection: sqlite3.Connection | None = connection

        self._create_schema()
        self._purge_expired()

    @staticmethod
    def _build_fernet(encryption_key: str | None) -> Fernet:
        if encryption_key is None:
            warnings.warn(_EPHEMERAL_KEY_WARNING, UserWarning, stacklevel=3)
            return Fernet(Fernet.generate_key())
        return Fernet(derive_fernet_key(encryption_key))

    def _create_schema(self) -> None:
        connection = self._require_connection()
        connection.executescript(_SCHEMA)
        connection.commit()

    def _purge_expired(self) -> None:
        cutoff = (datetime.now(UTC) - timedelta(days=self._retention_days)).isoformat(
            timespec="microseconds"
        )
        connection = self._require_connection()
        connection.execute("DELETE FROM verdicts WHERE created_at < ?", (cutoff,))
        connection.commit()

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("TraceStore is closed")
        return self._connection

    def record_run(
        self,
        run_id: str,
        started_at: datetime | str,
        policy_sha256: str,
        manifest_sha256: str | None,
        target_url: str,
        total_requests: int = 0,
    ) -> None:
        """Insert one run row."""
        connection = self._require_connection()
        connection.execute(
            "INSERT INTO runs "
            "(run_id, started_at, policy_sha256, manifest_sha256, target_url, "
            "total_requests) VALUES (?, ?, ?, ?, ?, ?)",
            (
                run_id,
                _timestamp(started_at),
                policy_sha256,
                manifest_sha256,
                target_url,
                total_requests,
            ),
        )
        connection.commit()

    def record_verdict(
        self,
        verdict_id: str,
        run_id: str,
        plan_id: str,
        transition_family: TransitionFamily,
        probe_type: ProbeType,
        verdict: VerdictKind,
        violation_subtype: ViolationSubtype = ViolationSubtype.NONE,
        trace: object = None,
        *,
        created_at: datetime | str | None = None,
    ) -> None:
        """Redact, encrypt, and insert one verdict row."""
        sanitized = Redactor.sanitize_trace(trace)
        payload = json.dumps(
            sanitized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        blob = self._fernet.encrypt(payload)

        connection = self._require_connection()
        connection.execute(
            "INSERT INTO verdicts "
            "(verdict_id, run_id, plan_id, transition_family, probe_type, verdict, "
            "violation_subtype, encrypted_trace_blob, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                verdict_id,
                run_id,
                plan_id,
                transition_family.value,
                probe_type.value,
                verdict.value,
                violation_subtype.value,
                blob,
                _timestamp(created_at),
            ),
        )
        connection.commit()

    def get_verdict(self, verdict_id: str) -> dict[str, object] | None:
        """Return one decrypted verdict as a mapping, or ``None`` when absent."""
        connection = self._require_connection()
        row = connection.execute(
            "SELECT verdict_id, run_id, plan_id, transition_family, probe_type, verdict, "
            "violation_subtype, encrypted_trace_blob, created_at "
            "FROM verdicts WHERE verdict_id = ?",
            (verdict_id,),
        ).fetchone()
        if row is None:
            return None
        return self._decode_row(row)

    def fetch_verdicts(self, run_id: str) -> list[dict[str, object]]:
        """Return all decrypted verdicts for ``run_id`` in insertion order."""
        connection = self._require_connection()
        rows = connection.execute(
            "SELECT verdict_id, run_id, plan_id, transition_family, probe_type, verdict, "
            "violation_subtype, encrypted_trace_blob, created_at "
            "FROM verdicts WHERE run_id = ? ORDER BY rowid",
            (run_id,),
        ).fetchall()
        return [self._decode_row(row) for row in rows]

    def _decode_row(self, row: sqlite3.Row) -> dict[str, object]:
        blob = _row_value(row, "encrypted_trace_blob")
        if not isinstance(blob, bytes):
            raise ValueError("stored encrypted_trace_blob is not a BLOB")
        decrypted = self._fernet.decrypt(blob).decode("utf-8")
        trace = cast(object, json.loads(decrypted))
        return {
            "verdict_id": _row_value(row, "verdict_id"),
            "run_id": _row_value(row, "run_id"),
            "plan_id": _row_value(row, "plan_id"),
            "transition_family": _row_value(row, "transition_family"),
            "probe_type": _row_value(row, "probe_type"),
            "verdict": _row_value(row, "verdict"),
            "violation_subtype": _row_value(row, "violation_subtype"),
            "created_at": _row_value(row, "created_at"),
            "trace": trace,
        }

    def close(self) -> None:
        """Close the database connection; safe to call more than once."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> TraceStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


__all__ = ["TraceStore", "derive_fernet_key"]
