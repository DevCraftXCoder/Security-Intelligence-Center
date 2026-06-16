"""SSO DB helpers — sso_configs table backed by the shared ~/.sic/state.db."""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DB_PATH = Path.home() / ".sic" / "state.db"

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS sso_configs (
    workspace_id        TEXT PRIMARY KEY,
    protocol            TEXT NOT NULL CHECK(protocol IN ('saml', 'oidc')),
    idp_metadata_url    TEXT,
    idp_entity_id       TEXT,
    idp_sso_url         TEXT,
    idp_x509_cert       TEXT,
    oidc_client_id      TEXT,
    oidc_client_secret  TEXT,
    oidc_discovery_url  TEXT,
    allowed_email_domains TEXT,
    enabled             INTEGER NOT NULL DEFAULT 1,
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
)
"""

_db_init_done: bool = False


def init_db() -> None:
    """Create the sso_configs table if it does not exist. Idempotent."""
    global _db_init_done
    if _db_init_done:
        return
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(_DB_PATH)) as con:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=5000")
        con.execute(_CREATE_SQL)
        con.commit()
    _db_init_done = True
    logger.debug("sso_configs table ready")


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


def get_config(workspace_id: str) -> dict[str, Any] | None:
    """Return the SSO config for a workspace, or None if not found / disabled."""
    init_db()
    with sqlite3.connect(str(_DB_PATH)) as con:
        con.row_factory = sqlite3.Row
        row = con.execute(
            "SELECT * FROM sso_configs WHERE workspace_id = ? AND enabled = 1",
            (workspace_id,),
        ).fetchone()
    return dict(row) if row else None


def list_configs() -> list[dict[str, Any]]:
    """Return all SSO configs (enabled and disabled), secrets redacted."""
    init_db()
    with sqlite3.connect(str(_DB_PATH)) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM sso_configs ORDER BY created_at DESC"
        ).fetchall()
    result = []
    for row in rows:
        d = dict(row)
        _redact_secrets(d)
        result.append(d)
    return result


def upsert_config(
    workspace_id: str,
    protocol: str,
    *,
    idp_metadata_url: str | None = None,
    idp_entity_id: str | None = None,
    idp_sso_url: str | None = None,
    idp_x509_cert: str | None = None,
    oidc_client_id: str | None = None,
    oidc_client_secret: str | None = None,
    oidc_discovery_url: str | None = None,
    allowed_email_domains: str | None = None,
) -> dict[str, Any]:
    """Create or replace an SSO config for a workspace. Returns the saved row (redacted)."""
    init_db()
    if protocol not in ("saml", "oidc"):
        raise ValueError(f"Invalid protocol: {protocol!r}")
    now = int(time.time())
    with sqlite3.connect(str(_DB_PATH)) as con:
        con.execute(
            """
            INSERT INTO sso_configs (
                workspace_id, protocol,
                idp_metadata_url, idp_entity_id, idp_sso_url, idp_x509_cert,
                oidc_client_id, oidc_client_secret, oidc_discovery_url,
                allowed_email_domains, enabled, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            ON CONFLICT(workspace_id) DO UPDATE SET
                protocol            = excluded.protocol,
                idp_metadata_url    = excluded.idp_metadata_url,
                idp_entity_id       = excluded.idp_entity_id,
                idp_sso_url         = excluded.idp_sso_url,
                idp_x509_cert       = excluded.idp_x509_cert,
                oidc_client_id      = excluded.oidc_client_id,
                oidc_client_secret  = excluded.oidc_client_secret,
                oidc_discovery_url  = excluded.oidc_discovery_url,
                allowed_email_domains = excluded.allowed_email_domains,
                enabled             = 1,
                updated_at          = excluded.updated_at
            """,
            (
                workspace_id, protocol,
                idp_metadata_url, idp_entity_id, idp_sso_url, idp_x509_cert,
                oidc_client_id, oidc_client_secret, oidc_discovery_url,
                allowed_email_domains, now, now,
            ),
        )
        con.commit()
    row = get_config(workspace_id)
    if row:
        _redact_secrets(row)
    return row or {}


def disable_config(workspace_id: str) -> bool:
    """Soft-delete (disable) an SSO config. Returns True if a row was affected."""
    init_db()
    now = int(time.time())
    with sqlite3.connect(str(_DB_PATH)) as con:
        cur = con.execute(
            "UPDATE sso_configs SET enabled = 0, updated_at = ? WHERE workspace_id = ?",
            (now, workspace_id),
        )
        con.commit()
    return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _redact_secrets(row: dict[str, Any]) -> None:
    """Redact sensitive fields in-place before returning to callers / logs."""
    if row.get("oidc_client_secret"):
        v = row["oidc_client_secret"]
        row["oidc_client_secret"] = f"<redacted, {len(v)} chars>"
    if row.get("idp_x509_cert"):
        v = row["idp_x509_cert"]
        row["idp_x509_cert"] = f"<redacted, {len(v)} chars>"
