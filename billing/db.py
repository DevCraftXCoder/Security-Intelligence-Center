"""billing/db.py — SQLite helpers for subscription state and webhook idempotency.

Tables managed here:
    subscriptions   — one row per email; tracks Stripe customer/subscription IDs,
                      tier, status, and renewal timestamp.
    billing_events  — append-only idempotency log; prevents duplicate webhook processing.

DB path matches auth.py and scan_history.py: ~/.sic/state.db
"""

from __future__ import annotations

import logging
import sqlite3
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_DB_PATH = Path.home() / ".sic" / "state.db"
_db_init_done: bool = False


# ---------------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------------


def _db_path() -> Path:
    """Ensure the DB directory exists and return the DB path."""
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return _DB_PATH


def _connect() -> sqlite3.Connection:
    """Return a sqlite3 connection with Row factory and WAL mode enabled."""
    conn = sqlite3.connect(str(_db_path()))
    conn.row_factory = sqlite3.Row
    # WAL mode allows concurrent reads and a single writer without blocking.
    # busy_timeout prevents immediate SQLITE_BUSY errors under concurrent writes.
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


# ---------------------------------------------------------------------------
# Schema init (idempotent)
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Create billing tables if they do not already exist.  Idempotent."""
    global _db_init_done
    if _db_init_done:
        return

    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subscriptions (
                email                   TEXT PRIMARY KEY,
                stripe_customer_id      TEXT,
                stripe_subscription_id  TEXT,
                tier                    TEXT NOT NULL DEFAULT 'community'
                                        CHECK(tier IN ('community', 'team', 'studio')),
                status                  TEXT,
                current_period_end      INTEGER,
                billing_interval        TEXT NOT NULL DEFAULT 'month'
                                        CHECK(billing_interval IN ('month', 'year')),
                updated_at              INTEGER NOT NULL
            )
            """
        )
        # Migration: add billing_interval column to existing DBs (idempotent).
        try:
            conn.execute(
                "ALTER TABLE subscriptions ADD COLUMN billing_interval TEXT NOT NULL "
                "DEFAULT 'month' CHECK(billing_interval IN ('month', 'year'))"
            )
            conn.commit()
            logger.debug("billing_interval column added via migration")
        except Exception:  # noqa: BLE001 — column already exists, safe to ignore
            pass
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS billing_events (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id      TEXT    NOT NULL UNIQUE,
                event_type    TEXT    NOT NULL,
                email         TEXT,
                payload       TEXT,
                processed_at  INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_billing_events_event_id "
            "ON billing_events (event_id)"
        )
        conn.commit()

    _db_init_done = True
    logger.debug("billing DB tables ensured")


# ---------------------------------------------------------------------------
# Subscription helpers
# ---------------------------------------------------------------------------


def upsert_subscription(
    *,
    email: str,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
    tier: str = "community",
    status: str | None = None,
    current_period_end: int | None = None,
    billing_interval: str = "month",
) -> None:
    """Insert or fully replace a subscription row."""
    billing_interval = billing_interval if billing_interval in ("month", "year") else "month"
    now = int(time.time())
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO subscriptions
                (email, stripe_customer_id, stripe_subscription_id,
                 tier, status, current_period_end, billing_interval, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                stripe_customer_id     = COALESCE(excluded.stripe_customer_id,
                                                   stripe_customer_id),
                stripe_subscription_id = COALESCE(excluded.stripe_subscription_id,
                                                   stripe_subscription_id),
                tier                   = excluded.tier,
                status                 = excluded.status,
                current_period_end     = excluded.current_period_end,
                billing_interval       = excluded.billing_interval,
                updated_at             = excluded.updated_at
            """,
            (
                email,
                stripe_customer_id,
                stripe_subscription_id,
                tier,
                status,
                current_period_end,
                billing_interval,
                now,
            ),
        )
        conn.commit()


def get_subscription(email: str) -> sqlite3.Row | None:
    """Return the subscription row for *email*, or None if not present."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM subscriptions WHERE email = ?", (email,)
        ).fetchone()


def get_tier(email: str) -> str:
    """Return the effective billing tier for *email*, defaulting to 'community'.

    Respects subscription status: canceled and unpaid subscriptions are
    immediately downgraded to community.  past_due subscriptions retain their
    tier as a grace period (the operator is expected to handle recovery).
    """
    row = get_subscription(email)
    if row is None:
        return "community"
    tier = row["tier"]
    # Guard against unexpected values already in the DB
    if tier not in ("community", "team", "studio"):
        return "community"
    # Bug 5: Status-aware access control.
    # canceled / unpaid → no paid access.
    # past_due → grace period, keep tier (operator should follow up).
    status = row["status"] if row["status"] else "active"
    if status in ("canceled", "unpaid"):
        return "community"
    return tier


# ---------------------------------------------------------------------------
# Webhook idempotency helpers
# ---------------------------------------------------------------------------


def event_already_processed(event_id: str) -> bool:
    """Return True if *event_id* has already been recorded."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT id FROM billing_events WHERE event_id = ?", (event_id,)
        ).fetchone()
    return row is not None


def record_event(
    *,
    event_id: str,
    event_type: str,
    email: str | None,
    payload: str,
) -> None:
    """Append a billing event for idempotency tracking."""
    now = int(time.time())
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO billing_events
                (event_id, event_type, email, payload, processed_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (event_id, event_type, email, payload, now),
        )
        conn.commit()
