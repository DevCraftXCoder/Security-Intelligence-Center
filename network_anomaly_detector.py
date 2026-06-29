"""
network_anomaly_detector.py — Basic network anomaly detection for SIC.

Detects three classes of anomaly available on all tiers:
  1. Request-rate spikes   — scan RPM exceeds 2× the rolling baseline
  2. New open ports        — port/service first seen on a target since baseline
  3. Auth-failure clusters — ≥3 consecutive 401/403 responses from one target

Community: all three detectors active.
Team+:      additionally inherits ARP/MITM detection (arp_detection flag).

Usage::

    from network_anomaly_detector import get_detector
    det = get_detector()
    det.record_request(target="192.168.1.1", status_code=401)
    det.record_open_port(target="192.168.1.1", port=4444, service="unknown")
    summary = det.summary()
"""
from __future__ import annotations

import logging
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DB_PATH = Path.home() / ".sic" / "state.db"

# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------
_RATE_WINDOW_SECONDS = 60          # measure RPM over this window
_RATE_SPIKE_MULTIPLIER = 2.0       # flag if current RPM > multiplier × baseline
_RATE_BASELINE_SAMPLES = 5         # samples to build initial baseline
_AUTH_FAILURE_THRESHOLD = 3        # consecutive auth failures before anomaly
_EVENT_RETENTION_DAYS = 7          # community tier: 7-day history


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _init_schema() -> None:
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS anomaly_events (
                id          TEXT PRIMARY KEY,
                ts          TEXT NOT NULL,
                kind        TEXT NOT NULL,
                target      TEXT NOT NULL,
                detail      TEXT NOT NULL,
                severity    TEXT NOT NULL DEFAULT 'medium'
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS anomaly_events_ts
            ON anomaly_events (ts DESC)
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS port_baseline (
                target      TEXT NOT NULL,
                port        INTEGER NOT NULL,
                service     TEXT NOT NULL DEFAULT '',
                first_seen  TEXT NOT NULL,
                PRIMARY KEY (target, port)
            )
        """)


# ---------------------------------------------------------------------------
# Anomaly detector
# ---------------------------------------------------------------------------

class NetworkAnomalyDetector:
    """Thread-safe in-process anomaly detector backed by SQLite."""

    def __init__(self) -> None:
        _init_schema()
        self._lock = threading.Lock()
        # Rate tracking: target → [(timestamp, status_code), ...]
        self._request_log: dict[str, list[tuple[float, int]]] = {}
        # Auth failure streak: target → consecutive_count
        self._auth_streak: dict[str, int] = {}
        # RPM baseline samples: target → [rpm_float, ...]
        self._rpm_baseline: dict[str, list[float]] = {}
        logger.info("NetworkAnomalyDetector initialised (db=%s)", _DB_PATH)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_request(self, target: str, status_code: int) -> None:
        """Call once per outbound scan request.

        Args:
            target: hostname or IP being scanned.
            status_code: HTTP status returned (0 if non-HTTP).
        """
        now = time.monotonic()
        with self._lock:
            log = self._request_log.setdefault(target, [])
            log.append((now, status_code))
            # Evict entries older than window * 10 to bound memory
            cutoff = now - _RATE_WINDOW_SECONDS * 10
            self._request_log[target] = [e for e in log if e[0] >= cutoff]

            self._check_rate_spike(target, now)
            self._check_auth_failure(target, status_code)

    def record_open_port(self, target: str, port: int, service: str = "") -> None:
        """Call when a scan discovers an open port on a target.

        First time a (target, port) pair is seen it becomes the baseline.
        Subsequent discoveries against the same pair are no-ops.
        New (target, port) pairs detected after baseline → anomaly event.
        """
        emit_anomaly = False
        with self._lock:
            try:
                with _connect() as conn:
                    existing = conn.execute(
                        "SELECT 1 FROM port_baseline WHERE target=? AND port=?",
                        (target, port),
                    ).fetchone()
                    if existing is None:
                        has_any = conn.execute(
                            "SELECT 1 FROM port_baseline WHERE target=? LIMIT 1",
                            (target,),
                        ).fetchone()
                        conn.execute(
                            "INSERT OR IGNORE INTO port_baseline "
                            "(target,port,service,first_seen) VALUES (?,?,?,?)",
                            (target, port, service or "", _iso_now()),
                        )
                        if has_any is not None:
                            emit_anomaly = True
            except sqlite3.Error:
                logger.exception("port_baseline DB error for %s:%s", target, port)

        # Emit outside the DB connection so _persist_event gets a clean lock
        if emit_anomaly:
            self._persist_event(
                kind="new_open_port",
                target=target,
                detail=f"Previously unseen port {port}/{service or 'unknown'} is now open",
                severity="high",
            )

    def summary(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of recent anomaly activity."""
        try:
            with _connect() as conn:
                rows = conn.execute(
                    """SELECT kind, severity, COUNT(*) as cnt
                       FROM anomaly_events
                       WHERE ts >= datetime('now', ?)
                       GROUP BY kind, severity
                       ORDER BY cnt DESC""",
                    (f"-{_EVENT_RETENTION_DAYS} days",),
                ).fetchall()
                total = conn.execute(
                    "SELECT COUNT(*) FROM anomaly_events WHERE ts >= datetime('now', ?)",
                    (f"-{_EVENT_RETENTION_DAYS} days",),
                ).fetchone()[0]
            breakdown = [dict(r) for r in rows]
        except sqlite3.Error:
            logger.exception("summary DB error")
            breakdown, total = [], 0

        return {
            "enabled": True,
            "retention_days": _EVENT_RETENTION_DAYS,
            "total_events": total,
            "breakdown": breakdown,
            "detectors": ["rate_spike", "new_open_port", "auth_failure_cluster"],
        }

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the *limit* most recent anomaly events."""
        try:
            with _connect() as conn:
                rows = conn.execute(
                    """SELECT id, ts, kind, target, detail, severity
                       FROM anomaly_events
                       WHERE ts >= datetime('now', ?)
                       ORDER BY ts DESC LIMIT ?""",
                    (f"-{_EVENT_RETENTION_DAYS} days", limit),
                ).fetchall()
            return [dict(r) for r in rows]
        except sqlite3.Error:
            logger.exception("recent_events DB error")
            return []

    def purge_old_events(self) -> int:
        """Delete events older than retention window. Returns rows deleted."""
        try:
            with _connect() as conn:
                cur = conn.execute(
                    "DELETE FROM anomaly_events WHERE ts < datetime('now', ?)",
                    (f"-{_EVENT_RETENTION_DAYS} days",),
                )
                return cur.rowcount
        except sqlite3.Error:
            logger.exception("purge_old_events DB error")
            return 0

    # ------------------------------------------------------------------
    # Internal detectors  (called under self._lock)
    # ------------------------------------------------------------------

    def _check_rate_spike(self, target: str, now: float) -> None:
        window = _RATE_WINDOW_SECONDS
        recent = [e for e in self._request_log[target] if e[0] >= now - window]
        current_rpm = len(recent) * (60.0 / window)

        baseline_list = self._rpm_baseline.setdefault(target, [])
        if len(baseline_list) < _RATE_BASELINE_SAMPLES:
            baseline_list.append(current_rpm)
            return

        baseline_avg = sum(baseline_list) / len(baseline_list)
        if baseline_avg > 0 and current_rpm > baseline_avg * _RATE_SPIKE_MULTIPLIER:
            self._persist_event(
                kind="rate_spike",
                target=target,
                detail=(
                    f"Request rate {current_rpm:.1f} rpm is "
                    f"{current_rpm / baseline_avg:.1f}× above baseline "
                    f"({baseline_avg:.1f} rpm)"
                ),
                severity="medium",
            )
        # Rolling baseline update
        baseline_list.append(current_rpm)
        if len(baseline_list) > _RATE_BASELINE_SAMPLES * 3:
            del baseline_list[: _RATE_BASELINE_SAMPLES]

    def _check_auth_failure(self, target: str, status_code: int) -> None:
        if status_code in (401, 403):
            streak = self._auth_streak.get(target, 0) + 1
            self._auth_streak[target] = streak
            if streak == _AUTH_FAILURE_THRESHOLD:
                self._persist_event(
                    kind="auth_failure_cluster",
                    target=target,
                    detail=(
                        f"{streak} consecutive authentication failures "
                        f"(HTTP {status_code}) — possible credential stuffing or lockout"
                    ),
                    severity="high",
                )
        else:
            self._auth_streak[target] = 0

    def _persist_event(
        self,
        kind: str,
        target: str,
        detail: str,
        severity: str = "medium",
    ) -> None:
        import secrets as _secrets
        event_id = _secrets.token_urlsafe(10)
        ts = _iso_now()
        logger.warning(
            "ANOMALY [%s] target=%s severity=%s — %s", kind, target, severity, detail
        )
        try:
            with _connect() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO anomaly_events (id,ts,kind,target,detail,severity) "
                    "VALUES (?,?,?,?,?,?)",
                    (event_id, ts, kind, target, detail, severity),
                )
        except sqlite3.Error:
            logger.exception("Failed to persist anomaly event")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso_now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_detector: NetworkAnomalyDetector | None = None
_detector_lock = threading.Lock()


def get_detector() -> NetworkAnomalyDetector:
    global _detector
    if _detector is None:
        with _detector_lock:
            if _detector is None:
                _detector = NetworkAnomalyDetector()
    return _detector
