"""Discord, Slack, generic webhook, and email alerting for SIC scan lifecycle events."""

from __future__ import annotations

import email.mime.multipart
import email.mime.text
import hashlib
import logging
import os
import smtplib
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

logger = logging.getLogger(__name__)

# Embed colors (decimal)
_COLORS: dict[str, int] = {
    "scan_started": 3447003,          # blue
    "scan_completed": 3066993,        # green
    "scan_failed": 15158332,          # red
    "scan_killed": 15105570,          # yellow
    "critical_finding": 15158332,     # red
    "unauthorized_attempt": 10038562, # dark red
}

_TITLES: dict[str, str] = {
    "scan_started": "Scan Started",
    "scan_completed": "Scan Completed",
    "scan_failed": "Scan Failed",
    "scan_killed": "Scan Killed",
    "critical_finding": "Critical Finding",
    "unauthorized_attempt": "Unauthorized Scan Attempt",
}

# Events that trigger email and deduplication
_EMAIL_EVENTS: frozenset[str] = frozenset({"critical_finding", "unauthorized_attempt"})

# Events that trigger magic-link delivery email
_MAGIC_LINK_EVENT = "auth_link_issued"

# ---------------------------------------------------------------------------
# Lazy-init URL / config helpers
# ---------------------------------------------------------------------------

_WEBHOOK_URL: str | None = None
_url_checked: bool = False
_url_lock = threading.Lock()

_SLACK_URL: str | None = None
_slack_checked: bool = False
_slack_lock = threading.Lock()

_GENERIC_URL: str | None = None
_generic_checked: bool = False
_generic_lock = threading.Lock()

_ALERT_EMAIL: str | None = None
_email_checked: bool = False
_email_lock = threading.Lock()


def _get_webhook_url() -> str | None:
    """Return the Discord webhook URL, logging a warning once if unset."""
    global _WEBHOOK_URL, _url_checked
    with _url_lock:
        if not _url_checked:
            _url_checked = True
            _WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL") or None
            if not _WEBHOOK_URL:
                logger.warning(
                    "DISCORD_WEBHOOK_URL is not set — Discord scan alerts are disabled"
                )
    return _WEBHOOK_URL


# Alias used by updated send_scan_alert
def _get_discord_url() -> str | None:
    return _get_webhook_url()


def _get_slack_url() -> str | None:
    """Return the Slack webhook URL, logging a warning once if unset."""
    global _SLACK_URL, _slack_checked
    with _slack_lock:
        if not _slack_checked:
            _slack_checked = True
            _SLACK_URL = os.environ.get("SLACK_WEBHOOK_URL") or None
    return _SLACK_URL


def _get_generic_webhook_url() -> str | None:
    """Return the generic SIC webhook URL."""
    global _GENERIC_URL, _generic_checked
    with _generic_lock:
        if not _generic_checked:
            _generic_checked = True
            _GENERIC_URL = os.environ.get("SIC_WEBHOOK_URL") or None
    return _GENERIC_URL


def _get_alert_email() -> str | None:
    """Return the SIC alert email recipients string."""
    global _ALERT_EMAIL, _email_checked
    with _email_lock:
        if not _email_checked:
            _email_checked = True
            _ALERT_EMAIL = os.environ.get("SIC_ALERT_EMAIL") or None
    return _ALERT_EMAIL


# ---------------------------------------------------------------------------
# Field builder (shared)
# ---------------------------------------------------------------------------

def _build_fields(details: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a flat details dict into Discord embed fields."""
    label_map = {
        "scan_type": "Scan Type",
        "target": "Target",
        "duration": "Duration",
        "findings_count": "Findings",
        "error": "Error",
        "severity": "Severity",
        "finding": "Finding",
        "reason": "Reason",
        "ip": "IP Address",
    }
    fields: list[dict[str, Any]] = []
    for key, value in details.items():
        label = label_map.get(key, key.replace("_", " ").title())
        fields.append({"name": label, "value": str(value), "inline": True})
    return fields


# ---------------------------------------------------------------------------
# First-failure-only deduplication
# ---------------------------------------------------------------------------

def _db_path() -> Path:
    p = Path.home() / ".sic"
    p.mkdir(parents=True, exist_ok=True)
    return p / "state.db"


def _make_finding_id(event: str, details: dict[str, Any]) -> str:
    """Return a 16-char hex ID derived from the event + target + finding."""
    raw = f"{event}:{details.get('target', '')}:{details.get('finding', '')}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _already_alerted(finding_id: str) -> bool:
    """Return True if this finding_id has already been alerted within 30 days.

    Uses SQLite at ~/.sic/state.db.  Cleans up expired rows on each call.
    Does NOT insert the dedup row — call _mark_alerted() after dispatching threads.
    """
    db = _db_path()
    now_iso = datetime.now(tz=timezone.utc).isoformat()

    try:
        with sqlite3.connect(str(db)) as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS alerted_findings "
                "(id TEXT PRIMARY KEY, first_alerted_at TEXT NOT NULL, expires_at TEXT NOT NULL)"
            )
            # Purge stale rows
            conn.execute(
                "DELETE FROM alerted_findings WHERE expires_at < ?", (now_iso,)
            )
            conn.commit()
            # Check if row already exists
            row = conn.execute(
                "SELECT id FROM alerted_findings WHERE id = ?", (finding_id,)
            ).fetchone()
            return row is not None
    except Exception:
        logger.debug("_already_alerted DB error for id %s", finding_id, exc_info=True)
        return False


def _mark_alerted(finding_id: str) -> None:
    """Insert the dedup row for finding_id after alert threads have been dispatched.

    Called only when at least one channel thread was successfully started.
    Best-effort — never raises.
    """
    db = _db_path()
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    expires_iso = (datetime.now(tz=timezone.utc) + timedelta(days=30)).isoformat()

    try:
        with sqlite3.connect(str(db)) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO alerted_findings (id, first_alerted_at, expires_at) "
                "VALUES (?, ?, ?)",
                (finding_id, now_iso, expires_iso),
            )
            conn.commit()
    except Exception:
        logger.debug("_mark_alerted DB error for id %s", finding_id, exc_info=True)


# ---------------------------------------------------------------------------
# Fire functions
# ---------------------------------------------------------------------------

def _fire_webhook(event: str, details: dict[str, Any]) -> None:
    """Send the Discord webhook request (runs in a daemon thread)."""
    url = _get_webhook_url()
    if not url:
        return
    try:
        payload = {
            "embeds": [
                {
                    "title": _TITLES.get(event, event),
                    "description": details.pop("description", f"SIC event: {event}"),
                    "color": _COLORS.get(event, 0),
                    "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                    "fields": _build_fields(details),
                    "footer": {"text": "SIC Scanner • HexStrike AI"},
                }
            ]
        }
        requests.post(url, json=payload, timeout=5)
    except Exception:
        logger.debug("Discord alert delivery failed for event '%s'", event, exc_info=True)


def _fire_slack(event: str, details: dict[str, Any]) -> None:
    """Send a Slack Block Kit webhook alert (runs in a daemon thread)."""
    url = _get_slack_url()
    if not url:
        return
    try:
        label_map = {
            "scan_type": "Scan Type",
            "target": "Target",
            "duration": "Duration",
            "findings_count": "Findings",
            "error": "Error",
            "severity": "Severity",
            "finding": "Finding",
            "reason": "Reason",
            "ip": "IP Address",
        }
        fields = []
        for key, value in details.items():
            label = label_map.get(key, key.replace("_", " ").title())
            fields.append({"type": "mrkdwn", "text": f"*{label}*\n{value}"})

        blocks: list[dict[str, Any]] = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": _TITLES.get(event, event),
                    "emoji": True,
                },
            },
        ]
        if fields:
            blocks.append({"type": "section", "fields": fields})

        requests.post(url, json={"blocks": blocks}, timeout=5)
    except Exception:
        logger.debug("Slack alert delivery failed for event '%s'", event, exc_info=True)


def _fire_webhook_generic(event: str, details: dict[str, Any]) -> None:
    """Send a generic HTTPS webhook alert (runs in a daemon thread)."""
    url = _get_generic_webhook_url()
    if not url:
        return
    try:
        payload: dict[str, Any] = {
            "event": event,
            "title": _TITLES.get(event, event),
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "details": details,
        }
        requests.post(url, json=payload, timeout=5)
    except Exception:
        logger.debug("Generic webhook delivery failed for event '%s'", event, exc_info=True)


def _fire_magic_link_email(details: dict[str, Any]) -> None:
    """Deliver a magic-link email to the requesting user.

    Tries Resend API first, falls back to smtplib.
    Failures are logged but never propagate — auth flow must not block.

    Expected keys in *details*:
        email (str)      — recipient address
        link (str)       — full magic-link URL
        expires_at (int) — Unix timestamp when the link expires
    """
    recipient = details.get("email")
    link = details.get("link")
    if not recipient or not link:
        logger.debug("_fire_magic_link_email: missing email or link in details")
        return

    from_addr = os.environ.get("SIC_ALERT_FROM", "")
    if not from_addr:
        print("[SIC WARNING] SIC_ALERT_FROM is not set — skipping email alert")
        return
    subject = "Your SIC login link"
    html_body = (
        "<html><body>"
        "<h2 style='color:#e94560;font-family:sans-serif'>SIC — Magic Link Login</h2>"
        "<p style='font-family:sans-serif'>Click the link below to sign in to SIC. "
        "It is valid for <strong>10 minutes</strong> and can only be used once.</p>"
        f"<p><a href='{link}' style='font-family:monospace;font-size:14px'>{link}</a></p>"
        "<p style='color:#888;font-size:12px;font-family:sans-serif'>"
        "If you did not request this link, you can safely ignore this email.</p>"
        "<hr style='border:none;border-top:1px solid #333;margin-top:24px'>"
        "<p style='color:#888;font-size:11px;font-family:sans-serif'>SIC &bull; HexStrike AI</p>"
        "</body></html>"
    )
    text_body = (
        f"Your SIC login link: {link}\n"
        "Valid for 10 minutes. Do not share this link.\n\n"
        "If you did not request this, ignore this email."
    )

    resend_key = os.environ.get("RESEND_API_KEY")
    if resend_key:
        try:
            resp = requests.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {resend_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "from": from_addr,
                    "to": [recipient],
                    "subject": subject,
                    "html": html_body,
                    "text": text_body,
                },
                timeout=5,
            )
            if resp.status_code in (200, 201):
                logger.info("magic-link email sent via Resend to %s", recipient)
                return
            logger.warning(
                "Resend magic-link delivery non-2xx: %s %s",
                resp.status_code,
                resp.text[:200],
            )
        except Exception:
            logger.debug(
                "Resend magic-link delivery failed, trying SMTP", exc_info=True
            )

    # SMTP fallback
    smtp_host = os.environ.get("SIC_SMTP_HOST")
    if not smtp_host:
        logger.debug(
            "SIC_SMTP_HOST not set — SMTP magic-link fallback unavailable for %s",
            recipient,
        )
        return

    try:
        smtp_port = int(os.environ.get("SIC_SMTP_PORT", "587"))
        smtp_user = os.environ.get("SIC_SMTP_USER", "")
        smtp_pass = os.environ.get("SIC_SMTP_PASS", "")

        msg = email.mime.multipart.MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = recipient
        msg.attach(email.mime.text.MIMEText(text_body, "plain"))
        msg.attach(email.mime.text.MIMEText(html_body, "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, [recipient], msg.as_string())

        logger.info("magic-link email sent via SMTP to %s", recipient)
    except Exception:
        logger.debug(
            "SMTP magic-link delivery failed for %s", recipient, exc_info=True
        )


def _fire_email(event: str, details: dict[str, Any]) -> None:
    """Send a transactional email alert (runs in a daemon thread).

    Only fires for critical_finding and unauthorized_attempt.
    Tries Resend API first, falls back to smtplib.
    """
    if event not in _EMAIL_EVENTS:
        return

    recipients_raw = _get_alert_email()
    if not recipients_raw:
        return

    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if not recipients:
        return

    from_addr = os.environ.get("SIC_ALERT_FROM", "")
    if not from_addr:
        print("[SIC WARNING] SIC_ALERT_FROM is not set — skipping email alert")
        return
    title = _TITLES.get(event, event)
    subject = f"[SIC] {title}"

    # Build HTML body
    rows_html = "".join(
        f"<tr><th style='text-align:left;padding:4px 8px;'>{f['name']}</th>"
        f"<td style='padding:4px 8px;'>{f['value']}</td></tr>"
        for f in _build_fields(details)
    )
    html_body = (
        f"<html><body>"
        f"<h2 style='color:#c0392b'>{title}</h2>"
        f"<table border='1' cellpadding='0' cellspacing='0' style='border-collapse:collapse;'>"
        f"{rows_html}"
        f"</table>"
        f"<p style='color:#888;font-size:12px;'>SIC Scanner &bull; HexStrike AI</p>"
        f"</body></html>"
    )

    resend_key = os.environ.get("RESEND_API_KEY")
    if resend_key:
        try:
            requests.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {resend_key}", "Content-Type": "application/json"},
                json={"from": from_addr, "to": recipients, "subject": subject, "html": html_body},
                timeout=5,
            )
            return
        except Exception:
            logger.debug("Resend email delivery failed for event '%s', trying SMTP", event, exc_info=True)

    # SMTP fallback
    smtp_host = os.environ.get("SIC_SMTP_HOST")
    if not smtp_host:
        logger.debug("SIC_SMTP_HOST not set — SMTP email fallback unavailable for event '%s'", event)
        return

    try:
        smtp_port = int(os.environ.get("SIC_SMTP_PORT", "587"))
        smtp_user = os.environ.get("SIC_SMTP_USER", "")
        smtp_pass = os.environ.get("SIC_SMTP_PASS", "")

        msg = email.mime.multipart.MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(recipients)
        msg.attach(email.mime.text.MIMEText(html_body, "html"))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            if smtp_user:
                server.login(smtp_user, smtp_pass)
            server.sendmail(from_addr, recipients, msg.as_string())
    except Exception:
        logger.debug("SMTP email delivery failed for event '%s'", event, exc_info=True)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_scan_alert(event: str, details: dict[str, Any] | None = None) -> None:
    """Fire alerts across all configured channels for a scan lifecycle event.

    Non-blocking: each channel fires in its own daemon thread.

    Args:
        event: One of scan_started, scan_completed, scan_failed, scan_killed,
               critical_finding, unauthorized_attempt.
        details: Optional flat dict of key/value pairs to render as fields.
                 Special key ``description`` becomes the Discord embed description.
    """
    payload = dict(details) if details else {}

    # Magic-link delivery — always fires in a daemon thread; never blocks auth flow
    if event == _MAGIC_LINK_EVENT:
        try:
            t = threading.Thread(
                target=_fire_magic_link_email, args=(dict(payload),), daemon=True
            )
            t.start()
        except Exception:
            logger.debug(
                "Failed to dispatch magic-link email thread", exc_info=True
            )
        # No other channels (Discord/Slack) for magic-link events — return early
        return

    # Deduplication for alert-worthy events — check BEFORE dispatching, mark AFTER.
    fid: str | None = None
    if event in _EMAIL_EVENTS:
        fid = _make_finding_id(event, payload)
        if _already_alerted(fid):
            logger.debug("Suppressed duplicate alert for finding %s", fid)
            return

    # Tier gate: check which alert channels the caller's subscription permits.
    # feature_gates is imported lazily so scan_alerts can be used standalone.
    _discord_allowed = True
    _slack_allowed = True
    try:
        from feature_gates import feature_enabled as _fe  # noqa: PLC0415
        _discord_allowed = _fe("discord_alerts")
        _slack_allowed = _fe("slack_alerts")
    except Exception:
        # No Flask context or feature_gates unavailable — allow (dev/test mode)
        pass

    dispatched = False
    try:
        if _discord_allowed and _get_discord_url():
            t = threading.Thread(target=_fire_webhook, args=(event, dict(payload)), daemon=True)
            t.start()
            dispatched = True
        if _slack_allowed and _get_slack_url():
            t = threading.Thread(target=_fire_slack, args=(event, dict(payload)), daemon=True)
            t.start()
            dispatched = True
        if _get_generic_webhook_url():
            t = threading.Thread(target=_fire_webhook_generic, args=(event, dict(payload)), daemon=True)
            t.start()
            dispatched = True
        if _get_alert_email():
            t = threading.Thread(target=_fire_email, args=(event, dict(payload)), daemon=True)
            t.start()
            dispatched = True
    except Exception:
        logger.debug("Failed to dispatch alert threads for event '%s'", event, exc_info=True)

    # Record dedup row AFTER at least one thread was started — prevents permanent
    # suppression when a process crash occurs between INSERT and thread dispatch.
    if fid and dispatched:
        _mark_alerted(fid)
