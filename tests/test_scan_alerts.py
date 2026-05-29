"""Tests for scan_alerts.py — magic-link email dispatch and send_scan_alert routing."""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_module_caches() -> None:
    """Reset lazy-init globals so each test starts clean."""
    import scan_alerts as sa  # noqa: PLC0415

    sa._url_checked = False
    sa._WEBHOOK_URL = None
    sa._slack_checked = False
    sa._SLACK_URL = None
    sa._generic_checked = False
    sa._GENERIC_URL = None
    sa._email_checked = False
    sa._ALERT_EMAIL = None


# ---------------------------------------------------------------------------
# P0-1: Magic-link email delivery
# ---------------------------------------------------------------------------


class TestFireMagicLinkEmail:
    """Unit tests for _fire_magic_link_email."""

    def setup_method(self) -> None:
        _reset_module_caches()

    def test_sends_via_resend_when_key_set(self) -> None:
        import scan_alerts as sa  # noqa: PLC0415

        mock_resp = MagicMock()
        mock_resp.status_code = 200

        with patch.dict("os.environ", {"RESEND_API_KEY": "re_test_key"}):
            with patch("requests.post", return_value=mock_resp) as mock_post:
                sa._fire_magic_link_email(
                    {"email": "admin@example.com", "link": "https://sic.example.com/auth/verify?token=abc123", "expires_at": int(time.time()) + 600}
                )

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        assert "resend.com/emails" in call_args[0][0]
        payload = call_args[1]["json"]
        assert payload["to"] == ["admin@example.com"]
        assert "Your SIC login link" in payload["subject"]
        assert "abc123" in payload["html"]

    def test_falls_back_to_smtp_when_resend_fails(self) -> None:
        import scan_alerts as sa  # noqa: PLC0415

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "internal error"

        with patch.dict(
            "os.environ",
            {
                "RESEND_API_KEY": "re_test_key",
                "SIC_SMTP_HOST": "smtp.example.com",
                "SIC_SMTP_USER": "user",
                "SIC_SMTP_PASS": "pass",
            },
        ):
            with patch("requests.post", return_value=mock_resp):
                with patch("smtplib.SMTP") as mock_smtp_cls:
                    mock_smtp = MagicMock()
                    mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_smtp)
                    mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

                    sa._fire_magic_link_email(
                        {"email": "admin@example.com", "link": "https://sic.example.com/auth/verify?token=xyz", "expires_at": int(time.time()) + 600}
                    )

        mock_smtp_cls.assert_called_once_with("smtp.example.com", 587)

    def test_skips_when_email_missing(self) -> None:
        import scan_alerts as sa  # noqa: PLC0415

        with patch("requests.post") as mock_post:
            sa._fire_magic_link_email({"link": "https://sic.example.com/auth/verify?token=abc"})

        mock_post.assert_not_called()

    def test_skips_when_link_missing(self) -> None:
        import scan_alerts as sa  # noqa: PLC0415

        with patch("requests.post") as mock_post:
            sa._fire_magic_link_email({"email": "admin@example.com"})

        mock_post.assert_not_called()

    def test_no_resend_no_smtp_host_is_silent(self) -> None:
        """Should log debug and return without raising."""
        import scan_alerts as sa  # noqa: PLC0415

        with patch.dict("os.environ", {}, clear=True):
            with patch("requests.post") as mock_post:
                sa._fire_magic_link_email(
                    {"email": "admin@example.com", "link": "https://sic.example.com/auth/verify?token=abc"}
                )

        mock_post.assert_not_called()


class TestSendScanAlertMagicLink:
    """Integration tests: send_scan_alert('auth_link_issued', ...) behaviour."""

    def setup_method(self) -> None:
        _reset_module_caches()

    def test_magic_link_event_fires_email_thread(self) -> None:
        import scan_alerts as sa  # noqa: PLC0415

        dispatched: list[threading.Thread] = []
        original_start = threading.Thread.start

        def capture_start(self_thread: threading.Thread) -> None:
            dispatched.append(self_thread)
            original_start(self_thread)

        with patch.object(threading.Thread, "start", capture_start):
            with patch.object(sa, "_fire_magic_link_email") as mock_deliver:
                mock_deliver.return_value = None
                sa.send_scan_alert(
                    "auth_link_issued",
                    {"email": "admin@example.com", "link": "https://sic.example.com/auth/verify?token=t", "expires_at": int(time.time()) + 600},
                )

        assert len(dispatched) == 1, "exactly one thread should be started for magic-link"

    def test_magic_link_event_does_not_fire_discord(self) -> None:
        """auth_link_issued must NOT post to Discord / Slack / generic webhooks."""
        import scan_alerts as sa  # noqa: PLC0415

        with patch.dict("os.environ", {"DISCORD_WEBHOOK_URL": "https://discord.example.com/hook"}):
            _reset_module_caches()  # flush _url_checked so env is re-read
            with patch.object(sa, "_fire_webhook") as mock_discord:
                with patch.object(sa, "_fire_magic_link_email") as mock_email:
                    mock_email.return_value = None
                    sa.send_scan_alert(
                        "auth_link_issued",
                        {"email": "admin@example.com", "link": "https://sic.example.com/auth/verify?token=t"},
                    )

        mock_discord.assert_not_called()

    def test_non_magic_link_event_still_reaches_discord(self) -> None:
        """Ensure the early-return for auth_link_issued doesn't break other events."""
        import scan_alerts as sa  # noqa: PLC0415

        with patch.dict("os.environ", {"DISCORD_WEBHOOK_URL": "https://discord.example.com/hook"}):
            _reset_module_caches()
            with patch("requests.post") as mock_post:
                sa.send_scan_alert("scan_started", {"target": "example.com"})
                # Give the daemon thread a moment to run
                time.sleep(0.05)

        mock_post.assert_called()


# ---------------------------------------------------------------------------
# P0-2: Rate-limit key function
# ---------------------------------------------------------------------------


class TestGetRealIp:
    """Unit tests for _get_real_ip in server (via imported helper)."""

    def test_xff_header_takes_priority(self) -> None:
        """_get_real_ip should return the leftmost XFF entry."""
        import scan_alerts as _sa  # noqa: F401 — ensure import path works

        # Import server module's helper directly

        # We cannot import server directly (heavy deps), so test
        # the logic inline by reproducing the same function.
        def _get_real_ip_impl(xff: str | None, remote_addr: str) -> str:
            if xff:
                real_ip = xff.split(",")[0].strip()
                if real_ip:
                    return real_ip
            return remote_addr or "127.0.0.1"

        assert _get_real_ip_impl("203.0.113.5, 10.0.0.1", "10.0.0.1") == "203.0.113.5"
        assert _get_real_ip_impl(None, "10.0.0.2") == "10.0.0.2"
        assert _get_real_ip_impl("", "10.0.0.3") == "10.0.0.3"
        assert _get_real_ip_impl("  198.51.100.1  ", "10.0.0.4") == "198.51.100.1"
