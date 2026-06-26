"""guards.py — Shared production startup guards for all SIC entrypoints.

Imported by billing_server.py, hexstrike_server.py, and mcp_server.py.
Fails hard (sys.exit(1)) if SIC_ENV=production and required safety vars are missing.
"""

from __future__ import annotations

import os
import sys


def _is_production() -> bool:
    return os.environ.get("SIC_ENV", "development").strip().lower() == "production"


def _waitlist_open() -> bool:
    return os.environ.get("SIC_WAITLIST_MODE", "").strip().lower() in ("open", "1", "true")


def run_production_startup_guards(server_name: str = "sic") -> None:
    """Refuse to start in production when required safety settings are missing."""
    if not _is_production():
        return

    errors: list[str] = []

    # Guard 1: signing secret must be explicitly set
    if not (
        os.environ.get("SIC_SECRET_KEY", "").strip()
        or os.environ.get("SIC_AUTH_SECRET", "").strip()
    ):
        errors.append(
            "SIC_SECRET_KEY (or SIC_AUTH_SECRET) is not set. In production the "
            "HMAC signing secret must be provided explicitly so sessions and "
            "magic links survive restarts and are stable across processes."
        )

    # Guard 2: BILLING_API_KEY must be set
    if not os.environ.get("BILLING_API_KEY", "").strip():
        errors.append(
            "BILLING_API_KEY is not set. In production the public-checkout / "
            "public-trial / portal-by-email endpoints require it for M2M auth."
        )

    # Guard 3: waitlist must be off
    if _waitlist_open():
        errors.append(
            "SIC_WAITLIST_MODE is open. Waitlist mode lets any email request a "
            "magic link regardless of subscription — it must be off in "
            "production. Unset SIC_WAITLIST_MODE or set it to 'off'."
        )

    # Guard 4: SIC_BASE_URL must be set so provisioning emails contain a reachable link
    if not os.environ.get("SIC_BASE_URL", "").strip():
        errors.append(
            "SIC_BASE_URL is not set. In production this must be the publicly "
            "accessible origin of the SIC instance so provisioning emails "
            "contain a reachable activation link."
        )

    if errors:
        sys.stderr.write(
            f"[{server_name} FATAL] Refusing to start in production — "
            "the following safety guards failed:\n"
        )
        for e in errors:
            sys.stderr.write(f"  - {e}\n")
        sys.stderr.flush()
        sys.exit(1)
