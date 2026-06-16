"""SAML 2.0 SP helpers — wraps python3-saml with lazy import.

Public API:
    build_authn_request(idp_config, sp_config) -> (redirect_url: str, request_id: str)
    process_response(saml_response_b64, idp_config, sp_config) -> email: str
    get_metadata_xml(sp_config) -> xml: str
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Lazy import guard
# ---------------------------------------------------------------------------

_saml_available: bool | None = None
_OneLogin_Saml2_Auth: Any = None
_OneLogin_Saml2_Settings: Any = None
_OneLogin_Saml2_Utils: Any = None


def _check_saml() -> bool:
    global _saml_available, _OneLogin_Saml2_Auth, _OneLogin_Saml2_Settings, _OneLogin_Saml2_Utils
    if _saml_available is not None:
        return _saml_available
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth as _Auth  # noqa: PLC0415
        from onelogin.saml2.settings import OneLogin_Saml2_Settings as _Settings  # noqa: PLC0415
        from onelogin.saml2.utils import OneLogin_Saml2_Utils as _Utils  # noqa: PLC0415

        _OneLogin_Saml2_Auth = _Auth
        _OneLogin_Saml2_Settings = _Settings
        _OneLogin_Saml2_Utils = _Utils
        _saml_available = True
        logger.debug("python3-saml loaded successfully")
    except ImportError:
        _saml_available = False
        logger.warning(
            "python3-saml not installed — SAML SSO unavailable. "
            "Install with: pip install python3-saml>=1.16.0"
        )
    return _saml_available


# ---------------------------------------------------------------------------
# SP / IdP config builders
# ---------------------------------------------------------------------------


def _build_settings(idp_config: dict[str, Any], sp_config: dict[str, Any]) -> dict[str, Any]:
    """Build the python3-saml settings dict from our DB row + SP env config."""
    base_url = sp_config["base_url"].rstrip("/")
    workspace_id = sp_config["workspace_id"]

    saml_settings: dict[str, Any] = {
        "strict": True,  # enforce NotBefore / NotOnOrAfter, audience, etc.
        "debug": os.environ.get("SIC_SAML_DEBUG", "").lower() in ("1", "true"),
        "sp": {
            "entityId": f"{base_url}/auth/sso/metadata/{workspace_id}",
            "assertionConsumerService": {
                "url": f"{base_url}/auth/sso/callback/saml/{workspace_id}",
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            # SP private key / cert are optional for unsigned requests
            "x509cert": sp_config.get("sp_x509cert", ""),
            "privateKey": sp_config.get("sp_private_key", ""),
        },
        "idp": {
            "entityId": idp_config.get("idp_entity_id", ""),
            "singleSignOnService": {
                "url": idp_config.get("idp_sso_url", ""),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": _strip_cert(idp_config.get("idp_x509_cert", "")),
        },
        "security": {
            "nameIdEncrypted": False,
            "authnRequestsSigned": bool(sp_config.get("sp_private_key")),
            "logoutRequestSigned": False,
            "logoutResponseSigned": False,
            "signMetadata": False,
            "wantMessagesSigned": True,    # require signed responses
            "wantAssertionsSigned": True,  # require signed assertions
            "wantAssertionsEncrypted": False,
            "wantNameId": True,
            "wantNameIdEncrypted": False,
            "wantAttributeStatement": True,
            "requestedAuthnContext": False,
            "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }
    return saml_settings


def _strip_cert(cert: str) -> str:
    """Remove PEM headers/footers and whitespace — python3-saml wants raw base64."""
    cert = cert.strip()
    for header in ("-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"):
        cert = cert.replace(header, "")
    return cert.replace("\n", "").replace("\r", "").replace(" ", "")


# ---------------------------------------------------------------------------
# Mock Flask request builder for python3-saml
# ---------------------------------------------------------------------------


def _build_request_dict(
    *,
    method: str = "GET",
    query_string: str = "",
    post_data: dict[str, Any] | None = None,
    base_url: str,
    path: str,
) -> dict[str, Any]:
    """Build the request dict python3-saml expects."""
    return {
        "https": "on" if base_url.startswith("https://") else "off",
        "http_host": base_url.split("://", 1)[-1].rstrip("/"),
        "script_name": path,
        "get_data": {},
        "post_data": post_data or {},
        "query_string": query_string,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_authn_request(
    idp_config: dict[str, Any],
    sp_config: dict[str, Any],
) -> tuple[str, str]:
    """Build a SAML AuthnRequest. Returns (redirect_url, request_id).

    Raises RuntimeError if python3-saml is not installed.
    """
    if not _check_saml():
        raise RuntimeError(
            "python3-saml is not installed. Run: pip install python3-saml>=1.16.0"
        )
    settings_data = _build_settings(idp_config, sp_config)
    workspace_id = sp_config["workspace_id"]
    base_url = sp_config["base_url"].rstrip("/")

    req = _build_request_dict(
        method="GET",
        base_url=base_url,
        path="/auth/sso/login",
    )
    auth = _OneLogin_Saml2_Auth(req, settings_data)  # type: ignore[operator]
    redirect_url = auth.login()
    request_id = auth.get_last_request_id()
    logger.info(
        "SAML AuthnRequest built for workspace=%s request_id=%s",
        workspace_id,
        request_id,
    )
    return redirect_url, request_id


def process_response(
    saml_response_b64: str,
    idp_config: dict[str, Any],
    sp_config: dict[str, Any],
    relay_state: str | None = None,
    request_id: str | None = None,
) -> str:
    """Consume and validate a SAMLResponse. Returns the asserted email.

    Args:
        saml_response_b64: Base64-encoded SAMLResponse from the IdP POST.
        idp_config: Workspace IdP configuration dict.
        sp_config: SP configuration dict (base_url, workspace_id, etc.).
        relay_state: Optional RelayState from the POST body. Must be a safe
            relative path if provided.
        request_id: Optional AuthnRequest ID from the originating login request.
            When provided, python3-saml enforces InResponseTo binding, preventing
            unsolicited-response and replay attacks.  Pass None only when the
            originating request_id is unavailable (degrades to permissive mode).

    Raises ValueError on any validation failure (signature, timing, audience,
    domain, etc.).
    Raises RuntimeError if python3-saml is not installed.
    """
    if not _check_saml():
        raise RuntimeError(
            "python3-saml is not installed. Run: pip install python3-saml>=1.16.0"
        )

    # Validate RelayState is not obviously tampered (must be a safe path string)
    if relay_state is not None:
        _validate_relay_state(relay_state)

    settings_data = _build_settings(idp_config, sp_config)
    base_url = sp_config["base_url"].rstrip("/")
    workspace_id = sp_config["workspace_id"]

    req = _build_request_dict(
        method="POST",
        base_url=base_url,
        path=f"/auth/sso/callback/saml/{workspace_id}",
        post_data={"SAMLResponse": saml_response_b64},
    )

    auth = _OneLogin_Saml2_Auth(req, settings_data)  # type: ignore[operator]
    # Pass request_id for InResponseTo binding (python3-saml >= 1.16.0).
    # When request_id is None the library skips InResponseTo enforcement —
    # this preserves backwards compatibility but is less secure.
    auth.process_response(request_id=request_id)
    errors = auth.get_errors()
    if errors:
        reason = auth.get_last_error_reason() or str(errors)
        logger.warning("SAML response validation failed workspace=%s: %s", workspace_id, reason)
        raise ValueError(f"SAML validation failed: {reason}")

    if not auth.is_authenticated():
        raise ValueError("SAML response: not authenticated")

    # Extract email — prefer NameID (formatted as emailAddress) then attributes
    email: str | None = auth.get_nameid()
    if not email:
        attrs = auth.get_attributes()
        for key in (
            "email",
            "mail",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
            "urn:oid:1.2.840.113549.1.9.1",
        ):
            vals = attrs.get(key)
            if vals:
                email = vals[0] if isinstance(vals, list) else vals
                break

    if not email or "@" not in email:
        raise ValueError("SAML response: no valid email address in assertion")

    email = email.strip().lower()

    # Enforce allowed_email_domains if configured
    domains_raw = idp_config.get("allowed_email_domains")
    if domains_raw:
        _check_email_domain(email, domains_raw)

    logger.info("SAML assertion accepted workspace=%s email_domain=%s", workspace_id, email.split("@")[1])
    return email


def get_metadata_xml(sp_config: dict[str, Any], idp_config: dict[str, Any]) -> str:
    """Return SP metadata XML for the given workspace.

    Raises RuntimeError if python3-saml is not installed.
    """
    if not _check_saml():
        raise RuntimeError(
            "python3-saml is not installed. Run: pip install python3-saml>=1.16.0"
        )
    settings_data = _build_settings(idp_config, sp_config)
    settings_obj = _OneLogin_Saml2_Settings(settings_data, sp_validation_only=True)  # type: ignore[operator]
    metadata = settings_obj.get_sp_metadata()
    errors = settings_obj.validate_metadata(metadata)
    if errors:
        logger.warning("SP metadata validation warnings: %s", errors)
    return metadata.decode("utf-8") if isinstance(metadata, bytes) else metadata


# ---------------------------------------------------------------------------
# Internal validators
# ---------------------------------------------------------------------------


def _validate_relay_state(relay_state: str) -> None:
    """Reject RelayState values that look like open-redirect payloads."""
    if len(relay_state) > 2048:
        raise ValueError("RelayState too long")
    # Only allow relative paths or same-origin URLs beginning with /
    stripped = relay_state.strip()
    if stripped and not stripped.startswith("/"):
        raise ValueError(f"RelayState must be a relative path, got: {stripped[:80]!r}")


def _check_email_domain(email: str, domains_raw: str) -> None:
    """Raise ValueError if email's domain is not in the allowed list."""
    allowed = {d.strip().lower() for d in domains_raw.split(",") if d.strip()}
    if not allowed:
        return
    domain = email.split("@", 1)[1]
    if domain not in allowed:
        raise ValueError(
            f"Email domain {domain!r} not in allowed domains for this workspace"
        )
