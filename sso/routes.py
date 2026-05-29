"""SSO Flask blueprint — SAML 2.0 + OIDC routes.

Routes:
    GET  /auth/sso/login?workspace=<id>                 — initiate SSO login
    POST /auth/sso/callback/saml/<workspace_id>         — consume SAMLResponse
    GET  /auth/sso/callback/oidc/<workspace_id>         — consume OIDC code
    GET  /auth/sso/metadata/<workspace_id>              — serve SP metadata XML
    GET  /api/sso/configs                               — list configs (admin)
    POST /api/sso/configs                               — create/update config (admin)
    DELETE /api/sso/configs/<workspace_id>              — disable config (admin)
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
import time
from typing import Any

from flask import (
    Blueprint,
    jsonify,
    redirect,
    request,
)

from .db import disable_config, get_config, list_configs, upsert_config

logger = logging.getLogger(__name__)

sso_bp = Blueprint("sic_sso", __name__)

# ---------------------------------------------------------------------------
# Feature-gate: require feature_gates to be importable — fail CLOSED if not.
# ---------------------------------------------------------------------------
try:
    from feature_gates import require_tier as _require_tier  # noqa: PLC0415

    _tier_decorator = _require_tier("studio")
    logger.debug("feature_gates loaded — SSO routes will be gated behind studio tier")
except ImportError as _fg_err:
    # Fail closed: if feature_gates is not importable the server must not start
    # with SSO routes accessible to all tiers.  Raise immediately so the caller
    # (server.py Phase 5 blueprint registration) sees the error.
    raise RuntimeError(
        "feature_gates module is required for SSO tier enforcement but could not be "
        f"imported: {_fg_err}.  Ensure feature_gates.py is on sys.path before "
        "registering the SSO blueprint."
    ) from _fg_err


def _studio_gated(f):
    """Wrap *f* with the studio-tier gate from feature_gates.require_tier."""
    return _tier_decorator(f)


# ---------------------------------------------------------------------------
# Auth decorator (from parent auth module)
# ---------------------------------------------------------------------------
try:
    from auth import require_auth as _require_auth  # noqa: PLC0415
except ImportError:
    # Fallback — should never happen in a live deployment, but keeps module importable
    def _require_auth(f):  # type: ignore[misc]
        return f

    logger.warning("auth module not found — SSO admin routes will be unprotected")


# ---------------------------------------------------------------------------
# SP config helper
# ---------------------------------------------------------------------------


def _sp_config(workspace_id: str) -> dict[str, Any]:
    base_url = os.environ.get("SIC_SSO_BASE_URL", "http://localhost:8888").rstrip("/")
    return {
        "workspace_id": workspace_id,
        "base_url": base_url,
        "sp_x509cert": os.environ.get("SIC_SAML_SP_CERT", ""),
        "sp_private_key": os.environ.get("SIC_SAML_SP_KEY", ""),
    }


# ---------------------------------------------------------------------------
# CSRF / OIDC state cookie helpers
# ---------------------------------------------------------------------------

_STATE_COOKIE_PREFIX = "sic_sso_state_"
_STATE_TTL = 600  # 10 minutes


def _make_state_cookie_name(workspace_id: str) -> str:
    wid_hash = hashlib.sha256(workspace_id.encode()).hexdigest()[:12]
    return f"{_STATE_COOKIE_PREFIX}{wid_hash}"


def _set_state_cookie(response, workspace_id: str, state: str, nonce: str) -> None:
    """Persist OIDC state+nonce in an HttpOnly cookie for CSRF protection."""
    value = f"{state}:{nonce}:{int(time.time())}"
    response.set_cookie(
        _make_state_cookie_name(workspace_id),
        value,
        max_age=_STATE_TTL,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
        path="/",
    )


def _verify_state_cookie(workspace_id: str, state_param: str) -> str | None:
    """Verify OIDC state param against cookie. Returns nonce if valid, else None."""
    cookie_val = request.cookies.get(_make_state_cookie_name(workspace_id))
    if not cookie_val:
        return None
    parts = cookie_val.split(":", 2)
    if len(parts) != 3:
        return None
    stored_state, nonce, issued_at_s = parts
    try:
        issued_at = int(issued_at_s)
    except ValueError:
        return None
    if time.time() - issued_at > _STATE_TTL:
        return None
    import hmac as _hmac  # noqa: PLC0415

    if not _hmac.compare_digest(stored_state, state_param):
        return None
    return nonce


def _clear_state_cookie(response, workspace_id: str) -> None:
    response.set_cookie(
        _make_state_cookie_name(workspace_id), "", max_age=0,
        httponly=True, samesite="Lax", secure=request.is_secure, path="/",
    )


# ---------------------------------------------------------------------------
# Session-cookie minting (replicates auth.py HMAC pattern)
# ---------------------------------------------------------------------------


def _mint_session(email: str) -> str:
    """Mint a session token identical to auth.py's _make_token."""
    # Import private helpers from auth if available (no public _mint_session yet)
    try:
        from auth import _make_token, _SESSION_TTL_SEC  # noqa: PLC0415

        now = int(time.time())
        return _make_token(email, now, now + _SESSION_TTL_SEC)
    except ImportError:
        pass

    # Fallback: replicate the HMAC pattern manually
    import base64  # noqa: PLC0415
    import hashlib  # noqa: PLC0415
    import hmac as _hmac  # noqa: PLC0415

    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    def _get_secret() -> bytes:
        env_val = os.environ.get("SIC_AUTH_SECRET")
        if env_val:
            return env_val.encode()
        key_path = os.path.join(os.path.expanduser("~"), ".sic", "auth.key")
        try:
            with open(key_path, "rb") as fh:
                return fh.read()
        except OSError:
            raise RuntimeError(
                "SIC_AUTH_SECRET env var not set and ~/.sic/auth.key not found. "
                "Cannot mint session cookie."
            )

    _SESSION_TTL = 30 * 86400
    now = int(time.time())
    expires_at = now + _SESSION_TTL
    payload_str = f"{email}|{now}|{expires_at}"
    payload_b64 = _b64url_encode(payload_str.encode())
    secret = _get_secret()
    sig = _hmac.new(secret, payload_b64.encode(), hashlib.sha256).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{payload_b64}.{sig_b64}"


_COOKIE_NAME = "sic_session"
_SESSION_TTL_SEC = 30 * 86400


def _set_session_cookie(response, email: str) -> None:
    token = _mint_session(email)
    response.set_cookie(
        _COOKIE_NAME,
        token,
        max_age=_SESSION_TTL_SEC,
        httponly=True,
        samesite="Lax",
        secure=request.is_secure,
        path="/",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@sso_bp.get("/auth/sso/login")
@_studio_gated
def sso_login():
    """Redirect user to IdP login. workspace= query param required.

    # TODO: gate behind studio tier — apply @require_tier("studio") once feature_gates is on path
    """
    workspace_id = request.args.get("workspace", "").strip()
    if not workspace_id:
        return jsonify({"error": "workspace_required"}), 400

    idp_config = get_config(workspace_id)
    if not idp_config:
        return jsonify({"error": "sso_not_configured", "workspace": workspace_id}), 404

    protocol = idp_config.get("protocol")
    sp_cfg = _sp_config(workspace_id)

    if protocol == "saml":
        try:
            from .saml_handler import build_authn_request  # noqa: PLC0415
        except ImportError:
            return jsonify({"error": "saml_handler_unavailable"}), 500

        try:
            redirect_url, _request_id = build_authn_request(idp_config, sp_cfg)
        except RuntimeError as exc:
            return (
                jsonify({"error": "saml_unavailable", "hint": str(exc)}),
                501,
            )
        except Exception as exc:
            logger.exception("Error building SAML AuthnRequest workspace=%s", workspace_id)
            return jsonify({"error": "saml_error", "detail": str(exc)}), 500

        return redirect(redirect_url)

    elif protocol == "oidc":
        try:
            from .oidc_handler import build_authorize_url  # noqa: PLC0415
        except ImportError:
            return jsonify({"error": "oidc_handler_unavailable"}), 500

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        try:
            authorize_url = build_authorize_url(idp_config, sp_cfg, state, nonce)
        except RuntimeError as exc:
            return (
                jsonify({"error": "oidc_unavailable", "hint": str(exc)}),
                501,
            )
        except Exception as exc:
            logger.exception("Error building OIDC authorize URL workspace=%s", workspace_id)
            return jsonify({"error": "oidc_error", "detail": str(exc)}), 500

        resp = redirect(authorize_url)
        _set_state_cookie(resp, workspace_id, state, nonce)
        return resp

    else:
        return jsonify({"error": "unsupported_protocol", "protocol": protocol}), 400


@sso_bp.post("/auth/sso/callback/saml/<workspace_id>")
@_studio_gated
def saml_callback(workspace_id: str):
    """Consume SAMLResponse, validate, mint session cookie, redirect to /dashboard.

    # TODO: gate behind studio tier — apply @require_tier("studio") once feature_gates is on path
    """
    idp_config = get_config(workspace_id)
    if not idp_config:
        return jsonify({"error": "sso_not_configured", "workspace": workspace_id}), 404

    saml_response = request.form.get("SAMLResponse", "")
    if not saml_response:
        return jsonify({"error": "missing_saml_response"}), 400

    relay_state = request.form.get("RelayState")

    try:
        from .saml_handler import process_response  # noqa: PLC0415
    except ImportError:
        return jsonify({"error": "saml_handler_unavailable"}), 500

    sp_cfg = _sp_config(workspace_id)

    try:
        email = process_response(saml_response, idp_config, sp_cfg, relay_state=relay_state)
    except RuntimeError as exc:
        return jsonify({"error": "saml_unavailable", "hint": str(exc)}), 501
    except ValueError as exc:
        logger.warning("SAML validation error workspace=%s: %s", workspace_id, exc)
        return jsonify({"error": "saml_validation_failed", "detail": str(exc)}), 401
    except Exception:
        logger.exception("Unexpected SAML error workspace=%s", workspace_id)
        return jsonify({"error": "saml_error"}), 500

    # Determine redirect target (safe relative path only)
    redirect_to = "/dashboard/"
    if relay_state and relay_state.startswith("/"):
        redirect_to = relay_state

    resp = redirect(redirect_to)
    _set_session_cookie(resp, email)
    logger.info("SSO SAML login success workspace=%s email_domain=%s", workspace_id, email.split("@")[1])
    return resp


@sso_bp.get("/auth/sso/callback/oidc/<workspace_id>")
@_studio_gated
def oidc_callback(workspace_id: str):
    """Consume OIDC authorization code, validate ID token, mint session cookie.

    # TODO: gate behind studio tier — apply @require_tier("studio") once feature_gates is on path
    """
    # Check for error from IdP
    error = request.args.get("error")
    if error:
        error_desc = request.args.get("error_description", "")
        logger.warning(
            "OIDC error from IdP workspace=%s error=%s desc=%s",
            workspace_id, error, error_desc,
        )
        return jsonify({"error": "idp_error", "idp_error": error, "description": error_desc}), 401

    code = request.args.get("code", "").strip()
    state_param = request.args.get("state", "")

    if not code:
        return jsonify({"error": "missing_code"}), 400
    if not state_param:
        return jsonify({"error": "missing_state"}), 400

    # CSRF: verify state against cookie
    nonce = _verify_state_cookie(workspace_id, state_param)
    if nonce is None:
        logger.warning(
            "OIDC state mismatch workspace=%s — possible CSRF", workspace_id
        )
        return jsonify({"error": "state_mismatch"}), 401

    idp_config = get_config(workspace_id)
    if not idp_config:
        return jsonify({"error": "sso_not_configured", "workspace": workspace_id}), 404

    try:
        from .oidc_handler import exchange_code  # noqa: PLC0415
    except ImportError:
        return jsonify({"error": "oidc_handler_unavailable"}), 500

    sp_cfg = _sp_config(workspace_id)

    try:
        claims = exchange_code(code, idp_config, sp_cfg, nonce=nonce)
    except RuntimeError as exc:
        return jsonify({"error": "oidc_unavailable", "hint": str(exc)}), 501
    except ValueError as exc:
        logger.warning("OIDC validation error workspace=%s: %s", workspace_id, exc)
        return jsonify({"error": "oidc_validation_failed", "detail": str(exc)}), 401
    except Exception:
        logger.exception("Unexpected OIDC error workspace=%s", workspace_id)
        return jsonify({"error": "oidc_error"}), 500

    email = claims.get("email", "")
    resp = redirect("/dashboard/")
    _set_session_cookie(resp, email)
    _clear_state_cookie(resp, workspace_id)
    logger.info("SSO OIDC login success workspace=%s email_domain=%s", workspace_id, email.split("@")[1])
    return resp


@sso_bp.get("/auth/sso/metadata/<workspace_id>")
def saml_metadata(workspace_id: str):
    """Serve SP SAML metadata XML. Public — IdPs need this for configuration.

    # TODO: gate behind studio tier — apply @require_tier("studio") once feature_gates is on path
    """
    idp_config = get_config(workspace_id)
    if not idp_config:
        return jsonify({"error": "sso_not_configured", "workspace": workspace_id}), 404

    if idp_config.get("protocol") != "saml":
        return jsonify({"error": "workspace_not_saml"}), 400

    try:
        from .saml_handler import get_metadata_xml  # noqa: PLC0415
    except ImportError:
        return jsonify({"error": "saml_handler_unavailable"}), 500

    sp_cfg = _sp_config(workspace_id)

    try:
        xml = get_metadata_xml(sp_cfg, idp_config)
    except RuntimeError as exc:
        return jsonify({"error": "saml_unavailable", "hint": str(exc)}), 501
    except Exception:
        logger.exception("Error generating SP metadata workspace=%s", workspace_id)
        return jsonify({"error": "metadata_error"}), 500

    from flask import Response  # noqa: PLC0415

    return Response(xml, mimetype="application/xml")


# ---------------------------------------------------------------------------
# Admin API — list / create / delete SSO configs
# ---------------------------------------------------------------------------


@sso_bp.get("/api/sso/configs")
@_require_auth
@_studio_gated
def list_sso_configs():
    """List all SSO configs (admin only). Secrets are redacted.

    # TODO: gate behind studio tier — apply @require_tier("studio") once feature_gates is on path
    """
    configs = list_configs()
    return jsonify({"configs": configs}), 200


@sso_bp.post("/api/sso/configs")
@_require_auth
@_studio_gated
def create_sso_config():
    """Create or update the SSO config for a workspace (admin only).

    Body (JSON):
        workspace_id         str  required
        protocol             str  "saml" | "oidc"  required
        idp_metadata_url     str  optional
        idp_entity_id        str  optional (SAML)
        idp_sso_url          str  optional (SAML)
        idp_x509_cert        str  optional (SAML)
        oidc_client_id       str  optional (OIDC)
        oidc_client_secret   str  optional (OIDC)
        oidc_discovery_url   str  optional (OIDC)
        allowed_email_domains str optional, comma-separated

    # TODO: gate behind studio tier — apply @require_tier("studio") once feature_gates is on path
    """
    body = request.get_json(silent=True) or {}

    workspace_id = body.get("workspace_id", "").strip()
    if not workspace_id:
        return jsonify({"error": "workspace_id_required"}), 400

    protocol = body.get("protocol", "").strip().lower()
    if protocol not in ("saml", "oidc"):
        return jsonify({"error": "protocol_must_be_saml_or_oidc"}), 400

    # Protocol-specific validation
    if protocol == "saml":
        if not body.get("idp_sso_url"):
            return jsonify({"error": "idp_sso_url_required_for_saml"}), 400
        if not body.get("idp_x509_cert"):
            return jsonify({"error": "idp_x509_cert_required_for_saml"}), 400
    elif protocol == "oidc":
        if not body.get("oidc_discovery_url"):
            return jsonify({"error": "oidc_discovery_url_required_for_oidc"}), 400
        if not body.get("oidc_client_id"):
            return jsonify({"error": "oidc_client_id_required_for_oidc"}), 400
        if not body.get("oidc_client_secret"):
            return jsonify({"error": "oidc_client_secret_required_for_oidc"}), 400

    try:
        saved = upsert_config(
            workspace_id=workspace_id,
            protocol=protocol,
            idp_metadata_url=body.get("idp_metadata_url"),
            idp_entity_id=body.get("idp_entity_id"),
            idp_sso_url=body.get("idp_sso_url"),
            idp_x509_cert=body.get("idp_x509_cert"),
            oidc_client_id=body.get("oidc_client_id"),
            oidc_client_secret=body.get("oidc_client_secret"),
            oidc_discovery_url=body.get("oidc_discovery_url"),
            allowed_email_domains=body.get("allowed_email_domains"),
        )
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        logger.exception("Error upserting SSO config workspace=%s", workspace_id)
        return jsonify({"error": "internal_error"}), 500

    logger.info("SSO config saved workspace=%s protocol=%s", workspace_id, protocol)
    return jsonify({"ok": True, "config": saved}), 200


@sso_bp.delete("/api/sso/configs/<workspace_id>")
@_require_auth
@_studio_gated
def delete_sso_config(workspace_id: str):
    """Disable SSO for a workspace (soft delete). Admin only.

    # TODO: gate behind studio tier — apply @require_tier("studio") once feature_gates is on path
    """
    affected = disable_config(workspace_id)
    if not affected:
        return jsonify({"error": "not_found"}), 404
    logger.info("SSO config disabled workspace=%s", workspace_id)
    return jsonify({"ok": True}), 200
