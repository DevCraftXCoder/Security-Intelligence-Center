#!/usr/bin/env python3
"""Patch hexstrike_server.py to add /assets/ route for serving static logo/image files."""

import pathlib

srv = pathlib.Path("/app/hexstrike_server.py")
txt = srv.read_text(encoding="utf-8")

# Check if already patched
if "@app.route('/assets/<path:filename>')" in txt:
    print("[patch_assets_route] Already applied — skipping.")
else:
    # Insert the /assets/ route right after the dashboard route function
    old = (
        "    return send_from_directory('/app/dashboard', filename)\n"
        "\n"
        "if __name__ == \"__main__\":"
    )
    new = (
        "    return send_from_directory('/app/dashboard', filename)\n"
        "\n"
        "\n"
        "@app.route('/assets/<path:filename>')\n"
        "def serve_assets(filename):\n"
        "    \"\"\"Serve static assets (logo, images) from /app/assets/.\"\"\"\n"
        "    from flask import send_from_directory as _sfd\n"
        "    return _sfd('/app/assets', filename)\n"
        "\n"
        "\n"
        "if __name__ == \"__main__\":"
    )
    if old not in txt:
        print("[patch_assets_route] ERROR: anchor not found — inspect hexstrike_server.py manually.")
    else:
        txt = txt.replace(old, new, 1)
        srv.write_text(txt, encoding="utf-8")
        print("[patch_assets_route] Done — /assets/ route added.")
