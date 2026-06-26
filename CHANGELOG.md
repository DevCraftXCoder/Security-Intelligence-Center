# SIC Changelog

## 7.0.0 — 2026-06-26

### Changed
- **Distribution split:** `sic-security` npm package is now scanner-only (free, MIT).
  The full platform (dashboard, MCP 85-tool suite, reporting pipeline, billing, auth)
  remains private — delivered from this repo, not from npm.
- `bin/sic.js` in the public package no longer launches the server. `npx sic-security`
  and `npx sic-security scan` both invoke the static scanner only.
- `scan_python.py` published verbatim to the public repo as the canonical free scanner.
- `package.json` `files` manifest trimmed to 7 entries — no server code ships in the
  public npm tarball.

### Fixed
- Prior npm release (`6.0.6`) shipped the full server codebase in its tarball.
  v7.0.0 closes the leak.

---

## 6.0.1 — 2026-06-06

### Fixed
- Republish with the current production dashboard bundle (`dashboard/*.{html,js,css}`) and production-readiness pass from 6.0.0. Synced reported version across `package.json`, launcher banner, and `/health` server version.

## 6.0.0-beta.1 — 2026-05-01

### Added
- npm package wrapper (`npx sic-security@beta`) — Python 3.8+ auto-detected at runtime
- Terminal logo banner on startup (ASCII art, red/bold; skipped when launched via npx to avoid double-print)
- `SIC_LOGO_PATH` env var — point to a custom PNG/SVG to override the default logo path
- `POST /api/logo` — upload a custom SVG or PNG logo (2 MB max, magic-byte validated)
- `GET /logo-upload` — browser UI for drag-and-drop logo replacement

### Fixed
- Windows-compatible launcher stubs for selenium, mitmproxy, pwntools, angr
