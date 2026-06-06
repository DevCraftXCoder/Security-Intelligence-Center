# SIC Changelog

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
