#!/usr/bin/env python3
"""
HexStrike AI — Windows-compatible launcher.
Stubs heavy optional dependencies (selenium, mitmproxy, pwntools, angr)
so the core Flask API server boots without them.
"""

import os
import sys
import types

# Stub modules that are imported at top-level but not needed for core API
STUB_MODULES = [
    "selenium", "selenium.webdriver", "selenium.webdriver.chrome",
    "selenium.webdriver.chrome.options", "selenium.webdriver.common",
    "selenium.webdriver.common.by", "selenium.webdriver.support",
    "selenium.webdriver.support.ui", "selenium.webdriver.support.expected_conditions",
    "selenium.common", "selenium.common.exceptions",
    "mitmproxy", "mitmproxy.http", "mitmproxy.tools", "mitmproxy.tools.dump",
    "mitmproxy.options",
    "pwn", "pwnlib",
    "angr",
]


class _StubModule(types.ModuleType):
    """Returns a no-op for any attribute access so import chains don't crash."""

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return _StubModule(f"{self.__name__}.{name}")

    def __call__(self, *args, **kwargs):
        return None

    def __bool__(self):
        return False


for mod_name in STUB_MODULES:
    if mod_name not in sys.modules:
        sys.modules[mod_name] = _StubModule(mod_name)

# ---------------------------------------------------------------------------
# H7: Load .env before spawning hexstrike_server — ensures SIC_SECRET_KEY,
# SIC_ADMIN_EMAILS, and friends are set when launched via the npx entrypoint,
# which does not load the environment itself.
# ---------------------------------------------------------------------------
_ENV_PATH = os.path.join(os.path.expanduser("~"), ".sic-security", ".env")
_FALLBACK_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

def _load_dotenv() -> None:
    """Load .env from ~/.sic-security/.env, falling back to the project .env."""
    _candidate = _ENV_PATH if os.path.exists(_ENV_PATH) else (
        _FALLBACK_ENV_PATH if os.path.exists(_FALLBACK_ENV_PATH) else None
    )
    if _candidate is None:
        return  # No .env found — operator must pass vars via shell env

    try:
        from dotenv import load_dotenv as _ld  # type: ignore[import-untyped]
        _ld(_candidate, override=False)  # override=False: shell env wins
    except ImportError:
        # python-dotenv not installed — parse manually (key=value, no spaces around =)
        try:
            with open(_candidate, encoding="utf-8") as _fh:
                for _line in _fh:
                    _line = _line.strip()
                    if not _line or _line.startswith("#") or "=" not in _line:
                        continue
                    _k, _, _v = _line.partition("=")
                    _k = _k.strip()
                    _v = _v.strip().strip('"').strip("'")
                    if _k and _k not in os.environ:
                        os.environ[_k] = _v
        except OSError:
            pass

_load_dotenv()

# Stub specific names that hexstrike_server.py imports directly
# selenium.common.exceptions exports
_exc_stub = sys.modules["selenium.common.exceptions"]
_exc_stub.TimeoutException = type("TimeoutException", (Exception,), {})
_exc_stub.WebDriverException = type("WebDriverException", (Exception,), {})

# mitmproxy aliases
sys.modules["mitmproxy.http"].HTTPFlow = type("HTTPFlow", (), {})
sys.modules["mitmproxy.tools.dump"].DumpMaster = type("DumpMaster", (), {})
sys.modules["mitmproxy.options"].Options = type("Options", (), {"__init__": lambda self, **kw: None})

# ── Terminal logo banner ──────────────────────────────────────────────────────
def _print_banner():
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    # Custom logo path (set by npx wrapper / user env) is consumed by the
    # Node.js banner; the Python banner below is ASCII-only.
    _ = os.environ.get("SIC_LOGO_PATH", "")

    banner = f"""
{RED}{BOLD}  ███████╗██╗ ██████╗{RESET}
{RED}{BOLD}  ██╔════╝██║██╔════╝{RESET}
{RED}{BOLD}  ███████╗██║██║     {RESET}
{RED}{BOLD}  ╚════██║██║██║     {RESET}
{RED}{BOLD}  ███████║██║╚██████╗{RESET}
{RED}{BOLD}  ╚══════╝╚═╝ ╚═════╝{RESET}

  {BOLD}Security Intelligence Center{RESET}  {DIM}v6.0.1{RESET}
  {DIM}AI-Powered Pentesting MCP Framework{RESET}
  {DIM}85 tools | 12+ agents | authorized testing only{RESET}
"""
    # Skip banner if already printed by the Node.js npx wrapper
    if not os.environ.get("SIC_NPX"):
        print(banner)


_print_banner()

# Now run the real server (same pattern as start_server.py)
if __name__ == "__main__":
    import runpy
    server_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hexstrike_server.py")
    runpy.run_path(server_path, run_name="__main__")
