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

    # Check for custom logo path (set by npx wrapper or user env)
    custom = os.environ.get("SIC_LOGO_PATH", "")
    logo_path = custom if custom and os.path.isfile(custom) else os.path.join(
        os.path.dirname(__file__), "assets", "hexstrike-logo.png"
    )

    banner = f"""
{RED}{BOLD}  ███████╗██╗ ██████╗{RESET}
{RED}{BOLD}  ██╔════╝██║██╔════╝{RESET}
{RED}{BOLD}  ███████╗██║██║     {RESET}
{RED}{BOLD}  ╚════██║██║██║     {RESET}
{RED}{BOLD}  ███████║██║╚██████╗{RESET}
{RED}{BOLD}  ╚══════╝╚═╝ ╚═════╝{RESET}

  {BOLD}Security Intelligence Center{RESET}  {DIM}v6.0.0-beta{RESET}
  {DIM}AI-Powered Pentesting MCP Framework{RESET}
  {DIM}150+ tools | 12+ agents | authorized testing only{RESET}
"""
    # Skip banner if already printed by the Node.js npx wrapper
    if not os.environ.get("SIC_NPX"):
        print(banner)


_print_banner()

# Now import and run the real server
if __name__ == "__main__":
    # Patch sys.argv so argparse in hexstrike_server.py sees our args
    import hexstrike_server  # noqa: E402 — triggers Flask app creation

    # The server's __main__ block calls app.run() — we just need to trigger it
    port = int(os.environ.get("HEXSTRIKE_PORT", sys.argv[1] if len(sys.argv) > 1 else 9888))
    print(f"[hexstrike-launcher] Starting on 127.0.0.1:{port}")
    hexstrike_server.app.run(
        host="127.0.0.1",
        port=port,
        debug=False,
        use_reloader=False,
    )
