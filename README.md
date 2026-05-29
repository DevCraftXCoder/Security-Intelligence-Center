<div align="center">

# SIC — Security Intelligence Center

### Penetration Testing MCP Framework for Authorized Security Testing

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](#mcp-integration)

**A penetration testing MCP framework with specialized agents for authorized security testing, CTF challenges, and defensive research.**

</div>

---

## Overview

SIC runs as a local server exposing an MCP interface for integration with any MCP-compatible client (Claude Code, Copilot, Cursor). All operations are IP-allowlisted to the home network.

---

## Quick Start

```bash
# Start the full server
python server.py

# MCP-only mode
python mcp_server.py

# CLI launcher
python launcher.py
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "sic": {
      "command": "python",
      "args": ["path/to/mcp_server.py"]
    }
  }
}
```

## Run with npx

```bash
npx sic-security@beta
```

## Authorized Use Only

> SIC is designed exclusively for authorized security testing. All operations must target systems you own or have explicit written permission to test.
