#!/usr/bin/env node
"use strict";

const { spawnSync, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const ROOT = path.resolve(__dirname, "..");
const LAUNCHER = path.join(ROOT, "launcher.py");
const MIN_PYTHON = [3, 8];

// ── find Python 3.8+ ──────────────────────────────────────────────────────────
function findPython() {
  const candidates = ["python3", "python", "python3.12", "python3.11", "python3.10", "python3.9", "python3.8"];
  for (const cmd of candidates) {
    try {
      const r = execSync(`${cmd} -c "import sys; print(sys.version_info.major, sys.version_info.minor)"`, {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
      const [major, minor] = r.trim().split(" ").map(Number);
      if (major > MIN_PYTHON[0] || (major === MIN_PYTHON[0] && minor >= MIN_PYTHON[1])) {
        return cmd;
      }
    } catch {}
  }
  return null;
}

// ── print banner ──────────────────────────────────────────────────────────────
function printBanner() {
  const red = "\x1b[91m";
  const dim = "\x1b[2m";
  const bold = "\x1b[1m";
  const reset = "\x1b[0m";
  const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

  const logo = `
  ${red}${bold}  ███████╗██╗ ██████╗${reset}
  ${red}${bold}  ██╔════╝██║██╔════╝${reset}
  ${red}${bold}  ███████╗██║██║     ${reset}
  ${red}${bold}  ╚════██║██║██║     ${reset}
  ${red}${bold}  ███████║██║╚██████╗${reset}
  ${red}${bold}  ╚══════╝╚═╝ ╚═════╝${reset}

  ${bold}Security Intelligence Center${reset}  ${dim}v${pkg.version}${reset}
  ${dim}AI-Powered Pentesting MCP Framework${reset}
  ${dim}150+ tools | 12+ agents | authorized testing only${reset}
`;
  process.stdout.write(logo + "\n");
}

// ── main ──────────────────────────────────────────────────────────────────────
const python = findPython();
if (!python) {
  process.stderr.write(
    "\x1b[91m[sic]\x1b[0m Python 3.8+ is required. Install from https://python.org\n"
  );
  process.exit(1);
}

// Check custom logo env override
const customLogo = process.env.SIC_LOGO_PATH;
if (customLogo && fs.existsSync(customLogo)) {
  // future: render image-to-ascii via custom path
}

printBanner();

const args = process.argv.slice(2);
const result = spawnSync(python, [LAUNCHER, ...args], {
  cwd: ROOT,
  stdio: "inherit",
  env: { ...process.env, SIC_NPX: "1" },
});

process.exit(result.status ?? 1);
