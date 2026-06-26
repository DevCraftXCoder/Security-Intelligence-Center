#!/usr/bin/env node
"use strict";

// SIC free code scanner — npx launcher.
// Runs the zero-dependency Python scanner (scan_python.py) against the directory
// you invoke it from, and prints findings immediately. Read-only, no network, no
// external binaries required (pip-audit is used for dependency CVEs if present).

const { spawnSync, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");

const ROOT = path.resolve(__dirname, "..");
const SCANNER = path.join(ROOT, "scan_python.py");
const MIN_PYTHON = [3, 8];

const red = "\x1b[91m";
const dim = "\x1b[2m";
const bold = "\x1b[1m";
const reset = "\x1b[0m";

function log(msg) {
  process.stderr.write(`${dim}[sic]${reset} ${msg}\n`);
}
function fail(msg) {
  process.stderr.write(`${red}[sic]${reset} ${msg}\n`);
  process.exit(1);
}

// ── find a system Python 3.8+ (the scanner is stdlib-only — no venv needed) ──────
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

function printBanner() {
  let version = "?";
  try {
    version = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).version;
  } catch {}
  process.stdout.write(`
  ${red}${bold}  ███████╗██╗ ██████╗${reset}
  ${red}${bold}  ██╔════╝██║██╔════╝${reset}
  ${red}${bold}  ███████╗██║██║     ${reset}
  ${red}${bold}  ╚════██║██║██║     ${reset}
  ${red}${bold}  ███████║██║╚██████╗${reset}
  ${red}${bold}  ╚══════╝╚═╝ ╚═════╝${reset}

  ${bold}SIC Code Scanner${reset}  ${dim}v${version}${reset}
  ${dim}Free, read-only static scanner — secrets, unsafe patterns, dep CVEs${reset}

`);
}

// ── resolve the user's codebase (the dir they ran the command from) ──────────────
function resolveProjectDir() {
  const candidate = process.env.SIC_PROJECT_DIR || process.env.INIT_CWD || process.cwd();
  try {
    const resolved = fs.realpathSync(candidate);
    if (path.resolve(resolved) === path.resolve(ROOT)) {
      return process.cwd();
    }
    return resolved;
  } catch {
    return process.cwd();
  }
}

// ── main ─────────────────────────────────────────────────────────────────────────
printBanner();

const args = process.argv.slice(2);
const sub = args[0];

if (sub && sub !== "scan") {
  if (sub === "-h" || sub === "--help" || sub === "help") {
    process.stdout.write(
      "  Usage:\n" +
      "    npx sic-security scan        Scan the current directory\n" +
      "    npx sic-security scan <dir>  Scan a specific directory\n\n" +
      "  The scanner is read-only and runs on the Python standard library alone.\n" +
      "  Install pip-audit to additionally surface dependency CVEs.\n"
    );
    process.exit(0);
  }
  log(`Unknown command: ${sub}`);
  log("Run `npx sic-security scan` to scan the current directory.");
  process.exit(1);
}

const PROJECT_DIR = resolveProjectDir();
const python = findPython();
if (!python) {
  fail("Python 3.8+ is required to run the scanner. Install from https://python.org");
}

if (!fs.existsSync(SCANNER)) {
  fail(`Scanner not found at ${SCANNER}. Re-run: npm install sic-security`);
}

log(`Scanning ${PROJECT_DIR} ...`);
const scanArgs = sub === "scan" ? args.slice(1) : [];
const result = spawnSync(python, [SCANNER, PROJECT_DIR, ...scanArgs], {
  cwd: ROOT,
  stdio: "inherit",
  env: { ...process.env, SIC_PROJECT_DIR: PROJECT_DIR },
});

process.exit(result.status ?? 1);
