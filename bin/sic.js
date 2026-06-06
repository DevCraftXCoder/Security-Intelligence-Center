#!/usr/bin/env node
"use strict";

const { spawnSync, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

const ROOT = path.resolve(__dirname, "..");
const LAUNCHER = path.join(ROOT, "launcher.py");
const REQ_CORE = path.join(ROOT, "requirements-core.txt");
const MIN_PYTHON = [3, 8];

// Per-user data dir so the venv survives across npx invocations (npx package
// dir is ephemeral — we must not install into ROOT).
const DATA_DIR = path.join(os.homedir(), ".sic-security");
const VENV_DIR = path.join(DATA_DIR, "venv");
const IS_WIN = process.platform === "win32";
const VENV_PYTHON = IS_WIN
  ? path.join(VENV_DIR, "Scripts", "python.exe")
  : path.join(VENV_DIR, "bin", "python");

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

// ── find a system Python 3.8+ (only needed to create the venv) ─────────────────
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

// ── print banner ───────────────────────────────────────────────────────────────
function printBanner() {
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
  ${dim}85 tools | 12+ agents | authorized testing only${reset}
`;
  process.stdout.write(logo + "\n");
}

// ── create the venv if missing ─────────────────────────────────────────────────
function ensureVenv() {
  if (fs.existsSync(VENV_PYTHON)) return;
  const python = findPython();
  if (!python) {
    fail("Python 3.8+ is required (used once to create an isolated env). Install from https://python.org");
  }
  fs.mkdirSync(DATA_DIR, { recursive: true });
  log(`Creating isolated environment at ${VENV_DIR} ...`);
  const r = spawnSync(python, ["-m", "venv", VENV_DIR], { stdio: "inherit" });
  if (r.status !== 0 || !fs.existsSync(VENV_PYTHON)) {
    fail("Failed to create virtual environment. Ensure the Python `venv` module is available.");
  }
}

// ── install core dependencies into the venv (once per version) ──────────────────
function ensureDeps(version) {
  const sentinel = path.join(DATA_DIR, `.installed-${version}`);
  const force = process.argv.includes("--reinstall");
  if (fs.existsSync(sentinel) && !force) return;

  if (!fs.existsSync(REQ_CORE)) {
    fail(`requirements-core.txt not found at ${REQ_CORE}`);
  }
  log("Installing core dependencies (first run only) ...");
  spawnSync(VENV_PYTHON, ["-m", "pip", "install", "--upgrade", "pip", "--quiet"], { stdio: "inherit" });
  const r = spawnSync(VENV_PYTHON, ["-m", "pip", "install", "-r", REQ_CORE], { stdio: "inherit" });
  if (r.status !== 0) {
    fail("Dependency install failed. See pip output above.");
  }
  fs.writeFileSync(sentinel, new Date().toISOString());
  log("Dependencies ready.");
}

// ── main ────────────────────────────────────────────────────────────────────────
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));

printBanner();
ensureVenv();
ensureDeps(pkg.version);

// Strip our own flags before handing argv to the launcher.
const args = process.argv.slice(2).filter((a) => a !== "--reinstall");

const result = spawnSync(VENV_PYTHON, [LAUNCHER, ...args], {
  cwd: ROOT,
  stdio: "inherit",
  env: { ...process.env, SIC_NPX: "1" },
});

process.exit(result.status ?? 1);
