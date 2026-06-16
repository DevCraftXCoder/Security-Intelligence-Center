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
  let pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  } catch (e) {
    fail(`Could not read package.json: ${e.message}\nRe-run: npm install`);
  }
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

// ── resolve the user's codebase (the dir they ran `npx sic-security` in) ─────────
// npm/npx exports INIT_CWD = the directory the command was invoked from. We fall
// back to process.cwd() (which, for an npx bin, is also the invocation dir).
// SIC scans / inspects THIS path — never SIC's own package files.
function resolveProjectDir() {
  const candidate = process.env.SIC_PROJECT_DIR || process.env.INIT_CWD || process.cwd();
  try {
    const resolved = fs.realpathSync(candidate);
    // Never let the project root resolve to SIC's own install dir — that would
    // scan the framework instead of the user's code.
    if (path.resolve(resolved) === path.resolve(ROOT)) {
      return process.cwd();
    }
    return resolved;
  } catch {
    return process.cwd();
  }
}

// ── lightweight project-type detection for a tailored first-run message ──────────
function detectProjectType(dir) {
  const markers = [
    ["package.json", "Node.js / JavaScript"],
    ["requirements.txt", "Python"],
    ["pyproject.toml", "Python"],
    ["go.mod", "Go"],
    ["Cargo.toml", "Rust"],
    ["pom.xml", "Java (Maven)"],
    ["build.gradle", "Java (Gradle)"],
    ["composer.json", "PHP"],
    ["Gemfile", "Ruby"],
    ["Dockerfile", "Docker"],
    [".git", "Git repository"],
  ];
  const found = [];
  for (const [file, label] of markers) {
    try {
      if (fs.existsSync(path.join(dir, file))) found.push(label);
    } catch {}
  }
  return found;
}

// ── main ────────────────────────────────────────────────────────────────────────
let pkg;
try {
  pkg = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
} catch (e) {
  process.stderr.write(`[sic] Cannot read package.json: ${e.message}\nRe-run: npm install\n`);
  process.exit(1);
}

printBanner();

const PROJECT_DIR = resolveProjectDir();
const detected = detectProjectType(PROJECT_DIR);
log(`Target codebase: ${PROJECT_DIR}`);
if (detected.length) {
  log(`Detected: ${detected.join(", ")}`);
} else {
  log("No recognized project markers found — scans will still run against this directory.");
  log("Tip: run `npx sic-security` from the root of the codebase you want to inspect.");
}

ensureVenv();
ensureDeps(pkg.version);

// Strip our own flags before handing argv to the launcher.
const args = process.argv.slice(2).filter((a) => a !== "--reinstall");

// The server resolves `dashboard/`, `assets/`, and its sibling modules via
// `Path(__file__).parent`, so cwd MUST stay at ROOT for imports to work. The
// user's codebase is passed explicitly via SIC_PROJECT_DIR — the server confines
// all inspect/spawn-claude operations to that root (see _resolve_spawn_cwd).
const result = spawnSync(VENV_PYTHON, [LAUNCHER, ...args], {
  cwd: ROOT,
  stdio: "inherit",
  env: { ...process.env, SIC_NPX: "1", SIC_PROJECT_DIR: PROJECT_DIR },
});

process.exit(result.status ?? 1);
