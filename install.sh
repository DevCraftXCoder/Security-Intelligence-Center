#!/usr/bin/env bash
# =============================================================================
# SIC — Automated Installer (Linux / macOS)
# Usage: ./install.sh
# Idempotent — safe to re-run; skips steps already completed.
# =============================================================================

set -euo pipefail

# --- colours -----------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  [OK]${NC} $*"; }
warn() { echo -e "${YELLOW}  [WARN]${NC} $*"; }
err()  { echo -e "${RED}  [ERROR]${NC} $*"; }
info() { echo -e "${CYAN}  [INFO]${NC} $*"; }
step() { echo -e "\n${BOLD}==> $*${NC}"; }

# --- error trap --------------------------------------------------------------
trap 'err "Installation failed on line $LINENO. Check the output above for details."' ERR

# --- working directory -------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BOLD}"
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   SIC — Security Intelligence Center    ║"
echo "  ║   Automated Installer v1.0               ║"
echo "  ╚══════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# STEP 1: Check Python >= 3.8
# =============================================================================
step "Checking Python >= 3.8"

PYTHON_BIN=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        version_str=$("$candidate" --version 2>&1 | awk '{print $2}')
        major=$(echo "$version_str" | cut -d. -f1)
        minor=$(echo "$version_str" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 8 ]; then
            PYTHON_BIN="$candidate"
            ok "Found $candidate $version_str"
            break
        else
            warn "$candidate $version_str is too old (need >= 3.8)"
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    err "Python 3.8+ not found. Install from https://www.python.org/downloads/"
    exit 1
fi

# =============================================================================
# STEP 2: Check Node.js >= 16 + npm
# =============================================================================
step "Checking Node.js >= 16 and npm"

if ! command -v node &>/dev/null; then
    err "Node.js not found. Install from https://nodejs.org/ (v16 or later)"
    exit 1
fi

node_version=$(node --version | sed 's/v//')
node_major=$(echo "$node_version" | cut -d. -f1)
if [ "$node_major" -lt 16 ]; then
    err "Node.js $node_version is too old (need >= 16). Update at https://nodejs.org/"
    exit 1
fi
ok "Node.js v$node_version"

if ! command -v npm &>/dev/null; then
    err "npm not found. It should come with Node.js — reinstall Node.js."
    exit 1
fi
ok "npm $(npm --version)"

# =============================================================================
# STEP 3: Create Python virtual environment
# =============================================================================
step "Setting up Python virtual environment (venv/)"

if [ -d "venv" ]; then
    ok "venv/ already exists — skipping creation"
else
    info "Creating venv..."
    "$PYTHON_BIN" -m venv venv
    ok "venv/ created"
fi

# Activate venv
# shellcheck disable=SC1091
source venv/bin/activate
ok "Virtual environment activated"

# =============================================================================
# STEP 4: Install Python dependencies
# =============================================================================
step "Installing Python dependencies"

# M3: default to requirements-core.txt (no angr/pwntools/mitmproxy).
# Pass --full to install requirements.txt for advanced users who need those tools.
FULL_INSTALL=false
for arg in "$@"; do
  [ "$arg" = "--full" ] && FULL_INSTALL=true
done

REQUIREMENTS_FILE="requirements-core.txt"
if $FULL_INSTALL; then
  REQUIREMENTS_FILE="requirements.txt"
  info "Full install requested (--full) — installing all dependencies from requirements.txt"
else
  info "Installing core dependencies from requirements-core.txt (add --full for angr/pwntools/mitmproxy)"
fi

info "Running pip install — this may take a few minutes on first run..."
pip install --quiet --upgrade pip
pip install --quiet -r "$REQUIREMENTS_FILE"
ok "Python dependencies installed"

# =============================================================================
# STEP 5: Generate .env from .env.example (first run only)
# =============================================================================
step "Configuring .env"

if [ -f ".env" ]; then
    ok ".env already exists — skipping (delete it to regenerate secrets)"
else
    if [ ! -f ".env.example" ]; then
        err ".env.example not found in $SCRIPT_DIR — cannot generate .env"
        exit 1
    fi
    cp .env.example .env
    info "Copied .env.example → .env"

    # Auto-generate secrets using Python secrets module
    info "Generating secrets..."

    SIC_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
    SIC_AUTH_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
    BILLING_API_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
    SOC_FEED_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

    # Replace placeholder values using sed (portable: works on Linux and macOS)
    # macOS sed requires an empty string after -i
    _SED_INPLACE=(-i)
    if [[ "$OSTYPE" == "darwin"* ]]; then
        _SED_INPLACE=(-i '')
    fi

    sed "${_SED_INPLACE[@]}" "s|^SIC_SECRET_KEY=.*|SIC_SECRET_KEY=${SIC_SECRET_KEY}|" .env
    sed "${_SED_INPLACE[@]}" "s|^SIC_AUTH_SECRET=.*|SIC_AUTH_SECRET=${SIC_AUTH_SECRET}|" .env
    sed "${_SED_INPLACE[@]}" "s|^BILLING_API_KEY=.*|BILLING_API_KEY=${BILLING_API_KEY}|" .env
    sed "${_SED_INPLACE[@]}" "s|^SOC_FEED_SECRET=.*|SOC_FEED_SECRET=${SOC_FEED_SECRET}|" .env

    ok ".env created with auto-generated secrets"
    warn "You still need to fill in RESEND_API_KEY, STRIPE_*, and SIC_ADMIN_EMAILS in .env"
fi

# Make sure logs/ directory exists (PM2 log targets require it)
mkdir -p logs
ok "logs/ directory ready"

# =============================================================================
# STEP 6: Install PM2 globally if not present
# =============================================================================
step "Checking PM2"

if npm list -g pm2 --depth=0 &>/dev/null 2>&1; then
    pm2_version=$(npm list -g pm2 --depth=0 2>/dev/null | grep pm2 | awk -F@ '{print $2}')
    ok "PM2 already installed (${pm2_version:-unknown version})"
else
    info "Installing PM2 globally..."
    npm install -g pm2
    ok "PM2 installed"
fi

# =============================================================================
# STEP 7: Start / restart SIC via PM2
# =============================================================================
step "Starting SIC processes via PM2"

# Check if any sic process is already managed by PM2
if pm2 list 2>/dev/null | grep -qE "sic-main|sic-billing|sic-mcp"; then
    info "PM2 processes detected — restarting..."
    pm2 restart ecosystem.config.cjs 2>/dev/null || pm2 start ecosystem.config.cjs
else
    info "Starting fresh PM2 processes..."
    pm2 start ecosystem.config.cjs
fi

ok "PM2 processes started"

# =============================================================================
# STEP 8: Wait and show PM2 status
# =============================================================================
step "Waiting for processes to stabilise..."
sleep 2
pm2 status

# =============================================================================
# POST-INSTALL CHECKLIST
# =============================================================================
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  POST-INSTALL: Manual Configuration Required                 ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Edit ${CYAN}$SCRIPT_DIR/.env${NC} and fill in the following:"
echo ""
echo -e "  ${YELLOW}[ ] SIC_ADMIN_EMAILS${NC}   — comma-separated admin emails for magic-link login"
echo -e "      e.g.  SIC_ADMIN_EMAILS=you@example.com"
echo ""
echo -e "  ${YELLOW}[ ] RESEND_API_KEY${NC}     — obtain from https://resend.com/api-keys"
echo -e "  ${YELLOW}[ ] SIC_ALERT_FROM${NC}     — verified sender address on your Resend domain"
echo ""
echo -e "  ${YELLOW}[ ] STRIPE_SECRET_KEY${NC}         — sk_test_... or sk_live_..."
echo -e "  ${YELLOW}[ ] STRIPE_WEBHOOK_SECRET${NC}     — whsec_... from Stripe > Webhooks"
echo -e "  ${YELLOW}[ ] STRIPE_PRICE_TEAM${NC}         — test-mode price ID"
echo -e "  ${YELLOW}[ ] STRIPE_PRICE_TEAM_YEARLY${NC}  — test-mode price ID"
echo -e "  ${YELLOW}[ ] STRIPE_PRICE_STUDIO${NC}       — test-mode price ID"
echo -e "  ${YELLOW}[ ] STRIPE_PRICE_STUDIO_YEARLY${NC} — test-mode price ID"
echo ""
echo -e "  ${YELLOW}[ ] BILLING_API_KEY in CF Worker${NC}"
echo -e "      The auto-generated BILLING_API_KEY from .env must also be set as a"
echo -e "      Cloudflare Worker secret (SIC_BILLING_KEY) in francois-landing:"
echo -e "      ${CYAN}cd packages/francois-landing && wrangler secret put SIC_BILLING_KEY${NC}"
echo ""
echo -e "  ${YELLOW}[ ] OPENROUTER_API_KEY${NC} (optional) — enables AI grading features"
echo -e "      https://openrouter.ai/keys"
echo ""
echo -e "${GREEN}${BOLD}  Auto-generated secrets (already in .env)${NC}"
echo -e "  ${GREEN}[✓] SIC_SECRET_KEY${NC}     — Flask session signing (32-byte hex)"
echo -e "  ${GREEN}[✓] SIC_AUTH_SECRET${NC}    — Magic-link HMAC signing (32-byte hex)"
echo -e "  ${GREEN}[✓] BILLING_API_KEY${NC}    — M2M billing auth (32-byte hex)"
echo -e "  ${GREEN}[✓] SOC_FEED_SECRET${NC}    — SOC feed auth (32-byte urlsafe)"
echo ""
echo -e "${BOLD}  Dashboard:${NC} ${CYAN}http://localhost:9888${NC}"
echo -e "${BOLD}  Billing:  ${NC} ${CYAN}http://localhost:9015${NC}"
echo ""
echo -e "  Verify with:"
echo -e "    ${CYAN}curl http://localhost:9888/health${NC}"
echo -e "    ${CYAN}curl http://localhost:9015/health${NC}"
echo ""
echo -e "  View logs:  ${CYAN}pm2 logs sic-main${NC}   ${CYAN}pm2 logs sic-billing${NC}"
echo ""
