#Requires -Version 5.1
# =============================================================================
# SIC — Automated Installer (Windows PowerShell)
# Usage: .\install.ps1
# Idempotent — safe to re-run; skips steps already completed.
# Run with: powershell -ExecutionPolicy Bypass -File .\install.ps1
# =============================================================================

$ErrorActionPreference = 'Stop'

# --- helpers -----------------------------------------------------------------
function Write-OK   { param([string]$Msg) Write-Host "  [OK] $Msg"   -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "  [WARN] $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "  [ERROR] $Msg" -ForegroundColor Red }
function Write-Info { param([string]$Msg) Write-Host "  [INFO] $Msg" -ForegroundColor Cyan }
function Write-Step { param([string]$Msg) Write-Host "`n==> $Msg" -ForegroundColor White }

# --- working directory -------------------------------------------------------
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host ""
Write-Host "  +==========================================+" -ForegroundColor Cyan
Write-Host "  |  SIC -- Security Intelligence Center    |" -ForegroundColor Cyan
Write-Host "  |  Automated Installer v1.0 (Windows)     |" -ForegroundColor Cyan
Write-Host "  +==========================================+" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# STEP 1: Check Python >= 3.8
# =============================================================================
Write-Step "Checking Python >= 3.8"

$PythonBin = $null
foreach ($candidate in @('python', 'python3')) {
    try {
        $verOutput = & $candidate --version 2>&1
        if ($verOutput -match 'Python\s+(\d+)\.(\d+)') {
            $major = [int]$Matches[1]
            $minor = [int]$Matches[2]
            if ($major -ge 3 -and $minor -ge 8) {
                $PythonBin = $candidate
                Write-OK "Found $candidate $($Matches[1]).$($Matches[2])"
                break
            } else {
                Write-Warn "$candidate $($Matches[1]).$($Matches[2]) is too old (need >= 3.8)"
            }
        }
    } catch {
        # candidate not on PATH — try next
    }
}

if (-not $PythonBin) {
    Write-Err "Python 3.8+ not found. Download from https://www.python.org/downloads/"
    Write-Err "Make sure to check 'Add Python to PATH' during installation."
    exit 1
}

# =============================================================================
# STEP 2: Check Node.js >= 16 + npm
# =============================================================================
Write-Step "Checking Node.js >= 16 and npm"

try {
    $nodeVer = (node --version) -replace 'v', ''
    $nodeMajor = [int]($nodeVer -split '\.')[0]
    if ($nodeMajor -lt 16) {
        Write-Err "Node.js $nodeVer is too old (need >= 16). Update at https://nodejs.org/"
        exit 1
    }
    Write-OK "Node.js v$nodeVer"
} catch {
    Write-Err "Node.js not found. Install from https://nodejs.org/ (v16 or later)"
    exit 1
}

try {
    $npmVer = npm --version
    Write-OK "npm $npmVer"
} catch {
    Write-Err "npm not found. Reinstall Node.js from https://nodejs.org/"
    exit 1
}

# =============================================================================
# STEP 3: Create Python virtual environment
# =============================================================================
Write-Step "Setting up Python virtual environment (venv\)"

if (Test-Path "venv") {
    Write-OK "venv\ already exists -- skipping creation"
} else {
    Write-Info "Creating venv..."
    & $PythonBin -m venv venv
    Write-OK "venv\ created"
}

# Resolve pip and python inside the venv (do not activate — avoids scope issues)
$VenvPip    = Join-Path $ScriptDir "venv\Scripts\pip.exe"
$VenvPython = Join-Path $ScriptDir "venv\Scripts\python.exe"

if (-not (Test-Path $VenvPip)) {
    Write-Err "venv pip not found at $VenvPip — venv creation may have failed."
    exit 1
}
Write-OK "Virtual environment ready"

# =============================================================================
# STEP 4: Install Python dependencies
# =============================================================================
Write-Step "Installing Python dependencies (requirements.txt)"

Write-Info "Running pip install -- this may take a few minutes on first run..."
& $VenvPip install --quiet --upgrade pip
& $VenvPip install --quiet -r requirements.txt
Write-OK "Python dependencies installed"

# =============================================================================
# STEP 5: Generate .env from .env.example (first run only)
# =============================================================================
Write-Step "Configuring .env"

if (Test-Path ".env") {
    Write-OK ".env already exists -- skipping (delete it to regenerate secrets)"
} else {
    if (-not (Test-Path ".env.example")) {
        Write-Err ".env.example not found in $ScriptDir -- cannot generate .env"
        exit 1
    }
    Copy-Item ".env.example" ".env"
    Write-Info "Copied .env.example -> .env"

    # Auto-generate secrets
    Write-Info "Generating secrets..."
    $SicSecretKey    = & $VenvPython -c "import secrets; print(secrets.token_hex(32))"
    $SicAuthSecret   = & $VenvPython -c "import secrets; print(secrets.token_hex(32))"
    $BillingApiKey   = & $VenvPython -c "import secrets; print(secrets.token_hex(32))"
    $SocFeedSecret   = & $VenvPython -c "import secrets; print(secrets.token_urlsafe(32))"

    # Read .env, replace placeholder lines, write back
    $envContent = Get-Content ".env" -Raw
    $envContent = $envContent -replace '(?m)^SIC_SECRET_KEY=.*$',   "SIC_SECRET_KEY=$SicSecretKey"
    $envContent = $envContent -replace '(?m)^SIC_AUTH_SECRET=.*$',  "SIC_AUTH_SECRET=$SicAuthSecret"
    $envContent = $envContent -replace '(?m)^BILLING_API_KEY=.*$',  "BILLING_API_KEY=$BillingApiKey"
    $envContent = $envContent -replace '(?m)^SOC_FEED_SECRET=.*$',  "SOC_FEED_SECRET=$SocFeedSecret"
    # Write with UTF-8 without BOM so Python dotenv can read it cleanly
    [System.IO.File]::WriteAllText("$ScriptDir\.env", $envContent, [System.Text.UTF8Encoding]::new($false))

    Write-OK ".env created with auto-generated secrets"
    Write-Warn "You still need to fill in RESEND_API_KEY, STRIPE_*, and SIC_ADMIN_EMAILS in .env"
}

# Ensure logs\ directory exists
if (-not (Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" | Out-Null
}
Write-OK "logs\ directory ready"

# =============================================================================
# STEP 6: Install PM2 globally if not present
# =============================================================================
Write-Step "Checking PM2"

$pm2Installed = $false
try {
    $pm2Check = npm list -g pm2 --depth=0 2>&1
    if ($pm2Check -match 'pm2@') {
        $pm2Installed = $true
        $pm2Ver = ($pm2Check | Select-String 'pm2@(\S+)').Matches[0].Groups[1].Value
        Write-OK "PM2 already installed ($pm2Ver)"
    }
} catch { }

if (-not $pm2Installed) {
    Write-Info "Installing PM2 globally..."
    npm install -g pm2
    Write-OK "PM2 installed"
}

# =============================================================================
# STEP 7: Start / restart SIC via PM2
# =============================================================================
Write-Step "Starting SIC processes via PM2"

$pm2List = pm2 list 2>&1
if ($pm2List -match 'sic-main|sic-billing|sic-mcp') {
    Write-Info "PM2 processes detected -- restarting..."
    try {
        pm2 restart ecosystem.config.cjs
    } catch {
        pm2 start ecosystem.config.cjs
    }
} else {
    Write-Info "Starting fresh PM2 processes..."
    pm2 start ecosystem.config.cjs
}

Write-OK "PM2 processes started"

# =============================================================================
# STEP 8: Wait and show PM2 status
# =============================================================================
Write-Step "Waiting for processes to stabilise..."
Start-Sleep -Seconds 2
pm2 status

# =============================================================================
# POST-INSTALL CHECKLIST
# =============================================================================
Write-Host ""
Write-Host "+================================================================+" -ForegroundColor Cyan
Write-Host "|  POST-INSTALL: Manual Configuration Required                   |" -ForegroundColor Cyan
Write-Host "+================================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Edit $ScriptDir\.env and fill in the following:" -ForegroundColor White
Write-Host ""
Write-Host "  [ ] SIC_ADMIN_EMAILS" -ForegroundColor Yellow -NoNewline
Write-Host "   -- comma-separated admin emails for magic-link login"
Write-Host "       e.g.  SIC_ADMIN_EMAILS=you@example.com"
Write-Host ""
Write-Host "  [ ] RESEND_API_KEY" -ForegroundColor Yellow -NoNewline
Write-Host "     -- obtain from https://resend.com/api-keys"
Write-Host "  [ ] SIC_ALERT_FROM" -ForegroundColor Yellow -NoNewline
Write-Host "     -- verified sender address on your Resend domain"
Write-Host ""
Write-Host "  [ ] STRIPE_SECRET_KEY" -ForegroundColor Yellow -NoNewline
Write-Host "         -- sk_test_... or sk_live_..."
Write-Host "  [ ] STRIPE_WEBHOOK_SECRET" -ForegroundColor Yellow -NoNewline
Write-Host "     -- whsec_... from Stripe > Webhooks"
Write-Host "  [ ] STRIPE_PRICE_TEAM / STRIPE_PRICE_STUDIO (and _YEARLY variants)" -ForegroundColor Yellow
Write-Host ""
Write-Host "  [ ] BILLING_API_KEY in CF Worker" -ForegroundColor Yellow
Write-Host "      Copy BILLING_API_KEY from .env, then run in francois-landing/:"
Write-Host "        wrangler secret put SIC_BILLING_KEY" -ForegroundColor Cyan
Write-Host ""
Write-Host "  [ ] OPENROUTER_API_KEY (optional) -- enables AI grading features" -ForegroundColor Yellow
Write-Host "      https://openrouter.ai/keys"
Write-Host ""
Write-Host "  Auto-generated secrets (already in .env):" -ForegroundColor Green
Write-Host "  [OK] SIC_SECRET_KEY     -- Flask session signing (32-byte hex)" -ForegroundColor Green
Write-Host "  [OK] SIC_AUTH_SECRET    -- Magic-link HMAC signing (32-byte hex)" -ForegroundColor Green
Write-Host "  [OK] BILLING_API_KEY    -- M2M billing auth (32-byte hex)" -ForegroundColor Green
Write-Host "  [OK] SOC_FEED_SECRET    -- SOC feed auth (32-byte urlsafe)" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard: " -NoNewline
Write-Host "http://localhost:9888" -ForegroundColor Cyan
Write-Host "  Billing:   " -NoNewline
Write-Host "http://localhost:9015" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Verify with:"
Write-Host "    curl http://localhost:9888/health" -ForegroundColor Cyan
Write-Host "    curl http://localhost:9015/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "  View logs:  pm2 logs sic-main   pm2 logs sic-billing" -ForegroundColor Cyan
Write-Host ""
