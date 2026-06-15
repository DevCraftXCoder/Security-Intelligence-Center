#Requires -Version 5.1
<#
.SYNOPSIS
    SIC prerequisites checker — verifies required external tools are on PATH.

.DESCRIPTION
    Checks each tool that SIC invokes via subprocess. For every missing tool,
    prints a one-line install command using winget, choco, or a download URL.
    Prints a "X/Y tools ready" summary at the end.

    Returns exit code 0 if all tools are present, 1 if any are missing.

    IMPORTANT: This script only CHECKS — it never downloads or runs anything.
    Run the printed install commands yourself after reviewing them.

.EXAMPLE
    .\install\check-prerequisites.ps1

.NOTES
    Run from the sic/ project root or from the install/ subfolder.
#>

# ─────────────────────────────────────────────────────────────────────────────
# Tool catalogue  [binary, description, winget-id-or-install-hint]
# ─────────────────────────────────────────────────────────────────────────────
$Tools = @(
    # Core scanning — always required
    [pscustomobject]@{ Binary = "nmap";        Tier = "core";     Description = "Network/port scanning";                   WingetId = "Insecure.Nmap";              ChocoId = "nmap";         FallbackUrl = "https://nmap.org/download.html" }
    [pscustomobject]@{ Binary = "nuclei";      Tier = "core";     Description = "Vulnerability template scanning";          WingetId = "ProjectDiscovery.Nuclei";    ChocoId = "";             FallbackUrl = "https://github.com/projectdiscovery/nuclei/releases" }
    [pscustomobject]@{ Binary = "nikto";       Tier = "core";     Description = "Web server scanning";                     WingetId = "";                           ChocoId = "nikto";        FallbackUrl = "https://github.com/sullo/nikto" }
    [pscustomobject]@{ Binary = "gobuster";    Tier = "core";     Description = "Directory/DNS brute-forcing";             WingetId = "OJ.gobuster";                ChocoId = "";             FallbackUrl = "https://github.com/OJ/gobuster/releases" }
    [pscustomobject]@{ Binary = "ffuf";        Tier = "core";     Description = "Web fuzzing";                             WingetId = "";                           ChocoId = "";             FallbackUrl = "https://github.com/ffuf/ffuf/releases" }
    [pscustomobject]@{ Binary = "sqlmap";      Tier = "core";     Description = "SQL injection testing";                   WingetId = "";                           ChocoId = "sqlmap";       FallbackUrl = "https://sqlmap.org" }
    [pscustomobject]@{ Binary = "subfinder";   Tier = "core";     Description = "Subdomain enumeration";                   WingetId = "ProjectDiscovery.Subfinder"; ChocoId = "";             FallbackUrl = "https://github.com/projectdiscovery/subfinder/releases" }
    [pscustomobject]@{ Binary = "amass";       Tier = "core";     Description = "Asset/subdomain discovery";               WingetId = "OWASP.Amass";                ChocoId = "";             FallbackUrl = "https://github.com/owasp-amass/amass/releases" }
    [pscustomobject]@{ Binary = "httpx";       Tier = "core";     Description = "HTTP probing";                            WingetId = "ProjectDiscovery.httpx";     ChocoId = "";             FallbackUrl = "https://github.com/projectdiscovery/httpx/releases" }

    # Web application tools
    [pscustomobject]@{ Binary = "feroxbuster"; Tier = "web";      Description = "Fast content discovery";                  WingetId = "epi052.feroxbuster";         ChocoId = "";             FallbackUrl = "https://github.com/epi052/feroxbuster/releases" }
    [pscustomobject]@{ Binary = "dirsearch";   Tier = "web";      Description = "Web path discovery";                     WingetId = "";                           ChocoId = "";             FallbackUrl = "https://github.com/maurosoria/dirsearch" }
    [pscustomobject]@{ Binary = "dirb";        Tier = "web";      Description = "Web content scanning";                   WingetId = "";                           ChocoId = "";             FallbackUrl = "https://github.com/v0re/dirb" }
    [pscustomobject]@{ Binary = "katana";      Tier = "web";      Description = "Web crawling/spidering";                 WingetId = "ProjectDiscovery.Katana";    ChocoId = "";             FallbackUrl = "https://github.com/projectdiscovery/katana/releases" }
    [pscustomobject]@{ Binary = "dalfox";      Tier = "web";      Description = "XSS scanning";                           WingetId = "";                           ChocoId = "";             FallbackUrl = "https://github.com/hahwul/dalfox/releases" }
    [pscustomobject]@{ Binary = "wfuzz";       Tier = "web";      Description = "Web fuzzer (Python)";                    WingetId = "";                           ChocoId = "";             FallbackUrl = "pip install wfuzz" }
    [pscustomobject]@{ Binary = "wafw00f";     Tier = "web";      Description = "WAF detection (Python)";                 WingetId = "";                           ChocoId = "";             FallbackUrl = "pip install wafw00f" }

    # Network recon
    [pscustomobject]@{ Binary = "masscan";     Tier = "recon";    Description = "High-speed port scanning";               WingetId = "";                           ChocoId = "masscan";      FallbackUrl = "https://github.com/robertdavidgraham/masscan" }
    [pscustomobject]@{ Binary = "rustscan";    Tier = "recon";    Description = "Fast port scanner (Rust)";              WingetId = "";                           ChocoId = "";             FallbackUrl = "https://github.com/RustScan/RustScan/releases" }

    # Cloud/infra scanning (optional — only needed if scanning cloud targets)
    [pscustomobject]@{ Binary = "trivy";       Tier = "cloud";    Description = "Container/IaC vulnerability scanning";   WingetId = "AquaSecurity.Trivy";         ChocoId = "";             FallbackUrl = "https://github.com/aquasecurity/trivy/releases" }
    [pscustomobject]@{ Binary = "checkov";     Tier = "cloud";    Description = "IaC security scanning (Python)";        WingetId = "";                           ChocoId = "";             FallbackUrl = "pip install checkov" }

    # Password/auth testing
    [pscustomobject]@{ Binary = "hydra";       Tier = "auth";     Description = "Online password attack";                 WingetId = "";                           ChocoId = "";             FallbackUrl = "https://github.com/vanhauser-thc/thc-hydra" }

    # Binary analysis / forensics (CTF / advanced)
    [pscustomobject]@{ Binary = "binwalk";     Tier = "forensics"; Description = "Firmware/binary analysis (Python)";    WingetId = "";                           ChocoId = "";             FallbackUrl = "pip install binwalk" }
    [pscustomobject]@{ Binary = "checksec";    Tier = "forensics"; Description = "Binary security properties check";     WingetId = "";                           ChocoId = "";             FallbackUrl = "https://github.com/slimm609/checksec.sh" }
    [pscustomobject]@{ Binary = "exiftool";    Tier = "forensics"; Description = "File metadata extraction";             WingetId = "OliverBetz.ExifTool";        ChocoId = "exiftool";     FallbackUrl = "https://exiftool.org" }
    [pscustomobject]@{ Binary = "strings";     Tier = "forensics"; Description = "String extraction from binaries";      WingetId = "";                           ChocoId = "sysinternals"; FallbackUrl = "ships with Sysinternals or GNU binutils" }
    [pscustomobject]@{ Binary = "objdump";     Tier = "forensics"; Description = "Object file disassembly";              WingetId = "";                           ChocoId = "mingw";        FallbackUrl = "ships with MinGW/binutils: choco install mingw" }
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
function Get-InstallHint {
    param([pscustomobject]$Tool)
    if ($Tool.WingetId) {
        return "winget install --id $($Tool.WingetId)"
    }
    if ($Tool.ChocoId) {
        return "choco install $($Tool.ChocoId)"
    }
    return $Tool.FallbackUrl
}

# ─────────────────────────────────────────────────────────────────────────────
# Main check loop
# ─────────────────────────────────────────────────────────────────────────────
$Ready   = 0
$Missing = 0
$MissingList = [System.Collections.Generic.List[string]]::new()

Write-Host ""
Write-Host "SIC Prerequisites Check" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor DarkGray
Write-Host ""

$CurrentTier = ""
foreach ($Tool in $Tools) {
    if ($Tool.Tier -ne $CurrentTier) {
        $CurrentTier = $Tool.Tier
        $Label = switch ($CurrentTier) {
            "core"      { "Core Scanning Tools (always required)" }
            "web"       { "Web Application Tools" }
            "recon"     { "Network Recon Tools" }
            "cloud"     { "Cloud / IaC Tools (needed for cloud targets)" }
            "auth"      { "Authentication Testing" }
            "forensics" { "Binary Analysis / Forensics (CTF / advanced)" }
            default     { $CurrentTier }
        }
        Write-Host ""
        Write-Host "  $Label" -ForegroundColor DarkCyan
        Write-Host ("  " + "-" * ($Label.Length)) -ForegroundColor DarkGray
    }

    $Found = $null -ne (Get-Command $Tool.Binary -ErrorAction SilentlyContinue)
    if ($Found) {
        Write-Host ("  [OK] {0,-14}  {1}" -f $Tool.Binary, $Tool.Description) -ForegroundColor Green
        $Ready++
    } else {
        $Hint = Get-InstallHint $Tool
        Write-Host ("  [--] {0,-14}  {1}" -f $Tool.Binary, $Tool.Description) -ForegroundColor Red
        Write-Host ("         Install:  $Hint") -ForegroundColor DarkYellow
        $Missing++
        $MissingList.Add($Tool.Binary) | Out-Null
    }
}

Write-Host ""
Write-Host ("=" * 60) -ForegroundColor DarkGray

$Total = $Ready + $Missing
if ($Missing -eq 0) {
    Write-Host "  $Ready/$Total tools ready — SIC is fully equipped." -ForegroundColor Green
    Write-Host ""
    exit 0
} else {
    Write-Host ("  $Ready/$Total tools ready — {0} missing: {1}" -f $Missing, ($MissingList -join ", ")) -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Run the install commands above, then re-run this script." -ForegroundColor DarkGray
    Write-Host "  SIC will still start with missing tools — those specific" -ForegroundColor DarkGray
    Write-Host "  scan types will fail at runtime with a clear error message." -ForegroundColor DarkGray
    Write-Host ""
    exit 1
}
