# SIC - PowerShell profile helpers
# Paste into your $PROFILE file (run "notepad $PROFILE" to open it),
# or dot-source this file: . "path\to\sic\install\sic-profile.ps1"

param([string]$SicToken = $env:SIC_TOKEN)

$SIC_BASE = "http://127.0.0.1:9888"

function sic-scan {
    <#
    .SYNOPSIS
        Run a SIC smart scan against a target.
    .PARAMETER Target
        Target host or URL to scan.
    .PARAMETER Type
        Scan category: web, recon, network, or full (default: full).
    .EXAMPLE
        sic-scan -Target 192.168.1.1
        sic-scan -Target https://example.com -Type web
    #>
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Type = "full"
    )
    $body = @{ target = $Target; scan_type = $Type } | ConvertTo-Json
    $r = Invoke-RestMethod -Uri "$SIC_BASE/api/intelligence/smart-scan" -Method POST `
        -ContentType "application/json" -Body $body `
        -Headers @{ Authorization = "Bearer $SicToken" }
    $r | ConvertTo-Json -Depth 5
}

function sic-health {
    <#
    .SYNOPSIS
        Check SIC server health and telemetry.
    .EXAMPLE
        sic-health
    #>
    $r = Invoke-RestMethod -Uri "$SIC_BASE/health" `
        -Headers @{ Authorization = "Bearer $SicToken" }
    $r | ConvertTo-Json -Depth 3
}

function sic-incidents {
    <#
    .SYNOPSIS
        List open SIC incidents.
    .EXAMPLE
        sic-incidents
    #>
    $r = Invoke-RestMethod -Uri "$SIC_BASE/api/incidents" `
        -Headers @{ Authorization = "Bearer $SicToken" }
    $r | ConvertTo-Json -Depth 5
}

function sic-fix {
    <#
    .SYNOPSIS
        Submit an AI-assisted remediation command for a finding or incident ID.
    .PARAMETER Id
        The finding or incident ID to remediate.
    .EXAMPLE
        sic-fix abc123
    #>
    param([Parameter(Mandatory)][string]$Id)
    $body = @{ command = "remediate"; finding_id = $Id } | ConvertTo-Json
    $r = Invoke-RestMethod -Uri "$SIC_BASE/api/command" -Method POST `
        -ContentType "application/json" -Body $body `
        -Headers @{ Authorization = "Bearer $SicToken" }
    $r | ConvertTo-Json -Depth 5
}

function sic-version {
    <#
    .SYNOPSIS
        Show SIC server version and status from the health endpoint.
    .EXAMPLE
        sic-version
    #>
    $r = Invoke-RestMethod -Uri "$SIC_BASE/health" `
        -Headers @{ Authorization = "Bearer $SicToken" }
    [PSCustomObject]@{
        version = $r.version
        status  = $r.status
        uptime  = $r.uptime
    } | Format-List
}

Write-Host "SIC helpers loaded: sic-scan, sic-health, sic-incidents, sic-fix, sic-version"
