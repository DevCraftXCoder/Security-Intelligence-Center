# SIC SOC Pipeline — WIDE NET → REFINED VERDICT
## Complete Usage Guide

---

## What It Does

The SOC pipeline produces two SOC (Security Operations Center) handoff reports for any project — automatically derived from the project's architecture, not from manually filling in templates.

**Stage 1 — Wide Net**
Scans the project filesystem and source code to detect which system components are present (Cloudflare Workers, SQL, OAuth, Stripe, etc.), then generates a complete SOC handoff template that lists every threat class relevant to that architecture. No scanner required. Output is a template ready for refinement.

**Stage 2 — Refined Verdict**
Runs the SIC live scanner against the project, then adjudicates each threat class from Stage 1 against real scanner findings. Threat classes with confirmed findings are marked **proven**. Threat classes with no matching evidence are marked **untested**. Output is a code-traceable verdict report with a computed security score and maturity stage.

The core philosophy: cast a wide net first (don't miss anything), then refine against evidence (don't keep anything you can't prove).

---

## Prerequisites

- Python 3.8+
- SIC installed at `C:\Za\sic\`
- All SIC dependencies installed (`pip install -r C:\Za\sic\requirements.txt`)
- For Stage 2 live scans: project must be accessible on the local filesystem

---

## CLI Reference

All commands run from `C:\Za\sic\`:

```
python soc_pipeline.py --path <project-root> [--net | --refine | --auto] [--scan-json <file>] [--output-dir <dir>]
```

### Flags

| Flag | Stage | What it does |
|------|-------|-------------|
| `--path` | Both | **Required.** Absolute path to the project root being assessed |
| `--net` | 1 only | Generate Wide-Net template without running a live scan |
| `--refine` | 2 only | Run SIC scanner + produce Refined Verdict (requires Stage 1 net to exist) |
| `--auto` | Both | Run Stage 1 then Stage 2 in sequence — the standard full-pipeline mode |
| `--scan-json` | 2 | Skip live scan, load an existing merged scan JSON file instead |
| `--output-dir` | Both | Where to write output HTML files (default: `C:\Za\sic\_runs\qa\`) |

---

## Common Workflows

### Full pipeline — new project assessment

```bash
cd C:\Za\sic
python soc_pipeline.py --path C:\Za\packages\underground-api --auto
```

Outputs two files:
- `sic/_runs/qa/underground-api-soc-net-YYYYMMDD.html` — Wide-Net template
- `sic/_runs/qa/underground-api-soc-refined-YYYYMMDD.html` — Refined Verdict

### Stage 1 only — architecture survey, no live scan

Use when you want to enumerate what a project's threat surface looks like before committing to a full scan. Fast. No network or scanner required.

```bash
python soc_pipeline.py --path C:\Za\francois-landing --net
```

### Stage 2 only — refine against an existing scan

Use when you already have a SIC scan JSON from a prior run and want to regenerate the refined report without re-scanning.

```bash
python soc_pipeline.py --path C:\Za\packages\underground-api --refine --scan-json sic/_runs/qa/merged-scan.json
```

### Custom output directory

```bash
python soc_pipeline.py --path C:\Za\packages\llm-gateway --auto --output-dir C:\Users\J\Documents\soc-reports
```

---

## How Component Detection Works

The pipeline reads the project filesystem and source code to detect which components are present. Detection is automatic — no config file needed.

| Component | Detection signal | Triggers what |
|-----------|-----------------|--------------|
| `cf-workers` | `wrangler.toml` exists | CF Worker secret/env exposure, CORS misconfiguration, cache poisoning |
| `edge-runtime` | `wrangler.toml` exists | Node.js API usage in edge context |
| `durable-objects` | `DurableObject` in `wrangler.toml` or any `.ts`/`.py` | DO auth bypass, concurrent state corruption |
| `token-auth` | `HMAC`, `JWT_SECRET`, `jwt.sign`, `refreshToken` in source | JWT lifecycle, timing attacks, TOCTOU race |
| `object-storage` | `R2`, `S3Client`, `presign`, `PutObject` in source | R2/S3 IDOR, pre-signed URL scope abuse |
| `sql` | Any `.sql` file, `.prepare(`, `D1Database`, `FROM … WHERE` | SQL injection, audit log integrity |
| `docker` | `Dockerfile` or `docker-compose*.yml` exists | Root container, privileged mount, secret in layer |
| `oauth` | `oauth`, `discord.com/api/oauth`, `accounts.google.com` in source | OAuth state/PKCE bypass, token swap |
| `stripe` | `stripe`, `constructEvent`, `checkout.sessions.create` in source | Webhook signature bypass, price manipulation |
| `websocket` | `WebSocket`, `wss://`, `upgrade.*websocket` in source | WS auth bypass, missing origin check |
| `public-web` | `next.config.*`, `vite.config.*`, or any `.html` | XSS, CSP misconfiguration, client-side secret exposure |
| `secrets-store` | Any `.env` / `.env.example` / `*.env*` file | Secret scanning, rotation coverage, vault audit |

**Order matters:** components are processed in detection order, and the pipeline deduplicates overlapping threat IDs so the same control section never appears twice.

---

## Threat Catalog — All 12 Components

The threat catalog (`C:\Za\sic\threat_catalog.py`) defines every threat class the pipeline knows about. Here is the full catalog, organized by component.

### CF Workers

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-cfworkers-env` | P1 | Worker secret/env-var exposure | CWE-312 | A02:2021 |
| `net-cfworkers-cors` | P2 | CORS misconfiguration | CWE-942 | A05:2021 |
| `net-cfworkers-cache` | P2 | Cache poisoning via unkeyed headers | CWE-601 | A04:2021 |

### Durable Objects

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-do-auth` | **P0** | DO unauthenticated access | CWE-287 | A01:2021 |
| `net-do-state` | P1 | DO concurrent state corruption | CWE-362 | A04:2021 |

### Token Auth

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-token-lifecycle` | **P0** | JWT/refresh-token lifecycle vulnerabilities | CWE-613 | A07:2021 |
| `net-token-timing` | P1 | Non-timing-safe token comparison | CWE-208 | A02:2021 |
| `net-token-toctou` | P1 | Token TOCTOU — check-then-use race | CWE-367 | A01:2021 |

### Object Storage (R2 / S3)

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-r2-idor` | **P0** | R2/S3 object key IDOR | CWE-639 | A01:2021 |
| `net-r2-presign` | P1 | Pre-signed URL expiry/scope abuse | CWE-732 | A04:2021 |

### SQL / D1

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-sql-injection` | **P0** | SQL injection via string interpolation | CWE-89 | A03:2021 |
| `net-sql-audit` | P1 | Missing/tamperable audit log integrity | CWE-778 | A09:2021 |

### Docker

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-docker-root` | **P0** | Root user in production container | CWE-269 | A05:2021 |
| `net-docker-mount` | P1 | Privileged/writable host mount | CWE-732 | A05:2021 |
| `net-docker-secret` | P1 | Secret baked into image layer | CWE-312 | A02:2021 |

### OAuth

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-oauth-state` | **P0** | OAuth state/PKCE bypass (CSRF) | CWE-352 | A01:2021 |
| `net-oauth-token` | P1 | OAuth token swap / open redirect | CWE-601 | A01:2021 |

### Stripe

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-stripe-webhook` | **P0** | Stripe webhook signature bypass | CWE-345 | A08:2021 |
| `net-stripe-price` | P1 | Client-side price/quantity manipulation | CWE-602 | A04:2021 |

### WebSocket

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-ws-auth` | **P0** | WebSocket auth bypass | CWE-287 | A01:2021 |
| `net-ws-origin` | P1 | Missing WebSocket origin check | CWE-346 | A07:2021 |

### Edge Runtime

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-edge-node` | P1 | Node.js API usage in edge runtime | CWE-477 | A06:2021 |
| `net-edge-timeout` | P2 | Unbounded compute / CPU limit risk | CWE-400 | A04:2021 |

### Secrets Store

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-secrets-rotation` | P1 | Secret rotation coverage gaps | CWE-321 | A02:2021 |
| `net-secrets-vault` | P2 | No secrets vault / plaintext .env in prod | CWE-312 | A02:2021 |

### Public Web

| ID | Priority | Threat | CWE | OWASP |
|----|----------|--------|-----|-------|
| `net-web-xss` | **P0** | XSS via innerHTML / dangerouslySetInnerHTML | CWE-79 | A03:2021 |
| `net-web-csp` | P1 | Missing or overly permissive CSP | CWE-693 | A05:2021 |
| `net-web-client-secret` | P1 | Client-side secret exposure | CWE-312 | A02:2021 |

---

## Reading the Output Reports

### Wide-Net Report (`*-soc-net-*.html`)

- **Confidence level:** `MODERATE` — architecture-derived, no scanner confirmation
- **Controls status:** All sections show `net` status (pending adjudication)
- **Summary:** Lists detected components and count of threat classes found
- **Pending action:** Always includes "Run Stage 2 refinement scan to confirm findings"

Use this report to:
- Scope a penetration test engagement
- Brief a security team before a scan
- Identify which SIC tools to prioritize

### Refined Verdict Report (`*-soc-refined-*.html`)

- **Controls status:** Each section is either `proven` (scanner confirmed) or `untested` (no matching finding)
- **Confidence level:** `HIGH` for proven sections, lower for untested
- **Security score:** Computed from proven/total ratio weighted by priority
- **Maturity stage:** Auto-derived — see section below

Use this report as the final SOC handoff deliverable.

---

## Maturity Stages

The pipeline automatically computes the project's current security maturity stage on every run. No manual input required.

| Stage | Label | What's required to reach it |
|-------|-------|----------------------------|
| 1 | **LITE** | Any controls present (all projects start here) |
| 2 | **HARDENED** | Attack mapping OR detection coverage populated |
| 3 | **VALIDATED** | At least one prior snapshot exists (baseline established) |
| 4 | **SOC-OBSERVABLE** | Both attack mapping AND detection coverage populated |
| 5 | **ENTERPRISE SOC** | Risk acceptance + incident linkage + SLA summary all present |

Stages are cumulative — reaching Stage 4 means Stages 1–3 are also satisfied.

---

## Growth Delta — Automatic Progress Tracking

Every time you run the pipeline, it records a snapshot of the project's security posture. On subsequent runs, `growthDelta` is automatically computed by diffing against the most recent snapshot:

| Delta field | What it measures |
|-------------|-----------------|
| `controlsAdded` | Net change in total control items since last scan |
| `attackCoverageDelta` | Change in attack mapping entries |
| `openGapsDelta` | Change in unresolved control items (negative = good) |
| `activeThreats.prior` | CRITICAL/HIGH count from last snapshot |
| `activeThreats.current` | CRITICAL/HIGH count this run |

Snapshots are persisted automatically inside each project's SOC data. You don't manage them manually.

---

## Python API Usage

The pipeline can be imported and called directly from other Python code.

```python
from soc_pipeline import stage1_net, stage2_refine

# Stage 1 — architecture survey
result = stage1_net(
    project_path="/path/to/project",
    output_base="/path/to/output"
)
print(result["output_path"])         # HTML file path
print(result["profile"]["components"])  # e.g. ["cf-workers", "token-auth", "sql"]
print(len(result["net"]))            # number of threat sections

# Stage 2 — refined verdict
result2 = stage2_refine(
    project_path="/path/to/project",
    scan_json=None,          # None = run live SIC scan
    output_base="/path/to/output"
)
print(result2["proven_count"])    # threat classes confirmed by scanner
print(result2["untested_count"])  # threat classes with no scanner evidence
```

### Using the threat catalog directly

```python
from project_config import detect_system_profile
from threat_catalog import build_net, adjudicate_net

# Detect what a project uses
profile = detect_system_profile("/path/to/project")
# {"components": ["cf-workers", "token-auth", "sql"], "scanners": [...]}

# Build the ordered threat section list
net = build_net(profile)
# [{"id": "net-token-lifecycle", "priority": "p0", ...}, ...]

# Adjudicate against your own findings list
findings = [{"name": "JWT not rotated on logout", "severity": "high"}]
adjudicated = adjudicate_net(net, findings)
proven = [s for s in adjudicated if s["status"] == "proven"]
```

---

## Compute Maturity Directly

```python
from sic_to_soc import compute_maturity

project_data = {
    "controls": [...],
    "attackMapping": [...],
    "detectionCoverage": [...],
    "riskAcceptance": [],
    "incidentLinkage": [],
    "slaSummary": {},
}
prior_snapshots = [...]  # list of prior _snapshot_counts dicts, oldest first

maturity = compute_maturity(project_data, prior_snapshots)
print(maturity["currentStage"])     # 1–5
print(maturity["priorStage"])       # stage from last snapshot
print(maturity["growthDelta"])      # auto-computed diff
```

---

## Output File Naming

All output files follow this pattern:

```
<project-folder-name>-soc-net-<YYYYMMDD>.html       (Stage 1)
<project-folder-name>-soc-refined-<YYYYMMDD>.html   (Stage 2)
```

The project slug is derived from the last segment of `--path`. For example:

| `--path` | Slug | Stage 1 filename |
|---------|------|-----------------|
| `C:\Za\packages\underground-api` | `underground-api` | `underground-api-soc-net-20260604.html` |
| `C:\Za\francois-landing` | `francois-landing` | `francois-landing-soc-net-20260604.html` |
| `C:\Za\sic` | `sic` | `sic-soc-net-20260604.html` |

---

## Integration with SIC (Automatic for New Projects)

The pipeline is wired into SIC's SOC report flow. When registering a new project via SIC, the `--auto` flag can be appended to any SIC SOC invocation:

```bash
# From SIC launcher
python C:\Za\sic\soc_pipeline.py --path <new-project-root> --auto
```

SIC's existing `/soc-report` skill will surface both output reports. The MCP server at `packages/soc-reporter-mcp/` serves both `default` (Wide-Net) and `dropstream` (Refined Verdict) template variants.

---

## Troubleshooting

**"No threat catalog sections matched"**
- The project root path may be wrong — verify `--path` points to the actual project directory (where `wrangler.toml`, `Dockerfile`, `*.sql`, etc. live)
- Check `detect_system_profile()` detection signals against the project's actual filesystem

**Stage 2 scan hangs**
- SIC scanner requires Docker. Confirm `docker ps` works and the `sic-scanner` container is running:
  ```bash
  docker compose -f C:\Za\docker\sic-scanner\docker-compose.yml up -d
  ```

**"No module named 'soc_runner'"**
- Run from `C:\Za\sic\` directory, not from a different working directory
- Or pass the SIC root explicitly via `sys.path` if calling from outside

**Refined report shows all sections as "untested"**
- Scanner ran but produced no findings matching the net probe strings
- Check the merged scan JSON in the output directory — confirm it contains findings
- May indicate the project has no reachable/triggerable vulnerabilities in those classes (a good result)

---

## Key Files

| File | Purpose |
|------|---------|
| `C:\Za\sic\soc_pipeline.py` | Main CLI entry point — Stage 1 and Stage 2 orchestration |
| `C:\Za\sic\threat_catalog.py` | 12-component threat class catalog + `build_net()` + `adjudicate_net()` |
| `C:\Za\sic\project_config.py` | `detect_system_profile()` — filesystem fingerprint detection |
| `C:\Za\sic\sic_to_soc.py` | `compute_maturity()`, `build_project_data()`, HTML injection |
| `C:\Za\sic\soc_runner.py` | SIC scanner runner called by Stage 2 |
| `C:\Za\sic\tests\test_threat_catalog.py` | Unit tests for catalog + adjudication |
| `C:\Za\sic\tests\test_soc_pipeline.py` | Unit tests for Stage 1 and Stage 2 CLI |
| `C:\Za\.claude\skills\soc-report\SKILL.md` | Skill documentation (SIC tool integration) |
| `C:\Za\sic\_runs\qa\` | Default output directory for all SOC reports |

---

*SIC v6.0.0 — SOC Pipeline shipped 2026-06-04*
