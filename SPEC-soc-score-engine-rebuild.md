# SPEC — SOC Score Engine Rebuild

> Status: DESIGN — ready for implementation
> Date: 2026-06-07
> Scope: `C:\Za\sic\` SOC report pipeline
> Author: forge brainstorm (Phase 2/3)

---

## Problem Statement

The SOC posture score is structurally fake. Four independent code paths each compute or carry a "score," none is authoritative, and they diverge silently: (1) `sic_to_soc.build_project_data` computes `current_score` as percent-of-items-remediated but only writes it into the week-over-week `snapshots[]` array — never into the HTML where it would be read back; (2) the HTML template's client-side `recalc()` derives the displayed ring score from a **hardcoded `const DATA=[...]`** block (DropStream sample controls) plus a `DEFAULT_DONE=[]` checklist, so the injected `<script id="project-data">` JSON is ignored at render time; (3) `soc_pipeline._extract_score` reads a **static `<!--soc-score:100-->`** comment that `sic_to_soc` never rewrites, so Discord always posts 100/PASS; (4) `dropstream-weekly-soc.mjs` computes its own weighted `scoreVal` from harness pass-rate. The result: every Discord post says 100/PASS regardless of findings, unscanned/architecture-only reports post green, and verdict thresholds disagree between the weekly bridge (`GO/REVIEW/ATTENTION/BLOCK`) and the pipeline (`PASS/REVIEW/NET/FAIL`). This rebuild makes the **Python server the single authoritative score source**, stamps it into the HTML, makes the template read injected data, and routes one verdict vocabulary end-to-end.

---

## Authoritative Score Design

### Single source of truth

`sic_to_soc.compute_posture()` (new function in `sic_to_soc.py`) is the **only** place a score is computed. It returns a `posture` dict:

```python
posture = {
    "score":   int,          # 0-100, authoritative
    "verdict": str,          # PASS | REVIEW | ATTENTION | BLOCK | NET (one vocabulary, see §Verdict)
    "model":   str,          # "inverse-risk" | "remediation-rate" | "net-only"
    "scanned": bool,         # False for Stage-1 wide-net / architecture-only reports
    "weights": {"p0":..,"p1":..,"p2":..,"p3":..},
    "counts":  {"p0":{"open":n,"total":n}, ... },
    "rationale": str,        # human-readable, shown in report + Discord
}
```

This dict is attached to `project_data["posture"]` (new top-level key) and is the **input to every downstream consumer** — the HTML score ring, the `<!--soc-score-->` comment, the Discord embed, and the snapshots array.

### How it's computed — inverse-risk model

The score is **not** "% manually checked" (gap 9). It is an inverse-risk score: start at 100, subtract weighted risk for every **open** (un-remediated, un-refuted) finding/control item, floored at 0.

```
weights        W = {p0: 40, p1: 15, p2: 5, p3: 1}   # risk cost of leaving one item open
risk           = sum(W[item.p] for item in all_items if item is OPEN)
max_risk       = sum(W[item.p] for item in all_items)        # if every item were open
score          = round(100 * (1 - risk / max_risk))  if max_risk > 0 else 100
```

- An item is **OPEN** unless `done == True` (manually verified) OR `net_status == "refuted"` (scanner proved the threat class absent — gap 7).
- A single open P0 caps the score hard: with W[p0]=40, even one open P0 in a small report drops the score well below the PASS threshold.
- `score_override` (weekly harness bridge) still wins when supplied, but it now feeds `compute_posture` rather than bypassing it, so verdict mapping stays consistent.

### Unscanned guard

If `posture["scanned"] is False` (Stage-1 wide-net, or a scan that produced zero scanner findings AND zero manually-checked items), the model is `"net-only"`, `score` is forced to `None`/0, and `verdict = "NET"`. The Discord notifier renders this amber as "NET — not yet assessed," never green PASS (gap 5).

### Verdict — one vocabulary

Single mapping function `verdict_for(score, scanned)` in `sic_to_soc.py`, imported by `soc_pipeline.py` AND referenced by the `.mjs` bridge (gap 6):

| Condition | Verdict | Color |
|-----------|---------|-------|
| `not scanned` | `NET` | amber `0xB89100` |
| `score >= 90` | `PASS` | green `0x4ADE80` |
| `70 <= score < 90` | `REVIEW` | amber `0xB89100` |
| `40 <= score < 70` | `ATTENTION` | orange `0xF59E0B` |
| `score < 40` | `BLOCK` | red `0xFF3B3B` |

The weekly bridge's `GO` maps to `PASS`, `BLOCK` stays `BLOCK`; `soc_pipeline`'s old `FAIL` is renamed `BLOCK`. All four code paths now speak `PASS/REVIEW/ATTENTION/BLOCK/NET`.

### How it flows through the pipeline

```
scan_merge._collect (vulns + secrets + misconfig)   ← gap 3
        │
        ▼
threat_catalog.adjudicate_net (proven/refuted/untested)   ← gaps 4,7
        │
        ▼
sic_to_soc.build_project_data
        │  builds controls + all_items
        ▼
sic_to_soc.compute_posture(all_items, net, scanned)   ← SINGLE SOURCE OF TRUTH
        │  → posture dict
        ├─► project_data["posture"]            (template reads this)
        ├─► project_data["snapshots"][-1].score (week-over-week)
        └─► stamp_score(html, posture)          → rewrites <!--soc-score:NN--> + verdict   ← gap 1
                │
                ▼
        inject_project_data(html, project_data)  (template DATA now sourced from project-data)  ← gap 2
                │
                ▼
        soc_pipeline._extract_score / _extract_posture (reads stamped comment)   ← gap 1
                │
                ▼
        _notify_discord (verdict + color from stamped posture)   ← gaps 5,6,14
```

---

## Fix Plan

### P0 — fix immediately

#### Gap 1 — `<!--soc-score-->` never written; `_extract_score` reads hardcoded 100
- **File:** `sic_to_soc.py` (add `compute_posture`, `stamp_score`; wire into `main()` and `build_project_data` ~L667–721, L777–789); `soc_pipeline.py` `_extract_score` L44–57 (extend to `_extract_posture`).
- **Change:** Add `compute_posture(all_items, net, scanned, score_override)` returning the posture dict. Add `stamp_score(html, posture)` that regex-replaces `<!--soc-score:\d+-->` with `<!--soc-score:{score}-->` and a sibling `<!--soc-verdict:{verdict}-->`; if the comment is absent, insert both right after `<head>`. Call `stamp_score` on the rendered HTML in `main()` (and in `soc_pipeline.stage1_net` / `stage2_refine` after `inject_project_data`). Extend `soc_pipeline._extract_score` → `_extract_posture` to read both comments (score + verdict) from the first 20 lines, falling back to `posture` JSON in the injected `project-data` script.
- **Acceptance:** A scan of a project with one open P0 produces HTML containing `<!--soc-score:NN-->` where `NN < 90`, and `_extract_posture` returns that same `NN` and a non-PASS verdict. No path returns a hardcoded 100.

#### Gap 2 — template `const DATA` hardcoded; injected project-data never read
- **File:** `templates/soc-handoff/soc-handoff-template-blank.html` (`const DATA=[...]` L1115–~1177; `DEFAULT_DONE` L1180; `recalc()` L1243–1250; bootstrap near L1179–1182).
- **Change:** Replace the literal `const DATA=[...]` with a loader that reads the injected JSON: `const PD=JSON.parse(document.getElementById('project-data').textContent); const DATA = (PD.controls && PD.controls.length) ? PD.controls : DATA_FALLBACK;` Keep the existing DropStream array renamed to `DATA_FALLBACK` (used only when `project-data` is empty, e.g. opening the blank template directly). Seed `DEFAULT_DONE` from `PD.controls` items where `done===1`. Add an authoritative-score short-circuit in `recalc()`: if `PD.posture` exists and the analyst has not manually toggled anything this session, render `PD.posture.score`/`verdict` directly; once the analyst edits the checklist, fall back to the live client recompute. This keeps the report interactive while making the **first render match the server score**.
- **Acceptance:** Open a generated report fresh (clear localStorage): the ring shows the server `posture.score`, the section list reflects injected `controls`, and the DropStream sample controls do **not** appear. Opening the raw blank template still renders the fallback without errors.

#### Gap 3 — `_collect` only reads `Vulnerabilities[]`, never `Secrets[]` / `Misconfigurations[]`
- **File:** `scan_merge.py` `_collect` L45–119 (and the mirror copy in `sic_to_soc.py` — dedupe by importing one).
- **Change:** In the trivy branch (L59–76), after collecting `Vulnerabilities`, also iterate `result.get("Secrets") or []` (map `RuleID`/`Title`/`Severity`/`Match` → finding, tags `["secret","exposure"]`) and `result.get("Misconfigurations") or []` (map `ID`/`Title`/`Severity`/`Description` → finding, tags `["misconfig","iac"]`). Keep "Results is authoritative" semantics: a vuln-free-but-secret-bearing scan now returns the secrets. Make `sic_to_soc.py` import `_collect` from `scan_merge` instead of carrying its own copy (eliminates drift).
- **Acceptance:** A merged scan JSON containing a `Secrets[]` entry and a `Misconfigurations[]` entry yields ≥2 findings from `_collect`, each with correct severity and tags; existing vuln-only scans are unchanged.

#### Gap 4 — `_probe_match` uses ultra-generic substrings on `severity` → false positives
- **File:** `threat_catalog.py` `_probe_match` L475–497.
- **Change:** Remove `severity`, `type`, and bare `category` from the matched `parts` haystack (severity values like "high"/"medium" are not threat-class signals). Match probes against semantic fields only: `name`, `vulnerabilityName`, `Title`, `template-id`, `checkID`, `description`, `message`, `rule_id`, `rule`, `tags`. Promote probe matching to **whole-word / token-boundary** regex (`\b{probe}\b`) instead of naive `in` substring, so probe `"env"` no longer matches `"environment"` inside an unrelated description. Probe lists in `SYSTEM_COMPONENTS` stay as-is but are now matched precisely.
- **Acceptance:** A finding whose only relevant field is `severity:"high"` matches **zero** net sections. A finding titled "CORS wildcard origin" matches the `net-cfworkers-cors` section. Add a regression case to `tests/test_threat_catalog.py`.

#### Gap 5 — Stage-1 wide-net posts green 100/PASS for unscanned reports
- **File:** `soc_pipeline.py` `stage1_net` L60–196, `_notify_discord` L334–408.
- **Change:** Stage-1 sets `project_data["posture"] = {"scanned": False, "verdict": "NET", "score": None, ...}` and `stamp_score` writes `<!--soc-score:0-->` + `<!--soc-verdict:NET-->`. `_notify_discord` reads the stamped verdict (not a score threshold) — when `verdict == "NET"` it renders amber "NET — architecture-only, not yet assessed" and never green. Remove the `score >= 95 → PASS` shortcut from the wide-net branch.
- **Acceptance:** `soc_pipeline --net --discord` posts an amber NET embed with no score and the text "not yet assessed"; it never posts green/PASS.

#### Gap 6 — verdict thresholds diverge (weekly vs pipeline)
- **File:** `sic_to_soc.py` (new `verdict_for`); `soc_pipeline.py` `_notify_discord` L348–402; `scripts/dropstream-weekly-soc.mjs` L604–620.
- **Change:** Define `verdict_for(score, scanned)` once in `sic_to_soc.py` (table in §Verdict). `soc_pipeline._notify_discord` imports and uses it. The `.mjs` bridge stops emitting its own verdict words; it feeds its `scoreVal` to `sic_to_soc --score` and lets the Python stamp the verdict, OR (if it must label locally) uses an identical JS port of the table. All paths emit `PASS/REVIEW/ATTENTION/BLOCK/NET`.
- **Acceptance:** A score of 75 yields `REVIEW` in the HTML, the Discord embed, and the `.mjs` fingerprint — identical word and color across all three.

### P1 — implement where feasible, stub otherwise

#### Gap 7 — `adjudicate_net` never assigns "refuted"
- **File:** `threat_catalog.py` `adjudicate_net` L500–519.
- **Change:** Add a third status. A section is `refuted` when (a) the relevant scanner that *would* surface this class actually ran (tracked via a new `section["covered_by"]` scanner tag matched against the merged scan's `scannersRun` list) AND (b) it produced no matching finding. Sections whose covering scanner did not run stay `untested`; sections with matches stay `proven`. Refuted items count as closed (not open) in the inverse-risk model.
- **Acceptance:** When the trivy scanner ran and returned no secret findings, the secret-leak net section is marked `refuted` (not `untested`); the posture score rises accordingly. If the SAST scanner did not run, injection-class sections remain `untested` and depress the score.

#### Gap 8 — Net sections need SAST coverage most scanners lack
- **File:** `threat_catalog.py` `SYSTEM_COMPONENTS` (`covered_by` metadata); `soc_runner.py` (scanner registry).
- **Change:** Tag each net section with `covered_by` (e.g. `["sast"]`, `["trivy-fs"]`, `["checkov"]`). Where no scanner in the SIC stack provides coverage (most SAST/injection classes), record the section as `untested` with `coverage_gap: true` and surface a "coverage gap" note in the report rather than silently treating absence as safety. **Stub:** do not add a new SAST scanner in this rebuild; only the coverage-gap accounting is implemented.
- **Acceptance:** A report lists each `untested` section's `covered_by` scanners and flags `coverage_gap` sections distinctly; no `untested` section is counted as `refuted`.

#### Gap 9 — score = "% manually checked", no inverse-risk model
- **File:** `sic_to_soc.py` L667–677.
- **Change:** Superseded by `compute_posture` (see Authoritative Score Design). The old `done / len(all_items) * 100` block is removed; `current_score` is sourced from `posture["score"]`.
- **Acceptance:** `compute_posture` is the only score computation in `sic_to_soc.py`; grep for `done / len` returns no score-producing matches.

#### Gap 10 — content detection greps only `.py`/`.ts`
- **File:** `project_config.py` `_grep_any` L399–413.
- **Change:** Replace the two hardcoded `rglob("*.py")` / `rglob("*.ts")` loops with a single loop over a suffix allowlist: `.py .ts .tsx .js .jsx .go .rs .java .html .vue .svelte`. Skip `node_modules`, `.git`, `dist`, `.next`, `_archive` directories. Cap per-file read size to avoid huge bundles.
- **Acceptance:** A project whose Stripe/WebSocket signals live only in `.js`/`.jsx` files is detected (component appears in profile); a `.go` app-server is detected.

#### Gap 11 — no app-server component in threat model
- **File:** `threat_catalog.py` `SYSTEM_COMPONENTS` (add `app-server` key); `project_config.py` `detect_system_profile` (add detection signal).
- **Change:** Add an `app-server` component with threat sections covering: missing auth middleware (CWE-306), unvalidated input/injection (CWE-20/89), verbose error leakage (CWE-209), missing rate limiting (OWASP API4), insecure deserialization (CWE-502). Detect via FastAPI/Hono/Express signals (`from fastapi`, `new Hono(`, `express()`, `app.listen`).
- **Acceptance:** A FastAPI or Hono or Express project yields `app-server` in the profile and its sections appear in the net.

#### Gap 12 — no error handling for malformed/missing scan JSON or template
- **File:** `soc_pipeline.py` `stage2_refine` L230–243 (scan load), L268–271 (template read); `sic_to_soc.py` template read in `main()`.
- **Change:** Wrap scan-JSON load in try/except for `json.JSONDecodeError` and `OSError`; on failure, abort the run with a clear stderr message and a non-zero exit (do not silently post a green report). Wrap template read in try/except `OSError`; on missing template, error out. When scan load fails but `--discord` is set, post a red `BLOCK`-style "scan failed — report not generated" embed so failures are visible, not silent.
- **Acceptance:** A corrupt scan JSON causes a non-zero exit with a readable error and (if `--discord`) a red failure embed; no green report is produced.

#### Gap 13 — only DropStream has scheduled SOC
- **File:** `scripts/dropstream-weekly-soc.mjs` (generalize) or new `scripts/weekly-soc.mjs` + scheduler entry.
- **Change:** Parameterize the weekly script to accept `--project <slug> --path <dir>` so any registered project can be scheduled, reading the project list from `~/.sic/projects.json`. **Stub acceptable:** if full multi-project scheduling is out of budget, extract the project-specific constants into a config block and document how to add a second scheduled project, leaving DropStream as the only wired schedule.
- **Acceptance:** The weekly script runs for at least one non-DropStream project given `--project/--path`, or (stub) a documented config block + second-project instructions exist.

#### Gap 14 — webhook var split: two env-var names for one endpoint
- **File:** `soc_pipeline.py` L458; `scripts/dropstream-weekly-soc.mjs` (its webhook env read).
- **Change:** Canonicalize on `DISCORD_WEBHOOK_SOC`. In both files, read `DISCORD_WEBHOOK_SOC` first, fall back to the legacy name (whatever the `.mjs` uses), and log a one-line deprecation warning when the legacy name is used. Document the canonical name in the SOC skill docs.
- **Acceptance:** Setting only `DISCORD_WEBHOOK_SOC` works for both the Python pipeline and the `.mjs` bridge; setting only the legacy name works with a deprecation warning.

#### Gap 15 — `patchHarnessControls()` regexes silently no-op on root template
- **File:** `scripts/dropstream-weekly-soc.mjs` `patchHarnessControls` region L560–620.
- **Change:** After each `html.replace(...)`, assert the replacement actually changed the string (compare pre/post, or check the regex matched). If a patch regex matches nothing, throw with the failing pattern name so a template drift is loud, not silent. Given gap 2 makes the template read `project-data` directly, several of these brittle regex patches (e.g. `DEFAULT_DONE`, `const DATA`) become redundant and should be removed rather than guarded — keep only the ones still needed (SK namespacing, fp value, "Prepared by").
- **Acceptance:** Running the bridge against a template missing an expected anchor throws a named error; against the current template it succeeds; redundant DATA/DEFAULT_DONE patches are removed.

---

## Files Changed

| File | Gaps | Nature |
|------|------|--------|
| `sic/sic_to_soc.py` | 1, 6, 9 | Add `compute_posture`, `verdict_for`, `stamp_score`; remove old `% done` score; import `_collect` from `scan_merge` |
| `sic/soc_pipeline.py` | 1, 5, 6, 12, 14 | `_extract_posture`, unscanned guard, verdict mapping, error handling, webhook var |
| `sic/scan_merge.py` | 3 | `_collect` reads Secrets[] + Misconfigurations[] |
| `sic/threat_catalog.py` | 4, 7, 8, 11 | Precise probe matching, `refuted` status, `covered_by` coverage, `app-server` component |
| `sic/project_config.py` | 10, 11 | Multi-suffix content detection, app-server signals |
| `sic/templates/soc-handoff/soc-handoff-template-blank.html` | 2 | Read injected `project-data`; DropStream array → fallback; posture short-circuit |
| `scripts/dropstream-weekly-soc.mjs` | 6, 13, 14, 15 | Verdict via Python, parameterize project (stub ok), webhook var, fail-loud patches |
| `sic/tests/test_threat_catalog.py` | 4, 7 | Probe false-positive + refuted regression tests |
| `sic/tests/test_soc_pipeline.py` | 1, 5, 12 | Score-stamp round-trip, unscanned NET, malformed-scan tests |

---

## Non-Goals

- **No new SAST scanner.** Gap 8 only adds coverage-gap accounting; we do not integrate a new static-analysis engine.
- **No full multi-project scheduling overhaul.** Gap 13 may ship as a documented config block + one verified non-DropStream run; we are not building a scheduler UI or registry-driven cron fan-out.
- **No template visual redesign.** The score ring, panes, and checklist UI are unchanged except for the data-source rewiring in §Gap 2. No CSS/layout changes.
- **No change to the SIC scanner stack (`soc_runner`, hexstrike) beyond a `scannersRun` tag** needed for `refuted` accounting.
- **No DB schema migration.** `findings_db.py` persistence is untouched; the posture dict lives in `project_data` and the HTML, not new tables.
- **No secret rotation, no webhook URL changes** — only the env-var *name* is canonicalized (gap 14).
- **No retroactive rescoring** of historical reports in `_runs/qa/`; the rebuild applies to new runs only.
