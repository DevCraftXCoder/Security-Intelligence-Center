"use strict";

// ─── Utilities ────────────────────────────────────────────────────────────────

function escapeHtml(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtDate(iso) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch { return iso; }
}

function fmtUptime(seconds) {
  if (!seconds && seconds !== 0) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  return `${m}m ${s}s`;
}

// ─── Base URLs ───────────────────────────────────────────────────────────────
// Main SIC server on port 9890 (sic-main PM2 process). Auth routes live here.
const SIC_MAIN_BASE = window.location.protocol + "//" + window.location.hostname + ":9890";
// Billing server runs on a separate port.
const BILLING_BASE = window.location.protocol + "//" + window.location.hostname + ":9015";

// billingFetch — routes to the separate billing server on :9015
async function billingFetch(path, options) {
  return apiFetch(BILLING_BASE + path, options);
}

// mainFetch — routes to the main SIC server on :9890 (auth, tools, scan-history)
async function mainFetch(path, options) {
  return apiFetch(SIC_MAIN_BASE + path, options);
}

// ─── apiFetch — centralized fetch with credentials + JSON headers ──────────

async function apiFetch(path, options) {
  const opts = Object.assign(
    { credentials: "include", headers: {} },
    options || {}
  );
  if (options && options.body && typeof options.body === "object" && !(options.body instanceof FormData)) {
    opts.body = JSON.stringify(options.body);
    opts.headers = Object.assign({ "Content-Type": "application/json" }, opts.headers);
  }
  const r = await fetch(path, opts);
  if (!r.ok) {
    const err = new Error("HTTP " + r.status);
    err.status = r.status;
    try { err.body = await r.json(); } catch { err.body = null; }
    throw err;
  }
  // 204 No Content
  if (r.status === 204) return null;
  return r.json();
}

// Legacy alias used by original dashboard code
async function fetchJson(url, opts) {
  return apiFetch(url, opts);
}

// ─── checkAuth — redirect to login if not authenticated ───────────────────
// Try the main SIC server (:9890) first for /auth/me.
// Fall back to the billing server (:9015/api/billing/auth/me) when the
// primary returns 404 (e.g. sic-main not running), so the dashboard stays
// functional even if one server is down.

async function checkAuth() {
  try {
    // Primary: main SIC server on port 9890
    return await mainFetch("/auth/me");
  } catch (e) {
    if (e.status === 404 || e.status === 0) {
      // Port 9890 not running or route missing — try billing server fallback
      try {
        return await billingFetch("/api/billing/auth/me");
      } catch (billingErr) {
        if (billingErr.status === 401 || billingErr.status === 403) {
          window.location.href = "/dashboard/login.html";
        }
        return null;
      }
    }
    if (e.status === 401 || e.status === 403) {
      window.location.href = "/dashboard/login.html";
    }
    return null;
  }
}

// Legacy alias
async function authCheck() {
  return checkAuth();
}

// ─── Badge helpers ─────────────────────────────────────────────────────────

function severityBadge(sev) {
  if (!sev) return "";
  const s = String(sev).toUpperCase();
  const map = {
    P0: "sic-badge--p0",
    P1: "sic-badge--p1",
    P2: "sic-badge--p2",
    CRITICAL: "sic-badge--p0",
    HIGH: "sic-badge--p1",
    MEDIUM: "sic-badge--p2",
    LOW: "sic-badge--low",
    INFO: "sic-badge--info",
  };
  const cls = map[s] || "sic-badge--info";
  return `<span class="sic-badge ${cls}">${escapeHtml(sev)}</span>`;
}

function gradeBadge(grade) {
  if (!grade) return `<span class="sic-grade sic-grade--na">—</span>`;
  const g = String(grade).toUpperCase();
  const cls = {
    A: "sic-grade--a",
    B: "sic-grade--b",
    C: "sic-grade--c",
    D: "sic-grade--d",
    F: "sic-grade--f",
  }[g] || "sic-grade--na";
  return `<span class="sic-grade ${cls}">${escapeHtml(grade)}</span>`;
}

function statusBadge(status) {
  if (!status) return "";
  const s = String(status).toLowerCase().replace(/\s+/g, "-");
  return `<span class="sic-status sic-status--${escapeHtml(s)}">${escapeHtml(status)}</span>`;
}

// ─── Nav helper — highlight active tab ────────────────────────────────────

function initNav(activeId) {
  const links = document.querySelectorAll(".sic-nav__link");
  links.forEach(l => {
    if (l.dataset.page === activeId) l.classList.add("sic-nav__link--active");
  });
}

// ─── Shared header init ────────────────────────────────────────────────────

async function initHeader(activePage) {
  const me = await checkAuth();
  if (!me) return null;
  const emailEl = document.getElementById("user-email");
  if (emailEl) emailEl.textContent = me.email || "admin";
  const logoutBtn = document.getElementById("logout-btn");
  if (logoutBtn) logoutBtn.addEventListener("click", logout);
  if (activePage) initNav(activePage);
  return me;
}

// ─── Dashboard page ────────────────────────────────────────────────────────

async function loadStats() {
  const el = document.getElementById("panel-stats");
  if (!el) return;
  try {
    const { scans } = await apiFetch("/api/scans?limit=200");
    const counts = { total: scans.length, completed: 0, failed: 0, running: 0, killed: 0 };
    for (const s of scans) counts[s.status] = (counts[s.status] || 0) + 1;
    const totalFindings = scans.reduce((n, s) => n + (s.findings_count || 0), 0);
    el.innerHTML = `
      <div class="sic-stat"><div class="sic-stat__num">${counts.total}</div><div class="sic-stat__label">Total Scans</div></div>
      <div class="sic-stat"><div class="sic-stat__num sic-stat__num--green">${counts.completed}</div><div class="sic-stat__label">Completed</div></div>
      <div class="sic-stat"><div class="sic-stat__num sic-stat__num--red">${counts.failed}</div><div class="sic-stat__label">Failed</div></div>
      <div class="sic-stat"><div class="sic-stat__num sic-stat__num--blue">${counts.running}</div><div class="sic-stat__label">Running</div></div>
      <div class="sic-stat"><div class="sic-stat__num">${totalFindings}</div><div class="sic-stat__label">Findings</div></div>
    `;
  } catch (e) {
    el.innerHTML = `<div class="sic-error">Failed to load stats (${escapeHtml(e.message)})</div>`;
  }
}

async function loadRecent() {
  const el = document.getElementById("panel-recent");
  if (!el) return;
  try {
    const { scans } = await apiFetch("/api/scans?limit=10");
    if (!scans || scans.length === 0) {
      el.innerHTML = `<div class="sic-empty">No scans recorded yet.</div>`;
      return;
    }
    const rows = scans.map(s => `
      <tr>
        <td>${escapeHtml(fmtDate(s.started_at))}</td>
        <td class="mono">${escapeHtml(s.scan_type || "—")}</td>
        <td class="mono">${escapeHtml(s.target || "—")}</td>
        <td>${statusBadge(s.status)}</td>
        <td>${s.findings_count || 0}</td>
      </tr>
    `).join("");
    el.innerHTML = `
      <table class="sic-table">
        <thead><tr><th>Started</th><th>Type</th><th>Target</th><th>Status</th><th>Findings</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    `;
  } catch (e) {
    el.innerHTML = `<div class="sic-error">Failed to load recent scans (${escapeHtml(e.message)})</div>`;
  }
}

async function loadHealth() {
  const el = document.getElementById("panel-health");
  if (!el) return;
  try {
    const data = await apiFetch("/health");
    const statusCls = data.status === "ok" ? "sic-stat__num--green" : "sic-stat__num--red";
    el.innerHTML = `
      <div class="sic-stats-row" style="gap:20px;flex-wrap:wrap">
        <div class="sic-stat">
          <div class="sic-stat__num ${statusCls}" style="font-size:16px;text-transform:uppercase">${escapeHtml(data.status || "unknown")}</div>
          <div class="sic-stat__label">Status</div>
        </div>
        <div class="sic-stat">
          <div class="sic-stat__num" style="font-size:18px">${escapeHtml(fmtUptime(data.uptime_s))}</div>
          <div class="sic-stat__label">Uptime</div>
        </div>
        <div class="sic-stat">
          <div class="sic-stat__num" style="font-size:18px">${data.scan_queue_size != null ? data.scan_queue_size : "—"}</div>
          <div class="sic-stat__label">Queue</div>
        </div>
        <div class="sic-stat">
          <div class="sic-stat__num mono" style="font-size:14px">${escapeHtml(data.version || "—")}</div>
          <div class="sic-stat__label">Version</div>
        </div>
      </div>
    `;
  } catch (e) {
    el.innerHTML = `<div class="sic-error">Health endpoint unreachable (${escapeHtml(e.message)})</div>`;
  }
}

async function startScan(target, type) {
  return apiFetch("/api/command", {
    method: "POST",
    body: { command: "full_scan", target },
  });
}

function initScanForm() {
  const btn = document.getElementById("scan-btn");
  const input = document.getElementById("scan-target");
  const msg = document.getElementById("scan-msg");
  if (!btn || !input) return;
  btn.addEventListener("click", async () => {
    const target = input.value.trim();
    if (!target) { msg.innerHTML = `<div class="sic-error">Enter a target first.</div>`; return; }
    btn.disabled = true;
    btn.textContent = "Starting…";
    msg.innerHTML = "";
    try {
      const res = await startScan(target);
      msg.innerHTML = `<div class="sic-success">Scan queued${res && res.id ? ` (ID: ${escapeHtml(String(res.id))})` : ""}.</div>`;
      input.value = "";
      setTimeout(() => { loadStats(); loadRecent(); }, 1200);
    } catch (e) {
      const reason = (e.body && e.body.error) || e.message;
      msg.innerHTML = `<div class="sic-error">${escapeHtml(reason)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Start Scan";
    }
  });
}

// ─── Login page ────────────────────────────────────────────────────────────

async function logout() {
  try { await fetch("/auth/logout", { method: "POST", credentials: "include" }); } catch {}
  window.location.href = "/dashboard/login.html";
}

function initLogin() {
  const form = document.getElementById("login-form");
  const msg = document.getElementById("login-msg");
  if (!form) return;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    msg.innerHTML = "";
    const email = form.email.value.trim();
    if (!email) return;
    try {
      const data = await mainFetch("/auth/request-link", {
        method: "POST",
        body: { email },
      });
      const expires = data.expires_at ? new Date(data.expires_at * 1000).toLocaleTimeString() : "—";
      let html = `<div class="sic-success">Magic link sent. Expires at ${escapeHtml(expires)}.</div>`;
      if (data.link) {
        html += `<div class="sic-stat__label" style="margin-top:8px">Dev mode link:</div><a class="sic-link" href="${escapeHtml(data.link)}">${escapeHtml(data.link)}</a>`;
      }
      msg.innerHTML = html;
    } catch (e) {
      const reason = (e.body && e.body.error) || e.message;
      msg.innerHTML = `<div class="sic-error">${escapeHtml(reason)}</div>`;
    }
  });

  // Clicking the centered logo cycles: Glitch → Galaxy → Navy → Glitch
  const cycleBtn = document.getElementById("login-bg-cycle");
  if (cycleBtn) {
    const BG_CYCLE = ["glitch", "galaxy", "navy"];
    function cycleBg() {
      const cur = localStorage.getItem("sic-bg-theme") || "default";
      const next = BG_CYCLE[(BG_CYCLE.indexOf(cur) + 1) % BG_CYCLE.length];
      localStorage.setItem("sic-bg-theme", next);
      applyTheme(next);
    }
    cycleBtn.addEventListener("click", (e) => {
      if (e.target.closest("input")) return;
      cycleBg();
    });
    cycleBtn.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); cycleBg(); }
    });
  }
}

// ─── Posture Grid page ─────────────────────────────────────────────────────

const POSTURE_DOMAINS = [
  { key: "audit",           label: "Audit" },
  { key: "posture",         label: "Posture" },
  { key: "vulnerabilities", label: "Vulnerabilities" },
  { key: "secrets",         label: "Secrets" },
  { key: "dependencies",    label: "Dependencies" },
  { key: "threats",         label: "Threats" },
  { key: "ai_fix",          label: "AI Fix" },
  { key: "zero_trust",      label: "Zero-Trust" },
  { key: "incidents",       label: "Incidents" },
];

function scoreToGrade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 45) return "D";
  return "F";
}

function buildDomainMap(findings) {
  const map = {};
  POSTURE_DOMAINS.forEach(d => { map[d.key] = []; });
  (findings || []).forEach(f => {
    const cat = (f.category || "").toLowerCase().replace(/[^a-z0-9_]/g, "_");
    const matchKey = POSTURE_DOMAINS.find(d => d.key === cat || d.label.toLowerCase() === cat);
    if (matchKey) map[matchKey.key].push(f);
  });
  return map;
}

function computeScore(domainFindings) {
  if (!domainFindings || domainFindings.length === 0) return null;
  let penalty = 0;
  domainFindings.forEach(f => {
    const sev = (f.severity || "").toUpperCase();
    if (sev === "CRITICAL" || sev === "P0") penalty += 25;
    else if (sev === "HIGH" || sev === "P1") penalty += 15;
    else if (sev === "MEDIUM" || sev === "P2") penalty += 8;
    else penalty += 3;
  });
  return Math.max(0, Math.min(100, 100 - penalty));
}

function buildScoreRingSvg(score) {
  if (score === null) {
    return `<svg viewBox="0 0 44 44" class="sic-score-ring"><circle cx="22" cy="22" r="18" fill="none" stroke="var(--sic-border)" stroke-width="4"/><text x="22" y="26" text-anchor="middle" fill="var(--sic-text-muted)" font-size="10">—</text></svg>`;
  }
  const r = 18;
  const circ = 2 * Math.PI * r;
  const pct = score / 100;
  const dash = (circ * pct).toFixed(2);
  const gap = (circ * (1 - pct)).toFixed(2);
  const grade = scoreToGrade(score);
  const gradeColor = { A: "#5acc8a", B: "#6cb0ff", C: "#f0c040", D: "#ff8c42", F: "#ff5266" }[grade] || "#888";
  return `<svg viewBox="0 0 44 44" class="sic-score-ring">
    <circle cx="22" cy="22" r="${r}" fill="none" stroke="var(--sic-border)" stroke-width="4"/>
    <circle cx="22" cy="22" r="${r}" fill="none" stroke="${gradeColor}" stroke-width="4"
      stroke-dasharray="${dash} ${gap}"
      stroke-dashoffset="${(circ * 0.25).toFixed(2)}"
      transform="rotate(-90 22 22)"
      stroke-linecap="round"/>
    <text x="22" y="25" text-anchor="middle" fill="${gradeColor}" font-size="11" font-weight="700">${grade}</text>
  </svg>`;
}

function renderPostureGrid(domainMap) {
  const grid = document.getElementById("posture-grid");
  if (!grid) return;
  grid.innerHTML = POSTURE_DOMAINS.map(d => {
    const findings = domainMap[d.key] || [];
    const score = findings.length > 0 ? computeScore(findings) : null;
    const grade = score !== null ? scoreToGrade(score) : null;
    return `
      <div class="sic-domain-card" data-domain="${escapeHtml(d.key)}" tabindex="0" role="button" aria-label="${escapeHtml(d.label)} domain">
        <div class="sic-domain-card__ring">${buildScoreRingSvg(score)}</div>
        <div class="sic-domain-card__body">
          <div class="sic-domain-card__name">${escapeHtml(d.label)}</div>
          <div class="sic-domain-card__meta">
            <span class="sic-domain-card__count">${findings.length} finding${findings.length !== 1 ? "s" : ""}</span>
            ${score !== null ? `<span class="sic-domain-card__score">${score}/100</span>` : ""}
          </div>
        </div>
      </div>
    `;
  }).join("");

  grid.querySelectorAll(".sic-domain-card").forEach(card => {
    card.addEventListener("click", () => openPosturePanel(card.dataset.domain, domainMap));
    card.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") openPosturePanel(card.dataset.domain, domainMap); });
  });
}

function openPosturePanel(domainKey, domainMap) {
  const domain = POSTURE_DOMAINS.find(d => d.key === domainKey);
  const findings = (domainMap[domainKey] || []);
  const overlay = document.getElementById("posture-panel-overlay");
  const panel = document.getElementById("posture-panel");
  const title = document.getElementById("posture-panel-title");
  const body = document.getElementById("posture-panel-body");
  if (!overlay || !panel) return;

  title.textContent = domain ? domain.label : domainKey;

  if (findings.length === 0) {
    body.innerHTML = `<div class="sic-empty">No findings for this domain.</div>`;
  } else {
    const rows = findings.map(f => `
      <div class="sic-finding-row">
        <div class="sic-finding-row__header">
          ${severityBadge(f.severity || f.priority || "INFO")}
          <span class="sic-finding-row__title">${escapeHtml(f.title || f.name || "Unnamed finding")}</span>
        </div>
        ${f.description ? `<div class="sic-finding-row__desc">${escapeHtml(f.description)}</div>` : ""}
        ${f.file || f.location ? `<div class="sic-finding-row__loc mono">${escapeHtml(f.file || f.location)}</div>` : ""}
      </div>
    `).join("");
    body.innerHTML = rows;
  }

  overlay.style.display = "block";
  requestAnimationFrame(() => overlay.classList.add("sic-overlay--open"));
}

function closePosturePanel() {
  const overlay = document.getElementById("posture-panel-overlay");
  if (!overlay) return;
  overlay.classList.remove("sic-overlay--open");
  overlay.addEventListener("transitionend", () => { overlay.style.display = "none"; }, { once: true });
}

async function initPosture() {
  const me = await initHeader("posture");
  if (!me) return;

  const grid = document.getElementById("posture-grid");
  const scanInfo = document.getElementById("posture-scan-info");

  // Close button
  const closeBtn = document.getElementById("posture-panel-close");
  if (closeBtn) closeBtn.addEventListener("click", closePosturePanel);
  const overlay = document.getElementById("posture-panel-overlay");
  if (overlay) overlay.addEventListener("click", e => { if (e.target === overlay) closePosturePanel(); });

  try {
    const { scans } = await apiFetch("/api/scans?limit=50");
    const completed = (scans || []).filter(s => s.status === "completed");

    if (!completed.length) {
      grid.innerHTML = POSTURE_DOMAINS.map(d => `
        <div class="sic-domain-card sic-domain-card--empty">
          <div class="sic-domain-card__ring">${buildScoreRingSvg(null)}</div>
          <div class="sic-domain-card__body">
            <div class="sic-domain-card__name">${escapeHtml(d.label)}</div>
            <div class="sic-domain-card__meta"><span class="sic-domain-card__count">No data</span></div>
          </div>
        </div>
      `).join("");
      if (scanInfo) scanInfo.textContent = "No completed scans found.";
      return;
    }

    const latest = completed[0];
    if (scanInfo) scanInfo.textContent = `Posture based on scan #${latest.id} — ${fmtDate(latest.started_at)}`;

    let findings = [];
    try {
      const detail = await apiFetch(`/api/scans/${latest.id}`);
      findings = detail.findings || detail.scan?.findings || [];
    } catch {}

    const domainMap = buildDomainMap(findings);
    renderPostureGrid(domainMap);
  } catch (e) {
    grid.innerHTML = `<div class="sic-error" style="grid-column:1/-1">Failed to load posture data (${escapeHtml(e.message)})</div>`;
  }
}

// ─── Incidents page ────────────────────────────────────────────────────────

let _incidents = [];
let _incidentFilters = { severity: null, status: null };

async function loadIncidents() {
  const tbody = document.getElementById("incidents-tbody");
  const empty = document.getElementById("incidents-empty");
  if (!tbody) return;
  try {
    const data = await apiFetch("/api/incidents");
    _incidents = Array.isArray(data) ? data : (data.incidents || []);
    renderIncidentTable();
  } catch (e) {
    if (empty) empty.innerHTML = `<div class="sic-error">Failed to load incidents (${escapeHtml(e.message)})</div>`;
  }
}

function renderIncidentTable() {
  const tbody = document.getElementById("incidents-tbody");
  const empty = document.getElementById("incidents-empty");
  if (!tbody) return;

  let rows = _incidents;
  if (_incidentFilters.severity) rows = rows.filter(i => i.severity === _incidentFilters.severity);
  if (_incidentFilters.status) rows = rows.filter(i => (i.status || "").toLowerCase().replace(/\s+/g, "-") === _incidentFilters.status);

  tbody.innerHTML = "";
  if (rows.length === 0) {
    if (empty) empty.style.display = "block";
    return;
  }
  if (empty) empty.style.display = "none";

  rows.forEach(inc => {
    const tr = document.createElement("tr");
    tr.className = "sic-incident-row";
    tr.dataset.id = inc.id;
    tr.innerHTML = `
      <td>${severityBadge(inc.severity || "P2")}</td>
      <td class="sic-incident-title">${escapeHtml(inc.title || "Untitled")}</td>
      <td>${statusBadge(inc.status || "open")}</td>
      <td class="mono">${escapeHtml(fmtDate(inc.created_at))}</td>
      <td class="mono">${escapeHtml(fmtDate(inc.updated_at))}</td>
    `;
    tr.addEventListener("click", () => toggleIncidentExpand(inc, tr));
    tbody.appendChild(tr);
  });
}

function toggleIncidentExpand(inc, tr) {
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains("sic-incident-expand")) {
    existing.remove();
    tr.classList.remove("sic-incident-row--open");
    return;
  }

  // Close any other open expansions
  document.querySelectorAll(".sic-incident-expand").forEach(el => el.remove());
  document.querySelectorAll(".sic-incident-row--open").forEach(el => el.classList.remove("sic-incident-row--open"));

  tr.classList.add("sic-incident-row--open");
  const expand = document.createElement("tr");
  expand.className = "sic-incident-expand";
  expand.innerHTML = `
    <td colspan="5">
      <div class="sic-incident-detail">
        <div class="sic-incident-detail__timeline">
          <div class="sic-incident-detail__label">Timeline Notes</div>
          <div class="sic-incident-detail__notes">${escapeHtml(inc.description || inc.notes || "No notes recorded.")}</div>
        </div>
        <div class="sic-incident-detail__actions">
          <div class="sic-incident-detail__label">Update Status</div>
          <div class="sic-incident-detail__form">
            <select class="sic-input sic-incident-status-select" id="inc-status-${inc.id}">
              <option value="open" ${inc.status === "open" ? "selected" : ""}>Open</option>
              <option value="in-progress" ${inc.status === "in-progress" ? "selected" : ""}>In Progress</option>
              <option value="resolved" ${inc.status === "resolved" ? "selected" : ""}>Resolved</option>
            </select>
            <textarea class="sic-input sic-incident-note" id="inc-note-${inc.id}" placeholder="Add a note…" rows="2"></textarea>
            <button class="sic-btn sic-btn--primary" id="inc-save-${inc.id}">Save</button>
            <span class="sic-incident-save-msg" id="inc-msg-${inc.id}"></span>
          </div>
        </div>
      </div>
    </td>
  `;
  tr.after(expand);

  document.getElementById(`inc-save-${inc.id}`).addEventListener("click", async () => {
    const status = document.getElementById(`inc-status-${inc.id}`).value;
    const note = document.getElementById(`inc-note-${inc.id}`).value.trim();
    const msg = document.getElementById(`inc-msg-${inc.id}`);
    try {
      await apiFetch(`/api/incidents/${inc.id}`, {
        method: "PATCH",
        body: { status, note },
      });
      msg.innerHTML = `<span class="sic-success">Saved.</span>`;
      inc.status = status;
      if (note) inc.notes = (inc.notes ? inc.notes + "\n" : "") + note;
      renderIncidentTable();
    } catch (e) {
      const reason = (e.body && e.body.error) || e.message;
      msg.innerHTML = `<span class="sic-error">${escapeHtml(reason)}</span>`;
    }
  });
}

function initNewIncidentForm() {
  const btn = document.getElementById("new-incident-btn");
  const formEl = document.getElementById("new-incident-form");
  const cancelBtn = document.getElementById("new-incident-cancel");
  const submitBtn = document.getElementById("new-incident-submit");
  const msg = document.getElementById("new-incident-msg");
  if (!btn || !formEl) return;

  btn.addEventListener("click", () => {
    formEl.style.display = formEl.style.display === "none" ? "block" : "none";
  });
  if (cancelBtn) cancelBtn.addEventListener("click", () => { formEl.style.display = "none"; });

  if (submitBtn) submitBtn.addEventListener("click", async () => {
    const title = document.getElementById("ni-title").value.trim();
    const severity = document.getElementById("ni-severity").value;
    const description = document.getElementById("ni-description").value.trim();
    if (!title) { msg.innerHTML = `<div class="sic-error">Title is required.</div>`; return; }
    submitBtn.disabled = true;
    msg.innerHTML = "";
    try {
      await apiFetch("/api/incidents", {
        method: "POST",
        body: { title, severity, description },
      });
      msg.innerHTML = `<div class="sic-success">Incident created.</div>`;
      document.getElementById("ni-title").value = "";
      document.getElementById("ni-description").value = "";
      formEl.style.display = "none";
      await loadIncidents();
    } catch (e) {
      const reason = (e.body && e.body.error) || e.message;
      msg.innerHTML = `<div class="sic-error">${escapeHtml(reason)}</div>`;
    } finally {
      submitBtn.disabled = false;
    }
  });
}

function initIncidentFilters() {
  document.querySelectorAll("[data-sev-filter]").forEach(btn => {
    btn.addEventListener("click", () => {
      const val = btn.dataset.sevFilter;
      _incidentFilters.severity = _incidentFilters.severity === val ? null : val;
      document.querySelectorAll("[data-sev-filter]").forEach(b => b.classList.toggle("sic-btn--active", b.dataset.sevFilter === _incidentFilters.severity));
      renderIncidentTable();
    });
  });
  document.querySelectorAll("[data-status-filter]").forEach(btn => {
    btn.addEventListener("click", () => {
      const val = btn.dataset.statusFilter;
      _incidentFilters.status = _incidentFilters.status === val ? null : val;
      document.querySelectorAll("[data-status-filter]").forEach(b => b.classList.toggle("sic-btn--active", b.dataset.statusFilter === _incidentFilters.status));
      renderIncidentTable();
    });
  });
}

async function initIncidents() {
  const me = await initHeader("incidents");
  if (!me) return;
  initNewIncidentForm();
  initIncidentFilters();
  await loadIncidents();
}

// ─── AI Fix page ───────────────────────────────────────────────────────────

let _currentFinding = null;

async function loadAiFindings() {
  const list = document.getElementById("ai-findings-list");
  if (!list) return;
  list.innerHTML = `<div class="sic-empty">Loading scans…</div>`;
  try {
    const { scans } = await apiFetch("/api/scans?limit=50");
    const completed = (scans || []).filter(s => s.status === "completed");
    if (!completed.length) {
      list.innerHTML = `<div class="sic-empty">No completed scans found.</div>`;
      return;
    }
    const latest = completed[0];
    let findings = [];
    try {
      const detail = await apiFetch(`/api/scans/${latest.id}`);
      findings = detail.findings || detail.scan?.findings || [];
    } catch {}

    const open = findings.filter(f => !f.resolved && f.status !== "resolved");
    if (!open.length) {
      list.innerHTML = `<div class="sic-empty">No open findings in latest scan.</div>`;
      return;
    }

    list.innerHTML = open.map((f, idx) => `
      <div class="sic-ai-finding" data-idx="${idx}" tabindex="0" role="button">
        ${severityBadge(f.severity || f.priority || "INFO")}
        <div class="sic-ai-finding__info">
          <div class="sic-ai-finding__title">${escapeHtml(f.title || f.name || "Unnamed finding")}</div>
          <div class="sic-ai-finding__cat">${escapeHtml(f.category || "")}</div>
        </div>
      </div>
    `).join("");

    list.querySelectorAll(".sic-ai-finding").forEach((el, idx) => {
      el.addEventListener("click", () => selectFinding(open[idx]));
      el.addEventListener("keydown", e => { if (e.key === "Enter" || e.key === " ") selectFinding(open[idx]); });
    });

    // Auto-select first
    if (open.length > 0) selectFinding(open[0]);
  } catch (e) {
    list.innerHTML = `<div class="sic-error">Failed to load findings (${escapeHtml(e.message)})</div>`;
  }
}

function selectFinding(finding) {
  _currentFinding = finding;
  document.querySelectorAll(".sic-ai-finding").forEach(el => el.classList.remove("sic-ai-finding--active"));
  const idx = _currentFinding && document.querySelector(`[data-idx]`);
  // highlight matching
  document.querySelectorAll(".sic-ai-finding").forEach(el => {
    const i = parseInt(el.dataset.idx, 10);
    if (finding === _currentFinding) {
      // compare by title
      const t = el.querySelector(".sic-ai-finding__title");
      if (t && t.textContent === (finding.title || finding.name || "Unnamed finding")) {
        el.classList.add("sic-ai-finding--active");
      }
    }
  });

  const detail = document.getElementById("ai-detail");
  const placeholder = document.getElementById("ai-placeholder");
  if (placeholder) placeholder.style.display = "none";
  if (detail) {
    detail.style.display = "block";
    document.getElementById("ai-detail-title").textContent = finding.title || finding.name || "Unnamed finding";
    document.getElementById("ai-detail-severity").innerHTML = severityBadge(finding.severity || "INFO");
    document.getElementById("ai-detail-category").textContent = finding.category || "—";
    document.getElementById("ai-detail-desc").textContent = finding.description || "No description provided.";
    document.getElementById("ai-detail-location").textContent = finding.file || finding.location || "—";
    document.getElementById("ai-fix-result").style.display = "none";
    document.getElementById("ai-fix-result").innerHTML = "";
  }
}

async function requestAiFix() {
  if (!_currentFinding) return;
  const btn = document.getElementById("ai-get-fix-btn");
  const resultEl = document.getElementById("ai-fix-result");
  btn.disabled = true;
  btn.textContent = "Analyzing…";
  resultEl.style.display = "none";

  try {
    const payload = {
      finding_id: _currentFinding.id,
      title: _currentFinding.title || _currentFinding.name || "",
      description: _currentFinding.description || "",
      category: _currentFinding.category || "",
      severity: _currentFinding.severity || _currentFinding.priority || "INFO",
    };
    const res = await apiFetch("/api/ai/grade", {
      method: "POST",
      body: payload,
    });
    const oneLiner = res["1_line_fix"] || res.one_line_fix || "";
    const confPct = res.confidence != null ? Math.round(res.confidence * (res.confidence <= 1 ? 100 : 1)) : null;
    const fpRisk = res.false_positive_risk;
    const remediation = res.remediation || "";

    resultEl.style.display = "block";
    resultEl.innerHTML = `
      <div class="sic-ai-result">
        <div class="sic-ai-result__meta">
          ${confPct != null ? `<span class="sic-badge sic-badge--info">Confidence: ${confPct}%</span>` : ""}
          ${fpRisk != null ? `<span class="sic-badge sic-badge--p2">FP Risk: ${escapeHtml(String(fpRisk))}</span>` : ""}
        </div>
        ${oneLiner ? `<div class="sic-ai-result__oneliner"><span class="sic-ai-result__oneliner-label">Quick fix</span><code class="sic-ai-result__code">${escapeHtml(oneLiner)}</code><button class="sic-btn sic-btn--ghost sic-copy-btn" data-copy="${escapeHtml(oneLiner)}">Copy</button></div>` : ""}
        <div class="sic-ai-result__label">Remediation</div>
        <div class="sic-ai-result__body">${escapeHtml(remediation) || "<em>No remediation provided.</em>"}</div>
      </div>
    `;
    resultEl.querySelectorAll(".sic-copy-btn").forEach(btn => {
      btn.addEventListener("click", () => {
        navigator.clipboard.writeText(btn.dataset.copy || "").then(() => {
          btn.textContent = "Copied!";
          setTimeout(() => { btn.textContent = "Copy"; }, 1500);
        });
      });
    });
  } catch (e) {
    const reason = (e.body && e.body.error) || e.message;
    resultEl.style.display = "block";
    resultEl.innerHTML = `<div class="sic-error">AI fix failed: ${escapeHtml(reason)}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Get AI Fix";
  }
}

async function initAiFix() {
  const me = await initHeader("aifix");
  if (!me) return;

  const fixBtn = document.getElementById("ai-get-fix-btn");
  if (fixBtn) fixBtn.addEventListener("click", requestAiFix);

  await loadAiFindings();
}

// ─── Page router ───────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initTheme();
  initLogoUpload();
  initControlBar();
  const page = document.body.dataset.page;
  switch (page) {
    case "login":     initLogin(); break;
    case "dashboard": initDashboard(); break;
    case "posture":   initPosture(); break;
    case "incidents": initIncidents(); break;
    case "aifix":     initAiFix(); break;
    default:
      // Fallback: detect by element presence (backward compat)
      if (document.getElementById("login-form")) initLogin();
      else if (document.getElementById("user-email")) initDashboard();
      break;
  }
});

// ─── Theme engine (Galaxy / Navy) ────────────────────────────────────────────

let _galaxyRaf = null;
let _glitchInterval = null;

function initTheme() {
  const saved = localStorage.getItem("sic-bg-theme") || "default";
  applyTheme(saved);
}

function applyTheme(theme) {
  const root = document.documentElement;
  root.classList.remove("theme-navy", "theme-galaxy", "theme-glitch");
  root.classList.add("theme-" + theme);
  if (theme === "galaxy") {
    startGalaxy();
  } else if (theme === "glitch") {
    startLetterGlitch();
  } else {
    stopGalaxy();
  }
  updateThemeToggleLabel(theme);
  updateControlBarActive(theme);
}

function toggleTheme() {
  const root = document.documentElement;
  let current = "default";
  if (root.classList.contains("theme-navy")) current = "navy";
  else if (root.classList.contains("theme-galaxy")) current = "galaxy";
  else if (root.classList.contains("theme-glitch")) current = "glitch";
  const next = current === "default" ? "galaxy" : current === "galaxy" ? "glitch" : "default";
  localStorage.setItem("sic-bg-theme", next);
  applyTheme(next);
}

function updateThemeToggleLabel(theme) {
  document.querySelectorAll(".sic-theme-toggle").forEach(btn => {
    if (theme === "default" || theme === "navy") {
      btn.textContent = "✦ Galaxy";
      btn.title = "Switch to Galaxy";
    } else if (theme === "galaxy") {
      btn.textContent = "⬡ Glitch";
      btn.title = "Switch to Letter Glitch";
    } else {
      btn.textContent = "◈ Default";
      btn.title = "Switch to Default";
    }
  });
}

function startGalaxy() {
  const canvas = document.getElementById("galaxy-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  let stars = [];
  let w, h;

  function resize() {
    w = canvas.width = window.innerWidth;
    h = canvas.height = window.innerHeight;
  }

  function initStars() {
    stars = Array.from({ length: 220 }, () => ({
      x: Math.random() * w,
      y: Math.random() * h,
      r: Math.random() * 1.4 + 0.2,
      speed: Math.random() * 0.25 + 0.05,
      alpha: Math.random() * 0.7 + 0.2,
      twinkleSpeed: Math.random() * 0.02 + 0.005,
      twinklePhase: Math.random() * Math.PI * 2,
    }));
  }

  function draw(ts) {
    if (!document.documentElement.classList.contains("theme-galaxy")) {
      stopGalaxy();
      return;
    }
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "#07111e";
    ctx.fillRect(0, 0, w, h);

    const grad = ctx.createRadialGradient(w * 0.3, h * 0.4, 0, w * 0.3, h * 0.4, w * 0.45);
    grad.addColorStop(0, "rgba(30, 60, 120, 0.18)");
    grad.addColorStop(1, "transparent");
    ctx.fillStyle = grad;
    ctx.fillRect(0, 0, w, h);

    const grad2 = ctx.createRadialGradient(w * 0.75, h * 0.65, 0, w * 0.75, h * 0.65, w * 0.35);
    grad2.addColorStop(0, "rgba(80, 20, 80, 0.12)");
    grad2.addColorStop(1, "transparent");
    ctx.fillStyle = grad2;
    ctx.fillRect(0, 0, w, h);

    const t = ts * 0.001;
    for (const s of stars) {
      s.y += s.speed;
      if (s.y > h) { s.y = 0; s.x = Math.random() * w; }
      const twinkle = s.alpha * (0.6 + 0.4 * Math.sin(t * s.twinkleSpeed * 60 + s.twinklePhase));
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fillStyle = "rgba(200, 220, 255, " + twinkle + ")";
      ctx.fill();
    }

    _galaxyRaf = requestAnimationFrame(draw);
  }

  if (_galaxyRaf) cancelAnimationFrame(_galaxyRaf);
  resize();
  initStars();
  window.addEventListener("resize", () => { resize(); initStars(); });
  _galaxyRaf = requestAnimationFrame(draw);
}

function stopGalaxy() {
  if (_galaxyRaf) {
    cancelAnimationFrame(_galaxyRaf);
    _galaxyRaf = null;
  }
  if (_glitchInterval) {
    clearTimeout(_glitchInterval);
    _glitchInterval = null;
  }
  const canvas = document.getElementById("galaxy-canvas");
  if (canvas) {
    const ctx = canvas.getContext("2d");
    ctx.clearRect(0, 0, canvas.width, canvas.height);
  }
}

// ─── Letter Glitch background ─────────────────────────────────────────────────

function startLetterGlitch() {
  stopGalaxy(); // cancel galaxy rAF if active

  const canvas = document.getElementById("galaxy-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");

  const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$&*()-_+=/[]{};:<>.,0123456789";
  const glitchColors = ["#1a0408", "#e94560", "#4a0f1e"];
  const charWidth = 10;
  const charHeight = 20;

  let cols, rows, grid, colorIndices, nextColorIndices, transitionProgress;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    cols = Math.ceil(canvas.width / charWidth);
    rows = Math.ceil(canvas.height / charHeight);
    grid = Array.from({ length: cols }, () =>
      Array.from({ length: rows }, () => characters[Math.floor(Math.random() * characters.length)])
    );
    colorIndices = Array.from({ length: cols }, () =>
      Array.from({ length: rows }, () => Math.floor(Math.random() * glitchColors.length))
    );
    nextColorIndices = colorIndices.map(col => [...col]);
    transitionProgress = Array.from({ length: cols }, () =>
      Array.from({ length: rows }, () => 1)
    );
  }

  function lerpColor(a, b, t) {
    const h = c => [parseInt(c.slice(1,3),16), parseInt(c.slice(3,5),16), parseInt(c.slice(5,7),16)];
    const [r1,g1,b1] = h(a), [r2,g2,b2] = h(b);
    return `rgb(${Math.round(r1+(r2-r1)*t)},${Math.round(g1+(g2-g1)*t)},${Math.round(b1+(b2-b1)*t)})`;
  }

  function tick() {
    if (!document.documentElement.classList.contains("theme-glitch")) {
      stopGalaxy();
      return;
    }

    // Resource saving — skip draw when tab is hidden, poll at 200ms
    if (document.hidden) {
      _glitchInterval = setTimeout(tick, 200);
      return;
    }

    const totalCells = cols * rows;
    const numToUpdate = Math.max(1, Math.floor(totalCells * 0.05));
    for (let i = 0; i < numToUpdate; i++) {
      const col = Math.floor(Math.random() * cols);
      const row = Math.floor(Math.random() * rows);
      grid[col][row] = characters[Math.floor(Math.random() * characters.length)];
      nextColorIndices[col][row] = Math.floor(Math.random() * glitchColors.length);
      transitionProgress[col][row] = 0;
    }

    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.font = "16px monospace";
    ctx.textBaseline = "top";

    for (let col = 0; col < cols; col++) {
      for (let row = 0; row < rows; row++) {
        const p = Math.min(1, (transitionProgress[col][row] || 1) + 0.05);
        transitionProgress[col][row] = p;
        if (p >= 1) colorIndices[col][row] = nextColorIndices[col][row];
        ctx.fillStyle = lerpColor(glitchColors[colorIndices[col][row]], glitchColors[nextColorIndices[col][row]], p);
        ctx.fillText(grid[col][row], col * charWidth, row * charHeight);
      }
    }

    _glitchInterval = setTimeout(tick, 50);
  }

  resize();
  window.addEventListener("resize", resize);
  tick();
}

// ─── Logo upload ──────────────────────────────────────────────────────────────

function initLogoUpload() {
  const logoWrap = document.querySelector(".sic-header__logo-wrap, .sic-login-logo");
  if (!logoWrap) return;

  const logoText = document.getElementById("logo-text");
  const logoImg  = document.getElementById("logo-img");
  const uploadBtn = document.getElementById("logo-upload-btn");
  const fileInput = document.getElementById("logo-file");

  const saved = localStorage.getItem("sic-custom-logo");
  if (saved && logoImg && logoText) {
    logoImg.src = saved;
    logoImg.style.display = "inline-block";
    logoText.style.display = "none";
  }

  if (!uploadBtn || !fileInput) return;

  uploadBtn.addEventListener("click", () => fileInput.click());

  fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) return;
    if (file.size > 2 * 1024 * 1024) {
      alert("Logo image must be under 2MB.");
      return;
    }
    const reader = new FileReader();
    reader.onload = (e) => {
      const dataUrl = e.target.result;
      localStorage.setItem("sic-custom-logo", dataUrl);
      if (logoImg) {
        logoImg.src = dataUrl;
        logoImg.style.display = "inline-block";
      }
      if (logoText) logoText.style.display = "none";
    };
    reader.readAsDataURL(file);
  });

  if (logoImg) {
    logoImg.addEventListener("contextmenu", (e) => {
      e.preventDefault();
      if (confirm("Reset to default SIC logo?")) {
        localStorage.removeItem("sic-custom-logo");
        logoImg.style.display = "none";
        logoImg.src = "";
        if (logoText) logoText.style.display = "";
      }
    });
  }
}

async function initDashboard() {
  const me = await initHeader("dashboard");
  if (!me) return;
  initScanForm();
  loadStats();
  loadRecent();
  loadHealth();
}

// ─── Control bar (logo-toggle settings) ──────────────────────────────────────

function initControlBar() {
  const bar = document.getElementById("control-bar");
  const logoToggle = document.getElementById("logo-toggle");
  if (!bar || !logoToggle) return;

  function setOpen(open) {
    bar.classList.toggle("is-open", open);
    bar.setAttribute("aria-hidden", open ? "false" : "true");
    logoToggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  function toggle() {
    setOpen(!bar.classList.contains("is-open"));
  }

  logoToggle.addEventListener("click", (e) => {
    if (e.target.closest("input")) return;
    toggle();
  });

  logoToggle.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      toggle();
    }
  });

  const closeBtn = document.getElementById("control-bar-close");
  if (closeBtn) closeBtn.addEventListener("click", () => setOpen(false));

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && bar.classList.contains("is-open")) setOpen(false);
  });

  bar.querySelectorAll(".sic-control-bar__btn[data-theme]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const theme = btn.dataset.theme;
      localStorage.setItem("sic-bg-theme", theme);
      applyTheme(theme);
    });
  });

  const saved = localStorage.getItem("sic-bg-theme") || "default";
  updateControlBarActive(saved);
}

function updateControlBarActive(theme) {
  document.querySelectorAll(".sic-control-bar__btn[data-theme]").forEach((btn) => {
    btn.classList.toggle("is-active", btn.dataset.theme === theme);
  });
}
