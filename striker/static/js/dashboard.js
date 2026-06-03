/**
 * Striker Dashboard — Frontend
 * postMessage bridge · tabs · sessions · live selection
 */
"use strict";

const $ = (id) => document.getElementById(id);
const els = {};
let selectModeOn = false;
let mitreMap = {};
let attacksData = {};

async function loadMitre(){try{const r=await fetch("/api/mitre");mitreMap=(await r.json()).mappings||{}}catch(_){}}
async function loadAttacks(){try{const r=await fetch("/api/attacks");attacksData=(await r.json()).attacks||{}}catch(_){}}

// ── Init ─────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  els.targetUrl = $("target-url");
  els.btnLoad = $("btn-load");
  els.btnSelect = $("btn-select-mode");
  els.btnScan = $("btn-scan");
  els.frame = $("target-frame");
  els.placeholder = $("iframe-placeholder");
  els.sessionList = $("sessions-list");
  els.sessionTable = $("sessions-table");
  els.elemList = $("elements-list");
  els.resultsList = $("results-list");
  els.selCount = $("selection-count");
  els.systemDot = $("system-dot");
  els.systemText = $("system-text");
  els.helpBtn = $("help-btn");
  els.helpModal = $("help-modal");
  els.clearBtn = $("btn-clear-sessions");
  els.clearSel = $("btn-clear-sel");
  els.timeDisplay = $("time-display");
  els.tabs = document.querySelectorAll(".tab");

  // ── IFRAME NAV ────────────────────────────────────────────
  const navBack = $("nav-back"), navFwd = $("nav-fwd"), navReload = $("nav-reload"), navUrl = $("nav-url");
  if (navBack) navBack.addEventListener("click", () => { els.frame?.contentWindow?.history?.back(); setTimeout(updateNavFromFrame, 200); });
  if (navFwd) navFwd.addEventListener("click", () => { els.frame?.contentWindow?.history?.forward(); setTimeout(updateNavFromFrame, 200); });
  if (navReload) navReload.addEventListener("click", () => { if (els.frame) els.frame.src = els.frame.src; });
  if (navUrl) navUrl.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.keyCode === 13) {
      e.preventDefault();
      let u = navUrl.value.trim();
      if (!u) return;
      if (!u.startsWith("http")) u = "http://" + u;
      // Parse base URL + path
      let proxyUrl;
      try {
        const parsed = new URL(u);
        const base = parsed.origin;
        const path = parsed.pathname + parsed.search;
        proxyUrl = "/proxy?target=" + encodeURIComponent(base) + "&path=" + encodeURIComponent(path);
      } catch(_) {
        proxyUrl = "/proxy?target=" + encodeURIComponent(u);
      }
      if (els.frame) { els.frame.src = proxyUrl; }
      navUrl.blur();
    }
  });

  // ── Hamburger menu (mobile) ────────────────────────────────
  const menuToggle = $("menu-toggle");
  const sidebar = document.querySelector(".sidebar");
  let backdrop = null;

  if (menuToggle && sidebar) {
    backdrop = document.createElement("div");
    backdrop.className = "sidebar-backdrop";
    document.querySelector(".main-grid")?.appendChild(backdrop);

    menuToggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
      backdrop.classList.toggle("visible");
    });
    backdrop.addEventListener("click", () => {
      sidebar.classList.remove("open");
      backdrop.classList.remove("visible");
    });
  }

  updateClock(); setInterval(updateClock, 1000);

  // ── LOAD ─────────────────────────────────────────────────
  els.btnLoad?.addEventListener("click", loadTarget);
  els.targetUrl?.addEventListener("keydown", (e) => { if (e.key === "Enter") loadTarget(); });

  // ── SELECT MODE toggle ────────────────────────────────────
  els.btnSelect?.addEventListener("click", () => {
    selectModeOn = !selectModeOn;
    if (selectModeOn) {
      els.btnSelect.textContent = "☷ NORMAL MODE";
      els.btnSelect.classList.add("active");
    } else {
      els.btnSelect.textContent = "☗ SELECT MODE";
      els.btnSelect.classList.remove("active");
    }
    // Send command to iframe
    els.frame?.contentWindow?.postMessage({ type: "cmd_toggle_mode" }, "*");
  });

  // ── SCAN ─────────────────────────────────────────────────
  els.btnScan?.addEventListener("click", () => {
    els.btnScan.textContent = "⋯ Scanning"; els.btnScan.disabled = true;
    // Limpiar resultados anteriores
    if (els.resultsList) els.resultsList.innerHTML = '<div class="elements-empty">Scanning…</div>';
    els.frame?.contentWindow?.postMessage({ type: "cmd_scan" }, "*");
  });

  // ── AUTO-DETECT (crawler) ─────────────────────────────────
  $("btn-autodetect")?.addEventListener("click", async () => {
    const url = els.targetUrl?.value?.trim();
    if (!url) return alert("Enter a target URL first");
    const target = url.startsWith("http") ? url : "http://" + url;
    $("btn-autodetect").textContent = "⋯ Crawling";
    try {
      const r = await fetch("/api/crawl", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: target }) });
      const d = await r.json();
      if (d.elements?.length) {
        // Send to iframe selector
        els.frame?.contentWindow?.postMessage({ type: "cmd_load_elements", elements: d.elements }, "*");
        alert(`Found ${d.count} elements. Switch to SELECT MODE to review.`);
      }
    } catch (_) { alert("Crawl failed"); }
    $("btn-autodetect").textContent = "🕷 Auto-detect inputs";
  });

  // ── SAST ───────────────────────────────────────────────────
  $("btn-sast")?.addEventListener("click", async () => {
    const path = prompt("Ruta del proyecto a analizar:", "../pagina-testing");
    if (!path) return;
    $("btn-sast").textContent = "⋯ Analyzing";
    try {
      const r = await fetch("/api/sast", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path }),
      });
      const d = await r.json();
      const count = d.count || 0;
      if (count > 0) {
        // Mostrar resultados en el panel derecho
        const sev = { critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#3b82f6" };
        const html = `<div class="st" style="margin-bottom:6px">🔍 SAST: ${count} vulnerabilidades en ${path}</div>` +
          (d.findings || []).slice(0, 15).map(f =>
            `<div class="card rc" style="border-left-color:${sev[f.severity]||'#3b82f6'}">
              <div style="font-size:8px;font-weight:700;color:${sev[f.severity]||'#3b82f6'}">${f.severity.toUpperCase()} · ${f.category}</div>
              <div style="font-family:monospace;font-size:9px;color:var(--accent)">${f.file?.split('/').pop()}:${f.line}</div>
              <div style="font-size:9px;color:var(--text-muted);margin-top:2px">${(f.code||'').slice(0, 80)}</div>
              ${f.fix ? `<div style="font-size:8px;color:var(--green);margin-top:2px">Fix: ${f.fix.slice(0, 80)}</div>` : ''}
            </div>`
          ).join("");
        if (els.resultsList) els.resultsList.innerHTML = html;
      } else {
        if (els.resultsList) els.resultsList.innerHTML = '<div style="color:var(--green);font-size:10px">✓ No vulnerabilities found</div>';
      }
    } catch (_) {
      if (els.resultsList) els.resultsList.innerHTML = '<div style="color:var(--danger);font-size:10px">✗ SAST failed. Check server logs.</div>';
    }
    $("btn-sast").textContent = "🔍 Analyze source code";
  });

  // ── EXPORT ──────────────────────────────────────────────────
  $("btn-export")?.addEventListener("click", async () => {
    try {
      const r = await fetch("/api/sessions"), d = await r.json();
      const blob = new Blob([JSON.stringify(d, null, 2)], { type: "application/json" });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "striker-report-" + new Date().toISOString().slice(0, 10) + ".json";
      a.click();
    } catch (_) { alert("Export failed"); }
  });

  // ── HELP ─────────────────────────────────────────────────
  els.helpBtn?.addEventListener("click", () => { els.helpModal.style.display = "flex"; });
  els.helpModal?.addEventListener("click", (e) => {
    if (e.target === els.helpModal || e.target.classList.contains("help-close"))
      els.helpModal.style.display = "none";
  });

  // ── TABS ─────────────────────────────────────────────────
  els.tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      els.tabs.forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      document.querySelectorAll(".tab-content").forEach((c) => c.style.display = "none");
      const target = $("tab-" + tab.dataset.tab);
      if (target) target.style.display = "flex";
    });
  });

  // ── CLEAR SESSIONS ──────────────────────────────────────
  els.clearBtn?.addEventListener("click", () => {
    if (!confirm("Delete all sessions?")) return;
    fetch("/api/sessions/clear", { method: "DELETE" }).catch(() => {});
    els.sessionList.innerHTML = '<div class="sessions-empty">No sessions yet.</div>';
    els.sessionTable.innerHTML = '<div class="sessions-empty-large">No scan sessions yet.</div>';
  });

  // ── Listen for iframe messages ────────────────────────────
  window.addEventListener("message", handleIframeMsg);

  // ── Load sessions ─────────────────────────────────────────
  loadSessions();
  loadMitre();
  loadAttacks();
  setInterval(loadSessions, 5000);
  startMonitorSSE();

  // ── DDoS Tab ────────────────────────────────────────────────
  let ddosInterval = null;
  $("btn-ddos-start")?.addEventListener("click", async () => {
    const url = $("ddos-url")?.value?.trim();
    if (!url) return;
    const threads = parseInt($("ddos-threads")?.value || "20");
    const duration = parseInt($("ddos-duration")?.value || "10");
    try {
      const r = await fetch("/api/ddos/start", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, threads, duration }),
      });
      const d = await r.json();
      if (d.status === "started") {
        $("btn-ddos-start").style.display = "none";
        $("btn-ddos-stop").style.display = "inline-block";
        $("ddos-log").innerHTML = `<div style="color:var(--amber)">💣 DDoS STARTED — ${threads} threads × ${duration}s → ${url}</div>`;
        ddosInterval = setInterval(pollDDoS, 1000);
      }
    } catch (_) {}
  });
  $("btn-ddos-stop")?.addEventListener("click", async () => {
    await fetch("/api/ddos/stop", { method: "POST" });
    stopDDoSUI();
  });

  function stopDDoSUI() {
    $("btn-ddos-start").style.display = "inline-block";
    $("btn-ddos-stop").style.display = "none";
    if (ddosInterval) { clearInterval(ddosInterval); ddosInterval = null; }
  }

  async function pollDDoS() {
    try {
      const r = await fetch("/api/ddos/stats"), d = await r.json();
      $("ddos-rps").textContent = d.rps || 0;
      $("ddos-total").textContent = d.total_requests || 0;
      $("ddos-errors").textContent = d.errors || 0;
      if (!d.running) stopDDoSUI();
    } catch (_) {}
  }

  // ── Restore last target ──────────────────────────────────
  try { const last = localStorage.getItem("striker_last_target"); if (last && els.targetUrl) els.targetUrl.value = last; } catch (_) {}
});

// ── Load Target ─────────────────────────────────────────────────
function loadTarget() {
  const raw = (els.targetUrl?.value || "").trim();
  if (!raw) return;
  let target = raw;
  if (!target.startsWith("http")) target = "http://" + target;
  try { localStorage.setItem("striker_last_target", target); } catch (_) {}

  if (els.systemText) els.systemText.textContent = "PROXYING";
  if (els.systemDot) { els.systemDot.className = "status-dot"; els.systemDot.style.background = "#3b82f6"; }

  // Separar base URL del path
  let proxyUrl;
  try {
    const parsed = new URL(target);
    const base = parsed.origin;
    const path = parsed.pathname + parsed.search;
    proxyUrl = "/proxy?target=" + encodeURIComponent(base) + "&path=" + encodeURIComponent(path);
  } catch(_) {
    proxyUrl = "/proxy?target=" + encodeURIComponent(target);
  }
  if (els.frame) { els.frame.src = proxyUrl; els.frame.style.display = "block"; }
  if (els.placeholder) els.placeholder.style.display = "none";
  // Update nav URL bar
  updateNavUrl(target, "/");
  // Track iframe navigation
  els.frame?.addEventListener("load", updateNavFromFrame);

  // Reset button states
  selectModeOn = false;
  if (els.btnSelect) { els.btnSelect.textContent = "☗ SELECT MODE"; els.btnSelect.classList.remove("active"); }
  if (els.btnScan) { els.btnScan.disabled = true; els.btnScan.textContent = "▶ SCAN"; }
  if (els.selCount) els.selCount.textContent = "0";
  if (els.elemList) els.elemList.innerHTML = '<div class="elements-empty">Use SELECT MODE on the target page to pick elements.</div>';
  if (els.resultsList) els.resultsList.innerHTML = '<div class="elements-empty">Run a scan to see results.</div>';
}

// ── Handle iframe messages ──────────────────────────────────────
function handleIframeMsg(e) {
  if (!e.data || typeof e.data !== "object") return;

  const d = e.data;

  if (d.type === "selection_changed") {
    if (els.selCount) els.selCount.textContent = d.count || 0;
    if (els.btnScan) { els.btnScan.disabled = (d.count || 0) === 0; }
    if (els.clearSel) els.clearSel.style.display = (d.count || 0) > 0 ? "block" : "none";
    renderElements(d.elements || []);
  }

  if (d.type === "scan_complete") {
    if (els.btnScan) { els.btnScan.textContent = "▶ SCAN"; els.btnScan.disabled = false; }
    if (els.systemText) { els.systemText.textContent = (d.count || 0) > 0 ? "VULNERABLE" : "CLEAN"; }
    if (els.systemDot) { els.systemDot.className = (d.count || 0) > 0 ? "status-dot red" : "status-dot green"; }
    renderResults(d.results || []);
    loadSessions();
  }

  if (d.type === "nav_update") {
    if (d.base) updateNavUrl(d.base, d.path || "/");
  }

  if (d.type === "mode_changed") {
    selectModeOn = d.selectMode;
    if (els.btnSelect) {
      els.btnSelect.textContent = selectModeOn ? "☷ NORMAL MODE" : "☗ SELECT MODE";
      if (selectModeOn) els.btnSelect.classList.add("active");
      else els.btnSelect.classList.remove("active");
    }
  }
}

// ── Render selected elements ─────────────────────────────────────
function renderElements(elements) {
  const html = buildElementsHTML(elements, "Use SELECT MODE on the target page to pick elements.");
  if (els.elemList) els.elemList.innerHTML = html;
  const tabList = $("elements-list-tab");
  if (tabList) tabList.innerHTML = buildElementsHTML(elements, "Use SELECT MODE on the target page to pick elements.");
}

function buildElementsHTML(elements, emptyMsg) {
  if (!elements || elements.length === 0) return `<div class="elements-empty">${emptyMsg}</div>`;
  const cols = { input:"#60a5fa", button:"#22c55e", textarea:"#f59e0b", select:"#8b5cf6", form:"#ec4899", a:"#3b82f6" };
  return elements.map((el) =>
    `<div class="element-card">
      <div class="element-label">${el.label||el.tag}</div>
      <div class="element-tag" style="color:${cols[el.tag]||"#60a5fa"}">&lt;${el.tag}${el.type?" type="+el.type:""}&gt;${el.id?" · #"+el.id:""}</div>
      ${el.formAction?`<div class="element-detail" style="color:var(--text-muted)">→ ${el.formAction}</div>`:""}
    </div>`
  ).join("");
}

// ── Render scan results ──────────────────────────────────────────
function renderResults(results) {
  if (!els.resultsList) return;
  if (!results || results.length === 0) {
    els.resultsList.innerHTML = '<div class="elements-empty" style="color:#22c55e">✓ No vulnerabilities found</div>';
    return;
  }
  const sev = { critical:"#ef4444", high:"#f97316", medium:"#f59e0b", low:"#3b82f6" };
  const html = results.map((r) =>
    `<div class="result-card" style="border-left-color:${sev[r.severity]||"#3b82f6"}">
      <div class="result-sev" style="color:${sev[r.severity]||"#3b82f6"}">${r.severity||"?"} · ${r.category||r.type||"?"}</div>
      <div class="result-detail">${r.element||"?"}: ${(r.evidence||"").slice(0,70)}</div>
    </div>`
  ).join("");
  els.resultsList.innerHTML = html;
  const tabResults = $("results-list-tab");
  if (tabResults) tabResults.innerHTML = html;

  // Click handlers → detail modal
  els.resultsList.querySelectorAll(".result-card").forEach((card, i) => {
    card.addEventListener("click", () => showDetail(results[i]));
  });
}

// ── Detail Modal ──────────────────────────────────────────────
const CATEGORY_MAP = {
  "sqli": "SQL Injection", "xss": "Cross-Site Scripting (XSS)",
  "nosqli": "NoSQL Injection", "cmdi": "Command Injection",
  "pathtrav": "Path Traversal", "lfi": "File Inclusion (LFI/RFI)",
  "rfi": "File Inclusion (LFI/RFI)", "scanner": "Scanner / Recon",
  "brute": "Brute Force", "http": "HTTP Anomaly",
};

function showDetail(r) {
  const catName = CATEGORY_MAP[r.category] || r.category || r.type || "?";
  const m = mitreMap[catName] || {};
  const a = attacksData[catName] || {};
  const sc = {critical:"#ef4444",high:"#f97316",medium:"#f59e0b",low:"#3b82f6"};

  const set = (id, v) => { const el = $(id); if (el) el.textContent = v || "—"; };

  set("detail-sev", (r.severity||"").toUpperCase());
  set("detail-type", catName);
  set("detail-element", r.element);
  set("detail-evidence", r.evidence);
  set("detail-mitre", a.mitre ? `${a.mitre} · ${a.mitre_name}` : (m.mitre_id ? `${m.mitre_id} · ${m.mitre_name}` : "—"));
  set("detail-tactic", a.tactic || m.tactic || "—");
  set("detail-cwe", a.cwe ? `${a.cwe} · ${a.cwe_name}` : (m.cwe ? `${m.cwe} · ${m.cwe_name}` : "—"));
  set("detail-owasp", a.owasp ? `${a.owasp} · ${a.owasp_name}` : (m.owasp ? `${m.owasp} · ${m.owasp_name}` : "—"));
  set("detail-desc", a.description || m.description || "Sin descripción disponible.");
  set("detail-indicators", a.indicators || "");
  set("detail-impact", a.impact || "");
  set("detail-fix", a.remediation || "Revisa la validación de inputs y aplica buenas prácticas de seguridad.");

  const sevEl = $("detail-sev");
  if (sevEl) sevEl.style.color = sc[r.severity] || "#3b82f6";

  const modal = $("detail-modal");
  $("detail-close").onclick = () => modal.style.display = "none";
  modal.onclick = (e) => { if (e.target === modal) modal.style.display = "none"; };
  modal.style.display = "flex";
}

// ── Load sessions ────────────────────────────────────────────────
async function loadSessions() {
  try {
    const resp = await fetch("/api/sessions");
    const data = await resp.json();
    renderSessionSidebar(data.sessions || []);
    renderSessionTable(data.sessions || []);
  } catch (_) {}
}

function renderSessionSidebar(sessions) {
  if (!els.sessionList) return;
  if (!sessions.length) {
    els.sessionList.innerHTML = '<div class="sessions-empty">No sessions yet.</div>';
    return;
  }
  els.sessionList.innerHTML = sessions.reverse().slice(0, 12).map((s) =>
    `<div class="session-item">
      <div class="session-info">
        <div class="session-id-text">${s.id}</div>
        <div class="session-count">${s.count} elements</div>
        <div class="session-status" style="color:${s.scan_status==='done'?'#22c55e':s.scan_status==='scanning'?'#f59e0b':'#4a5d78'}">${s.scan_status}</div>
      </div>
      <button class="session-delete" data-sid="${s.id}" title="Delete">✕</button>
    </div>`
  ).join("");
  // Delete handlers
  els.sessionList.querySelectorAll(".session-delete").forEach((btn) => {
    btn.addEventListener("click", () => {
      const sid = btn.dataset.sid;
      fetch("/api/sessions/" + sid, { method: "DELETE" }).then(loadSessions).catch(() => {});
    });
  });
}

function renderSessionTable(sessions) {
  if (!els.sessionTable) return;
  if (!sessions.length) {
    els.sessionTable.innerHTML = '<div class="sessions-empty-large">No scan sessions yet.</div>';
    return;
  }
  els.sessionTable.innerHTML = sessions.reverse().map((s) =>
    `<div class="session-item" style="padding:8px 10px;margin-bottom:6px;">
      <div class="session-info">
        <div class="session-id-text">${s.id}</div>
        <div class="session-count">Target: ${(s.target_url||"").slice(0,40)} · ${s.count} elements</div>
        <div class="session-status" style="color:${s.scan_status==='done'?'#22c55e':s.scan_status==='scanning'?'#f59e0b':'#4a5d78'}">${s.scan_status} · ${s.result_count||0} vulns</div>
      </div>
      <button class="session-delete" data-sid="${s.id}" title="Delete">✕</button>
    </div>`
  ).join("");
  els.sessionTable.querySelectorAll(".session-delete").forEach((btn) => {
    btn.addEventListener("click", () => {
      fetch("/api/sessions/" + btn.dataset.sid, { method: "DELETE" }).then(loadSessions).catch(() => {});
    });
  });
}

// ── Clock ────────────────────────────────────────────────────────
function updateClock() { if (els.timeDisplay) els.timeDisplay.textContent = new Date().toTimeString().split(" ")[0] + " UTC"; }

// ── Nav URL tracking ────────────────────────────────────────────
function updateNavUrl(base, path) {
  const el = $("nav-url");
  if (!el) return;
  if (path === "/" || !path) el.value = base;
  else el.value = base.replace(/\/$/, "") + path;
}

function updateNavFromFrame() {
  try {
    const frame = els.frame;
    if (!frame || !frame.src) return;
    const url = new URL(frame.src);
    const base = url.searchParams.get("target");
    const path = url.searchParams.get("path") || "/";
    if (base) updateNavUrl(base, path);
  } catch (_) {}
}

// ═══ SENSORS + MONITOR + AUDIO ═══════════════════════════════════
let soundOn = true;
const Audio = {
  _ctx: null,
  ctx(){if(!this._ctx){this._ctx=new(window.AudioContext||window.webkitAudioContext)()}if(this._ctx.state==='suspended')this._ctx.resume();return this._ctx},
  beep(f,d=0.1,v=0.08,t='sine'){try{const c=this.ctx(),o=c.createOscillator(),g=c.createGain();o.type=t;o.frequency.value=f;g.gain.setValueAtTime(v,c.currentTime);g.gain.exponentialRampToValueAtTime(0.001,c.currentTime+d);o.connect(g);g.connect(c.destination);o.start();o.stop(c.currentTime+d)}catch(_){}},
  alertLow(){this.beep(800,0.06,0.06)},
  alertMed(){this.beep(880,0.1,0.08);setTimeout(()=>this.beep(660,0.08,0.06),100)},
  alertHigh(){this.beep(1200,0.15,0.1);setTimeout(()=>this.beep(900,0.12,0.08),150);setTimeout(()=>this.beep(600,0.15,0.06),300)},
  alertCrit(){this.beep(400,0.3,0.12);setTimeout(()=>this.beep(300,0.4,0.1),200);setTimeout(()=>this.beep(500,0.3,0.12),400);setTimeout(()=>this.beep(250,0.6,0.08),700)},
};

function startMonitorSSE(){
  const src=new EventSource('/api/sensors/stream');
  src.onmessage=e=>{
    try{const d=JSON.parse(e.data);if(d.alerts)d.alerts.forEach(a=>renderMonitorAlert(a));if(d.summary)updateMonitorStats(d.summary)}catch(_){}
  };
  src.onerror=()=>setTimeout(startMonitorSSE,3000);
}

function renderMonitorAlert(a){
  const feed=$('monitor-feed');if(!feed)return;
  const sev=a.findings[0]?.severity||'low';
  const types=[...new Set(a.findings.map(f=>f.type))].join(', ');
  const el=document.createElement('div');
  el.className='monitor-alert '+sev;
  el.innerHTML=`<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap"><span class="ma-ip">${a.ip||'?'}</span><span class="ma-type" style="color:${sev==='critical'?'var(--red)':sev==='high'?'#f97316':'var(--amber)'}">${sev.toUpperCase()}</span><span>${types}</span></div><div class="ma-match">${a.findings[0]?.matched||''}</div>`;
  feed.insertBefore(el,feed.firstChild);
  if(feed.children.length>50)feed.lastChild.remove();
  if(soundOn){if(sev==='critical')Audio.alertCrit();else if(sev==='high')Audio.alertHigh();else if(sev==='medium')Audio.alertMed();else Audio.alertLow()}
}

function updateMonitorStats(s){
  const t=$('mon-total');if(t)t.textContent=s.total_alerts||0;
  const i=$('mon-ips');if(i)i.textContent=s.unique_ips||0;
}
