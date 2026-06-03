/**
 * Striker Element Selector — Inyectado vía proxy
 *
 * Barra mínima. Modo NORMAL/SELECT. F2 togglea.
 * postMessage al dashboard en cada selección.
 * Escucha comandos del dashboard (toggle_mode, scan).
 */

(function () {
  "use strict";

  const STATE = {
    selectMode: false,
    targets: [],
    hoverElement: null,
  };

  let sessionId = null;

  // ── BARRA MÍNIMA (fixed top, 28px) ────────────────────────────
  const BAR = document.createElement("div");
  BAR.id = "__striker_bar";
  BAR.style.cssText =
    "position:fixed;top:0;left:0;right:0;height:28px;z-index:99998;" +
    "display:flex;align-items:center;justify-content:space-between;" +
    "padding:0 12px;background:#0e1624;border-bottom:1px solid #1a2b44;" +
    "font-family:'DM Sans',system-ui,sans-serif;font-size:11px;color:#8899b4;" +
    "user-select:none;";
  BAR.innerHTML = `
    <span style="display:flex;align-items:left;gap:10px; padding:4px 18px;border-radius:4px;">
      <b style="color:#3b82f6;font-size:10px;">◈   </b>
      <span id="__striker_status" style="color:#f59e0b;">NORMAL</span>
      <span style="color:#60a5fa;font-family:monospace;font-size:10px;" id="__striker_count">0 selected</span>
    </span>
    <span style="color:#4a5d78;font-size:10px;">F2 = toggle</span>
  `;

  // ── OVERLAYS ──────────────────────────────────────────────────
  const HOVER = document.createElement("div");
  HOVER.style.cssText =
    "position:fixed;pointer-events:none;z-index:99997;" +
    "border:2px solid #3b82f6;background:rgba(59,130,246,0.08);" +
    "transition:all 0.1s ease;display:none;border-radius:3px;";

  const CLICK_OVERLAY = document.createElement("div");
  CLICK_OVERLAY.style.cssText =
    "display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;" +
    "z-index:99996;cursor:crosshair;background:transparent;";

  const labels = [];

  // ── HELPERS ───────────────────────────────────────────────────
  function getInfo(el) {
    // Identificador legible: name > id > placeholder > class > texto recortado
    const name = el.getAttribute("name");
    const id = el.id;
    const placeholder = el.getAttribute("placeholder");
    const cls = (typeof el.className === "string" && el.className.trim().split(/\s+/)[0]) || null;
    const text = (el.textContent || "").replace(/\s+/g, " ").trim();
    const truncated = text.length > 30 ? text.slice(0, 28) + "…" : text;
    const label = name || id || placeholder || (cls && "." + cls) || truncated || el.tagName.toLowerCase();

    // La página real corre dentro del proxy: /proxy?target=...&path=/xss/1
    // Extraemos el path REAL de la query string del proxy
    const proxyParams = new URLSearchParams(window.location.search);
    const pagePath = proxyParams.get("path") || window.location.pathname;

    return {
      tag: el.tagName.toLowerCase(),
      id: id || null,
      name: name || null,
      type: el.getAttribute("type") || null,
      placeholder: placeholder || null,
      formAction: el.closest("form")?.getAttribute("action") || pagePath,
      formMethod: el.closest("form")?.getAttribute("method") || "GET",
      selector: buildSel(el),
      label: label,
      page_url: pagePath,
    };
  }

  function buildSel(el) {
    if (el.id) return "#" + CSS.escape(el.id);
    const p = [];
    let c = el;
    while (c && c !== document.body && c !== document.documentElement) {
      let s = c.tagName.toLowerCase();
      if (c.id) { p.unshift("#" + CSS.escape(c.id)); break; }
      if (c.className && typeof c.className === "string") {
        const cls = c.className.trim().split(/\s+/)[0];
        if (cls) s += "." + CSS.escape(cls);
      }
      const par = c.parentElement;
      if (par) {
        const sibs = Array.from(par.children).filter((x) => x.tagName === c.tagName);
        if (sibs.length > 1) s += ":nth-of-type(" + (sibs.indexOf(c) + 1) + ")";
      }
      p.unshift(s);
      c = c.parentElement;
    }
    return p.join(" > ");
  }

  // ── LABELS ────────────────────────────────────────────────────
  function addLabel(el, i) {
    const l = document.createElement("div");
    l.style.cssText =
      "position:fixed;pointer-events:none;z-index:99995;background:#ef4444;" +
      "color:white;font-family:monospace;font-size:10px;padding:1px 5px;" +
      "border-radius:2px;font-weight:700;";
    l.textContent = "T" + (i + 1);
    document.body.appendChild(l);
    labels.push({ el: l, target: el });
  }

  function refreshLabels() {
    labels.forEach(({ el, target }) => {
      const r = target.getBoundingClientRect();
      el.style.left = Math.max(0, r.left) + "px";
      el.style.top = Math.max(0, r.top - 15) + "px";
    });
  }

  function clearLabels() {
    labels.forEach(({ el }) => el.remove());
    labels.length = 0;
  }

  // ── MODE TOGGLE ───────────────────────────────────────────────
  function setMode(on) {
    STATE.selectMode = on;
    const st = document.getElementById("__striker_status");
    if (st) {
      st.textContent = on ? "SELECTING" : "NORMAL";
      st.style.color = on ? "#22c55e" : "#f59e0b";
    }
    CLICK_OVERLAY.style.display = on ? "block" : "none";
    HOVER.style.display = "none";
    if (!on) clearLabels();
    else refreshLabels();

    // Notificar al dashboard
    window.parent?.postMessage({ type: "mode_changed", selectMode: on }, "*");
  }

  // ─── HOVER (solo modo SELECT) ─────────────────────────────────
  CLICK_OVERLAY.addEventListener("mousemove", function (e) {
    if (!STATE.selectMode) return;
    this.style.pointerEvents = "none";
    const el = document.elementFromPoint(e.clientX, e.clientY);
    this.style.pointerEvents = "auto";
    if (!el || el === document.body || el === document.documentElement ||
        el.closest("#__striker_bar") || el === HOVER || el === CLICK_OVERLAY) {
      HOVER.style.display = "none"; STATE.hoverElement = null; return;
    }
    STATE.hoverElement = el;
    const r = el.getBoundingClientRect();
    HOVER.style.display = "block";
    HOVER.style.left = r.left + "px"; HOVER.style.top = r.top + "px";
    HOVER.style.width = r.width + "px"; HOVER.style.height = r.height + "px";
    const sel = STATE.targets.some((t) => t.el === el);
    HOVER.style.borderColor = sel ? "#22c55e" : "#3b82f6";
    HOVER.style.background = sel ? "rgba(34,197,94,0.12)" : "rgba(59,130,246,0.08)";
  });

  // ── CLICK (modo SELECT) ───────────────────────────────────────
  CLICK_OVERLAY.addEventListener("click", function () {
    if (!STATE.selectMode) return;
    const el = STATE.hoverElement;
    if (!el) return;
    const idx = STATE.targets.findIndex((t) => t.el === el);
    if (idx >= 0) STATE.targets.splice(idx, 1);
    else STATE.targets.push({ el, info: getInfo(el) });
    beep(idx >= 0 ? 300 : 800);
    notify();
  });

  // ── NOTIFY DASHBOARD ──────────────────────────────────────────
  function notify() {
    clearLabels();
    STATE.targets.forEach((t, i) => addLabel(t.el, i));
    refreshLabels();
    const c = document.getElementById("__striker_count");
    if (c) c.textContent = STATE.targets.length + " selected";

    window.parent?.postMessage({
      type: "selection_changed",
      elements: STATE.targets.map((t) => t.info),
      count: STATE.targets.length,
    }, "*");
  }

  // ── SCAN ──────────────────────────────────────────────────────
  function startScan() {
    if (STATE.targets.length === 0) return;
    const elements = STATE.targets.map((t) => t.info);
    // Extraer el target REAL de la URL del proxy (no la URL del proxy mismo)
    const proxyParams = new URLSearchParams(window.location.search);
    const actualTarget = proxyParams.get("target") || window.location.origin;

    fetch("/api/targets?" + new URLSearchParams({ target: actualTarget }), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ elements }),
    })
      .then((r) => r.json())
      .then((data) => {
        sessionId = data.session_id;
        window.parent?.postMessage({ type: "scan_started", sessionId: sessionId, count: data.count }, "*");
        return fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ session_id: sessionId }),
        });
      })
      .then((r) => r.json())
      .then((data) => {
        if (data.status === "scanning") poll(data.session_id || sessionId);
      })
      .catch((err) => window.parent?.postMessage({ type: "scan_error", error: err.message }, "*"));
  }

  function poll(sid) {
    let n = 0;
    const iv = setInterval(() => {
      n++;
      fetch("/api/scan/" + sid + "/status")
        .then((r) => r.json())
        .then((d) => {
          if (d.scan_status === "done" || d.scan_status === "error") {
            clearInterval(iv);
            window.parent?.postMessage({
              type: "scan_complete", sessionId: sid,
              results: d.results || [], count: d.result_count || 0,
            }, "*");
          }
        }).catch(() => clearInterval(iv));
      if (n > 60) clearInterval(iv);
    }, 2000);
  }

  // ── BEEP ──────────────────────────────────────────────────────
  function beep(freq) {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const o = ctx.createOscillator(), g = ctx.createGain();
      o.type = "sine"; o.frequency.value = freq;
      g.gain.setValueAtTime(0.06, ctx.currentTime);
      g.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.07);
      o.connect(g); g.connect(ctx.destination); o.start(); o.stop(ctx.currentTime + 0.07);
    } catch (_) {}
  }

  // ── LISTEN PARENT COMMANDS ────────────────────────────────────
  window.addEventListener("message", (e) => {
    if (!e.data || typeof e.data !== "object") return;
    if (e.data.type === "cmd_toggle_mode") setMode(!STATE.selectMode);
    if (e.data.type === "cmd_scan") startScan();
    if (e.data.type === "cmd_clear_selection") clearAll();
    if (e.data.type === "cmd_load_elements") loadExternalElements(e.data.elements || []);
  });

  // ── LOAD EXTERNAL ELEMENTS (from crawler) ───────────────────
  function loadExternalElements(elements) {
    STATE.targets = [];
    elements.forEach(info => {
      try {
        const el = document.querySelector(info.selector);
        if (el) {
          STATE.targets.push({ el, info });
        } else {
          // Crear un elemento fantasma para representarlo
          const ghost = document.createElement('span');
          ghost.style.display = 'none';
          ghost.__striker_info = info;
          document.body.appendChild(ghost);
          STATE.targets.push({ el: ghost, info });
        }
      } catch (_) {
        STATE.targets.push({ el: null, info });
      }
    });
    notify();
    // Auto-poner en modo SELECT para ver las etiquetas
    setMode(true);
  }

  // ── CLEAR ALL ──────────────────────────────────────────────
  function clearAll() {
    STATE.targets = [];
    clearLabels();
    const c = document.getElementById("__striker_count");
    if (c) c.textContent = "0 selected";
    notify();
  }

  // ── INIT ──────────────────────────────────────────────────────
  function init() {
    const body = document.body;
    body.style.marginTop = (parseInt(getComputedStyle(body).marginTop) || 0) + 28 + "px";
    body.insertBefore(BAR, body.firstChild);
    body.appendChild(HOVER);
    body.appendChild(CLICK_OVERLAY);

    document.addEventListener("keydown", (e) => {
      if (e.key === "F2") { e.preventDefault(); setMode(!STATE.selectMode); }
    });
    window.addEventListener("scroll", refreshLabels, { passive: true });
    window.addEventListener("resize", refreshLabels, { passive: true });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
