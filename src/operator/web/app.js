"use strict";

// Token from ?token=... is stored by the server as an httpOnly cookie, but we
// also keep it in-memory so the first XHRs after redirect carry it explicitly.
const URL_TOKEN = new URLSearchParams(location.search).get("token") || "";
const REFRESH_MS = 4000;

let activeTab = "feed";
let autoRefresh = true;
let refreshTimer = null;

async function api(path) {
  const headers = {};
  if (URL_TOKEN) headers.Authorization = "Bearer " + URL_TOKEN;
  const res = await fetch(path, { headers, credentials: "same-origin" });
  if (!res.ok) throw new Error(path + " -> " + res.status);
  return res.json();
}

async function apiPost(path, body) {
  const headers = { "Content-Type": "application/json" };
  if (URL_TOKEN) headers.Authorization = "Bearer " + URL_TOKEN;
  const res = await fetch(path, {
    method: "POST",
    headers,
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(path + " -> " + res.status);
  return res.json();
}

const el = (tag, attrs, children) => {
  const node = document.createElement(tag);
  if (attrs) for (const k in attrs) {
    if (k === "class") node.className = attrs[k];
    else if (k === "html") node.innerHTML = attrs[k];
    else node.setAttribute(k, attrs[k]);
  }
  (children || []).forEach((c) => node.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
  return node;
};

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const shortTime = (iso) => { const d = new Date(iso); return isNaN(d) ? "—" : d.toLocaleTimeString(); };
const pill = (cls, text) => `<span class="pill ${esc(cls)}">${esc(text)}</span>`;

function setLive(ok) {
  const dot = document.getElementById("liveDot");
  const txt = document.getElementById("liveText");
  dot.className = "dot " + (ok ? "live" : "stale");
  txt.textContent = ok ? "live" : "stale / retrying";
}

function renderKpis(o) {
  const k = [
    ["Attackers", o.attackers.total],
    ["Active 15m", o.attackers.active15m],
    ["Sessions", o.sessions.active + " / " + o.sessions.total],
    ["Transcripts", o.transcripts.total],
    ["High Alerts", o.alerts.high, o.alerts.high > 0],
    ["Threat Score", o.attackers.totalScore],
    ["Default Action", o.control.defaultAction],
  ];
  const root = document.getElementById("kpis");
  root.innerHTML = "";
  k.forEach(([label, value, alert]) => {
    root.appendChild(el("div", { class: "kpi" + (alert ? " alert" : "") }, [
      el("div", { class: "k-label" }, [label]),
      el("div", { class: "k-value" }, [String(value)]),
    ]));
  });
}

function renderBars(id, entries, opts) {
  opts = opts || {};
  const root = document.getElementById(id);
  root.innerHTML = "";
  const max = Math.max(1, ...entries.map((e) => e.count));
  if (!entries.length) { root.innerHTML = '<div class="empty">no data</div>'; return; }
  entries.forEach((e) => {
    const fillCls = opts.riskColors ? " r-" + e.key : "";
    root.appendChild(el("div", { class: "bar-row" }, [
      el("div", { class: "bl", title: e.key }, [e.key]),
      el("div", { class: "bar-track" }, [
        el("div", { class: "bar-fill" + fillCls, style: "width:" + Math.round((e.count / max) * 100) + "%" }),
      ]),
      el("div", { class: "bv" }, [String(e.count)]),
    ]));
  });
}

const mapToEntries = (m) => Object.entries(m || {}).map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count);

function renderTimeline(points) {
  const wrap = document.getElementById("timeline");
  const W = 600, H = 160, pad = 8;
  const max = Math.max(1, ...points.map((p) => p.count));
  const n = points.length;
  const x = (i) => pad + (i / Math.max(1, n - 1)) * (W - 2 * pad);
  const y = (v) => H - pad - (v / max) * (H - 2 * pad);
  const line = points.map((p, i) => (i ? "L" : "M") + x(i).toFixed(1) + " " + y(p.count).toFixed(1)).join(" ");
  const area = line + ` L${x(n - 1).toFixed(1)} ${H - pad} L${x(0).toFixed(1)} ${H - pad} Z`;
  const expLine = points.map((p, i) => (i ? "L" : "M") + x(i).toFixed(1) + " " + y(p.exploitation).toFixed(1)).join(" ");
  wrap.innerHTML =
    `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">` +
    `<defs><linearGradient id="ag" x1="0" y1="0" x2="0" y2="1">` +
    `<stop offset="0" stop-color="#b13049" stop-opacity="0.45"/>` +
    `<stop offset="1" stop-color="#b13049" stop-opacity="0"/></linearGradient></defs>` +
    `<path d="${area}" fill="url(#ag)"/>` +
    `<path d="${line}" fill="none" stroke="#b13049" stroke-width="1.6"/>` +
    `<path d="${expLine}" fill="none" stroke="#c2495b" stroke-width="1" stroke-dasharray="3 3"/>` +
    `</svg>`;
  const total = points.reduce((s, p) => s + p.count, 0);
  document.getElementById("timelineMeta").textContent = total + " events · — exploitation";
}

// ---- Tab panels ----------------------------------------------------------

let feedFilter = "";

async function renderFeed() {
  const rows = await api("/api/feed?limit=120");
  const panel = document.getElementById("panel");
  const f = feedFilter.toLowerCase();
  const shown = f
    ? rows.filter((r) => [r.service, r.sourceIp, r.intent, r.action, r.request].join(" ").toLowerCase().includes(f))
    : rows;
  const hadFocus = document.activeElement && document.activeElement.id === "feedFilter";
  const body = shown.map((r) => `<tr data-attacker="${esc(r.attackerId)}">
    <td>${shortTime(r.at)}</td>
    <td>${esc(r.service)}</td>
    <td>${esc(r.sourceIp)}</td>
    <td>${pill(r.intent, r.intent)}</td>
    <td>${esc(r.score)}</td>
  </tr>`).join("");
  panel.innerHTML = `
    <div class="control-row" style="margin-bottom:10px">
      <input id="feedFilter" class="txt" placeholder="filter by service / ip / intent / request…" value="${esc(feedFilter)}" style="flex:1" />
      <span class="muted">${shown.length}/${rows.length} · click a row for detail</span>
    </div>
    <table><thead><tr>
      <th>Time</th><th>Service</th><th>Source IP</th><th>Intent</th><th>Score</th>
    </tr></thead><tbody>${body || '<tr><td colspan="5" class="empty">no matches</td></tr>'}</tbody></table>`;
  const input = document.getElementById("feedFilter");
  input.oninput = (e) => { feedFilter = e.target.value; };
  if (hadFocus) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
  wireRowDrawer(panel, "attacker");
}

async function renderAttackers() {
  const rows = await api("/api/attackers");
  const panel = document.getElementById("panel");
  if (!rows.length) { panel.innerHTML = '<div class="empty">No attackers profiled yet.</div>'; return; }
  const body = rows.map((r) => `<tr data-attacker="${esc(r.id)}">
    <td>${esc(r.sourceIp)}</td>
    <td>${esc(r.country)}</td>
    <td>${pill(r.risk, r.risk)}</td>
    <td>${pill(r.intent, r.intent)}</td>
    <td>${esc(r.totalScore)}</td>
    <td>${shortTime(r.lastSeenAt)}</td>
  </tr>`).join("");
  panel.innerHTML = `<table><thead><tr>
    <th>Source IP</th><th>Geo</th><th>Risk</th><th>Intent</th><th>Score</th><th>Last Seen</th>
  </tr></thead><tbody>${body}</tbody></table>
  <p class="cfg-note" style="margin-top:8px">Click a row for full profile, captured creds, commands & actions.</p>`;
  wireRowDrawer(panel, "attacker");
}

async function renderSessions() {
  const rows = await api("/api/sessions");
  const panel = document.getElementById("panel");
  if (!rows.length) { panel.innerHTML = '<div class="empty">No sessions recorded yet.</div>'; return; }
  const body = rows.slice().reverse().map((r) => `<tr data-session="${esc(r.id)}">
    <td>${esc(r.id.slice(0, 8))}</td>
    <td>${esc(r.service)}</td>
    <td>${esc(r.ip)}</td>
    <td>${esc(r.status)}</td>
    <td>${esc(r.currentAction)}</td>
    <td>${esc(r.intent || "—")}</td>
    <td>${shortTime(r.lastSeenAt)}</td>
  </tr>`).join("");
  panel.innerHTML = `<table><thead><tr>
    <th>Session</th><th>Service</th><th>IP</th><th>Status</th><th>Action</th><th>Intent</th><th>Last Seen</th>
  </tr></thead><tbody>${body}</tbody></table>`;
  panel.querySelectorAll("tr[data-session]").forEach((tr) => {
    tr.onclick = () => openReplay(tr.getAttribute("data-session"));
  });
}

async function openReplay(sessionId) {
  let steps = [];
  try { steps = await api("/api/replay/" + encodeURIComponent(sessionId)); } catch (e) {}
  document.getElementById("drawerTitle").textContent = "Replay · " + sessionId.slice(0, 8);
  const body = document.getElementById("drawerBody");
  if (!steps.length) { body.innerHTML = '<div class="empty">no transcript steps for this session</div>'; document.getElementById("drawer").classList.remove("hidden"); return; }
  const render = (n) => steps.slice(0, n).map((s) => `
    <div class="replay-step">
      <div class="muted">${shortTime(s.at)} · ${esc(s.service)} · ${pill(s.intent, s.intent)} · score ${esc(s.score)} · ${esc(s.action)}</div>
      <div class="rq">$ ${esc(s.request || "")}</div>
      <pre class="rs">${esc((s.response || "").slice(0, 600))}</pre>
    </div>`).join("");
  let shown = 0;
  const draw = () => {
    body.innerHTML = `<div class="drawer-actions">
        <button class="act sm" id="rpStep">Step ▸</button>
        <button class="act sm" id="rpAll">Play all</button>
        <span class="muted">${shown}/${steps.length}</span>
      </div><div id="rpBody">${render(shown)}</div>`;
    document.getElementById("rpStep").onclick = () => { shown = Math.min(steps.length, shown + 1); draw(); };
    document.getElementById("rpAll").onclick = () => { shown = steps.length; draw(); };
  };
  shown = 1; draw();
  document.getElementById("drawer").classList.remove("hidden");
}

function alertNarrative(a) {
  const svc = (a.services || []).join(", ") || "multiple services";
  const ev = (a.recent_events || []).slice(-3).join("  •  ");
  let rec;
  if (a.risk === "high" && a.intent === "exploitation") rec = "Exploitation from a high-risk source — recommend BLOCK and review any captured credentials/commands.";
  else if (a.risk === "high") rec = "High-risk escalation — recommend tarpit/stall and close monitoring.";
  else if (a.intent === "brute_force") rec = "Credential brute-forcing — consider decoy_success to observe post-login behavior, or block.";
  else rec = "Continue monitoring; no immediate action required.";
  return `${a.source_ip} escalated ${a.previous_risk} → ${a.risk}. Behavior classified as ${a.intent} (score ${a.score}) across ${svc}.`
    + (ev ? `\n\nRecent activity:\n${ev}` : "")
    + `\n\n${rec}`;
}

function openAlertDrawer(a) {
  document.getElementById("drawerTitle").textContent = "Alert · " + a.source_ip;
  const body = document.getElementById("drawerBody");
  body.innerHTML = `
    <div class="alert-what"><div class="aw-h">What happened</div><div class="aw-b">${esc(alertNarrative(a))}</div></div>
    <div class="drawer-actions">
      <input id="injMsg" class="txt" placeholder="message to ${esc(a.source_ip)}…" style="flex:1" />
      <button class="act sm" id="injBtn">Inject</button>
      <button class="act sm danger" id="blkBtn">Block IP</button>
    </div>
    <pre class="jsonview">${highlightJson(a)}</pre>`;
  document.getElementById("injBtn").onclick = async () => {
    const m = document.getElementById("injMsg").value; if (!m) return;
    await apiPost("/api/inject", { target: a.source_ip, message: m });
    document.getElementById("injBtn").textContent = "sent ✓";
  };
  document.getElementById("blkBtn").onclick = async () => {
    await apiPost("/api/control", { scope: "block", ip: a.source_ip });
    document.getElementById("blkBtn").textContent = "blocked ✓";
  };
  document.getElementById("drawer").classList.remove("hidden");
}

let alertCache = [];
async function renderAlerts() {
  alertCache = await api("/api/alerts");
  const panel = document.getElementById("panel");
  if (!alertCache.length) { panel.innerHTML = '<div class="empty">No escalations yet.</div>'; return; }
  const body = alertCache.map((r, i) => `<tr data-alert="${i}">
    <td>${shortTime(r.at)}</td>
    <td>${esc(r.source_ip)}</td>
    <td>${pill(r.previous_risk, r.previous_risk)} → ${pill(r.risk, r.risk)}</td>
    <td>${pill(r.intent, r.intent)}</td>
    <td>${esc(r.score)}</td>
  </tr>`).join("");
  panel.innerHTML = `<table><thead><tr>
    <th>Time</th><th>Source IP</th><th>Escalation</th><th>Intent</th><th>Score</th>
  </tr></thead><tbody>${body}</tbody></table>`;
  panel.querySelectorAll("tr[data-alert]").forEach((tr) => {
    tr.onclick = () => openAlertDrawer(alertCache[+tr.getAttribute("data-alert")]);
  });
}

const ACTIONS = ["allow", "stall", "fake_error", "decoy_success", "camera_offline"];

const MODES = [
  { key: "deterministic", title: "Deterministic", desc: "Hardcoded responders only. Safest — fully predictable, no model in the loop. Recommended default." },
  { key: "shadow", title: "Shadow", desc: "Serves the deterministic reply, but the trained model also generates a candidate that is logged for review. The attacker never sees the model. Use this to vet the model before trusting it." },
  { key: "ai", title: "AI on decoy_success", desc: "When a session's action is decoy_success, the trained model writes the served response (intelligent shell / panel replies). Highest realism, highest risk — requires the model backend to be running." },
];

async function renderControl() {
  const state = await api("/api/control");
  const panel = document.getElementById("panel");
  const opts = (sel) => ACTIONS.map((a) => `<option ${a === sel ? "selected" : ""}>${a}</option>`).join("");
  const overrides = Object.entries(state.sessionActions || {});
  const blocked = state.blockedIps || [];

  const modeCards = MODES.map((m) => `
    <label class="mode-card ${state.mode === m.key ? "sel" : ""}">
      <input type="radio" name="engineMode" value="${m.key}" ${state.mode === m.key ? "checked" : ""} />
      <div class="mode-title">${esc(m.title)}</div>
      <div class="mode-desc">${esc(m.desc)}</div>
    </label>`).join("");

  panel.innerHTML = `
    <div class="cfg-section">
      <h4>Engine mode <span class="muted">how responses are generated</span></h4>
      <div class="mode-grid">${modeCards}</div>
    </div>

    <div class="cfg-section">
      <h4>Default response action</h4>
      <div class="control-row">
        <select id="defaultAction">${opts(state.defaultAction)}</select>
        <button class="act" id="applyDefault">Apply</button>
      </div>
      <p class="cfg-note">Applies to every session without an explicit override. <code>decoy_success</code> lets attackers "in" (fake shell / dashboard) so their actions are logged.</p>
    </div>

    <div class="cfg-section">
      <h4>Per-session override</h4>
      <div class="control-row">
        <input id="ovSession" class="txt" placeholder="session id" />
        <select id="ovAction">${opts("stall")}</select>
        <button class="act" id="applyOverride">Set</button>
      </div>
      <table><thead><tr><th>Session</th><th>Override</th></tr></thead><tbody>
        ${overrides.length ? overrides.map(([s, a]) => `<tr><td>${esc(s)}</td><td>${pill("recon", a)}</td></tr>`).join("") : '<tr><td colspan="2" class="empty">no overrides</td></tr>'}
      </tbody></table>
    </div>

    <div class="cfg-section">
      <h4>Block / kick IP <span class="muted">refuse all connections from an address</span></h4>
      <div class="control-row">
        <input id="blkIp" class="txt" placeholder="1.2.3.4" />
        <button class="act danger" id="applyBlock">Block</button>
      </div>
      <table><thead><tr><th>Blocked IP</th><th></th></tr></thead><tbody>
        ${blocked.length ? blocked.map((ip) => `<tr><td>${esc(ip)}</td><td><button class="act sm" data-unblock="${esc(ip)}">unblock</button></td></tr>`).join("") : '<tr><td colspan="2" class="empty">none blocked</td></tr>'}
      </tbody></table>
    </div>`;

  panel.querySelectorAll('input[name="engineMode"]').forEach((r) => {
    r.onchange = async (e) => { await apiPost("/api/control", { scope: "mode", mode: e.target.value }); renderControl(); };
  });
  document.getElementById("applyDefault").onclick = async () => {
    await apiPost("/api/control", { scope: "default", action: document.getElementById("defaultAction").value });
    renderControl();
  };
  document.getElementById("applyOverride").onclick = async () => {
    const sessionId = document.getElementById("ovSession").value.trim();
    if (!sessionId) return;
    await apiPost("/api/control", { scope: "session", sessionId, action: document.getElementById("ovAction").value });
    renderControl();
  };
  document.getElementById("applyBlock").onclick = async () => {
    const ip = document.getElementById("blkIp").value.trim();
    if (!ip) return;
    await apiPost("/api/control", { scope: "block", ip });
    renderControl();
  };
  panel.querySelectorAll("button[data-unblock]").forEach((b) => {
    b.onclick = async () => { await apiPost("/api/control", { scope: "unblock", ip: b.getAttribute("data-unblock") }); renderControl(); };
  });

  // --- Auto-response playbooks ---
  let pbs = [];
  try { pbs = await api("/api/playbooks"); } catch (e) {}
  const pbActions = ["block", "alert", "stall", "fake_error", "decoy_success", "allow"];
  const whenStr = (w) => Object.entries(w).map(([k, v]) => `${k}=${v}`).join(" · ") || "any";
  const pbRows = pbs.map((p, i) => `<tr>
      <td><input type="checkbox" data-pb="${i}" ${p.enabled ? "checked" : ""}></td>
      <td>${esc(p.name)}</td>
      <td class="muted">${esc(whenStr(p.when))}</td>
      <td><select data-pbact="${i}">${pbActions.map((a) => `<option ${a === p.then ? "selected" : ""}>${a}</option>`).join("")}</select></td>
    </tr>`).join("");
  panel.insertAdjacentHTML("beforeend", `
    <div class="cfg-section">
      <h4>Auto-response playbooks <span class="muted">fire automatically on matching events</span></h4>
      <table><thead><tr><th>On</th><th>Rule</th><th>When</th><th>Then</th></tr></thead><tbody>${pbRows || '<tr><td colspan="4" class="empty">none</td></tr>'}</tbody></table>
      <p class="cfg-note">Enable cautiously — these act on live traffic (block IPs, tarpit, or let attackers in via decoy_success).</p>
    </div>`);
  const savePbs = async () => { await apiPost("/api/playbooks", pbs); };
  panel.querySelectorAll("input[data-pb]").forEach((cb) => {
    cb.onchange = async (e) => { pbs[+e.target.getAttribute("data-pb")].enabled = e.target.checked; await savePbs(); };
  });
  panel.querySelectorAll("select[data-pbact]").forEach((sel) => {
    sel.onchange = async (e) => { pbs[+e.target.getAttribute("data-pbact")].then = e.target.value; await savePbs(); };
  });
}

async function renderMlops() {
  const panel = document.getElementById("panel");
  let status = { state: "idle", message: "" };
  try { status = await api("/api/retrain/status"); } catch (e) {}
  let control = {};
  try { control = await api("/api/control"); } catch (e) {}
  const st = status.state || "idle";
  panel.innerHTML = `
    <div class="cfg-section">
      <h4>Model retraining <span class="muted">Qwen3-4B QLoRA on collected transcripts</span></h4>
      <div class="control-row">
        <button class="act" id="retrainBtn" ${status.running ? "disabled" : ""}>${status.running ? "running…" : "Retrain now"}</button>
        <label class="muted"><input type="checkbox" id="retrainForce" /> force (ignore min-new gate)</label>
        <label class="muted"><input type="checkbox" id="retrainExport" /> export-only (no GPU)</label>
      </div>
      <div class="kpis" style="margin-top:14px">
        <div class="kpi"><div class="k-label">State</div><div class="k-value" style="font-size:18px">${esc(st)}</div></div>
        <div class="kpi"><div class="k-label">New transcripts</div><div class="k-value" style="font-size:18px">${esc(status.new_transcripts ?? "—")}</div></div>
        <div class="kpi"><div class="k-label">Backend</div><div class="k-value" style="font-size:18px">${esc(status.backend || "—")}</div></div>
        <div class="kpi"><div class="k-label">Engine mode</div><div class="k-value" style="font-size:18px">${esc(control.mode || "—")}</div></div>
      </div>
      <p class="cfg-note">Last run ${esc(status.run_id || "—")}: ${esc(status.message || "no retrain yet")}. In-pod this is a no-op (training runs as a host/CronJob); on this host it spawns the pipeline.</p>
    </div>`;
  // AI inference status + shadow comparisons
  let ai = { configured: false };
  let shadow = [];
  try { ai = await api("/api/ai/status"); } catch (e) {}
  try { shadow = await api("/api/shadow?limit=40"); } catch (e) {}

  const aiBadge = ai.configured
    ? `<span class="pill recon">model endpoint: connected (${esc(ai.model)})</span>`
    : `<span class="pill high">model endpoint: NOT configured</span>`;

  const shadowRows = shadow.length
    ? shadow.map((s) => `<tr>
        <td>${shortTime(s.at)}</td><td>${esc(s.service)}</td>
        <td class="wrap"><code>${esc(s.request)}</code></td>
        <td class="wrap">${esc((s.deterministic||"").slice(0,160))}</td>
        <td class="wrap">${esc((s.model||"").slice(0,160))}</td>
        <td>${esc(s.latencyMs)}ms</td></tr>`).join("")
    : '<tr><td colspan="6" class="empty">no shadow samples yet — set Engine Mode to “shadow” (and configure AI_MODEL_URL) to collect model-vs-deterministic comparisons</td></tr>';

  panel.insertAdjacentHTML("beforeend", `
    <div class="cfg-section">
      <h4>AI inference ${aiBadge}</h4>
      <p class="cfg-note">${ai.configured
        ? "Shadow mode logs a model candidate next to each deterministic reply below. AI mode serves the model on decoy_success."
        : "Set <code>AI_MODEL_URL</code> (OpenAI-compatible endpoint, e.g. llama-server / Ollama) on the honeypot to enable shadow/AI modes. Until then they fall back to deterministic."}</p>
      <table><thead><tr>
        <th>Time</th><th>Svc</th><th>Request</th><th>Deterministic</th><th>Model candidate</th><th>Lat</th>
      </tr></thead><tbody>${shadowRows}</tbody></table>
    </div>`);

  const btn = document.getElementById("retrainBtn");
  if (btn) btn.onclick = async () => {
    btn.disabled = true; btn.textContent = "starting…";
    try {
      await apiPost("/api/retrain", {
        force: document.getElementById("retrainForce").checked,
        exportOnly: document.getElementById("retrainExport").checked,
      });
    } catch (e) {}
    setTimeout(renderMlops, 1500);
  };
}

function wireRowDrawer(panel, key) {
  panel.querySelectorAll("tr[data-" + key + "]").forEach((tr) => {
    tr.onclick = async () => {
      const id = tr.getAttribute("data-" + key);
      if (!id) return;
      try {
        const detail = await api("/api/attackers/" + encodeURIComponent(id));
        openDrawer("Attacker " + detail.sourceIp, detail);
      } catch (e) { openDrawer("Detail", String(e)); }
    };
  });
}

function highlightJson(obj) {
  let json = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
  json = json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  // token coloring
  json = json.replace(
    /("(?:\\.|[^"\\])*"(\s*:)?|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?)/g,
    (m) => {
      let cls = "j-num";
      if (/^"/.test(m)) cls = /:$/.test(m) ? "j-key" : "j-str";
      else if (/true|false/.test(m)) cls = "j-bool";
      else if (/null/.test(m)) cls = "j-null";
      return `<span class="${cls}">${m}</span>`;
    }
  );
  // important-value emphasis
  json = json
    .replace(/"(high|exploitation)"/g, '"<span class="hot">$1</span>"')
    .replace(/"(brute_force|medium)"/g, '"<span class="warnv">$1</span>"')
    .replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g, '<span class="ipv">$1</span>');
  return json;
}

function openDrawer(title, detail) {
  document.getElementById("drawerTitle").textContent = title;
  const body = document.getElementById("drawerBody");
  const sourceIp = detail && typeof detail === "object" ? detail.sourceIp : null;
  const actions = sourceIp
    ? `<div class="drawer-actions">
         <input id="injMsg" class="txt" placeholder="message to inject into ${esc(sourceIp)} session…" style="flex:1" />
         <button class="act sm" id="injBtn">Inject</button>
         <button class="act sm danger" id="blkBtn">Block IP</button>
       </div>`
    : "";
  body.innerHTML = actions + `<pre class="jsonview">${highlightJson(detail)}</pre>`;
  if (sourceIp) {
    document.getElementById("injBtn").onclick = async () => {
      const m = document.getElementById("injMsg").value;
      if (!m) return;
      await apiPost("/api/inject", { target: sourceIp, message: m });
      document.getElementById("injMsg").value = "";
      document.getElementById("injBtn").textContent = "sent ✓";
    };
    document.getElementById("blkBtn").onclick = async () => {
      await apiPost("/api/control", { scope: "block", ip: sourceIp });
      document.getElementById("blkBtn").textContent = "blocked ✓";
    };
  }
  document.getElementById("drawer").classList.remove("hidden");
}

async function renderCti() {
  const panel = document.getElementById("panel");
  let iocs = { iocs: [], counts: {} }, attack = [], conn = {};
  try { iocs = await api("/api/cti/iocs"); } catch (e) {}
  try { attack = await api("/api/cti/attack"); } catch (e) {}
  try { conn = await api("/api/cti/connectors"); } catch (e) {}

  const tok = URL_TOKEN ? ("?token=" + encodeURIComponent(URL_TOKEN)) : "";
  const counts = iocs.counts || {};
  const countCards = Object.entries(counts).map(([k, v]) =>
    `<div class="kpi"><div class="k-label">${esc(k)}</div><div class="k-value" style="font-size:20px">${esc(v)}</div></div>`).join("") || '<div class="muted">no IOCs yet</div>';

  const maxTech = Math.max(1, ...attack.map((t) => t.count));
  const heat = attack.length ? attack.map((t) => `
    <div class="bar-row">
      <div class="bl" title="${esc(t.tactic)}">${esc(t.id)} ${esc(t.name)}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.round((t.count / maxTech) * 100)}%"></div></div>
      <div class="bv">${esc(t.count)}</div>
    </div>`).join("") : '<div class="empty">no techniques observed yet</div>';

  const topIocs = (iocs.iocs || []).slice(0, 60).map((i) => `<tr>
    <td>${esc(i.type)}</td><td class="wrap">${esc(i.value)}</td><td>${esc(i.count)}</td><td>${shortTime(i.lastSeen)}</td></tr>`).join("");

  const badge = (label, arr) => {
    const on = arr && arr.length;
    return `<span class="pill ${on ? "recon" : "high"}">${esc(label)}: ${on ? arr.join(",") : "none"}</span>`;
  };

  panel.innerHTML = `
    <div class="cfg-section">
      <h4>Connectors</h4>
      <div class="control-row">
        ${badge("enrichment", conn.enrichment)}
        ${badge("forwarding", conn.forwarding)}
        <span class="pill ${conn.feeds ? "recon" : "high"}">feeds: ${esc(conn.feeds || 0)}</span>
        <button class="act sm" id="ingestFeeds">ingest feeds → block</button>
      </div>
      <p class="cfg-note">Configure via env: <code>ABUSEIPDB_API_KEY</code>/<code>GREYNOISE_API_KEY</code>/<code>VIRUSTOTAL_API_KEY</code> (enrichment), <code>SYSLOG_URL</code>/<code>CTI_WEBHOOK_URL</code>/<code>SPLUNK_HEC_URL</code> (forwarding), <code>THREAT_FEEDS</code> (ingest).</p>
    </div>
    <div class="cfg-section">
      <h4>Exports</h4>
      <div class="control-row">
        <a class="act sm" href="/api/cti/stix${tok}">STIX 2.1</a>
        <a class="act sm" href="/api/cti/misp${tok}">MISP event</a>
        <a class="act sm" href="/api/cti/blocklist.csv${tok}">Blocklist CSV</a>
        <span class="muted">TAXII 2.1: <code>/taxii2/cti/collections/honeypot/objects</code></span>
      </div>
    </div>
    <div class="cfg-section">
      <h4>IOCs</h4>
      <div class="kpis" style="margin-bottom:12px">${countCards}</div>
      <table><thead><tr><th>Type</th><th>Value</th><th>Count</th><th>Last seen</th></tr></thead>
        <tbody>${topIocs || '<tr><td colspan="4" class="empty">none</td></tr>'}</tbody></table>
    </div>
    <div class="cfg-section">
      <h4>MITRE ATT&CK coverage</h4>
      <div class="bars">${heat}</div>
    </div>`;

  const ing = document.getElementById("ingestFeeds");
  if (ing) ing.onclick = async () => { ing.disabled = true; ing.textContent = "ingesting…"; try { await apiPost("/api/cti/ingest-feeds", {}); } catch (e) {} renderCti(); };

  // MITRE ATT&CK kill-chain (tactic-ordered)
  const TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact", "ICS Impact"];
  const byTactic = {};
  (attack || []).forEach((t) => { (byTactic[t.tactic] = byTactic[t.tactic] || []).push(t); });
  const killchain = TACTIC_ORDER.filter((t) => byTactic[t]).map((t) => `
    <div class="kc-col"><div class="kc-h">${esc(t)}</div>${byTactic[t].map((x) => `<div class="kc-tech" title="${esc(x.name)}">${esc(x.id)}<span>${esc(x.count)}</span></div>`).join("")}</div>`).join("");

  // Campaigns + novelty (anomaly) + dark-web views
  let campaigns = [], novelty = { iocs: [], techniques: [] }, darkweb = { configured: false, hits: [] };
  try { campaigns = await api("/api/cti/campaigns"); } catch (e) {}
  try { novelty = await api("/api/cti/novelty?hours=24"); } catch (e) {}
  try { darkweb = await api("/api/cti/darkweb"); } catch (e) {}
  const campRows = campaigns.slice(0, 20).map((c) => `<tr>
    <td>${esc(c.origin)}</td><td>${pill(c.intent, c.intent)}</td><td>${esc(c.members)}</td>
    <td>${esc(c.totalScore)}</td><td class="wrap">${esc((c.services || []).join(","))}</td></tr>`).join("");
  const novRows = (novelty.iocs || []).map((i) => `<tr><td>${esc(i.type)}</td><td class="wrap">${esc(i.value)}</td><td>${shortTime(i.firstSeen)}</td></tr>`).join("");
  panel.insertAdjacentHTML("beforeend", `
    <div class="cfg-section">
      <h4>Campaigns <span class="muted">attackers clustered by origin + intent</span></h4>
      <table><thead><tr><th>Origin</th><th>Intent</th><th>Members</th><th>Score</th><th>Services</th></tr></thead>
        <tbody>${campRows || '<tr><td colspan="5" class="empty">no multi-member campaigns yet</td></tr>'}</tbody></table>
    </div>
    <div class="cfg-section">
      <h4>Novelty <span class="muted">first seen in last 24h (${esc((novelty.techniques || []).length)} new techniques)</span></h4>
      <table><thead><tr><th>Type</th><th>Value</th><th>First seen</th></tr></thead>
        <tbody>${novRows || '<tr><td colspan="3" class="empty">nothing new</td></tr>'}</tbody></table>
    </div>
    <div class="cfg-section">
      <h4>MITRE ATT&CK kill-chain</h4>
      <div class="killchain">${killchain || '<div class="empty">no techniques yet</div>'}</div>
    </div>
    <div class="cfg-section">
      <h4>Dark-web intel stream
        <span class="pill ${darkweb.configured ? "recon" : "high"}">${darkweb.configured ? "feeds configured" : "not configured"}</span>
        <button class="act sm" id="dwRefresh">refresh</button>
      </h4>
      <p class="cfg-note">Correlates our observed IPs/usernames/URLs against external leak/paste/breach feeds. Set <code>DARKWEB_FEEDS</code> (and optionally <code>DARKWEB_PROXY</code> for Tor/.onion).</p>
      <table><thead><tr><th>Indicator</th><th>Type</th><th>Source</th><th>Context</th></tr></thead><tbody>
        ${(darkweb.hits || []).map((h) => `<tr><td class="hot">${esc(h.indicator)}</td><td>${esc(h.type)}</td><td class="wrap">${esc(h.source)}</td><td class="wrap muted">${esc(h.context)}</td></tr>`).join("") || '<tr><td colspan="4" class="empty">no correlations (configure DARKWEB_FEEDS)</td></tr>'}
      </tbody></table>
    </div>`);
  const dw = document.getElementById("dwRefresh");
  if (dw) dw.onclick = async () => { dw.disabled = true; dw.textContent = "scanning…"; try { await apiPost("/api/cti/darkweb/refresh", {}); } catch (e) {} renderCti(); };
}

async function renderDarkweb() {
  const panel = document.getElementById("panel");
  let feed = { configured: false, items: [] };
  try { feed = await api("/api/cti/darkweb-feed?limit=200"); } catch (e) {}
  const items = feed.items || [];

  const kindPill = (kind) => {
    const cls = kind === "breach" || kind === "leak" ? "high"
      : kind === "listing" ? "brute_force"
      : kind === "correlation" ? "exploitation" : "recon";
    return pill(cls, kind);
  };
  const counts = items.reduce((m, i) => (m[i.kind] = (m[i.kind] || 0) + 1, m), {});
  const countCards = Object.entries(counts).map(([k, v]) =>
    `<div class="kpi"><div class="k-label">${esc(k)}</div><div class="k-value" style="font-size:20px">${esc(v)}</div></div>`).join("")
    || '<div class="muted">no items yet</div>';

  const rows = items.map((i) => `<tr>
    <td>${shortTime(i.at)}</td>
    <td>${pill("darkweb", "dark-web")} ${kindPill(i.kind)}</td>
    <td class="hot wrap">${esc(i.title)}${(i.tags && i.tags.length) ? " " + i.tags.map((t) => pill("recon", t)).join(" ") : ""}</td>
    <td class="wrap muted">${esc(i.detail)}</td>
    <td class="wrap muted">${esc(i.source)}</td>
  </tr>`).join("");

  panel.innerHTML = `
    <div class="cfg-section">
      <h4>Dark-web news &amp; events
        <span class="pill ${feed.configured ? "recon" : "high"}">${feed.configured ? "feeds configured" : "not configured"}</span>
        <button class="act sm" id="dwFeedRefresh">refresh</button>
      </h4>
      <p class="cfg-note">External dark-web intel — leak/breach announcements, marketplace listings, actor chatter, plus correlations of our own captured IOCs. Every row is tagged <span class="pill darkweb">dark-web</span> to mark it as external, not honeypot-observed. Set <code>DARKWEB_FEEDS</code> and/or <code>DARKWEB_NEWS_FEEDS</code> (optionally <code>DARKWEB_PROXY</code> for Tor/.onion).</p>
      <div class="kpis" style="margin-bottom:12px">${countCards}</div>
      <table><thead><tr><th>Time</th><th>Source</th><th>Headline / Indicator</th><th>Detail</th><th>Feed</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5" class="empty">no dark-web items yet (configure DARKWEB_FEEDS / DARKWEB_NEWS_FEEDS, then refresh)</td></tr>'}</tbody></table>
    </div>`;

  const btn = document.getElementById("dwFeedRefresh");
  if (btn) btn.onclick = async () => { btn.disabled = true; btn.textContent = "scanning…"; try { await apiPost("/api/cti/darkweb/refresh", {}); } catch (e) {} renderDarkweb(); };
}

async function renderFleet() {
  const panel = document.getElementById("panel");
  let nodes = [];
  try { nodes = await api("/api/fleet"); } catch (e) {}
  const rows = nodes.map((n) => `<tr>
    <td>${n.online ? '<span class="pill recon">online</span>' : '<span class="pill high">offline</span>'}</td>
    <td>${esc(n.name)}</td><td>${esc(n.region || "—")}</td>
    <td>${esc(n.attackers)}</td><td>${esc(n.active15m)}</td><td>${esc(n.highRisk)}</td>
    <td>${esc(n.transcripts)}</td><td>${esc(n.topCountry)}</td><td>${shortTime(n.lastSeen)}</td>
  </tr>`).join("");
  panel.innerHTML = `
    <div class="kpis" style="margin-bottom:14px">
      <div class="kpi"><div class="k-label">Nodes</div><div class="k-value">${nodes.length}</div></div>
      <div class="kpi"><div class="k-label">Online</div><div class="k-value">${nodes.filter((n) => n.online).length}</div></div>
      <div class="kpi"><div class="k-label">Total attackers</div><div class="k-value">${nodes.reduce((s, n) => s + (n.attackers || 0), 0)}</div></div>
    </div>
    <table><thead><tr><th>Status</th><th>Node</th><th>Region</th><th>Attackers</th><th>Active 15m</th><th>High</th><th>Transcripts</th><th>Top origin</th><th>Last seen</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="9" class="empty">no nodes reporting yet</td></tr>'}</tbody></table>
    <p class="cfg-note" style="margin-top:12px">Point other deployments here with <code>FLEET_MASTER_URL</code> (+ <code>FLEET_TOKEN</code>) and label them via <code>NODE_NAME</code>/<code>NODE_REGION</code>.</p>`;
}

const TAB_RENDERERS = {
  feed: renderFeed,
  attackers: renderAttackers,
  sessions: renderSessions,
  alerts: renderAlerts,
  control: renderControl,
  cti: renderCti,
  darkweb: renderDarkweb,
  fleet: renderFleet,
  mlops: renderMlops,
};

// Tabs with form inputs / heavy content we must not clobber on the 4s auto-refresh.
const STATIC_TABS = new Set(["control", "mlops", "cti"]);

async function refresh() {
  try {
    const [overview, timeline] = await Promise.all([api("/api/overview"), api("/api/timeline?hours=24")]);
    renderKpis(overview);
    renderBars("riskBars", mapToEntries(overview.attackers.byRisk), { riskColors: true });
    renderBars("intentBars", mapToEntries(overview.attackers.byIntent));
    renderBars("countryBars", overview.attackers.byCountry);
    renderBars("serviceBars", mapToEntries(overview.transcripts.byService));
    renderTimeline(timeline);
    if (!STATIC_TABS.has(activeTab)) await TAB_RENDERERS[activeTab]();
    document.getElementById("lastUpdated").textContent = "updated " + new Date().toLocaleTimeString();
    setLive(true);
  } catch (e) {
    setLive(false);
  }
}

function startTimer() {
  if (refreshTimer) clearInterval(refreshTimer);
  if (autoRefresh) refreshTimer = setInterval(refresh, REFRESH_MS);
}

document.querySelectorAll(".tab").forEach((btn) => {
  btn.onclick = () => {
    document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    activeTab = btn.getAttribute("data-tab");
    document.getElementById("panel").classList.toggle("mlops-theme", activeTab === "mlops");
    TAB_RENDERERS[activeTab]();
  };
});
document.getElementById("autoRefresh").onchange = (e) => { autoRefresh = e.target.checked; startTimer(); };
document.getElementById("drawerClose").onclick = () => document.getElementById("drawer").classList.add("hidden");

// Boot splash: glow the ASCII logo briefly, then reveal the metrics.
(async () => {
  const splash = document.getElementById("splash");
  try {
    const r = await fetch("/api/logo", { headers: URL_TOKEN ? { Authorization: "Bearer " + URL_TOKEN } : {}, credentials: "same-origin" });
    if (r.ok) document.getElementById("splashLogo").textContent = await r.text();
  } catch (e) {}
  setTimeout(() => splash && splash.classList.add("gone"), 1600);
})();

refresh();
startTimer();
