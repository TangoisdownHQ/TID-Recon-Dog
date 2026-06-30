import { ResponderContext } from "./types.js";

// Attacker-facing decoy login panels served by the HTTP listener. Each one is a
// deterministic, believable product login that records submitted credentials
// into attacker memory (login attempts score as brute_force) and never reveals
// it is a decoy. Memory normalizes these to the `http` service (see
// serviceNames.ts), while the operator sees the distinct service tag.

export type PanelRenderArgs = {
  host: string;
  message?: string;
  username?: string;
};

export type PanelDefinition = {
  /** Operator-facing service tag (uppercased into sessions/transcripts). */
  service: string;
  /** Routes this panel answers (GET = login page, POST = auth attempt). */
  paths: string[];
  /** Lowercased credential field names accepted on POST. */
  fields: string[];
  renderLogin: (ctx: ResponderContext, args: PanelRenderArgs) => string;
  renderDashboard: (ctx: ResponderContext, args: PanelRenderArgs) => string;
};

const esc = (value: string) =>
  String(value).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

// ---------------------------------------------------------------------------
// 1. OpsCenter appliance admin console
// ---------------------------------------------------------------------------

function adminLogin(ctx: ResponderContext, { host, message }: PanelRenderArgs): string {
  const err = message
    ? `<div class="err">${esc(message)}</div>`
    : "";
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>OpsCenter Appliance Manager</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:-apple-system,Segoe UI,Roboto,sans-serif;
background:linear-gradient(160deg,#0f1b2d,#0a1320);color:#dce6f2}
.box{width:min(380px,calc(100vw - 32px));background:#101e30;border:1px solid #213750;border-radius:6px;
padding:30px 28px;box-shadow:0 24px 70px rgba(0,0,0,.45)}
.logo{font-size:.78rem;letter-spacing:.22em;color:#5e89bf;text-transform:uppercase}
h1{font-size:1.32rem;margin:6px 0 2px;font-weight:600}
.sub{color:#7e93ab;font-size:.82rem;margin-bottom:20px}
label{display:block;font-size:.76rem;color:#93a6bc;margin:14px 0 5px}
input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #28415d;background:#0b1726;color:#e7eef6;border-radius:4px}
button{width:100%;margin-top:22px;padding:11px;border:0;border-radius:4px;background:#2f6fb3;color:#fff;font-weight:600;cursor:pointer}
button:hover{background:#3a82cc}
.err{background:#3a1620;border:1px solid #7d2435;color:#f0a9b4;padding:9px 11px;border-radius:4px;font-size:.82rem;margin-bottom:6px}
.ft{margin-top:18px;color:#5a6f87;font-size:.72rem;text-align:center}
</style></head><body>
<form class="box" method="POST" action="/admin/login">
<div class="logo">OpsCenter</div>
<h1>Appliance Manager</h1>
<div class="sub">${esc(host)}</div>
${err}
<label for="username">Username</label>
<input id="username" name="username" autocomplete="username" autofocus required />
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required />
<button type="submit">Sign in</button>
<div class="ft">OpsCenter Appliance Manager v7.4.2 &middot; node ${esc(host)}</div>
</form></body></html>`;
}

function adminDashboard(ctx: ResponderContext, { host, username }: PanelRenderArgs): string {
  // Rich, explorable IoT access-control console — doors, gates, units, devices,
  // and a live access log, so an attacker has plenty of believable data to dig
  // through (and controls to "actuate", which we log as exploitation intent).
  const doors = [
    ["Main Lobby", "DR-101", "locked", "08:42 j.harmon", "online"],
    ["Loading Dock A", "DR-204", "UNLOCKED", "09:15 svc_delivery", "online"],
    ["Server Room", "DR-330", "locked", "07:58 ops.deploy", "online"],
    ["Roof Access", "DR-401", "locked", "—", "offline"],
    ["Parking Gate North", "GT-12", "open", "09:31 visitor-4821", "online"],
    ["Parking Gate South", "GT-13", "closed", "06:22 j.harmon", "online"],
    ["Garage Rolling Door", "GT-20", "closed", "yesterday", "online"],
  ];
  const units = [
    ["Bldg A · Apt 1203", "Harmon, J.", "armed", "Aug 2025"],
    ["Bldg A · Apt 1207", "Okafor, D.", "disarmed", "Jan 2026"],
    ["Bldg B · Penthouse", "Globex Corp", "armed", "Mar 2024"],
    ["Bldg C · Unit 14", "vacant", "armed", "—"],
  ];
  const events = [
    ["09:31:04", "GT-12", "granted", "fob 4821 (visitor)", "Parking Gate North"],
    ["09:28:55", "DR-204", "forced", "alarm: held open 90s", "Loading Dock A"],
    ["09:15:12", "DR-204", "granted", "card svc_delivery", "Loading Dock A"],
    ["08:42:30", "DR-101", "granted", "mobile j.harmon", "Main Lobby"],
    ["08:40:01", "DR-330", "DENIED", "pin retries=3 unknown", "Server Room"],
  ];
  const devices = [
    ["AXIS-P3265 cam", "CAM-LOBBY-1", "10.20.8.21", "fw 11.7.61", "streaming"],
    ["HID controller", "CTRL-A1", "10.20.8.40", "fw 8.2.3", "online"],
    ["Z-Wave hub", "HUB-B", "10.20.8.55", "fw 2.19", "online"],
    ["Gate motor ctrl", "GT-12-MC", "10.20.8.61", "fw 1.4", "online"],
  ];
  const row = (cells: string[], flag = -1) =>
    `<tr>${cells.map((c, i) => `<td${i === flag && /UNLOCK|open|forced|DENIED|offline/i.test(c) ? ' class="hot"' : ""}>${esc(c)}</td>`).join("")}</tr>`;
  const sidebar = ["Overview", "Doors & Gates", "Buildings", "Residents", "Access Log", "Cameras", "Devices", "Schedules", "Alarms", "Reports", "Settings"]
    .map((s, i) => `<a class="${i === 1 ? "sel" : ""}">${s}</a>`).join("");
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" />
<title>OpsCenter · Access Control</title><style>
:root{color-scheme:dark}
*{box-sizing:border-box}body{margin:0;font-family:-apple-system,Segoe UI,Roboto,sans-serif;background:#0a1320;color:#dce6f2;font-size:13px}
.top{display:flex;justify-content:space-between;align-items:center;padding:10px 18px;background:#0d1726;border-bottom:1px solid #213750}
.top b{letter-spacing:.04em}.layout{display:grid;grid-template-columns:200px 1fr;min-height:100vh}
.side{background:#0d1726;border-right:1px solid #213750;padding:10px 0}
.side a{display:block;padding:9px 18px;color:#9fb2c8;text-decoration:none;cursor:pointer;font-size:.86rem}
.side a:hover{background:#13243a}.side a.sel{background:#16304d;color:#fff;border-left:3px solid #3f86d6}
.main{padding:18px 22px}.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:#101e30;border:1px solid #213750;border-radius:6px;padding:12px 14px}
.kpi .n{font-size:1.6rem;font-weight:600}.kpi .l{color:#7e93ab;font-size:.72rem;text-transform:uppercase}
h3{font-size:.95rem;margin:18px 0 8px}table{width:100%;border-collapse:collapse;background:#101e30;border:1px solid #213750;border-radius:6px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #1b2d44;font-size:.84rem}th{color:#7e93ab;text-transform:uppercase;font-size:.68rem;letter-spacing:.06em}
td.hot{color:#ff8f8f;font-weight:600}.btn{background:#16304d;border:1px solid #2c5d92;color:#cfe0f5;padding:3px 9px;border-radius:4px;cursor:pointer;font-size:.78rem}
</style></head><body>
<div class="top"><b>OpsCenter · Access &amp; Building Control</b><span>${esc(username || "operator")} · ${esc(host)} · <a style="color:#7fa9d6">sign out</a></span></div>
<div class="layout">
<nav class="side">${sidebar}</nav>
<main class="main">
<div class="kpis">
  <div class="kpi"><div class="n">3</div><div class="l">Sites</div></div>
  <div class="kpi"><div class="n">42</div><div class="l">Doors &amp; Gates</div></div>
  <div class="kpi"><div class="n">2</div><div class="l">Open / Unlocked</div></div>
  <div class="kpi"><div class="n">128</div><div class="l">Active Credentials</div></div>
  <div class="kpi"><div class="n">1</div><div class="l">Alarms</div></div>
</div>
<h3>Doors &amp; Gates</h3>
<table><thead><tr><th>Location</th><th>ID</th><th>State</th><th>Last access</th><th>Device</th><th></th></tr></thead><tbody>
${doors.map((d) => row(d, 2).replace("</tr>", `<td><button class="btn">${/lock/i.test(d[2]) ? "unlock" : "lock"}</button></td></tr>`)).join("")}
</tbody></table>
<h3>Buildings &amp; Residents</h3>
<table><thead><tr><th>Unit</th><th>Resident</th><th>Alarm</th><th>Since</th></tr></thead><tbody>${units.map((u) => row(u, 2)).join("")}</tbody></table>
<h3>Recent Access Events</h3>
<table><thead><tr><th>Time</th><th>Device</th><th>Result</th><th>Credential</th><th>Location</th></tr></thead><tbody>${events.map((e) => row(e, 2)).join("")}</tbody></table>
<h3>Devices</h3>
<table><thead><tr><th>Type</th><th>ID</th><th>Address</th><th>Firmware</th><th>Status</th></tr></thead><tbody>${devices.map((d) => row(d, 4)).join("")}</tbody></table>
</main></div></body></html>`;
}

// ---------------------------------------------------------------------------
// 2. Adminer-style database login (PostgreSQL)
// ---------------------------------------------------------------------------

function dbLogin(ctx: ResponderContext, { host, message }: PanelRenderArgs): string {
  const err = message ? `<p class="error">${esc(message)}</p>` : "";
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Login - Adminer</title>
<style>
body{font-family:Verdana,Arial,sans-serif;font-size:13px;margin:0;background:#fff;color:#000}
#menu{position:absolute;top:0;left:0;width:190px;padding:10px;box-sizing:border-box}
#menu h1{font-size:15px;margin:0 0 14px}
#menu h1 a.h1{color:#09f;text-decoration:none}
#content{margin-left:210px;padding:14px}
h2{font-size:15px;margin:0 0 12px;border-bottom:1px solid #ccc;padding-bottom:6px}
table{border-collapse:collapse}
th{text-align:right;padding:3px 8px 3px 0;font-weight:normal}
input{font:inherit;padding:2px 4px;border:1px solid #999}
input[type=submit]{cursor:pointer;padding:3px 9px}
.error{background:#fee;border:1px solid #d88;padding:6px 9px;color:#900}
select{font:inherit}
</style></head><body>
<div id="menu"><h1><a href="https://www.adminer.org/" class="h1">Adminer</a> <span style="font-size:11px">4.8.1</span></h1></div>
<div id="content">
<h2>Login</h2>
${err}
<form method="POST" action="/adminer.php">
<table cellspacing="0">
<tr><th>System<td><select name="system"><option value="pgsql" selected>PostgreSQL</option><option>MySQL</option></select>
<tr><th>Server<td><input name="server" value="${esc(host)}" />
<tr><th>Username<td><input name="username" autocomplete="username" autofocus />
<tr><th>Password<td><input type="password" name="password" autocomplete="current-password" />
<tr><th>Database<td><input name="database" value="operations" />
</table>
<p><input type="submit" value="Login" /> <label><input type="checkbox" name="permanent" value="1" /> Permanent login</label></p>
</form></div></body></html>`;
}

// Fake tables with believable rows — bait that captures the attacker's SQL.
export const DB_TABLES: Record<string, { cols: string[]; rows: string[][] }> = {
  users: {
    cols: ["id", "username", "email", "password_hash", "role", "last_login"],
    rows: [
      ["1", "relayadmin", "admin@ops.internal", "$2y$10$Rl4yK9fakeHASHhoneypotABCDEF", "superuser", "2026-06-29 08:42"],
      ["2", "ops.deploy", "deploy@ops.internal", "$2y$10$D3plfakeHASHhoneypotGHIJKL", "operator", "2026-06-29 09:01"],
      ["3", "j.harmon", "jordan@ops.internal", "$2y$10$HrmnfakeHASHhoneypotMNOPQR", "operator", "2026-06-28 17:33"],
      ["4", "svc_backup", "backup@ops.internal", "$2y$10$Bk0fakeHASHhoneypotSTUVWX", "service", "2026-06-30 02:00"],
    ],
  },
  customers: {
    cols: ["id", "name", "email", "plan", "card_last4", "mrr"],
    rows: [
      ["1001", "Acme Logistics", "ap@acme-log.com", "enterprise", "4242", "4800"],
      ["1002", "Northwind Foods", "billing@northwind.co", "growth", "1881", "1200"],
      ["1003", "Globex Corp", "finance@globex.com", "enterprise", "7702", "5200"],
    ],
  },
  payments: {
    cols: ["id", "customer_id", "amount", "card_last4", "status", "processed_at"],
    rows: [
      ["88121", "1001", "4800.00", "4242", "captured", "2026-06-01 02:14"],
      ["88122", "1003", "5200.00", "7702", "captured", "2026-06-01 02:15"],
      ["88123", "1002", "1200.00", "1881", "refunded", "2026-06-03 11:02"],
    ],
  },
  audit_log: {
    cols: ["id", "actor", "action", "ip", "at"],
    rows: [
      ["9001", "relayadmin", "login", "10.20.4.7", "2026-06-29 08:42"],
      ["9002", "ops.deploy", "deploy v7.4.2", "10.20.4.9", "2026-06-29 09:05"],
      ["9003", "unknown", "failed_login x3", "45.143.x.x", "2026-06-29 09:11"],
    ],
  },
  assets: { cols: ["id", "hostname", "ip", "type"], rows: [["1", "db-prod-01", "10.20.5.12", "postgres"], ["2", "vault", "10.20.6.10", "secrets"], ["3", "backup-01", "10.20.5.40", "storage"]] },
  sites: { cols: ["id", "name", "region"], rows: [["1", "DC4 Loading Dock", "us-east"], ["2", "HQ Lobby", "us-east"], ["3", "Field Gateway 12", "us-west"]] },
};

const ADMINER_HEAD = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" /><title>operations - Adminer</title>
<style>body{font-family:Verdana,Arial,sans-serif;font-size:13px;margin:0;background:#fff;color:#000}
#menu{position:absolute;top:0;left:0;width:170px;padding:10px}#menu h1{font-size:15px;margin:0 0 10px}#menu a{display:block;color:#09f;text-decoration:none;padding:2px 0}
#content{margin-left:190px;padding:14px}h2{font-size:15px;border-bottom:1px solid #ccc;padding-bottom:6px}a{color:#09f}
table{border-collapse:collapse;margin-top:8px}td,th{border:1px solid #ccc;padding:3px 10px;text-align:left}th{background:#f5f5f5}
textarea{width:90%;height:60px;font-family:monospace}input[type=submit]{padding:3px 9px}</style></head><body>`;

function adminerMenu(active: string): string {
  const tabs = Object.keys(DB_TABLES);
  return `<div id="menu"><h1>Adminer <span style="font-size:11px">4.8.1</span></h1>
    <a href="/adminer.php">operations</a><b style="font-size:11px;color:#666">Tables</b>
    ${tabs.map((t) => `<a href="/adminer.php?select=${t}" style="${t === active ? "font-weight:bold" : ""}">${t}</a>`).join("")}
    <br><a href="/adminer.php?sql=">SQL command</a></div>`;
}

function dbDashboard(ctx: ResponderContext, { host }: PanelRenderArgs): string {
  const rows = Object.entries(DB_TABLES).map(([t, d]) => `<tr><td><a href="/adminer.php?select=${t}">${t}</a><td style="text-align:right">${d.rows.length * 137 + 11}</tr>`).join("");
  return `${ADMINER_HEAD}${adminerMenu("")}<div id="content">
    <h2>Database: operations &middot; ${esc(host)}</h2>
    <table cellspacing="0"><tr><th>Table<th>Rows</tr>${rows}</table>
    <h2 style="margin-top:18px">SQL command</h2>
    <form method="POST" action="/adminer.php"><textarea name="sql" placeholder="SELECT * FROM users;"></textarea><br><input type="submit" value="Execute" /></form>
    </div></body></html>`;
}

export function renderDbTable(ctx: ResponderContext, table: string): string {
  const t = DB_TABLES[table];
  if (!t) return `${ADMINER_HEAD}${adminerMenu("")}<div id="content"><h2>Error</h2><p>Table '${esc(table)}' not found.</p></div></body></html>`;
  const head = t.cols.map((c) => `<th>${esc(c)}</th>`).join("");
  const body = t.rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("");
  return `${ADMINER_HEAD}${adminerMenu(table)}<div id="content">
    <h2>Select: ${esc(table)} <span style="font-size:11px;color:#666">(${t.rows.length} rows)</span></h2>
    <table cellspacing="0"><tr>${head}</tr>${body}</table>
    <h2 style="margin-top:18px">SQL command</h2>
    <form method="POST" action="/adminer.php"><textarea name="sql">SELECT * FROM ${esc(table)};</textarea><br><input type="submit" value="Execute" /></form>
    </div></body></html>`;
}

export function renderDbResult(ctx: ResponderContext, sql: string): string {
  const m = sql.match(/from\s+([a-z_]+)/i);
  const t = m && DB_TABLES[m[1].toLowerCase()];
  let result = `<p style="color:#080">Query executed OK.</p>`;
  if (t) {
    const head = t.cols.map((c) => `<th>${esc(c)}</th>`).join("");
    const body = t.rows.map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("");
    result = `<table cellspacing="0"><tr>${head}</tr>${body}</table><p style="color:#666">${t.rows.length} row(s)</p>`;
  } else if (/drop|delete|update|insert|;.*--|union/i.test(sql)) {
    result = `<p style="color:#900">ERROR: permission denied for relation (role "relay_ro" is read-only)</p>`;
  }
  return `${ADMINER_HEAD}${adminerMenu("")}<div id="content">
    <h2>SQL command</h2>
    <form method="POST" action="/adminer.php"><textarea name="sql">${esc(sql)}</textarea><br><input type="submit" value="Execute" /></form>
    <div style="margin-top:12px">${result}</div></div></body></html>`;
}

// ---------------------------------------------------------------------------
// 3. Fieldline embedded gateway (industrial IoT device)
// ---------------------------------------------------------------------------

function iotLogin(ctx: ResponderContext, { host, message }: PanelRenderArgs): string {
  const err = message ? `<div class="msg">${esc(message)}</div>` : "";
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Fieldline Gateway</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:"Segoe UI",Tahoma,sans-serif;
background:radial-gradient(circle at top,#0c2b2b,#06181a);color:#cfeae6}
.unit{width:min(360px,calc(100vw - 28px));border:1px solid #1d4b48;background:#0a2321;border-radius:4px;padding:26px 24px}
.brand{display:flex;align-items:center;gap:10px;margin-bottom:4px}
.dot{width:10px;height:10px;border-radius:50%;background:#43c9a9;box-shadow:0 0 8px #43c9a9}
h1{font-size:1.18rem;margin:0;letter-spacing:.04em}
.model{color:#69a399;font-size:.78rem;margin-bottom:18px}
label{display:block;font-size:.75rem;color:#7fb3a9;margin:12px 0 5px}
input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #1d4b48;background:#06181a;color:#dff3ef;border-radius:3px}
button{width:100%;margin-top:20px;padding:10px;border:0;border-radius:3px;background:#1f7d6c;color:#eafff9;font-weight:600;cursor:pointer}
button:hover{background:#269683}
.msg{background:#3a1d22;border:1px solid #7d3640;color:#f1b3ba;padding:8px 10px;border-radius:3px;font-size:.8rem}
.fw{margin-top:16px;font-size:.7rem;color:#4e7d75;text-align:center}
</style></head><body>
<form class="unit" method="POST" action="/gateway/login">
<div class="brand"><span class="dot"></span><h1>Fieldline Gateway</h1></div>
<div class="model">FG-2200 &middot; ${esc(host)}</div>
${err}
<label for="username">Operator</label>
<input id="username" name="username" autocomplete="username" autofocus required />
<label for="password">Access code</label>
<input id="password" name="password" type="password" autocomplete="current-password" required />
<button type="submit">Authenticate</button>
<div class="fw">Firmware FG2200-3.11.6 &middot; Modbus/TCP bridge active</div>
</form></body></html>`;
}

function iotDashboard(ctx: ResponderContext, { host }: PanelRenderArgs): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" /><title>Fieldline Gateway &middot; Status</title>
<style>body{margin:0;font-family:"Segoe UI",Tahoma,sans-serif;background:#06181a;color:#cfeae6}
.bar{padding:12px 18px;background:#0a2321;border-bottom:1px solid #1d4b48}
.g{padding:18px;display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}
.c{background:#0a2321;border:1px solid #1d4b48;border-radius:4px;padding:14px}
.k{color:#69a399;font-size:.72rem;text-transform:uppercase}.v{font-size:1.3rem;margin-top:5px}</style>
</head><body><div class="bar">Fieldline Gateway FG-2200 &middot; ${esc(host)}</div>
<div class="g">
<div class="c"><div class="k">Bridge</div><div class="v">Online</div></div>
<div class="c"><div class="k">Modbus units</div><div class="v">6 / 6</div></div>
<div class="c"><div class="k">Loop pressure</div><div class="v">4.2 bar</div></div>
<div class="c"><div class="k">Firmware</div><div class="v">3.11.6</div></div>
</div></body></html>`;
}

export const PANELS: PanelDefinition[] = [
  {
    service: "ADMIN",
    paths: ["/admin", "/admin/login", "/administrator", "/manager", "/login"],
    fields: ["username", "password"],
    renderLogin: adminLogin,
    renderDashboard: adminDashboard,
  },
  {
    service: "DB-WEB",
    paths: ["/adminer.php", "/adminer", "/pgadmin", "/phpmyadmin", "/db"],
    fields: ["system", "server", "username", "password", "database"],
    renderLogin: dbLogin,
    renderDashboard: dbDashboard,
  },
  {
    service: "IOT",
    paths: ["/gateway", "/gateway/login", "/device", "/iot", "/cgi-bin/luci"],
    fields: ["username", "password"],
    renderLogin: iotLogin,
    renderDashboard: iotDashboard,
  },
];
