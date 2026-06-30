import crypto from "crypto";
import express, { Request, Response } from "express";
import rateLimit from "express-rate-limit";
import multer from "multer";
import fs from "fs/promises";
import path from "path";
import { Server } from "http";
import { config } from "../config/config.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import {
  applyHttpAction,
  buildCameraArchive,
  buildCameraFrame,
  buildCameraMessage,
  buildHttpHealth,
  buildHttpShellOutput,
  buildRtspUrl,
  findHttpFile,
  listHttpFiles,
} from "../responders/httpResponder.js";
import { logError, logWarning } from "../utils/logger.js";
import { PANELS, PanelDefinition, renderDbTable, renderDbResult } from "../responders/webPanels.js";
import { getServiceProfile } from "../profiles/serviceProfiles.js";
import { jitter, nginxErrorPage, serverTokenFromBanner } from "../utils/hardening.js";
import { isIpBlockedSync } from "../operator/controlPlane.js";

const uploadsDir = path.resolve("uploads");

const esc = (s: string) =>
  String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));

function getClientIp(req: Request): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (Array.isArray(forwarded)) {
    return forwarded[0];
  }
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return req.ip || req.socket.remoteAddress || "unknown";
}

function getSessionId(req: Request): string | undefined {
  const headerSession = req.headers["x-session-id"];
  if (typeof headerSession === "string" && headerSession.trim()) {
    return headerSession.trim();
  }

  const cookieHeader = req.headers.cookie || "";
  const match = cookieHeader.match(/tid_session=([^;]+)/);
  return match?.[1];
}

function setSessionCookie(res: Response, sessionId: string) {
  res.setHeader("Set-Cookie", `tid_session=${sessionId}; HttpOnly; Path=/; SameSite=Lax`);
}

function renderCameraLogin(
  rtspUrl: string,
  message?: string,
  siteName = "DC-4 / Loading Dock"
) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CamWatch Remote Viewer</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b1118;
      --panel: #111b26;
      --line: #31475d;
      --text: #d7e3ef;
      --muted: #8fa7bd;
      --accent: #63c5a7;
      --danger: #df6666;
    }
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background:
        radial-gradient(circle at top, rgba(99,197,167,0.14), transparent 30%),
        linear-gradient(180deg, #081018, var(--bg));
      font-family: "IBM Plex Sans", sans-serif;
      color: var(--text);
    }
    .panel {
      width: min(420px, calc(100vw - 32px));
      padding: 28px;
      border: 1px solid var(--line);
      background: rgba(17,27,38,0.92);
      box-shadow: 0 20px 80px rgba(0,0,0,0.35);
    }
    h1 {
      margin: 0 0 8px;
      font-size: 1.5rem;
      letter-spacing: 0.06em;
      text-transform: uppercase;
    }
    p {
      margin: 0 0 18px;
      color: var(--muted);
    }
    label {
      display: block;
      margin: 14px 0 6px;
      font-size: 0.86rem;
      color: var(--muted);
    }
    input {
      width: 100%;
      box-sizing: border-box;
      padding: 12px;
      border: 1px solid var(--line);
      background: #081018;
      color: var(--text);
    }
    button {
      width: 100%;
      margin-top: 18px;
      padding: 12px;
      border: 0;
      background: var(--accent);
      color: #06110c;
      font-weight: 700;
      cursor: pointer;
    }
    .msg {
      min-height: 20px;
      margin-top: 12px;
      color: ${message ? "var(--danger)" : "var(--muted)"};
    }
  </style>
</head>
<body>
  <form class="panel" method="POST" action="/camera/login">
    <h1>CamWatch Remote Viewer</h1>
    <p>Sign in to access camera groups, archived clips, live monitoring, and RTSP relay credentials.</p>
    <label for="username">Operator ID</label>
    <input id="username" name="username" autocomplete="username" required />
    <label for="password">Passphrase</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required />
    <label for="site">Site</label>
    <input id="site" name="site" value="${siteName}" />
    <button type="submit">Open Live Feed</button>
    <div class="msg">${message || `RTSP endpoint: ${rtspUrl}`}</div>
  </form>
</body>
</html>`;
}

function renderCameraFeed(sessionId: string, action: string, recorder: string, rtspUrl: string, retentionDays: string) {
  const offline = action === "camera_offline";
  const cams = [
    { id: "cam01", name: "Loading Dock A" },
    { id: "cam02", name: "Main Lobby" },
    { id: "cam03", name: "Server Room" },
    { id: "cam04", name: "Parking Gate N" },
    { id: "cam05", name: "Roof Access" },
    { id: "cam06", name: "Warehouse Aisle 3" },
  ];
  const clips = [
    ["06:14:22", "cam01", "motion"],
    ["05:58:03", "cam03", "door-open"],
    ["04:41:55", "cam04", "vehicle-enter"],
    ["02:10:09", "cam05", "tamper"],
  ];
  const tiles = cams
    .map(
      (c, i) => `<div class="tile">
      <canvas class="cv" width="320" height="180" data-name="${c.name}" data-id="${c.id}" data-off="${offline && i % 3 === 0}"></canvas>
      <div class="tlabel"><span class="rec"></span>${c.name} · ${c.id}</div>
    </div>`
    )
    .join("");
  const clipRows = clips
    .map((cl) => `<a class="clip" href="/camera/archive?id=${cl[1]}"><span>${cl[0]}</span> ${cl[1]} <em>${cl[2]}</em></a>`)
    .join("");
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>CamWatch NVR — Live</title>
<style>
:root{color-scheme:dark;--bg:#070d13;--panel:#0f1a25;--line:#22384a;--muted:#8aa3b8;--accent:#7fe6c2;--danger:#db6a6a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#dfe8f0;font-family:"Segoe UI",system-ui,sans-serif;font-size:13px}
.bar{display:flex;justify-content:space-between;align-items:center;padding:10px 16px;background:var(--panel);border-bottom:1px solid var(--line)}
.bar b{letter-spacing:.06em}.wrap{display:grid;grid-template-columns:1fr 230px;gap:14px;padding:14px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:10px}
.tile{position:relative;border:1px solid var(--line);background:#000;overflow:hidden}
.cv{display:block;width:100%;height:auto}
.tlabel{position:absolute;left:0;bottom:0;right:0;padding:4px 8px;background:rgba(0,0,0,.55);font-size:12px;display:flex;align-items:center;gap:7px}
.rec{width:8px;height:8px;border-radius:50%;background:var(--danger);box-shadow:0 0 6px var(--danger);animation:blink 1.4s infinite}
@keyframes blink{50%{opacity:.25}}
.side{border:1px solid var(--line);background:var(--panel);padding:12px}
.side h3{margin:0 0 8px;font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}
.clip{display:block;padding:7px 8px;border-bottom:1px solid var(--line);color:#cfe0ee;text-decoration:none;font-size:12px}
.clip:hover{background:#13243a}.clip span{color:var(--accent)}.clip em{color:var(--muted);font-style:normal;float:right}
.meta{margin-top:12px;font-size:12px;color:var(--muted);line-height:1.7}
</style></head><body>
<div class="bar"><b>CamWatch NVR · ${esc(recorder)}</b><span>${cams.length} channels · ${offline ? "DEGRADED" : "all online"} · <span id="ts"></span></span></div>
<div class="wrap">
  <div class="grid">${tiles}</div>
  <aside class="side">
    <h3>Recordings</h3>${clipRows}
    <div class="meta">
      Retention: ${esc(retentionDays)}d (motion)<br>
      RTSP: ${esc(rtspUrl)}<br>
      API: /camera/api/frame<br>
      Archive: /camera/archive?id=cam04
    </div>
  </aside>
</div>
<script>
// Render believable CCTV noise + overlays on each canvas tile.
const cvs=[...document.querySelectorAll('.cv')];
function draw(){
  const t=new Date().toISOString().replace('T',' ').slice(0,19);
  document.getElementById('ts').textContent=t;
  for(const cv of cvs){
    const x=cv.getContext('2d'),w=cv.width,h=cv.height,off=cv.dataset.off==='true';
    if(off){x.fillStyle='#0a0a0a';x.fillRect(0,0,w,h);x.fillStyle='#555';x.font='13px monospace';x.fillText('NO SIGNAL',w/2-34,h/2);continue;}
    // base gradient + drifting noise
    const g=x.createLinearGradient(0,0,0,h);g.addColorStop(0,'#1b2733');g.addColorStop(1,'#0c141d');x.fillStyle=g;x.fillRect(0,0,w,h);
    const img=x.getImageData(0,0,w,h),d=img.data;
    for(let i=0;i<d.length;i+=4){if(Math.random()<0.10){const n=Math.random()*70;d[i]+=n;d[i+1]+=n;d[i+2]+=n;}}
    x.putImageData(img,0,0);
    // scanline
    const y=(Date.now()/12)%h;x.fillStyle='rgba(255,255,255,0.05)';x.fillRect(0,y,w,2);
    // overlays
    x.fillStyle='#cfe0ee';x.font='11px monospace';x.fillText(cv.dataset.name,8,16);x.fillText(t,8,h-8);
  }
}
setInterval(draw,120);draw();
</script></body></html>`;
}

function renderCameraFeedOld(sessionId: string, action: string, recorder: string, rtspUrl: string, retentionDays: string) {
  const offline = action === "camera_offline";
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>CamWatch Live Feed</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #091017;
      --panel: #0f1a25;
      --line: #274155;
      --muted: #8aa3b8;
      --accent: #7fe6c2;
      --warn: #efb85d;
      --danger: #db6a6a;
    }
    body {
      margin: 0;
      background:
        radial-gradient(circle at top right, rgba(127,230,194,0.10), transparent 25%),
        linear-gradient(180deg, #081018, var(--bg));
      font-family: "IBM Plex Sans", sans-serif;
      color: #dfe8f0;
    }
    .layout {
      display: grid;
      gap: 18px;
      grid-template-columns: minmax(0, 1fr);
      padding: 18px;
    }
    .bar, .panel {
      border: 1px solid var(--line);
      background: rgba(15,26,37,0.92);
    }
    .bar {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      padding: 12px 16px;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      font-size: 0.82rem;
    }
    .grid {
      display: grid;
      gap: 18px;
      grid-template-columns: minmax(0, 1fr);
    }
    @media (min-width: 980px) {
      .grid {
        grid-template-columns: 2.2fr 1fr;
      }
    }
    .feed {
      position: relative;
      min-height: 420px;
      overflow: hidden;
    }
    .feed::before {
      content: "";
      position: absolute;
      inset: 0;
      background:
        linear-gradient(180deg, transparent, rgba(0,0,0,0.35)),
        repeating-linear-gradient(180deg, rgba(255,255,255,0.05), rgba(255,255,255,0.05) 1px, transparent 1px, transparent 4px),
        radial-gradient(circle at 20% 22%, rgba(255,255,255,0.08), transparent 14%),
        linear-gradient(135deg, #1c2835, #0e151d 45%, #162430);
      opacity: ${offline ? "0.4" : "1"};
    }
    .feed-overlay {
      position: relative;
      z-index: 1;
      padding: 20px;
      display: flex;
      height: 100%;
      flex-direction: column;
      justify-content: space-between;
    }
    .badge {
      display: inline-flex;
      gap: 8px;
      align-items: center;
      padding: 6px 10px;
      background: rgba(9,16,23,0.7);
      border: 1px solid var(--line);
    }
    .side {
      padding: 16px;
    }
    .metric {
      padding: 14px 0;
      border-bottom: 1px solid rgba(138,163,184,0.16);
    }
    .metric:last-child {
      border-bottom: 0;
    }
    .label {
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }
    .value {
      margin-top: 6px;
      font-size: 1.05rem;
    }
    .status {
      color: ${offline ? "var(--danger)" : "var(--accent)"};
    }
    .warn {
      color: var(--warn);
    }
  </style>
</head>
<body>
  <div class="layout">
    <div class="bar">
      <div>CamWatch Stream Relay</div>
      <div>Session ${sessionId}</div>
    </div>
    <div class="grid">
      <section class="panel feed">
        <div class="feed-overlay">
          <div class="badge">${offline ? "Signal lost" : "Live"} / Camera ${recorder}</div>
          <div class="badge" id="timestamp">${new Date().toISOString()}</div>
        </div>
      </section>
      <aside class="panel side">
        <div class="metric">
          <div class="label">Feed Status</div>
          <div class="value status">${offline ? "Offline - Relay timeout" : "Streaming - 1080p substream"}</div>
        </div>
        <div class="metric">
          <div class="label">Recorder</div>
          <div class="value">${recorder}</div>
        </div>
        <div class="metric">
          <div class="label">Retention</div>
          <div class="value warn">${retentionDays} days / motion-tagged only</div>
        </div>
        <div class="metric">
          <div class="label">Operator Hint</div>
          <div class="value">Try /camera/api/frame, /camera/archive?id=cam04, or ${rtspUrl}</div>
        </div>
      </aside>
    </div>
  </div>
  <script>
    setInterval(() => {
      const stamp = document.getElementById("timestamp");
      if (stamp) {
        stamp.textContent = new Date().toISOString();
      }
    }, 1000);
  </script>
</body>
</html>`;
}

async function applyAction(action: string, context: Awaited<ReturnType<typeof resolveAttackerService>>, details: string) {
  if (action === "stall") {
    await new Promise((resolve) => setTimeout(resolve, 2500));
  }

  return applyHttpAction(action, context, details);
}

export async function startHttpService() {
  await fs.mkdir(uploadsDir, { recursive: true });

  const app = express();
  app.set("trust proxy", true);
  // Strip framework fingerprints: nginx never advertises Express.
  app.disable("x-powered-by");
  app.disable("etag");

  const serverToken = serverTokenFromBanner(getServiceProfile("http").banner);

  // Operator-issued block: drop the connection with no response (like nginx 444).
  app.use((req, res, next) => {
    if (isIpBlockedSync(getClientIp(req))) {
      req.socket.destroy();
      return;
    }
    next();
  });

  // Present as the persona's web server on every response (incl. errors), and
  // add small randomized latency so timing looks like a real upstream.
  app.use(async (req, res, next) => {
    res.setHeader("Server", serverToken);
    await jitter();
    next();
  });

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const upload = multer({ dest: uploadsDir });

  app.use(
    rateLimit({
      windowMs: 60_000,
      max: 100,
      // nginx never emits X-RateLimit-*/RateLimit-* headers — suppress the
      // express-rate-limit signature that gives away the framework.
      standardHeaders: false,
      legacyHeaders: false,
      keyGenerator: (req) => getClientIp(req),
      // Mirror nginx's limit_req 503, not a plaintext Express-style message.
      handler: async (req, res) => {
        const ip = getClientIp(req);
        await logWarning("HTTP", ip, "Rate limit exceeded");
        res.status(503).type("html").send(nginxErrorPage(503, serverToken));
      },
    })
  );

  app.get("/healthz", async (req, res) => {
    const context = await resolveAttackerService(getClientIp(req), "http");
    res.json(buildHttpHealth(context));
  });

  app.get("/camera", async (_req, res) => {
    res.redirect("/camera/login");
  });

  app.get("/camera/login", async (req, res) => {
    const context = await resolveAttackerService(getClientIp(req), "http");
    res.type("html").send(renderCameraLogin(buildRtspUrl(context)));
  });

  app.post("/camera/login", async (req, res) => {
    const ip = getClientIp(req);
    const context = await resolveAttackerService(ip, "http");
    const sessionId = crypto.randomUUID();
    const username = String(req.body?.username || "unknown");
    const password = String(req.body?.password || "unknown");
    const site = String(req.body?.site || "unspecified");
    const action = await getActionForSession(sessionId);

    await recordInteractionEvent({
      sessionId,
      service: "CAMERA",
      ip,
      detail: `camera login username=${username} site=${site}`,
      currentAction: action,
      metadata: { username, password_length: password.length, site },
      request: `POST /camera/login username=${username} site=${site}`,
      response: buildCameraMessage(context, action),
      patch: {
        usernames: [username],
      },
    });

    setSessionCookie(res, sessionId);

    if (action === "camera_offline") {
      res.status(200).type("html").send(renderCameraLogin(buildRtspUrl(context), buildCameraMessage(context, action), site));
      return;
    }

    res.redirect(`/camera/live?sid=${sessionId}`);
  });

  app.get("/camera/live", async (req, res) => {
    const ip = getClientIp(req);
    const sessionId = String(req.query.sid || getSessionId(req) || crypto.randomUUID());
    const action = await getActionForSession(sessionId);
    const context = await resolveAttackerService(ip, "http");

    await recordInteractionEvent({
      sessionId,
      service: "CAMERA",
      ip,
      detail: "opened camera live feed",
      currentAction: action,
    });

    const recorder = context.serviceMemory.host.split(".")[0].toUpperCase();
    const retention = String(context.serviceMemory.deviceState.retention_days || 14);
    res.type("html").send(renderCameraFeed(sessionId, action, recorder, buildRtspUrl(context), retention));
  });

  app.get("/camera/api/frame", async (req, res) => {
    const ip = getClientIp(req);
    const sessionId = getSessionId(req) || String(req.query.sid || crypto.randomUUID());
    const action = await getActionForSession(sessionId);
    const context = await resolveAttackerService(ip, "http");

    await recordInteractionEvent({
      sessionId,
      service: "CAMERA",
      ip,
      detail: "requested camera frame metadata",
      currentAction: action,
      response: JSON.stringify(buildCameraFrame(context, sessionId)),
    });

    if (action === "camera_offline") {
      res.status(504).json({ status: "offline", message: "camera relay timed out" });
      return;
    }

    res.json(buildCameraFrame(context, sessionId));
  });

  app.get("/camera/archive", async (req, res) => {
    const ip = getClientIp(req);
    const context = await resolveAttackerService(ip, "http");
    const archiveId = String(req.query.id || "cam04");
    const sessionId = getSessionId(req) || crypto.randomUUID();
    const payload = buildCameraArchive(context, archiveId);

    await recordInteractionEvent({
      sessionId,
      service: "CAMERA",
      ip,
      detail: `requested archive ${archiveId}`,
      response: JSON.stringify(payload),
    });

    res.json(payload);
  });

  app.post("/upload", upload.single("file"), async (req: Request, res: Response) => {
    const ip = getClientIp(req);
    const sessionId = getSessionId(req) || crypto.randomUUID();
    const context = await resolveAttackerService(ip, "http");
    const originalName = req.file?.originalname || "unknown.bin";
    const uploadedRecord = {
      path: `/${originalName}`,
      contents: `uploaded artifact ${originalName} received by ${context.serviceMemory.host}`,
      modifiedAt: new Date().toISOString(),
    };

    await recordInteractionEvent({
      sessionId,
      service: "HTTP",
      ip,
      detail: `uploaded file ${originalName}`,
      request: `POST /upload ${originalName}`,
      response: `stored ${originalName}`,
      patch: {
        files: [...context.serviceMemory.files, uploadedRecord],
      },
    });

    res.json({ status: "ok", message: `File "${originalName}" saved.` });
  });

  app.get("/files", async (req: Request, res: Response) => {
    const ip = getClientIp(req);
    const sessionId = getSessionId(req) || crypto.randomUUID();
    const context = await resolveAttackerService(ip, "http");
    const files = listHttpFiles(context);

    await recordInteractionEvent({
      sessionId,
      service: "HTTP",
      ip,
      detail: "requested file listing",
      response: JSON.stringify(files),
    });

    res.json({ status: "ok", files });
  });

  app.get("/files/:filename", async (req: Request, res: Response) => {
    const ip = getClientIp(req);
    const sessionId = getSessionId(req) || crypto.randomUUID();
    const { filename } = req.params;
    const context = await resolveAttackerService(ip, "http");
    const file = findHttpFile(context, filename);

    await recordInteractionEvent({
      sessionId,
      service: "HTTP",
      ip,
      detail: `requested file content ${filename}`,
      response: file?.contents || "not-found",
    });

    if (file) {
      res.type("text/plain").send(file.contents);
      return;
    }

    res.status(404).json({ error: "File not found" });
  });

  app.post("/shell", async (req: Request, res: Response) => {
    const ip = getClientIp(req);
    const sessionId = getSessionId(req) || crypto.randomUUID();
    const cmd = String(req.body?.cmd || "unknown");
    const action = await getActionForSession(sessionId);
    const context = await resolveAttackerService(ip, "http");
    const actionResult = await applyAction(action, context, `CMD ${cmd}`);
    if (actionResult) {
      await recordInteractionEvent({
        sessionId,
        service: "HTTP-SHELL",
        ip,
        detail: `shell command=${cmd}`,
        currentAction: action,
        request: cmd,
        response: actionResult.body,
        patch: {
          command: cmd,
        },
      });
      res.status(actionResult.status).send(actionResult.body);
      return;
    }

    const output = buildHttpShellOutput(cmd, context);
    await recordInteractionEvent({
      sessionId,
      service: "HTTP-SHELL",
      ip,
      detail: `shell command=${cmd}`,
      currentAction: action,
      request: cmd,
      response: output,
      patch: {
        command: cmd,
      },
    });

    res.json({
      status: "Executed",
      session_id: sessionId,
      action,
      command: cmd,
      output,
      timestamp: new Date().toISOString(),
    });
  });

  app.post("/run", async (req: Request, res: Response) => {
    const ip = getClientIp(req);
    const sessionId = getSessionId(req) || crypto.randomUUID();
    const cmd = String(req.body?.cmd || "unknown");
    const action = await getActionForSession(sessionId);
    const context = await resolveAttackerService(ip, "http");
    const fakeTaskId = crypto.randomUUID();
    const payload = {
      status: action === "stall" ? "Queued" : "Processing",
      task_id: fakeTaskId,
      session_id: sessionId,
      estimated_time_completion: "00:02:30",
      log_url: `https://${context.serviceMemory.host}/api/logs/${fakeTaskId}`,
    };

    await recordInteractionEvent({
      sessionId,
      service: "HTTP",
      ip,
      detail: `task command=${cmd}`,
      currentAction: action,
      request: cmd,
      response: JSON.stringify(payload),
      patch: {
        command: cmd,
      },
    });

    res.json(payload);
  });

  // Fake login panels (admin console, DB web client, IoT gateway). Each GET
  // serves a believable login page; each POST records the submitted username
  // (scored as brute_force) and returns a realistic auth failure unless the
  // operator control action overrides it.
  function registerPanel(panel: PanelDefinition) {
    const serveLogin = async (req: Request, res: Response) => {
      const ip = getClientIp(req);
      const sessionId = getSessionId(req) || crypto.randomUUID();
      const context = await resolveAttackerService(ip, "http");
      setSessionCookie(res, sessionId);

      // DB panel: browsing a table (?select=) — serve fake rows, log the access.
      if (panel.service === "DB-WEB" && typeof req.query.select === "string") {
        const table = String(req.query.select);
        await recordInteractionEvent({
          sessionId, service: "DB-WEB", ip,
          detail: `DB browse table=${table}`,
          currentAction: await getActionForSession(sessionId),
          request: `GET ${req.originalUrl}`,
          response: `table ${table}`,
        });
        res.type("html").send(renderDbTable(context, table));
        return;
      }

      await recordInteractionEvent({
        sessionId,
        service: panel.service,
        ip,
        detail: `requested ${panel.service} panel ${req.path}`,
        currentAction: await getActionForSession(sessionId),
      });
      res.type("html").send(panel.renderLogin(context, { host: context.serviceMemory.host }));
    };

    const handleAuth = async (req: Request, res: Response) => {
      const ip = getClientIp(req);
      const sessionId = getSessionId(req) || crypto.randomUUID();
      const context = await resolveAttackerService(ip, "http");
      const action = await getActionForSession(sessionId);

      // DB panel: SQL execution — capture the query (exploitation) + fake result.
      if (panel.service === "DB-WEB" && typeof req.body?.sql === "string" && req.body.sql.trim()) {
        const sql = String(req.body.sql).slice(0, 1000);
        setSessionCookie(res, sessionId);
        await recordInteractionEvent({
          sessionId, service: "DB-WEB", ip,
          detail: `DB sql query=${sql.slice(0, 200)}`,
          currentAction: action,
          request: sql,
          response: "executed",
          patch: { command: sql },
        });
        res.type("html").send(renderDbResult(context, sql));
        return;
      }

      const username = String(req.body?.username || req.body?.user || "unknown");
      const password = String(req.body?.password || req.body?.pass || "");

      const metadata: Record<string, unknown> = { password_length: password.length };
      for (const field of panel.fields) {
        if (field === "password") continue;
        if (req.body?.[field] != null) metadata[field] = String(req.body[field]);
      }

      if (action === "stall") {
        await new Promise((resolve) => setTimeout(resolve, 2500));
      }

      const authed = action === "decoy_success";
      await recordInteractionEvent({
        sessionId,
        service: panel.service,
        ip,
        detail: `${panel.service} login username=${username}`,
        currentAction: action,
        metadata,
        request: `POST ${req.path} username=${username}`,
        response: authed ? "authenticated" : "invalid credentials",
        patch: { usernames: [username] },
      });
      setSessionCookie(res, sessionId);

      if (action === "fake_error") {
        res.status(500).type("html").send(panel.renderLogin(context, {
          host: context.serviceMemory.host,
          message: "Service temporarily unavailable. Try again later.",
          username,
        }));
        return;
      }

      if (authed) {
        res.type("html").send(panel.renderDashboard(context, { host: context.serviceMemory.host, username }));
        return;
      }

      res.status(401).type("html").send(panel.renderLogin(context, {
        host: context.serviceMemory.host,
        message: "Invalid credentials.",
        username,
      }));
    };

    for (const route of panel.paths) {
      app.get(route, serveLogin);
      app.post(route, handleAuth);
    }
  }

  for (const panel of PANELS) {
    registerPanel(panel);
  }

  app.all("*", async (req: Request, res: Response) => {
    const ip = getClientIp(req);
    const sessionId = getSessionId(req) || crypto.randomUUID();
    const action = await getActionForSession(sessionId);
    const context = await resolveAttackerService(ip, "http");
    const details = `Method: ${req.method}, Path: ${req.originalUrl}, UA: ${req.headers["user-agent"] || "none"}`;
    const actionResult = await applyAction(action, context, details);

    if (actionResult) {
      await recordInteractionEvent({
        sessionId,
        service: "HTTP",
        ip,
        detail: details,
        currentAction: action,
        metadata: { userAgent: String(req.headers["user-agent"] || "none") },
        request: `${req.method} ${req.originalUrl}`,
        response: actionResult.body,
      });
      res.status(actionResult.status).send(actionResult.body);
      return;
    }

    try {
      // Unknown paths behave like a real nginx vhost: a 404, not a chatty relay
      // banner that leaks internal hostnames and screams "honeypot". The
      // interaction is still recorded so scanning is captured.
      const body = nginxErrorPage(404, serverToken);
      await recordInteractionEvent({
        sessionId,
        service: "HTTP",
        ip,
        detail: details,
        currentAction: action,
        metadata: { userAgent: String(req.headers["user-agent"] || "none") },
        request: `${req.method} ${req.originalUrl}`,
        response: "404",
      });
      res.status(404).type("html").send(body);
    } catch (error) {
      await logError("HTTP", ip, "Responder error in catch-all", { error: String(error) });
      res.status(500).type("html").send(nginxErrorPage(500, serverToken));
    }
  });

  const server = await new Promise<Server>((resolve, reject) => {
    const instance = app.listen(config.services.http.port, config.services.http.host, () => resolve(instance));
    instance.once("error", reject);
  });

  return {
    name: "http",
    server,
    port: config.services.http.port,
    host: config.services.http.host,
  };
}
