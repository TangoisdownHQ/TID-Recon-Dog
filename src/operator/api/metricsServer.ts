import crypto from "crypto";
import { spawn } from "child_process";
import express, { NextFunction, Request, Response } from "express";
import fs from "fs";
import fsp from "fs/promises";
import path from "path";
import { fileURLToPath } from "url";
import { Server } from "http";
import { config } from "../../config/config.js";
import { formatConsole } from "../../utils/logger.js";
import { ASCII_LOGO } from "../../utils/logo.js";
import { listAttackers, getAttackerById, summarizeAttacker } from "../../deception_engine/state/attacker_memory.js";
import { listCanaries } from "../../deception_engine/canary/canaryTokens.js";
import { readSessionSnapshots } from "../../utils/logger.js";
import { readTranscripts } from "../../deception_engine/logging/transcript_store.js";
import { readAlerts } from "../alertHook.js";
import { readShadow } from "../../deception_engine/logging/shadow_store.js";
import { isAiConfigured } from "../../responders/aiEngine.js";
import { buildIocs, buildAttackMatrix, buildActors, buildCampaigns, buildNovelty } from "../../cti/iocEngine.js";
import { readPlaybooks, writePlaybooks, Playbook } from "../playbooks.js";
import { listNodes, reportNode, selfReport, listFleetFeed, reportFeed, reportDetail, fleetOverview, fleetTimeline, fleetAttackers, fleetSessions, reportCanary, fleetCanaries, FleetNode, FleetDetail, NodeCanaryReport } from "../fleet.js";
import { buildStixBundle, buildMispEvent, buildBlocklist } from "../../cti/export.js";
import { enrichmentProviders } from "../../cti/enrich.js";
import { forwardingTargets } from "../../cti/forward.js";
import { feedUrls, ingestFeeds, autoBlockEnabled } from "../../cti/feeds.js";
import { buildCredentials } from "../credentials.js";
import { readPayloads } from "../payloadStore.js";
import { refreshDarkweb, readDarkwebHits, darkwebConfigured, buildDarkwebFeed } from "../../cti/darkweb.js";
import {
  isValidAction,
  isValidMode,
  readControlState,
  setDefaultAction,
  setSessionAction,
  setEngineMode,
  blockIp,
  unblockIp,
  queueMessage,
} from "../controlPlane.js";
import {
  buildOverview,
  buildTimeline,
  buildFeed,
  buildPrometheus,
} from "./metrics.js";

const moduleDir = path.dirname(fileURLToPath(import.meta.url));

/**
 * Locate the static web assets. After `tsc` they are copied to
 * dist/operator/web; in source/dev they live in src/operator/web.
 */
function resolveWebDir(): string {
  const candidates = [
    path.join(moduleDir, "..", "web"),
    path.resolve("dist", "operator", "web"),
    path.resolve("src", "operator", "web"),
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "index.html"))) return dir;
  }
  return candidates[0];
}

/** Constant-time bearer-token comparison. */
function tokenMatches(provided: string, expected: string): boolean {
  if (!provided || provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
}

export type OperatorServerHandle = {
  name: string;
  server: Server;
  host: string;
  port: number;
  token: string;
};

export async function startOperatorServer(): Promise<OperatorServerHandle> {
  const token = config.operator.token || crypto.randomBytes(24).toString("hex");
  const generated = !config.operator.token;

  const app = express();
  app.disable("x-powered-by");
  // 8mb, not the 100kb default: a busy node's fleet-detail snapshot (up to 200
  // attackers + 200 sessions + overview/timeline/feed) can exceed 100kb, and a
  // 413 there silently drops that node from the fleet-wide view.
  app.use(express.json({ limit: "8mb" }));

  const webDir = resolveWebDir();

  const cookieAttrs = "HttpOnly; Path=/; SameSite=Strict";

  // Exchange a token for the auth cookie WITHOUT putting it in the URL. Preferred
  // over ?token= (which leaks into browser history and proxy/access logs). This
  // route is intentionally reachable pre-auth; it validates the token itself.
  app.post("/api/login", express.json(), (req: Request, res: Response) => {
    const provided = typeof req.body?.token === "string" ? req.body.token : "";
    if (!tokenMatches(provided, token)) {
      res.status(401).json({ error: "invalid token" });
      return;
    }
    res.setHeader("Set-Cookie", `tid_op=${encodeURIComponent(provided)}; ${cookieAttrs}`);
    res.json({ status: "ok" });
  });

  const auth = (req: Request, res: Response, next: NextFunction) => {
    // Health/readiness probes and the login exchange are unauthenticated.
    if (req.path === "/healthz" || req.path === "/readyz" || req.path === "/api/login") return next();

    const header = req.headers.authorization || "";
    const bearer = header.startsWith("Bearer ") ? header.slice(7) : "";
    const queryToken = typeof req.query.token === "string" ? req.query.token : "";
    const cookieToken = decodeURIComponent((req.headers.cookie || "").match(/tid_op=([^;]+)/)?.[1] || "");
    const provided = bearer || queryToken || cookieToken;

    if (tokenMatches(provided, token)) {
      // Persist the token as a cookie so GUI XHRs authenticate automatically.
      if (queryToken) {
        res.setHeader("Set-Cookie", `tid_op=${encodeURIComponent(queryToken)}; ${cookieAttrs}`);
      }
      return next();
    }

    if (req.path.startsWith("/api/")) {
      res.status(401).json({ error: "unauthorized" });
      return;
    }
    // Login form: token is pasted into a field and POSTed to /api/login, so it
    // never appears in the URL. On success the cookie is set and we reload.
    res.status(401).type("html").send(
      `<!doctype html><meta charset=utf-8><title>TID Operator</title>` +
        `<body style="font-family:monospace;background:#0d0d0f;color:#d6cfcf;display:flex;min-height:90vh;align-items:center;justify-content:center">` +
        `<form id=f style="border:1px solid #3a2a2e;background:#141416;padding:28px;min-width:320px">` +
        `<h2 style="margin:0 0 4px">TID-RECON-DOG</h2>` +
        `<div style="color:#8a8080;font-size:12px;margin-bottom:16px">// OPERATOR CONSOLE — LOCKED</div>` +
        `<input id=t type=password placeholder="operator token" autofocus autocomplete=off ` +
        `style="width:100%;box-sizing:border-box;padding:9px;background:#0d0d0f;border:1px solid #3a2a2e;color:#d6cfcf;font-family:monospace">` +
        `<button style="margin-top:12px;width:100%;padding:9px;background:#6e1622;border:1px solid #b13049;color:#fff;font-family:monospace;cursor:pointer">Unlock</button>` +
        `<div id=e style="color:#c2495b;font-size:12px;margin-top:10px;min-height:14px"></div></form>` +
        `<script>document.getElementById('f').onsubmit=async(ev)=>{ev.preventDefault();` +
        `const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},` +
        `body:JSON.stringify({token:document.getElementById('t').value})});` +
        `if(r.ok){location.href='/';}else{document.getElementById('e').textContent='Invalid token.';}};</script>` +
        `</body>`
    );
  };

  app.use(auth);

  app.get("/healthz", (_req, res) => res.json({ status: "ok" }));
  app.get("/readyz", (_req, res) => res.json({ status: "ready" }));

  app.get("/api/logo", (_req, res) => res.type("text/plain").send(ASCII_LOGO));

  app.get("/api/overview", async (_req, res) => {
    res.json(await buildOverview());
  });

  app.get("/api/timeline", async (req, res) => {
    const hours = Math.min(168, Math.max(1, Number(req.query.hours) || 24));
    res.json(await buildTimeline(hours));
  });

  app.get("/api/feed", async (req, res) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 50));
    res.json(await buildFeed(limit));
  });

  app.get("/api/attackers", async (req, res) => {
    // scope=fleet delegates to the aggregated fleet view so this endpoint can't
    // silently return master-only data when a caller asks for the whole fleet.
    if (req.query.scope === "fleet") {
      res.json(await fleetAttackers());
      return;
    }
    const attackers = await listAttackers();
    res.json(
      attackers
        .map((a) => ({
          id: a.id,
          sourceIp: a.sourceIp,
          risk: a.risk,
          intent: a.intent,
          totalScore: a.totalScore,
          country: a.geo?.countryCode || "??",
          isp: a.geo?.isp || "",
          services: Object.keys(a.services),
          firstSeenAt: a.firstSeenAt,
          lastSeenAt: a.lastSeenAt,
          connections: a.counters.connections,
          authAttempts: a.counters.authAttempts,
          commands: a.counters.commands,
          uploads: a.counters.uploads,
          summary: summarizeAttacker(a).headline,
        }))
        .sort((a, b) => b.totalScore - a.totalScore)
    );
  });

  app.get("/api/attackers/:id", async (req, res) => {
    const attacker =
      (await getAttackerById(req.params.id)) ||
      (await listAttackers()).find((a) => a.id.startsWith(req.params.id));
    if (!attacker) {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.json({ ...attacker, activity: summarizeAttacker(attacker) });
  });

  app.get("/api/sessions", async (_req, res) => {
    res.json(await readSessionSnapshots());
  });

  app.get("/api/transcripts", async (req, res) => {
    const limit = Math.min(1000, Math.max(1, Number(req.query.limit) || 200));
    const all = await readTranscripts();
    res.json(all.slice(-limit).reverse());
  });

  app.get("/api/credentials", async (_req, res) => {
    res.json(await buildCredentials(150));
  });

  app.get("/api/payloads", async (req, res) => {
    const limit = Math.min(1000, Math.max(1, Number(req.query.limit) || 300));
    res.json(await readPayloads(limit));
  });

  app.get("/api/alerts", async (_req, res) => {
    res.json((await readAlerts()).reverse());
  });

  app.get("/api/canaries", async (_req, res) => {
    res.json(await listCanaries());
  });

  app.get("/api/control", async (_req, res) => {
    res.json(await readControlState());
  });

  app.post("/api/control", async (req, res) => {
    const { scope, sessionId, action, mode, ip } = req.body || {};

    if (scope === "mode") {
      if (!isValidMode(String(mode))) {
        res.status(400).json({ error: "invalid mode" });
        return;
      }
      await setEngineMode(mode);
      res.json(await readControlState());
      return;
    }

    if (scope === "block" || scope === "unblock") {
      const target = String(ip || "").trim();
      if (!target) {
        res.status(400).json({ error: "missing ip" });
        return;
      }
      if (scope === "block") await blockIp(target);
      else await unblockIp(target);
      res.json(await readControlState());
      return;
    }

    if (!isValidAction(String(action))) {
      res.status(400).json({ error: "invalid action" });
      return;
    }
    if (scope === "default") {
      await setDefaultAction(action);
    } else if (scope === "session" && sessionId) {
      await setSessionAction(String(sessionId), action);
    } else {
      res.status(400).json({ error: "invalid scope" });
      return;
    }
    res.json(await readControlState());
  });

  // --- MLOps: on-demand retrain (local host only) + status ----------------
  // The retrain runs the host pipeline (GPU/venv live on the host), so this is
  // a no-op in a containerized pod — there, retrain runs as the k8s CronJob and
  // on-demand is `kubectl create job --from=cronjob/tidrc-retrain`.
  const retrainScript = path.resolve("mlops/tidrc-ml-pipeline/scripts/auto_retrain.sh");
  const retrainStatusFile = path.resolve("runtime/retrain_status.json");
  let retrainRunning = false;

  app.get("/api/retrain/status", async (_req, res) => {
    try {
      const raw = await fsp.readFile(retrainStatusFile, "utf8");
      res.json({ running: retrainRunning, ...JSON.parse(raw) });
    } catch {
      res.json({ running: retrainRunning, state: "idle", message: "no retrain has run yet" });
    }
  });

  app.post("/api/retrain", async (req, res) => {
    if (!fs.existsSync(retrainScript)) {
      res.status(501).json({ error: "retrain pipeline not present on this host" });
      return;
    }
    if (retrainRunning) {
      res.status(409).json({ error: "retrain already running" });
      return;
    }
    const env = { ...process.env };
    if (req.body?.force) env.RETRAIN_FORCE = "1";
    if (req.body?.exportOnly) env.RETRAIN_BACKEND = "none";

    retrainRunning = true;
    const child = spawn("bash", [retrainScript], { env, detached: true, stdio: "ignore" });
    child.on("exit", () => { retrainRunning = false; });
    child.on("error", () => { retrainRunning = false; });
    child.unref();
    res.status(202).json({ status: "started" });
  });

  app.get("/api/ai/status", (_req, res) => {
    res.json({ configured: isAiConfigured(), model: config.ai.model, url: config.ai.url ? "set" : "" });
  });

  app.get("/api/shadow", async (req, res) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 100));
    res.json(await readShadow(limit));
  });

  // --- CTI: intel views, standard exports, TAXII-style feed, feed ingest ----
  app.get("/api/cti/iocs", async (_req, res) => res.json(await buildIocs()));
  app.get("/api/cti/attack", async (_req, res) => res.json(await buildAttackMatrix()));
  app.get("/api/cti/actors", async (_req, res) => res.json(await buildActors()));
  app.get("/api/cti/campaigns", async (_req, res) => res.json(await buildCampaigns()));
  app.get("/api/cti/novelty", async (req, res) => {
    const hours = Math.min(168, Math.max(1, Number(req.query.hours) || 24));
    res.json(await buildNovelty(hours));
  });

  // Auto-response playbooks
  app.get("/api/playbooks", async (_req, res) => res.json(await readPlaybooks()));
  app.post("/api/playbooks", async (req, res) => {
    if (!Array.isArray(req.body)) {
      res.status(400).json({ error: "expected an array of playbooks" });
      return;
    }
    await writePlaybooks(req.body as Playbook[]);
    res.json(await readPlaybooks());
  });

  // Session replay — ordered transcript steps for one session.
  app.get("/api/replay/:sessionId", async (req, res) => {
    const all = await readTranscripts();
    const steps = all
      .filter((t) => t.sessionId === req.params.sessionId)
      .sort((a, b) => a.at.localeCompare(b.at))
      .map((t) => ({ at: t.at, service: t.service, request: t.request, response: t.response, intent: t.intent, score: t.score, action: t.action }));
    res.json(steps);
  });
  app.get("/api/cti/connectors", (_req, res) =>
    res.json({ enrichment: enrichmentProviders(), forwarding: forwardingTargets(), feeds: feedUrls().length })
  );
  app.get("/api/cti/stix", async (_req, res) => {
    res.setHeader("Content-Disposition", "attachment; filename=tid-stix-bundle.json");
    res.json(await buildStixBundle());
  });
  app.get("/api/cti/misp", async (_req, res) => {
    res.setHeader("Content-Disposition", "attachment; filename=tid-misp-event.json");
    res.json(await buildMispEvent());
  });
  app.get("/api/cti/blocklist.txt", async (_req, res) => res.type("text/plain").send((await buildBlocklist()).txt));
  app.get("/api/cti/blocklist.csv", async (_req, res) => res.type("text/csv").send((await buildBlocklist()).csv));
  app.post("/api/cti/ingest-feeds", async (_req, res) => res.json(await ingestFeeds()));
  app.get("/api/cti/darkweb", async (_req, res) => res.json({ configured: darkwebConfigured(), hits: await readDarkwebHits(100) }));
  app.get("/api/cti/darkweb-feed", async (req, res) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 150));
    res.json({ configured: darkwebConfigured(), items: await buildDarkwebFeed(limit) });
  });
  app.post("/api/cti/darkweb/refresh", async (_req, res) => res.json(await refreshDarkweb()));

  // Minimal TAXII 2.1-style discovery + objects (lets a TAXII client pull intel).
  app.get("/taxii2", (_req, res) =>
    res.json({ title: "TID-Recon-Dog TAXII", api_roots: ["/taxii2/cti/"] })
  );
  app.get("/taxii2/cti", (_req, res) =>
    res.json({ title: "CTI", versions: ["application/taxii+json;version=2.1"], collections: "/taxii2/cti/collections/" })
  );
  app.get("/taxii2/cti/collections", (_req, res) =>
    res.json({ collections: [{ id: "honeypot", title: "Honeypot observations", can_read: true, can_write: false }] })
  );
  app.get("/taxii2/cti/collections/honeypot/objects", async (_req, res) => {
    const bundle = (await buildStixBundle()) as { objects: object[] };
    res.json({ objects: bundle.objects });
  });

  // Inject an operator message into a live session (by session id or source IP).
  app.post("/api/inject", (req, res) => {
    const target = String(req.body?.target || "").trim();
    const message = String(req.body?.message || "");
    if (!target || !message) {
      res.status(400).json({ error: "target and message required" });
      return;
    }
    queueMessage(target, message);
    res.json({ status: "queued", target });
  });

  // Fleet: nodes report summaries here; the GUI lists all nodes.
  app.get("/api/fleet", async (_req, res) => res.json(await listNodes()));
  app.post("/api/fleet/report", async (req, res) => {
    const n = req.body as FleetNode;
    if (!n || !n.nodeId) {
      res.status(400).json({ error: "invalid node report" });
      return;
    }
    await reportNode(n);
    res.json({ status: "ok" });
  });

  // Fleet-wide live feed: nodes push recent activity; the GUI merges all nodes.
  app.get("/api/fleet/feed", async (req, res) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 120));
    res.json(await listFleetFeed(limit));
  });
  app.post("/api/fleet/feed", async (req, res) => {
    const node = String(req.body?.node || "").trim();
    const items = Array.isArray(req.body?.items) ? req.body.items : null;
    if (!node || !items) {
      res.status(400).json({ error: "node and items required" });
      return;
    }
    await reportFeed(node, items);
    res.json({ status: "ok" });
  });

  // Fleet-wide detail: nodes push overview/timeline/attackers/sessions; the
  // master merges so the dashboard + Attackers/Sessions tabs can show all nodes.
  app.post("/api/fleet/detail", async (req, res) => {
    const d = req.body as FleetDetail;
    if (!d || !d.node || !d.overview) {
      res.status(400).json({ error: "invalid detail report" });
      return;
    }
    await reportDetail(d);
    res.json({ status: "ok" });
  });
  app.get("/api/fleet/overview", async (_req, res) => res.json(await fleetOverview()));
  app.get("/api/fleet/timeline", async (req, res) => {
    const hours = Math.min(168, Math.max(1, Number(req.query.hours) || 24));
    res.json(await fleetTimeline(hours));
  });
  app.get("/api/fleet/attackers", async (_req, res) => res.json(await fleetAttackers()));
  app.get("/api/fleet/sessions", async (_req, res) => res.json(await fleetSessions()));
  app.post("/api/fleet/canary", async (req, res) => {
    const c = req.body as NodeCanaryReport;
    if (!c || !c.node) {
      res.status(400).json({ error: "invalid canary report" });
      return;
    }
    await reportCanary(c);
    res.json({ status: "ok" });
  });
  app.get("/api/fleet/canaries", async (_req, res) => res.json(await fleetCanaries()));

  app.get("/metrics", async (_req, res) => {
    res.type("text/plain").send(await buildPrometheus());
  });

  app.use(express.static(webDir, { index: "index.html" }));

  // Malformed percent-encoded paths throw URIError during route matching;
  // answer 400 instead of leaving it unhandled.
  app.use((err: Error, _req: express.Request, res: express.Response, next: (e?: unknown) => void) => {
    if (err instanceof URIError) {
      res.status(400).json({ error: "bad request" });
      return;
    }
    next(err);
  });

  const server = await new Promise<Server>((resolve, reject) => {
    const instance = app.listen(config.operator.port, config.operator.host, () => resolve(instance));
    instance.once("error", reject);
  });

  // Fleet self-report (to a master if FLEET_MASTER_URL is set, else local) so
  // this node always shows up in the Fleet view.
  void selfReport();
  setInterval(() => void selfReport(), 60_000);

  // Auto-refresh the dark-web news/event + correlation stream so the CTI tab
  // populates without anyone clicking "refresh". Only runs when feeds are
  // configured (DARKWEB_FEEDS / DARKWEB_NEWS_FEEDS); errors are swallowed inside
  // refreshDarkweb so a flaky feed never takes the operator plane down.
  if (darkwebConfigured()) {
    const dwRefresh = Math.max(5, Number(process.env.DARKWEB_REFRESH_MINUTES) || 30) * 60_000;
    setTimeout(() => void refreshDarkweb(), 15_000); // initial pull shortly after boot
    setInterval(() => void refreshDarkweb(), dwRefresh);
  }
  // Auto-ingest threat-intel blocklists into the auto-block list on the same
  // cadence (defaults to 6h). Opt-in only: requires THREAT_FEEDS_AUTOBLOCK=true.
  // Without it, configuring THREAT_FEEDS does NOT block anyone — operators block
  // explicitly via POST /api/cti/ingest-feeds or the control endpoint.
  if (feedUrls().length && autoBlockEnabled()) {
    const fiRefresh = Math.max(15, Number(process.env.THREAT_FEEDS_MINUTES) || 360) * 60_000;
    setTimeout(() => void ingestFeeds(), 20_000);
    setInterval(() => void ingestFeeds(), fiRefresh);
  }

  if (generated) {
    console.log(
      formatConsole(
        `Operator console token (generated): ${token}\n` +
          `  Open: http://${config.operator.host}:${config.operator.port}/?token=${token}`
      )
    );
  } else {
    console.log(
      formatConsole(
        `Operator console: http://${config.operator.host}:${config.operator.port}/ (OPERATOR_TOKEN set)`
      )
    );
  }

  return {
    name: "operator",
    server,
    host: config.operator.host,
    port: config.operator.port,
    token,
  };
}
