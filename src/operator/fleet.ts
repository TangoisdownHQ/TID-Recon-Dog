// Multi-honeypot fleet: each node reports a compact summary to a central master
// (or to itself when standalone), so one operator console can watch many nodes.
//
//   NODE_ID / NODE_NAME    identify this node (default: hostname)
//   NODE_REGION            free-text location label
//   FLEET_MASTER_URL       if set, POST self-reports here instead of storing local
//   FLEET_TOKEN            bearer token used when posting to the master
import fs from "fs/promises";
import os from "os";
import path from "path";
import { buildOverview, buildFeed, buildTimeline, OverviewMetrics, TimelinePoint } from "./api/metrics.js";
import { getNodeStatus, getNodeNetwork, getNodePorts, getNodeMisc } from "./nodeStatus.js";
import { listAttackers, summarizeAttacker } from "../deception_engine/state/attacker_memory.js";
import { readSessionSnapshots } from "../utils/logger.js";

const filePath = path.resolve("runtime", "fleet.json");
const feedPath = path.resolve("runtime", "fleet-feed.json");
const detailPath = path.resolve("runtime", "fleet-detail.json");

export type FleetNode = {
  nodeId: string;
  name: string;
  region: string;
  attackers: number;
  active15m: number;
  highRisk: number;
  transcripts: number;
  topCountry: string;
  lastSeen: string;
  // Identity / exposure — so the Fleet tab shows where each node is and what it exposes.
  publicIp: string;
  privateIp: string;
  hostname: string;
  ports: string; // comma-separated exposed ports, e.g. "80,554"
  services: string; // e.g. "http rtsp"
  // Restart accounting — so flapping nodes are visible with a reason.
  restarts: number;
  lastStartAt: string;
  lastStartReason: string;
  // Host identity + misc (optional: older nodes may not report these yet).
  instanceId?: string;
  instanceType?: string;
  az?: string;
  os?: string;
  arch?: string;
  appVersion?: string;
  nodeVersion?: string;
  uptimeSec?: number;
  load1?: number;
  memPct?: number;
};

export function nodeId(): string {
  return process.env.NODE_ID || os.hostname();
}

export function nodeName(): string {
  return process.env.NODE_NAME || nodeId();
}

// --- Fleet-wide live feed ----------------------------------------------------
// Each node pushes its recent transcript feed to the master alongside its
// summary; the master keeps a bounded slice per node so the operator console
// can show one merged, fleet-wide activity stream (not just the master's own).
export type FleetFeedItem = {
  node: string;
  at: string;
  service: string;
  sourceIp: string;
  intent: string;
  score: number;
  action: string;
  request: string;
  label: string;
  sessionId: string;
  attackerId: string;
};

const FEED_PER_NODE = 40;

async function readFeedStore(): Promise<Record<string, FleetFeedItem[]>> {
  try {
    return JSON.parse(await fs.readFile(feedPath, "utf8")) as Record<string, FleetFeedItem[]>;
  } catch {
    return {};
  }
}

export async function reportFeed(node: string, items: FleetFeedItem[]): Promise<void> {
  const all = await readFeedStore();
  all[node] = items.slice(0, FEED_PER_NODE);
  await fs.mkdir(path.dirname(feedPath), { recursive: true });
  await fs.writeFile(feedPath, JSON.stringify(all), "utf8");
}

export async function listFleetFeed(limit = 120): Promise<FleetFeedItem[]> {
  const all = await readFeedStore();
  return Object.values(all)
    .flat()
    .sort((a, b) => Date.parse(b.at) - Date.parse(a.at))
    .slice(0, limit);
}

/** This node's recent feed, tagged with the node name, for pushing to master. */
async function buildFeedItems(): Promise<FleetFeedItem[]> {
  const name = nodeName();
  const feed = await buildFeed(FEED_PER_NODE);
  return feed.map((f) => ({ node: name, ...f }));
}

// --- Fleet-wide detail (overview / timeline / attackers / sessions) ----------
// So the main dashboard KPIs+bars and the Attackers/Sessions tabs can show the
// whole fleet, not just the master's own box. Each node pushes a compact detail
// snapshot; the master merges across nodes.
type AttackerRow = Record<string, unknown> & { node?: string };
type SessionRow = Record<string, unknown> & { node?: string };

export type FleetDetail = {
  node: string;
  at: string;
  overview: OverviewMetrics;
  timeline: TimelinePoint[];
  attackers: AttackerRow[];
  sessions: SessionRow[];
};

const ATTACKERS_PER_NODE = 200;
const SESSIONS_PER_NODE = 200;

async function readDetailStore(): Promise<Record<string, FleetDetail>> {
  try {
    return JSON.parse(await fs.readFile(detailPath, "utf8")) as Record<string, FleetDetail>;
  } catch {
    return {};
  }
}

export async function reportDetail(detail: FleetDetail): Promise<void> {
  const all = await readDetailStore();
  all[detail.node] = detail;
  await fs.mkdir(path.dirname(detailPath), { recursive: true });
  await fs.writeFile(detailPath, JSON.stringify(all), "utf8");
}

/** Only merge nodes seen in the last 5 min so a dead node stops inflating totals. */
function liveDetails(all: Record<string, FleetDetail>): FleetDetail[] {
  const now = Date.now();
  return Object.values(all).filter((d) => now - Date.parse(d.at) < 5 * 60_000);
}

function mergeMaps(maps: Array<Record<string, number>>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const m of maps) for (const [k, v] of Object.entries(m || {})) out[k] = (out[k] || 0) + v;
  return out;
}

function topEntries(map: Record<string, number>, limit: number): Array<{ key: string; count: number }> {
  return Object.entries(map).map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count).slice(0, limit);
}

export async function fleetOverview(): Promise<OverviewMetrics> {
  const details = liveDetails(await readDetailStore());
  const os = details.map((d) => d.overview).filter(Boolean);
  if (os.length === 0) return buildOverview(); // standalone / nothing reported yet
  const sum = (pick: (o: OverviewMetrics) => number) => os.reduce((s, o) => s + (pick(o) || 0), 0);
  const base = os[0];
  return {
    ...base,
    generatedAt: new Date().toISOString(),
    attackers: {
      total: sum((o) => o.attackers.total),
      active15m: sum((o) => o.attackers.active15m),
      byRisk: mergeMaps(os.map((o) => o.attackers.byRisk)),
      byIntent: mergeMaps(os.map((o) => o.attackers.byIntent)),
      byCountry: topEntries(mergeMaps(os.map((o) => Object.fromEntries((o.attackers.byCountry || []).map((c) => [c.key, c.count])))), 12),
      totalScore: sum((o) => o.attackers.totalScore),
    },
    sessions: {
      total: sum((o) => o.sessions.total),
      active: sum((o) => o.sessions.active),
      byService: mergeMaps(os.map((o) => o.sessions.byService)),
      byStatus: mergeMaps(os.map((o) => o.sessions.byStatus)),
    },
    transcripts: {
      total: sum((o) => o.transcripts.total),
      byService: mergeMaps(os.map((o) => o.transcripts.byService)),
      byIntent: mergeMaps(os.map((o) => o.transcripts.byIntent)),
    },
    logs: { total: sum((o) => o.logs.total), byLevel: mergeMaps(os.map((o) => o.logs.byLevel)) },
    alerts: { total: sum((o) => o.alerts.total), high: sum((o) => o.alerts.high) },
  };
}

export async function fleetTimeline(hours = 24): Promise<TimelinePoint[]> {
  const details = liveDetails(await readDetailStore());
  // Merge per-node hourly buckets keyed to the hour, so slightly-offset bucket
  // boundaries still line up.
  const byHour = new Map<string, TimelinePoint>();
  for (const d of details) {
    for (const p of d.timeline || []) {
      const hourKey = p.bucket.slice(0, 13);
      const cur = byHour.get(hourKey) || { bucket: p.bucket, count: 0, exploitation: 0 };
      cur.count += p.count;
      cur.exploitation += p.exploitation;
      byHour.set(hourKey, cur);
    }
  }
  return [...byHour.values()].sort((a, b) => Date.parse(a.bucket) - Date.parse(b.bucket)).slice(-hours);
}

export async function fleetAttackers(): Promise<AttackerRow[]> {
  const details = liveDetails(await readDetailStore());
  return details
    .flatMap((d) => d.attackers || [])
    .sort((a, b) => Number(b.totalScore || 0) - Number(a.totalScore || 0));
}

export async function fleetSessions(): Promise<SessionRow[]> {
  const details = liveDetails(await readDetailStore());
  return details
    .flatMap((d) => d.sessions || [])
    .sort((a, b) => Date.parse(String(b.lastSeenAt || 0)) - Date.parse(String(a.lastSeenAt || 0)));
}

/** Build this node's compact detail snapshot, tagged with the node name. */
async function buildDetail(): Promise<FleetDetail> {
  const name = nodeName();
  const [overview, timeline, attackers, sessions] = await Promise.all([
    buildOverview(),
    buildTimeline(24),
    listAttackers(),
    readSessionSnapshots(),
  ]);
  const attackerRows: AttackerRow[] = attackers
    .map((a) => ({
      node: name,
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
    .sort((a, b) => (b.totalScore || 0) - (a.totalScore || 0))
    .slice(0, ATTACKERS_PER_NODE);
  const sessionRows: SessionRow[] = readSessionTail(sessions, SESSIONS_PER_NODE, name);
  return { node: name, at: new Date().toISOString(), overview, timeline, attackers: attackerRows, sessions: sessionRows };
}

function readSessionTail(sessions: Array<Record<string, unknown>>, limit: number, name: string): SessionRow[] {
  return sessions.slice(-limit).map((s) => ({ ...s, node: name }));
}

async function readAll(): Promise<Record<string, FleetNode>> {
  try {
    return JSON.parse(await fs.readFile(filePath, "utf8")) as Record<string, FleetNode>;
  } catch {
    return {};
  }
}

export async function reportNode(node: FleetNode): Promise<void> {
  const all = await readAll();
  all[node.nodeId] = node;
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(all, null, 2), "utf8");
}

export async function listNodes(): Promise<Array<FleetNode & { online: boolean }>> {
  const all = await readAll();
  const now = Date.now();
  // Container recreates change the default nodeId (container hostname), leaving
  // ghost entries behind. Collapse to the freshest report per node name.
  const byName = new Map<string, FleetNode>();
  for (const n of Object.values(all)) {
    const prev = byName.get(n.name);
    if (!prev || Date.parse(n.lastSeen) > Date.parse(prev.lastSeen)) byName.set(n.name, n);
  }
  return [...byName.values()]
    .map((n) => ({ ...n, online: now - Date.parse(n.lastSeen) < 5 * 60_000 }))
    .sort((a, b) => b.attackers - a.attackers);
}

/** Build this node's summary from live metrics. */
export async function buildSelfReport(): Promise<FleetNode> {
  const o = await buildOverview();
  const byRisk = o.attackers.byRisk as Record<string, number>;
  const net = await getNodeNetwork();
  const status = getNodeStatus();
  return {
    nodeId: nodeId(),
    name: process.env.NODE_NAME || nodeId(),
    region: process.env.NODE_REGION || "",
    attackers: o.attackers.total,
    active15m: o.attackers.active15m,
    highRisk: byRisk.high || 0,
    transcripts: o.transcripts.total,
    topCountry: o.attackers.byCountry[0]?.key || "?",
    lastSeen: o.generatedAt,
    publicIp: net.publicIp,
    privateIp: net.privateIp,
    hostname: net.hostname,
    ports: getNodePorts(),
    services: process.env.NODE_SERVICES || "",
    restarts: status.startCount,
    lastStartAt: status.lastStartAt,
    lastStartReason: status.lastStartReason,
    instanceId: net.instanceId,
    instanceType: net.instanceType,
    az: net.az,
    ...getNodeMisc(),
  };
}

/** Report this node — to the central master if configured, else locally. */
export async function selfReport(): Promise<void> {
  const node = await buildSelfReport();
  const feed = await buildFeedItems();
  const detail = await buildDetail();
  const master = process.env.FLEET_MASTER_URL;
  if (master) {
    const base = master.replace(/\/$/, "");
    const headers = {
      "Content-Type": "application/json",
      ...(process.env.FLEET_TOKEN ? { Authorization: `Bearer ${process.env.FLEET_TOKEN}` } : {}),
    };
    const post = async (pathname: string, body: unknown) => {
      try {
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 6000);
        await fetch(base + pathname, { method: "POST", headers, body: JSON.stringify(body), signal: ctrl.signal });
        clearTimeout(t);
      } catch {
        /* master unreachable — try again next tick */
      }
    };
    await post("/api/fleet/report", node);
    await post("/api/fleet/feed", { node: node.name, items: feed });
    await post("/api/fleet/detail", detail);
  } else {
    await reportNode(node);
    await reportFeed(node.name, feed);
    await reportDetail(detail);
  }
}
