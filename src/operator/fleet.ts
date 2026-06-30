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
import { buildOverview } from "./api/metrics.js";

const filePath = path.resolve("runtime", "fleet.json");

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
};

export function nodeId(): string {
  return process.env.NODE_ID || os.hostname();
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
  return Object.values(all)
    .map((n) => ({ ...n, online: now - Date.parse(n.lastSeen) < 5 * 60_000 }))
    .sort((a, b) => b.attackers - a.attackers);
}

/** Build this node's summary from live metrics. */
export async function buildSelfReport(): Promise<FleetNode> {
  const o = await buildOverview();
  const byRisk = o.attackers.byRisk as Record<string, number>;
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
  };
}

/** Report this node — to the central master if configured, else locally. */
export async function selfReport(): Promise<void> {
  const node = await buildSelfReport();
  const master = process.env.FLEET_MASTER_URL;
  if (master) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 6000);
      await fetch(master.replace(/\/$/, "") + "/api/fleet/report", {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(process.env.FLEET_TOKEN ? { Authorization: `Bearer ${process.env.FLEET_TOKEN}` } : {}) },
        body: JSON.stringify(node),
        signal: ctrl.signal,
      });
      clearTimeout(t);
    } catch {
      /* master unreachable — try again next tick */
    }
  } else {
    await reportNode(node);
  }
}
