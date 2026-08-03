// Per-node status: restart accounting ("how many times, and why") and the node's
// own network identity (public/private IP, hostname, exposed ports). Surfaced in
// the Fleet tab so an operator can see, per box, where it is, what it exposes,
// and whether it has been flapping.
import fs from "fs";
import fsp from "fs/promises";
import os from "os";
import path from "path";

const runtimeDir = path.resolve("runtime");
const statusPath = path.join(runtimeDir, "node-status.json");
const cleanMarker = path.join(runtimeDir, ".clean-shutdown");
const autohealMarker = path.join(runtimeDir, ".autoheal-restart"); // written by host auto-heal before a restart

export type NodeStatus = {
  startCount: number;
  lastStartAt: string;
  lastStartReason: string; // human-readable "why"
};

let cached: NodeStatus = { startCount: 0, lastStartAt: "", lastStartReason: "unknown" };

/**
 * Call once at boot. Increments the restart counter and classifies WHY this
 * process started, based on markers left by the previous run / host auto-heal:
 *   - first boot            no prior state
 *   - clean restart         previous run caught SIGTERM (planned stop / redeploy)
 *   - auto-heal (healthz)   host auto-heal timer restarted a wedged container
 *   - unclean (crash/OOM/kill)  no clean-shutdown marker — process died hard
 */
export function initNodeStatus(): void {
  let prev: NodeStatus | null = null;
  try {
    prev = JSON.parse(fs.readFileSync(statusPath, "utf8")) as NodeStatus;
  } catch {
    prev = null;
  }

  const healed = fs.existsSync(autohealMarker);
  const clean = fs.existsSync(cleanMarker);
  let reason: string;
  if (!prev) reason = "first boot";
  else if (healed) reason = "auto-heal (healthz down)";
  else if (clean) reason = "clean restart (stop/redeploy)";
  else reason = "unclean (crash/OOM/kill)";

  // Consume markers so the next boot reflects the next shutdown.
  for (const m of [cleanMarker, autohealMarker]) {
    try { fs.unlinkSync(m); } catch { /* not present */ }
  }

  cached = {
    startCount: (prev?.startCount || 0) + 1,
    lastStartAt: new Date().toISOString(),
    lastStartReason: reason,
  };
  try {
    fs.mkdirSync(runtimeDir, { recursive: true });
    fs.writeFileSync(statusPath, JSON.stringify(cached, null, 2), "utf8");
  } catch { /* best effort */ }

  // Mark a clean shutdown when we exit on a signal, so the next boot knows.
  const onSignal = () => {
    try { fs.writeFileSync(cleanMarker, new Date().toISOString(), "utf8"); } catch { /* ignore */ }
    process.exit(0);
  };
  process.once("SIGTERM", onSignal);
  process.once("SIGINT", onSignal);
}

export function getNodeStatus(): NodeStatus {
  return cached;
}

// --- Network identity (EC2 IMDSv2, cached; env overrides win) ----------------
export type NodeNetwork = {
  publicIp: string;
  privateIp: string;
  hostname: string;
  instanceId: string;
  instanceType: string;
  az: string;
};
let netCache: NodeNetwork | null = null;

async function imds(pathname: string, token: string): Promise<string> {
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 500);
    const r = await fetch(`http://169.254.169.254/latest/meta-data/${pathname}`, {
      headers: { "X-aws-ec2-metadata-token": token },
      signal: ctrl.signal,
    });
    clearTimeout(t);
    return r.ok ? (await r.text()).trim() : "";
  } catch {
    return "";
  }
}

export async function getNodeNetwork(): Promise<NodeNetwork> {
  if (netCache) return netCache;
  let publicIp = process.env.NODE_PUBLIC_IP || "";
  let privateIp = process.env.NODE_PRIVATE_IP || "";
  const hostname = process.env.NODE_HOSTNAME || os.hostname();
  let instanceId = "";
  let instanceType = "";
  let az = "";

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 500);
    const tr = await fetch("http://169.254.169.254/latest/api/token", {
      method: "PUT",
      headers: { "X-aws-ec2-metadata-token-ttl-seconds": "21600" },
      signal: ctrl.signal,
    });
    clearTimeout(t);
    if (tr.ok) {
      const token = (await tr.text()).trim();
      publicIp = publicIp || (await imds("public-ipv4", token));
      privateIp = privateIp || (await imds("local-ipv4", token));
      instanceId = await imds("instance-id", token);
      instanceType = await imds("instance-type", token);
      az = await imds("placement/availability-zone", token);
    }
  } catch {
    /* not on EC2 / IMDS unavailable */
  }
  netCache = { publicIp, privateIp, hostname, instanceId, instanceType, az };
  return netCache;
}

/** Ports this node exposes to the world (from NODE_PORTS env, e.g. "80,554"). */
export function getNodePorts(): string {
  return process.env.NODE_PORTS || "";
}

// --- Misc host info (OS, runtime, resource pressure) --------------------------
export type NodeMisc = {
  os: string; // e.g. "linux 6.1.134-150.224.amzn2023.x86_64"
  arch: string;
  appVersion: string; // package.json version (+ IMAGE_TAG env when set)
  nodeVersion: string; // Node.js runtime
  uptimeSec: number; // this process
  load1: number; // 1-minute load average
  memPct: number; // host memory in use, 0-100
};

let appVersionCache = "";
function appVersion(): string {
  if (!appVersionCache) {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.resolve("package.json"), "utf8")) as { version?: string };
      appVersionCache = pkg.version || "?";
    } catch {
      appVersionCache = "?";
    }
    if (process.env.IMAGE_TAG) appVersionCache += ` (${process.env.IMAGE_TAG})`;
  }
  return appVersionCache;
}

export function getNodeMisc(): NodeMisc {
  return {
    os: `${os.platform()} ${os.release()}`,
    arch: os.arch(),
    appVersion: appVersion(),
    nodeVersion: process.version,
    uptimeSec: Math.round(process.uptime()),
    load1: Math.round(os.loadavg()[0] * 100) / 100,
    memPct: Math.round((1 - os.freemem() / os.totalmem()) * 100),
  };
}
