// Turns first-party honeypot observations into structured threat intelligence:
// deduplicated IOCs and MITRE ATT&CK technique coverage.

import { listAttackers, AttackerProfile } from "../deception_engine/state/attacker_memory.js";
import { readTranscripts, TranscriptRecord } from "../deception_engine/logging/transcript_store.js";

export type IocType = "ipv4" | "ipv6" | "username" | "command" | "url" | "user-agent";

/** Public-routable check so we never publish loopback/private IPs as indicators. */
export function isPublicIp(ip: string): boolean {
  if (!ip || ip === "unknown") return false;
  if (ip.includes(":")) {
    const l = ip.toLowerCase();
    return !(l === "::1" || l.startsWith("fe80") || l.startsWith("fc") || l.startsWith("fd"));
  }
  const o = ip.split(".").map(Number);
  if (o.length !== 4 || o.some((n) => Number.isNaN(n))) return false;
  if (o[0] === 10 || o[0] === 127 || (o[0] === 192 && o[1] === 168)) return false;
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false;
  if (o[0] === 169 && o[1] === 254) return false;
  return true;
}

export type Ioc = {
  type: IocType;
  value: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  sources: string[]; // attacker ids / services seen on
};

export type AttackTechnique = {
  id: string; // MITRE ATT&CK id, e.g. T1110
  name: string;
  tactic: string;
  count: number;
  attackers: string[];
};

const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
const PATH_RE = /(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+(\/[^\s]*)/i;

// (matcher, technique) rules. Matched against transcript request/detail + intent.
type Rule = { test: RegExp | ((t: TranscriptRecord) => boolean); id: string; name: string; tactic: string };

const ATTACK_RULES: Rule[] = [
  { test: (t) => t.intent === "brute_force", id: "T1110", name: "Brute Force", tactic: "Credential Access" },
  { test: (t) => t.intent === "recon", id: "T1595", name: "Active Scanning", tactic: "Reconnaissance" },
  { test: /\b(nmap|masscan|scan|probe|describe|options)\b/i, id: "T1046", name: "Network Service Discovery", tactic: "Discovery" },
  { test: /(union\s+select|or\s+1=1|sqlmap|';--)/i, id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  { test: /\.\.\/|\/etc\/passwd|\/etc\/shadow/i, id: "T1083", name: "File and Directory Discovery", tactic: "Discovery" },
  { test: /\/etc\/shadow|getent\s+shadow|unshadow/i, id: "T1003", name: "OS Credential Dumping", tactic: "Credential Access" },
  { test: /\b(whoami|id|groups)\b/i, id: "T1033", name: "System Owner/User Discovery", tactic: "Discovery" },
  { test: /\b(uname|hostname|lscpu|cat\s+\/proc)/i, id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
  { test: /\bps\b|\btop\b|tasklist/i, id: "T1057", name: "Process Discovery", tactic: "Discovery" },
  { test: /\b(wget|curl)\b.*https?:|tftp|scp\s/i, id: "T1105", name: "Ingress Tool Transfer", tactic: "Command and Control" },
  { test: /chmod\s|chattr\s/i, id: "T1222", name: "File and Directory Permissions Modification", tactic: "Defense Evasion" },
  { test: /(nc\s+-e|bash\s+-i|\/dev\/tcp\/|reverse shell|mkfifo)/i, id: "T1059", name: "Command and Scripting Interpreter", tactic: "Execution" },
  { test: /(useradd|adduser|authorized_keys|ssh-keygen)/i, id: "T1136", name: "Create Account", tactic: "Persistence" },
  { test: /(crontab|systemctl enable|rc\.local|\/etc\/cron)/i, id: "T1053", name: "Scheduled Task/Job", tactic: "Persistence" },
  { test: (t) => /modbus/i.test(t.service) && /write|wr=|fc=(5|6|16)/i.test(t.request), id: "T0831", name: "Manipulation of Control (ICS)", tactic: "ICS Impact" },
  { test: (t) => t.intent === "exploitation", id: "T1190", name: "Exploit Public-Facing Application", tactic: "Initial Access" },
];

function bump<T extends { count: number; lastSeen?: string; firstSeen?: string }>(
  map: Map<string, T>,
  key: string,
  make: () => T,
  at?: string
) {
  let e = map.get(key);
  if (!e) {
    e = make();
    map.set(key, e);
  }
  e.count += 1;
  if (at) {
    if (!e.firstSeen || at < e.firstSeen) e.firstSeen = at;
    if (!e.lastSeen || at > e.lastSeen) e.lastSeen = at;
  }
  return e;
}

export async function buildIocs(): Promise<{ iocs: Ioc[]; counts: Record<IocType, number> }> {
  const attackers = await listAttackers();
  const transcripts = await readTranscripts();
  const map = new Map<string, Ioc>();
  const add = (type: IocType, value: string, source: string, at: string) => {
    if (!value) return;
    const e = bump<Ioc>(map, `${type}:${value}`, () => ({ type, value, count: 0, firstSeen: at, lastSeen: at, sources: [] }), at);
    if (source && !e.sources.includes(source)) e.sources.push(source);
  };

  for (const a of attackers) {
    add(a.sourceIp.includes(":") ? "ipv6" : "ipv4", a.sourceIp, a.id.slice(0, 12), a.lastSeenAt);
    for (const svc of Object.values(a.services)) {
      for (const u of svc?.usernames || []) add("username", u, a.id.slice(0, 12), a.lastSeenAt);
    }
  }

  for (const t of transcripts) {
    const req = t.request || "";
    if (/login|auth|username=/i.test(t.request) || /command=|shell input=|exec/i.test(t.request)) {
      const cmd = req.replace(/^POST\s+\S+\s*/, "").slice(0, 120).trim();
      if (cmd) add("command", cmd, t.service, t.at);
    }
    const ua = (t.metadata && (t.metadata.userAgent as string)) || "";
    if (ua && ua !== "none") add("user-agent", String(ua).slice(0, 160), t.service, t.at);
    for (const m of req.match(URL_RE) || []) add("url", m, t.service, t.at);
    const pathM = req.match(PATH_RE);
    if (pathM && pathM[1] && pathM[1] !== "/") add("url", pathM[1], t.service, t.at);
  }

  const iocs = [...map.values()].sort((a, b) => b.count - a.count);
  const counts = iocs.reduce(
    (acc, i) => ((acc[i.type] = (acc[i.type] || 0) + 1), acc),
    {} as Record<IocType, number>
  );
  return { iocs, counts };
}

export async function buildAttackMatrix(): Promise<AttackTechnique[]> {
  const transcripts = await readTranscripts();
  const map = new Map<string, AttackTechnique>();
  for (const t of transcripts) {
    const hay = `${t.request || ""} ${t.response || ""}`;
    for (const rule of ATTACK_RULES) {
      const hit = typeof rule.test === "function" ? rule.test(t) : rule.test.test(hay);
      if (!hit) continue;
      const e = map.get(rule.id) || { id: rule.id, name: rule.name, tactic: rule.tactic, count: 0, attackers: [] };
      e.count += 1;
      if (t.attackerId && !e.attackers.includes(t.attackerId)) e.attackers.push(t.attackerId);
      map.set(rule.id, e);
    }
  }
  return [...map.values()].sort((a, b) => b.count - a.count);
}

/** Cluster attackers into campaigns by shared origin (ISP/country) + intent. */
export async function buildCampaigns(): Promise<Array<Record<string, unknown>>> {
  const attackers = await listAttackers();
  const groups = new Map<string, AttackerProfile[]>();
  for (const a of attackers) {
    const key = `${a.geo?.isp || a.geo?.countryCode || "unknown"}|${a.intent}`;
    groups.set(key, [...(groups.get(key) || []), a]);
  }
  return [...groups.entries()]
    .map(([key, members]) => {
      const [origin, intent] = key.split("|");
      const services = new Set<string>();
      members.forEach((m) => Object.keys(m.services).forEach((s) => services.add(s)));
      return {
        id: key,
        origin,
        intent,
        members: members.length,
        ips: members.map((m) => m.sourceIp).slice(0, 25),
        services: [...services],
        totalScore: members.reduce((s, m) => s + (m.totalScore || 0), 0),
        firstSeen: members.map((m) => m.firstSeenAt).sort()[0],
        lastSeen: members.map((m) => m.lastSeenAt).sort().slice(-1)[0],
      };
    })
    .filter((c) => (c.members as number) > 1 || (c.totalScore as number) > 40)
    .sort((a, b) => (b.totalScore as number) - (a.totalScore as number));
}

/** Novel IOCs/techniques first observed within the last `hours` (anomaly view). */
export async function buildNovelty(hours = 24): Promise<{ iocs: Ioc[]; techniques: AttackTechnique[] }> {
  const cutoff = Date.now() - hours * 3600_000;
  const { iocs } = await buildIocs();
  const techniques = await buildAttackMatrix();
  const fresh = (iso: string) => {
    const t = Date.parse(iso);
    return !Number.isNaN(t) && t >= cutoff;
  };
  return {
    iocs: iocs.filter((i) => fresh(i.firstSeen) && i.count <= 3).slice(0, 50),
    techniques: techniques.filter((t) => t.count <= 2),
  };
}

/** Compact per-attacker intel summary for actor/campaign views. */
export async function buildActors(): Promise<Array<Record<string, unknown>>> {
  const attackers = await listAttackers();
  return attackers
    .map((a: AttackerProfile) => ({
      id: a.id.slice(0, 12),
      sourceIp: a.sourceIp,
      country: a.geo?.countryCode || "??",
      isp: a.geo?.isp || "",
      risk: a.risk,
      intent: a.intent,
      score: a.totalScore,
      services: Object.keys(a.services),
      firstSeen: a.firstSeenAt,
      lastSeen: a.lastSeenAt,
    }))
    .sort((x, y) => (y.score as number) - (x.score as number));
}
