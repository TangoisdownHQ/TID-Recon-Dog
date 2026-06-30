// Auto-response playbooks: operator-defined rules that turn observations into
// action (block / tarpit / decoy_success / fake_error / alert) automatically.
// Evaluated on every recorded interaction, after scoring.
import fs from "fs/promises";
import path from "path";
import { ControlAction, blockIp, setSessionAction } from "./controlPlane.js";

export type PlaybookAction = "block" | "alert" | ControlAction; // controlActions + block + alert

export type Playbook = {
  id: string;
  name: string;
  enabled: boolean;
  when: {
    intent?: string; // recon | brute_force | exploitation
    risk?: string; // low | medium | high
    minScore?: number;
    service?: string; // SSH, HTTP, ...
    commandMatch?: string; // regex against the detail/request
  };
  then: PlaybookAction;
};

const filePath = path.resolve("runtime", "playbooks.json");

const DEFAULTS: Playbook[] = [
  { id: "pb-exploit-block", name: "Block on exploitation", enabled: false, when: { intent: "exploitation" }, then: "block" },
  { id: "pb-high-tarpit", name: "Tarpit high-risk", enabled: false, when: { risk: "high" }, then: "stall" },
  { id: "pb-brute-decoy", name: "Let brute-forcers in (decoy)", enabled: false, when: { intent: "brute_force", minScore: 30 }, then: "decoy_success" },
  { id: "pb-creds-alert", name: "Alert on credential-file access", enabled: false, when: { commandMatch: "/etc/shadow|/etc/passwd|id_rsa|\\.env|config\\.yaml" }, then: "alert" },
];

let cache: Playbook[] | null = null;

export async function readPlaybooks(): Promise<Playbook[]> {
  if (cache) return cache;
  try {
    cache = JSON.parse(await fs.readFile(filePath, "utf8")) as Playbook[];
  } catch {
    cache = DEFAULTS;
  }
  return cache;
}

export async function writePlaybooks(pbs: Playbook[]) {
  cache = pbs;
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, JSON.stringify(pbs, null, 2), "utf8");
}

export type PlaybookContext = {
  sessionId: string;
  sourceIp: string;
  service: string;
  intent: string;
  risk: string;
  score: number;
  detail: string;
};

export type PlaybookHit = { rule: string; action: PlaybookAction };

function matches(pb: Playbook, c: PlaybookContext): boolean {
  const w = pb.when;
  if (w.intent && w.intent !== c.intent) return false;
  if (w.risk && w.risk !== c.risk) return false;
  if (typeof w.minScore === "number" && c.score < w.minScore) return false;
  if (w.service && w.service.toUpperCase() !== c.service.toUpperCase()) return false;
  if (w.commandMatch) {
    try {
      if (!new RegExp(w.commandMatch, "i").test(c.detail)) return false;
    } catch {
      return false;
    }
  }
  return true;
}

/** Evaluate enabled rules and apply their actions. Returns what fired. */
export async function evaluatePlaybooks(c: PlaybookContext, onAlert: (hit: PlaybookHit) => void): Promise<PlaybookHit[]> {
  const pbs = await readPlaybooks();
  const fired: PlaybookHit[] = [];
  for (const pb of pbs) {
    if (!pb.enabled || !matches(pb, c)) continue;
    fired.push({ rule: pb.name, action: pb.then });
    try {
      if (pb.then === "block") await blockIp(c.sourceIp);
      else if (pb.then === "alert") onAlert({ rule: pb.name, action: pb.then });
      else await setSessionAction(c.sessionId, pb.then as ControlAction); // stall/decoy_success/fake_error/etc.
    } catch {
      /* never break the live path */
    }
  }
  return fired;
}
