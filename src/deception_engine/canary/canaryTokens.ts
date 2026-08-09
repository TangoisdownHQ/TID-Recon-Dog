// Honeytokens / canary tokens.
//
// The decoy filesystem (fakeFilesystem.ts) and persona files plant distinctive
// fake secrets — AWS keys, DB passwords, Vault/Stripe tokens, a Slack webhook,
// and a reachable "status beacon" URL. This module does two things:
//
//   1. noteCanaryServed(response, ctx)  — when we hand a decoy file back to an
//      attacker, record WHICH token was served to WHICH source IP and WHEN.
//   2. checkCanaryTrigger(input, ctx)   — when any planted secret later appears
//      in ATTACKER INPUT (a login attempt, a curl of the beacon URL, a shell
//      command echoing it), fire a high-severity CANARY TRIGGERED alert and
//      attribute it: "planted secret read by X is now being used by Y, N min
//      later." That "read it here, used it there" loop is the highest-signal
//      event a deception platform can produce.
//
// State is persisted to runtime/canaries.json (best-effort, debounced).

import fs from "fs/promises";
import path from "path";
import { emitAlert } from "../../operator/alertHook.js";

export type CanaryKind =
  | "aws_key"
  | "db_cred"
  | "vault_token"
  | "api_key"
  | "webhook"
  | "beacon_url";

export type CanaryToken = {
  id: string;
  kind: CanaryKind;
  label: string; // human name shown in the operator console
  value: string; // the distinctive string matched in attacker input / our responses
  plantedPath: string; // decoy file it lives in (operator context)
};

export type CanaryEvent = { ip: string; service: string; at: string; evidence?: string };

type CanaryState = {
  served: Record<string, CanaryEvent[]>; // tokenId -> times we handed it out
  triggers: Record<string, CanaryEvent[]>; // tokenId -> times an attacker used it
};

// Distinctive secrets planted across the decoy FS. Values are chosen to be
// high-entropy / unlikely to false-positive on ordinary traffic. Keep in sync
// with fakeFilesystem.ts when decoy content changes.
export const CANARY_TOKENS: CanaryToken[] = [
  { id: "aws-prod", kind: "aws_key", label: "AWS prod access key", value: "AKIA4RELAYPRODX7QZ", plantedPath: "~/.aws/credentials" },
  { id: "aws-backup", kind: "aws_key", label: "AWS backup access key", value: "AKIA4BACKUPSVC2026", plantedPath: "~/.aws/credentials" },
  { id: "db-prod", kind: "db_cred", label: "prod DB password", value: "Rel4y!Pr0d2026", plantedPath: "/opt/relay/config.yaml" },
  { id: "db-admin", kind: "db_cred", label: "relay admin password", value: "R3lay@dmin2026", plantedPath: "relayd.conf" },
  { id: "backup-offsite", kind: "db_cred", label: "offsite backup password", value: "B@ckup$Offsite40", plantedPath: "/opt/backup/.env" },
  { id: "deploy-pass", kind: "db_cred", label: "deploy password", value: "D3pl0y2026", plantedPath: "~/.env" },
  // Split literals so GitHub push-protection doesn't flag the fake key patterns;
  // the concatenated runtime value still matches what fakeFilesystem.ts serves.
  { id: "stripe", kind: "api_key", label: "Stripe live key", value: "sk_" + "live_fakeHONEYPOTstripeKEYexample123", plantedPath: "/opt/relay/config.yaml" },
  { id: "vault-token", kind: "vault_token", label: "Vault token", value: "hvs.CAESfakeHONEYPOTvaultTOKENexample", plantedPath: "/opt/relay/config.yaml" },
  { id: "slack-hook", kind: "webhook", label: "Slack webhook", value: "hooks.slack.internal/services/T00/B00/relay", plantedPath: "~/.env" },
  { id: "jira-cred", kind: "db_cred", label: "Jira password", value: "Summer2026!", plantedPath: "~/passwords.txt" },
  { id: "vpn-cred", kind: "db_cred", label: "VPN password", value: "V3lcr0!Field", plantedPath: "~/passwords.txt" },
  { id: "bastion-cred", kind: "db_cred", label: "bastion password", value: "Harmon$SSH99", plantedPath: "~/passwords.txt" },
  { id: "beacon-1", kind: "beacon_url", label: "status beacon URL", value: "/_hc/relay-7f3a9c2e", plantedPath: "/opt/relay/deploy.sh" },
];

const EVENT_CAP = 50;
const STATE_PATH = path.resolve("runtime", "canaries.json");

let state: CanaryState = { served: {}, triggers: {} };
let loaded = false;
let flushTimer: NodeJS.Timeout | null = null;

async function ensureLoaded(): Promise<void> {
  if (loaded) return;
  loaded = true;
  try {
    const raw = await fs.readFile(STATE_PATH, "utf8");
    const parsed = JSON.parse(raw) as Partial<CanaryState>;
    state = { served: parsed.served || {}, triggers: parsed.triggers || {} };
  } catch {
    // fresh state
  }
}

function scheduleFlush(): void {
  if (flushTimer) return;
  flushTimer = setTimeout(async () => {
    flushTimer = null;
    try {
      await fs.mkdir(path.dirname(STATE_PATH), { recursive: true });
      await fs.writeFile(STATE_PATH, JSON.stringify(state), "utf8");
    } catch {
      // best-effort persistence
    }
  }, 1000);
  if (typeof flushTimer.unref === "function") flushTimer.unref();
}

/** Record that a decoy secret was handed to an attacker (scanned in our reply). */
export async function noteCanaryServed(
  text: string | undefined,
  ctx: { ip: string; service: string }
): Promise<void> {
  if (!text) return;
  await ensureLoaded();
  const now = new Date().toISOString();
  let changed = false;
  for (const t of CANARY_TOKENS) {
    if (!text.includes(t.value)) continue;
    const arr = (state.served[t.id] ||= []);
    const last = arr[arr.length - 1];
    // Collapse rapid repeats from the same source (e.g. re-cat within a minute).
    if (last && last.ip === ctx.ip && Date.parse(now) - Date.parse(last.at) < 60000) continue;
    arr.push({ ip: ctx.ip, service: ctx.service, at: now });
    state.served[t.id] = arr.slice(-EVENT_CAP);
    changed = true;
  }
  if (changed) scheduleFlush();
}

/**
 * Scan attacker-supplied input for any planted secret. On a hit, record the
 * trigger and fire an attributed CANARY TRIGGERED alert. Returns matched tokens.
 */
export async function checkCanaryTrigger(
  text: string | undefined,
  ctx: { ip: string; service: string }
): Promise<CanaryToken[]> {
  if (!text) return [];
  await ensureLoaded();
  const now = new Date().toISOString();
  const hits: CanaryToken[] = [];
  for (const t of CANARY_TOKENS) {
    if (!text.includes(t.value)) continue;
    hits.push(t);
    const arr = (state.triggers[t.id] ||= []);
    arr.push({ ip: ctx.ip, service: ctx.service, at: now, evidence: text.slice(0, 160) });
    state.triggers[t.id] = arr.slice(-EVENT_CAP);
    void fireCanaryAlert(t, ctx, now);
  }
  if (hits.length) scheduleFlush();
  return hits;
}

async function fireCanaryAlert(
  token: CanaryToken,
  ctx: { ip: string; service: string },
  at: string
): Promise<void> {
  const served = state.served[token.id] || [];
  // Prefer attribution to a *different* source that read the secret earlier.
  const prior =
    [...served].reverse().find((s) => s.ip !== ctx.ip) || served[served.length - 1];
  let attribution: string;
  if (prior) {
    const dtMin = Math.max(0, Math.round((Date.parse(at) - Date.parse(prior.at)) / 60000));
    attribution =
      prior.ip === ctx.ip
        ? ` Same source read it here ${dtMin}m earlier.`
        : ` Secret was served to ${prior.ip} (${prior.service}) ${dtMin}m earlier — a different source is now using it.`;
  } else {
    attribution = " No prior read recorded on this node — likely exfiltrated from another node or persona.";
  }
  const summary = `CANARY TRIGGERED: ${token.label} (planted in ${token.plantedPath}) was used by ${ctx.ip} on ${ctx.service}.${attribution}`;
  await emitAlert({
    at,
    event: "canary_triggered",
    attacker_id: "canary",
    source_ip: ctx.ip,
    risk: "high",
    previous_risk: "medium",
    intent: "exploitation",
    score: 0,
    services: [ctx.service],
    recent_events: [summary],
    summary,
  });
}

/**
 * Compact snapshot of this node's canary state for reporting to the fleet
 * master, which correlates served↔trigger events across nodes. Bounded so the
 * self-report payload stays small.
 */
export async function getCanaryExport(): Promise<{
  served: Record<string, CanaryEvent[]>;
  triggers: Record<string, CanaryEvent[]>;
}> {
  await ensureLoaded();
  const trim = (m: Record<string, CanaryEvent[]>) => {
    const out: Record<string, CanaryEvent[]> = {};
    for (const [k, v] of Object.entries(m)) if (v.length) out[k] = v.slice(-25);
    return out;
  };
  return { served: trim(state.served), triggers: trim(state.triggers) };
}

/** Operator API view: every token with its served/trigger history and counts. */
export async function listCanaries() {
  await ensureLoaded();
  return CANARY_TOKENS.map((t) => {
    const served = state.served[t.id] || [];
    const triggers = state.triggers[t.id] || [];
    return {
      id: t.id,
      kind: t.kind,
      label: t.label,
      plantedPath: t.plantedPath,
      servedCount: served.length,
      triggerCount: triggers.length,
      served: served.slice(-10),
      triggers: triggers.slice(-10),
      lastServed: served[served.length - 1]?.at || null,
      lastTrigger: triggers[triggers.length - 1]?.at || null,
    };
  });
}
