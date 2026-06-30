import fs from "fs/promises";
import path from "path";

export const validActions = [
  "allow",
  "stall",
  "fake_error",
  "decoy_success",
  "camera_offline",
] as const;

export type ControlAction = typeof validActions[number];

// Engine mode = how responses are generated.
//  - deterministic: hardcoded responders only (safe default)
//  - shadow:        deterministic is served, but the trained model also generates
//                   a candidate response that is logged for review (never served)
//  - ai:            when a session's action is decoy_success, the trained model
//                   generates the served response (intelligent replies)
export const engineModes = ["deterministic", "shadow", "ai"] as const;
export type EngineMode = typeof engineModes[number];

type ControlState = {
  defaultAction: ControlAction;
  sessionActions: Record<string, ControlAction>;
  mode: EngineMode;
  blockedIps: string[];
};

const controlFilePath = path.resolve("runtime", "controls.json");

const defaultState: ControlState = {
  defaultAction: "allow",
  sessionActions: {},
  mode: "deterministic",
  blockedIps: [],
};

// In-memory mirror of the blocklist. The operator API and the services share a
// single process, so updates here take effect on the next connection instantly.
let blockedCache = new Set<string>();

// Operator -> live session message injection (keyed by sessionId or source IP).
// Same-process, so a message queued from the API is picked up by the service
// within its poll interval and written into the attacker's terminal.
const messageQueue = new Map<string, string[]>();

export function queueMessage(target: string, text: string) {
  const list = messageQueue.get(target) || [];
  list.push(text);
  messageQueue.set(target, list);
}

/** Returns and clears any messages queued for this session id or IP. */
export function takeMessages(...targets: string[]): string[] {
  const out: string[] = [];
  for (const t of targets) {
    if (!t) continue;
    const list = messageQueue.get(t);
    if (list && list.length) {
      out.push(...list);
      messageQueue.delete(t);
    }
  }
  return out;
}

/** Synchronous block check for hot connection paths (see connectionThrottle). */
export function isIpBlockedSync(ip: string): boolean {
  return blockedCache.has(ip);
}

async function ensureControlFile() {
  await fs.mkdir(path.dirname(controlFilePath), { recursive: true });
  try {
    await fs.access(controlFilePath);
  } catch {
    await fs.writeFile(controlFilePath, JSON.stringify(defaultState, null, 2), "utf8");
  }
}

export async function readControlState(): Promise<ControlState> {
  await ensureControlFile();
  const raw = await fs.readFile(controlFilePath, "utf8");
  const parsed = JSON.parse(raw) as Partial<ControlState>;
  // Backfill fields added after a controls.json was first written.
  const state: ControlState = {
    defaultAction: parsed.defaultAction || "allow",
    sessionActions: parsed.sessionActions || {},
    mode: parsed.mode || "deterministic",
    blockedIps: parsed.blockedIps || [],
  };
  blockedCache = new Set(state.blockedIps);
  return state;
}

async function writeControlState(state: ControlState) {
  await ensureControlFile();
  blockedCache = new Set(state.blockedIps);
  await fs.writeFile(controlFilePath, JSON.stringify(state, null, 2), "utf8");
}

export async function getActionForSession(sessionId?: string): Promise<ControlAction> {
  const state = await readControlState();
  if (sessionId && state.sessionActions[sessionId]) {
    return state.sessionActions[sessionId];
  }

  return state.defaultAction;
}

export async function setDefaultAction(action: ControlAction) {
  const state = await readControlState();
  state.defaultAction = action;
  await writeControlState(state);
}

export async function setSessionAction(sessionId: string, action: ControlAction) {
  const state = await readControlState();
  state.sessionActions[sessionId] = action;
  await writeControlState(state);
}

export async function getEngineMode(): Promise<EngineMode> {
  return (await readControlState()).mode;
}

export async function setEngineMode(mode: EngineMode) {
  const state = await readControlState();
  state.mode = mode;
  await writeControlState(state);
}

export async function blockIp(ip: string) {
  const state = await readControlState();
  if (!state.blockedIps.includes(ip)) {
    state.blockedIps.push(ip);
    await writeControlState(state);
  }
}

export async function unblockIp(ip: string) {
  const state = await readControlState();
  state.blockedIps = state.blockedIps.filter((entry) => entry !== ip);
  await writeControlState(state);
}

export async function isIpBlocked(ip: string): Promise<boolean> {
  const state = await readControlState();
  return state.blockedIps.includes(ip);
}

export function isValidAction(action: string): action is ControlAction {
  return (validActions as readonly string[]).includes(action);
}

export function isValidMode(mode: string): mode is EngineMode {
  return (engineModes as readonly string[]).includes(mode);
}
