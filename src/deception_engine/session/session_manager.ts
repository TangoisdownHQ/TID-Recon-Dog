import crypto from "crypto";
import { persistSessions, readSessionSnapshots, SessionSnapshot } from "../../utils/logger.js";

export type SessionEvent = {
  at: string;
  detail: string;
};

export type SessionRecord = SessionSnapshot & {
  events: string[];
};

const sessions = new Map<string, SessionRecord>();
let hydrated = false;
let flushTimer: ReturnType<typeof setTimeout> | null = null;

// Every connection creates a session; without eviction the Map (and sessions.json,
// which is parsed on every operator request) grew unbounded and saturated the
// event loop. Keep the most-recent MAX_SESSIONS by lastSeenAt.
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS || "750", 10);

function pruneSessions() {
  if (sessions.size <= MAX_SESSIONS) return;
  const ordered = Array.from(sessions.values()).sort((a, b) =>
    a.lastSeenAt.localeCompare(b.lastSeenAt)
  );
  for (const stale of ordered.slice(0, sessions.size - MAX_SESSIONS)) {
    sessions.delete(stale.id);
  }
}

async function hydrateSessions() {
  if (hydrated) {
    return;
  }

  const existing = await readSessionSnapshots();
  for (const session of existing) {
    sessions.set(session.id, {
      ...session,
      events: session.events.slice(),
    });
  }
  hydrated = true;
}

function snapshot(session: SessionRecord): SessionSnapshot {
  return {
    id: session.id,
    service: session.service,
    ip: session.ip,
    status: session.status,
    currentAction: session.currentAction,
    firstSeenAt: session.firstSeenAt,
    lastSeenAt: session.lastSeenAt,
    attackerId: session.attackerId,
    intent: session.intent,
    score: session.score,
    personaId: session.personaId,
    events: session.events.slice(-20),
    metadata: session.metadata,
  };
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    void persistSessions(Array.from(sessions.values()).map(snapshot));
  }, 500);
}

export async function upsertSession(params: {
  id?: string;
  service: string;
  ip: string;
  status?: string;
  currentAction?: string;
  detail: string;
  metadata?: Record<string, string>;
  attackerId?: string;
  intent?: string;
  score?: number;
  personaId?: string;
}) {
  await hydrateSessions();
  const id = params.id || crypto.randomUUID();
  const now = new Date().toISOString();
  const existing = sessions.get(id);

  const record: SessionRecord = existing || {
    id,
    service: params.service,
    ip: params.ip,
    status: params.status || "active",
    currentAction: params.currentAction || "allow",
    firstSeenAt: now,
    lastSeenAt: now,
    attackerId: params.attackerId,
    intent: params.intent,
    score: params.score,
    personaId: params.personaId,
    events: [],
    metadata: params.metadata,
  };

  record.service = params.service;
  record.ip = params.ip;
  record.status = params.status || record.status;
  record.currentAction = params.currentAction || record.currentAction;
  record.lastSeenAt = now;
  record.attackerId = params.attackerId || record.attackerId;
  record.intent = params.intent || record.intent;
  record.score = params.score ?? record.score;
  record.personaId = params.personaId || record.personaId;
  record.metadata = { ...(record.metadata || {}), ...(params.metadata || {}) };
  record.events.push(`${now} ${params.detail}`);

  sessions.set(id, record);
  pruneSessions();
  scheduleFlush();

  return record;
}

export function getSession(id: string) {
  return sessions.get(id);
}

export function listSessions() {
  return Array.from(sessions.values()).map(snapshot);
}

export async function setSessionAction(id: string, action: string) {
  await hydrateSessions();
  const session = sessions.get(id);
  if (!session) {
    return undefined;
  }

  session.currentAction = action;
  session.events.push(`${new Date().toISOString()} operator action set to ${action}`);
  scheduleFlush();
  return snapshot(session);
}
