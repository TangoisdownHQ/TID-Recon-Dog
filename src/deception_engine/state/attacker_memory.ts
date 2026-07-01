import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import {
  DecoyPersona,
  PersonaFile,
  PersonaGroup,
  PersonaStateValue,
  getPersonaById,
  getPersonaGroupForService,
  selectPersonaId,
} from "../../profiles/personaLibrary.js";
import { ResponderServiceName } from "../../responders/serviceNames.js";
import { sanitizeText } from "../../responders/safety.js";
import { GeoResult, lookupGeo } from "../../utils/geoip.js";
import { maybeFireAlert } from "../../operator/alertHook.js";
import { summarizeActivity, ActivitySummary, ActivityInput } from "../../operator/activitySummary.js";

export type AttackerIntent = "unknown" | "recon" | "brute_force" | "exploitation";

export type AttackerServiceMemory = {
  service: ResponderServiceName;
  personaId: string;
  personaGroup: PersonaGroup;
  host: string;
  banner: string;
  usernames: string[];
  files: PersonaFile[];
  deviceState: Record<string, PersonaStateValue>;
  commandHistory: string[];
  firstSeenAt: string;
  lastSeenAt: string;
};

export type AttackerProfile = {
  id: string;
  sourceIp: string;
  fingerprint: string;
  firstSeenAt: string;
  lastSeenAt: string;
  totalScore: number;
  risk: "low" | "medium" | "high";
  intent: AttackerIntent;
  intentCounts: Record<AttackerIntent, number>;
  counters: {
    connections: number;
    authAttempts: number;
    commands: number;
    uploads: number;
  };
  geo?: GeoResult;
  personaAssignments: Record<string, string>;
  personaAssignedAt: Record<string, string>;
  services: Partial<Record<ResponderServiceName, AttackerServiceMemory>>;
  recentEvents: string[];
};

export type InteractionAssessment = {
  scoreDelta: number;
  intents: AttackerIntent[];
};

export type MemoryPatch = {
  usernames?: string[];
  command?: string;
  files?: PersonaFile[];
  deviceState?: Record<string, PersonaStateValue>;
};

export type AttackerServiceResolution = {
  attacker: AttackerProfile;
  serviceMemory: AttackerServiceMemory;
  persona: DecoyPersona;
};

const runtimeDir = path.resolve("runtime");
const attackerStatePath = path.join(runtimeDir, "attackers.json");
const attackers = new Map<string, AttackerProfile>();
let hydrated = false;
let flushTimer: ReturnType<typeof setTimeout> | null = null;

const PERSONA_ROTATE_HOURS = parseInt(process.env.PERSONA_ROTATE_AFTER_HOURS || "0", 10);

function buildFingerprint(sourceIp: string) {
  return crypto.createHash("sha256").update(sourceIp).digest("hex");
}

function deriveRisk(score: number): "low" | "medium" | "high" {
  if (score >= 45) return "high";
  if (score >= 18) return "medium";
  return "low";
}

function deriveIntent(profile: AttackerProfile): AttackerIntent {
  if (profile.intentCounts.exploitation > 0) return "exploitation";
  if (profile.intentCounts.brute_force >= 2) return "brute_force";
  if (profile.intentCounts.recon > 0) return "recon";
  return "unknown";
}

function incrementCounters(profile: AttackerProfile, detail: string) {
  if (/connection opened/i.test(detail)) profile.counters.connections += 1;
  if (/(login|auth|password|username=|PASS |USER )/i.test(detail)) profile.counters.authAttempts += 1;
  if (/(cmd:|shell input=|exec command=|run\b|command)/i.test(detail)) profile.counters.commands += 1;
  if (/upload/i.test(detail)) profile.counters.uploads += 1;
}

export function assessInteraction(service: ResponderServiceName, detail: string): InteractionAssessment {
  const normalized = detail.toLowerCase();
  const intents = new Set<AttackerIntent>();
  let scoreDelta = 1;

  if (
    /(\.\.\/|union select|curl |wget |chmod |nc -e|\/etc\/passwd|powershell|cmd\.exe|upload|shell input=|exec command=)/i.test(
      normalized
    )
  ) {
    intents.add("exploitation");
    scoreDelta += 22;
  }

  if (/(login|auth|password|username=|authentication failed|PASS |USER )/i.test(normalized)) {
    intents.add("brute_force");
    scoreDelta += 10;
  }

  if (
    /(options|describe|play|setup|requested file listing|connection opened|initial negotiation|function=1|function=3|function=4|\/healthz|requested archive|payload=|requested camera frame|list|snmp-request)/i.test(
      normalized
    )
  ) {
    intents.add("recon");
    scoreDelta += 4;
  }

  if (service === "modbus" && /function=16|function=5|function=6/i.test(normalized)) {
    intents.add("exploitation");
    scoreDelta += 18;
  }

  return {
    scoreDelta,
    intents: intents.size === 0 ? ["unknown"] : Array.from(intents),
  };
}

function buildServiceMemory(persona: DecoyPersona, service: ResponderServiceName): AttackerServiceMemory {
  const overlay = persona.services[service];
  const now = new Date().toISOString();

  return {
    service,
    personaId: persona.id,
    personaGroup: persona.group,
    host: persona.host,
    banner: overlay?.banner || `${service.toUpperCase()} ready`,
    usernames: (overlay?.usernames || []).slice(),
    files: (overlay?.files || []).map((file) => ({ ...file })),
    deviceState: { ...(overlay?.deviceState || {}) },
    commandHistory: [],
    firstSeenAt: now,
    lastSeenAt: now,
  };
}

async function ensureRuntimeDir() {
  await fs.mkdir(runtimeDir, { recursive: true });
}

async function doFlush() {
  await ensureRuntimeDir();
  await fs.writeFile(attackerStatePath, JSON.stringify(Array.from(attackers.values()), null, 2), "utf8");
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    void doFlush();
  }, 500);
}

async function hydrate() {
  if (hydrated) return;
  await ensureRuntimeDir();
  try {
    const raw = await fs.readFile(attackerStatePath, "utf8");
    const parsed = JSON.parse(raw) as AttackerProfile[];
    for (const attacker of parsed) {
      // Back-fill personaAssignedAt if missing (older persisted state)
      if (!attacker.personaAssignedAt) {
        attacker.personaAssignedAt = {};
      }
      attackers.set(attacker.id, attacker);
    }
  } catch {
    // start clean
  }
  hydrated = true;
}

function isPersonaExpired(assignedAt: string): boolean {
  if (!PERSONA_ROTATE_HOURS) return false;
  const age = Date.now() - new Date(assignedAt).getTime();
  return age > PERSONA_ROTATE_HOURS * 3600 * 1000;
}

function getOrCreatePersonaAssignment(profile: AttackerProfile, service: ResponderServiceName) {
  const group = getPersonaGroupForService(service);
  const existing = profile.personaAssignments[group];
  const assignedAt = profile.personaAssignedAt[group];

  if (existing && assignedAt && !isPersonaExpired(assignedAt)) {
    return existing;
  }

  // Assign (or rotate) — use a time-salted seed so rotation produces a different pick
  const salt = PERSONA_ROTATE_HOURS
    ? Math.floor(Date.now() / (PERSONA_ROTATE_HOURS * 3600 * 1000)).toString()
    : "";
  const personaId = selectPersonaId(`${profile.fingerprint}${salt}`, service);
  profile.personaAssignments[group] = personaId;
  profile.personaAssignedAt[group] = new Date().toISOString();

  if (existing && existing !== personaId) {
    // Drop stale service memory when persona rotates
    delete profile.services[service];
  }

  return personaId;
}

function getPersonaOrThrow(personaId: string) {
  const persona = getPersonaById(personaId);
  if (!persona) throw new Error(`Unknown persona ${personaId}`);
  return persona;
}

async function getOrCreateAttacker(sourceIp: string) {
  await hydrate();
  const fingerprint = buildFingerprint(sourceIp);
  let profile = attackers.get(fingerprint);
  if (!profile) {
    const now = new Date().toISOString();
    profile = {
      id: fingerprint,
      sourceIp,
      fingerprint,
      firstSeenAt: now,
      lastSeenAt: now,
      totalScore: 0,
      risk: "low",
      intent: "unknown",
      intentCounts: { unknown: 0, recon: 0, brute_force: 0, exploitation: 0 },
      counters: { connections: 0, authAttempts: 0, commands: 0, uploads: 0 },
      personaAssignments: {},
      personaAssignedAt: {},
      services: {},
      recentEvents: [],
    };
    attackers.set(fingerprint, profile);

    // GeoIP lookup in the background; best-effort
    void lookupGeo(sourceIp).then((geo) => {
      if (geo && profile) {
        profile.geo = geo;
        scheduleFlush();
      }
    });
  }

  profile.lastSeenAt = new Date().toISOString();
  return profile;
}

export async function resolveAttackerService(
  sourceIp: string,
  service: ResponderServiceName
): Promise<AttackerServiceResolution> {
  const attacker = await getOrCreateAttacker(sourceIp);
  const personaId = getOrCreatePersonaAssignment(attacker, service);
  const persona = getPersonaOrThrow(personaId);

  if (!attacker.services[service]) {
    attacker.services[service] = buildServiceMemory(persona, service);
    scheduleFlush();
  }

  const serviceMemory = attacker.services[service] as AttackerServiceMemory;
  serviceMemory.lastSeenAt = new Date().toISOString();
  attacker.lastSeenAt = serviceMemory.lastSeenAt;

  return { attacker, serviceMemory, persona };
}

export async function updateAttackerMemory(params: {
  sourceIp: string;
  service: ResponderServiceName;
  detail: string;
  patch?: MemoryPatch;
}): Promise<AttackerServiceResolution & { assessment: InteractionAssessment }> {
  const { attacker, serviceMemory, persona } = await resolveAttackerService(params.sourceIp, params.service);
  const assessment = assessInteraction(params.service, params.detail);
  const now = new Date().toISOString();
  const previousRisk = attacker.risk;

  attacker.totalScore += assessment.scoreDelta;
  attacker.risk = deriveRisk(attacker.totalScore);
  for (const intent of assessment.intents) {
    attacker.intentCounts[intent] += 1;
  }
  attacker.intent = deriveIntent(attacker);
  attacker.lastSeenAt = now;
  attacker.recentEvents.push(`${now} ${sanitizeText(params.detail, serviceMemory.host, 256)}`);
  attacker.recentEvents = attacker.recentEvents.slice(-20);
  incrementCounters(attacker, params.detail);

  serviceMemory.lastSeenAt = now;
  if (params.patch?.usernames) {
    const merged = new Set([...serviceMemory.usernames, ...params.patch.usernames.filter(Boolean)]);
    serviceMemory.usernames = Array.from(merged).slice(0, 12);
  }
  if (params.patch?.command) {
    serviceMemory.commandHistory.push(sanitizeText(params.patch.command, serviceMemory.host, 180));
    serviceMemory.commandHistory = serviceMemory.commandHistory.slice(-10);
  }
  if (params.patch?.files) {
    serviceMemory.files = params.patch.files.map((file) => ({
      ...file,
      contents: sanitizeText(file.contents, serviceMemory.host, 2048),
    }));
  }
  if (params.patch?.deviceState) {
    serviceMemory.deviceState = { ...serviceMemory.deviceState, ...params.patch.deviceState };
  }

  scheduleFlush();

  // Fire alert if risk escalated (non-blocking)
  void maybeFireAlert({
    attackerId: attacker.id,
    sourceIp: attacker.sourceIp,
    risk: attacker.risk,
    previousRisk,
    intent: attacker.intent,
    score: attacker.totalScore,
    services: Object.keys(attacker.services),
    recentEvents: attacker.recentEvents,
    highlights: summarizeAttacker(attacker),
  });

  return { attacker, serviceMemory, persona, assessment };
}

/** Aggregate a profile's captured activity into a plain-language summary. */
export function summarizeAttacker(profile: AttackerProfile): ActivitySummary {
  const usernames = new Set<string>();
  const commands: string[] = [];
  for (const svc of Object.values(profile.services)) {
    if (!svc) continue;
    for (const u of svc.usernames || []) usernames.add(u);
    for (const c of svc.commandHistory || []) commands.push(c);
  }
  const input: ActivityInput = {
    events: profile.recentEvents,
    counters: profile.counters,
    usernames: Array.from(usernames),
    commands,
    services: Object.keys(profile.services),
  };
  return summarizeActivity(input);
}

export async function listAttackers(): Promise<AttackerProfile[]> {
  await hydrate();
  return Array.from(attackers.values()).sort((a, b) => b.lastSeenAt.localeCompare(a.lastSeenAt));
}

export async function getAttackerById(attackerId: string) {
  await hydrate();
  return attackers.get(attackerId);
}
