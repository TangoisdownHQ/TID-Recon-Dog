import fs from "fs/promises";
import path from "path";

const runtimeDir = path.resolve("runtime");
const logDir = path.resolve("logs");
const logFilePath = path.join(logDir, "connections.log");
const sessionSnapshotPath = path.join(runtimeDir, "sessions.json");

export type LogLevel = "info" | "warn" | "error";

export type SessionSnapshot = {
  id: string;
  service: string;
  ip: string;
  status: string;
  currentAction: string;
  firstSeenAt: string;
  lastSeenAt: string;
  attackerId?: string;
  intent?: string;
  score?: number;
  personaId?: string;
  events: string[];
  metadata?: Record<string, string>;
};

async function ensureRuntimePaths() {
  await fs.mkdir(logDir, { recursive: true });
  await fs.mkdir(runtimeDir, { recursive: true });
}

async function appendLine(line: string) {
  await ensureRuntimePaths();
  await fs.appendFile(logFilePath, `${line}\n`, "utf8");
}

export async function writeLog(
  level: LogLevel,
  service: string,
  ip: string,
  details: string,
  metadata?: Record<string, unknown>
) {
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    service,
    ip,
    details,
    metadata,
  };

  await appendLine(JSON.stringify(entry));
}

export async function logInteraction(
  service: string,
  ip: string,
  details: string,
  metadata?: Record<string, unknown>
) {
  await writeLog("info", service, ip, details, metadata);
}

export async function logWarning(
  service: string,
  ip: string,
  details: string,
  metadata?: Record<string, unknown>
) {
  await writeLog("warn", service, ip, details, metadata);
}

export async function logError(
  service: string,
  ip: string,
  details: string,
  metadata?: Record<string, unknown>
) {
  await writeLog("error", service, ip, details, metadata);
}

export async function persistSessions(sessions: SessionSnapshot[]) {
  await ensureRuntimePaths();
  await fs.writeFile(sessionSnapshotPath, JSON.stringify(sessions, null, 2), "utf8");
}

export async function readSessionSnapshots(): Promise<SessionSnapshot[]> {
  try {
    const raw = await fs.readFile(sessionSnapshotPath, "utf8");
    return JSON.parse(raw) as SessionSnapshot[];
  } catch {
    return [];
  }
}

export async function readLogEntries(): Promise<Array<Record<string, unknown>>> {
  try {
    const raw = await fs.readFile(logFilePath, "utf8");
    return raw
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .flatMap((line) => {
        try {
          return [JSON.parse(line) as Record<string, unknown>];
        } catch {
          return [];
        }
      });
  } catch {
    return [];
  }
}

export function formatConsole(message: string) {
  return `[${new Date().toISOString()}] ${message}`;
}
