import fs from "fs/promises";
import path from "path";

const runtimeDir = path.resolve("runtime");
const transcriptPath = path.join(runtimeDir, "transcripts.jsonl");

export type TranscriptRecord = {
  id: string;
  at: string;
  sessionId: string;
  attackerId: string;
  service: string;
  sourceIp: string;
  action: string;
  intent: string;
  score: number;
  personaId: string;
  request: string;
  response: string;
  metadata?: Record<string, unknown>;
};

// Keep transcripts.jsonl bounded. It's append-only and every operator read
// (feed, IOC engine, metrics) parses the whole file — left unbounded it grew to
// megabytes under live scanner traffic and saturated the event loop. We retain
// the most recent MAX_TRANSCRIPTS lines and trim periodically (not every append,
// to avoid rewrite churn).
const MAX_TRANSCRIPTS = parseInt(process.env.MAX_TRANSCRIPTS || "3000", 10);
const TRIM_EVERY = 250;
let appendsSinceTrim = 0;

async function ensureRuntimeDir() {
  await fs.mkdir(runtimeDir, { recursive: true });
}

async function trimTranscripts() {
  try {
    const raw = await fs.readFile(transcriptPath, "utf8");
    const lines = raw.split(/\r?\n/).filter((l) => l.trim());
    if (lines.length <= MAX_TRANSCRIPTS) return;
    const kept = lines.slice(-MAX_TRANSCRIPTS).join("\n") + "\n";
    await fs.writeFile(transcriptPath, kept, "utf8");
  } catch {
    // best-effort; never break the write path
  }
}

export async function appendTranscript(record: TranscriptRecord) {
  await ensureRuntimeDir();
  await fs.appendFile(transcriptPath, `${JSON.stringify(record)}\n`, "utf8");
  if (++appendsSinceTrim >= TRIM_EVERY) {
    appendsSinceTrim = 0;
    await trimTranscripts();
  }
}

export async function readTranscripts(): Promise<TranscriptRecord[]> {
  try {
    const raw = await fs.readFile(transcriptPath, "utf8");
    return raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line) as TranscriptRecord);
  } catch {
    return [];
  }
}
