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

async function ensureRuntimeDir() {
  await fs.mkdir(runtimeDir, { recursive: true });
}

export async function appendTranscript(record: TranscriptRecord) {
  await ensureRuntimeDir();
  await fs.appendFile(transcriptPath, `${JSON.stringify(record)}\n`, "utf8");
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
