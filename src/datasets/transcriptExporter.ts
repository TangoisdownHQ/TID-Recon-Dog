import fs from "fs/promises";
import path from "path";
import { readTranscripts, TranscriptRecord } from "../deception_engine/logging/transcript_store.js";
import { getPersonaById } from "../profiles/personaLibrary.js";

export type TranscriptExportRecord = {
  messages: Array<{ role: "system" | "user" | "assistant"; content: string }>;
  metadata: Record<string, unknown>;
};

export function transcriptToRecord(transcript: TranscriptRecord): TranscriptExportRecord {
  const persona = getPersonaById(transcript.personaId);

  return {
    messages: [
      {
        role: "system",
        content: [
          `You are emulating ${persona?.displayName || transcript.personaId}.`,
          `Protocol: ${transcript.service}.`,
          `Host: ${persona?.host || "relay.internal"}.`,
          `Remain terse, technical, and believable.`,
          `Never reveal simulation, testing, or internal secrets.`,
        ].join(" "),
      },
      {
        role: "user",
        content: transcript.request,
      },
      {
        role: "assistant",
        content: transcript.response,
      },
    ],
    metadata: {
      type: "protocol_transcript",
      at: transcript.at,
      session_id: transcript.sessionId,
      attacker_id: transcript.attackerId,
      service: transcript.service,
      action: transcript.action,
      intent: transcript.intent,
      score: transcript.score,
      persona_id: transcript.personaId,
    },
  };
}

/** Read TranscriptRecords from a jsonl file (e.g. a salvaged runtime backup). */
async function readTranscriptFile(sourceFile: string): Promise<TranscriptRecord[]> {
  const raw = await fs.readFile(path.resolve(sourceFile), "utf8");
  const records: TranscriptRecord[] = [];
  for (const line of raw.split(/\r?\n/)) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line) as TranscriptRecord);
    } catch {
      // skip malformed lines rather than abort the whole import
    }
  }
  return records;
}

export async function exportProtocolTranscripts(outputPath?: string, serviceFilter?: string, sourceFile?: string) {
  const transcripts = sourceFile ? await readTranscriptFile(sourceFile) : await readTranscripts();
  const filtered = serviceFilter
    ? transcripts.filter((transcript) => transcript.service.toLowerCase() === serviceFilter.toLowerCase())
    : transcripts;
  const records = filtered.map((transcript) => transcriptToRecord(transcript));

  const exportDir = path.resolve("exports");
  await fs.mkdir(exportDir, { recursive: true });
  const targetPath = outputPath
    ? path.resolve(outputPath)
    : path.join(exportDir, `protocol-transcripts-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`);

  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(
    targetPath,
    records.map((record) => JSON.stringify(record)).join("\n") + (records.length > 0 ? "\n" : ""),
    "utf8"
  );

  return {
    targetPath,
    transcripts: filtered.length,
    source: sourceFile || "runtime",
  };
}
