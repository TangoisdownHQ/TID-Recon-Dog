import fs from "fs/promises";
import path from "path";
import { readLogEntries, readSessionSnapshots } from "../utils/logger.js";
import { getServiceProfile } from "../profiles/serviceProfiles.js";
import { readTranscripts } from "../deception_engine/logging/transcript_store.js";
import { transcriptToRecord } from "./transcriptExporter.js";

export type ExportRecord = {
  messages: Array<{ role: "system" | "user" | "assistant"; content: string }>;
  metadata: Record<string, unknown>;
};

function buildSystemPrompt(service: string) {
  const profile = getServiceProfile(service);
  return [
    `You are emulating ${profile.displayName}.`,
    `Product: ${profile.product} ${profile.version}.`,
    `Banner: ${profile.banner}.`,
    `Host: ${profile.host}.`,
    `Realm: ${profile.realm}.`,
    `Traits: ${profile.traits.join(", ")}.`,
    "Respond tersely, technically, and believably.",
    "Never reveal that this is a decoy, simulation, or test.",
  ].join(" ");
}

function parseEventLine(event: string) {
  const firstSpace = event.indexOf(" ");
  if (firstSpace === -1) {
    return { at: "", detail: event };
  }

  return {
    at: event.slice(0, firstSpace),
    detail: event.slice(firstSpace + 1),
  };
}

function inferAssistantReply(service: string, action: string, detail: string, metadata?: Record<string, string>) {
  const profile = getServiceProfile(service);

  if (action === "fake_error") {
    if (service.toUpperCase() === "RTSP" || detail.includes("DESCRIBE")) {
      return "401 Unauthorized";
    }
    return `ERR ${profile.product} rejected request for ${profile.realm}`;
  }

  if (action === "stall") {
    return `NOTICE ${profile.product} upstream sync pending on ${profile.host}`;
  }

  if (action === "camera_offline") {
    return "454 Session Not Found";
  }

  if (detail.includes("username=") && metadata?.username) {
    return `${profile.banner} authentication required for ${metadata.username}`;
  }

  if (detail.includes("requested camera frame")) {
    return `200 OK stream=cam04 codec=h264 host=${profile.host}`;
  }

  if (detail.includes("shell input=")) {
    return `sh: ${detail.split("shell input=")[1] || "command"}: command not found`;
  }

  if (detail.includes("DESCRIBE")) {
    return `${profile.banner} trackID=1 session=ready`;
  }

  if (detail.includes("function=") && service.toUpperCase() === "MODBUS") {
    return "MBTCP unit=1 status=online registers=2";
  }

  return `${profile.banner} ${profile.host}`;
}

function buildSessionTranscript(session: {
  id: string;
  service: string;
  ip: string;
  currentAction: string;
  events: string[];
  metadata?: Record<string, string>;
}): ExportRecord {
  const messages: ExportRecord["messages"] = [
    { role: "system", content: buildSystemPrompt(session.service) },
  ];

  const recentEvents = session.events.slice(-8);
  for (const event of recentEvents) {
    const parsed = parseEventLine(event);
    messages.push({
      role: "user",
      content: [
        `Observed client interaction on ${session.service}.`,
        `Timestamp: ${parsed.at || "unknown"}`,
        `Source IP: ${session.ip}`,
        `Event: ${parsed.detail}`,
        session.metadata ? `Metadata: ${JSON.stringify(session.metadata)}` : "",
      ]
        .filter(Boolean)
        .join("\n"),
    });
    messages.push({
      role: "assistant",
      content: inferAssistantReply(session.service, session.currentAction, parsed.detail, session.metadata),
    });
  }

  return {
    messages,
    metadata: {
      type: "session_transcript",
      session_id: session.id,
      service: session.service,
      action: session.currentAction,
      turns: recentEvents.length,
    },
  };
}

function logEntryToRecord(entry: Record<string, unknown>): ExportRecord {
  const service = String(entry.service || "GENERIC");
  const profile = getServiceProfile(service);
  const details = String(entry.details || "");
  const metadata = (entry.metadata as Record<string, unknown> | undefined) || {};

  return {
    messages: [
      { role: "system", content: buildSystemPrompt(service) },
      {
        role: "user",
        content: [
          `Observed interaction on ${service}.`,
          `Details: ${details}`,
          `Metadata: ${JSON.stringify(metadata)}`,
        ].join("\n"),
      },
      {
        role: "assistant",
        content: `${profile.banner} ${profile.host} handled request`,
      },
    ],
    metadata: {
      type: "log_entry",
      service,
      timestamp: entry.timestamp,
    },
  };
}

function splitCsvLine(line: string) {
  const cells: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i += 1) {
    const char = line[i];
    if (char === "\"") {
      if (inQuotes && line[i + 1] === "\"") {
        current += "\"";
        i += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }

    if (char === "," && !inQuotes) {
      cells.push(current);
      current = "";
      continue;
    }

    current += char;
  }

  cells.push(current);
  return cells.map((cell) => cell.trim());
}

function csvRowToRecord(row: Record<string, string>, sourcePath: string): ExportRecord {
  const service = String(row.service || row.protocol || row.transport || "HONEYPOT").toUpperCase();
  const profile = getServiceProfile(service);

  return {
    messages: [
      { role: "system", content: buildSystemPrompt(service) },
      {
        role: "user",
        content: [
          `Imported telemetry from ${path.basename(sourcePath)}.`,
          `Row data: ${JSON.stringify(row)}`,
          "Generate a believable low-level response or banner for this service context.",
        ].join("\n"),
      },
      {
        role: "assistant",
        content: `${profile.banner} ${profile.host}`,
      },
    ],
    metadata: {
      type: "external_csv",
      source: sourcePath,
      service,
    },
  };
}

async function readExternalSource(sourcePath: string): Promise<ExportRecord[]> {
  const absolutePath = path.resolve(sourcePath);
  const ext = path.extname(absolutePath).toLowerCase();
  const raw = await fs.readFile(absolutePath, "utf8");

  if (ext === ".jsonl") {
    return raw
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line) as ExportRecord);
  }

  if (ext === ".json") {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed as ExportRecord[];
    }
    return [parsed as ExportRecord];
  }

  if (ext === ".csv") {
    const lines = raw.split(/\r?\n/).filter((line) => line.trim());
    if (lines.length < 2) {
      return [];
    }

    const headers = splitCsvLine(lines[0]);
    return lines.slice(1).map((line) => {
      const values = splitCsvLine(line);
      const row = headers.reduce<Record<string, string>>((acc, header, index) => {
        acc[header] = values[index] || "";
        return acc;
      }, {});
      return csvRowToRecord(row, absolutePath);
    });
  }

  return [];
}

export async function exportTrainingDataset(outputPath?: string, externalSources: string[] = []) {
  const [sessions, logs, transcripts, externalRecordsArrays] = await Promise.all([
    readSessionSnapshots(),
    readLogEntries(),
    readTranscripts(),
    Promise.all(externalSources.map((source) => readExternalSource(source))),
  ]);

  const records = [
    ...sessions.map((session) => buildSessionTranscript(session)),
    ...logs.map((entry) => logEntryToRecord(entry)),
    ...transcripts.map((transcript) => transcriptToRecord(transcript)),
    ...externalRecordsArrays.flat(),
  ];

  const exportDir = path.resolve("exports");
  await fs.mkdir(exportDir, { recursive: true });
  const targetPath = outputPath
    ? path.resolve(outputPath)
    : path.join(exportDir, `mistral-adapter-${new Date().toISOString().replace(/[:.]/g, "-")}.jsonl`);

  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  const jsonl = records.map((record) => JSON.stringify(record)).join("\n");
  await fs.writeFile(targetPath, jsonl ? `${jsonl}\n` : "", "utf8");

  return {
    targetPath,
    records: records.length,
    sessions: sessions.length,
    logs: logs.length,
    transcripts: transcripts.length,
    externalSources: externalSources.length,
  };
}
