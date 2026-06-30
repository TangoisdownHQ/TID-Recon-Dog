import fs from "fs/promises";
import path from "path";

const runtimeDir = path.resolve("runtime");
const shadowPath = path.join(runtimeDir, "shadow.jsonl");

export type ShadowRecord = {
  at: string;
  service: string;
  sessionId: string;
  sourceIp: string;
  request: string;
  deterministic: string;
  model: string;
  latencyMs: number;
};

export async function appendShadow(record: ShadowRecord) {
  try {
    await fs.mkdir(runtimeDir, { recursive: true });
    await fs.appendFile(shadowPath, `${JSON.stringify(record)}\n`, "utf8");
  } catch {
    // best-effort; shadow logging must never break a live response
  }
}

export async function readShadow(limit = 100): Promise<ShadowRecord[]> {
  try {
    const raw = await fs.readFile(shadowPath, "utf8");
    return raw
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean)
      .slice(-limit)
      .reverse()
      .flatMap((l) => {
        try {
          return [JSON.parse(l) as ShadowRecord];
        } catch {
          return [];
        }
      });
  } catch {
    return [];
  }
}
