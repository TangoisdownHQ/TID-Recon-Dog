// Captured attacker payloads (file uploads). We keep the bytes, hash them, and
// index metadata so an operator can see what was dropped, dedupe by SHA-256, and
// (out of band) submit hashes to a sandbox/VT. Bounded like the other stores.
import fs from "fs/promises";
import crypto from "crypto";
import path from "path";

const runtimeDir = path.resolve("runtime");
const indexPath = path.join(runtimeDir, "payloads.jsonl");
const MAX_PAYLOADS = parseInt(process.env.MAX_PAYLOADS || "2000", 10);

export type PayloadRecord = {
  at: string;
  sha256: string;
  size: number;
  originalName: string;
  service: string;
  sourceIp: string;
  sessionId: string;
  storedPath: string; // path within the uploads volume
};

/** Hash a saved upload and append a metadata record. Returns the record. */
export async function recordPayload(params: {
  filePath: string;
  originalName: string;
  service: string;
  sourceIp: string;
  sessionId: string;
}): Promise<PayloadRecord | null> {
  try {
    const buf = await fs.readFile(params.filePath);
    const sha256 = crypto.createHash("sha256").update(buf).digest("hex");
    const rec: PayloadRecord = {
      at: new Date().toISOString(),
      sha256,
      size: buf.length,
      originalName: params.originalName.slice(0, 200),
      service: params.service,
      sourceIp: params.sourceIp,
      sessionId: params.sessionId,
      storedPath: path.basename(params.filePath),
    };
    await fs.mkdir(runtimeDir, { recursive: true });
    await fs.appendFile(indexPath, `${JSON.stringify(rec)}\n`, "utf8");
    return rec;
  } catch {
    return null;
  }
}

export async function readPayloads(limit = 500): Promise<PayloadRecord[]> {
  try {
    const raw = await fs.readFile(indexPath, "utf8");
    const lines = raw.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    // Keep the file bounded.
    if (lines.length > MAX_PAYLOADS) {
      await fs.writeFile(indexPath, lines.slice(-MAX_PAYLOADS).join("\n") + "\n", "utf8");
    }
    return lines
      .slice(-limit)
      .reverse()
      .flatMap((l) => { try { return [JSON.parse(l) as PayloadRecord]; } catch { return []; } });
  } catch {
    return [];
  }
}
