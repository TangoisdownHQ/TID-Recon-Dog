import fs from "fs/promises";
import path from "path";

const logPath = path.resolve("logs", "interactions.log");

export async function logInteraction(entry: Record<string, unknown>): Promise<void> {
  try {
    await fs.mkdir(path.dirname(logPath), { recursive: true });
    await fs.appendFile(logPath, `${JSON.stringify(entry)}\n`, "utf8");
  } catch {
    // best-effort; never throw from logger
  }
}
