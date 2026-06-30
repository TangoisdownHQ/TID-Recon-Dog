import fs from "fs";
import path from "path";

const rawDatasetPath = path.resolve("ct", "datasets", "raw_interactions.jsonl");

export function collectTrainingSample(sample: unknown) {
  fs.mkdirSync(path.dirname(rawDatasetPath), { recursive: true });
  fs.appendFileSync(rawDatasetPath, `${JSON.stringify(sample)}\n`, "utf8");
}
