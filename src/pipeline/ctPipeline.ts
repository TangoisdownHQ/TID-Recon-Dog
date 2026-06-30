import fs from "fs/promises";
import path from "path";

export type CtManifest = {
  version: number;
  created_at: string;
  base_model: string;
  adapter_type: "lora";
  corpus_path: string;
  train_split: number;
  eval_split: number;
  output_dir: string;
  eval_suite_path: string;
  verification: {
    min_eval_examples: number;
    require_no_prompt_leakage: boolean;
    require_protocol_banner_match: boolean;
    max_hallucinated_disclosure_rate: number;
  };
  deployment: {
    strategy: "promote_after_verification";
    current_adapter_path: string;
    candidate_adapter_path: string;
    healthcheck_command: string;
  };
  stages: Array<{
    name: string;
    owner: string;
    action: string;
  }>;
};

export async function generateCtManifest(outputPath?: string, corpusPath?: string) {
  const ctDir = path.resolve("ct");
  await fs.mkdir(ctDir, { recursive: true });

  const manifest: CtManifest = {
    version: 1,
    created_at: new Date().toISOString(),
    base_model: "mistralai/Mistral-7B-Instruct-v0.3",
    adapter_type: "lora",
    corpus_path: path.resolve(corpusPath || "exports/latest-corpus.jsonl"),
    train_split: 0.9,
    eval_split: 0.1,
    output_dir: path.resolve("ct/artifacts"),
    eval_suite_path: path.resolve("ct/eval/suite.jsonl"),
    verification: {
      min_eval_examples: 100,
      require_no_prompt_leakage: true,
      require_protocol_banner_match: true,
      max_hallucinated_disclosure_rate: 0.01,
    },
    deployment: {
      strategy: "promote_after_verification",
      current_adapter_path: path.resolve("ct/deploy/current"),
      candidate_adapter_path: path.resolve("ct/deploy/candidate"),
      healthcheck_command: "node dist/index.js profiles",
    },
    stages: [
      {
        name: "ingest",
        owner: "dataset-agent",
        action: "merge local captures and external datasets into JSONL corpus",
      },
      {
        name: "split",
        owner: "training-agent",
        action: "create train/eval partitions with service-family balancing",
      },
      {
        name: "train",
        owner: "training-agent",
        action: "run LoRA adapter training on the candidate corpus",
      },
      {
        name: "verify",
        owner: "verification-agent",
        action: "check banner fidelity, deception leakage, and protocol-style responses",
      },
      {
        name: "deploy",
        owner: "deployment-agent",
        action: "promote the verified adapter and restart inference only after health checks pass",
      },
    ],
  };

  const targetPath = path.resolve(outputPath || "ct/manifest.json");
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.writeFile(targetPath, JSON.stringify(manifest, null, 2), "utf8");
  return { targetPath, manifest };
}
