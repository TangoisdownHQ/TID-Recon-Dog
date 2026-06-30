import fs from "fs/promises";
import path from "path";

type EvalCase = {
  id: string;
  service: string;
  prompt: string;
};

type EvalResponse = {
  id: string;
  response: string;
};

async function callModel(prompt: string): Promise<string> {
  const provider = process.env.EVAL_PROVIDER || "ollama";
  const model = process.env.EVAL_MODEL || (provider === "ollama" ? "llama3" : "claude-haiku-4-5-20251001");

  if (provider === "ollama") {
    const apiUrl = process.env.EVAL_API_URL || "http://localhost:11434/api/generate";
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await fetch(apiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model, prompt, stream: false }),
        signal: controller.signal,
      });
      clearTimeout(tid);
      const data = await response.json() as { response?: string };
      return (data.response || "").trim();
    } finally {
      clearTimeout(tid);
    }
  }

  if (provider === "anthropic") {
    const apiUrl = process.env.EVAL_API_URL || "https://api.anthropic.com/v1/messages";
    const apiKey = process.env.ANTHROPIC_API_KEY || process.env.EVAL_API_KEY || "";
    if (!apiKey) throw new Error("ANTHROPIC_API_KEY not set for anthropic eval provider");
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 45000);
    try {
      const response = await fetch(apiUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model,
          max_tokens: 256,
          messages: [{ role: "user", content: prompt }],
        }),
        signal: controller.signal,
      });
      clearTimeout(tid);
      const data = await response.json() as { content?: Array<{ text: string }> };
      return (data.content?.[0]?.text || "").trim();
    } finally {
      clearTimeout(tid);
    }
  }

  // OpenAI-compatible fallback
  const apiUrl = process.env.EVAL_API_URL || "https://api.openai.com/v1/chat/completions";
  const apiKey = process.env.EVAL_API_KEY || "";
  const controller = new AbortController();
  const tid = setTimeout(() => controller.abort(), 45000);
  try {
    const response = await fetch(apiUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        max_tokens: 256,
        messages: [{ role: "user", content: prompt }],
      }),
      signal: controller.signal,
    });
    clearTimeout(tid);
    const data = await response.json() as { choices?: Array<{ message: { content: string } }> };
    return (data.choices?.[0]?.message?.content || "").trim();
  } finally {
    clearTimeout(tid);
  }
}

export async function runEvalSuite(suitePath?: string, outputPath?: string) {
  const resolvedSuitePath = path.resolve(suitePath || path.join("ct", "eval", "suite.jsonl"));
  const resolvedOutputPath = path.resolve(outputPath || path.join("ct", "eval", "responses.jsonl"));

  let suiteLines: string[];
  try {
    const raw = await fs.readFile(resolvedSuitePath, "utf8");
    suiteLines = raw.split("\n").map((l) => l.trim()).filter(Boolean);
  } catch {
    throw new Error(`Eval suite not found at ${resolvedSuitePath}. Run export-eval-suite first.`);
  }

  const cases = suiteLines.map((line) => JSON.parse(line) as EvalCase);
  const responses: EvalResponse[] = [];
  const provider = process.env.EVAL_PROVIDER || "ollama";
  const model = process.env.EVAL_MODEL || (provider === "ollama" ? "llama3" : "claude-haiku-4-5-20251001");

  console.log(`Running ${cases.length} eval cases against ${provider}/${model}`);

  for (const evalCase of cases) {
    process.stdout.write(`  ${evalCase.id}...`);
    try {
      const response = await callModel(evalCase.prompt);
      responses.push({ id: evalCase.id, response });
      process.stdout.write(" ok\n");
    } catch (error) {
      process.stdout.write(` failed: ${String(error)}\n`);
      responses.push({ id: evalCase.id, response: "" });
    }
  }

  await fs.mkdir(path.dirname(resolvedOutputPath), { recursive: true });
  await fs.writeFile(
    resolvedOutputPath,
    responses.map((r) => JSON.stringify(r)).join("\n") + "\n",
    "utf8"
  );

  return { targetPath: resolvedOutputPath, cases: responses.length };
}
