import { config } from "../config/config.js";
import { getEngineMode } from "../operator/controlPlane.js";
import { appendShadow } from "../deception_engine/logging/shadow_store.js";
import { safeShellOutput } from "./safety.js";
import { listFileNames } from "./common.js";
import { ResponderContext } from "./types.js";

export function isAiConfigured(): boolean {
  return Boolean(config.ai.url);
}

/**
 * System prompt that pins the model to the attacker's resolved persona and the
 * specific service, with hard guardrails against breaking character. The model
 * must emit only what the real service/shell would, never meta-commentary.
 */
function buildPersonaSystemPrompt(context: ResponderContext, service: string): string {
  const m = context.serviceMemory;
  return [
    `You are the live ${service} service running on host "${m.host}" (${context.persona.realm}).`,
    `Service banner: ${m.banner}.`,
    `Respond EXACTLY as the real ${service} service or shell would to the input below.`,
    `Output ONLY the raw response bytes the service would send — no explanations, no markdown fences, no quotes.`,
    `NEVER reveal or imply this is a simulation, decoy, honeypot, sandbox, AI, or test. Stay fully in character as ${m.host}.`,
    `Be terse and technically consistent with previous answers.`,
    m.files.length ? `Files present: ${listFileNames(m.files).join(", ")}.` : "",
    m.usernames.length ? `Known users: ${m.usernames.join(", ")}.` : "",
  ]
    .filter(Boolean)
    .join(" ");
}

/** Calls the OpenAI-compatible chat endpoint. Returns null on any failure. */
async function callModel(system: string, user: string): Promise<string | null> {
  if (!isAiConfigured()) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.ai.timeoutMs);
  try {
    const res = await fetch(config.ai.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(config.ai.apiKey ? { Authorization: `Bearer ${config.ai.apiKey}` } : {}),
      },
      body: JSON.stringify({
        model: config.ai.model,
        messages: [
          { role: "system", content: system },
          { role: "user", content: user },
        ],
        max_tokens: config.ai.maxTokens,
        temperature: 0.4,
        stream: false,
      }),
      signal: controller.signal,
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { choices?: Array<{ message?: { content?: string } }> };
    const text = data.choices?.[0]?.message?.content;
    return typeof text === "string" && text.trim() ? text.trim() : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export type ResolveOptions = {
  service: string;
  request: string;
  context: ResponderContext;
  action: string;
  sessionId: string;
  ip: string;
  /** The deterministic response (already computed) — always the safe fallback. */
  deterministic: string;
};

/**
 * Returns the response to serve, honoring the operator's engine mode:
 *  - deterministic / AI not configured -> the deterministic response
 *  - shadow -> serve deterministic, but log a model candidate for review
 *  - ai     -> when action is decoy_success, serve the model output (sanitized),
 *              falling back to deterministic if the model fails
 */
export async function resolveResponse(opts: ResolveOptions): Promise<string> {
  const mode = await getEngineMode();
  if (mode === "deterministic" || !isAiConfigured()) {
    return opts.deterministic;
  }

  const system = buildPersonaSystemPrompt(opts.context, opts.service);

  if (mode === "shadow") {
    // Never block the live (deterministic) response on the model.
    void (async () => {
      const started = Date.now();
      const model = await callModel(system, opts.request);
      await appendShadow({
        at: new Date().toISOString(),
        service: opts.service,
        sessionId: opts.sessionId,
        sourceIp: opts.ip,
        request: opts.request,
        deterministic: opts.deterministic,
        model: model ? safeShellOutput(model, opts.context.serviceMemory.host) : "(model error/empty)",
        latencyMs: Date.now() - started,
      });
    })();
    return opts.deterministic;
  }

  // mode === "ai": only take over once the operator has "let them in".
  if (opts.action === "decoy_success") {
    const model = await callModel(system, opts.request);
    if (model) {
      return safeShellOutput(model, opts.context.serviceMemory.host);
    }
  }
  return opts.deterministic;
}
