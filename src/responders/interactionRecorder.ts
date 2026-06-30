import { appendTranscript } from "../deception_engine/logging/transcript_store.js";
import { upsertSession } from "../deception_engine/session/session_manager.js";
import { updateAttackerMemory } from "../deception_engine/state/attacker_memory.js";
import { logInteraction } from "../utils/logger.js";
import { normalizeServiceName } from "./serviceNames.js";
import { sanitizeMetadata, sanitizeText } from "./safety.js";
import { forwardEvent } from "../cti/forward.js";
import { evaluatePlaybooks } from "../operator/playbooks.js";

export async function recordInteractionEvent(params: {
  sessionId: string;
  service: string;
  ip: string;
  detail: string;
  currentAction?: string;
  metadata?: Record<string, unknown>;
  request?: string;
  response?: string;
  patch?: {
    usernames?: string[];
    command?: string;
    files?: Array<{ path: string; contents: string; modifiedAt: string }>;
    deviceState?: Record<string, string | number | boolean>;
  };
}) {
  const normalizedService = normalizeServiceName(params.service);
  const resolution = await updateAttackerMemory({
    sourceIp: params.ip,
    service: normalizedService,
    detail: params.detail,
    patch: params.patch,
  });

  const safeDetail = sanitizeText(params.detail, resolution.serviceMemory.host, 512);
  const safeMetadata = sanitizeMetadata(params.metadata, resolution.serviceMemory.host);
  const sessionMetadata = {
    ...(safeMetadata || {}),
    attackerId: resolution.attacker.id,
    personaId: resolution.persona.id,
    host: resolution.serviceMemory.host,
    banner: resolution.serviceMemory.banner,
    intent: resolution.attacker.intent,
    risk: resolution.attacker.risk,
    score: resolution.attacker.totalScore,
  };

  await upsertSession({
    id: params.sessionId,
    service: params.service.toUpperCase(),
    ip: params.ip,
    detail: safeDetail,
    currentAction: params.currentAction || "allow",
    attackerId: resolution.attacker.id,
    intent: resolution.attacker.intent,
    score: resolution.attacker.totalScore,
    personaId: resolution.persona.id,
    metadata: Object.fromEntries(
      Object.entries(sessionMetadata).map(([key, value]) => [key, String(value)])
    ),
  });

  await logInteraction(params.service.toUpperCase(), params.ip, safeDetail, {
    sessionId: params.sessionId,
    action: params.currentAction || "allow",
    attackerId: resolution.attacker.id,
    personaId: resolution.persona.id,
    intent: resolution.attacker.intent,
    risk: resolution.attacker.risk,
    score: resolution.attacker.totalScore,
    ...(safeMetadata || {}),
  });

  if (params.request || params.response) {
    await appendTranscript({
      id: `${params.sessionId}:${Date.now()}`,
      at: new Date().toISOString(),
      sessionId: params.sessionId,
      attackerId: resolution.attacker.id,
      service: params.service.toUpperCase(),
      sourceIp: params.ip,
      action: params.currentAction || "allow",
      intent: resolution.attacker.intent,
      score: resolution.attacker.totalScore,
      personaId: resolution.persona.id,
      request: sanitizeText(params.request || safeDetail, resolution.serviceMemory.host, 2048),
      response: sanitizeText(params.response || "", resolution.serviceMemory.host, 2048),
      metadata: safeMetadata,
    });
  }

  // Auto-response playbooks: may block/tarpit/decoy/alert based on this event.
  void evaluatePlaybooks(
    {
      sessionId: params.sessionId,
      sourceIp: params.ip,
      service: params.service.toUpperCase(),
      intent: resolution.attacker.intent,
      risk: resolution.attacker.risk,
      score: resolution.attacker.totalScore,
      detail: safeDetail,
    },
    (hit) =>
      void logInteraction("PLAYBOOK", params.ip, `rule fired: ${hit.rule} -> ${hit.action}`, {
        sessionId: params.sessionId,
        attackerId: resolution.attacker.id,
      })
  );

  // Forward to SIEM / webhook / Splunk (best-effort, only if configured).
  forwardEvent({
    at: new Date().toISOString(),
    service: params.service.toUpperCase(),
    sourceIp: params.ip,
    intent: resolution.attacker.intent,
    risk: resolution.attacker.risk,
    score: resolution.attacker.totalScore,
    action: params.currentAction || "allow",
    detail: safeDetail,
  });

  return resolution;
}
