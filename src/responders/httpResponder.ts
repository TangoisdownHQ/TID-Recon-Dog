import path from "path";
import { config } from "../config/config.js";
import { safeShellOutput, sanitizeText } from "./safety.js";
import { listFileNames, pickDeterministic, renderShellOutput } from "./common.js";
import { ResponderContext } from "./types.js";

export function applyHttpAction(action: string, context: ResponderContext, details: string) {
  if (action === "fake_error") {
    return {
      status: 503,
      body: `ERR relay=${context.serviceMemory.host} upstream appliance rejected request`,
    };
  }

  if (action === "decoy_success") {
    return {
      status: 200,
      body: `OK relay=${context.serviceMemory.host} accepted ${sanitizeText(details, context.serviceMemory.host, 180)}`,
    };
  }

  return null;
}

export function buildHttpHealth(context: ResponderContext) {
  return {
    status: "ok",
    service: "http",
    banner: context.serviceMemory.banner,
    relay_host: context.serviceMemory.host,
    camera_rtsp_url: buildRtspUrl(context),
    intent: context.attacker.intent,
  };
}

export function buildRtspUrl(context: ResponderContext) {
  const channel = String(context.serviceMemory.deviceState.channel || "401");
  return `rtsp://${context.serviceMemory.host}:${config.services.rtsp.port}/Streaming/Channels/${channel}`;
}

export function buildCameraMessage(context: ResponderContext, action: string, message?: string) {
  if (message) {
    return message;
  }
  if (action === "camera_offline") {
    return "Authentication relay accepted, but the selected feed is offline.";
  }
  return `RTSP endpoint: ${buildRtspUrl(context)}`;
}

export function buildCameraFrame(context: ResponderContext, sessionId: string) {
  return {
    session_id: sessionId,
    channel: String(context.serviceMemory.deviceState.channel || "cam04-loading-dock"),
    rtsp_url: buildRtspUrl(context),
    codec: String(context.serviceMemory.deviceState.codec || "h264"),
    status: String(context.serviceMemory.deviceState.status || "live"),
    ts: new Date().toISOString(),
    motion: String(context.serviceMemory.deviceState.motion || "clear"),
  };
}

export function buildCameraArchive(context: ResponderContext, archiveId: string) {
  const seed = `${context.attacker.id}:${archiveId}`;
  const events = ["motion", "door-open", "vehicle-enter", "tamper"];
  return {
    archive_id: archiveId,
    relay_host: context.serviceMemory.host,
    clips: [0, 1, 2].map((offset) => ({
      started_at: new Date(Date.UTC(2026, 3, 15, 6 - offset, 10 + offset * 3, 22 - offset)).toISOString(),
      duration_seconds: 12 + offset * 11,
      event: pickDeterministic(`${seed}:${offset}`, events),
    })),
  };
}

export function listHttpFiles(context: ResponderContext) {
  return listFileNames(context.serviceMemory.files);
}

export function findHttpFile(context: ResponderContext, filename: string) {
  return context.serviceMemory.files.find((file) => path.basename(file.path) === filename || file.path === filename);
}

export function buildHttpShellOutput(command: string, context: ResponderContext) {
  return safeShellOutput(renderShellOutput(command, context), context.serviceMemory.host);
}

export function buildCatchAllResponse(method: string, originalUrl: string, userAgent: string, context: ResponderContext) {
  const routeHint = originalUrl.startsWith("/api")
    ? "api gateway"
    : originalUrl.startsWith("/camera")
      ? "camera relay"
      : "edge proxy";

  return [
    `${method} ${originalUrl} handled by ${routeHint}`,
    `relay=${context.serviceMemory.host}`,
    `banner=${context.serviceMemory.banner.replace(/^Server:\s*/i, "")}`,
    `ua=${sanitizeText(userAgent || "unknown", context.serviceMemory.host, 96)}`,
  ].join(" ");
}
