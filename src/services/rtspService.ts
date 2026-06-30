import crypto from "crypto";
import net, { Socket } from "net";
import { config } from "../config/config.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildRtspHandler } from "../responders/rtspResponder.js";
import { logError } from "../utils/logger.js";

function parseRtspRequest(payload: string) {
  const [requestLine, ...headerLines] = payload.split("\r\n");
  const [method = "UNKNOWN", uri = "*"] = requestLine.split(" ");
  const headers = Object.fromEntries(
    headerLines
      .filter((line) => line.includes(":"))
      .map((line) => {
        const [key, ...rest] = line.split(":");
        return [key.trim().toLowerCase(), rest.join(":").trim()];
      })
  );

  return { method, uri, headers };
}

export async function startRtspService() {
  const server = net.createServer((socket: Socket) => {
    const remoteAddress = socket.remoteAddress || "unknown";
    const sessionId = crypto.randomUUID();

    void recordInteractionEvent({
      sessionId,
      service: "RTSP",
      ip: remoteAddress,
      detail: "connection opened",
    });

    socket.on("data", async (chunk: Buffer) => {
      const action = await getActionForSession(sessionId);
      const context = await resolveAttackerService(remoteAddress, "rtsp");
      const raw = chunk.toString("utf8");
      const { method, uri, headers } = parseRtspRequest(raw);
      const reply = buildRtspHandler({
        action,
        method,
        headers,
        sessionId,
        context,
      });
      await recordInteractionEvent({
        sessionId,
        service: "RTSP",
        ip: remoteAddress,
        detail: `${method} ${uri}`,
        currentAction: action,
        metadata: { uri, userAgent: String(headers["user-agent"] || "unknown") },
        request: raw,
        response: reply,
      });

      if (action === "stall") {
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }

      socket.write(reply);
      if (action === "fake_error") {
        socket.end();
      }
    });

    socket.on("error", (error) => {
      void logError("RTSP", remoteAddress, "Socket error", { sessionId, error: error.message });
    });

    socket.on("close", async () => {
      await recordInteractionEvent({
        sessionId,
        service: "RTSP",
        ip: remoteAddress,
        detail: "connection closed",
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.services.rtsp.port, config.services.rtsp.host, () => resolve());
  });

  return {
    name: "rtsp",
    server,
    port: config.services.rtsp.port,
    host: config.services.rtsp.host,
  };
}
