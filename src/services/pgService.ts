import crypto from "crypto";
import net, { Socket } from "net";
import { config } from "../config/config.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildPostgresReply } from "../responders/pgResponder.js";
import { logError } from "../utils/logger.js";
import { acquireConnection, releaseConnection } from "../utils/connectionThrottle.js";

async function handleSocket(socket: Socket) {
  const remoteAddress = socket.remoteAddress || "unknown";

  if (!acquireConnection(remoteAddress, "postgres")) {
    socket.destroy();
    return;
  }

  const sessionId = crypto.randomUUID();
  const action = await getActionForSession(sessionId);

  await recordInteractionEvent({
    sessionId,
    service: "POSTGRES",
    ip: remoteAddress,
    detail: "connection opened",
    currentAction: action,
  });

  socket.setEncoding("utf8");
  socket.write("N");

  socket.on("data", async (chunk: string | Buffer) => {
    const payload = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    const context = await resolveAttackerService(remoteAddress, "postgres");
    const reply = buildPostgresReply(payload, action, context);
    await recordInteractionEvent({
      sessionId,
      service: "POSTGRES",
      ip: remoteAddress,
      detail: `payload=${JSON.stringify(payload.slice(0, 60))}`,
      currentAction: action,
      request: payload.slice(0, 240),
      response: reply,
      patch: {
        usernames: context.serviceMemory.usernames,
      },
    });

    const delay = action === "stall" ? 4000 : 1000;
    setTimeout(() => {
      socket.write(`${reply}\n`);
      socket.end();
    }, delay);
  });

  socket.on("error", (error) => {
    void logError("POSTGRES", remoteAddress, "Socket error", { sessionId, error: error.message });
  });

  socket.on("close", async () => {
    releaseConnection(remoteAddress, "postgres");
    await recordInteractionEvent({
      sessionId,
      service: "POSTGRES",
      ip: remoteAddress,
      detail: "connection closed",
      currentAction: action,
    });
  });
}

export async function startPgService() {
  const server = net.createServer((socket) => {
    void handleSocket(socket);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.services.postgres.port, config.services.postgres.host, () => resolve());
  });

  return {
    name: "postgres",
    server,
    port: config.services.postgres.port,
    host: config.services.postgres.host,
  };
}
