import crypto from "crypto";
import net, { Socket } from "net";
import { config } from "../config/config.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildRdpResponse } from "../responders/rdpResponder.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { logError } from "../utils/logger.js";

export async function startRdpService() {
  const server = net.createServer((socket: Socket) => {
    const remoteAddress = socket.remoteAddress || "unknown";
    const sessionId = crypto.randomUUID();

    void recordInteractionEvent({
      sessionId,
      service: "RDP",
      ip: remoteAddress,
      detail: "connection opened",
    });

    socket.on("data", async (chunk: Buffer) => {
      const action = await getActionForSession(sessionId);
      const context = await resolveAttackerService(remoteAddress, "rdp");
      const buffers = buildRdpResponse(action, context);
      // RDP clients put the target username in the X.224 mstshash cookie.
      const mstshash = chunk.toString("latin1").match(/mstshash=([^\r\n\0]+)/i)?.[1]?.trim();
      await recordInteractionEvent({
        sessionId,
        service: "RDP",
        ip: remoteAddress,
        detail: mstshash ? `login username=${mstshash}` : `negotiation bytes=${chunk.length}`,
        currentAction: action,
        metadata: mstshash ? { username: mstshash } : undefined,
        request: chunk.subarray(0, 24).toString("hex"),
        response: buffers.map((buffer) => buffer.toString("hex")).join(" "),
        patch: mstshash ? { usernames: [mstshash] } : undefined,
      });

      if (action === "stall") {
        await new Promise((resolve) => setTimeout(resolve, 1800));
      }

      for (const buffer of buffers) {
        socket.write(buffer);
      }
      socket.end();
    });

    socket.on("error", (error) => {
      void logError("RDP", remoteAddress, "Socket error", { sessionId, error: error.message });
    });

    socket.on("close", async () => {
      await recordInteractionEvent({
        sessionId,
        service: "RDP",
        ip: remoteAddress,
        detail: "connection closed",
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.services.rdp.port, config.services.rdp.host, () => resolve());
  });

  return {
    name: "rdp",
    server,
    port: config.services.rdp.port,
    host: config.services.rdp.host,
  };
}
