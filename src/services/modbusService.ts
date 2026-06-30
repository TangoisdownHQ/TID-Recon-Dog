import crypto from "crypto";
import net, { Socket } from "net";
import { config } from "../config/config.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildModbusReply } from "../responders/modbusResponder.js";
import { logError } from "../utils/logger.js";
import { acquireConnection, releaseConnection } from "../utils/connectionThrottle.js";

export async function startModbusService() {
  const server = net.createServer((socket: Socket) => {
    const remoteAddress = socket.remoteAddress || "unknown";

    if (!acquireConnection(remoteAddress, "modbus")) {
      socket.destroy();
      return;
    }

    const sessionId = crypto.randomUUID();

    void recordInteractionEvent({
      sessionId,
      service: "MODBUS",
      ip: remoteAddress,
      detail: "connection opened",
    });

    socket.on("data", async (chunk: Buffer) => {
      if (chunk.length < 8) {
        return;
      }

      const action = await getActionForSession(sessionId);
      const context = await resolveAttackerService(remoteAddress, "modbus");
      const transactionId = chunk.readUInt16BE(0);
      const unitId = chunk.readUInt8(6);
      const functionCode = chunk.readUInt8(7);
      const reply = buildModbusReply({
        action,
        transactionId,
        unitId,
        functionCode,
        chunk,
        context,
      });
      await recordInteractionEvent({
        sessionId,
        service: "MODBUS",
        ip: remoteAddress,
        detail: `function=${functionCode} transaction=${transactionId}`,
        currentAction: action,
        request: chunk.toString("hex"),
        response: reply.buffer.toString("hex"),
        patch: reply.patch,
      });

      if (action === "stall") {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }

      socket.write(reply.buffer);
    });

    socket.on("error", (error) => {
      void logError("MODBUS", remoteAddress, "Socket error", { sessionId, error: error.message });
    });

    socket.on("close", async () => {
      releaseConnection(remoteAddress, "modbus");
      await recordInteractionEvent({
        sessionId,
        service: "MODBUS",
        ip: remoteAddress,
        detail: "connection closed",
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.services.modbus.port, config.services.modbus.host, () => resolve());
  });

  return {
    name: "modbus",
    server,
    port: config.services.modbus.port,
    host: config.services.modbus.host,
  };
}
