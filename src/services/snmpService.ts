import crypto from "crypto";
import dgram from "dgram";
import { config } from "../config/config.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildSnmpReply } from "../responders/snmpResponder.js";
import { logError } from "../utils/logger.js";
import { acquireConnection, releaseConnection } from "../utils/connectionThrottle.js";

export async function startSnmpService() {
  const socket = dgram.createSocket("udp4");

  socket.on("message", async (msg, rinfo) => {
    const remoteAddress = rinfo.address;

    if (!acquireConnection(remoteAddress, "snmp")) {
      return;
    }

    const sessionId = crypto.randomUUID();

    try {
      const context = await resolveAttackerService(remoteAddress, "snmp");
      const reply = buildSnmpReply(msg, context);

      await recordInteractionEvent({
        sessionId,
        service: "SNMP",
        ip: remoteAddress,
        detail: `snmp-request bytes=${msg.length}`,
        request: msg.slice(0, 32).toString("hex"),
        response: reply.slice(0, 32).toString("hex"),
      });

      socket.send(reply, rinfo.port, rinfo.address, () => {
        releaseConnection(remoteAddress, "snmp");
      });
    } catch (error) {
      releaseConnection(remoteAddress, "snmp");
      void logError("SNMP", remoteAddress, "Handler error", { error: String(error) });
    }
  });

  socket.on("error", (error) => {
    void logError("SNMP", "server", "UDP socket error", { error: error.message });
    socket.close();
  });

  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(config.services.snmp.port, config.services.snmp.host, () => resolve());
  });

  return {
    name: "snmp",
    server: socket,
    port: config.services.snmp.port,
    host: config.services.snmp.host,
  };
}
