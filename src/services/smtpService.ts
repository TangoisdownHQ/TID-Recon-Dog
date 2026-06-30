import crypto from "crypto";
import net, { Socket } from "net";
import { config } from "../config/config.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildSmtpBanner, buildSmtpReply, SmtpStage } from "../responders/smtpResponder.js";
import { logError } from "../utils/logger.js";
import { acquireConnection, releaseConnection } from "../utils/connectionThrottle.js";

export async function startSmtpService() {
  const server = net.createServer((socket: Socket) => {
    const remoteAddress = socket.remoteAddress || "unknown";

    if (!acquireConnection(remoteAddress, "smtp")) {
      socket.destroy();
      return;
    }

    const sessionId = crypto.randomUUID();
    let stage: SmtpStage = "greeting";

    void (async () => {
      try {
        const context = await resolveAttackerService(remoteAddress, "smtp");
        const banner = buildSmtpBanner(context);
        socket.write(banner);
        stage = "command";
        await recordInteractionEvent({
          sessionId,
          service: "SMTP",
          ip: remoteAddress,
          detail: "connection opened",
          response: banner.trim(),
        });
      } catch (error) {
        void logError("SMTP", remoteAddress, "Banner error", { error: String(error) });
        socket.destroy();
      }
    })();

    socket.on("data", async (chunk: Buffer) => {
      const input = chunk.toString("utf8").replace(/\r\n/g, "\n").trim();
      if (!input) return;

      try {
        const context = await resolveAttackerService(remoteAddress, "smtp");
        const reply = buildSmtpReply(input, stage, context);
        const cmd = input.split(/\s/)[0].toUpperCase();

        // Advance stage
        if (stage === "command" && cmd === "DATA") {
          stage = "data";
        } else if (stage === "data" && input.trim() === ".") {
          stage = "command";
        } else if (cmd === "QUIT") {
          stage = "done";
        }

        await recordInteractionEvent({
          sessionId,
          service: "SMTP",
          ip: remoteAddress,
          detail: `smtp_cmd=${cmd}`,
          request: input.slice(0, 240),
          response: reply.trim().slice(0, 240),
          patch: { command: input.slice(0, 180) },
        });

        if (reply) socket.write(reply);

        if (stage === "done") {
          socket.end();
        }
      } catch (error) {
        void logError("SMTP", remoteAddress, "Handler error", { error: String(error) });
      }
    });

    socket.on("error", (error) => {
      void logError("SMTP", remoteAddress, "Socket error", { sessionId, error: error.message });
    });

    socket.on("close", async () => {
      releaseConnection(remoteAddress, "smtp");
      await recordInteractionEvent({
        sessionId,
        service: "SMTP",
        ip: remoteAddress,
        detail: "connection closed",
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.services.smtp.port, config.services.smtp.host, () => resolve());
  });

  return {
    name: "smtp",
    server,
    port: config.services.smtp.port,
    host: config.services.smtp.host,
  };
}
