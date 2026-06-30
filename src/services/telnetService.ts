import crypto from "crypto";
import net, { Socket } from "net";
import { config } from "../config/config.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildTelnetBanner, buildTelnetShellIntro } from "../responders/telnetResponder.js";
import { runShellCommand } from "../responders/fakeFilesystem.js";
import { safeShellOutput } from "../responders/safety.js";
import { logError } from "../utils/logger.js";
import { acquireConnection, releaseConnection } from "../utils/connectionThrottle.js";

const IAC_WILL_ECHO = Buffer.from([255, 251, 1]);
const IAC_WILL_SUPPRESS_GO_AHEAD = Buffer.from([255, 251, 3]);

export async function startTelnetService() {
  const server = net.createServer((socket: Socket) => {
    const remoteAddress = socket.remoteAddress || "unknown";

    if (!acquireConnection(remoteAddress, "telnet")) {
      socket.destroy();
      return;
    }

    const sessionId = crypto.randomUUID();
    let stage: "username" | "password" | "shell" = "username";
    let username = "unknown";
    const shellState = { cwd: "/root" };

    void (async () => {
      const context = await resolveAttackerService(remoteAddress, "telnet");
      await recordInteractionEvent({
        sessionId,
        service: "TELNET",
        ip: remoteAddress,
        detail: "connection opened",
      });
      socket.write(Buffer.concat([IAC_WILL_ECHO, IAC_WILL_SUPPRESS_GO_AHEAD]));
      socket.write(buildTelnetBanner(context));
    })();

    socket.on("data", async (chunk: Buffer) => {
      const action = await getActionForSession(sessionId);
      const context = await resolveAttackerService(remoteAddress, "telnet");
      const input = chunk.toString("utf8").replace(/\u0000/g, "").trim();

      if (stage === "username") {
        username = input || "admin";
        stage = "password";
        await recordInteractionEvent({
          sessionId,
          service: "TELNET",
          ip: remoteAddress,
          detail: `username=${username}`,
          currentAction: action,
          metadata: { stage },
          patch: {
            usernames: [username],
          },
        });
        socket.write("\r\nPassword: ");
        return;
      }

      if (stage === "password") {
        await recordInteractionEvent({
          sessionId,
          service: "TELNET",
          ip: remoteAddress,
          detail: `password_attempt length=${input.length}`,
          currentAction: action,
          metadata: { stage, username },
        });

        if (action === "fake_error") {
          socket.write("\r\nLogin incorrect\r\n");
          socket.end();
          return;
        }

        stage = "shell";
        shellState.cwd = username === "root" ? "/root" : `/home/${username}`;
        socket.write(buildTelnetShellIntro(context, username));
        return;
      }

      const short = context.serviceMemory.host.split(".")[0];
      const sign = username === "root" ? "#" : "$";
      const promptFor = () => {
        const home = username === "root" ? "/root" : `/home/${username}`;
        return `${username}@${short}:${shellState.cwd === home ? "~" : shellState.cwd}${sign} `;
      };

      if (input === "exit" || input === "logout") {
        socket.write("logout\r\n");
        socket.end();
        return;
      }

      // Stateful explorable filesystem shell (cd/ls/cat/find/grep…).
      const fsResult = runShellCommand(input, shellState, context, username);
      shellState.cwd = fsResult.cwd;
      const output = safeShellOutput(fsResult.output, context.serviceMemory.host);
      await recordInteractionEvent({
        sessionId,
        service: "TELNET",
        ip: remoteAddress,
        detail: `shell input=${input}`,
        currentAction: action,
        request: input,
        response: output,
        patch: {
          command: input,
          usernames: [username],
        },
      });

      if (action === "stall") {
        await new Promise((resolve) => setTimeout(resolve, 1200));
      }

      socket.write(`${output ? output + "\r\n" : ""}${promptFor()}`);
    });

    socket.on("error", (error) => {
      void logError("TELNET", remoteAddress, "Socket error", { sessionId, error: error.message });
    });

    socket.on("close", async () => {
      releaseConnection(remoteAddress, "telnet");
      await recordInteractionEvent({
        sessionId,
        service: "TELNET",
        ip: remoteAddress,
        detail: "connection closed",
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.services.telnet.port, config.services.telnet.host, () => resolve());
  });

  return {
    name: "telnet",
    server,
    port: config.services.telnet.port,
    host: config.services.telnet.host,
  };
}
