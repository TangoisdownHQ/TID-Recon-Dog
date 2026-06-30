import { FtpSrv } from "ftp-srv";
import crypto from "crypto";
import { config } from "../config/config.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { getServiceProfile } from "../profiles/serviceProfiles.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildFtpLoginFailure } from "../responders/ftpResponder.js";
import { logError } from "../utils/logger.js";

export async function startFtpService() {
  const profile = getServiceProfile("ftp");
  const passiveHost = config.services.ftp.host === "0.0.0.0" ? "127.0.0.1" : config.services.ftp.host;
  const ftpServer = new FtpSrv(`ftp://${config.services.ftp.host}:${config.services.ftp.port}`, {
    greeting: profile.banner,
    pasv_url: passiveHost,
  } as any);

  ftpServer.on("client-error", ({ connection, context, error }) => {
    const remoteAddress = connection?.ip || "unknown";
    void logError("FTP", remoteAddress, "Client error", { context, error: error.message });
  });

  ftpServer.on("login", async ({ connection, username }, _resolve, reject) => {
    const remoteAddress = connection?.ip || "unknown";
    const sessionId = crypto.randomUUID();
    const action = await getActionForSession(sessionId);
    const context = await resolveAttackerService(remoteAddress, "ftp");
    const failureMessage = buildFtpLoginFailure(action, String(username || "unknown"), context);
    await recordInteractionEvent({
      sessionId,
      service: "FTP",
      ip: remoteAddress,
      detail: `login username=${username}`,
      currentAction: action,
      metadata: {
        username: String(username || "unknown"),
        banner: profile.banner,
        host: context.serviceMemory.host,
      },
      request: `USER ${String(username || "anonymous")}`,
      response: failureMessage,
      patch: {
        usernames: [String(username || "unknown")],
      },
    });

    const delay = action === "stall" ? 9000 : 2500;
    setTimeout(() => {
      reject(new Error(failureMessage));
    }, delay);
  });

  await ftpServer.listen();

  return {
    name: "ftp",
    server: ftpServer,
    port: config.services.ftp.port,
    host: config.services.ftp.host,
  };
}
