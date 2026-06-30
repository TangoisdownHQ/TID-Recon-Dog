import { FtpSrv } from "ftp-srv";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { config } from "../config/config.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { getServiceProfile } from "../profiles/serviceProfiles.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildFtpLoginFailure } from "../responders/ftpResponder.js";
import { logError } from "../utils/logger.js";

// A fake FTP root full of bait files, served read-only when the operator lets
// an attacker "in" (decoy_success). Built once at startup.
function ensureFakeRoot(): string {
  const root = path.resolve("runtime", "ftproot");
  fs.mkdirSync(root, { recursive: true });
  const files: Record<string, string> = {
    "README.txt": "backup-nas-07 :: nightly dumps land here. Restore runbook in /opt/backup.\n",
    "relaydb-2026-06-29.sql.gz": "[gzip] relaydb full dump 2026-06-29 (412MB placeholder)\n",
    "customers.csv": "id,name,email,plan,card_last4,mrr\n1001,Acme Logistics,ap@acme-log.com,enterprise,4242,4800\n1003,Globex Corp,finance@globex.com,enterprise,7702,5200\n",
    "config.yaml": "database:\n  host: db-prod-01.internal\n  user: relay_admin\n  password: Rel4y!Pr0d2026\n",
    "id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAfakeHONEYPOTkeyDoNotUse...\n-----END OPENSSH PRIVATE KEY-----\n",
  };
  for (const [name, content] of Object.entries(files)) {
    try { fs.writeFileSync(path.join(root, name), content); } catch { /* ignore */ }
  }
  return root;
}

export async function startFtpService() {
  const profile = getServiceProfile("ftp");
  const fakeRoot = ensureFakeRoot();
  const passiveHost = config.services.ftp.host === "0.0.0.0" ? "127.0.0.1" : config.services.ftp.host;
  const ftpServer = new FtpSrv(`ftp://${config.services.ftp.host}:${config.services.ftp.port}`, {
    greeting: profile.banner,
    pasv_url: passiveHost,
  } as any);

  ftpServer.on("client-error", ({ connection, context, error }) => {
    const remoteAddress = connection?.ip || "unknown";
    void logError("FTP", remoteAddress, "Client error", { context, error: error.message });
  });

  ftpServer.on("login", async ({ connection, username }, resolve, reject) => {
    const remoteAddress = connection?.ip || "unknown";
    const sessionId = crypto.randomUUID();
    const action = await getActionForSession(sessionId);
    const context = await resolveAttackerService(remoteAddress, "ftp");
    const authed = action === "decoy_success";
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
      response: authed ? "230 Login successful" : failureMessage,
      patch: {
        usernames: [String(username || "unknown")],
      },
    });

    // decoy_success → drop them into the bait filesystem (read-only browse/get).
    if (authed) {
      resolve({ root: fakeRoot });
      return;
    }

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
