import crypto from "crypto";
import fs from "fs";
import path from "path";
import pkg from "ssh2";
import { config } from "../config/config.js";
import { getActionForSession, takeMessages } from "../operator/controlPlane.js";
import { runShellCommand } from "../responders/fakeFilesystem.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildSshAuthentication, buildSshCommandOutput, buildSshShellIntro } from "../responders/sshResponder.js";
import { resolveResponse } from "../responders/aiEngine.js";
import { logError } from "../utils/logger.js";
import { acquireConnection, releaseConnection } from "../utils/connectionThrottle.js";
import { getServiceProfile } from "../profiles/serviceProfiles.js";
import { opensshAlgorithms } from "../utils/hardening.js";

const { Server } = pkg;
const honeypotID = "honeypot-01";

// Advertise as OpenSSH (ssh2's default ident is "SSH-2.0-ssh2js<ver>", a giveaway).
// ssh2 prefixes "SSH-2.0-", so pass only the software/version part.
const SSH_IDENT = getServiceProfile("ssh").banner.replace(/^SSH-2\.0-/, "");

function getClientIp(client: any) {
  return client?._sock?.remoteAddress || client?._socket?.remoteAddress || "unknown";
}

/**
 * Stable host key persisted under runtime/ssh. Real hosts keep the same key
 * across restarts (a key that changes every boot is itself suspicious). RSA in
 * PKCS#1 PEM is the format ssh2 reliably parses without external tooling.
 */
function getHostKey(): Buffer {
  const dir = path.resolve("runtime", "ssh");
  fs.mkdirSync(dir, { recursive: true });
  const rsa = path.join(dir, "ssh_host_rsa_key");
  if (!fs.existsSync(rsa)) {
    const { privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 3072,
      privateKeyEncoding: { type: "pkcs1", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    fs.writeFileSync(rsa, privateKey, { mode: 0o600 });
  }
  return fs.readFileSync(rsa);
}

export async function startSshService() {
  const hostKeys = [getHostKey()];

  const sshServer = new Server(
    { hostKeys, ident: SSH_IDENT, algorithms: opensshAlgorithms as any },
    (client) => {
    const remoteAddress = getClientIp(client);

    if (!acquireConnection(remoteAddress, "ssh")) {
      client.end();
      return;
    }

    const sessionId = crypto.randomUUID();
    let authenticatedUser = "admin";

    void recordInteractionEvent({
      sessionId,
      service: "SSH",
      ip: remoteAddress,
      detail: `connection opened honeypot=${honeypotID}`,
    });

    client.on("authentication", async (ctx) => {
      const action = await getActionForSession(sessionId);
      const attemptDetails = `username=${ctx.username} method=${ctx.method}`;
      const decision = buildSshAuthentication(action);
      authenticatedUser = ctx.username || authenticatedUser;
      await recordInteractionEvent({
        sessionId,
        service: "SSH",
        ip: remoteAddress,
        detail: `auth ${attemptDetails}`,
        currentAction: action,
        metadata: { username: ctx.username, method: ctx.method },
        patch: {
          usernames: [ctx.username],
        },
      });

      setTimeout(() => {
        if (decision.accept) {
          ctx.accept();
        } else {
          ctx.reject();
        }
      }, decision.delayMs);
    });

    client.on("session", (accept) => {
      const session = accept();
      session.on("exec", async (acceptExec, _reject, info) => {
        const channel = acceptExec();
        const action = await getActionForSession(sessionId);
        const context = await resolveAttackerService(remoteAddress, "ssh");
        const deterministic = buildSshCommandOutput(info.command, context, authenticatedUser);
        const output = await resolveResponse({
          service: "ssh",
          request: info.command,
          context,
          action,
          sessionId,
          ip: remoteAddress,
          deterministic,
        });
        await recordInteractionEvent({
          sessionId,
          service: "SSH",
          ip: remoteAddress,
          detail: `exec command=${info.command}`,
          currentAction: action,
          request: info.command,
          response: output,
          patch: {
            command: info.command,
            usernames: [authenticatedUser],
          },
        });
        channel.write(`${output}\n`);
        channel.exit(0);
        channel.end();
      });

      session.on("pty", (acceptPty) => acceptPty && acceptPty());
      session.on("shell", async (acceptShell) => {
        const action = await getActionForSession(sessionId);
        const context = await resolveAttackerService(remoteAddress, "ssh");
        const channel = acceptShell();
        await recordInteractionEvent({
          sessionId,
          detail: "interactive shell requested",
          service: "SSH",
          ip: remoteAddress,
          currentAction: action,
          patch: {
            usernames: [authenticatedUser],
          },
        });

        const shortHost = context.serviceMemory.host.split(".")[0];
        const home = authenticatedUser === "root" ? "/root" : `/home/${authenticatedUser}`;
        const sign = authenticatedUser === "root" ? "#" : "$";
        const shellState = { cwd: home };
        const promptFor = () =>
          `${authenticatedUser}@${shortHost}:${shellState.cwd === home ? "~" : shellState.cwd}${sign} `;
        // CRLF for raw PTYs (a lone \n staircases the terminal).
        const crlf = (s: string) => s.replace(/\r?\n/g, "\r\n");
        channel.write(crlf(`${buildSshShellIntro(context, action, authenticatedUser)}\n`) + promptFor());

        // Operator message injection: poll for queued messages and write them
        // into the attacker's terminal (wall-style), then redraw the prompt.
        const injectTimer = setInterval(() => {
          const msgs = takeMessages(sessionId, remoteAddress);
          if (msgs.length) {
            channel.write("\r\n" + crlf(msgs.join("\n")) + "\r\n" + promptFor());
          }
        }, 2000);
        channel.on("close", () => clearInterval(injectTimer));

        // Real PTY line discipline: the server must echo keystrokes and buffer a
        // line until Enter. Processing each keystroke as a command is the bug
        // that made `ls` run as `l` then `s`.
        let lineBuffer = "";
        let inEscape = false;

        const runCommand = async (command: string) => {
          if (command === "exit" || command === "logout") {
            channel.write("logout\r\n");
            clearInterval(injectTimer);
            channel.close();
            return;
          }
          if (command === "clear") {
            channel.write("\x1b[2J\x1b[H" + promptFor());
            return;
          }
          const commandContext = await resolveAttackerService(remoteAddress, "ssh");
          // Stateful fake-filesystem shell (cd/ls/cat/find/grep…) updates cwd.
          const fsResult = runShellCommand(command, shellState, commandContext, authenticatedUser);
          shellState.cwd = fsResult.cwd;
          const output = await resolveResponse({
            service: "ssh",
            request: command,
            context: commandContext,
            action,
            sessionId,
            ip: remoteAddress,
            deterministic: fsResult.output,
          });
          await recordInteractionEvent({
            sessionId,
            service: "SSH",
            ip: remoteAddress,
            detail: `shell input=${command}`,
            currentAction: action,
            request: command,
            response: output,
            patch: { command, usernames: [authenticatedUser] },
          });
          channel.write((output ? crlf(output) + "\r\n" : "") + promptFor());
        };

        channel.on("data", async (data: Buffer) => {
          const text = data.toString("utf8");
          for (const ch of text) {
            const code = ch.charCodeAt(0);

            // Swallow ANSI escape sequences (arrow keys, etc.).
            if (inEscape) {
              if (code >= 0x40 && code <= 0x7e) inEscape = false;
              continue;
            }
            if (code === 0x1b) {
              inEscape = true;
              continue;
            }

            if (ch === "\r" || ch === "\n") {
              channel.write("\r\n");
              const command = lineBuffer.trim();
              lineBuffer = "";
              if (command.length === 0) {
                channel.write(promptFor());
              } else {
                await runCommand(command);
              }
            } else if (code === 0x7f || code === 0x08) {
              // backspace: erase one char on screen + buffer
              if (lineBuffer.length > 0) {
                lineBuffer = lineBuffer.slice(0, -1);
                channel.write("\b \b");
              }
            } else if (code === 0x03) {
              // Ctrl-C
              lineBuffer = "";
              channel.write("^C\r\n" + promptFor());
            } else if (code === 0x04) {
              // Ctrl-D on an empty line logs out
              if (lineBuffer.length === 0) {
                channel.write("logout\r\n");
                channel.close();
                return;
              }
            } else if (code >= 0x20) {
              // printable: echo it and buffer it
              lineBuffer += ch;
              channel.write(ch);
            }
          }
        });
      });
    });

    client.on("error", (error) => {
      void logError("SSH", remoteAddress, "SSH client error", { sessionId, error: error.message });
    });

    client.on("end", () => {
      releaseConnection(remoteAddress, "ssh");
      void recordInteractionEvent({
        sessionId,
        service: "SSH",
        ip: remoteAddress,
        detail: "connection closed",
      });
    });
  });

  await new Promise<void>((resolve, reject) => {
    sshServer.once("error", reject);
    sshServer.listen(config.services.ssh.port, config.services.ssh.host, () => resolve());
  });

  return {
    name: "ssh",
    server: sshServer,
    port: config.services.ssh.port,
    host: config.services.ssh.host,
  };
}
