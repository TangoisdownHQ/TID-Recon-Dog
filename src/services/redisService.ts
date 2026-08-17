import crypto from "crypto";
import net, { Socket } from "net";
import { config } from "../config/config.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { buildRedisReply, createRedisState, RedisSessionState } from "../responders/redisResponder.js";
import { logError } from "../utils/logger.js";
import { acquireConnection, releaseConnection } from "../utils/connectionThrottle.js";

// Framing limits — a scanner that sends a malformed multibulk header must not
// be able to make us allocate on its behalf.
const MAX_BUFFER = 1024 * 1024;
const MAX_ARGS = 1024;
const MAX_ARG_BYTES = 512 * 1024;

type ParseResult = { commands: string[][]; rest: Buffer; fatal?: string };

/**
 * Pull complete commands off the wire. Redis accepts both the RESP multibulk
 * form (redis-cli, most bots) and bare inline commands (netcat, naive scanners),
 * so both are handled — an incomplete tail is returned for the next chunk.
 */
export function parseRedisCommands(buf: Buffer): ParseResult {
  const commands: string[][] = [];
  let offset = 0;

  while (offset < buf.length) {
    if (buf[offset] === 0x2a /* '*' */) {
      const headerEnd = buf.indexOf("\r\n", offset, "utf8");
      if (headerEnd === -1) break;
      const count = Number(buf.subarray(offset + 1, headerEnd).toString("latin1"));
      if (!Number.isInteger(count) || count < 0 || count > MAX_ARGS) {
        return { commands, rest: Buffer.alloc(0), fatal: "invalid multibulk length" };
      }

      let cursor = headerEnd + 2;
      const args: string[] = [];
      let incomplete = false;

      for (let i = 0; i < count; i += 1) {
        if (cursor >= buf.length) { incomplete = true; break; }
        if (buf[cursor] !== 0x24 /* '$' */) {
          return { commands, rest: Buffer.alloc(0), fatal: "expected '$'" };
        }
        const lenEnd = buf.indexOf("\r\n", cursor, "utf8");
        if (lenEnd === -1) { incomplete = true; break; }
        const len = Number(buf.subarray(cursor + 1, lenEnd).toString("latin1"));
        if (!Number.isInteger(len) || len < -1 || len > MAX_ARG_BYTES) {
          return { commands, rest: Buffer.alloc(0), fatal: "invalid bulk length" };
        }
        const dataStart = lenEnd + 2;
        if (len === -1) { args.push(""); cursor = dataStart; continue; }
        if (buf.length < dataStart + len + 2) { incomplete = true; break; }
        args.push(buf.subarray(dataStart, dataStart + len).toString("utf8"));
        cursor = dataStart + len + 2;
      }

      if (incomplete) break;
      offset = cursor;
      if (args.length) commands.push(args);
      continue;
    }

    // Inline command
    const lineEnd = buf.indexOf("\n", offset, "utf8");
    if (lineEnd === -1) break;
    const line = buf.subarray(offset, lineEnd).toString("utf8").replace(/\r$/, "");
    offset = lineEnd + 1;
    const parts = line.trim().split(/\s+/).filter(Boolean);
    if (parts.length) commands.push(parts.slice(0, MAX_ARGS));
  }

  return { commands, rest: buf.subarray(offset) };
}

async function handleSocket(socket: Socket) {
  const remoteAddress = socket.remoteAddress || "unknown";
  if (!acquireConnection(remoteAddress, "redis")) {
    socket.destroy();
    return;
  }

  const sessionId = crypto.randomUUID();
  const state: RedisSessionState = createRedisState();
  let buf = Buffer.alloc(0);

  // Redis sends no banner — the client speaks first.
  void recordInteractionEvent({
    sessionId,
    service: "REDIS",
    ip: remoteAddress,
    detail: "connection opened",
  });

  socket.on("data", async (chunk: Buffer) => {
    buf = Buffer.concat([buf, chunk]);
    if (buf.length > MAX_BUFFER) {
      socket.destroy();
      return;
    }

    const { commands, rest, fatal } = parseRedisCommands(buf);
    buf = rest;

    try {
      const action = await getActionForSession(sessionId);
      const context = await resolveAttackerService(remoteAddress, "redis");

      for (const [cmd, ...args] of commands) {
        const result = buildRedisReply(cmd, args, state, action, context);

        await recordInteractionEvent({
          sessionId,
          service: "REDIS",
          ip: remoteAddress,
          detail: result.exploitation ? `${result.detail} exec command=redis` : result.detail,
          currentAction: action,
          request: [cmd, ...args].join(" ").slice(0, 2000),
          response: result.reply.slice(0, 2000),
          patch: { command: [cmd, ...args].join(" ").slice(0, 400) },
        });

        if (action === "stall") await new Promise((r) => setTimeout(r, 1500));
        if (result.reply) socket.write(result.reply);
        if (result.close) { socket.end(); return; }
      }

      if (fatal) {
        socket.write(`-ERR Protocol error: ${fatal}\r\n`);
        socket.end();
      }
    } catch (error) {
      void logError("REDIS", remoteAddress, "Handler error", { sessionId, error: String(error) });
    }
  });

  socket.on("error", (error) => {
    void logError("REDIS", remoteAddress, "Socket error", { sessionId, error: error.message });
  });

  socket.on("close", () => {
    releaseConnection(remoteAddress, "redis");
    void recordInteractionEvent({
      sessionId,
      service: "REDIS",
      ip: remoteAddress,
      detail: "connection closed",
    });
  });
}

export async function startRedisService() {
  const server = net.createServer((socket) => void handleSocket(socket));
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.services.redis.port, config.services.redis.host, () => resolve());
  });

  return {
    name: "redis",
    server,
    port: config.services.redis.port,
    host: config.services.redis.host,
  };
}
