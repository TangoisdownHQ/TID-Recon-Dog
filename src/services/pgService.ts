import crypto from "crypto";
import net, { Socket } from "net";
import { config } from "../config/config.js";
import { getActionForSession } from "../operator/controlPlane.js";
import { resolveAttackerService } from "../deception_engine/state/attacker_memory.js";
import { recordInteractionEvent } from "../responders/interactionRecorder.js";
import { DB_TABLES } from "../responders/webPanels.js";
import { logError } from "../utils/logger.js";
import { acquireConnection, releaseConnection } from "../utils/connectionThrottle.js";

// Minimal PostgreSQL v3 backend: enough to let psql connect (capturing the
// password), then answer SELECTs against the fake DB_TABLES — so the decoy DB is
// actually explorable instead of erroring on the startup packet.

const int32 = (n: number) => { const b = Buffer.alloc(4); b.writeInt32BE(n, 0); return b; };
const int16 = (n: number) => { const b = Buffer.alloc(2); b.writeInt16BE(n, 0); return b; };
const cstr = (s: string) => Buffer.concat([Buffer.from(s, "utf8"), Buffer.from([0])]);
// Backend message: type byte + int32 length(incl self) + payload.
const msg = (type: string, payload: Buffer) =>
  Buffer.concat([Buffer.from(type), int32(payload.length + 4), payload]);

function authOkAndReady(): Buffer {
  const params: Record<string, string> = {
    server_version: "14.11",
    server_encoding: "UTF8",
    client_encoding: "UTF8",
    DateStyle: "ISO, MDY",
    standard_conforming_strings: "on",
    integer_datetimes: "on",
  };
  const parts: Buffer[] = [msg("R", int32(0))]; // AuthenticationOk
  for (const [k, v] of Object.entries(params)) parts.push(msg("S", Buffer.concat([cstr(k), cstr(v)])));
  parts.push(msg("K", Buffer.concat([int32(4242), int32(0x1a2b3c4d)]))); // BackendKeyData
  parts.push(msg("Z", Buffer.from("I"))); // ReadyForQuery (Idle)
  return Buffer.concat(parts);
}

function errorResponse(code: string, message: string): Buffer {
  const payload = Buffer.concat([
    Buffer.from("S"), cstr("ERROR"),
    Buffer.from("C"), cstr(code),
    Buffer.from("M"), cstr(message),
    Buffer.from([0]),
  ]);
  return Buffer.concat([msg("E", payload), msg("Z", Buffer.from("I"))]);
}

function rowDescription(cols: string[]): Buffer {
  const fields = cols.map((c) =>
    Buffer.concat([cstr(c), int32(0), int16(0), int32(25 /*text*/), int16(-1), int32(-1), int16(0)])
  );
  return msg("T", Buffer.concat([int16(cols.length), ...fields]));
}
function dataRow(vals: string[]): Buffer {
  const cells = vals.map((v) => { const b = Buffer.from(v, "utf8"); return Buffer.concat([int32(b.length), b]); });
  return msg("D", Buffer.concat([int16(vals.length), ...cells]));
}
const commandComplete = (tag: string) => msg("C", cstr(tag));
const readyForQuery = () => msg("Z", Buffer.from("I"));

function handleQuery(sql: string): Buffer {
  const q = sql.trim().replace(/;+\s*$/, "");
  if (/^\s*(insert|update|delete|drop|alter|create|truncate|grant)/i.test(q)) {
    return errorResponse("42501", 'permission denied: role "relay_ro" is read-only');
  }
  if (/version\s*\(\)/i.test(q)) {
    return Buffer.concat([rowDescription(["version"]), dataRow(["PostgreSQL 14.11 on x86_64-pc-linux-gnu"]), commandComplete("SELECT 1"), readyForQuery()]);
  }
  const m = q.match(/from\s+"?([a-z_][a-z0-9_]*)"?/i);
  const t = m && DB_TABLES[m[1].toLowerCase()];
  if (t) {
    return Buffer.concat([
      rowDescription(t.cols),
      ...t.rows.map((r) => dataRow(r)),
      commandComplete(`SELECT ${t.rows.length}`),
      readyForQuery(),
    ]);
  }
  if (/^\s*select/i.test(q)) {
    // Unknown SELECT — empty result, no error (keeps the session alive).
    return Buffer.concat([rowDescription(["?column?"]), commandComplete("SELECT 0"), readyForQuery()]);
  }
  if (m) return errorResponse("42P01", `relation "${m[1]}" does not exist`);
  return Buffer.concat([commandComplete("OK"), readyForQuery()]);
}

async function handleSocket(socket: Socket) {
  const remoteAddress = socket.remoteAddress || "unknown";
  if (!acquireConnection(remoteAddress, "postgres")) { socket.destroy(); return; }

  const sessionId = crypto.randomUUID();
  let buf = Buffer.alloc(0);
  let startupDone = false;
  let dbUser = "unknown";

  void recordInteractionEvent({ sessionId, service: "POSTGRES", ip: remoteAddress, detail: "connection opened" });

  socket.on("data", async (chunk: Buffer) => {
    buf = Buffer.concat([buf, chunk]);
    const action = await getActionForSession(sessionId);

    while (true) {
      if (!startupDone) {
        if (buf.length < 8) break;
        const len = buf.readInt32BE(0);
        if (buf.length < len) break;
        const code = buf.readInt32BE(4);
        if (code === 80877103 || code === 80877104) { // SSLRequest / GSSENCRequest
          socket.write(Buffer.from("N")); // no SSL
          buf = buf.subarray(len);
          continue;
        }
        // StartupMessage: parse key\0value\0 params (after the 4-byte protocol)
        const params = buf.subarray(8, len).toString("utf8").split("\0");
        for (let i = 0; i < params.length - 1; i += 2) if (params[i] === "user") dbUser = params[i + 1];
        buf = buf.subarray(len);
        startupDone = true;
        socket.write(msg("R", int32(3))); // AuthenticationCleartextPassword
        continue;
      }
      if (buf.length < 5) break;
      const type = String.fromCharCode(buf[0]);
      const len = buf.readInt32BE(1);
      if (buf.length < len + 1) break;
      const payload = buf.subarray(5, len + 1);
      buf = buf.subarray(len + 1);

      if (type === "p") { // PasswordMessage — capture and accept
        const pw = payload.toString("utf8").replace(/\0+$/, "");
        const context = await resolveAttackerService(remoteAddress, "postgres");
        await recordInteractionEvent({
          sessionId, service: "POSTGRES", ip: remoteAddress,
          detail: `login user=${dbUser}`, currentAction: action,
          metadata: { username: dbUser, password_length: pw.length },
          request: `STARTUP user=${dbUser}`, response: "authenticated",
          patch: { usernames: [dbUser] },
        });
        if (action === "fake_error") { socket.write(errorResponse("28P01", "password authentication failed")); socket.end(); return; }
        socket.write(authOkAndReady());
      } else if (type === "Q") { // simple Query
        const sql = payload.toString("utf8").replace(/\0+$/, "");
        await recordInteractionEvent({
          sessionId, service: "POSTGRES", ip: remoteAddress,
          detail: `query=${sql.slice(0, 200)}`, currentAction: action,
          request: sql.slice(0, 2000), response: "result", patch: { command: sql },
        });
        if (action === "stall") await new Promise((r) => setTimeout(r, 1500));
        socket.write(handleQuery(sql));
      } else if (type === "X") { // Terminate
        socket.end(); return;
      }
    }
  });

  socket.on("error", (error) => void logError("POSTGRES", remoteAddress, "Socket error", { sessionId, error: error.message }));
  socket.on("close", () => {
    releaseConnection(remoteAddress, "postgres");
    void recordInteractionEvent({ sessionId, service: "POSTGRES", ip: remoteAddress, detail: "connection closed" });
  });
}

export async function startPgService() {
  const server = net.createServer((socket) => void handleSocket(socket));
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(config.services.postgres.port, config.services.postgres.host, () => resolve());
  });
  return { name: "postgres", server, port: config.services.postgres.port, host: config.services.postgres.host };
}
