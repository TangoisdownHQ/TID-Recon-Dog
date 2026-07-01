// Turns raw captured activity (per-IP events + command history) into a readable
// "what happened" summary + structured highlights. The honeypot already records
// everything an attacker did; this is the layer that says it in plain language —
// which decoy files they touched, what they uploaded, which creds they tried,
// what commands/queries they ran, and which known exploits they threw.
//
// Deliberately decoupled from AttackerProfile (takes a minimal input shape) so it
// can run in the alert path, the API layer, and tests without import cycles.

export type ActivityInput = {
  // recentEvents entries, each optionally prefixed with an ISO timestamp.
  events: string[];
  counters?: { connections?: number; authAttempts?: number; commands?: number; uploads?: number };
  usernames?: string[]; // aggregated across services
  commands?: string[]; // aggregated command/query history
  services?: string[];
};

export type ExploitHit = { name: string; evidence: string };

export type ActivitySummary = {
  headline: string; // one-line plain-language summary
  credentials: string[]; // usernames (and passwords when captured) tried
  filesTouched: string[]; // decoy paths requested / read
  uploads: string[]; // upload attempts (paths or a count)
  commands: string[]; // notable shell commands / SQL queries
  exploits: ExploitHit[]; // matched known-exploit signatures
};

// Known-exploit / high-signal request signatures → human names. Order matters
// only for readability; all matches are reported.
const EXPLOIT_SIGNATURES: { re: RegExp; name: string }[] = [
  { re: /eval-stdin\.php/i, name: "PHPUnit RCE (CVE-2017-9841)" },
  { re: /think\\?\/?app\/invokefunction|invokefunction&function=/i, name: "ThinkPHP RCE" },
  { re: /pearcmd/i, name: "PHP pearcmd LFI→RCE" },
  { re: /\/\+CSCOE\+\/|\/\+webvpn/i, name: "Cisco ASA/AnyConnect probe" },
  { re: /\/manager\/html|\/jmx-console|\/wls-wsat/i, name: "app-server console probe" },
  { re: /\.aws\/credentials|\.aws\/config|\.env\b|tfstate|application\.ya?ml|wp-config\.php/i, name: "cloud/app secret harvesting" },
  { re: /\/etc\/passwd|\/etc\/shadow|id_rsa/i, name: "sensitive-file read" },
  { re: /\.\.(%2f|\/)/i, name: "path traversal" },
  { re: /union\s+select|' or '1'='1|sleep\(\d/i, name: "SQL injection" },
  { re: /\b(curl|wget)\s+https?:\/\//i, name: "remote payload fetch" },
  { re: /nc\s+-e|bash\s+-i|\/dev\/tcp\//i, name: "reverse-shell attempt" },
  { re: /chmod\s+\+x|chmod\s+777/i, name: "payload chmod" },
  { re: /shell input=enable|\benable\b.*\bconfigure terminal\b/i, name: "router enable-mode attempt" },
];

// Modbus write function codes (5/6/15/16/22/23) = ICS state tampering.
const MODBUS_WRITE = /function=(5|6|15|16|22|23)\b/i;

/** Strip a leading ISO timestamp ("2026-07-01T02:02:00.615Z rest") → "rest". */
function stripTs(line: string): string {
  return line.replace(/^\s*\d{4}-\d{2}-\d{2}T[\d:.]+Z\s+/, "").trim();
}

function uniq(items: string[], cap: number): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of items) {
    const v = raw.trim();
    if (!v || seen.has(v)) continue;
    seen.add(v);
    out.push(v);
    if (out.length >= cap) break;
  }
  return out;
}

export function summarizeActivity(input: ActivityInput): ActivitySummary {
  const events = (input.events || []).map(stripTs);
  const cmds = input.commands || [];
  const lines = [...events, ...cmds];

  const credentials: string[] = [...(input.usernames || [])];
  const filesTouched: string[] = [];
  const uploads: string[] = [];
  const commands: string[] = [];
  const exploits: ExploitHit[] = [];
  const seenExploit = new Set<string>();

  for (const line of lines) {
    // Credentials — "username=x", "USER x", "auth username=x", "login username=x"
    const u = line.match(/(?:^|\b)(?:user(?:name)?|login)[=\s]+([^\s,]+)/i);
    if (u && u[1] && !/^method$/i.test(u[1])) credentials.push(u[1]);
    if (/password_attempt|PASS\b|password=/i.test(line)) {
      const pw = line.match(/password=([^\s,]+)/i);
      if (pw) credentials.push(`pw:${pw[1]}`);
    }

    // Files / paths requested or read
    const httpPath = line.match(/Path:\s*([^\s,]+)/i);
    if (httpPath) filesTouched.push(httpPath[1]);
    const panel = line.match(/requested\s+\w+\s+panel\s+(\/\S+)/i);
    if (panel) filesTouched.push(panel[1]);
    const catFile = line.match(/\b(?:cat|less|more|head|tail)\s+(\/\S+)/i);
    if (catFile) filesTouched.push(catFile[1]);

    // Uploads
    if (/upload/i.test(line)) {
      const up = line.match(/upload(?:ed)?\s+(?:file\s+)?([^\s,]+)/i);
      uploads.push(up && up[1] ? up[1] : "file upload");
    }

    // Notable commands / SQL
    if (/^\s*(SELECT|INSERT|UPDATE|DELETE|DROP|COPY)\b/i.test(line) || /\bunion\s+select\b/i.test(line)) {
      commands.push(line.slice(0, 120));
    } else {
      const shell = line.match(/(?:cmd:|shell input=|exec command=)\s*(.+)/i);
      if (shell && shell[1] && !/^enable$/i.test(shell[1].trim())) commands.push(shell[1].slice(0, 120));
    }

    // Exploit signatures
    for (const sig of EXPLOIT_SIGNATURES) {
      if (sig.re.test(line) && !seenExploit.has(sig.name)) {
        seenExploit.add(sig.name);
        exploits.push({ name: sig.name, evidence: line.slice(0, 140) });
      }
    }
    if (MODBUS_WRITE.test(line) && !seenExploit.has("Modbus write (ICS tamper)")) {
      seenExploit.add("Modbus write (ICS tamper)");
      exploits.push({ name: "Modbus write (ICS tamper)", evidence: line.slice(0, 140) });
    }
  }

  const creds = uniq(credentials, 12);
  const files = uniq(filesTouched, 15);
  const ups = uniq(uploads, 8);
  const cmdList = uniq(commands, 8);

  return {
    headline: buildHeadline(input, { creds, files, ups, cmdList, exploits }),
    credentials: creds,
    filesTouched: files,
    uploads: ups,
    commands: cmdList,
    exploits,
  };
}

/**
 * A short, plain-language label for a single feed request/detail line — used to
 * annotate live-feed rows so the operator sees "GET /.aws/credentials —
 * secret-harvesting" instead of a bare path. Returns "" when nothing notable.
 */
export function describeRequest(request: string): string {
  const line = stripTs(request || "");
  if (!line) return "";
  for (const sig of EXPLOIT_SIGNATURES) {
    if (sig.re.test(line)) return sig.name;
  }
  if (MODBUS_WRITE.test(line)) return "Modbus write (ICS tamper)";
  if (/^\s*(SELECT|INSERT|UPDATE|DELETE|DROP|COPY)\b|union\s+select/i.test(line)) return "database query";
  if (/password_attempt|auth username=|login username=|USER\b|PASS\b/i.test(line)) return "credential attempt";
  if (/requested\s+\w+\s+panel/i.test(line)) return "decoy admin-panel hit";
  if (/upload/i.test(line)) return "file upload";
  const path = line.match(/Path:\s*([^\s,]+)/i);
  if (path) return `probe ${path[1]}`;
  return "";
}

function buildHeadline(
  input: ActivityInput,
  x: { creds: string[]; files: string[]; ups: string[]; cmdList: string[]; exploits: ExploitHit[] }
): string {
  const c = input.counters || {};
  const svc = (input.services || []).join(", ");
  const parts: string[] = [];

  if (x.exploits.length) parts.push(`ran ${x.exploits.length} known exploit${x.exploits.length > 1 ? "s" : ""} (${x.exploits.map((e) => e.name).slice(0, 3).join(", ")})`);
  if (c.uploads || x.ups.length) parts.push(`${c.uploads || x.ups.length} upload${(c.uploads || x.ups.length) > 1 ? "s" : ""}`);
  if (x.cmdList.length) parts.push(`ran ${x.cmdList.length} command${x.cmdList.length > 1 ? "s" : ""}/quer${x.cmdList.length > 1 ? "ies" : "y"}`);
  if (c.authAttempts) parts.push(`${c.authAttempts} auth attempt${c.authAttempts > 1 ? "s" : ""}${x.creds.length ? ` (${x.creds.slice(0, 4).join(", ")})` : ""}`);
  if (x.files.length) parts.push(`touched ${x.files.length} decoy path${x.files.length > 1 ? "s" : ""} (${x.files.slice(0, 3).join(", ")})`);

  if (!parts.length) {
    const conns = c.connections ? `${c.connections} connection${c.connections > 1 ? "s" : ""}` : "activity";
    return `${conns}${svc ? ` on ${svc}` : ""} — reconnaissance only, no notable payloads yet.`;
  }
  return `${parts.join("; ")}${svc ? ` — across ${svc}` : ""}.`;
}
