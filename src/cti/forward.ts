// Forward honeypot events to external systems: syslog (RFC5424 / CEF),
// a generic webhook, and Splunk HEC. All best-effort, configured via env.
import dgram from "dgram";
import net from "net";

export type ForwardEvent = {
  at: string;
  service: string;
  sourceIp: string;
  intent: string;
  risk?: string;
  score?: number;
  action?: string;
  detail: string;
};

function cef(e: ForwardEvent): string {
  // ArcSight CEF — widely accepted by SIEMs.
  const ext = [
    `src=${e.sourceIp}`,
    `app=${e.service}`,
    `act=${e.action || ""}`,
    `cs1Label=intent cs1=${e.intent}`,
    `cs2Label=risk cs2=${e.risk || ""}`,
    `cn1Label=score cn1=${e.score ?? 0}`,
    `msg=${e.detail.replace(/[\r\n=]/g, " ").slice(0, 200)}`,
  ].join(" ");
  const sev = e.risk === "high" ? 9 : e.risk === "medium" ? 6 : 3;
  return `CEF:0|TID|Recon-Dog|1.0|${e.intent}|${e.service} interaction|${sev}|${ext}`;
}

function sendSyslog(line: string) {
  const target = process.env.SYSLOG_URL; // udp://host:514 or tcp://host:514
  if (!target) return;
  const m = target.match(/^(udp|tcp):\/\/([^:]+):(\d+)$/);
  if (!m) return;
  const [, proto, host, portStr] = m;
  const port = Number(portStr);
  const pri = 134; // local0.info
  const msg = `<${pri}>1 ${line}`;
  if (proto === "udp") {
    const sock = dgram.createSocket("udp4");
    sock.send(Buffer.from(msg), port, host, () => sock.close());
  } else {
    const sock = net.connect(port, host, () => {
      sock.write(msg + "\n");
      sock.end();
    });
    sock.on("error", () => sock.destroy());
  }
}

async function postJson(url: string, body: object, headers: Record<string, string> = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 5000);
  try {
    await fetch(url, { method: "POST", headers: { "Content-Type": "application/json", ...headers }, body: JSON.stringify(body), signal: ctrl.signal });
  } catch {
    /* best effort */
  } finally {
    clearTimeout(t);
  }
}

export function forwardingTargets(): string[] {
  const t: string[] = [];
  if (process.env.SYSLOG_URL) t.push("syslog");
  if (process.env.CTI_WEBHOOK_URL) t.push("webhook");
  if (process.env.SPLUNK_HEC_URL && process.env.SPLUNK_HEC_TOKEN) t.push("splunk-hec");
  return t;
}

/** Fire an event to every configured forwarder. Never throws. */
export function forwardEvent(e: ForwardEvent): void {
  try {
    if (process.env.SYSLOG_URL) sendSyslog(cef(e));
    if (process.env.CTI_WEBHOOK_URL) void postJson(process.env.CTI_WEBHOOK_URL, e);
    if (process.env.SPLUNK_HEC_URL && process.env.SPLUNK_HEC_TOKEN) {
      void postJson(process.env.SPLUNK_HEC_URL, { event: e, sourcetype: "tid:recon-dog" }, { Authorization: `Splunk ${process.env.SPLUNK_HEC_TOKEN}` });
    }
  } catch {
    /* never break the live path */
  }
}
