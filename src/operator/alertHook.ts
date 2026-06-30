import fs from "fs/promises";
import path from "path";

export type AlertPayload = {
  at: string;
  event: string;
  attacker_id: string;
  source_ip: string;
  risk: string;
  previous_risk: string;
  intent: string;
  score: number;
  services: string[];
  recent_events: string[];
};

const alertLogPath = path.resolve("runtime", "alerts.jsonl");

async function writeAlertLog(entry: AlertPayload) {
  try {
    await fs.mkdir(path.dirname(alertLogPath), { recursive: true });
    await fs.appendFile(alertLogPath, `${JSON.stringify(entry)}\n`, "utf8");
  } catch {
    // best-effort
  }
}

async function fireWebhook(url: string, payload: AlertPayload) {
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 5000);
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(tid);
  } catch {
    // never crash on webhook failure
  }
}

export async function readAlerts(): Promise<AlertPayload[]> {
  try {
    const raw = await fs.readFile(alertLogPath, "utf8");
    return raw
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
      .flatMap((line) => {
        try {
          return [JSON.parse(line) as AlertPayload];
        } catch {
          return [];
        }
      });
  } catch {
    return [];
  }
}

export async function maybeFireAlert(params: {
  attackerId: string;
  sourceIp: string;
  risk: string;
  previousRisk: string;
  intent: string;
  score: number;
  services: string[];
  recentEvents: string[];
}) {
  // Only fire on actual risk escalation, not de-escalation
  const rankOf = (r: string) => (r === "high" ? 2 : r === "medium" ? 1 : 0);
  if (rankOf(params.risk) <= rankOf(params.previousRisk)) return;

  const payload: AlertPayload = {
    at: new Date().toISOString(),
    event: "risk_escalation",
    attacker_id: params.attackerId.slice(0, 12),
    source_ip: params.sourceIp,
    risk: params.risk,
    previous_risk: params.previousRisk,
    intent: params.intent,
    score: params.score,
    services: params.services,
    recent_events: params.recentEvents.slice(-3),
  };

  await writeAlertLog(payload);

  const webhookUrl = process.env.ALERT_WEBHOOK_URL;
  if (webhookUrl) {
    void fireWebhook(webhookUrl, payload);
  }
}
