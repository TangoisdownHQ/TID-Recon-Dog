import fs from "fs/promises";
import path from "path";
import { ActivitySummary } from "./activitySummary.js";

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
  // Plain-language "what happened" + structured highlights. Optional so older
  // alerts.jsonl lines without them still parse.
  summary?: string;
  highlights?: ActivitySummary;
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

/**
 * Push a high-risk alert to Telegram via the Bot API. Requires TELEGRAM_BOT_TOKEN
 * and TELEGRAM_CHAT_ID. Best-effort — never throws into the live path.
 */
async function fireTelegram(payload: AlertPayload) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if (!token || !chatId) return;
  const node = process.env.NODE_NAME ? ` [${process.env.NODE_NAME}]` : "";
  // Plain text (no parse_mode): summaries/exploit names contain underscores and
  // brackets that would break Telegram Markdown parsing and drop the alert.
  const lines = [
    `🚨 ${payload.risk.toUpperCase()} escalation${node}`,
    `${payload.source_ip} · ${payload.intent} · score ${payload.score}`,
    `services: ${payload.services.join(", ") || "—"}`,
  ];
  if (payload.summary) lines.push(`\n${payload.summary}`);
  if (payload.highlights?.exploits?.length) {
    lines.push(`\n⚠ exploits: ${payload.highlights.exploits.map((e) => e.name).join(", ")}`);
  }
  try {
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 5000);
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text: lines.join("\n"), disable_web_page_preview: true }),
      signal: controller.signal,
    });
    clearTimeout(tid);
  } catch {
    // never crash on notify failure
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

/**
 * Persist an alert and fan it out to webhook + Telegram. Shared by the
 * risk-escalation path and the canary-trigger path. Best-effort on delivery.
 */
export async function emitAlert(payload: AlertPayload): Promise<void> {
  await writeAlertLog(payload);
  const webhookUrl = process.env.ALERT_WEBHOOK_URL;
  if (webhookUrl) {
    void fireWebhook(webhookUrl, payload);
  }
  void fireTelegram(payload);
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
  highlights?: ActivitySummary;
}) {
  // Only fire on actual risk escalation, not de-escalation
  const rankOf = (r: string) => (r === "high" ? 2 : r === "medium" ? 1 : 0);
  if (rankOf(params.risk) <= rankOf(params.previousRisk)) return;

  await emitAlert({
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
    summary: params.highlights?.headline,
    highlights: params.highlights,
  });
}
