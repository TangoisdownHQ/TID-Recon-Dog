import { listAttackers } from "../../deception_engine/state/attacker_memory.js";
import { readTranscripts } from "../../deception_engine/logging/transcript_store.js";
import {
  readSessionSnapshots,
  readLogEntries,
} from "../../utils/logger.js";
import { readControlState } from "../controlPlane.js";
import { readAlerts } from "../alertHook.js";
import { config } from "../../config/config.js";

type CountMap = Record<string, number>;

function tally<T>(items: T[], key: (item: T) => string | undefined): CountMap {
  const out: CountMap = {};
  for (const item of items) {
    const k = key(item);
    if (!k) continue;
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

function sortedTop(map: CountMap, limit = 10): Array<{ key: string; count: number }> {
  return Object.entries(map)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function minutesAgo(iso: string | undefined, nowMs: number): number {
  if (!iso) return Number.POSITIVE_INFINITY;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return Number.POSITIVE_INFINITY;
  return (nowMs - t) / 60000;
}

export type OverviewMetrics = {
  generatedAt: string;
  attackers: {
    total: number;
    active15m: number;
    byRisk: CountMap;
    byIntent: CountMap;
    byCountry: Array<{ key: string; count: number }>;
    totalScore: number;
  };
  sessions: {
    total: number;
    active: number;
    byService: CountMap;
    byStatus: CountMap;
  };
  transcripts: {
    total: number;
    byService: CountMap;
    byIntent: CountMap;
  };
  logs: {
    total: number;
    byLevel: CountMap;
  };
  alerts: {
    total: number;
    high: number;
  };
  control: {
    defaultAction: string;
    overrides: number;
  };
  services: Array<{ name: string; host: string; port: number }>;
};

export async function buildOverview(): Promise<OverviewMetrics> {
  const now = Date.now();
  const [attackers, sessions, transcripts, logs, control, alerts] = await Promise.all([
    listAttackers(),
    readSessionSnapshots(),
    readTranscripts(),
    readLogEntries(),
    readControlState(),
    readAlerts(),
  ]);

  const totalScore = attackers.reduce((sum, a) => sum + (a.totalScore || 0), 0);

  return {
    generatedAt: new Date(now).toISOString(),
    attackers: {
      total: attackers.length,
      active15m: attackers.filter((a) => minutesAgo(a.lastSeenAt, now) <= 15).length,
      byRisk: tally(attackers, (a) => a.risk),
      byIntent: tally(attackers, (a) => a.intent),
      byCountry: sortedTop(
        tally(attackers, (a) => a.geo?.countryCode || "??"),
        12
      ),
      totalScore,
    },
    sessions: {
      total: sessions.length,
      active: sessions.filter((s) => s.status !== "closed").length,
      byService: tally(sessions, (s) => s.service),
      byStatus: tally(sessions, (s) => s.status),
    },
    transcripts: {
      total: transcripts.length,
      byService: tally(transcripts, (t) => t.service),
      byIntent: tally(transcripts, (t) => t.intent),
    },
    logs: {
      total: logs.length,
      byLevel: tally(logs, (l) => String(l.level || "info")),
    },
    alerts: {
      total: alerts.length,
      high: alerts.filter((a) => a.risk === "high").length,
    },
    control: {
      defaultAction: control.defaultAction,
      overrides: Object.keys(control.sessionActions).length,
    },
    services: Object.entries(config.services).map(([name, cfg]) => ({
      name,
      host: cfg.host,
      port: cfg.port,
    })),
  };
}

export type TimelinePoint = { bucket: string; count: number; exploitation: number };

/**
 * Buckets transcript activity into the last `hours` hours, one point per hour.
 */
export async function buildTimeline(hours = 24): Promise<TimelinePoint[]> {
  const transcripts = await readTranscripts();
  const now = Date.now();
  const hourMs = 3600_000;
  const start = now - hours * hourMs;
  const buckets: TimelinePoint[] = [];
  for (let i = 0; i < hours; i += 1) {
    const bucketStart = start + i * hourMs;
    buckets.push({
      bucket: new Date(bucketStart).toISOString(),
      count: 0,
      exploitation: 0,
    });
  }
  for (const t of transcripts) {
    const at = Date.parse(t.at);
    if (Number.isNaN(at) || at < start) continue;
    const idx = Math.min(hours - 1, Math.floor((at - start) / hourMs));
    if (idx < 0) continue;
    buckets[idx].count += 1;
    if (t.intent === "exploitation") buckets[idx].exploitation += 1;
  }
  return buckets;
}

/** Recent attacker-facing events, newest first, lightly shaped for the GUI. */
export async function buildFeed(limit = 50) {
  const transcripts = await readTranscripts();
  return transcripts
    .slice(-limit)
    .reverse()
    .map((t) => ({
      at: t.at,
      service: t.service,
      sourceIp: t.sourceIp,
      intent: t.intent,
      score: t.score,
      action: t.action,
      request: (t.request || "").slice(0, 240),
      response: (t.response || "").slice(0, 240),
      sessionId: t.sessionId,
      attackerId: t.attackerId,
    }));
}

/** Prometheus text exposition for k8s-native scraping. */
export async function buildPrometheus(): Promise<string> {
  const o = await buildOverview();
  const lines: string[] = [];
  const push = (name: string, help: string, type: string, value: number, labels?: string) => {
    lines.push(`# HELP ${name} ${help}`);
    lines.push(`# TYPE ${name} ${type}`);
    lines.push(`${name}${labels ? `{${labels}}` : ""} ${value}`);
  };
  push("tid_attackers_total", "Total profiled attackers", "gauge", o.attackers.total);
  push("tid_attackers_active_15m", "Attackers seen in last 15m", "gauge", o.attackers.active15m);
  push("tid_attackers_score_total", "Sum of attacker scores", "gauge", o.attackers.totalScore);
  for (const [risk, n] of Object.entries(o.attackers.byRisk)) {
    lines.push(`tid_attackers_by_risk{risk="${risk}"} ${n}`);
  }
  for (const [intent, n] of Object.entries(o.attackers.byIntent)) {
    lines.push(`tid_attackers_by_intent{intent="${intent}"} ${n}`);
  }
  push("tid_sessions_total", "Total recorded sessions", "gauge", o.sessions.total);
  push("tid_sessions_active", "Active sessions", "gauge", o.sessions.active);
  for (const [svc, n] of Object.entries(o.sessions.byService)) {
    lines.push(`tid_sessions_by_service{service="${svc}"} ${n}`);
  }
  push("tid_transcripts_total", "Total recorded transcripts", "counter", o.transcripts.total);
  push("tid_alerts_total", "Total risk-escalation alerts", "counter", o.alerts.total);
  push("tid_alerts_high", "High-risk alerts", "counter", o.alerts.high);
  return lines.join("\n") + "\n";
}
