// Ingest external IP blocklist feeds and auto-block known-bad on the honeypot.
// Feed URLs come from THREAT_FEEDS (comma-separated). Each feed is a plaintext
// list of IPs/CIDRs, one per line (comments with # ignored) — the common format
// used by FireHOL, abuse.ch, spamhaus drop, etc.
import { blockIps } from "../operator/controlPlane.js";

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

export function feedUrls(): string[] {
  return (process.env.THREAT_FEEDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/**
 * Whether feed IPs should be auto-blocked on the scheduled cadence. Off by
 * default: configuring THREAT_FEEDS only fetches the lists; nothing is blocked
 * until an operator explicitly opts in (THREAT_FEEDS_AUTOBLOCK=true) or runs a
 * manual ingest. This keeps the honeypot from blanket-blocking IPs nobody
 * specified — which can lock out management/health-check addresses.
 */
export function autoBlockEnabled(): boolean {
  return /^(1|true|yes|on)$/i.test(process.env.THREAT_FEEDS_AUTOBLOCK || "");
}

async function fetchFeed(url: string): Promise<string[]> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 15000);
  try {
    const r = await fetch(url, { signal: ctrl.signal });
    if (!r.ok) return [];
    const text = await r.text();
    return text
      .split(/\r?\n/)
      .map((l) => l.split("#")[0].trim())
      .filter((l) => IP_RE.test(l))
      // Only block bare IPs (CIDR blocking would need range logic in the throttle).
      .map((l) => l.split("/")[0]);
  } catch {
    return [];
  } finally {
    clearTimeout(t);
  }
}

export async function ingestFeeds(): Promise<{ feeds: number; blocked: number }> {
  const urls = feedUrls();
  const seen = new Set<string>();
  for (const url of urls) {
    for (const ip of await fetchFeed(url)) seen.add(ip);
  }
  // Single batched write — never one file rewrite per IP.
  const blocked = await blockIps([...seen]);
  return { feeds: urls.length, blocked };
}
