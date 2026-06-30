// Ingest external IP blocklist feeds and auto-block known-bad on the honeypot.
// Feed URLs come from THREAT_FEEDS (comma-separated). Each feed is a plaintext
// list of IPs/CIDRs, one per line (comments with # ignored) — the common format
// used by FireHOL, abuse.ch, spamhaus drop, etc.
import { blockIp } from "../operator/controlPlane.js";

const IP_RE = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;

export function feedUrls(): string[] {
  return (process.env.THREAT_FEEDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
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
  let blocked = 0;
  for (const ip of seen) {
    await blockIp(ip);
    blocked += 1;
  }
  return { feeds: urls.length, blocked };
}
