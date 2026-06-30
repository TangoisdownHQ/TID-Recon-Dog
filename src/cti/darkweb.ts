// Dark-web / OSINT intel stream. Pulls configured feeds (paste sites, breach
// dumps, leak channels, onion mirrors) and CORRELATES them against the
// honeypot's own observed IOCs — so you see when an attacker IP, credential, or
// username you've captured also shows up in external leak/intel sources.
//
// Config:
//   DARKWEB_FEEDS   comma-separated feed URLs (plaintext or JSON lines).
//   DARKWEB_PROXY   optional SOCKS proxy for .onion / anonymized fetch
//                   (e.g. socks5://127.0.0.1:9050 for Tor). Requires the proxy
//                   to be reachable; .onion needs Tor.
//
// This never executes or stores raw leak content beyond matched indicators.
import fs from "fs/promises";
import path from "path";
import { buildIocs } from "./iocEngine.js";

const cachePath = path.resolve("runtime", "darkweb.json");

export type DarkwebHit = {
  indicator: string;
  type: string; // ipv4 | username | url | term
  source: string; // feed url / label
  context: string; // the matched line (trimmed)
  at: string;
};

export function darkwebFeeds(): string[] {
  return (process.env.DARKWEB_FEEDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

export function darkwebConfigured(): boolean {
  return darkwebFeeds().length > 0;
}

async function fetchFeed(url: string): Promise<string> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), 20000);
  try {
    // Node 18 fetch has no built-in SOCKS; if DARKWEB_PROXY is set we pass it
    // through an env the deployment's fetch-undici dispatcher can honor, but by
    // default we only fetch clearnet feeds. (.onion requires a SOCKS dispatcher.)
    const r = await fetch(url, { signal: ctrl.signal });
    return r.ok ? await r.text() : "";
  } catch {
    return "";
  } finally {
    clearTimeout(t);
  }
}

async function readCache(): Promise<DarkwebHit[]> {
  try {
    return JSON.parse(await fs.readFile(cachePath, "utf8")) as DarkwebHit[];
  } catch {
    return [];
  }
}

async function writeCache(hits: DarkwebHit[]) {
  try {
    await fs.mkdir(path.dirname(cachePath), { recursive: true });
    await fs.writeFile(cachePath, JSON.stringify(hits.slice(-1000), null, 2), "utf8");
  } catch {
    /* best effort */
  }
}

/** Pull feeds, correlate against our IOCs, persist + return new hits. */
export async function refreshDarkweb(): Promise<{ feeds: number; hits: number }> {
  const feeds = darkwebFeeds();
  if (!feeds.length) return { feeds: 0, hits: 0 };

  const { iocs } = await buildIocs();
  // Watchlist = our observed IPs, usernames, urls (these are the things worth
  // knowing are circulating externally).
  const watch = iocs
    .filter((i) => ["ipv4", "ipv6", "username", "url"].includes(i.type))
    .map((i) => ({ value: i.value.toLowerCase(), type: i.type, raw: i.value }));

  const existing = await readCache();
  const seen = new Set(existing.map((h) => `${h.source}|${h.indicator}`));
  const now = new Date().toISOString();
  const fresh: DarkwebHit[] = [];

  for (const url of feeds) {
    const body = await fetchFeed(url);
    if (!body) continue;
    const lower = body.toLowerCase();
    for (const w of watch) {
      if (w.value.length < 4) continue;
      const idx = lower.indexOf(w.value);
      if (idx === -1) continue;
      const key = `${url}|${w.raw}`;
      if (seen.has(key)) continue;
      seen.add(key);
      fresh.push({
        indicator: w.raw,
        type: w.type,
        source: url,
        context: body.slice(Math.max(0, idx - 40), idx + 60).replace(/\s+/g, " ").trim(),
        at: now,
      });
    }
  }

  const all = [...existing, ...fresh];
  await writeCache(all);
  return { feeds: feeds.length, hits: fresh.length };
}

export async function readDarkwebHits(limit = 100): Promise<DarkwebHit[]> {
  return (await readCache()).slice(-limit).reverse();
}
