// Dark-web / OSINT intel stream. Pulls configured feeds (paste sites, breach
// dumps, leak channels, onion mirrors) and CORRELATES them against the
// honeypot's own observed IOCs — so you see when an attacker IP, credential, or
// username you've captured also shows up in external leak/intel sources.
//
// It does two things:
//   1. CORRELATION — flags when one of our captured IOCs shows up in a feed.
//   2. NEWS/EVENTS — surfaces feed entries themselves (leak announcements,
//      breach dumps, marketplace listings, actor chatter) as a dark-web news
//      stream, even when they don't match our own indicators. Every news item
//      is clearly tagged origin: "dark-web" so the operator can never mistake
//      it for honeypot-observed activity.
//
// Config:
//   DARKWEB_FEEDS       comma-separated feed URLs (plaintext or JSON lines).
//                       Used for IOC correlation AND as news sources.
//   DARKWEB_NEWS_FEEDS  optional extra feeds used only for the news/event
//                       stream (headlines, RSS-as-JSONL, breach trackers).
//   DARKWEB_PROXY       optional SOCKS proxy for .onion / anonymized fetch.
//                       When set, feeds are pulled through it via a SOCKS agent
//                       (Node's built-in fetch can't do SOCKS, so proxied
//                       requests go through node http/https instead). Use
//                       socks5h://127.0.0.1:9050 for Tor — the "h" makes the
//                       proxy resolve DNS, which .onion addresses require.
//                       Falls back to a direct clearnet fetch if unset or if
//                       the socks-proxy-agent dependency is unavailable.
//
// This never executes or stores raw leak content beyond matched indicators
// and sanitized headlines/summaries.
import fs from "fs/promises";
import path from "path";
import { buildIocs } from "./iocEngine.js";
import { sanitizeText } from "../responders/safety.js";

const cachePath = path.resolve("runtime", "darkweb.json");
const newsCachePath = path.resolve("runtime", "darkweb-news.json");

export type DarkwebHit = {
  indicator: string;
  type: string; // ipv4 | username | url | term
  source: string; // feed url / label
  context: string; // the matched line (trimmed)
  at: string;
};

// A standalone dark-web news / event item (not tied to our own IOCs).
export type DarkwebNewsKind = "leak" | "breach" | "chatter" | "listing" | "news";
export type DarkwebNewsItem = {
  id: string; // dedupe key (source + title hash-ish)
  title: string;
  summary: string;
  source: string; // feed url / label
  kind: DarkwebNewsKind;
  at: string;
  tags: string[];
};

// Unified, source-annotated feed entry merging correlation hits + news items.
export type DarkwebFeedItem = {
  at: string;
  origin: "dark-web"; // constant annotation — always external
  kind: string; // "correlation" | DarkwebNewsKind
  title: string; // indicator (correlation) or headline (news)
  detail: string; // matched context or news summary
  source: string;
  indicator?: string; // present on correlation entries
  indicatorType?: string;
  tags: string[];
};

export function darkwebFeeds(): string[] {
  return (process.env.DARKWEB_FEEDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

// Feeds used for the news/event stream: dedicated news feeds plus the
// correlation feeds (every leak/paste source doubles as a news source).
export function darkwebNewsFeeds(): string[] {
  const extra = (process.env.DARKWEB_NEWS_FEEDS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return Array.from(new Set([...extra, ...darkwebFeeds()]));
}

export function darkwebConfigured(): boolean {
  return darkwebFeeds().length > 0 || (process.env.DARKWEB_NEWS_FEEDS || "").trim().length > 0;
}

const FETCH_TIMEOUT_MS = 20000;
const MAX_FEED_BYTES = 5_000_000; // don't buffer unbounded leak dumps

export function darkwebProxy(): string {
  return (process.env.DARKWEB_PROXY || "").trim();
}

// Build a SOCKS agent for the configured proxy. Lazily imported so the module
// still loads (and clearnet fetch still works) if the optional dependency is
// missing. Returns null if no proxy is set or the agent can't be created.
async function socksAgent(): Promise<import("http").Agent | null> {
  const proxy = darkwebProxy();
  if (!proxy) return null;
  try {
    const { SocksProxyAgent } = await import("socks-proxy-agent");
    return new SocksProxyAgent(proxy) as unknown as import("http").Agent;
  } catch {
    return null;
  }
}

// Fetch a feed through a SOCKS proxy using node http/https (which handle TLS,
// chunked encoding, and redirects — things a hand-rolled socket can't). Follows
// up to a few redirects and caps the body size.
function fetchViaSocks(url: string, agent: import("http").Agent, redirectsLeft = 3): Promise<string> {
  return new Promise((resolve) => {
    let lib: typeof import("https");
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      resolve("");
      return;
    }
    const isHttps = parsed.protocol === "https:";
    const mod = isHttps ? "https" : "http";
    import(mod)
      .then((m: any) => {
        lib = m.default || m;
        const req = lib.get(url, { agent, timeout: FETCH_TIMEOUT_MS } as any, (res) => {
          const status = res.statusCode || 0;
          const loc = res.headers.location;
          if (status >= 300 && status < 400 && loc && redirectsLeft > 0) {
            res.resume();
            resolve(fetchViaSocks(new URL(loc, url).toString(), agent, redirectsLeft - 1));
            return;
          }
          if (status < 200 || status >= 400) {
            res.resume();
            resolve("");
            return;
          }
          let data = "";
          res.setEncoding("utf8");
          res.on("data", (c: string) => {
            data += c;
            if (data.length > MAX_FEED_BYTES) req.destroy();
          });
          res.on("end", () => resolve(data));
        });
        req.on("timeout", () => req.destroy());
        req.on("error", () => resolve(""));
      })
      .catch(() => resolve(""));
  });
}

async function fetchFeed(url: string): Promise<string> {
  // .onion (and any anonymized fetch) requires the SOCKS proxy: route through
  // node http/https + a SOCKS agent. Node's built-in fetch has no SOCKS support.
  const agent = await socksAgent();
  if (agent) return fetchViaSocks(url, agent);

  // Clearnet path: plain fetch with an abort-based timeout.
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
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

async function readNewsCache(): Promise<DarkwebNewsItem[]> {
  try {
    return JSON.parse(await fs.readFile(newsCachePath, "utf8")) as DarkwebNewsItem[];
  } catch {
    return [];
  }
}

async function writeNewsCache(items: DarkwebNewsItem[]) {
  try {
    await fs.mkdir(path.dirname(newsCachePath), { recursive: true });
    await fs.writeFile(newsCachePath, JSON.stringify(items.slice(-1000), null, 2), "utf8");
  } catch {
    /* best effort */
  }
}

// Heuristic classification of a headline/summary into a dark-web event kind.
function classifyNews(text: string): DarkwebNewsKind {
  const t = text.toLowerCase();
  if (/\b(breach|breached|hacked|data\s*leak|exposed\s+database|ransom)\b/.test(t)) return "breach";
  if (/\b(dump|combo\s*list|credentials?|passwords?|paste|leak)\b/.test(t)) return "leak";
  if (/\b(for\s*sale|selling|market|listing|price|btc|monero|xmr|vendor)\b/.test(t)) return "listing";
  if (/\b(forum|thread|channel|telegram|chatter|claims?|threat\s*actor)\b/.test(t)) return "chatter";
  return "news";
}

// Stable-ish dedupe id from source + title without Date/random.
function newsId(source: string, title: string): string {
  let h = 0;
  const s = source + "|" + title;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return "dw_" + (h >>> 0).toString(36);
}

// Field aliases seen across common feeds: generic news JSON, RSS-as-JSON,
// ransomware leak-site trackers (ransomware.live: post_title/group_name/
// discovered), paste/breach APIs.
const pickTitle = (o: any): string => o.title || o.headline || o.name || o.post_title || o.victim || o.subject || "";
const pickSummary = (o: any): string => o.summary || o.description || o.text || o.info || o.details || o.body || "";
const pickKind = (o: any): string | undefined => o.kind || o.category || o.type;
const pickAt = (o: any): string | undefined => o.at || o.date || o.published || o.discovered || o.created || o.pubDate || o.post_date;
function pickTags(o: any): string[] | undefined {
  if (Array.isArray(o.tags)) return o.tags as string[];
  const t: string[] = [];
  if (o.group_name) t.push(String(o.group_name));
  else if (o.group) t.push(String(o.group));
  if (o.country) t.push(String(o.country));
  if (o.activity && o.activity !== "Not Found") t.push(String(o.activity));
  return t.length ? t : undefined;
}

// Minimal XML helpers (no XML dep) — enough to lift <item>/<entry> fields.
const stripCdata = (s: string): string => s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1");
const decodeEntities = (s: string): string =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;|&apos;/g, "'").replace(/&#x27;/gi, "'").replace(/&amp;/g, "&");
const stripHtml = (s: string): string => decodeEntities(stripCdata(s)).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
function xmlTag(xml: string, name: string): string {
  const m = xml.match(new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)<\\/${name}>`, "i"));
  return m ? stripHtml(m[1]) : "";
}

// Parse one feed body into news items. Supports RSS/Atom (XML), JSON arrays,
// JSON objects that wrap an array (e.g. {data:[...]}), JSON-lines, and falls
// back to treating non-empty plaintext lines as headlines.
function parseNews(body: string, source: string, now: string): DarkwebNewsItem[] {
  const out: DarkwebNewsItem[] = [];
  const push = (rawTitle: string, rawSummary: string, kind?: string, tags?: unknown, at?: string) => {
    const title = sanitizeText(String(rawTitle || "").trim(), undefined, 200);
    if (!title) return;
    const summary = sanitizeText(String(rawSummary || "").trim(), undefined, 400);
    const tagList = Array.isArray(tags)
      ? tags.map((x) => sanitizeText(String(x), undefined, 40)).filter(Boolean).slice(0, 8)
      : [];
    const k: DarkwebNewsKind = (["leak", "breach", "chatter", "listing", "news"].includes(String(kind))
      ? (kind as DarkwebNewsKind)
      : classifyNews([title, summary, ...tagList].join(" ")));
    // Normalize the timestamp to ISO so mixed feeds (RSS pubDate vs JSON ISO)
    // sort consistently in the unified feed.
    let when = now;
    if (at) {
      const d = new Date(at);
      if (!isNaN(d.getTime())) when = d.toISOString();
    }
    out.push({ id: newsId(source, title), title, summary, source, kind: k, at: when, tags: tagList });
  };
  const pushObj = (o: any) => {
    if (o && typeof o === "object") push(pickTitle(o), pickSummary(o), pickKind(o), pickTags(o), pickAt(o));
  };

  const trimmed = body.trim();

  // RSS / Atom (XML) — lift each <item>/<entry>.
  if (/^<\?xml|^<rss\b|^<feed\b/i.test(trimmed) || /<(item|entry)\b/i.test(trimmed)) {
    const entries = trimmed.match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) || [];
    for (const e of entries) {
      push(xmlTag(e, "title"), xmlTag(e, "description") || xmlTag(e, "summary") || xmlTag(e, "content"), undefined, undefined, xmlTag(e, "pubDate") || xmlTag(e, "published") || xmlTag(e, "updated"));
    }
    if (out.length) return out;
  }

  // JSON array, or an object wrapping an array under a common key.
  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      let arr: any[] | null = Array.isArray(parsed) ? parsed : null;
      if (!arr && parsed && typeof parsed === "object") {
        const keys = ["data", "results", "items", "victims", "posts", "entries", "list"];
        const k = keys.find((x) => Array.isArray(parsed[x]));
        arr = k ? parsed[k] : ((Object.values(parsed).find((v) => Array.isArray(v)) as any[]) || null);
      }
      if (arr) {
        for (const o of arr) pushObj(o);
        if (out.length) return out;
      }
    } catch {
      /* fall through to line parsing */
    }
  }

  // JSON-lines or plaintext headlines.
  for (const line of trimmed.split(/\r?\n/)) {
    const s = line.trim();
    if (!s) continue;
    if (s.startsWith("{")) {
      try {
        pushObj(JSON.parse(s));
        continue;
      } catch {
        /* treat as plaintext */
      }
    }
    push(s, "");
  }
  return out;
}

/** Pull news/event feeds, sanitize + classify entries, persist + return count. */
export async function refreshDarkwebNews(): Promise<{ feeds: number; items: number }> {
  const feeds = darkwebNewsFeeds();
  if (!feeds.length) return { feeds: 0, items: 0 };

  const existing = await readNewsCache();
  const seen = new Set(existing.map((n) => n.id));
  const now = new Date().toISOString();
  const fresh: DarkwebNewsItem[] = [];

  for (const url of feeds) {
    const body = await fetchFeed(url);
    if (!body) continue;
    for (const item of parseNews(body, url, now)) {
      if (seen.has(item.id)) continue;
      seen.add(item.id);
      fresh.push(item);
    }
  }

  await writeNewsCache([...existing, ...fresh]);
  return { feeds: feeds.length, items: fresh.length };
}

export async function readDarkwebNews(limit = 100): Promise<DarkwebNewsItem[]> {
  return (await readNewsCache()).slice(-limit).reverse();
}

/**
 * Pull feeds, correlate against our IOCs, AND refresh the news/event stream.
 * Persists both and returns counts for each.
 */
export async function refreshDarkweb(): Promise<{ feeds: number; hits: number; news: number }> {
  const news = await refreshDarkwebNews();
  const feeds = darkwebFeeds();
  if (!feeds.length) return { feeds: news.feeds, hits: 0, news: news.items };

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
  return { feeds: feeds.length, hits: fresh.length, news: news.items };
}

export async function readDarkwebHits(limit = 100): Promise<DarkwebHit[]> {
  return (await readCache()).slice(-limit).reverse();
}

/**
 * Unified dark-web feed: merges correlation hits + news/event items into one
 * chronological stream, each entry annotated origin: "dark-web".
 */
export async function buildDarkwebFeed(limit = 150): Promise<DarkwebFeedItem[]> {
  const [hits, news] = await Promise.all([readDarkwebHits(limit), readDarkwebNews(limit)]);
  const items: DarkwebFeedItem[] = [];
  for (const h of hits) {
    items.push({
      at: h.at,
      origin: "dark-web",
      kind: "correlation",
      title: h.indicator,
      detail: h.context,
      source: h.source,
      indicator: h.indicator,
      indicatorType: h.type,
      tags: [],
    });
  }
  for (const n of news) {
    items.push({
      at: n.at,
      origin: "dark-web",
      kind: n.kind,
      title: n.title,
      detail: n.summary,
      source: n.source,
      tags: n.tags,
    });
  }
  return items.sort((a, b) => b.at.localeCompare(a.at)).slice(0, limit);
}
