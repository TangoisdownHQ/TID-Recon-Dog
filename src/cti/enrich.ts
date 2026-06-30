// Optional IP reputation enrichment. Each provider is used only if its API key
// is set; results are cached so we don't re-query. All failures are non-fatal.
import fs from "fs/promises";
import path from "path";

const cachePath = path.resolve("runtime", "enrichment.json");

export type Enrichment = {
  ip: string;
  abuseConfidence?: number;
  greynoise?: string; // classification: benign/malicious/unknown
  vtMalicious?: number;
  at: string;
};

type Cache = Record<string, Enrichment>;

async function readCache(): Promise<Cache> {
  try {
    return JSON.parse(await fs.readFile(cachePath, "utf8")) as Cache;
  } catch {
    return {};
  }
}

async function writeCache(c: Cache) {
  try {
    await fs.mkdir(path.dirname(cachePath), { recursive: true });
    await fs.writeFile(cachePath, JSON.stringify(c, null, 2), "utf8");
  } catch {
    /* best effort */
  }
}

export function enrichmentProviders(): string[] {
  const p: string[] = [];
  if (process.env.ABUSEIPDB_API_KEY) p.push("abuseipdb");
  if (process.env.GREYNOISE_API_KEY) p.push("greynoise");
  if (process.env.VIRUSTOTAL_API_KEY) p.push("virustotal");
  return p;
}

async function getJson(url: string, headers: Record<string, string>, timeoutMs = 8000): Promise<any | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const r = await fetch(url, { headers, signal: ctrl.signal });
    return r.ok ? await r.json() : null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

export async function enrichIp(ip: string, force = false): Promise<Enrichment> {
  const cache = await readCache();
  if (!force && cache[ip]) return cache[ip];

  const out: Enrichment = { ip, at: new Date().toISOString() };

  if (process.env.ABUSEIPDB_API_KEY) {
    const d = await getJson(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}`, {
      Key: process.env.ABUSEIPDB_API_KEY,
      Accept: "application/json",
    });
    if (d?.data) out.abuseConfidence = d.data.abuseConfidenceScore;
  }
  if (process.env.GREYNOISE_API_KEY) {
    const d = await getJson(`https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`, {
      key: process.env.GREYNOISE_API_KEY,
    });
    if (d?.classification) out.greynoise = d.classification;
  }
  if (process.env.VIRUSTOTAL_API_KEY) {
    const d = await getJson(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`, {
      "x-apikey": process.env.VIRUSTOTAL_API_KEY,
    });
    const stats = d?.data?.attributes?.last_analysis_stats;
    if (stats) out.vtMalicious = stats.malicious;
  }

  cache[ip] = out;
  await writeCache(cache);
  return out;
}
