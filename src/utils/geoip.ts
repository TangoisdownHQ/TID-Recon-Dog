import fs from "fs/promises";
import path from "path";

export type GeoResult = {
  country: string;
  countryCode: string;
  city: string;
  isp: string;
  org: string;
  asn: string;
};

const cacheFile = path.resolve("runtime", "geoip-cache.json");
const cache = new Map<string, GeoResult>();
let cacheLoaded = false;
let savePending = false;

async function loadCache() {
  if (cacheLoaded) return;
  cacheLoaded = true;
  try {
    const raw = await fs.readFile(cacheFile, "utf8");
    const data = JSON.parse(raw) as Record<string, GeoResult>;
    for (const [ip, result] of Object.entries(data)) {
      cache.set(ip, result);
    }
  } catch {
    // fresh cache
  }
}

function scheduleSave() {
  if (savePending) return;
  savePending = true;
  setTimeout(async () => {
    savePending = false;
    try {
      await fs.mkdir(path.dirname(cacheFile), { recursive: true });
      const data: Record<string, GeoResult> = {};
      for (const [ip, result] of cache.entries()) {
        data[ip] = result;
      }
      await fs.writeFile(cacheFile, JSON.stringify(data, null, 2), "utf8");
    } catch {
      // best-effort
    }
  }, 2000);
}

const privateRanges = [
  /^127\./,
  /^192\.168\./,
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^::1$/,
  /^fc00:/i,
  /^fd/i,
];

export function isPrivateIp(ip: string): boolean {
  return ip === "unknown" || privateRanges.some((re) => re.test(ip));
}

export async function lookupGeo(ip: string): Promise<GeoResult | null> {
  if (isPrivateIp(ip)) return null;
  await loadCache();
  if (cache.has(ip)) return cache.get(ip)!;

  try {
    const url = `http://ip-api.com/json/${ip}?fields=status,country,countryCode,city,isp,org,as`;
    const controller = new AbortController();
    const tid = setTimeout(() => controller.abort(), 4000);
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(tid);
    const data = await response.json() as Record<string, string>;
    if (data.status !== "success") return null;

    const result: GeoResult = {
      country: data.country || "",
      countryCode: data.countryCode || "",
      city: data.city || "",
      isp: data.isp || "",
      org: data.org || "",
      asn: data.as || "",
    };
    cache.set(ip, result);
    scheduleSave();
    return result;
  } catch {
    return null;
  }
}
