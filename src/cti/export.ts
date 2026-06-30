// Standard CTI export formats so other tools can consume the honeypot's intel.
import crypto from "crypto";
import { buildIocs, buildAttackMatrix, isPublicIp, Ioc } from "./iocEngine.js";

const NS = "tid-recon-dog";
const now = () => new Date().toISOString();

function stixId(type: string, seed: string): string {
  // Deterministic-ish id from a seed so re-exports are stable.
  const uuid = crypto.createHash("sha1").update(`${NS}:${type}:${seed}`).digest("hex");
  return `${type}--${uuid.slice(0, 8)}-${uuid.slice(8, 12)}-${uuid.slice(12, 16)}-${uuid.slice(16, 20)}-${uuid.slice(20, 32)}`;
}

const STIX_PATTERN: Partial<Record<Ioc["type"], (v: string) => string>> = {
  ipv4: (v) => `[ipv4-addr:value = '${v.replace(/'/g, "")}']`,
  ipv6: (v) => `[ipv6-addr:value = '${v.replace(/'/g, "")}']`,
  url: (v) => `[url:value = '${v.replace(/'/g, "")}']`,
  username: (v) => `[user-account:account_login = '${v.replace(/'/g, "")}']`,
  "user-agent": (v) => `[network-traffic:extensions.'http-request-ext'.request_header.'User-Agent' = '${v.replace(/'/g, "")}']`,
};

/** STIX 2.1 bundle: identity + indicators + attack-patterns. */
export async function buildStixBundle(): Promise<object> {
  const { iocs } = await buildIocs();
  const techniques = await buildAttackMatrix();
  const ts = now();
  const identity = {
    type: "identity",
    spec_version: "2.1",
    id: stixId("identity", NS),
    created: ts,
    modified: ts,
    name: "TID-Recon-Dog",
    identity_class: "system",
    description: "Deception-driven CTI source",
  };

  const objects: object[] = [identity];

  for (const ioc of iocs) {
    const pattern = STIX_PATTERN[ioc.type]?.(ioc.value);
    if (!pattern) continue;
    objects.push({
      type: "indicator",
      spec_version: "2.1",
      id: stixId("indicator", `${ioc.type}:${ioc.value}`),
      created: ioc.firstSeen,
      modified: ioc.lastSeen,
      created_by_ref: identity.id,
      name: `${ioc.type}: ${ioc.value.slice(0, 80)}`,
      indicator_types: ["malicious-activity"],
      pattern,
      pattern_type: "stix",
      valid_from: ioc.firstSeen,
      labels: [`count:${ioc.count}`],
    });
  }

  for (const t of techniques) {
    objects.push({
      type: "attack-pattern",
      spec_version: "2.1",
      id: stixId("attack-pattern", t.id),
      created: ts,
      modified: ts,
      created_by_ref: identity.id,
      name: t.name,
      external_references: [{ source_name: "mitre-attack", external_id: t.id }],
      labels: [t.tactic, `observations:${t.count}`],
    });
  }

  return { type: "bundle", id: stixId("bundle", ts), objects };
}

/** MISP event JSON (importable into a MISP instance). */
export async function buildMispEvent(): Promise<object> {
  const { iocs } = await buildIocs();
  const typeMap: Partial<Record<Ioc["type"], string>> = {
    ipv4: "ip-src",
    ipv6: "ip-src",
    url: "url",
    username: "target-user",
    "user-agent": "user-agent",
    command: "comment",
  };
  const attributes = iocs
    .map((i) => {
      const mtype = typeMap[i.type];
      if (!mtype) return null;
      return { type: mtype, category: i.type === "ipv4" ? "Network activity" : "Payload delivery", value: i.value, to_ids: i.type === "ipv4" || i.type === "url", comment: `seen ${i.count}x` };
    })
    .filter(Boolean);
  return {
    Event: {
      info: "TID-Recon-Dog honeypot observations",
      date: now().slice(0, 10),
      threat_level_id: "2",
      analysis: "1",
      Attribute: attributes,
    },
  };
}

/** Plain IP blocklist (one per line) + a CSV variant for firewalls/SIEM. */
export async function buildBlocklist(): Promise<{ txt: string; csv: string }> {
  const { iocs } = await buildIocs();
  const ips = iocs.filter((i) => (i.type === "ipv4" || i.type === "ipv6") && isPublicIp(i.value));
  const txt = ips.map((i) => i.value).join("\n") + "\n";
  const csv = "ip,count,first_seen,last_seen\n" + ips.map((i) => `${i.value},${i.count},${i.firstSeen},${i.lastSeen}`).join("\n") + "\n";
  return { txt, csv };
}
