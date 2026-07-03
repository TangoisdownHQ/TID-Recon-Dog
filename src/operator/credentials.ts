// Credentials analytics: aggregate the usernames attackers try, across the whole
// fleet, by frequency and by service — turning 100s of brute-force events into a
// live picture of the wordlists in use. Built from captured attacker profiles
// (usernames per service). Passwords are intentionally stored length-only, so we
// report usernames + attempt volume, not plaintext secrets.
import { listAttackers } from "../deception_engine/state/attacker_memory.js";

export type CredentialStat = {
  username: string;
  sources: number; // distinct source IPs that tried it
  services: string[]; // services it was tried against
  authAttempts: number; // total auth attempts from those sources
  sampleIps: string[];
};

export type CredentialsReport = {
  totalAttempts: number; // sum of authAttempts across brute-forcing attackers
  uniqueUsernames: number;
  topUsernames: CredentialStat[];
  byService: Record<string, number>; // distinct usernames seen per service
};

export async function buildCredentials(limit = 100): Promise<CredentialsReport> {
  const attackers = await listAttackers();
  const byUser = new Map<string, { sources: Set<string>; services: Set<string>; attempts: number; ips: Set<string> }>();
  const serviceUsers = new Map<string, Set<string>>();
  let totalAttempts = 0;

  for (const a of attackers) {
    totalAttempts += a.counters?.authAttempts || 0;
    for (const [svc, mem] of Object.entries(a.services)) {
      if (!mem) continue;
      for (const uname of mem.usernames || []) {
        if (!uname) continue;
        const key = uname.toLowerCase();
        let e = byUser.get(key);
        if (!e) { e = { sources: new Set(), services: new Set(), attempts: 0, ips: new Set() }; byUser.set(key, e); }
        e.sources.add(a.sourceIp);
        e.services.add(svc);
        e.attempts += a.counters?.authAttempts || 0;
        if (e.ips.size < 5) e.ips.add(a.sourceIp);

        if (!serviceUsers.has(svc)) serviceUsers.set(svc, new Set());
        serviceUsers.get(svc)!.add(key);
      }
    }
  }

  const topUsernames: CredentialStat[] = Array.from(byUser.entries())
    .map(([username, e]) => ({
      username,
      sources: e.sources.size,
      services: Array.from(e.services),
      authAttempts: e.attempts,
      sampleIps: Array.from(e.ips),
    }))
    .sort((a, b) => b.sources - a.sources || b.authAttempts - a.authAttempts)
    .slice(0, limit);

  const byService: Record<string, number> = {};
  for (const [svc, set] of serviceUsers) byService[svc] = set.size;

  return {
    totalAttempts,
    uniqueUsernames: byUser.size,
    topUsernames,
    byService,
  };
}
