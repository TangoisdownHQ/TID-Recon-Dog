// Per-IP connection throttle for raw TCP services.
// HTTP already uses express-rate-limit; this guards the remaining socket-based services.

import { logWarning } from "./logger.js";
import { isIpBlockedSync } from "../operator/controlPlane.js";

const MAX_PER_IP = parseInt(process.env.MAX_CONNECTIONS_PER_IP || "25", 10);
const counts = new Map<string, number>();

function key(ip: string, service: string) {
  return `${service}:${ip}`;
}

export function acquireConnection(ip: string, service: string): boolean {
  // Operator-issued block: refuse the connection outright (kick/keep out).
  if (isIpBlockedSync(ip)) {
    return false;
  }
  const k = key(ip, service);
  const current = counts.get(k) ?? 0;
  if (current >= MAX_PER_IP) {
    void logWarning(service.toUpperCase(), ip, `Connection limit reached (${current}/${MAX_PER_IP})`);
    return false;
  }
  counts.set(k, current + 1);
  return true;
}

export function releaseConnection(ip: string, service: string) {
  const k = key(ip, service);
  const current = counts.get(k) ?? 0;
  if (current <= 1) {
    counts.delete(k);
  } else {
    counts.set(k, current - 1);
  }
}

export function getConnectionCount(ip: string, service: string): number {
  return counts.get(key(ip, service)) ?? 0;
}
