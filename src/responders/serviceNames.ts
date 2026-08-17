export const responderServices = [
  "http",
  "ssh",
  "postgres",
  "ftp",
  "rtsp",
  "rdp",
  "telnet",
  "modbus",
  "snmp",
  "smtp",
  "redis",
] as const;

export type ResponderServiceName = typeof responderServices[number];

const aliases: Record<string, ResponderServiceName> = {
  camera: "http",
  "camera-api": "http",
  "http-shell": "http",
  pg: "postgres",
  postgresql: "postgres",
  "redis-cache": "redis",
  valkey: "redis",
};

export function normalizeServiceName(service: string): ResponderServiceName {
  const key = service.trim().toLowerCase();
  if ((responderServices as readonly string[]).includes(key)) {
    return key as ResponderServiceName;
  }

  if (aliases[key]) {
    return aliases[key];
  }

  if (key.startsWith("camera")) return "http";
  if (key.includes("shell")) return "http";
  if (key.startsWith("smtp")) return "smtp";
  if (key.startsWith("snmp")) return "snmp";
  if (key.startsWith("redis")) return "redis";

  return "http";
}
