export type ServiceProfile = {
  service: string;
  displayName: string;
  product: string;
  version: string;
  banner: string;
  host: string;
  realm: string;
  ports: number[];
  tags: string[];
  traits: string[];
};

const serviceProfiles: Record<string, ServiceProfile> = {
  http: {
    service: "HTTP",
    displayName: "CamWatch Admin Gateway",
    product: "nginx",
    version: "1.27.4",
    banner: "Server: nginx/1.27.4",
    host: "cam-gateway-dc4.internal",
    realm: "DC4 Camera Operations",
    ports: [3000],
    tags: ["web", "camera", "admin-panel"],
    traits: ["short errors", "leaks internal routes", "pretends to proxy upstream relay"],
  },
  ssh: {
    service: "SSH",
    displayName: "Relay Edge Shell",
    product: "OpenSSH",
    version: "8.9p1 Ubuntu-3ubuntu0.10",
    banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    host: "relay-edge-01.internal",
    realm: "Edge Operations",
    ports: [2222],
    tags: ["shell", "linux", "ops"],
    traits: ["slow auth rejection", "fake Ubuntu host", "interactive shell lure"],
  },
  ftp: {
    service: "FTP",
    displayName: "Backup Drop FTP",
    product: "vsFTPd",
    version: "3.0.5",
    banner: "220 (vsFTPd 3.0.5)",
    host: "backup-drop.internal",
    realm: "Archive Relay",
    ports: [2121],
    tags: ["storage", "backup", "legacy"],
    traits: ["rejects auth", "suggests archived data exists"],
  },
  postgres: {
    service: "POSTGRES",
    displayName: "Operations DB",
    product: "PostgreSQL",
    version: "14.11",
    banner: "PostgreSQL 14.11 on x86_64-pc-linux-gnu",
    host: "ops-db.internal",
    realm: "Telemetry Warehouse",
    ports: [5432],
    tags: ["database", "ops", "sql"],
    traits: ["accepts connection", "drops after error", "pretends auth exists"],
  },
  rtsp: {
    service: "RTSP",
    displayName: "CamWatch RTSP Relay",
    product: "CamWatch Media Relay",
    version: "4.8.12",
    banner: "RTSP/1.0 200 OK\r\nServer: CamWatch Media Relay/4.8.12",
    host: "nvr-dc4-edge-02.internal",
    realm: "Camera Stream Relay",
    ports: [8554],
    tags: ["camera", "video", "rtsp"],
    traits: ["supports DESCRIBE/SETUP/PLAY", "returns believable SDP", "times out under load"],
  },
  rdp: {
    service: "RDP",
    displayName: "Windows Jump Host",
    product: "Microsoft Terminal Services",
    version: "10.0.17763",
    banner: "Cookie: mstshash=ADMIN-JUMP\r\n",
    host: "admin-jump-01.internal",
    realm: "Remote Access",
    ports: [3389],
    tags: ["windows", "desktop", "admin"],
    traits: ["fake preauth", "delayed reset", "corp desktop naming"],
  },
  telnet: {
    service: "TELNET",
    displayName: "Legacy Field Gateway",
    product: "BusyBox",
    version: "1.35.0",
    banner: "FieldGateway login:",
    host: "field-gw-legacy.internal",
    realm: "Legacy Device Access",
    ports: [2323],
    tags: ["iot", "legacy", "shell"],
    traits: ["simple login prompt", "busybox shell lure", "captures credentials"],
  },
  modbus: {
    service: "MODBUS",
    displayName: "PLC Relay Controller",
    product: "Schneider Modicon Bridge",
    version: "2.14",
    banner: "MBTCP unit 1 online",
    host: "plc-edge-04.internal",
    realm: "Industrial Controls",
    ports: [1502],
    tags: ["ics", "ot", "plc"],
    traits: ["responds to read coils", "static holding registers", "pretends unit id 1"],
  },
  snmp: {
    service: "SNMP",
    displayName: "PLC SNMP Agent",
    product: "Net-SNMP",
    version: "5.9.3",
    banner: "SNMP agent ready",
    host: "plc-edge-04.internal",
    realm: "Industrial Controls",
    ports: [16100],
    tags: ["ics", "ot", "snmp", "udp"],
    traits: ["returns sysDescr", "exposes pressure and RPM OIDs", "community: public"],
  },
  smtp: {
    service: "SMTP",
    displayName: "Ops Mail Relay",
    product: "Postfix",
    version: "3.6.4",
    banner: "220 mail-relay-ops-01.internal ESMTP Postfix (Ubuntu)",
    host: "mail-relay-ops-01.internal",
    realm: "Operations Mail",
    ports: [2525],
    tags: ["mail", "smtp", "ops"],
    traits: ["ESMTP with AUTH", "rejects AUTH credentials", "queues mail silently"],
  },
};

export function getServiceProfile(serviceName: string): ServiceProfile {
  const key = serviceName.toLowerCase();
  return serviceProfiles[key] || {
    service: serviceName.toUpperCase(),
    displayName: `${serviceName.toUpperCase()} Service`,
    product: "Generic Appliance",
    version: "1.0",
    banner: `${serviceName.toUpperCase()} ready`,
    host: `${key}.internal`,
    realm: "Generic Realm",
    ports: [],
    tags: ["generic"],
    traits: ["generic response"],
  };
}

export function listServiceProfiles(): ServiceProfile[] {
  return Object.values(serviceProfiles);
}
