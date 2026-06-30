import crypto from "crypto";
import { ResponderServiceName } from "../responders/serviceNames.js";

export type PersonaGroup =
  | "camera_nvr"
  | "jump_host"
  | "backup_server"
  | "operations_db"
  | "field_gateway"
  | "plc_controller"
  | "mail_relay";

export type PersonaFile = {
  path: string;
  contents: string;
  modifiedAt: string;
};

export type PersonaStateValue = string | number | boolean;

export type ServicePersonaOverlay = {
  banner: string;
  usernames: string[];
  files?: PersonaFile[];
  deviceState?: Record<string, PersonaStateValue>;
};

export type DecoyPersona = {
  id: string;
  group: PersonaGroup;
  displayName: string;
  host: string;
  realm: string;
  description: string;
  services: Partial<Record<ResponderServiceName, ServicePersonaOverlay>>;
};

const personas: DecoyPersona[] = [
  {
    id: "camera-dc4-loading-dock",
    group: "camera_nvr",
    displayName: "CamWatch DC4 Loading Dock",
    host: "nvr-dc4-edge-02.internal",
    realm: "DC4 Camera Operations",
    description: "Warehouse loading dock NVR with archive relay and motion-tagged clips.",
    services: {
      http: {
        banner: "Server: nginx/1.24.0",
        usernames: ["camadmin", "ops.camera", "svc_rtsp"],
        files: [
          {
            path: "/backup.sql",
            contents: "-- CamWatch archive catalog\nCREATE TABLE clips (camera_id text, started_at timestamptz, event text);",
            modifiedAt: "2026-04-15T06:14:00Z",
          },
          {
            path: "/secrets.env",
            contents: "RTSP_REALM=DC4 Camera Operations\nARCHIVE_NODE=nvr-dc4-edge-02.internal\nCLIP_RETENTION_DAYS=14",
            modifiedAt: "2026-04-12T03:10:00Z",
          },
          {
            path: "/config.yaml",
            contents: "site: dc4-loading-dock\nrelay_host: nvr-dc4-edge-02.internal\nstream_path: /Streaming/Channels/401",
            modifiedAt: "2026-04-10T04:11:00Z",
          },
        ],
        deviceState: {
          channel: "401",
          codec: "h264",
          retention_days: 14,
          motion: "clear",
        },
      },
      rtsp: {
        banner: "RTSP/1.0 200 OK\r\nServer: CamWatch Media Relay/4.8.12",
        usernames: ["camadmin", "svc_rtsp", "viewer.dc4"],
        deviceState: {
          channel: "401",
          stream_name: "loading-dock-cam04",
          status: "live",
          profile: "main",
        },
      },
    },
  },
  {
    id: "camera-west-yard",
    group: "camera_nvr",
    displayName: "CamWatch West Yard",
    host: "nvr-yard-west-07.internal",
    realm: "West Yard Camera Cluster",
    description: "Outdoor camera relay serving truck gate and west yard streams.",
    services: {
      http: {
        banner: "Server: nginx/1.24.0",
        usernames: ["yard.ops", "svc_camrelay", "viewer.west"],
        files: [
          {
            path: "/notes.md",
            contents: "# Yard Relay Notes\n- Camera 07 requires digest auth\n- Gate sensor events mirrored to archive tier",
            modifiedAt: "2026-04-14T05:21:00Z",
          },
          {
            path: "/credentials.txt",
            contents: "role: viewer.west\nrealm: West Yard Camera Cluster\nrotation: weekly",
            modifiedAt: "2026-04-09T07:30:00Z",
          },
        ],
        deviceState: {
          channel: "207",
          codec: "h265",
          retention_days: 21,
          motion: "detected",
        },
      },
      rtsp: {
        banner: "RTSP/1.0 200 OK\r\nServer: CamWatch Media Relay/4.8.12",
        usernames: ["yard.ops", "svc_camrelay", "viewer.west"],
        deviceState: {
          channel: "207",
          stream_name: "yard-west-cam07",
          status: "live",
          profile: "sub",
        },
      },
    },
  },
  {
    id: "jump-admin-east",
    group: "jump_host",
    displayName: "Admin Jump Host East",
    host: "admin-jump-01.internal",
    realm: "Remote Access",
    description: "Shared Windows and SSH jump host for operations staff.",
    services: {
      ssh: {
        banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        usernames: ["administrator", "svc_ops", "relayadmin"],
        files: [
          {
            path: "/etc/issue",
            contents: "Ubuntu 22.04.4 LTS \\n \\l",
            modifiedAt: "2026-04-11T02:15:00Z",
          },
        ],
        deviceState: {
          os: "ubuntu-22.04",
          patch_window: "sunday-0300z",
          shell_policy: "restricted",
        },
      },
      rdp: {
        banner: "Cookie: mstshash=ADMIN-JUMP\r\n",
        usernames: ["Administrator", "svc_ops", "helpdesk.admin"],
        deviceState: {
          build: "10.0.17763",
          domain: "OPS",
          patch_level: "2026-03",
        },
      },
    },
  },
  {
    id: "jump-bastion-west",
    group: "jump_host",
    displayName: "Ops Bastion West",
    host: "relay-edge-01.internal",
    realm: "Edge Operations",
    description: "Linux bastion paired with a Windows terminal services endpoint.",
    services: {
      ssh: {
        banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        usernames: ["opsrelay", "svc_patch", "neteng"],
        files: [
          {
            path: "/etc/issue",
            contents: "Ubuntu 22.04.4 LTS relay-edge-01",
            modifiedAt: "2026-04-10T09:03:00Z",
          },
        ],
        deviceState: {
          os: "ubuntu-22.04",
          patch_window: "wednesday-0100z",
          shell_policy: "audit-only",
        },
      },
      rdp: {
        banner: "Cookie: mstshash=RELAY-OPS\r\n",
        usernames: ["opsrelay", "svc_patch", "field.support"],
        deviceState: {
          build: "10.0.17763",
          domain: "EDGE",
          patch_level: "2026-02",
        },
      },
    },
  },
  {
    id: "backup-drop-archive-a",
    group: "backup_server",
    displayName: "Archive Relay A",
    host: "backup-drop.internal",
    realm: "Archive Relay",
    description: "Legacy FTP drop used for nightly archive syncs.",
    services: {
      ftp: {
        banner: "220 (vsFTPd 3.0.5)",
        usernames: ["backup", "nightsync", "archive_drop"],
        files: [
          {
            path: "/nightly/ops-2026-04-15.sql.gz",
            contents: "gzip payload placeholder for operations archive",
            modifiedAt: "2026-04-15T05:40:00Z",
          },
          {
            path: "/nightly/camera-index-2026-04-15.csv",
            contents: "camera_id,started_at,event\ncam04,2026-04-15T06:10:22Z,motion",
            modifiedAt: "2026-04-15T06:12:00Z",
          },
        ],
        deviceState: {
          storage_tier: "warm",
          sync_window: "02:00-03:00Z",
          last_sync: "2026-04-15T06:12:00Z",
        },
      },
    },
  },
  {
    id: "backup-drop-archive-b",
    group: "backup_server",
    displayName: "Archive Relay B",
    host: "backup-nas-07.internal",
    realm: "Cold Archive Staging",
    description: "Secondary FTP staging node with weekly retention rollups.",
    services: {
      ftp: {
        banner: "220 (vsFTPd 3.0.5)",
        usernames: ["coldsync", "vaultcopy", "weekly-rollup"],
        files: [
          {
            path: "/weekly/warehouse-west-2026-W15.tar",
            contents: "tar payload placeholder for weekly archive",
            modifiedAt: "2026-04-13T23:11:00Z",
          },
        ],
        deviceState: {
          storage_tier: "cold",
          sync_window: "sunday-23:00Z",
          last_sync: "2026-04-13T23:11:00Z",
        },
      },
    },
  },
  {
    id: "ops-db-primary",
    group: "operations_db",
    displayName: "Operations DB Primary",
    host: "ops-db.internal",
    realm: "Telemetry Warehouse",
    description: "Operational telemetry warehouse for camera and field gateway events.",
    services: {
      postgres: {
        banner: "PostgreSQL 14.11 on x86_64-pc-linux-gnu",
        usernames: ["postgres", "svc_reports", "backup"],
        deviceState: {
          cluster: "ops-primary",
          schema: "telemetry",
          wal_mode: "replica",
        },
      },
    },
  },
  {
    id: "ops-db-replica",
    group: "operations_db",
    displayName: "Operations DB Replica",
    host: "ops-db-replica-02.internal",
    realm: "Telemetry Warehouse",
    description: "Read-mostly replica for archive and report queries.",
    services: {
      postgres: {
        banner: "PostgreSQL 14.11 on x86_64-pc-linux-gnu",
        usernames: ["postgres", "analytics", "svc_archive"],
        deviceState: {
          cluster: "ops-replica",
          schema: "archive",
          wal_mode: "hot_standby",
        },
      },
    },
  },
  {
    id: "field-gateway-legacy-a",
    group: "field_gateway",
    displayName: "Legacy Field Gateway A",
    host: "field-gw-legacy.internal",
    realm: "Legacy Device Access",
    description: "BusyBox-backed device bridging serial field sensors into IP.",
    services: {
      telnet: {
        banner: "FieldGateway login:",
        usernames: ["admin", "service", "fieldops"],
        deviceState: {
          firmware: "1.35.0",
          site: "north-pump-room",
          uptime_hours: 438,
        },
      },
    },
  },
  {
    id: "field-gateway-legacy-b",
    group: "field_gateway",
    displayName: "Legacy Field Gateway B",
    host: "field-gw-03.internal",
    realm: "Legacy Device Access",
    description: "Relay node for edge serial devices and environmental sensors.",
    services: {
      telnet: {
        banner: "EdgeRelay login:",
        usernames: ["tech", "fieldsvc", "maint"],
        deviceState: {
          firmware: "1.34.2",
          site: "south-yard-mixer",
          uptime_hours: 912,
        },
      },
    },
  },
  {
    id: "plc-edge-04",
    group: "plc_controller",
    displayName: "PLC Relay Controller A",
    host: "plc-edge-04.internal",
    realm: "Industrial Controls",
    description: "Schneider bridge exposing read-heavy holding registers.",
    services: {
      modbus: {
        banner: "MBTCP unit 1 online",
        usernames: ["operator", "plcadmin"],
        deviceState: {
          unit_id: 1,
          pressure_kpa: 125,
          motor_rpm: 300,
          alarm: false,
          uptime_hours: 438,
        },
      },
      snmp: {
        banner: "SNMP agent ready",
        usernames: ["operator", "plcadmin"],
        deviceState: {
          unit_id: 1,
          pressure_kpa: 125,
          motor_rpm: 300,
          alarm: false,
          uptime_hours: 438,
        },
      },
    },
  },
  {
    id: "plc-mixer-12",
    group: "plc_controller",
    displayName: "PLC Relay Controller B",
    host: "mixer-plc-12.internal",
    realm: "Industrial Controls",
    description: "Legacy mixer controller exporting static read coils and temperature registers.",
    services: {
      modbus: {
        banner: "MBTCP unit 1 online",
        usernames: ["operator", "maint"],
        deviceState: {
          unit_id: 1,
          pressure_kpa: 98,
          motor_rpm: 240,
          alarm: true,
          uptime_hours: 912,
        },
      },
      snmp: {
        banner: "SNMP agent ready",
        usernames: ["operator", "maint"],
        deviceState: {
          unit_id: 1,
          pressure_kpa: 98,
          motor_rpm: 240,
          alarm: true,
          uptime_hours: 912,
        },
      },
    },
  },
  {
    id: "mail-relay-ops-01",
    group: "mail_relay",
    displayName: "Ops Mail Relay A",
    host: "mail-relay-ops-01.internal",
    realm: "Operations Mail",
    description: "Postfix relay forwarding ops-team notifications and camera alerts.",
    services: {
      smtp: {
        banner: "220 mail-relay-ops-01.internal ESMTP Postfix (Ubuntu)",
        usernames: ["postmaster", "ops.alerts", "svc_mailer"],
        files: [
          {
            path: "/etc/postfix/main.cf",
            contents: "myhostname = mail-relay-ops-01.internal\nrelayhost = [smtp.internal]:587\nmaximal_queue_lifetime = 1d",
            modifiedAt: "2026-04-10T08:00:00Z",
          },
        ],
        deviceState: {
          queue_size: 0,
          relay_host: "smtp.internal",
          tls: "optional",
        },
      },
    },
  },
  {
    id: "mail-relay-ops-02",
    group: "mail_relay",
    displayName: "Ops Mail Relay B",
    host: "mail-relay-ops-02.internal",
    realm: "Operations Mail",
    description: "Secondary Postfix relay for camera event notifications.",
    services: {
      smtp: {
        banner: "220 mail-relay-ops-02.internal ESMTP Postfix (Ubuntu)",
        usernames: ["postmaster", "camera.alerts", "svc_notify"],
        files: [
          {
            path: "/etc/postfix/main.cf",
            contents: "myhostname = mail-relay-ops-02.internal\nrelayhost = [smtp.internal]:587\nmaximal_queue_lifetime = 2d",
            modifiedAt: "2026-04-11T09:15:00Z",
          },
        ],
        deviceState: {
          queue_size: 3,
          relay_host: "smtp.internal",
          tls: "required",
        },
      },
    },
  },
];

const serviceGroupMap: Record<ResponderServiceName, PersonaGroup> = {
  http: "camera_nvr",
  ssh: "jump_host",
  postgres: "operations_db",
  ftp: "backup_server",
  rtsp: "camera_nvr",
  rdp: "jump_host",
  telnet: "field_gateway",
  modbus: "plc_controller",
  snmp: "plc_controller",
  smtp: "mail_relay",
};

export function getPersonaGroupForService(service: ResponderServiceName): PersonaGroup {
  return serviceGroupMap[service];
}

export function listPersonasForService(service: ResponderServiceName): DecoyPersona[] {
  const group = getPersonaGroupForService(service);
  return personas.filter((persona) => persona.group === group);
}

export function listPersonas(): DecoyPersona[] {
  return personas.slice();
}

export function getPersonaById(personaId: string): DecoyPersona | undefined {
  return personas.find((persona) => persona.id === personaId);
}

export function selectPersonaId(seed: string, service: ResponderServiceName): string {
  const candidates = listPersonasForService(service);
  const digest = crypto.createHash("sha256").update(`${seed}:${serviceGroupMap[service]}`).digest();
  const index = digest.readUInt32BE(0) % candidates.length;
  return candidates[index].id;
}
