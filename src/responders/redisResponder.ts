import { ResponderContext } from "./types.js";

// Deterministic Redis 7.x emulation for an *unprotected* instance — no AUTH
// required, which is the exact condition mass scanners hunt for. The value is
// not the PING/INFO noise but what comes after: CONFIG SET dir + SET + SAVE
// (cron/authorized_keys write), REPLICAOF (replication-module RCE), and
// MODULE LOAD. Those are captured verbatim and scored as exploitation.

export type RedisSessionState = {
  db: number;
  dir: string;
  dbfilename: string;
  written: Map<string, string>;
};

const MAX_WRITTEN_KEYS = 200;
const MAX_VALUE_BYTES = 4096;

export function createRedisState(): RedisSessionState {
  return { db: 0, dir: "/var/lib/redis", dbfilename: "dump.rdb", written: new Map() };
}

// --- RESP encoding -------------------------------------------------------

const simple = (s: string) => `+${s}\r\n`;
const error = (s: string) => `-${s}\r\n`;
const integer = (n: number) => `:${n}\r\n`;
const nil = () => "$-1\r\n";
const bulk = (s: string) => `$${Buffer.byteLength(s, "utf8")}\r\n${s}\r\n`;
const array = (items: string[]) => `*${items.length}\r\n${items.map(bulk).join("")}`;

/**
 * Seeded keyspace. Values deliberately reuse the canary tokens planted across
 * the decoy filesystem, so a GET here registers as "served" and any later reuse
 * of that secret on another service fires attributed cross-node attribution.
 */
function seededKeys(context: ResponderContext): Record<string, string> {
  const host = context.serviceMemory.host;
  return {
    "session:ops:current": `{"user":"ops.relay","node":"${host}","expires":1786500000}`,
    "config:db:dsn": "postgres://relay_ro:Rel4y!Pr0d2026@ops-db.internal:5432/relay",
    "config:aws:key": "AKIA4BACKUPSVC2026",
    "cache:vault:token": "hvs.CAESfakeHONEYPOTvaultTOKENexample",
    "queue:archive:pending": "17",
    "cache:camera:index": '{"cam04":"motion","cam09":"idle"}',
    "backup:last_run": "2026-08-16T02:00:11Z",
    "feature:maintenance_mode": "0",
  };
}

function infoBlock(context: ResponderContext, state: RedisSessionState, keyCount: number): string {
  const host = context.serviceMemory.host;
  return [
    "# Server",
    "redis_version:7.0.15",
    "redis_git_sha1:00000000",
    "redis_mode:standalone",
    "os:Linux 5.15.0-91-generic x86_64",
    "arch_bits:64",
    "process_id:1041",
    `run_id:${runId(context)}`,
    "tcp_port:6379",
    "uptime_in_seconds:4192883",
    "uptime_in_days:48",
    "executable:/usr/bin/redis-server",
    "config_file:/etc/redis/redis.conf",
    "",
    "# Clients",
    "connected_clients:3",
    "blocked_clients:0",
    "",
    "# Memory",
    "used_memory:2314576",
    "used_memory_human:2.21M",
    "used_memory_peak_human:4.08M",
    "maxmemory:0",
    "maxmemory_policy:noeviction",
    "",
    "# Persistence",
    "loading:0",
    "rdb_changes_since_last_save:14",
    "rdb_last_save_time:1786490000",
    "rdb_last_bgsave_status:ok",
    "aof_enabled:0",
    "",
    "# Replication",
    "role:master",
    "connected_slaves:0",
    "master_replid:8f2a1c9d4e7b3a6510f2c8d9e4b7a3c6d1f0e5b2",
    "master_repl_offset:0",
    "",
    "# CPU",
    "used_cpu_sys:812.44",
    "used_cpu_user:1904.10",
    "",
    "# Keyspace",
    `db0:keys=${keyCount},expires=2,avg_ttl=0`,
    "",
    `# Server hostname: ${host}`,
    "",
  ].join("\r\n");
}

function runId(context: ResponderContext): string {
  // Stable per-attacker so reconnects look like the same box.
  const seed = context.attacker.id.replace(/[^a-f0-9]/gi, "").padEnd(40, "0");
  return seed.slice(0, 40).toLowerCase();
}

const CONFIG_DEFAULTS: Record<string, string> = {
  maxmemory: "0",
  "maxmemory-policy": "noeviction",
  requirepass: "",
  bind: "0.0.0.0",
  "protected-mode": "no",
  save: "3600 1 300 100 60 10000",
  appendonly: "no",
  timeout: "0",
  loglevel: "notice",
  logfile: "/var/log/redis/redis-server.log",
};

export type RedisReply = {
  reply: string;
  detail: string;
  /** Set when the command is an unambiguous takeover attempt. */
  exploitation?: boolean;
  close?: boolean;
};

export function buildRedisReply(
  cmd: string,
  args: string[],
  state: RedisSessionState,
  action: string,
  context: ResponderContext
): RedisReply {
  const name = cmd.toUpperCase();
  const sub = (args[0] || "").toUpperCase();
  const seeded = seededKeys(context);
  const allKeys = () => [...Object.keys(seeded), ...state.written.keys()];
  const detail = `redis_cmd=${[name, ...args].join(" ").slice(0, 300)}`;

  if (action === "fake_error") {
    return { reply: error("LOADING Redis is loading the dataset in memory"), detail };
  }

  switch (name) {
    case "PING":
      return { reply: args.length ? bulk(args[0]) : simple("PONG"), detail };

    case "ECHO":
      return { reply: args.length ? bulk(args.join(" ")) : error("ERR wrong number of arguments for 'echo' command"), detail };

    case "HELLO": {
      // redis-cli 7 handshakes with HELLO; answer the RESP2 map-as-array form.
      const proto = args[0] === "3" ? 3 : 2;
      return {
        reply:
          "*14\r\n" +
          bulk("server") + bulk("redis") +
          bulk("version") + bulk("7.0.15") +
          bulk("proto") + integer(proto) +
          bulk("id") + integer(41) +
          bulk("mode") + bulk("standalone") +
          bulk("role") + bulk("master") +
          bulk("modules") + "*0\r\n",
        detail,
      };
    }

    case "AUTH":
      // The whole point of the lure: this box has no password set.
      return { reply: error("ERR Client sent AUTH, but no password is set"), detail };

    case "INFO":
      return { reply: bulk(infoBlock(context, state, allKeys().length)), detail };

    case "CONFIG": {
      if (sub === "GET") {
        const pattern = (args[1] || "").toLowerCase();
        const live: Record<string, string> = {
          ...CONFIG_DEFAULTS,
          dir: state.dir,
          dbfilename: state.dbfilename,
        };
        const matched =
          pattern === "*"
            ? Object.entries(live)
            : Object.entries(live).filter(([k]) => k === pattern);
        return { reply: array(matched.flatMap(([k, v]) => [k, v])), detail };
      }
      if (sub === "SET") {
        const key = (args[1] || "").toLowerCase();
        const value = (args[2] || "").slice(0, 512);
        if (key === "dir") state.dir = value;
        if (key === "dbfilename") state.dbfilename = value;
        // CONFIG SET dir/dbfilename is the RDB-write primitive — cron, SSH keys,
        // webshells all start here. Accept it so the chain continues.
        const isWritePrimitive = key === "dir" || key === "dbfilename";
        return {
          reply: simple("OK"),
          detail: `${detail} (config_set ${key})`,
          exploitation: isWritePrimitive,
        };
      }
      if (sub === "RESETSTAT" || sub === "REWRITE") return { reply: simple("OK"), detail };
      return { reply: error(`ERR Unknown CONFIG subcommand or wrong number of arguments for '${args[0] || ""}'`), detail };
    }

    case "SET": {
      const key = args[0];
      if (!key) return { reply: error("ERR wrong number of arguments for 'set' command"), detail };
      const value = (args[1] || "").slice(0, MAX_VALUE_BYTES);
      if (state.written.size < MAX_WRITTEN_KEYS) state.written.set(key, value);
      // A payload staged into a key right after CONFIG SET dir is the webshell/
      // cron body itself — flag when it carries shell or key material.
      const payloadish = /(\bcurl\b|\bwget\b|\/bin\/(ba)?sh|ssh-rsa|ssh-ed25519|\*\s*\*\s*\*|<\?php|bash -i|nc -e)/i.test(value);
      return { reply: simple("OK"), detail: `${detail.slice(0, 400)}`, exploitation: payloadish };
    }

    case "GET": {
      const key = args[0] || "";
      const value = state.written.has(key) ? state.written.get(key)! : seeded[key];
      return { reply: value === undefined ? nil() : bulk(value), detail };
    }

    case "MGET":
      return {
        reply:
          `*${args.length}\r\n` +
          args
            .map((k) => {
              const v = state.written.has(k) ? state.written.get(k)! : seeded[k];
              return v === undefined ? nil() : bulk(v);
            })
            .join(""),
        detail,
      };

    case "DEL": {
      let removed = 0;
      for (const k of args) if (state.written.delete(k) || seeded[k] !== undefined) removed += 1;
      return { reply: integer(removed), detail };
    }

    case "KEYS":
      return { reply: array(allKeys()), detail };

    case "SCAN":
      return { reply: `*2\r\n${bulk("0")}${array(allKeys())}`, detail };

    case "DBSIZE":
      return { reply: integer(allKeys().length), detail };

    case "TYPE":
      return { reply: simple("string"), detail };

    case "TTL":
      return { reply: integer(-1), detail };

    case "EXPIRE":
      return { reply: integer(1), detail };

    case "SELECT": {
      const db = Number(args[0]);
      if (!Number.isInteger(db) || db < 0 || db > 15) {
        return { reply: error("ERR DB index is out of range"), detail };
      }
      state.db = db;
      return { reply: simple("OK"), detail };
    }

    case "SAVE":
      // Pairs with CONFIG SET dir — this is the moment the "file write" lands.
      return { reply: simple("OK"), detail, exploitation: state.dir !== "/var/lib/redis" };

    case "BGSAVE":
      return {
        reply: simple("Background saving started"),
        detail,
        exploitation: state.dir !== "/var/lib/redis",
      };

    case "BGREWRITEAOF":
      return { reply: simple("Background append only file rewriting started"), detail };

    case "LASTSAVE":
      return { reply: integer(1786490000), detail };

    case "FLUSHALL":
    case "FLUSHDB":
      state.written.clear();
      return { reply: simple("OK"), detail, exploitation: true };

    case "SLAVEOF":
    case "REPLICAOF": {
      const target = `${args[0] || ""}:${args[1] || ""}`;
      const clearing = (args[0] || "").toUpperCase() === "NO";
      // Replication-based RCE: attacker points us at their own master, then
      // ships a malicious module over the replication stream.
      return {
        reply: simple("OK"),
        detail: `${detail} (replicaof ${target})`,
        exploitation: !clearing,
      };
    }

    case "MODULE": {
      if (sub === "LIST") return { reply: "*0\r\n", detail };
      if (sub === "LOAD") {
        return {
          reply: error("ERR Error loading the extension. Please check the server logs."),
          detail: `${detail} (module_load ${args[1] || ""})`,
          exploitation: true,
        };
      }
      return { reply: error("ERR unknown subcommand"), detail };
    }

    case "EVAL":
    case "EVALSHA": {
      const script = args[0] || "";
      const sandboxEscape = /(os\.|io\.|dofile|loadfile|package|require|redis\.call\(['"]config)/i.test(script);
      return {
        reply: sandboxEscape
          ? error("ERR Error compiling script (new function): user_script:1: Script attempted to access nonexistent global variable")
          : nil(),
        detail: `${detail.slice(0, 400)}`,
        exploitation: sandboxEscape,
      };
    }

    case "SCRIPT":
      return { reply: sub === "LOAD" ? bulk(runId(context).slice(0, 40)) : simple("OK"), detail };

    case "DEBUG":
      return { reply: error("ERR DEBUG command not allowed"), detail, exploitation: true };

    case "SHUTDOWN":
      // Real Redis closes without replying.
      return { reply: "", detail, exploitation: true, close: true };

    case "CLIENT": {
      if (sub === "LIST") {
        return {
          reply: bulk(
            `id=41 addr=10.20.4.19:51844 laddr=10.20.4.7:6379 fd=8 name= age=118 idle=0 flags=N db=0 cmd=client|list user=default\n`
          ),
          detail,
        };
      }
      if (sub === "GETNAME") return { reply: nil(), detail };
      if (sub === "SETNAME" || sub === "SETINFO") return { reply: simple("OK"), detail };
      if (sub === "ID") return { reply: integer(41), detail };
      return { reply: simple("OK"), detail };
    }

    case "COMMAND":
      if (sub === "COUNT") return { reply: integer(240), detail };
      return { reply: "*0\r\n", detail };

    case "TIME":
      return { reply: array([String(Math.floor(Date.now() / 1000)), "141200"]), detail };

    case "ROLE":
      return { reply: `*3\r\n${bulk("master")}${integer(0)}*0\r\n`, detail };

    case "QUIT":
      return { reply: simple("OK"), detail, close: true };

    default:
      return {
        reply: error(
          `ERR unknown command '${name.slice(0, 40)}', with args beginning with: ${args
            .slice(0, 2)
            .map((a) => `'${a.slice(0, 20)}',`)
            .join(" ")}`
        ),
        detail,
      };
  }
}
