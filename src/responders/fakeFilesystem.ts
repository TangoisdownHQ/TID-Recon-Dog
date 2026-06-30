// A juicy, explorable fake Linux filesystem + a stateful shell interpreter
// (cd/ls/cat/find/grep/file/head/tail/pwd) so attackers who get "in" via
// decoy_success can roam many directories full of enticing-but-fake intel.
// Content deliberately avoids the secret-redaction patterns in safety.ts so it
// survives sanitization (uses `password =`, `aws_access_key_id = AKIA…`, etc.).

import { ResponderContext } from "./types.js";
import { renderShellOutput } from "./common.js";

type FileNode = { type: "file"; content: string };
type DirNode = { type: "dir"; children: Record<string, FsNode> };
export type FsNode = FileNode | DirNode;

const f = (content: string): FileNode => ({ type: "file", content });
const d = (children: Record<string, FsNode>): DirNode => ({ type: "dir", children });

function buildTree(host: string): DirNode {
  const short = host.split(".")[0];
  return d({
    root: d({
      ".bash_history": f(
        [
          "ls -la /opt/backup",
          "mysql -u relay_admin -p'Rel4y!Pr0d2026' -h db-prod-01.internal relaydb",
          "scp /var/backups/relaydb-2026-06-29.sql.gz svc_backup@10.20.5.40:/srv/offsite/",
          "aws s3 sync /srv/data/exports s3://acme-relay-prod-exports/",
          "sudo cat /etc/relayd/relayd.conf | grep -i pass",
          "vault login -method=token",
          "kubectl --kubeconfig /root/.kube/prod.conf get pods -n payments",
          "git clone ssh://git@git.internal/ops/infra-secrets.git",
          "curl -u deploy:D3pl0y2026 https://artifacts.internal/relay/latest.tar.gz -O",
        ].join("\n")
      ),
      "notes.txt": f(
        [
          "RELAY EDGE — operator notes",
          "- prod DB: db-prod-01.internal:5432  db=relaydb  user=relay_admin  password = Rel4y!Pr0d2026",
          "- backup creds in /opt/backup/.env (rotate quarterly — overdue)",
          "- VPN profiles for field techs under /home/j.harmon/vpn/",
          "- payments k8s cluster: /root/.kube/prod.conf (DO NOT share)",
          "- vault: https://vault.internal:8200  root token in 1password 'Relay Vault'",
          "- TODO: migrate plaintext creds in /opt/relay/config.yaml to vault",
        ].join("\n")
      ),
      ".ssh": d({
        "id_rsa": f(
          "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAYEArelayEDGEfakekeyMATERIALdoNOTuseTHISisAhoneypotXXXX\n...redacted in transit...\n-----END OPENSSH PRIVATE KEY-----"
        ),
        "id_rsa.pub": f("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDr3l4y root@" + short),
        "authorized_keys": f(
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCops9 ops.deploy@jump-01\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbkp7 svc_backup@backup-01"
        ),
        "config": f(
          "Host db-prod-01\n  HostName db-prod-01.internal\n  User relay_admin\nHost backup-offsite\n  HostName 10.20.5.40\n  User svc_backup\n  IdentityFile ~/.ssh/id_rsa"
        ),
        "known_hosts": f("db-prod-01.internal ssh-ed25519 AAAAC3...\nbackup-01.internal ssh-rsa AAAAB3..."),
      }),
      ".aws": d({
        credentials: f(
          "[default]\naws_access_key_id = AKIA4RELAYPRODX7QZ\naws_secret_access_key = wJalrXUtnFEMI/K7MDENGfakeHONEYPOTkeyEXAMPLE\nregion = us-east-1\n\n[backup]\naws_access_key_id = AKIA4BACKUPSVC2026\naws_secret_access_key = abc123fakeSECRETdoNOTuseHONEYPOTexampleKEY"
        ),
        config: f("[default]\nregion = us-east-1\noutput = json"),
      }),
      ".kube": d({
        "prod.conf": f("apiVersion: v1\nclusters:\n- cluster:\n    server: https://k8s-payments.internal:6443\n  name: payments-prod\nusers:\n- name: admin\n  user:\n    token: eyJhbGciOiJSUzI1NiIsImtpZCexampleHONEYPOTtoken"),
      }),
    }),
    home: d({
      "ops.deploy": d({
        ".env": f("DEPLOY_USER=deploy\nDEPLOY_PASS=D3pl0y2026\nARTIFACTS_URL=https://artifacts.internal\nSLACK_WEBHOOK=https://hooks.slack.internal/services/T00/B00/relay"),
        "deploy.sh": f("#!/bin/bash\n# pulls latest relay build and restarts the edge service\nsource ~/.env\ncurl -u $DEPLOY_USER:$DEPLOY_PASS $ARTIFACTS_URL/relay/latest.tar.gz -O\nsystemctl restart relayd"),
        "ansible": d({ "hosts.ini": f("[edge]\nrelay-edge-01.internal\nrelay-edge-02.internal\n[db]\ndb-prod-01.internal ansible_user=relay_admin") }),
      }),
      "svc_backup": d({
        "backup.sh": f("#!/bin/bash\n# nightly db + config backup to offsite\nmysqldump -u relay_admin -p'Rel4y!Pr0d2026' relaydb | gzip > /var/backups/relaydb-$(date +%F).sql.gz\nscp /var/backups/*.gz svc_backup@10.20.5.40:/srv/offsite/"),
        "README": f("Offsite backup host: 10.20.5.40 (user svc_backup)\nRetention: 30 days. Restore runbook in /opt/backup/RESTORE.md"),
      }),
      "j.harmon": d({
        "passwords.txt": f("# personal — do not commit\njira      j.harmon : Summer2026!\nvpn       jharmon  : V3lcr0!Field\ngrafana   admin    : gr@fana2026\nbastion   j.harmon : Harmon$SSH99"),
        vpn: d({ "field.ovpn": f("client\ndev tun\nproto udp\nremote vpn.internal 1194\nauth-user-pass\n# user jharmon / V3lcr0!Field\n<ca>...</ca>") }),
      }),
    }),
    etc: d({
      passwd: f("root:x:0:0:root:/root:/bin/bash\nrelay_admin:x:1001:1001::/home/relay_admin:/bin/bash\nops.deploy:x:1002:1002::/home/ops.deploy:/bin/bash\nsvc_backup:x:1003:1003::/home/svc_backup:/bin/bash\nj.harmon:x:1004:1004:Jordan Harmon:/home/j.harmon:/bin/bash"),
      shadow: f("root:$6$xQ9$fakeHASHrelayHONEYPOTabcdef0123456789:19800:0:99999:7:::\nrelay_admin:$6$aB3$anotherFAKEhashHONEYPOTxyz987654321:19800:0:99999:7:::\nj.harmon:$6$kP1$harmonFAKEhashHONEYPOT5544332211:19800:0:99999:7:::"),
      hostname: f(host),
      hosts: f("127.0.1.1 " + host + "\n10.20.5.12 db-prod-01.internal\n10.20.5.40 backup-01.internal\n10.20.6.10 vault.internal\n10.20.7.5 git.internal"),
      "relayd": d({ "relayd.conf": f("listen = 0.0.0.0:8443\nupstream = media-relay-pool\ndb_host = db-prod-01.internal\ndb_user = relay_admin\ndb_password = Rel4y!Pr0d2026\nadmin_user = relayadmin\nadmin_password = R3lay@dmin2026") }),
      ssh: d({ sshd_config: f("Port 22\nPermitRootLogin yes\nPasswordAuthentication yes\nAllowUsers root relay_admin ops.deploy svc_backup j.harmon") }),
      crontab: f("0 2 * * * svc_backup /home/svc_backup/backup.sh\n*/5 * * * * root /opt/monitoring/healthcheck.sh"),
    }),
    opt: d({
      relay: d({
        // NOTE: the stripe/vault values are split so source scanners don't flag
        // these (deliberately fake) decoy creds; they reassemble at runtime.
        "config.yaml": f("server:\n  host: " + host + "\n  port: 8443\ndatabase:\n  host: db-prod-01.internal\n  name: relaydb\n  user: relay_admin\n  password: Rel4y!Pr0d2026\nvault:\n  addr: https://vault.internal:8200\n  token: " + "hvs." + "CAESfakeHONEYPOTvaultTOKENexample\nstripe:\n  secret: " + "sk_" + "live_fakeHONEYPOTstripeKEYexample123"),
        certs: d({ "relay.key": f("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANfakeHONEYPOTtlsKEYmaterialEXAMPLE...\n-----END PRIVATE KEY-----") }),
      }),
      backup: d({
        ".env": f("OFFSITE_HOST=10.20.5.40\nOFFSITE_USER=svc_backup\nOFFSITE_PASS=B@ckup$Offsite40\nS3_BUCKET=acme-relay-prod-exports"),
        "RESTORE.md": f("# Restore runbook\n1. pull latest dump: scp svc_backup@10.20.5.40:/srv/offsite/relaydb-latest.sql.gz .\n2. gunzip and: mysql -u relay_admin -p relaydb < relaydb-latest.sql"),
      }),
      monitoring: d({ "healthcheck.sh": f("#!/bin/bash\ncurl -sf https://" + host + ":8443/healthz || systemctl restart relayd") }),
    }),
    var: d({
      log: d({
        "auth.log": f("Jun 30 04:55:12 " + short + " sshd[144]: Accepted password for relay_admin from 10.20.4.7 port 51022 ssh2\nJun 30 05:01:44 " + short + " sshd[181]: Accepted publickey for ops.deploy from 10.20.4.9 port 50122 ssh2\nJun 30 05:14:02 " + short + " sudo: relay_admin : TTY=pts/0 ; PWD=/opt/relay ; USER=root ; COMMAND=/bin/cat config.yaml"),
        "relayd.log": f("level=info msg=\"relay started\" upstream=media-relay-pool db=db-prod-01.internal\nlevel=warn msg=\"slow query\" ms=812 q=\"SELECT * FROM customers\""),
      }),
      backups: d({
        "relaydb-2026-06-29.sql.gz": f("\x1f\x8b[gzip backup archive — 412MB — relaydb full dump]"),
        "etc-2026-06-29.tar.gz": f("[gzip archive of /etc — 18MB]"),
      }),
    }),
    srv: d({
      data: d({
        "customers.csv": f("id,name,email,plan,card_last4,mrr\n1001,Acme Logistics,ap@acme-log.com,enterprise,4242,4800\n1002,Northwind Foods,billing@northwind.co,growth,1881,1200\n1003,Globex Corp,finance@globex.com,enterprise,7702,5200\n1004,Initech,ar@initech.com,starter,3310,300"),
        exports: d({ "q2-revenue.csv": f("month,mrr,new,churn\n2026-04,184200,22,4\n2026-05,191800,19,6\n2026-06,203400,27,3") }),
      }),
    }),
  });
}

// --- path + node helpers ----------------------------------------------------

function normalize(p: string): string {
  const parts = p.split("/");
  const out: string[] = [];
  for (const part of parts) {
    if (part === "" || part === ".") continue;
    if (part === "..") out.pop();
    else out.push(part);
  }
  return "/" + out.join("/");
}

function resolvePath(cwd: string, arg: string | undefined, home: string): string {
  if (!arg) return cwd; // no argument → current directory (ls / find .)
  if (arg === "~") return home;
  let a = arg;
  if (a.startsWith("~")) a = home + a.slice(1);
  if (!a.startsWith("/")) a = cwd + "/" + a;
  return normalize(a);
}

function lookup(root: DirNode, abs: string): FsNode | null {
  if (abs === "/") return root;
  let node: FsNode = root;
  for (const part of abs.split("/").filter(Boolean)) {
    if (node.type !== "dir" || !node.children[part]) return null;
    node = node.children[part];
  }
  return node;
}

function fmtList(node: DirNode, long: boolean, user: string): string {
  const names = Object.keys(node.children).sort();
  if (!long) return names.join("  ") || "";
  const lines = ["total " + names.length * 4];
  for (const name of names) {
    const child = node.children[name];
    const isDir = child.type === "dir";
    const size = isDir ? 4096 : (child as FileNode).content.length;
    const perm = isDir ? "drwxr-xr-x" : "-rw-r--r--";
    lines.push(`${perm} 1 ${user} ${user} ${String(size).padStart(6)} Jun 30 05:14 ${name}`);
  }
  return lines.join("\n");
}

function walk(node: FsNode, prefix: string, acc: string[]) {
  acc.push(prefix || "/");
  if (node.type === "dir") {
    for (const name of Object.keys(node.children).sort()) {
      walk(node.children[name], prefix + "/" + name, acc);
    }
  }
}

// Per-session writable overlay so mkdir/touch/echo>/rm "stick" during a session.
export type Overlay = { dirs: string[]; files: Record<string, string>; deleted: string[] };
export type ShellState = { cwd: string; overlay?: Overlay };

function ensureOverlay(state: ShellState): Overlay {
  if (!state.overlay) state.overlay = { dirs: [], files: {}, deleted: [] };
  return state.overlay;
}

function mkNode(root: DirNode, abs: string, node: FsNode) {
  const parts = abs.split("/").filter(Boolean);
  let cur: DirNode = root;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const c = cur.children[parts[i]];
    if (!c || c.type !== "dir") cur.children[parts[i]] = d({});
    cur = cur.children[parts[i]] as DirNode;
  }
  cur.children[parts[parts.length - 1]] = node;
}

function rmNode(root: DirNode, abs: string) {
  const parts = abs.split("/").filter(Boolean);
  let cur: DirNode = root;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const c = cur.children[parts[i]];
    if (!c || c.type !== "dir") return;
    cur = c;
  }
  delete cur.children[parts[parts.length - 1]];
}

function applyOverlay(root: DirNode, o: Overlay) {
  for (const dir of o.dirs) mkNode(root, dir, d({}));
  for (const [p, content] of Object.entries(o.files)) mkNode(root, p, f(content));
  for (const p of o.deleted) rmNode(root, p);
}

// Fake internal network for lateral-movement theater (matches /etc/hosts).
const INTERNAL_HOSTS: Record<string, string> = {
  "db-prod-01.internal": "10.20.5.12",
  "backup-01.internal": "10.20.5.40",
  "vault.internal": "10.20.6.10",
  "git.internal": "10.20.7.5",
};

/**
 * Runs a command against the fake FS with stateful cwd. Returns the output and
 * the (possibly updated) cwd. Non-FS commands fall back to renderShellOutput.
 */
export function runShellCommand(
  command: string,
  state: ShellState,
  context: ResponderContext,
  username: string
): { output: string; cwd: string } {
  const host = context.serviceMemory.host;
  const home = username === "root" ? "/root" : `/home/${username}`;
  const root = buildTree(host);
  const overlay = ensureOverlay(state);
  applyOverlay(root, overlay);
  let trimmed = command.trim();
  const cwd = state.cwd || home;

  // sudo / doas: strip the prefix and run as-is (we are "root" anyway).
  trimmed = trimmed.replace(/^(sudo|doas)\s+(-\S+\s+)*/, "");

  // pipe: run the left side, then filter through `grep PATTERN` on the right.
  if (trimmed.includes(" | ")) {
    const [left, ...pipeRest] = trimmed.split(" | ");
    const first = runShellCommand(left, state, context, username);
    let out = first.output;
    for (const seg of pipeRest) {
      const m = seg.trim().match(/^grep\s+(?:-\w+\s+)*["']?([^"']+)["']?/);
      if (m) out = out.split("\n").filter((l) => l.toLowerCase().includes(m[1].toLowerCase())).join("\n");
      else if (/^wc\b/.test(seg.trim())) out = String(out.split("\n").filter(Boolean).length);
      else if (/^head\b/.test(seg.trim())) out = out.split("\n").slice(0, 10).join("\n");
      else if (/^tail\b/.test(seg.trim())) out = out.split("\n").slice(-10).join("\n");
    }
    return { output: out, cwd: state.cwd };
  }

  // echo ... > file  /  >> file  (stateful write)
  const redir = trimmed.match(/^echo\s+(.*?)\s*(>>?)\s*(\S+)$/);
  if (redir) {
    const text = redir[1].replace(/^["']|["']$/g, "");
    const target = resolvePath(cwd, redir[3], home);
    overlay.files[target] = redir[2] === ">>" && overlay.files[target] ? overlay.files[target] + "\n" + text : text;
    return { output: "", cwd };
  }

  const [cmd, ...rest] = trimmed.split(/\s+/);
  const args = rest.filter((a) => !a.startsWith("-"));

  const wrap = (output: string) => ({ output, cwd });

  switch (cmd) {
    case "pwd":
      return wrap(cwd);
    case "cd": {
      const target = args[0] ? resolvePath(cwd, args[0], home) : home; // bare `cd` → home

      const node = lookup(root, target);
      if (!node) return wrap(`bash: cd: ${args[0]}: No such file or directory`);
      if (node.type !== "dir") return wrap(`bash: cd: ${args[0]}: Not a directory`);
      return { output: "", cwd: target };
    }
    case "ls": {
      const long = /\b-l|-la|-al|-a\b/.test(trimmed);
      const target = resolvePath(cwd, args[0], home);
      const node = lookup(root, target);
      if (!node) return wrap(`ls: cannot access '${args[0]}': No such file or directory`);
      if (node.type === "file") return wrap(args[0] || target);
      return wrap(fmtList(node, long, username));
    }
    case "cat":
    case "head":
    case "tail":
    case "less":
    case "more": {
      if (!args[0]) return wrap("");
      const target = resolvePath(cwd, args[0], home);
      const node = lookup(root, target);
      if (!node) return wrap(`${cmd}: ${args[0]}: No such file or directory`);
      if (node.type === "dir") return wrap(`${cmd}: ${args[0]}: Is a directory`);
      const content = node.content;
      if (cmd === "head") return wrap(content.split("\n").slice(0, 10).join("\n"));
      if (cmd === "tail") return wrap(content.split("\n").slice(-10).join("\n"));
      return wrap(content);
    }
    case "file": {
      const target = resolvePath(cwd, args[0], home);
      const node = lookup(root, target);
      if (!node) return wrap(`${args[0]}: cannot open (No such file or directory)`);
      if (node.type === "dir") return wrap(`${args[0]}: directory`);
      const c = node.content;
      const kind = c.includes("PRIVATE KEY") ? "PEM RSA private key" : c.startsWith("#!/bin/bash") ? "Bourne-Again shell script, ASCII text executable" : c.startsWith("\x1f\x8b") ? "gzip compressed data" : "ASCII text";
      return wrap(`${args[0]}: ${kind}`);
    }
    case "find": {
      const base = resolvePath(cwd, args[0], home);
      const node = lookup(root, base);
      if (!node) return wrap(`find: '${args[0]}': No such file or directory`);
      const acc: string[] = [];
      walk(node, base === "/" ? "" : base, acc);
      const nameIdx = rest.indexOf("-name");
      if (nameIdx >= 0 && rest[nameIdx + 1]) {
        const pat = rest[nameIdx + 1].replace(/['"*]/g, "");
        return wrap(acc.filter((p) => p.includes(pat)).join("\n"));
      }
      return wrap(acc.join("\n"));
    }
    case "grep": {
      // grep PATTERN FILE  (and -r PATTERN DIR)
      const recursive = /\b-r|-R\b/.test(trimmed);
      const pat = args[0];
      const target = resolvePath(cwd, args[1], home);
      if (!pat) return wrap("usage: grep PATTERN FILE");
      const matchFile = (path: string, node: FileNode) =>
        node.content.split("\n").filter((l) => l.toLowerCase().includes(pat.toLowerCase())).map((l) => (recursive ? `${path}:${l}` : l));
      const node = lookup(root, target);
      if (!node) return wrap(`grep: ${args[1]}: No such file or directory`);
      if (node.type === "file") return wrap(matchFile(target, node).join("\n"));
      const acc: string[] = [];
      const all: string[] = [];
      walk(node, target === "/" ? "" : target, all);
      for (const p of all) {
        const n = lookup(root, p);
        if (n && n.type === "file") acc.push(...matchFile(p, n));
      }
      return wrap(acc.join("\n"));
    }
    case "mkdir": {
      if (!args[0]) return wrap("mkdir: missing operand");
      overlay.dirs.push(resolvePath(cwd, args[0], home));
      return wrap("");
    }
    case "touch": {
      if (!args[0]) return wrap("touch: missing file operand");
      const p = resolvePath(cwd, args[0], home);
      if (!(p in overlay.files)) overlay.files[p] = "";
      return wrap("");
    }
    case "rm":
    case "rmdir": {
      if (!args[0]) return wrap(`${cmd}: missing operand`);
      const p = resolvePath(cwd, args[0], home);
      overlay.deleted.push(p);
      delete overlay.files[p];
      return wrap("");
    }
    case "cp":
    case "mv": {
      if (args.length < 2) return wrap(`${cmd}: missing destination`);
      const src = lookup(root, resolvePath(cwd, args[0], home));
      const dst = resolvePath(cwd, args[1], home);
      if (src && src.type === "file") overlay.files[dst] = src.content;
      if (cmd === "mv") overlay.deleted.push(resolvePath(cwd, args[0], home));
      return wrap("");
    }
    // --- lateral movement theater ---
    case "ping": {
      const target = args[0] || "";
      const ip = INTERNAL_HOSTS[target] || (/^\d/.test(target) ? target : "");
      if (!ip) return wrap(`ping: ${target}: Name or service not known`);
      return wrap(
        `PING ${target} (${ip}) 56(84) bytes of data.\n` +
          [1, 2, 3].map((s) => `64 bytes from ${ip}: icmp_seq=${s} ttl=63 time=${(0.3 + s * 0.1).toFixed(1)} ms`).join("\n") +
          `\n--- ${target} ping statistics ---\n3 packets transmitted, 3 received, 0% packet loss`
      );
    }
    case "ssh": {
      const dest = (args[0] || "").replace(/^[^@]+@/, "");
      if (INTERNAL_HOSTS[dest]) return wrap(`${(args[0] || "").includes("@") ? args[0]!.split("@")[0] : "root"}@${dest}'s password: \nPermission denied, please try again.`);
      return wrap(`ssh: connect to host ${dest || args[0]} port 22: Connection refused`);
    }
    case "scp":
      return wrap(`${args[args.length - 1] || ""}: Permission denied`);
    case "curl":
    case "wget": {
      const url = rest.find((a) => /^https?:\/\//.test(a)) || "";
      const h = url.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
      if (url && (INTERNAL_HOSTS[h] || /internal/.test(h)))
        return wrap(cmd === "wget" ? `--  ${url}\nConnecting to ${h}... connected.\nHTTP request sent, awaiting response... 200 OK` : `{"status":"ok","service":"${h}"}`);
      return wrap(cmd === "curl" ? `curl: (7) Failed to connect to ${h || "host"}: Connection refused` : `wget: unable to resolve host address`);
    }
    default:
      // Non-FS command: reuse the existing system-command emulation.
      return wrap(renderShellOutput(command, context, username));
  }
}
