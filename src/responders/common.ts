import path from "path";
import crypto from "crypto";
import { PersonaFile } from "../profiles/personaLibrary.js";
import { safeShellOutput } from "./safety.js";
import { ResponderContext } from "./types.js";

export async function sleep(ms: number) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}

export function pickDeterministic<T>(seed: string, values: T[]): T {
  const digest = crypto.createHash("sha256").update(seed).digest();
  return values[digest.readUInt32BE(0) % values.length];
}

export function listFileNames(files: PersonaFile[]) {
  return files.map((file) => path.basename(file.path));
}

export function findDecoyFile(files: PersonaFile[], target: string) {
  const normalizedTarget = target.trim().replace(/\/+/g, "/");
  return files.find((file) => file.path === normalizedTarget || path.basename(file.path) === normalizedTarget);
}

export function renderShellOutput(command: string, context: ResponderContext, username?: string) {
  const trimmed = command.trim();
  const fileNames = listFileNames(context.serviceMemory.files);
  const effectiveUser = username || context.serviceMemory.usernames[0] || "operator";
  const shortHost = context.serviceMemory.host.split(".")[0];

  if (!trimmed) {
    return "";
  }

  // help
  if (trimmed === "help" || trimmed === "?") {
    return "builtins: ls cat pwd whoami hostname id ps uname env ip ifconfig netstat df free uptime date which history echo";
  }

  // ls variants
  if (/^ls(\s|$)/.test(trimmed)) {
    const allFiles = fileNames.join("  ");
    if (/\s+-la?$|\s+-al?$/.test(trimmed) || trimmed === "ls -la" || trimmed === "ls -al" || trimmed === "ls -a") {
      const now = new Date();
      const month = now.toLocaleString("en-US", { month: "short" });
      const day = String(now.getDate()).padStart(2, " ");
      return [
        "total 48",
        `drwxr-xr-x 4 ${effectiveUser} ${effectiveUser} 4096 ${month} ${day} 05:14 .`,
        `drwxr-xr-x 6 root root 4096 ${month} ${day} 04:01 ..`,
        `-rw-r--r-- 1 ${effectiveUser} ${effectiveUser}  220 ${month} ${day} 04:01 .bash_logout`,
        `-rw-r--r-- 1 ${effectiveUser} ${effectiveUser} 3526 ${month} ${day} 04:01 .bashrc`,
        `-rw-r--r-- 1 ${effectiveUser} ${effectiveUser}  807 ${month} ${day} 04:01 .profile`,
        ...context.serviceMemory.files.map(
          (f) => `-rw-r--r-- 1 ${effectiveUser} ${effectiveUser} ${f.contents.length.toString().padStart(5)} ${month} ${day} 05:14 ${path.basename(f.path)}`
        ),
      ].join("\n");
    }
    return allFiles || "(empty)";
  }

  // pwd
  if (trimmed === "pwd") {
    return `/home/${effectiveUser}`;
  }

  // whoami
  if (trimmed === "whoami") {
    return effectiveUser;
  }

  // hostname
  if (trimmed === "hostname" || trimmed === "hostname -f") {
    return context.serviceMemory.host;
  }

  // id
  if (trimmed === "id") {
    return `uid=1001(${effectiveUser}) gid=1001(${effectiveUser}) groups=1001(${effectiveUser}),27(sudo),1001(${effectiveUser})`;
  }

  // uname
  if (/^uname(\s|$)/.test(trimmed)) {
    if (trimmed === "uname -a" || trimmed === "uname --all") {
      return `Linux ${context.serviceMemory.host} 5.15.0-91-generic #101-Ubuntu SMP Thu Jan 11 14:32:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux`;
    }
    if (trimmed === "uname -r") return "5.15.0-91-generic";
    if (trimmed === "uname -m") return "x86_64";
    if (trimmed === "uname -s") return "Linux";
    if (trimmed === "uname -n") return context.serviceMemory.host;
    return "Linux";
  }

  // ps
  if (/^ps(\s|$)/.test(trimmed)) {
    return [
      "  PID TTY          TIME CMD",
      `    1 ?        00:00:02 systemd`,
      `  101 ?        00:01:14 ${effectiveUser} /usr/sbin/relayd --host ${context.serviceMemory.host}`,
      `  144 ?        00:00:03 sshd`,
      `  201 ?        00:02:47 media-relay --site ${context.persona.displayName}`,
      `  512 pts/0    00:00:00 bash`,
      `  513 pts/0    00:00:00 ps`,
    ].join("\n");
  }

  // cat
  if (trimmed.startsWith("cat ")) {
    const target = trimmed.slice(4).trim();
    if (target === "/etc/issue" || target === "/etc/issue.net") {
      return "Ubuntu 22.04.4 LTS";
    }
    if (target === "/etc/os-release") {
      return [
        'PRETTY_NAME="Ubuntu 22.04.4 LTS"',
        'NAME="Ubuntu"',
        'VERSION_ID="22.04"',
        'VERSION="22.04.4 LTS (Jammy Jellyfish)"',
        'ID=ubuntu',
        'ID_LIKE=debian',
      ].join("\n");
    }
    if (target === "/etc/hostname") return context.serviceMemory.host;
    if (target === "/proc/version") {
      return `Linux version 5.15.0-91-generic (buildd@lcy02-amd64-013) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Thu Jan 11 14:32:04 UTC 2024`;
    }
    if (target === "/etc/passwd") {
      return [
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        `${effectiveUser}:x:1001:1001::/home/${effectiveUser}:/bin/bash`,
        "svc_rtsp:x:1002:1002::/home/svc_rtsp:/usr/sbin/nologin",
      ].join("\n");
    }
    const file = findDecoyFile(context.serviceMemory.files, target);
    if (file) {
      return safeShellOutput(file.contents, context.serviceMemory.host);
    }
    return `cat: ${target}: No such file or directory`;
  }

  // env / printenv
  if (trimmed === "env" || trimmed === "printenv" || trimmed === "set") {
    return [
      `HOME=/home/${effectiveUser}`,
      `USER=${effectiveUser}`,
      `LOGNAME=${effectiveUser}`,
      `SHELL=/bin/bash`,
      `HOSTNAME=${context.serviceMemory.host}`,
      `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`,
      `TERM=xterm-256color`,
      `LANG=en_US.UTF-8`,
      `PWD=/home/${effectiveUser}`,
    ].join("\n");
  }

  // ip addr / ifconfig
  if (trimmed === "ip addr" || trimmed === "ip a" || trimmed === "ip addr show" || trimmed === "ifconfig") {
    return [
      "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536",
      "    inet 127.0.0.1/8 scope host lo",
      "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500",
      `    inet 10.0.${pickDeterministic(context.attacker.id, [1, 2, 4, 8, 12])}.${pickDeterministic(context.attacker.id + "b", [10, 20, 30, 40, 50])}/24 brd 10.0.1.255 scope global eth0`,
      "    inet6 fe80::1/64 scope link",
    ].join("\n");
  }

  // ip route
  if (trimmed === "ip route" || trimmed === "ip r" || trimmed === "route" || trimmed === "route -n") {
    return [
      "default via 10.0.1.1 dev eth0 proto dhcp src 10.0.1.10 metric 100",
      "10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.10",
    ].join("\n");
  }

  // netstat
  if (/^netstat(\s|$)/.test(trimmed)) {
    return [
      "Active Internet connections (only servers)",
      "Proto Recv-Q Send-Q Local Address           Foreign Address         State",
      "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN",
      "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN",
      "tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN",
      "tcp        0      0 0.0.0.0:8554            0.0.0.0:*               LISTEN",
    ].join("\n");
  }

  // ss
  if (/^ss(\s|$)/.test(trimmed)) {
    return [
      "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port",
      "tcp   LISTEN 0      128    0.0.0.0:22          0.0.0.0:*",
      "tcp   LISTEN 0      128    0.0.0.0:80          0.0.0.0:*",
      "tcp   LISTEN 0      100    127.0.0.1:5432      0.0.0.0:*",
    ].join("\n");
  }

  // df
  if (/^df(\s|$)/.test(trimmed)) {
    return [
      "Filesystem      Size  Used Avail Use% Mounted on",
      "/dev/sda1        50G   12G   36G  25% /",
      "tmpfs           3.9G     0  3.9G   0% /dev/shm",
      "/dev/sda2       100G   43G   52G  46% /var/archive",
    ].join("\n");
  }

  // free
  if (/^free(\s|$)/.test(trimmed)) {
    return [
      "              total        used        free      shared  buff/cache   available",
      "Mem:        8145728     1892432     4312104      156012     1941192     5847744",
      "Swap:       2097148           0     2097148",
    ].join("\n");
  }

  // uptime
  if (trimmed === "uptime") {
    const uptimeHours = Number(context.serviceMemory.deviceState.uptime_hours ?? 438);
    const days = Math.floor(uptimeHours / 24);
    const hours = uptimeHours % 24;
    return ` ${new Date().toTimeString().slice(0, 5)} up ${days} days, ${hours}:${String(Math.floor(Math.random() * 60)).padStart(2, "0")},  1 user,  load average: 0.05, 0.07, 0.04`;
  }

  // date
  if (trimmed === "date" || trimmed === "date -u") {
    return new Date().toUTCString().replace("GMT", "UTC");
  }

  // history
  if (trimmed === "history" || /^history\s+\d+/.test(trimmed)) {
    const cmds = context.serviceMemory.commandHistory.slice(-10);
    if (cmds.length === 0) {
      return "    1  ls\n    2  pwd";
    }
    return cmds.map((cmd, i) => `  ${String(i + 1).padStart(3)}  ${cmd}`).join("\n");
  }

  // which
  if (trimmed.startsWith("which ")) {
    const bin = trimmed.slice(6).trim();
    const known: Record<string, string> = {
      bash: "/bin/bash",
      sh: "/bin/sh",
      python3: "/usr/bin/python3",
      python: "/usr/bin/python3",
      curl: "/usr/bin/curl",
      wget: "/usr/bin/wget",
      nc: "/usr/bin/nc",
      ssh: "/usr/bin/ssh",
      cat: "/usr/bin/cat",
      ls: "/usr/bin/ls",
    };
    return known[bin] ? known[bin] : `which: no ${bin} in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)`;
  }

  // echo
  if (trimmed.startsWith("echo ")) {
    const arg = trimmed.slice(5);
    // Expand simple $VAR references
    const expanded = arg
      .replace(/\$HOME/g, `/home/${effectiveUser}`)
      .replace(/\$USER/g, effectiveUser)
      .replace(/\$HOSTNAME/g, context.serviceMemory.host)
      .replace(/\$SHELL/g, "/bin/bash")
      .replace(/\$PATH/g, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    return expanded.replace(/^["']|["']$/g, "");
  }

  // cd — acknowledge silently
  if (/^cd(\s|$)/.test(trimmed)) {
    return "";
  }

  // sudo — reject
  if (trimmed.startsWith("sudo ")) {
    return `[sudo] password for ${effectiveUser}: \nSorry, try again.`;
  }

  // wget / curl — look busy then fail
  if (/^wget\s/.test(trimmed) || /^curl\s/.test(trimmed)) {
    return `${trimmed.startsWith("curl") ? "curl" : "wget"}: (6) Could not resolve host: (network unreachable)`;
  }

  // find — return partial results for common paths
  if (trimmed.startsWith("find ")) {
    return fileNames.map((f) => `/home/${effectiveUser}/${f}`).join("\n") || "(no results)";
  }

  // mkdir / rm / mv / cp / chmod / chown — acknowledge
  if (/^(mkdir|rm|mv|cp|touch|chmod|chown)(\s|$)/.test(trimmed)) {
    return "";
  }

  // clear / reset
  if (trimmed === "clear" || trimmed === "reset") {
    return "\x1Bc";
  }

  // exit / logout
  if (trimmed === "exit" || trimmed === "logout") {
    return "logout";
  }

  return `bash: ${trimmed.split(/\s/)[0]}: command not found`;
}
