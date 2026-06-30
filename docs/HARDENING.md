# Anti-fingerprinting hardening

Goal: make each decoy behave like the real product it imitates, so automated
honeypot scanners and version probes can't trivially flag it. Scope is
**defensive realism** — looking like a genuine service — not evading any
specific vendor's detection.

## Done (verified)

**HTTP (`src/services/httpService.ts`)**
- Removed the `X-Powered-By: Express` header (a framework giveaway) and disabled ETag.
- Sends `Server: nginx/1.24.0` (from the persona profile) on **every** response, including errors.
- Unknown paths return a byte-accurate **nginx 404** page instead of a chatty relay banner that leaked the internal hostname.
- Rate-limit responses return nginx's `503` page, not a plaintext Express message.
- Small randomized **response jitter** (`src/utils/hardening.ts`) so latency isn't suspiciously uniform.

**SSH (`src/services/sshService.ts`)**
- Advertises `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` — ssh2's default `ssh2js<ver>` ident was the single biggest tell.
- Offers an **OpenSSH-like algorithm set** (kex/cipher/MAC/hostkey) instead of ssh2's defaults, so the KEXINIT/HASSH fingerprint is much closer to real OpenSSH. Verified: a stock `ssh` client negotiates the full handshake.
- **Stable host key** persisted to `runtime/ssh/` (a key that changes every restart is itself suspicious), replacing the per-boot ephemeral key.

## Known limitations / follow-ups

- **HASSH not byte-identical.** ssh2 doesn't implement `umac-*` MACs, so the MAC offer differs slightly from stock OpenSSH. RSA-only host key (ssh2 can't parse Node's ed25519 PEM without OpenSSH-format tooling).
- **No TLS yet.** The web panels are plain HTTP; real admin/camera UIs are often HTTPS. Adding HTTPS with a plausible self-signed cert is the next HTTP item.
- **Other TCP services** (ftp/smtp/telnet/postgres/rtsp/modbus) have realistic banners but no jitter yet, and could use the same treatment.
- **TCP/IP stack fingerprint (`nmap -O`)** is set by the host kernel, not the app — out of app scope (handle at the OS/network layer if needed).

## Deployment-level hardening (important)

The strongest tell is structural: a **single IP exposing 10 unrelated services**
(camera + Postgres + Modbus + SSH + RDP + SMTP …) does not look like a real host
— real hosts are specialized. In production, split personas across IPs/hosts so
each endpoint exposes only the ports its device type would:

| Persona | Plausible exposed ports |
|---------|-------------------------|
| camera_nvr | 80/443 (HTTP), 554 (RTSP) |
| operations_db | 5432 |
| plc_controller | 502 (Modbus), 161 (SNMP) |
| jump_host | 22 (SSH), 3389 (RDP) |
| mail_relay | 25 (SMTP) |

On EKS this maps to multiple Deployments/Services (or multiple LoadBalancer IPs)
rather than one all-ports host; on a VPS fleet, one persona per box.
