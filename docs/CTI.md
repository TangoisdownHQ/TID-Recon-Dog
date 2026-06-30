# Cyber Threat Intelligence (CTI)

TID-Recon-Dog doubles as a **deception-driven CTI source**: every interaction is
high-signal (no benign traffic), and with `decoy_success`/AI it captures
post-exploitation TTPs. The `src/cti/` module turns those observations into
standard, shareable intelligence.

## What it produces

- **IOCs** (`src/cti/iocEngine.ts`): IPs (v4/v6, public only), usernames tried,
  commands, URLs/paths, user-agents — deduped with counts + first/last seen.
- **MITRE ATT&CK mapping**: observed behavior → technique IDs (T1110 brute force,
  T1595 scanning, T1190 exploit, T1083/T1082/T1033 discovery, T1105 tool transfer,
  T1059 execution, T0831 ICS manipulation, …) with per-technique counts.
- **Actors**: per-attacker summaries (IP, geo/ISP, risk, intent, services, timeline).

## Standard exports (`src/cti/export.ts`)

| Format | CLI | API |
|--------|-----|-----|
| STIX 2.1 bundle | `cti stix [out]` | `GET /api/cti/stix` |
| MISP event | `cti misp [out]` | `GET /api/cti/misp` |
| IP blocklist (txt/csv) | `cti blocklist [out]` | `GET /api/cti/blocklist.{txt,csv}` |
| IOC / ATT&CK JSON | `cti iocs` / `cti attack` | `GET /api/cti/iocs` `/api/cti/attack` |

**TAXII 2.1-style** pull endpoint for SIEM/CTI clients:
`GET /taxii2/cti/collections/honeypot/objects` (returns the STIX objects).

## Enrichment (optional, set API keys)

`ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `VIRUSTOTAL_API_KEY` — IP reputation,
cached in `runtime/enrichment.json`. No keys = skipped gracefully.

## Threat-feed ingestion → auto-block

`THREAT_FEEDS` = comma-separated URLs of plaintext IP/CIDR blocklists (FireHOL,
abuse.ch, spamhaus DROP, …). `cti ingest-feeds` (or the CTI tab button / 
`POST /api/cti/ingest-feeds`) pulls them and blocks the IPs via the control-plane
blocklist (same engine as manual block/kick).

## Forwarding to your stack (`src/cti/forward.ts`)

Every interaction is forwarded (best-effort) to whatever is configured:
- `SYSLOG_URL=udp://host:514` or `tcp://host:514` — emits **CEF** (SIEM-friendly).
- `CTI_WEBHOOK_URL` — raw JSON event POST (Slack-compatible relays, etc.).
- `SPLUNK_HEC_URL` + `SPLUNK_HEC_TOKEN` — Splunk HTTP Event Collector.

## Campaigns, novelty & kill-chain

- **Campaigns** — attackers clustered into actors by origin (ISP/country) + intent
  (`GET /api/cti/campaigns`).
- **Novelty / anomaly** — IOCs & techniques first seen in the last N hours
  (`GET /api/cti/novelty?hours=24`).
- **ATT&CK kill-chain** — techniques laid out across the tactic order (Recon →
  Impact) in the CTI tab.

## Dark-web intel stream

Correlates the honeypot's own observed indicators (IPs, usernames, URLs) against
external leak / paste / breach feeds — so you're alerted when something you
captured is also circulating externally.

```sh
DARKWEB_FEEDS=https://feed1/...,https://feed2/...   # plaintext or JSONL feeds
DARKWEB_PROXY=socks5://127.0.0.1:9050               # optional, for Tor/.onion
node dist/index.js cti darkweb                      # scan + correlate now
```
`GET /api/cti/darkweb` / `POST /api/cti/darkweb/refresh`, and the CTI tab's
dark-web section. Only matched indicators are stored, never raw leak content.

## Scheduled intel reports

```sh
node dist/index.js cti report [dir]   # writes intel-report-<date>.md + stix-<date>.json
```
Automate daily with cron/systemd, or pair with the forwarding webhook to push
summaries to Slack/email.

## Operator GUI

The **CTI** tab shows connector status, IOC counts + table, the ATT&CK coverage
heatmap + kill-chain, campaigns, novelty, dark-web correlations, and one-click
STIX/MISP/blocklist downloads + feed ingestion.

## Typical uses

- **SOC**: high-fidelity alerts → auto-blocklist push + SIEM forwarding.
- **Threat research**: real attacker tooling/TTPs mapped to ATT&CK; actor clustering.
- **Sharing**: publish STIX/TAXII or MISP feeds to your team / an ISAC.
