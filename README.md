```
      ______     __     __     ______
     /\  == \   /\ \   /\ \   /\  ___\
     \ \  __<   \ \ \  \ \ \  \ \  __\
      \ \_\ \_\  \ \_\  \ \_\  \ \_____\
       \/_/ /_/   \/_/   \/_/   \/_____/

T   54    A   41    N   4E    G   47    O   4F    I   49    S   53    D   44    O   4F    W   57    N   4E    -   2D
R   52    E   45    C   43    O   4F    N   4E    -   2D
D   44    O   4F    G   47

            BRAVE NEW WORLD . .  .  .


           𓏺𓏺 𓎆𓎆𓏺𓏺𓏺𓏺𓏺𓏺 𓆼𓆼 𓎆𓎆 𓏺𓏺𓏺𓏺𓏺

  -'ALL WARFARE IS BASED ON DECEPTION'-
  - - -  -  - --SUN TZU'--- - -- - - -  -
```

# TID-Recon-Dog

TID-Recon-Dog is a CLI/TUI-first deception platform that exposes deterministic fake services, keeps attacker-specific memory across reconnects, and records protocol transcripts for operator review and offline training.

📚 **Full documentation: [`docs/`](docs/README.md)** (architecture, hosting, hardening, CTI, MLOps, deployment).

## What It Does

- Runs deceptive services for `http`, `ssh`, `ftp`, `postgres`, `rtsp`, `rdp`, `telnet`, `modbus`, `snmp`, and `smtp`
- Uses per-service responders instead of free-form runtime LLM output
- Pins each attacker to stable decoy personas and state
- Scores attacker behavior and classifies intent as `recon`, `brute_force`, or `exploitation`
- Exports structured transcripts, datasets, and cloud-ready bundles
- Provides a CLI/TUI dashboard for live sessions and per-session action overrides

## Architecture

- `src/services/`: protocol listeners and socket/http adapters
- `src/responders/`: deterministic per-service deception logic
- `src/profiles/personaLibrary.ts`: camera NVR, jump host, backup server, field gateway, PLC, ops DB, and mail relay personas
- `src/deception_engine/state/attacker_memory.ts`: persistent attacker memory, scoring, intent classification, GeoIP enrichment
- `src/deception_engine/logging/transcript_store.ts`: protocol transcript persistence
- `src/operator/watch.ts`: CLI/TUI dashboard
- `src/operator/alertHook.ts`: risk-escalation alert log + optional webhook
- `src/utils/connectionThrottle.ts`: per-IP connection cap for TCP services
- `src/utils/geoip.ts`: GeoIP lookup with local cache (ip-api.com)
- `src/cloud/bundle.ts`: cloud packaging bundle for S3, SQS, Kinesis, and ECS/Fargate handoff
- `src/pipeline/evalRunner.ts`: run eval suite against Ollama, Anthropic, or OpenAI-compatible models

## Install

```sh
npm install
npm run build
```

## Run

Start the full tool. This boots every deceptive service and opens the operator TUI menu:

```sh
npm start
```

The combined launcher is also available directly:

```sh
node dist/index.js start tidrecondog
```

If you want the literal shell command `start tidrecondog`, link the package once:

```sh
npm link
start tidrecondog
```

Start only the deceptive services without opening the TUI:

```sh
npm run start:services
```

Start only selected services:

```sh
node dist/index.js start http ssh rtsp snmp smtp
```

If one of the default listener ports is already in use on your machine, set the matching env var before launch, for example `POSTGRES_PORT=15432 npm start`.

Open the operator dashboard:

```sh
npm run dashboard
```

## CLI Commands

```sh
node dist/index.js start [all|http|ssh|ftp|postgres|rtsp|rdp|telnet|modbus|snmp|smtp ...]
node dist/index.js start tidrecondog
node dist/index.js sessions
node dist/index.js attackers
node dist/index.js attacker <id>
node dist/index.js dashboard
node dist/index.js profiles
node dist/index.js personas
node dist/index.js export-dataset [output.jsonl] [source1.csv source2.jsonl ...]
node dist/index.js export-transcripts [output.jsonl] [service]
node dist/index.js cloud-bundle [output-dir]
node dist/index.js export-eval-suite [output.jsonl]
node dist/index.js run-eval [suite.jsonl] [responses.jsonl]
node dist/index.js score-eval <responses.jsonl> [suite.jsonl] [output.json]
node dist/index.js control show
node dist/index.js control set default <allow|stall|fake_error|decoy_success|camera_offline>
node dist/index.js control set session <sessionId> <allow|stall|fake_error|decoy_success|camera_offline>
```

## Dashboard Commands

Inside `watch` / `dashboard`:

```text
menu
1 / sessions
2 / attackers
3 / controls
4 / profiles
5 / personas
show <sessionId>
attacker <attackerId>
replay <sessionId>
refresh
default <action>
set <sessionId> <action>
quit
```

## Fake Login Panels (attacker-facing decoys)

Beyond the CamWatch camera viewer, the HTTP listener serves believable product
login pages on the paths scanners commonly probe. Submitted usernames are
recorded into attacker memory (scored as `brute_force`); failed logins return a
realistic error, and the operator can flip a session to `decoy_success` to serve
a fake authenticated dashboard.

| Panel | Decoy product | Paths |
|-------|---------------|-------|
| Admin console | OpsCenter Appliance Manager | `/admin`, `/admin/login`, `/administrator`, `/manager`, `/login` |
| Database web client | Adminer 4.8.1 (PostgreSQL) | `/adminer.php`, `/adminer`, `/pgadmin`, `/phpmyadmin`, `/db` |
| IoT gateway | Fieldline FG-2200 gateway | `/gateway`, `/gateway/login`, `/device`, `/iot`, `/cgi-bin/luci` |

Operator-facing service tags: `ADMIN`, `DB-WEB`, `IOT` (memory normalizes them
to the `http` service). Defined in `src/responders/webPanels.ts`.

## Operator Metrics Console (Web GUI)

A read-only web dashboard (grey/black/burgundy) runs on a **separate, internal**
plane from the attacker-facing services so the deployment can never be
fingerprinted as a honeypot through the operator UI.

- Boots automatically with `npm start` and `start all` (disable with `OPERATOR_DISABLE=1`)
- Run it standalone against existing runtime data: `npm run serve:dashboard`
- Binds to `127.0.0.1:9090` by default — set `OPERATOR_HOST` / `OPERATOR_PORT`
- Requires a bearer token. Set `OPERATOR_TOKEN`, or one is generated and printed
  once at boot. Open `http://<host>:<port>/?token=<token>`.

Endpoints:

| Path                 | Auth | Purpose                                  |
|----------------------|------|------------------------------------------|
| `/`                  | yes  | Dashboard GUI                            |
| `/api/overview`      | yes  | KPIs, risk/intent/country/service tallies|
| `/api/timeline`      | yes  | Hourly activity buckets                  |
| `/api/feed`          | yes  | Recent interaction transcripts           |
| `/api/attackers`     | yes  | Attacker table + `/api/attackers/:id`    |
| `/api/sessions`      | yes  | Session snapshots                        |
| `/api/alerts`        | yes  | Risk-escalation alerts                   |
| `/api/control` (GET/POST) | yes | Read/set default + per-session actions |
| `/metrics`           | yes  | Prometheus exposition (k8s scraping)     |
| `/healthz` `/readyz` | no   | k8s liveness/readiness probes            |

## Retraining (MLOps)

The honeypot's transcripts feed a QLoRA fine-tune of Qwen3-4B
(`mlops/tidrc-ml-pipeline/`). Retrain on demand or on a schedule:

```sh
npm run retrain                       # respects the >=10-new-transcripts gate
node dist/index.js retrain --force    # retrain now
node dist/index.js retrain --export-only   # dataset export only (no GPU)
```

Automatic every-8-hours: a systemd timer locally (`mlops/systemd/`) or a k8s
CronJob on EKS (`k8s/mlops/cronjob.yaml`). The operator console exposes
`POST /api/retrain` and `GET /api/retrain/status`. Full guide:
[`mlops/RETRAIN.md`](mlops/RETRAIN.md).

## Cyber Threat Intelligence (CTI)

Doubles as a deception-driven CTI source: extracts IOCs, maps observed behavior
to MITRE ATT&CK, and exports STIX 2.1 / MISP / blocklists over CLI, API, and a
TAXII 2.1-style feed; optional enrichment (AbuseIPDB/GreyNoise/VirusTotal),
threat-feed ingestion → auto-block, and SIEM forwarding (syslog/CEF, webhook,
Splunk HEC). Operator **CTI** tab + `node dist/index.js cti <iocs|attack|stix|misp|blocklist|ingest-feeds>`.
Full guide: [`docs/CTI.md`](docs/CTI.md).

## Anti-fingerprinting

Decoys are hardened to look like the real products they imitate (nginx `Server`
header + no Express tell + nginx error pages + response jitter on HTTP; OpenSSH
ident + algorithm set + stable host key on SSH). See [`docs/HARDENING.md`](docs/HARDENING.md),
including the **deployment-level** guidance (don't expose all 10 services on one IP).

## Hosting & testing

See [`docs/HOSTING.md`](docs/HOSTING.md) for the recommended exposure path
(public-IP VPS on real ports), firewall rules, and how to generate test traffic.

## Deterministic Runtime Model

The runtime path no longer depends on `src/ai_agents`. Each service now calls a responder that:

- picks a stable persona for the attacker
- returns protocol-appropriate banners and replies
- reuses attacker-specific usernames, files, hostnames, and device state
- records structured request/response transcripts
- never emits raw env vars, localhost values, or unrestricted shell output

## Services

| Service  | Default Port | Protocol | Persona Group   |
|----------|-------------|----------|-----------------|
| http     | 3000        | TCP/HTTP | camera_nvr      |
| ssh      | 2222        | TCP      | jump_host       |
| ftp      | 2121        | TCP      | backup_server   |
| postgres | 5432        | TCP      | operations_db   |
| rtsp     | 8554        | TCP      | camera_nvr      |
| rdp      | 3389        | TCP      | jump_host       |
| telnet   | 2323        | TCP      | field_gateway   |
| modbus   | 1502        | TCP      | plc_controller  |
| snmp     | 16100       | UDP      | plc_controller  |
| smtp     | 2525        | TCP      | mail_relay      |

Override any port with the matching env var: `SNMP_PORT=161 SMTP_PORT=25 npm start`.

## Environment Variables

| Variable                   | Default      | Description                                           |
|---------------------------|-------------|-------------------------------------------------------|
| `ALERT_WEBHOOK_URL`       | (none)       | POST risk-escalation payloads here                    |
| `PERSONA_ROTATE_AFTER_HOURS` | 0 (never) | Rotate attacker persona assignments after N hours     |
| `MAX_CONNECTIONS_PER_IP`  | 25           | Simultaneous connection cap per IP per TCP service    |
| `EVAL_PROVIDER`           | ollama       | `ollama` / `anthropic` / `openai`                    |
| `EVAL_MODEL`              | llama3       | Model name passed to the eval provider                |
| `EVAL_API_URL`            | (auto)       | Override the model API endpoint for run-eval          |
| `EVAL_API_KEY`            | (none)       | API key for run-eval (or `ANTHROPIC_API_KEY`)         |
| `AI_MODEL_URL`            | (none)       | OpenAI-compatible chat endpoint for shadow/AI engine modes (see [`mlops/INFERENCE.md`](mlops/INFERENCE.md)) |
| `AI_MODEL`                | honeypot-qwen| Model name sent to the inference endpoint             |
| `AI_API_KEY`              | (none)       | Bearer token for the inference endpoint, if required  |
| `AI_TIMEOUT_MS`           | 12000        | Inference request timeout                             |
| `AI_MAX_TOKENS`           | 256          | Max tokens per generated response                     |

## Alert Hook

When an attacker's risk level escalates (low→medium or any→high), TID-Recon-Dog:

1. Appends a JSONL entry to `runtime/alerts.jsonl`
2. POSTs to `ALERT_WEBHOOK_URL` if set (non-blocking, best-effort)

Payload fields: `at`, `event`, `attacker_id`, `source_ip`, `risk`, `previous_risk`, `intent`, `score`, `services`, `recent_events`.

## Eval Pipeline

```sh
# 1. Generate eval prompts from service profiles
node dist/index.js export-eval-suite

# 2. Run prompts against a local Ollama model
EVAL_PROVIDER=ollama EVAL_MODEL=llama3 node dist/index.js run-eval

# 3. Score the responses
node dist/index.js score-eval ct/eval/responses.jsonl

# Or run against Claude (requires ANTHROPIC_API_KEY)
EVAL_PROVIDER=anthropic EVAL_MODEL=claude-haiku-4-5-20251001 node dist/index.js run-eval
```

## Cloud Bundle

`cloud-bundle` writes a portable packaging directory under `exports/` with:

- `s3/`: logs, transcripts, sessions, attackers, controls
- `sqs/`: JSONL message envelopes
- `kinesis/`: JSONL base64 records
- `ecs/`: Fargate task definition

This is intended as a handoff artifact for later AWS deployment, not a live AWS publisher.

## Docker

Build:

```sh
docker build -t tid-recon-dog .
```

Run:

```sh
docker compose up --build
```

The container exposes health on `http://localhost:9090/healthz` and the operator
GUI on `http://127.0.0.1:9090/` (token printed at boot).

## Kubernetes

Kustomize manifests live in `k8s/` and deploy with `kubectl -k` (no Helm needed):

```sh
# internal / ClusterIP only
kubectl apply -k k8s/base

# public exposure on real well-known ports via a cloud LoadBalancer
kubectl apply -k k8s/overlays/external
```

Each protocol is its own `Service` (real-port → container-port), the operator
metrics plane stays `ClusterIP`-only (never internet-reachable), and the pod
ships `/healthz` + `/readyz` probes and a Prometheus `/metrics` endpoint. See
[`k8s/README.md`](k8s/README.md) for the full walkthrough (image build, secret
creation, dashboard port-forward, design notes).
