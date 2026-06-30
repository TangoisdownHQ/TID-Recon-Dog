# Architecture

```
                          ┌──────────────────────────────────────────┐
   attackers / scanners ─▶│  Decoy services (attacker-facing surface)  │
   (internet)             │  http ssh ftp postgres rtsp rdp telnet     │
                          │  modbus snmp smtp  — per-protocol listeners│
                          └───────────────┬────────────────────────────┘
                                          │ every interaction
                          ┌───────────────▼────────────────────────────┐
                          │  Responders (deterministic) + AI engine     │
                          │  + juicy fake filesystem + fake panels       │
                          └───────────────┬────────────────────────────┘
                                          │ recordInteractionEvent()
        ┌─────────────────────────────────┼─────────────────────────────────┐
        ▼                 ▼                ▼                ▼                 ▼
  attacker memory    transcripts      playbooks        forwarding        CTI engine
  (scoring/intent)   (jsonl)          (auto-response)  (syslog/HEC)       (IOC/ATT&CK)
        │                 │                                                  │
        └──────┬──────────┴──────────────────────────────────────────┬──────┘
               ▼                                                       ▼
   Operator plane (ClusterIP/localhost, token-gated)        CTI exports + streams
   metrics GUI · control · MLOps · CTI tabs                 STIX/MISP/TAXII · blocklist
               │                                            dark-web correlation
               ▼                                            scheduled reports
   transcripts ──▶ MLOps pipeline (Qwen3-4B QLoRA) ──▶ model ──▶ shadow/AI engine modes
```

## Two planes (never share a port)
- **Attacker-facing** — the decoy services. Designed to look real (hardened
  banners/headers, juicy explorable filesystem, fake login panels).
- **Operator-facing** — the metrics/CTI/control GUI + API. Internal only
  (loopback / ClusterIP), token-gated. Keeping this off the public surface is
  what stops the deployment being fingerprinted as a honeypot.

## Module map (`src/`)
| Area | Path |
|------|------|
| CLI entrypoint / command router | `index.ts` |
| Protocol listeners | `services/*.ts` |
| Deterministic responders | `responders/*.ts` (+ `fakeFilesystem.ts`, `webPanels.ts`, `aiEngine.ts`) |
| Attacker memory / scoring | `deception_engine/state/attacker_memory.ts` |
| Transcripts / shadow / sessions | `deception_engine/logging/`, `utils/logger.ts` |
| Operator API + GUI | `operator/api/metricsServer.ts`, `operator/web/` |
| Control plane (actions, mode, blocklist, injection) | `operator/controlPlane.ts` |
| Auto-response playbooks | `operator/playbooks.ts` |
| CTI (IOC/ATT&CK/exports/enrich/feeds/forward/darkweb) | `cti/*.ts` |
| Profiles / personas | `profiles/*.ts` |
| Safety (output sanitization) | `responders/safety.ts` |

## Data on disk (`runtime/`)
`attackers.json` · `sessions.json` · `transcripts.jsonl` · `controls.json` ·
`alerts.jsonl` · `shadow.jsonl` · `playbooks.json` · `enrichment.json` ·
`darkweb.json` · `retrain_status.json` · `ssh/` (stable host key)

## Engine modes (operator-selectable)
- **deterministic** — hardcoded responders only (default, safe)
- **shadow** — serve deterministic, log a model candidate for review
- **ai** — model writes the served response when a session is `decoy_success`

## MLOps loop
transcripts → `mlops/tidrc-ml-pipeline` (ingest → dataset → QLoRA fine-tune →
eval → quality gate) → GGUF (base + LoRA adapter) → served via Ollama/llama.cpp →
shadow/AI engine modes. On-demand (`retrain`) or every 8h (systemd timer / k8s CronJob).
