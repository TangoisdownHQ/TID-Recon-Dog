# TID-Recon-Dog — Documentation

Deception platform + CTI source + MLOps loop. This is the documentation hub;
each topic links to its detailed guide.

## Start here
- [Architecture overview](ARCHITECTURE.md) — how the pieces fit together
- Main [README](../README.md) — features, CLI, services, env vars

## Operating
- [Hosting & testing](HOSTING.md) — run it, expose it, generate test traffic
- [Anti-fingerprinting](HARDENING.md) — make decoys look real; deployment-level tells
- Operator console — metrics GUI, control plane, engine modes (see README "Operator Metrics Console")

## Deception content
- Fake services & login panels — README "Fake Login Panels"
- Juicy explorable filesystem (SSH/telnet): `cd`/`ls`/`cat`/`find`/`grep`, stateful writes,
  `sudo`, pipes, lateral movement (`ssh`/`ping`/`curl` to fake internal hosts)
- IoT OpsCenter admin console (doors/gates/buildings/access log)
- Operator response tactics: block/kick, tarpit, decoy_success, **message injection**, **auto-response playbooks**

## Threat intelligence (CTI)
- [CTI guide](CTI.md) — IOC extraction, MITRE ATT&CK mapping + kill-chain, STIX 2.1 / MISP / TAXII,
  enrichment (AbuseIPDB/GreyNoise/VirusTotal), threat-feed ingestion → auto-block,
  SIEM forwarding (syslog/CEF, webhook, Splunk HEC), campaign clustering, novelty/anomaly,
  **dark-web intel stream**, scheduled intel reports

## MLOps (model)
- [Retraining](../mlops/RETRAIN.md) — Qwen3-4B QLoRA on collected transcripts (on-demand + 8h)
- [Live inference](../mlops/INFERENCE.md) — shadow / AI engine modes, model-server setup

## Deployment
- [Kubernetes](../k8s/README.md) — kustomize manifests, per-protocol Services, Cilium NetworkPolicy
- [AWS — EC2 (Phase 1)](../infra/aws/terraform/README.md) — single-host honeypot via Terraform
- [AWS — EKS (Phase 2)](../infra/aws/eks/README.md) — production cluster
- [AWS — GPU model host](../infra/aws/model/README.md) — optional AI inference (Path C)

## Quick reference

```sh
npm install && npm run build
npm start                              # all services + operator TUI
node dist/index.js serve-dashboard     # operator web GUI only
node dist/index.js cti report          # write a STIX + markdown intel report
node dist/index.js retrain --force     # retrain the model now
```

> Status of features and what's verified/deployed is tracked per-topic in each
> guide. See [ARCHITECTURE.md](ARCHITECTURE.md) for the module map.
