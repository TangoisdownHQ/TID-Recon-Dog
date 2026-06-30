# Hosting & testing

Goal: let real users/scanners hit the honeypot, observe what it gets hit with,
and mirror the eventual Amazon EKS deployment. Recommended path while hosting
locally: **a small public-IP cloud VPS running the container on real ports.**
Keep `kind` for dev iteration; use the VPS for exposure.

## Why a VPS over tunnels (ngrok / Cloudflare)

A honeypot must look like a real host. Tunnels assign random high ports and
add a recognizable tunnel hostname (a fingerprint), and TCP tunnels drop the
attacker's source IP — which kills GeoIP/attribution. A VPS gives **real
well-known ports + real source IPs**, exactly like EKS will. See the
`ngrok-exposure-plan` note for the full tradeoff.

## 1. Stand up the VPS (any provider: Hetzner / Vultr / Lightsail / EC2)

- Smallest tier with a public IPv4 is fine to start (1–2 vCPU / 2–4 GB).
- Install Docker + compose plugin.
- **Do NOT run the MLOps trainer here** — training needs a GPU and stays on your
  local host (or the EKS GPU CronJob). The VPS only runs the honeypot services.

## 2. Deploy the honeypot

```sh
git clone <repo> && cd TID-Recon-Dog
docker compose up -d --build      # binds real high ports; operator on 127.0.0.1:9090
```

To present **real well-known ports** to the internet (so it looks legit), map
them in compose or with host firewall DNAT, e.g. publish container 2222→22,
3000→80, 5432→5432, etc. (the k8s `external` overlay already does this mapping;
on a single VPS use compose `ports:` like `"22:2222"`, `"80:3000"`, …).

## 3. Firewall rules

Open ONLY the decoy ports inbound; never expose the operator plane.

```sh
# example with ufw
sudo ufw default deny incoming
sudo ufw allow 22,80,21,5432,554,3389,23,502,25/tcp
sudo ufw allow 161/udp
# operator 9090 stays closed; reach it over SSH tunnel:
#   ssh -L 9090:127.0.0.1:9090 user@vps   then open http://127.0.0.1:9090/?token=...
sudo ufw enable
```

> Run your real admin SSH on a non-standard port and lock it to your IP, since
> port 22 is now the honeypot's fake SSH.

## 4. Watch what it gets hit with

- Operator GUI over the SSH tunnel: `http://127.0.0.1:9090/?token=$OPERATOR_TOKEN`
- CLI: `node dist/index.js attackers` / `sessions`, or `docker compose exec`.
- Prometheus scrape of `:9090/metrics` if you wire monitoring.

## 5. Generate your own test traffic (local or VPS)

```sh
nmap -sV -p 22,80,21,5432,3389,23,502,25 <host>     # banner/version probes
curl http://<host>/admin   http://<host>/adminer.php  # hit the fake panels
hydra -l admin -P rockyou.txt <host> http-post-form \
  "/admin/login:username=^USER^&password=^PASS^:Invalid"   # brute force → scored
```

Each hit flows into attacker memory + transcripts, and feeds the 8-hourly
retrain (see `mlops/RETRAIN.md`).

## 6. Migrating to EKS

The Kubernetes manifests (`k8s/`) are the production target: per-protocol
Services, Cilium-enforced operator isolation, and the retrain CronJob
(`k8s/mlops/cronjob.yaml`). The VPS setup is the testing rehearsal for it.
