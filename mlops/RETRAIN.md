# Retraining (MLOps)

The honeypot collects attacker transcripts into `runtime/transcripts.jsonl`. The
pipeline in `mlops/tidrc-ml-pipeline/` turns that live data (plus curated
`manual_examples/`) into a fine-tuned Qwen3-4B model via QLoRA.

```
runtime/transcripts.jsonl  ──►  build_dataset.py + tidrc-ml-pipeline (Rust)
                                   ├─ ingest → preprocess → export train/eval JSONL
                                   ├─ QLoRA fine-tune Qwen3-4B  (scripts/train_qlora.py)
                                   ├─ evaluate vs served model
                                   └─ deployment gate (non-empty rate, similarity)
```

`scripts/auto_retrain.sh` is the single entrypoint. It only retrains once
`RETRAIN_MIN_NEW` (default 10) new transcript lines have arrived since the last
run, and writes `runtime/retrain_status.json` for the operator console.

## Retrain at will (on demand)

```sh
# from the repo root, on the host that has the GPU + .venv-train + base model
npm run retrain                      # respects the >=10-new gate
node dist/index.js retrain --force   # retrain now regardless
node dist/index.js retrain --export-only   # dataset export only, no GPU

# or from the operator console (local host only):
#   POST /api/retrain   { "force": true }
#   GET  /api/retrain/status
```

On Kubernetes, on-demand = spawn the CronJob immediately:

```sh
kubectl -n tid-recon-dog create job --from=cronjob/tidrc-retrain retrain-now-$(date +%s)
```

## Retraining from the AWS fleet (capture ≠ train)

The honeypot fleet runs on small AWS nodes with **no GPU** — they only capture
and back up transcripts to S3 (daily, per node, under
`s3://<backup-bucket>/nodes/<node>/<ts>/opt_tid-runtime.tgz`). Training lives on
**this machine** (GPU, `.venv-train`, base model). `sync_retrain.sh` bridges the
two: it pulls each node's latest capture from S3, merges the transcripts into a
dedicated `runtime-fleet/` dir, then hands off to `auto_retrain.sh` (the
salvaged/archived batches in `archive_logs/` are still folded in and deduped).

```sh
# from the repo root, on the GPU host — fresh fleet data + QLoRA retrain:
bash mlops/tidrc-ml-pipeline/scripts/sync_retrain.sh
```

### Poisoning defense

The pulled transcripts are attacker-controlled, and responders reflect input, so
a source that suspects a honeypot could craft traffic that teaches the model to
break character if trained on. After merging, `sync_retrain.sh` runs
`filter_poison.py`, which **quarantines** (does not delete — poisoned records are
themselves intel) anything unsafe to train on: break-character/AI-reveal phrases
in the response (training target), prompt-injection in the request, oversized
fields, control-char/binary reflection, and per-attacker floods (surplus over
`MAX_PER_ATTACKER` down-sampled, lowest-signal first). Quarantined records and a
stats summary land in `FLEET_RUNTIME_DIR` (`poison-quarantine.jsonl`,
`poison-stats.json`). `POISON_DISABLE=1` skips the pass.

Because nodes only back up to S3 daily, `sync_retrain.sh` defaults to `FRESH=1`:
it first triggers `tid-backup.sh` on every running node via SSM and waits, so S3
holds current capture before the pull. Requires AWS creds (`aws sts
get-caller-identity` must succeed) with SSM + S3 read.

| Env | Default | Purpose |
|-----|---------|---------|
| `FRESH` | `1` | force an on-demand backup on all nodes before pulling (`0` = use existing S3 snapshots) |
| `SYNC_ONLY` | `0` | `1` = download + merge only, skip the retrain (inspect the data) |
| `TID_BACKUP_BUCKET` | `tid-recon-dog-backups-<acct>` | S3 backup bucket |
| `TID_NODES` | the 7 fleet nodes | which nodes to pull |
| `FLEET_RUNTIME_DIR` | `<repo>/runtime-fleet` | where merged transcripts land |

All `auto_retrain.sh` knobs (`RETRAIN_FORCE`, `RETRAIN_BACKEND`, …) pass through:

```sh
SYNC_ONLY=1 bash …/sync_retrain.sh                       # just pull + inspect
FRESH=0 RETRAIN_BACKEND=none RETRAIN_FORCE=1 bash …/sync_retrain.sh   # export-only dry run
```

> `sync_retrain.sh` lives in the (gitignored) pipeline dir alongside
> `auto_retrain.sh`; it isn't pushed, but this doc is the reference to recreate it.

## Retrain every 8 hours

**Local host** (training runs where the GPU/model live) — systemd timer:

```sh
sudo cp mlops/systemd/tidrc-retrain.{service,timer} /etc/systemd/system/
# edit User/WorkingDirectory/paths in the .service first
sudo systemctl daemon-reload
sudo systemctl enable --now tidrc-retrain.timer
systemctl list-timers tidrc-retrain.timer      # confirm next run
```

(cron alternative: `0 */8 * * * cd /…/mlops/tidrc-ml-pipeline && bash scripts/auto_retrain.sh >> retrain.log 2>&1`)

To train on **live AWS fleet** data on that schedule, point the timer/cron at
`scripts/sync_retrain.sh` instead of `auto_retrain.sh` — it pulls fresh capture
from S3 first (see the fleet section above), then retrains.

**EKS** — `kubectl apply -f k8s/mlops/cronjob.yaml` (GPU node pool + shared
transcript storage required; see comments in that file and `infra/aws/README.md`).

## Backends

| `RETRAIN_BACKEND` | Needs GPU | What it does |
|-------------------|-----------|--------------|
| `qlora` (default) | yes       | full QLoRA fine-tune of Qwen3-4B |
| `none`            | no        | dataset export + quality gate only (for CI / dry runs) |

## Quality gate

A retrained candidate is only accepted if it clears `PIPELINE_MIN_NON_EMPTY_RATE`
(0.80) and `PIPELINE_MIN_SIMILARITY_SCORE` (0.55) against the eval set — so a bad
run can't silently ship a model that would blow the honeypot's cover.

> Status: the retrain **orchestration** (triggers + scheduling + gate) is wired
> and verified in export-only mode. Serving the fine-tuned model back to the
> honeypot in **shadow mode** is the next step (see project notes).
