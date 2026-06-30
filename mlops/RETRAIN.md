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
