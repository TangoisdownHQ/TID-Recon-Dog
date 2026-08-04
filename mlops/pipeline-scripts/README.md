# Pipeline scripts (versioned reference copies)

The live ML pipeline lives in `mlops/tidrc-ml-pipeline/`, which is a **separate
local git repo with no remote** — so nothing in it is backed up. These are the
versioned copies of the scripts we author/edit, kept in the main repo (which
pushes to GitHub) for backup and review.

| Script | Role |
|--------|------|
| `sync_retrain.sh`  | Pull fresh fleet capture from S3 (FRESH=1 forces a backup via SSM), quarantine poisoning attempts, hand off to `auto_retrain.sh`. |
| `filter_poison.py` | Quarantine training-poisoning attempts (break-character in target, prompt-injection input, oversized, control-char reflection, per-attacker flood) out of a transcripts.jsonl. |
| `auto_retrain.sh`  | New-line gate + build dataset + QLoRA fine-tune + quality gate. Reads live + archive log dirs. |

To restore the live pipeline after these edits, copy them back:
`cp mlops/pipeline-scripts/*.{sh,py} mlops/tidrc-ml-pipeline/scripts/`
See `mlops/RETRAIN.md` for the full flow and env knobs.
