#!/usr/bin/env bash
# Portable retrain entrypoint for the TID-Recon-Dog ML pipeline.
#
# - Paths are derived from this script's location (works on host, container, EKS).
# - Retrains only when >= RETRAIN_MIN_NEW new transcript lines have arrived since
#   the last run, unless RETRAIN_FORCE=1.
# - Writes a machine-readable status file the operator console can read.
#
# Env knobs (all optional):
#   RUNTIME_DIR          live honeypot data dir (default: <repo>/runtime)
#   RETRAIN_MIN_NEW      min new transcript lines to trigger (default: 10)
#   RETRAIN_FORCE        1 = retrain regardless of new-line count
#   RETRAIN_BACKEND      qlora | none  (none = export dataset only, no GPU)
#   PIPELINE_BASE_MODEL  base checkpoint dir (default: <repo>/mlops/Qwen3-4-Base)
#   TRAINER_PYTHON       trainer venv python (default: <pipeline>/.venv-train/bin/python)
#   RETRAIN_STATUS_FILE  status json path (default: <runtime>/retrain_status.json)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PIPELINE_DIR/../.." && pwd)"

RUNTIME_DIR="${RUNTIME_DIR:-$REPO_ROOT/runtime}"
TRANSCRIPT_FILE="$RUNTIME_DIR/transcripts.jsonl"
LAST_COUNT_FILE="$PIPELINE_DIR/.last_example_count"
STATUS_FILE="${RETRAIN_STATUS_FILE:-$RUNTIME_DIR/retrain_status.json}"
MIN_NEW="${RETRAIN_MIN_NEW:-10}"
FORCE="${RETRAIN_FORCE:-0}"
BACKEND="${RETRAIN_BACKEND:-qlora}"
BASE_MODEL="${PIPELINE_BASE_MODEL:-$REPO_ROOT/mlops/Qwen3-4-Base}"
TRAINER_PY="${TRAINER_PYTHON:-$PIPELINE_DIR/.venv-train/bin/python}"
RUN_ID="$(date +%Y%m%dT%H%M%SZ)"

mkdir -p "$RUNTIME_DIR"

write_status() {
  # write_status <state> <message>
  local state="$1" msg="$2"
  cat > "$STATUS_FILE" <<JSON
{
  "state": "$state",
  "run_id": "$RUN_ID",
  "backend": "$BACKEND",
  "new_transcripts": ${new:-0},
  "total_transcripts": ${count:-0},
  "min_new": $MIN_NEW,
  "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "message": "$msg"
}
JSON
}

on_error() { write_status "failed" "retrain failed; see retrain.log"; }
trap on_error ERR

cd "$PIPELINE_DIR"

count=$(wc -l < "$TRANSCRIPT_FILE" 2>/dev/null || echo 0)
last=$(cat "$LAST_COUNT_FILE" 2>/dev/null || echo 0)
new=$((count - last))

if [ "$FORCE" != "1" ] && [ "$new" -lt "$MIN_NEW" ]; then
  echo "[$(date)] Only $new new lines (need $MIN_NEW); skipping. Set RETRAIN_FORCE=1 to override."
  write_status "skipped" "only $new new lines (need $MIN_NEW)"
  exit 0
fi

echo "[$(date)] Retraining (run $RUN_ID) — $new new transcript lines, backend=$BACKEND"
write_status "running" "retraining with $new new transcript lines"

python3 scripts/build_dataset.py

# Archive log dirs (salvaged/historical transcripts) are trained on alongside
# live runtime. The pipeline dedupes by unique example, so overlap is harmless.
# Default includes the salvaged pre-fleet backup; override with RETRAIN_ARCHIVE_DIRS.
ARCHIVE_DIRS="${RETRAIN_ARCHIVE_DIRS:-$PIPELINE_DIR/archive_logs}"
LOG_DIRS="$RUNTIME_DIR"
if [ -n "$ARCHIVE_DIRS" ] && [ -d "${ARCHIVE_DIRS%%,*}" ]; then
  LOG_DIRS="$RUNTIME_DIR,$ARCHIVE_DIRS"
fi

# Export-only ('none') omits the trainer backend so no GPU is needed.
TRAINER_ARGS=(
  "PIPELINE_LOG_DIRS=$LOG_DIRS"
  "PIPELINE_BASE_MODEL=$BASE_MODEL"
  "PIPELINE_MANUAL_EXAMPLES_DIR=./manual_examples"
  "TRAINER_PYTHON=$TRAINER_PY"
  "TRAINER_NUM_TRAIN_EPOCHS=${TRAINER_NUM_TRAIN_EPOCHS:-5}"
  "TRAINER_USE_4BIT=${TRAINER_USE_4BIT:-true}"
  "TRAINER_DISABLE_THINKING=${TRAINER_DISABLE_THINKING:-true}"
)
if [ "$BACKEND" = "qlora" ]; then
  TRAINER_ARGS+=("PIPELINE_TRAINER_BACKEND=qlora")
fi

env "${TRAINER_ARGS[@]}" ./target/release/tidrc-ml-pipeline

echo "$count" > "$LAST_COUNT_FILE"
echo "[$(date)] Retrain complete (run $RUN_ID)"
write_status "success" "retrain complete"
