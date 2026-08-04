#!/usr/bin/env bash
# Sync-then-retrain: pull fresh fleet capture down from S3, then retrain locally.
#
# The AWS honeypot nodes have no GPU and can't train — they only capture and
# back up their transcripts to S3 daily. Training lives on this machine (GPU,
# venv, base model). This wrapper bridges the two: it downloads each node's
# latest runtime backup, merges the transcripts into a dedicated fleet runtime
# dir, then hands off to auto_retrain.sh (which gates on new-line count and runs
# the QLoRA pipeline). The historical salvaged batch in archive_logs/ is still
# folded in by auto_retrain.sh, so training sees fleet + archive together.
#
# Env knobs (all optional):
#   TID_BACKUP_BUCKET   S3 bucket (default: tid-recon-dog-backups-275573051415)
#   AWS_REGION          region (default: us-east-1)
#   TID_NODES           space-separated node names (default: the 7 fleet nodes)
#   FLEET_RUNTIME_DIR   where merged fleet transcripts land
#                       (default: <repo>/runtime-fleet)
#   FRESH               1 (default) = trigger an on-demand backup on every node
#                       via SSM first, so S3 holds current capture (nodes back up
#                       to S3 only daily otherwise). 0 = use existing S3 snapshots.
#   TID_NAME_PREFIX     EC2 Name-tag prefix used to find nodes for FRESH backups
#                       (default: tid-recon-dog-)
#   SYNC_ONLY           1 = download + merge, skip retrain (inspect the data)
#   ...plus every auto_retrain.sh knob (RETRAIN_FORCE, RETRAIN_BACKEND, etc.),
#      which are passed straight through.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIPELINE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PIPELINE_DIR/../.." && pwd)"

BUCKET="${TID_BACKUP_BUCKET:-tid-recon-dog-backups-275573051415}"
REGION="${AWS_REGION:-us-east-1}"
NODES="${TID_NODES:-jump-host camera-nvr backup field-gw mail-relay ops-db plc}"
FLEET_RUNTIME_DIR="${FLEET_RUNTIME_DIR:-$REPO_ROOT/runtime-fleet}"
MERGED="$FLEET_RUNTIME_DIR/transcripts.jsonl"

command -v aws >/dev/null 2>&1 || { echo "ERROR: aws CLI not found on PATH." >&2; exit 1; }
if ! aws sts get-caller-identity --region "$REGION" >/dev/null 2>&1; then
  echo "ERROR: AWS credentials not configured / not valid (aws sts get-caller-identity failed)." >&2
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$FLEET_RUNTIME_DIR"

# --- Optional: force a fresh backup on every node before pulling --------------
# Nodes push to S3 only daily, so without this the newest S3 snapshot can be up
# to 24h stale. FRESH runs each node's tid-backup.sh via SSM and waits for it.
if [ "${FRESH:-1}" = "1" ]; then
  prefix="${TID_NAME_PREFIX:-tid-recon-dog-}"
  echo "[fresh] resolving running nodes tagged Name=$prefix*"
  ids="$(aws ec2 describe-instances --region "$REGION" \
          --filters "Name=tag:Name,Values=${prefix}*" "Name=instance-state-name,Values=running" \
          --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null)"
  if [ -z "$ids" ]; then
    echo "[fresh] no running nodes found — falling back to existing S3 snapshots."
  else
    echo "[fresh] triggering tid-backup.sh on: $ids"
    cmd="$(aws ssm send-command --region "$REGION" \
            --instance-ids $ids \
            --document-name AWS-RunShellScript \
            --parameters 'commands=["/usr/local/bin/tid-backup.sh"]' \
            --query Command.CommandId --output text 2>/dev/null)"
    if [ -n "$cmd" ]; then
      want="$(echo "$ids" | wc -w | tr -d ' ')"
      echo "[fresh] waiting for backups to finish (command $cmd)…"
      for _ in $(seq 1 30); do
        done_n="$(aws ssm list-command-invocations --region "$REGION" --command-id "$cmd" \
                  --query "length(CommandInvocations[?Status=='Success' || Status=='Failed' || Status=='TimedOut'])" \
                  --output text 2>/dev/null || echo 0)"
        [ "$done_n" = "$want" ] && break
        sleep 5
      done
      echo "[fresh] backups complete."
    else
      echo "[fresh] could not send SSM backup command — falling back to existing S3 snapshots."
    fi
  fi
fi

echo "[sync] bucket=s3://$BUCKET region=$REGION"
: > "$TMP/merged.jsonl"
pulled=0
for node in $NODES; do
  # Latest timestamp prefix for this node (prefixes sort lexically = chronologically).
  latest="$(aws s3 ls "s3://$BUCKET/nodes/$node/" --region "$REGION" 2>/dev/null \
            | awk '/PRE/ {print $2}' | sort | tail -1)"
  if [ -z "$latest" ]; then
    echo "[sync] $node: no backups yet — skipping"
    continue
  fi
  key="s3://$BUCKET/nodes/$node/${latest}opt_tid-runtime.tgz"
  if ! aws s3 cp "$key" "$TMP/$node.tgz" --region "$REGION" >/dev/null 2>&1; then
    echo "[sync] $node: could not download ${latest}opt_tid-runtime.tgz — skipping"
    continue
  fi
  mkdir -p "$TMP/$node"
  tar xzf "$TMP/$node.tgz" -C "$TMP/$node" 2>/dev/null || true
  src="$TMP/$node/transcripts.jsonl"
  if [ -s "$src" ]; then
    lines="$(wc -l < "$src" | tr -d ' ')"
    cat "$src" >> "$TMP/merged.jsonl"
    echo "[sync] $node: ${latest%/} — $lines transcripts"
    pulled=$((pulled + 1))
  else
    echo "[sync] $node: backup had no transcripts.jsonl — skipping"
  fi
done

if [ "$pulled" -eq 0 ]; then
  echo "[sync] no transcripts pulled from any node; leaving $MERGED untouched and exiting." >&2
  exit 1
fi

total="$(wc -l < "$TMP/merged.jsonl" | tr -d ' ')"
mv "$TMP/merged.jsonl" "$MERGED"
echo "[sync] merged $total transcripts from $pulled node(s) -> $MERGED"

# Quarantine training-poisoning attempts before anything reaches the trainer.
# The transcripts are attacker-controlled; a crafted source could otherwise
# teach the model to break character. POISON_DISABLE=1 skips this.
PY="${TRAINER_PYTHON:-$PIPELINE_DIR/.venv-train/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3 || echo python3)"
"$PY" "$SCRIPT_DIR/filter_poison.py" "$MERGED" \
  --quarantine "$FLEET_RUNTIME_DIR/poison-quarantine.jsonl" \
  --stats "$FLEET_RUNTIME_DIR/poison-stats.json" || \
  echo "[poison] filter errored — continuing with unfiltered data" >&2

if [ "${SYNC_ONLY:-0}" = "1" ]; then
  echo "[sync] SYNC_ONLY=1 — done (skipping retrain)."
  exit 0
fi

echo "[sync] handing off to auto_retrain.sh (RUNTIME_DIR=$FLEET_RUNTIME_DIR)"
RUNTIME_DIR="$FLEET_RUNTIME_DIR" exec "$SCRIPT_DIR/auto_retrain.sh"
