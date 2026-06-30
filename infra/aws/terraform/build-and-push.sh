#!/usr/bin/env bash
# Build the honeypot image and push it to the ECR repo created by Terraform.
# Run from the repo root after `terraform apply` (or after a targeted ECR apply).
set -euo pipefail

TF_DIR="infra/aws/terraform"
REGION="$(terraform -chdir="$TF_DIR" output -raw region 2>/dev/null || echo us-east-1)"
REPO="$(terraform -chdir="$TF_DIR" output -raw ecr_repository_url)"
TAG="${1:-latest}"
REGISTRY="${REPO%/*}"

echo "Logging in to $REGISTRY ..."
aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$REGISTRY"

echo "Building $REPO:$TAG ..."
docker build -t "$REPO:$TAG" .

echo "Pushing ..."
docker push "$REPO:$TAG"
echo "Done. The instance pulls it within ~60s (systemd tid.timer)."
