# AI model host (optional, GPU) — Path C

A **separate, independent** GPU stack that serves your fine-tuned model (base +
LoRA adapter) over an OpenAI-compatible API, reachable **only** by the honeypot.
Deploy/destroy or stop/start it on demand — the honeypot runs fine without it
(it falls back to deterministic), so this is the "AI portion" you can add or
remove at will.

```
honeypot (t3.small, always on)  ──private VPC──>  model host (g5.xlarge, on demand)
        AI_MODEL_URL ────────────────────────────> http://<fixed-ip>:11434/v1/chat/completions
   GPU up  -> shadow/AI modes work        GPU down -> graceful deterministic fallback
```

## One-time setup

```sh
cd infra/aws/model
terraform init

# bucket name must be globally unique; pick a free private IP in your default
# subnet range (check: aws ec2 describe-subnets) so AI_MODEL_URL stays stable.
export TF_VAR_model_bucket="tid-models-$(aws sts get-caller-identity --query Account --output text)"
export TF_VAR_model_private_ip="172.31.80.80"   # adjust to your subnet

# 1. create the bucket first, then upload the GGUFs
terraform apply -target=aws_s3_bucket.models
cd ../../../ && aws s3 cp mlops/Qwen3-4B-Base-Q8.gguf  s3://$TF_VAR_model_bucket/Qwen3-4B-Base-Q8.gguf
              aws s3 cp mlops/honeypot-lora.gguf       s3://$TF_VAR_model_bucket/honeypot-lora.gguf

# 2. launch the GPU host (it pulls the GGUFs + loads the model on boot, ~5-10 min)
cd infra/aws/model && terraform apply
terraform output ai_model_url     # set this on the honeypot
```

Point the honeypot at it (Terraform var on the honeypot stack):
```sh
cd ../terraform && terraform apply -var "ai_model_url=$(cd ../model && terraform output -raw ai_model_url)"
```
Then in the operator GUI set Engine Mode → **shadow** (review) → **ai** (serve).

## Toggle AI between sessions (your 3–5 day pattern)

Stop/start keeps the fixed private IP, so AI_MODEL_URL never changes:
```sh
aws ec2 stop-instances  --region us-east-1 --instance-ids $(terraform output -raw instance_id)   # AI OFF, GPU billing stops
aws ec2 start-instances --region us-east-1 --instance-ids $(terraform output -raw instance_id)   # AI ON  (model reloads ~1-2 min)
```
While stopped you pay only for the EBS volume (~a few $/mo), not the ~$1/hr GPU.
Fully remove it: `terraform destroy` (honeypot is unaffected).

## Notes
- The model serves **base + your LoRA adapter** (`honeypot-lora.gguf`). Set
  `adapter_gguf_key=""` to serve the base only.
- Inference port is never public — the security group allows it only from the
  honeypot's SG. Admin via SSM (`aws ssm start-session`).
- If `terraform apply` can't find the AMI, adjust the `Deep Learning Base ... AMI`
  name filter in `main.tf` for your region.
