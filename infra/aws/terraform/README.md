# AWS deploy — Phase 1 (single EC2 honeypot)

Terraform that stands up the honeypot on one EC2 instance with the image in ECR.
This is the rehearsal for the eventual EKS deployment (which reuses the same ECR
image + the `k8s/` manifests).

What it creates: an ECR repo, an EC2 instance (Amazon Linux 2023) running the
honeypot via Docker on **real well-known ports**, a security group exposing only
the decoy ports, and an IAM role for **SSM** (admin access with no inbound SSH).

## Prerequisites

- AWS account + credentials configured (`aws configure` / SSO).
- Terraform ≥ 1.5, AWS CLI v2, Docker — all already on this machine.
- The [Session Manager plugin](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html)
  for the AWS CLI (for `aws ssm start-session`).

## Steps

```sh
cd infra/aws/terraform
terraform init

# Lock admin SSH to your IP (primary access is SSM anyway):
export TF_VAR_admin_cidr="$(curl -s https://checkip.amazonaws.com)/32"

# 1) Create the ECR repo first so we can push the image.
terraform apply -target=aws_ecr_repository.app

# 2) Build + push the image (from repo root).
cd ../../../ && bash infra/aws/terraform/build-and-push.sh

# 3) Create the rest (instance, SG, IAM, EIP). It pulls the image within ~60s.
cd infra/aws/terraform && terraform apply

terraform output public_ip            # point test traffic here
```

## Access (no public admin port)

```sh
# admin shell
eval "$(terraform output -raw ssm_session)"

# operator GUI tunneled to your laptop, then open http://127.0.0.1:9090/?token=...
eval "$(terraform output -raw operator_port_forward)"
# get the auto-generated token from the container:
#   (in the SSM shell) docker logs $(docker ps -q) | grep 'Operator console token'
```

## Test it

```sh
nmap -sV -p 22,80,21,5432,3389,23,502,25 $(terraform output -raw public_ip)
curl http://$(terraform output -raw public_ip)/adminer.php
```

## Update the image later

```sh
bash infra/aws/terraform/build-and-push.sh   # instance auto-pulls within 60s
```

## Tear down (stop paying)

```sh
terraform destroy
```

## Notes

- **ToS:** confirm your account/region usage permits honeypots before exposing it.
- **Realism:** one box exposing all services is a structural tell — see
  `docs/HARDENING.md`. For production, split personas across instances/IPs.
- **Cost:** `t3.small` + EIP is a few dollars/month; `terraform destroy` between
  test runs keeps it near zero.
- **EKS (Phase 2):** same ECR image, `kubectl apply -k k8s/` + the Cilium and
  retrain manifests. EKS Terraform can live alongside this later.
