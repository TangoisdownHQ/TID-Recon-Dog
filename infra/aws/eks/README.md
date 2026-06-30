# AWS deploy — Phase 2 (EKS)

Production-shaped deployment: a real EKS cluster running the `k8s/` manifests.
Terraform provisions the **infrastructure** (VPC, EKS, node groups, addons, ECR);
the **app** deploys with `kubectl apply -k` (the manifests you already have).

Created by Terraform:
- VPC across 2 AZs (public + private subnets, single NAT).
- EKS cluster + a general managed node group (and an optional GPU node group).
- Addons: CoreDNS, kube-proxy, **VPC CNI with NetworkPolicy enforcement on**
  (so `k8s/base/networkpolicy.yaml` is enforced — no Cilium needed on EKS), and
  the EBS CSI driver (with IRSA) for the runtime PVC.
- An ECR repo for the image.

## Prerequisites

- AWS creds, Terraform ≥ 1.5, AWS CLI v2, `kubectl`, `kustomize`, Docker.
- This pulls the public `terraform-aws-modules` (VPC/EKS/IAM).

## Provision the cluster

```sh
cd infra/aws/eks
terraform init
# (recommended) restrict the API endpoint to your IP:
export TF_VAR_cluster_public_access_cidrs='["'"$(curl -s https://checkip.amazonaws.com)"'/32"]'
terraform apply            # ~15 min for EKS

terraform output configure_kubectl   # run the printed command
```

## Deploy the honeypot

`terraform output deploy_app` prints the exact commands. In short:

```sh
aws eks update-kubeconfig --region <region> --name tid-recon-dog
# build + push image to the ECR repo (terraform output ecr_repository_url)
# point manifests at it: kustomize edit set image tid-recon-dog=<ecr-url>:latest
kubectl create namespace tid-recon-dog
kubectl -n tid-recon-dog create secret generic tid-secrets --from-literal=OPERATOR_TOKEN="$(openssl rand -hex 24)"
kubectl apply -k k8s/overlays/external        # public LoadBalancers on real ports
kubectl -n tid-recon-dog get svc tid-edge -w  # wait for the external hostname
```

Operator GUI (never public): `kubectl -n tid-recon-dog port-forward svc/tid-operator 9090:9090`.

## MLOps retrain on EKS

Set `enable_gpu_nodes=true` to get a GPU node group, then deploy the CronJob:

```sh
terraform apply -var enable_gpu_nodes=true
# install the NVIDIA device plugin (one-time):
kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.16.2/deployments/static/nvidia-device-plugin.yml
kubectl apply -f k8s/mlops/cronjob.yaml        # needs the trainer image + shared transcript storage
```

> The CronJob needs a trainer image (pipeline + base model / S3 sync) and an
> RWX volume (EFS) for transcripts — see `k8s/mlops/cronjob.yaml` comments.

## Network policy on EKS

The VPC CNI addon is configured with `enableNetworkPolicy=true`, so the standard
NetworkPolicy is enforced natively — the operator plane (9090) stays in-cluster.
Prefer Cilium instead? The `k8s/cilium/` values work on EKS too; you'd disable
the VPC CNI NP feature and install Cilium in ENI/overlay mode.

## Cost & teardown

EKS control plane (~$0.10/h) + nodes + NAT + LBs. Not free — `terraform destroy`
when not testing. Delete the LoadBalancer Services first
(`kubectl delete -k k8s/overlays/external`) so the ELBs are removed before
`terraform destroy` tears down the VPC.
```
