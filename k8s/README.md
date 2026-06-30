# Kubernetes deployment

Kustomize-based manifests — deploy with plain `kubectl -k` (no Helm required).

```
k8s/
  base/                     # ClusterIP everything, safe to apply anywhere
    namespace.yaml
    configmap.yaml          # ports + behavioural env
    secret.example.yaml     # template — create the real secret out-of-band
    pvc.yaml                # persists runtime/ (attacker memory, transcripts)
    deployment.yaml         # single replica, non-root, read-only rootfs
    service-operator.yaml   # operator metrics plane — ClusterIP ONLY
    services-honeypot.yaml  # one Service per protocol, real-port -> container-port
    networkpolicy.yaml      # decoy ports open; operator port in-cluster only
    servicemonitor.yaml     # OPTIONAL Prometheus Operator scrape (apply separately)
  overlays/
    external/               # base + public LoadBalancer edge (real external exposure)
```

## 1. Build and load the image

```sh
docker build -t tid-recon-dog:latest .
# push to your registry, or load into a local cluster:
kind load docker-image tid-recon-dog:latest        # kind
minikube image load tid-recon-dog:latest           # minikube
```

Point the manifests at your image:

```sh
cd k8s/base && kustomize edit set image tid-recon-dog=YOUR_REGISTRY/tid-recon-dog:TAG
```

## 2. Create the operator token secret

The example secret is intentionally excluded from kustomize so no placeholder
token reaches a cluster. Create the real one:

```sh
kubectl create namespace tid-recon-dog
kubectl -n tid-recon-dog create secret generic tid-secrets \
  --from-literal=OPERATOR_TOKEN="$(openssl rand -hex 24)"
# optional alerting:
#   --from-literal=ALERT_WEBHOOK_URL="https://..."
```

## 3. Deploy

Internal/ClusterIP only (dev, or behind your own ingress):

```sh
kubectl apply -k k8s/base
```

Public exposure (cloud LoadBalancer on real well-known ports):

```sh
kubectl apply -k k8s/overlays/external
kubectl -n tid-recon-dog get svc tid-edge -w     # wait for EXTERNAL-IP
```

## 4. Reach the operator dashboard (never exposed publicly)

```sh
kubectl -n tid-recon-dog port-forward svc/tid-operator 9090:9090
TOKEN=$(kubectl -n tid-recon-dog get secret tid-secrets -o jsonpath='{.data.OPERATOR_TOKEN}' | base64 -d)
open "http://127.0.0.1:9090/?token=$TOKEN"
```

## Enforcing the NetworkPolicy with Cilium

kindnet ignores NetworkPolicy, so to actually enforce the operator-plane
isolation, run the cluster on Cilium (files in `k8s/cilium/`):

```sh
# 1. cluster with the default CNI disabled
kind create cluster --name tid --config k8s/cilium/kind-cluster.yaml

# 2. install Cilium
helm repo add cilium https://helm.cilium.io/ && helm repo update
helm install cilium cilium/cilium --version 1.19.4 \
  --namespace kube-system -f k8s/cilium/values.yaml
kubectl -n kube-system rollout status ds/cilium

# 3. deploy as usual — the standard NetworkPolicy is now enforced
kubectl -n tid-recon-dog create secret generic tid-secrets \
  --from-literal=OPERATOR_TOKEN="$(openssl rand -hex 24)"
kubectl apply -k k8s/base
```

Cilium enforces the standard `networkpolicy.yaml` natively — no CRD needed. An
optional `k8s/cilium/ciliumnetworkpolicy.yaml` (Cilium-native equivalent) is
provided if you'd rather use CRDs / extend with L7 rules.

Verified behavior under Cilium (drops show as `Policy denied` in
`cilium monitor --type drop`):

| Source | → decoy :80 | → operator :9090 |
|--------|-------------|------------------|
| pod in another namespace | allowed | **dropped** |
| pod in `tid-recon-dog` (or `tid-monitoring=true`) ns | allowed | allowed |
| `kubectl port-forward` (host) | n/a | allowed |

## Design notes

- **Operator plane isolation.** `tid-operator` is `ClusterIP` and has no external
  Service in any overlay — the dashboard/API cannot be reached from the internet,
  so the deployment can't be fingerprinted as a honeypot through the operator UI.
  `networkpolicy.yaml` adds in-cluster-only enforcement on port 9090, which
  requires a policy-enforcing CNI. kind's default kindnet does NOT enforce it —
  install **Cilium** (see below). `port-forward` to the operator keeps working
  under Cilium (host→pod is allowed), so operator access is unaffected.
- **Real-port illusion.** Services map well-known ports (22, 80, 5432, …) onto the
  container's unprivileged high ports, so scanners see genuine-looking services
  while the container needs no privileged-port capabilities and runs as non-root.
- **Single replica.** Attacker memory is a file-backed single-writer store on a
  ReadWriteOnce PVC, so `replicas: 1` + `Recreate`. Do not scale horizontally
  without first moving state to a shared backend.
- **Probes & metrics.** `/healthz` + `/readyz` (unauthenticated) drive liveness/
  readiness; `/metrics` (Prometheus) is scraped via pod annotations or the
  optional ServiceMonitor.
```
