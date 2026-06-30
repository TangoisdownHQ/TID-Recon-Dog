output "region" {
  value = var.region
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "cluster_endpoint" {
  value = module.eks.cluster_endpoint
}

output "ecr_repository_url" {
  description = "Push the honeypot image here; set it as the kustomize image."
  value       = aws_ecr_repository.app.repository_url
}

output "configure_kubectl" {
  description = "Point kubectl at the new cluster."
  value       = "aws eks update-kubeconfig --region ${var.region} --name ${module.eks.cluster_name}"
}

output "deploy_app" {
  description = "After kubeconfig: build/push image, set it, and deploy the manifests."
  value       = <<-EOT
    # 1. build + push image
    aws ecr get-login-password --region ${var.region} | docker login --username AWS --password-stdin ${split("/", aws_ecr_repository.app.repository_url)[0]}
    docker build -t ${aws_ecr_repository.app.repository_url}:latest . && docker push ${aws_ecr_repository.app.repository_url}:latest

    # 2. point the manifests at the ECR image
    cd k8s/base && kustomize edit set image tid-recon-dog=${aws_ecr_repository.app.repository_url}:latest && cd -

    # 3. operator token + deploy (external overlay = public LoadBalancers)
    kubectl create namespace tid-recon-dog
    kubectl -n tid-recon-dog create secret generic tid-secrets --from-literal=OPERATOR_TOKEN="$(openssl rand -hex 24)"
    kubectl apply -k k8s/overlays/external
  EOT
}
