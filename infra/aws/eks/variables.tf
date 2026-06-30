variable "region" {
  description = "AWS region."
  type        = string
  default     = "us-east-1"
}

variable "cluster_name" {
  description = "EKS cluster name."
  type        = string
  default     = "tid-recon-dog"
}

variable "cluster_version" {
  description = "EKS Kubernetes version."
  type        = string
  default     = "1.31"
}

variable "vpc_cidr" {
  description = "CIDR for the cluster VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "node_instance_type" {
  description = "Instance type for the general (honeypot) node group."
  type        = string
  default     = "t3.large"
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "node_min_size" {
  type    = number
  default = 1
}

variable "node_max_size" {
  type    = number
  default = 3
}

variable "enable_gpu_nodes" {
  description = "Create a GPU node group for the MLOps retrain CronJob (expensive — off by default)."
  type        = bool
  default     = false
}

variable "gpu_instance_type" {
  description = "GPU instance type for the retrain node group."
  type        = string
  default     = "g5.xlarge"
}

variable "cluster_public_access_cidrs" {
  description = "CIDRs allowed to reach the EKS API. Restrict to your IP in production."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "image_repo_name" {
  description = "ECR repo name for the honeypot image (shared with the EC2/Phase-1 deploy)."
  type        = string
  default     = "tid-recon-dog"
}
