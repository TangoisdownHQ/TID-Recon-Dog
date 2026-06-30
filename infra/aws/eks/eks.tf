module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"

  cluster_name    = var.cluster_name
  cluster_version = var.cluster_version

  cluster_endpoint_public_access       = true
  cluster_endpoint_public_access_cidrs = var.cluster_public_access_cidrs

  # The identity running `terraform apply` becomes cluster admin (so you can
  # kubectl immediately after).
  enable_cluster_creator_admin_permissions = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  cluster_addons = {
    coredns    = {}
    kube-proxy = {}
    # Enable the VPC CNI's built-in NetworkPolicy enforcement so the existing
    # k8s/base/networkpolicy.yaml (operator-plane isolation) is enforced without
    # installing Cilium. before_compute so it's ready before nodes join.
    vpc-cni = {
      before_compute = true
      configuration_values = jsonencode({
        enableNetworkPolicy = "true"
      })
    }
    aws-ebs-csi-driver = {
      service_account_role_arn = module.ebs_csi_irsa.iam_role_arn
    }
  }

  eks_managed_node_groups = merge(
    {
      default = {
        instance_types = [var.node_instance_type]
        min_size       = var.node_min_size
        max_size       = var.node_max_size
        desired_size   = var.node_desired_size
      }
    },
    var.enable_gpu_nodes ? {
      gpu = {
        instance_types = [var.gpu_instance_type]
        ami_type       = "AL2_x86_64_GPU"
        min_size       = 0
        max_size       = 1
        desired_size   = 1
        # Keep general workloads off the pricey GPU box; the retrain CronJob
        # tolerates this taint (see k8s/mlops/cronjob.yaml).
        taints = {
          gpu = {
            key    = "nvidia.com/gpu"
            value  = "true"
            effect = "NO_SCHEDULE"
          }
        }
      }
    } : {}
  )
}

# IRSA role the EBS CSI driver assumes to manage gp3 volumes (for the PVC).
module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.0"

  role_name             = "${var.cluster_name}-ebs-csi"
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}
