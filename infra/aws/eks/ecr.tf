# Honeypot image registry. If you already created this in the Phase-1 (EC2)
# deploy, either point both at the same repo or `terraform destroy` Phase 1
# first — the repo name is shared via var.image_repo_name.
resource "aws_ecr_repository" "app" {
  name                 = var.image_repo_name
  image_tag_mutability = "MUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
}
