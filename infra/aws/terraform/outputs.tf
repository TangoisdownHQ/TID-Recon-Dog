output "region" {
  value = var.region
}

# Every node's public IP + which persona/services it exposes. Point test traffic
# at any of these; each looks like a single specialized device.
output "fleet" {
  description = "Fleet nodes: persona -> { role, public_ip, instance_id, services }."
  value = merge(
    {
      (local.master_key) = {
        role        = "master"
        public_ip   = var.assign_eip ? aws_eip.master[0].public_ip : aws_instance.master.public_ip
        private_ip  = aws_instance.master.private_ip
        instance_id = aws_instance.master.id
        services    = local.personas[local.master_key].services
      }
    },
    {
      for k, v in local.node_personas : k => {
        role        = "node"
        public_ip   = var.assign_eip ? aws_eip.node[k].public_ip : aws_instance.node[k].public_ip
        private_ip  = aws_instance.node[k].private_ip
        instance_id = aws_instance.node[k].id
        services    = v.services
      }
    }
  )
}

output "operator_token" {
  description = "Operator/fleet auth token (append ?token=... to the console URL)."
  value       = local.operator_token
  sensitive   = true
}

output "ecr_repository_url" {
  description = "Push the image here before/after apply."
  value       = aws_ecr_repository.app.repository_url
}

output "push_commands" {
  description = "Build and push the honeypot image to ECR."
  value       = <<-EOT
    aws ecr get-login-password --region ${var.region} | docker login --username AWS --password-stdin ${local.registry}
    docker build --network=host -t ${aws_ecr_repository.app.repository_url}:${var.image_tag} .
    docker push ${aws_ecr_repository.app.repository_url}:${var.image_tag}
  EOT
}

output "operator_console" {
  description = "Tunnel the aggregating operator GUI (master's 9090) to your laptop via SSM."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.master.id} --document-name AWS-StartPortForwardingSession --parameters '{\"portNumber\":[\"9090\"],\"localPortNumber\":[\"9090\"]}'"
}

output "ssm_sessions" {
  description = "Open an admin shell on any node (no SSH port needed)."
  value = merge(
    { (local.master_key) = "aws ssm start-session --region ${var.region} --target ${aws_instance.master.id}" },
    { for k, v in local.node_personas : k => "aws ssm start-session --region ${var.region} --target ${aws_instance.node[k].id}" }
  )
}
