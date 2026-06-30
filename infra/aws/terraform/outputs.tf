output "region" {
  value = var.region
}

output "public_ip" {
  description = "Public IP of the honeypot (point your test traffic here)."
  value       = var.assign_eip ? aws_eip.honeypot[0].public_ip : aws_instance.honeypot.public_ip
}

output "instance_id" {
  value = aws_instance.honeypot.id
}

output "ecr_repository_url" {
  description = "Push the image here before/after apply."
  value       = aws_ecr_repository.app.repository_url
}

output "push_commands" {
  description = "Build and push the honeypot image to ECR."
  value       = <<-EOT
    aws ecr get-login-password --region ${var.region} | docker login --username AWS --password-stdin ${local.registry}
    docker build -t ${aws_ecr_repository.app.repository_url}:${var.image_tag} .
    docker push ${aws_ecr_repository.app.repository_url}:${var.image_tag}
  EOT
}

output "ssm_session" {
  description = "Open an admin shell (no SSH port needed)."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.honeypot.id}"
}

output "operator_port_forward" {
  description = "Tunnel the operator GUI (9090) to your laptop via SSM."
  value       = "aws ssm start-session --region ${var.region} --target ${aws_instance.honeypot.id} --document-name AWS-StartPortForwardingSession --parameters '{\"portNumber\":[\"9090\"],\"localPortNumber\":[\"9090\"]}'"
}
