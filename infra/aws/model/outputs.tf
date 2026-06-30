output "region" { value = var.region }
output "instance_id" { value = aws_instance.model.id }
output "model_private_ip" { value = aws_instance.model.private_ip }
output "model_bucket" { value = aws_s3_bucket.models.bucket }

output "ai_model_url" {
  description = "Set this as AI_MODEL_URL on the honeypot."
  value       = "http://${aws_instance.model.private_ip}:${var.model_port}/v1/chat/completions"
}

output "upload_models" {
  description = "Upload the GGUFs to S3 (run from repo root) — instance pulls them on boot."
  value       = <<-EOT
    aws s3 cp mlops/${var.base_gguf_key} s3://${aws_s3_bucket.models.bucket}/${var.base_gguf_key} --region ${var.region}
    ${var.adapter_gguf_key != "" ? "aws s3 cp mlops/${var.adapter_gguf_key} s3://${aws_s3_bucket.models.bucket}/${var.adapter_gguf_key} --region ${var.region}" : "# (no adapter)"}
  EOT
}

output "start_stop" {
  description = "Toggle the GPU box between sessions (keeps the private IP)."
  value       = <<-EOT
    aws ec2 stop-instances  --region ${var.region} --instance-ids ${aws_instance.model.id}   # AI off (stops GPU billing)
    aws ec2 start-instances --region ${var.region} --instance-ids ${aws_instance.model.id}   # AI on
  EOT
}
