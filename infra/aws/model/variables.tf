variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  type    = string
  default = "tid-model"
}

variable "instance_type" {
  description = "GPU instance. g5.xlarge = 1x A10G 24GB, ample for a 4B Q8 model."
  type        = string
  default     = "g5.xlarge"
}

variable "model_bucket" {
  description = "S3 bucket for the GGUF artifacts (must be globally unique)."
  type        = string
}

variable "base_gguf_key" {
  type    = string
  default = "Qwen3-4B-Base-Q8.gguf"
}

variable "adapter_gguf_key" {
  description = "Fine-tuned LoRA adapter GGUF (empty = serve base model only)."
  type        = string
  default     = "honeypot-lora.gguf"
}

variable "model_name" {
  description = "Name registered in Ollama / sent as the model id."
  type        = string
  default     = "honeypot-qwen"
}

variable "model_private_ip" {
  description = <<-EOT
    Fixed private IP for the model host so the honeypot's AI_MODEL_URL stays
    stable across stop/start. Pick a free address in your default-VPC subnet's
    range. Leave empty to let AWS assign one (then update AI_MODEL_URL each time).
  EOT
  type        = string
  default     = ""
}

variable "honeypot_sg_name" {
  description = "Security group name of the honeypot; only it may reach the model port."
  type        = string
  default     = "tid-recon-dog-sg"
}

variable "model_port" {
  type    = number
  default = 11434
}

variable "root_volume_gb" {
  description = "Root EBS — must hold the GGUFs + Ollama cache."
  type        = number
  default     = 60
}
