variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type for the honeypot host."
  type        = string
  default     = "t3.small"
}

variable "name" {
  description = "Name prefix for created resources."
  type        = string
  default     = "tid-recon-dog"
}

# --- Optional AI portion -----------------------------------------------------
# Leave empty to deploy WITHOUT AI (deterministic only). Set to the model host's
# OpenAI-compatible endpoint (see infra/aws/model) to arm shadow/AI engine modes.
# Even when set, AI only activates while the model host is reachable.
variable "ai_model_url" {
  type    = string
  default = ""
}

variable "ai_model" {
  type    = string
  default = "honeypot-qwen"
}

variable "admin_cidr" {
  description = <<-EOT
    CIDR allowed to reach the fallback admin SSH port (2200). Primary admin
    access is AWS SSM Session Manager (no inbound port), so this can stay locked
    down. STRONGLY recommend setting this to YOUR.IP/32 — never leave 0.0.0.0/0.
  EOT
  type        = string
  default     = "127.0.0.1/32"
}

variable "assign_eip" {
  description = "Allocate a stable Elastic IP for the honeypot."
  type        = bool
  default     = true
}

variable "image_tag" {
  description = "ECR image tag the instance runs."
  type        = string
  default     = "latest"
}

variable "root_volume_gb" {
  description = "Root EBS volume size (GB)."
  type        = number
  default     = 20
}

# Decoy ports exposed to the internet (this is the honeypot's attack surface).
# host_port is what the world hits; the container listens on container_port.
variable "decoy_ports_tcp" {
  description = "TCP decoy port mappings (real well-known port -> container port)."
  type = list(object({
    host = number, container = number
  }))
  default = [
    { host = 22, container = 2222 },   # ssh
    { host = 80, container = 3000 },   # http
    { host = 21, container = 2121 },   # ftp
    { host = 5432, container = 5432 }, # postgres
    { host = 554, container = 8554 },  # rtsp
    { host = 3389, container = 3389 }, # rdp
    { host = 23, container = 2323 },   # telnet
    { host = 502, container = 1502 },  # modbus
    { host = 25, container = 2525 },   # smtp
  ]
}

# --- CTI / dark-web feeds ----------------------------------------------------
# All comma-separated lists of URLs, injected into the container's environment.
# Defaults point at reputable free/public sources so the CTI + Dark-web tabs
# populate out of the box; override per-deploy or set "" to disable a stream.

# IP blocklists ingested by "ingest feeds -> block" (plaintext IP-per-line).
variable "threat_feeds" {
  description = "Comma-separated IP-blocklist feed URLs (THREAT_FEEDS)."
  type        = string
  default     = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt,https://lists.blocklist.de/lists/all.txt,https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt"
}

# Feeds correlated against our own observed IOCs (IPs/usernames/URLs).
variable "darkweb_feeds" {
  description = "Comma-separated feeds for IOC correlation (DARKWEB_FEEDS)."
  type        = string
  default     = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt,https://urlhaus.abuse.ch/downloads/text/"
}

# Feeds surfaced as the dark-web news/event stream (JSON, RSS/Atom, or plaintext
# headlines). Defaults: ransomware leak-site tracker + security-news RSS.
variable "darkweb_news_feeds" {
  description = "Comma-separated news/event feed URLs (DARKWEB_NEWS_FEEDS)."
  type        = string
  default     = "https://api.ransomware.live/v1/recentvictims,https://www.bleepingcomputer.com/feed/,https://feeds.feedburner.com/TheHackersNews"
}

# Optional SOCKS proxy for .onion / anonymized fetch. Requires a reachable Tor
# proxy on the host; leave empty unless you run one. Use socks5h:// for .onion.
variable "darkweb_proxy" {
  description = "SOCKS proxy URL for dark-web fetch (DARKWEB_PROXY), e.g. socks5h://127.0.0.1:9050."
  type        = string
  default     = ""
}
