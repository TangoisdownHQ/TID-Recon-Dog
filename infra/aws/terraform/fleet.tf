# ---------------------------------------------------------------------------
# Fleet: one specialized honeypot per persona.
#
# The strongest honeypot tell is structural — a single IP exposing 10 unrelated
# services (camera + Postgres + Modbus + SSH + RDP + SMTP ...) is obviously not a
# real host. Here each node exposes ONLY the ports its device type would, gets its
# own public IP and a minimal security group, and self-reports to a master
# operator plane so one console watches the whole fleet (Fleet tab).
#
# Nodes are just the same image started with a subset of services
# (`start <services>`); the master aggregates fleet reports on 9090 (reachable
# only within the VPC via the shared fleet SG, never from the internet).
# ---------------------------------------------------------------------------

locals {
  # service tokens map to the app's `start <services>` CLI. tcp = host->container.
  personas = {
    camera-nvr = {
      services = "http rtsp"
      region   = "camera / NVR edge"
      tcp      = [{ host = 80, container = 3000 }, { host = 554, container = 8554 }]
      snmp     = false
    }
    ops-db = {
      services = "postgres"
      region   = "operations DB"
      tcp      = [{ host = 5432, container = 5432 }]
      snmp     = false
    }
    plc = {
      services = "modbus snmp"
      region   = "PLC / ICS controller"
      tcp      = [{ host = 502, container = 1502 }]
      snmp     = true
    }
    jump-host = {
      services = "ssh rdp"
      region   = "jump / bastion"
      tcp      = [{ host = 22, container = 2222 }, { host = 3389, container = 3389 }]
      snmp     = false
    }
    mail-relay = {
      services = "smtp"
      region   = "mail relay"
      tcp      = [{ host = 25, container = 2525 }]
      snmp     = false
    }
    backup = {
      services = "ftp"
      region   = "backup server"
      tcp      = [{ host = 21, container = 2121 }]
      snmp     = false
    }
    field-gw = {
      services = "telnet"
      region   = "field gateway"
      tcp      = [{ host = 23, container = 2323 }]
      snmp     = false
    }
  }

  master_key = var.master_persona
  # Non-master personas run as `aws_instance.node`. The master is a separate
  # resource so nodes can reference its private IP without a for_each self-cycle.
  node_personas = { for k, v in local.personas : k => v if k != local.master_key }

  operator_token = var.operator_token != "" ? var.operator_token : random_password.operator_token.result
  backup_bucket  = var.backup_bucket != "" ? var.backup_bucket : "${var.name}-backups-${data.aws_caller_identity.me.account_id}"

  # Params common to every node's user_data.
  user_data_common = {
    region                 = var.region
    registry               = local.registry
    image_uri              = local.image_uri
    operator_token         = local.operator_token
    fleet_token            = local.operator_token
    ai_model_url           = var.ai_model_url
    ai_model               = var.ai_model
    threat_feeds           = var.threat_feeds
    threat_feeds_autoblock = var.threat_feeds_autoblock
    darkweb_feeds          = var.darkweb_feeds
    darkweb_news_feeds     = var.darkweb_news_feeds
    darkweb_proxy          = var.darkweb_proxy
  }
}

resource "random_password" "operator_token" {
  length  = 32
  special = false
}

# Let every fleet node read/write the backup bucket (daily S3 log backup + restore).
resource "aws_iam_role_policy" "backup" {
  name = "${var.name}-s3-backup"
  role = aws_iam_role.instance.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "TidBackup"
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
      Resource = ["arn:aws:s3:::${local.backup_bucket}", "arn:aws:s3:::${local.backup_bucket}/*"]
    }]
  })
}

# Fleet-internal SG: lets nodes reach the master's operator plane (9090). Not
# open to the internet — only members of this SG can talk 9090 to each other.
resource "aws_security_group" "fleet" {
  name        = "${var.name}-fleet"
  description = "Fleet-internal operator reporting (9090)"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "operator plane within fleet"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    self        = true
  }
  egress {
    description = "all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Per-persona SG: only that device type's ports open to the world.
resource "aws_security_group" "persona" {
  for_each    = local.personas
  name        = "${var.name}-${each.key}"
  description = "decoy surface for ${each.key}"
  vpc_id      = data.aws_vpc.default.id

  dynamic "ingress" {
    for_each = each.value.tcp
    content {
      description = "decoy tcp ${ingress.value.host}"
      from_port   = ingress.value.host
      to_port     = ingress.value.host
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "ingress" {
    for_each = each.value.snmp ? [1] : []
    content {
      description = "decoy snmp"
      from_port   = 161
      to_port     = 161
      protocol    = "udp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  ingress {
    description = "fallback admin ssh (primary access is SSM)"
    from_port   = 2200
    to_port     = 2200
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Master node: runs its persona AND hosts the aggregating operator plane.
resource "aws_instance" "master" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.master_instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.persona[local.master_key].id, aws_security_group.fleet.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  user_data = templatefile("${path.module}/user_data.sh.tftpl", merge(local.user_data_common, {
    services         = local.personas[local.master_key].services
    node_name        = local.master_key
    node_region      = local.personas[local.master_key].region
    ports_tcp        = local.personas[local.master_key].tcp
    udp_snmp         = local.personas[local.master_key].snmp
    node_ports       = join(",", concat([for p in local.personas[local.master_key].tcp : tostring(p.host)], local.personas[local.master_key].snmp ? ["161"] : []))
    backup_bucket    = local.backup_bucket
    fleet_master_url = ""          # master aggregates locally
    operator_publish = "9090:9090" # reachable by fleet (SG-restricted, not public)
  }))

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }
  metadata_options {
    http_tokens = "required" # IMDSv2 only
  }
  tags = { Name = "${var.name}-${local.master_key}", Role = "master", Persona = local.master_key }
}

# Persona nodes: each starts only its services and reports to the master.
resource "aws_instance" "node" {
  for_each               = local.node_personas
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.node_instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.persona[each.key].id, aws_security_group.fleet.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  user_data = templatefile("${path.module}/user_data.sh.tftpl", merge(local.user_data_common, {
    services         = each.value.services
    node_name        = each.key
    node_region      = each.value.region
    ports_tcp        = each.value.tcp
    udp_snmp         = each.value.snmp
    node_ports       = join(",", concat([for p in each.value.tcp : tostring(p.host)], each.value.snmp ? ["161"] : []))
    backup_bucket    = local.backup_bucket
    fleet_master_url = "http://${aws_instance.master.private_ip}:9090"
    operator_publish = "127.0.0.1:9090:9090" # localhost only on nodes
  }))

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }
  metadata_options {
    http_tokens = "required" # IMDSv2 only
  }
  tags = { Name = "${var.name}-${each.key}", Role = "node", Persona = each.key }
}

resource "aws_eip" "master" {
  count    = var.assign_eip ? 1 : 0
  instance = aws_instance.master.id
  domain   = "vpc"
  tags     = { Name = "${var.name}-${local.master_key}" }
}

resource "aws_eip" "node" {
  for_each = var.assign_eip ? local.node_personas : {}
  instance = aws_instance.node[each.key].id
  domain   = "vpc"
  tags     = { Name = "${var.name}-${each.key}" }
}
