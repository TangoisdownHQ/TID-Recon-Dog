data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Latest Amazon Linux 2023 AMI via the public SSM parameter (no hardcoded IDs).
data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# --- ECR: where the honeypot image lives (EKS will reuse this repo) ----------
resource "aws_ecr_repository" "app" {
  name                 = var.name
  image_tag_mutability = "MUTABLE"
  force_delete         = true
  image_scanning_configuration {
    scan_on_push = true
  }
}

# --- IAM: instance role for SSM (admin access) + ECR pull --------------------
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance" {
  name               = "${var.name}-instance"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "ecr" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name}-instance"
  role = aws_iam_role.instance.name
}

# --- Security group: decoy ports open to the world; no admin SSH ingress -----
resource "aws_security_group" "honeypot" {
  name        = "${var.name}-sg"
  description = "TID-Recon-Dog decoy surface"
  vpc_id      = data.aws_vpc.default.id

  dynamic "ingress" {
    for_each = var.decoy_ports_tcp
    content {
      description = "decoy tcp ${ingress.value.host}"
      from_port   = ingress.value.host
      to_port     = ingress.value.host
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  ingress {
    description = "decoy snmp"
    from_port   = 161
    to_port     = 161
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
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

locals {
  registry  = "${data.aws_caller_identity.me.account_id}.dkr.ecr.${var.region}.amazonaws.com"
  image_uri = "${aws_ecr_repository.app.repository_url}:${var.image_tag}"
}

data "aws_caller_identity" "me" {}

resource "aws_instance" "honeypot" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    region             = var.region
    registry           = local.registry
    image_uri          = local.image_uri
    decoy_ports_tcp    = var.decoy_ports_tcp
    ai_model_url       = var.ai_model_url
    ai_model           = var.ai_model
    threat_feeds       = var.threat_feeds
    darkweb_feeds      = var.darkweb_feeds
    darkweb_news_feeds = var.darkweb_news_feeds
    darkweb_proxy      = var.darkweb_proxy
  })

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required" # IMDSv2 only
  }

  tags = { Name = var.name }
}

resource "aws_eip" "honeypot" {
  count    = var.assign_eip ? 1 : 0
  instance = aws_instance.honeypot.id
  domain   = "vpc"
}
