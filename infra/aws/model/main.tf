data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Lock the model port to the honeypot's security group only (never public).
data "aws_security_group" "honeypot" {
  filter {
    name   = "group-name"
    values = [var.honeypot_sg_name]
  }
}

# Ubuntu GPU AMI with NVIDIA drivers + CUDA preinstalled (AWS Deep Learning Base).
data "aws_ami" "dlami" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Deep Learning Base OSS Nvidia Driver GPU AMI (Ubuntu 22.04)*"]
  }
  filter {
    name   = "architecture"
    values = ["x86_64"]
  }
}

resource "aws_s3_bucket" "models" {
  bucket        = var.model_bucket
  force_destroy = true
}

# --- IAM: SSM admin + read the model bucket ---------------------------------
data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "model" {
  name               = "${var.name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.model.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "s3_read" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.models.arn, "${aws_s3_bucket.models.arn}/*"]
  }
}

resource "aws_iam_role_policy" "s3_read" {
  name   = "${var.name}-s3-read"
  role   = aws_iam_role.model.id
  policy = data.aws_iam_policy_document.s3_read.json
}

resource "aws_iam_instance_profile" "model" {
  name = "${var.name}-profile"
  role = aws_iam_role.model.name
}

resource "aws_security_group" "model" {
  name        = "${var.name}-sg"
  description = "TID model host — inference port reachable only from the honeypot"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description     = "inference from honeypot only"
    from_port       = var.model_port
    to_port         = var.model_port
    protocol        = "tcp"
    security_groups = [data.aws_security_group.honeypot.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "model" {
  ami                    = data.aws_ami.dlami.id
  instance_type          = var.instance_type
  subnet_id              = data.aws_subnets.default.ids[0]
  private_ip             = var.model_private_ip != "" ? var.model_private_ip : null
  vpc_security_group_ids = [aws_security_group.model.id]
  iam_instance_profile   = aws_iam_instance_profile.model.name

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    bucket           = aws_s3_bucket.models.bucket
    base_gguf_key    = var.base_gguf_key
    adapter_gguf_key = var.adapter_gguf_key
    model_name       = var.model_name
    model_port       = var.model_port
    region           = var.region
  })

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = { Name = var.name }
}
