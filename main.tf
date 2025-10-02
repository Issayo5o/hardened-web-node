terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
    random = { source = "hashicorp/random", version = "~> 3.0" }
    archive = { source = "hashicorp/archive", version = "~> 2.0" }
  }
}

provider "aws" {
  region = var.region
}

# ------------------ Networking: locked-down security group ------------------
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

resource "aws_security_group" "web_sg" {
  name        = "${var.project}-sg"
  description = "Strict SG: HTTP only, all egress"
  vpc_id      = data.aws_vpc.default.id

  # Public web traffic (HTTP). Add HTTPS later if you attach a cert/ALB.
  ingress {
    description = "Public HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # No SSH exposed. Administration via SSM Session Manager.
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Project = var.project }
}

# ------------------ IAM: least-privilege instance role ------------------
data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "instance_role" {
  name               = "${var.project}-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = { Project = var.project }
}

# Attach SSM core (for Session Manager) and CW agent policies
resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}
resource "aws_iam_role_policy_attachment" "cw_agent" {
  role       = aws_iam_role.instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "instance_profile" {
  name = "${var.project}-instance-profile"
  role = aws_iam_role.instance_role.name
}

# ------------------ AMI ------------------
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["137112412989"] # Amazon
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# ------------------ User data (hardening + web stack) ------------------
locals {
  cloud_init = <<-EOT
    #!/bin/bash
    set -euxo pipefail

    # 1) System updates & auto security updates
    dnf -y update
    dnf -y install dnf-automatic docker nginx amazon-cloudwatch-agent jq

    # Enable unattended security updates
    sed -i 's/^apply_updates = no/apply_updates = yes/' /etc/dnf/automatic.conf
    systemctl enable --now dnf-automatic.timer

    # 2) Enable & configure Docker
    systemctl enable --now docker
    usermod -aG docker ec2-user || true

    # 3) Minimal containerized app (returns JSON with instance metadata)
    cat >/usr/local/bin/run_app.sh <<'APP'
    #!/bin/bash
    set -e
    docker rm -f whoami || true
    docker run -d --name whoami --restart always -p 127.0.0.1:8080:80 \
      containous/whoami
    APP
    chmod +x /usr/local/bin/run_app.sh
    /usr/local/bin/run_app.sh

    # 4) Nginx as reverse proxy + basic hardening headers
    cat >/etc/nginx/conf.d/web.conf <<'NGINX'
    server {
      listen 80 default_server;
      server_name _;

      # Security headers
      add_header X-Content-Type-Options nosniff;
      add_header X-Frame-Options DENY;
      add_header X-XSS-Protection "1; mode=block";
      add_header Referrer-Policy "no-referrer-when-downgrade";

      location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
      }

      location = /healthz {
        return 200 'ok';
        add_header Content-Type text/plain;
      }
    }
    NGINX

    # Harden default Nginx a bit
    sed -i 's/# server_tokens off;/server_tokens off;/' /etc/nginx/nginx.conf || true

    systemctl enable --now nginx

    # 5) CloudWatch Agent (basic CPU/mem/NGINX access log)
    cat >/opt/aws/amazon-cloudwatch-agent/bin/config.json <<'CW'
    {
      "metrics": {
        "append_dimensions": { "InstanceId": "$${aws:InstanceId}" },
        "aggregation_dimensions": [["InstanceId"]],
        "metrics_collected": {
          "mem": { "measurement": ["mem_used_percent"], "metrics_collection_interval": 60 },
          "cpu": { "measurement": ["cpu_usage_idle", "cpu_usage_user", "cpu_usage_system"], "metrics_collection_interval": 60, "totalcpu": true },
          "disk": { "measurement": ["used_percent"], "resources": ["*"], "metrics_collection_interval": 60 }
        }
      },
      "logs": {
        "logs_collected": {
          "files": {
            "collect_list": [
              { "file_path": "/var/log/nginx/access.log", "log_group_name": "${var.project}-nginx", "log_stream_name": "{instance_id}-access" },
              { "file_path": "/var/log/nginx/error.log",  "log_group_name": "${var.project}-nginx", "log_stream_name": "{instance_id}-error"  }
            ]
          }
        }
      }
    }
    CW

    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
      -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s

    # 6) SSM agent enabled by default on AL2023
    systemctl enable --now amazon-ssm-agent

    # 7) Minimal banner
    echo "Managed by Terraform • ${var.project}" >/etc/motd
  EOT
}

# ------------------ EC2 Instance ------------------
resource "aws_instance" "web" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  subnet_id                   = data.aws_subnets.default.ids[0]
  vpc_security_group_ids      = [aws_security_group.web_sg.id]
  associate_public_ip_address = true

  iam_instance_profile = aws_iam_instance_profile.instance_profile.name
  user_data            = local.cloud_init

  tags = {
    Name    = "${var.project}-node"
    Project = var.project
  }
}

# ------------------ CloudWatch Alarm ------------------
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "${var.project}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 70
  dimensions = {
    InstanceId = aws_instance.web.id
  }
  alarm_description = "CPU > 70% (avg over 2 min) on ${var.project}"
}

# Random suffix (optional if you later add buckets or names needing uniqueness)
resource "random_id" "suffix" {
  byte_length = 2
}
