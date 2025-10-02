output "public_ip" {
  description = "EC2 public IP"
  value       = aws_instance.web.public_ip
}

output "web_url" {
  description = "HTTP URL (reverse-proxied container)"
  value       = "http://${aws_instance.web.public_dns}"
}

output "ssm_how_to_connect" {
  value = <<EOT
Admin access is via Session Manager (no SSH port open):
1) In AWS Console > Systems Manager > Fleet Manager, select the instance '${aws_instance.web.id}'.
2) Click 'Connect' -> 'Session Manager' to open a shell.

Or with AWS CLI:
aws ssm start-session --target ${aws_instance.web.id}
EOT
}
