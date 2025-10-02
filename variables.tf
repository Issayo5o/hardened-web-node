variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "project" {
  description = "Project name tag/prefix"
  type        = string
  default     = "hardened-web-node"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro" # free/cheap; switch to t3.small if you need more headroom
}
