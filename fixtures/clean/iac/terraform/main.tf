resource "aws_security_group" "good" {
  name = "good"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_security_group" "egress" {
  name = "egress"
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "private" {
  bucket = "private-bucket"
  acl    = "private"
}

resource "aws_ebs_volume" "encrypted" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = true
}

provider "aws" {
  region   = "us-east-1"
  password = "${var.db_password}"
}

data "aws_iam_policy_document" "scoped" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::private-bucket/*"]
  }
}