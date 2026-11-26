resource "aws_security_group" "bad" {
  name = "bad"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public" {
  bucket = "public-bucket"
  acl    = "public-read"
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 10
  encrypted         = false
}

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAEXAMPLE12345"
  secret_key = "SuperSecretValue123"
}

data "aws_iam_policy_document" "wildcard" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}