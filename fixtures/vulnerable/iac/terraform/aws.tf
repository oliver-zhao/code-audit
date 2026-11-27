resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  ipv6_cidr_blocks  = ["::/0"]
  security_group_id = aws_security_group.web.id
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket              = aws_s3_bucket.logs.id
  block_public_acls   = false
  block_public_policy = true
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_elasticache_replication_group" "cache" {
  replication_group_id       = "cache"
  transit_encryption_enabled = false
}

data "aws_iam_policy_document" "deploy" {
  statement {
    actions   = ["iam:PassRole"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.ci.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_kms_key" "data" {
  description         = "data key"
  enable_key_rotation = false
}

resource "aws_cloudtrail" "main" {
  name           = "main"
  enable_logging = false
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.web.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
}

resource "aws_cloudfront_distribution" "site" {
  default_cache_behavior {
    viewer_protocol_policy = "allow-all"
  }
  viewer_certificate {
    minimum_protocol_version = "TLSv1"
  }
}

resource "aws_instance" "web" {
  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_lambda_function" "worker" {
  function_name = "worker"
  environment {
    variables = {
      STRIPE_API_KEY = "sk_fake_51HxxFAKEFAKEFAKE"
    }
  }
}

variable "db_password" { default = "Wint3rIsC0ming!" }

data "aws_iam_policy_document" "ops" {
  statement {
    actions   = ["s3:*", "ec2:DescribeInstances"]
    resources = [aws_s3_bucket.logs.arn]
  }
}
