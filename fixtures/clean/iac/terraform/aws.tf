resource "aws_security_group_rule" "https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.web.id
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  publicly_accessible = false
  storage_encrypted   = true
  password            = var.db_password
}

resource "aws_elasticache_replication_group" "cache" {
  replication_group_id       = "cache"
  transit_encryption_enabled = true
}

data "aws_iam_policy_document" "deploy" {
  statement {
    actions   = ["iam:PassRole"]
    resources = [aws_iam_role.task.arn]
  }
  statement {
    actions   = ["ec2:DescribeInstances"]
    resources = ["arn:aws:ec2:us-east-1:111122223333:instance/*"]
  }
}

resource "aws_iam_role_policy_attachment" "read" {
  role       = aws_iam_role.ci.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_kms_key" "data" {
  description         = "data key"
  enable_key_rotation = true
}

resource "aws_cloudtrail" "main" {
  name                       = "main"
  enable_logging             = true
  enable_log_file_validation = true
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.web.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

resource "aws_cloudfront_distribution" "site" {
  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
  }
  viewer_certificate {
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

resource "aws_instance" "web" {
  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_lambda_function" "worker" {
  function_name = "worker"
  environment {
    variables = {
      STRIPE_API_KEY_ARN = aws_secretsmanager_secret.stripe.arn
      API_KEY            = var.api_key
      CLIENT_SECRET      = "${var.client_secret}"
    }
  }
}

# acl = "public-read" was removed; access goes through the bucket policy.
variable "db_password" {
  type      = string
  sensitive = true
}

data "aws_iam_policy_document" "ops" {
  statement {
    actions   = ["s3:GetObject", "s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/*"]
  }
}
