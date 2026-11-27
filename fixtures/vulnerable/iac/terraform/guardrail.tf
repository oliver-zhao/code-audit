data "aws_iam_policy_document" "mixed" {
  statement {
    effect    = "Deny"
    actions   = ["s3:DeleteBucket"]
    resources = ["*"]
  }
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
