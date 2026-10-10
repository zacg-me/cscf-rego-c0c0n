resource "aws_s3_bucket" "probe" {
  bucket = "ckv70-probe"
}

data "aws_iam_policy_document" "open" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.probe.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "probe" {
  bucket = aws_s3_bucket.probe.id
  policy = data.aws_iam_policy_document.open.json
}
