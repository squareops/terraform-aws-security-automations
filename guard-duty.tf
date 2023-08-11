data "aws_region" "current" {}

data "aws_iam_policy_document" "bucket_pol" {
  count = var.enable_guard_duty ? 1 : 0
  statement {
    sid = "Allow PutObject"
    actions = [
      "s3:PutObject"
    ]

    resources = [
      "${aws_s3_bucket.gd_bucket[0].arn}/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid = "Allow GetBucketLocation"
    actions = [
      "s3:GetBucketLocation"
    ]

    resources = [
      aws_s3_bucket.gd_bucket[0].arn
    ]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "kms_pol" {
  count = var.enable_guard_duty ? 1 : 0
  statement {
    sid = "Allow GuardDuty to encrypt findings"
    actions = [
      "kms:GenerateDataKey"
    ]

    resources = [
      "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"
    ]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }
  }

  statement {
    sid = "Allow all users to modify/delete key (test only)"
    actions = [
      "kms:*"
    ]

    resources = [
      "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }

}

resource "aws_guardduty_detector" "gd" {
  count = var.enable_guard_duty ? 1 : 0
  enable = true
}

resource "aws_s3_bucket" "gd_bucket" {
  count = var.enable_guard_duty ? 1 : 0
  bucket        = format("%s-gd-findingd-%s", var.name, data.aws_caller_identity.current.account_id)
  force_destroy = true
}

resource "aws_s3_bucket_policy" "gd_bucket_policy" {
  count = var.enable_guard_duty ? 1 : 0
  bucket = aws_s3_bucket.gd_bucket[0].id
  policy = data.aws_iam_policy_document.bucket_pol[0].json
}

resource "aws_kms_key" "gd_key" {
  count = var.enable_guard_duty ? 1 : 0
  description             = "Temporary key for AccTest of TF"
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms_pol[0].json
}

resource "aws_guardduty_publishing_destination" "gd_destination" {
  count = var.enable_guard_duty ? 1 : 0
  detector_id     = aws_guardduty_detector.gd[0].id
  destination_arn = aws_s3_bucket.gd_bucket[0].arn
  kms_key_arn     = aws_kms_key.gd_key[0].arn

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
  ]
}