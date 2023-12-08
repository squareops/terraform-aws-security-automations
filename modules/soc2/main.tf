## Enable guard duty

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

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
  statement {
    sid    = "DenyInsecureAccess"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions = ["s3:*"]
    resources = [
      "${aws_s3_bucket.gd_bucket[0].arn}",
      "${aws_s3_bucket.gd_bucket[0].arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
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
  count  = var.enable_guard_duty ? 1 : 0
  enable = true
}

resource "aws_s3_bucket" "gd_bucket" {
  count         = var.enable_guard_duty ? 1 : 0
  bucket        = format("%s-gd-findingd-%s", var.name, data.aws_caller_identity.current.account_id)
  force_destroy = true
}

resource "aws_s3_bucket_lifecycle_configuration" "bucket-config" {
  bucket = aws_s3_bucket.gd_bucket[0].id
  rule {
    id = "guardduty_s3"
    expiration {
      days = var.s3_object_expiration_days
    }
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "gd_bucket_policy" {
  count  = var.enable_guard_duty ? 1 : 0
  bucket = aws_s3_bucket.gd_bucket[0].id
  policy = data.aws_iam_policy_document.bucket_pol[0].json
}

resource "aws_kms_key" "gd_key" {
  count                   = var.enable_guard_duty ? 1 : 0
  description             = "Temporary key for AccTest of TF"
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.kms_pol[0].json
}

resource "aws_guardduty_publishing_destination" "gd_destination" {
  count           = var.enable_guard_duty ? 1 : 0
  detector_id     = aws_guardduty_detector.gd[0].id
  destination_arn = aws_s3_bucket.gd_bucket[0].arn
  kms_key_arn     = aws_kms_key.gd_key[0].arn

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
  ]
}


## Enable security hub

resource "aws_securityhub_account" "security-hub" {
  count = var.enable_security_hub ? 1 : 0
}

resource "aws_securityhub_standards_subscription" "cis_v1" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
}

resource "aws_securityhub_standards_subscription" "cis_v1_2" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0"
}

resource "aws_securityhub_standards_subscription" "cis_v1_4" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/cis-aws-foundations-benchmark/v/1.4.0"
}

resource "aws_securityhub_standards_subscription" "nist_800_53" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/nist-800-53/v/5.0.0"
}

resource "aws_securityhub_standards_subscription" "pci_321" {
  count         = var.enable_security_hub ? 1 : 0
  depends_on    = [aws_securityhub_account.security-hub]
  standards_arn = "arn:aws:securityhub:${var.region}::standards/pci-dss/v/3.2.1"
}
