# 2.5 – Ensure AWS Config is enabled

data "aws_iam_policy_document" "recorder_assume_role_policy" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "recorder" {
  name               = "${var.name}-config-role"
  assume_role_policy = data.aws_iam_policy_document.recorder_assume_role_policy.json
  tags               = var.tags
}

#https://docs.aws.amazon.com/config/latest/developerguide/iamrole-permissions.html
data "aws_iam_policy_document" "recorder_publish_policy" {
  depends_on = [aws_s3_bucket.audit[0]]
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.audit[0].arn}/config/AWSLogs/${var.aws_account_id}/*"]

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.audit[0].arn]
  }

  statement {
    actions = ["sns:Publish"]

    resources = [aws_sns_topic.trail-unauthorised.arn]
  }
}

resource "aws_iam_role_policy" "recorder_publish_policy" {
  name   = "${var.name}-config-policy"
  role   = aws_iam_role.recorder.id
  policy = data.aws_iam_policy_document.recorder_publish_policy.json
}

resource "aws_iam_role_policy_attachment" "recorder_read_policy" {
  role       = aws_iam_role.recorder.id
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "recorder" {
  count = var.config_enabled ? 1 : 0

  name = format("%s-config-recorder", var.name)

  role_arn = aws_iam_role.recorder.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = var.include_global_resource_types
  }
}

resource "aws_config_delivery_channel" "bucket" {
  count = var.config_enabled ? 1 : 0

  name = format("%s-config-delivery", var.name)

  s3_bucket_name = aws_s3_bucket.audit[0].id
  s3_key_prefix  = "config"
  # s3_kms_key_arn = aws_kms_key.cloudtrail.arn
  # sns_topic_arn  = aws_sns_topic.trail-unauthorised.arn

  snapshot_delivery_properties {
    delivery_frequency = "One_Hour"
  }

  depends_on = [
    aws_config_configuration_recorder.recorder[0],
    aws_s3_bucket_policy.audit_log[0],
    aws_s3_bucket_public_access_block.audit[0]
  ]
}

resource "aws_config_configuration_recorder_status" "recorder" {
  count = var.config_enabled ? 1 : 0

  name = aws_config_configuration_recorder.recorder[0].id

  is_enabled = true
  depends_on = [aws_config_delivery_channel.bucket[0]]
}
