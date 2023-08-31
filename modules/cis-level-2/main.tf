data "aws_caller_identity" "current" {}

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
  #count = var.check_level == "level-2" || var.check_level == "soc-2" ? 1 : 0
  name               = "${var.name}-config-role"
  assume_role_policy = data.aws_iam_policy_document.recorder_assume_role_policy.json
  tags               = var.tags
}

#https://docs.aws.amazon.com/config/latest/developerguide/iamrole-permissions.html
data "aws_iam_policy_document" "recorder_publish_policy" {
  #depends_on = [module.level-1.audit_bucket]
  statement {
    actions   = ["s3:PutObject"]
    resources = ["${var.audit_bucket_arn}/config/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [var.audit_bucket_arn]
  }

  statement {
    actions = ["sns:Publish"]

    resources = [var.sns_topic_arn]
  }
}

resource "aws_iam_role_policy" "recorder_publish_policy" {
  #count = var.check_level == "level-2" || var.check_level == "soc-2" ? 1 : 0
  name   = "${var.name}-config-policy"
  role   = aws_iam_role.recorder.id
  policy = data.aws_iam_policy_document.recorder_publish_policy.json
}

resource "aws_iam_role_policy_attachment" "recorder_read_policy" {
  #count      = var.check_level == "level-2" || var.check_level == "soc-2" ? 1 : 0
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

  s3_bucket_name = var.audit_bucket_id
  s3_key_prefix  = "config"

  snapshot_delivery_properties {
    delivery_frequency = "One_Hour"
  }

  depends_on = [
    aws_config_configuration_recorder.recorder[0]
  ]
}

resource "aws_config_configuration_recorder_status" "recorder" {
  count = var.config_enabled ? 1 : 0

  name = aws_config_configuration_recorder.recorder[0].id

  is_enabled = true
  depends_on = [aws_config_delivery_channel.bucket[0]]
}



# 3.10 – Ensure a log metric filter and alarm exist for security group changes
resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "SecurityGroupChanges"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}"
  log_group_name = var.cloud_watch_log_group
  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.10-SecurityGroupChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.security_group_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed."
  alarm_actions             = [var.sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.11 – Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)
resource "aws_cloudwatch_log_metric_filter" "nacl_changes" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "NACLChanges"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = var.cloud_watch_log_group
  metric_transformation {
    name      = "NACLChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.11-NetworkACLChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.nacl_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed."
  alarm_actions             = [var.sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.6 – Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
resource "aws_cloudwatch_log_metric_filter" "console_signin_failures" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "ConsoleSigninFailures"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = var.cloud_watch_log_group
  metric_transformation {
    name      = "ConsoleSigninFailures"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "console_signin_failures" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.6-ConsoleAuthenticationFailure"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.console_signin_failures[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = [var.sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.7 – Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
resource "aws_cloudwatch_log_metric_filter" "disable_or_delete_cmk" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "DisableOrDeleteCMK"
  pattern        = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = var.cloud_watch_log_group
  metric_transformation {
    name      = "DisableOrDeleteCMK"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "disable_or_delete_cmk" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.7-DisableOrDeleteCMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.disable_or_delete_cmk[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = [var.sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.9 – Ensure a log metric filter and alarm exist for AWS Config configuration changes
resource "aws_cloudwatch_log_metric_filter" "aws_config_changes" {
  count = var.alerting_enabled ? 1 : 0

  name           = "AWSConfigChanges"
  pattern        = "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }"
  log_group_name = var.cloud_watch_log_group

  metric_transformation {
    name      = "AWSConfigChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "aws_config_changes" {
  count = var.alerting_enabled ? 1 : 0

  alarm_name                = "CIS-3.9-AWSConfigChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.aws_config_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account."
  alarm_actions             = [var.sns_topic_arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = var.tags
}

## Enable aws macie

resource "aws_macie2_account" "aws-macie" {
  count = var.enable_aws_macie ? 1 : 0
}
