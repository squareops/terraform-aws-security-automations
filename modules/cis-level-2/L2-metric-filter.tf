
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

