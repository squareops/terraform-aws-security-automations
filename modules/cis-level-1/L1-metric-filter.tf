resource "aws_sns_topic" "trail-unauthorised" {
  name = format("%s-sns", var.name)
}

resource "aws_sns_topic_policy" "default" {
  arn = aws_sns_topic.trail-unauthorised.arn

  policy = data.aws_iam_policy_document.sns_topic_policy.json
}

data "aws_iam_policy_document" "sns_topic_policy" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = ["${data.aws_caller_identity.current.account_id}"]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.trail-unauthorised.arn,
    ]

    sid = "__default_policy_ID"
  }
  statement {
    actions = ["SNS:Publish"]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = ["${data.aws_caller_identity.current.account_id}"]
    }
    condition {
      test     = "ArnLike"
      variable = "AWS:SourceArn"

      values = ["arn:aws:cloudwatch:${var.region}:${data.aws_caller_identity.current.account_id}:alarm:*"]
    }
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    resources = [
      aws_sns_topic.trail-unauthorised.arn,
    ]

    sid = "Allow_Publish_Alarms"
  }
}

resource "aws_sns_topic_subscription" "sms" {
  topic_arn = aws_sns_topic.trail-unauthorised.arn
  protocol  = "email"
  endpoint  = var.email
}

# 3.1 – Ensure a log metric filter and alarm exist for unauthorized API calls
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "UnauthorizedAPICalls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id
  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.1-UnauthorizedAPICalls"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.unauthorized_api_calls[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.12 – Ensure a log metric filter and alarm exist for changes to network gateways
resource "aws_cloudwatch_log_metric_filter" "network_gw_changes" {
  count = var.alerting_enabled ? 1 : 0

  name           = "NetworkGWChanges"
  pattern        = "{($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id

  metric_transformation {
    name      = "NetworkGWChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "network_gw_changes" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.12-NetworkGatewayChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.network_gw_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path."
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.13 – Ensure a log metric filter and alarm exist for route table changes
resource "aws_cloudwatch_log_metric_filter" "route_table_changes" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "RouteTableChanges"
  pattern        = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id
  metric_transformation {
    name      = "RouteTableChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.13-RouteTableChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.route_table_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.14 – Ensure a log metric filter and alarm exist for VPC changes
resource "aws_cloudwatch_log_metric_filter" "vpc_changes" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "VPCChanges"
  pattern        = "{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id
  metric_transformation {
    name      = "VPCChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "vpc_changes" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.14-VPCChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.vpc_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to VPC will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

#4.15 – Ensure a log metric filter and alarm exists for AWS Organizations changes
resource "aws_cloudwatch_log_metric_filter" "aws_organizations" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "AwsOrganizationChanges"
  pattern        = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = \"AcceptHandshake\") || ($.eventName = \"AttachPolicy\") || ($.eventName = \"CreateAccount\") || ($.eventName = \"CreateOrganizationalUnit\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeclineHandshake\") || ($.eventName = \"DeleteOrganization\") || ($.eventName = \"DeleteOrganizationalUnit\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"DetachPolicy\") || ($.eventName = \"DisablePolicyType\") || ($.eventName = \"EnablePolicyType\") || ($.eventName = \"InviteAccountToOrganization\") || ($.eventName = \"LeaveOrganization\") || ($.eventName = \"MoveAccount\") || ($.eventName = \"RemoveAccountFromOrganization\") || ($.eventName = \"UpdatePolicy\") || ($.eventName = \"UpdateOrganizationalUnit\")) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id
  metric_transformation {
    name      = "AwsOrganizationChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "aws_organizations" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-4.15-aws_organizations"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.aws_organizations[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Real-time monitoring of API calls can be achieved by directing CloudTrail Logs to CloudWatch Logs and establishing corresponding metric filters and alarms."
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.2 – Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA
resource "aws_cloudwatch_log_metric_filter" "no_mfa_console_signin" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "NoMFAConsoleSignin"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id
  metric_transformation {
    name      = "NoMFAConsoleSignin"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "no_mfa_console_signin" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.2-ConsoleSigninWithoutMFA"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.no_mfa_console_signin[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA."
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 1.1 – Avoid the use of the "root" account
resource "aws_cloudwatch_log_metric_filter" "aws_cis_1_1_avoid_the_use_of_root_account" {
  count          = var.alerting_enabled ? 1 : 0
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id
  name           = "RootAccountUsage"
  pattern        = "{ $.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\" }"
  metric_transformation {
    name      = "RootAccountUsage"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "aws_cis_1_1_avoid_the_use_of_root_account" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_description         = "Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it."
  alarm_name                = "CIS-1.1-RootAccountUsage"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  datapoints_to_alarm       = 1
  evaluation_periods        = 1
  insufficient_data_actions = []
  metric_name               = aws_cloudwatch_log_metric_filter.aws_cis_1_1_avoid_the_use_of_root_account[0].id
  namespace                 = var.alarm_namespace
  ok_actions                = []
  period                    = 300
  statistic                 = "Sum"
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  threshold                 = 1
  treat_missing_data        = "notBreaching"
  tags                      = var.tags
}

# 3.4 – Ensure a log metric filter and alarm exist for IAM policy changes
resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "IAMChanges"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id
  metric_transformation {
    name      = "IAMChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.4-IAMPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.iam_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact."
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.5 – Ensure a log metric filter and alarm exist for CloudTrail configuration changes
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_cfg_changes" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "CloudTrailCfgChanges"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id
  metric_transformation {
    name      = "CloudTrailCfgChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_cfg_changes" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.5-CloudTrailChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.cloudtrail_cfg_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account."
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}

# 3.8 – Ensure a log metric filter and alarm exist for S3 bucket policy changes
resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_changes" {
  count          = var.alerting_enabled ? 1 : 0
  name           = "S3BucketPolicyChanges"
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = aws_cloudwatch_log_group.cloudtrail_events.id
  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_changes" {
  count                     = var.alerting_enabled ? 1 : 0
  alarm_name                = "CIS-3.8-S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes[0].id
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = [aws_sns_topic.trail-unauthorised.arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = var.tags
}
