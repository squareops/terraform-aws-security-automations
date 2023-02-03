resource "aws_cloudwatch_metric_alarm" "policychange" {
  alarm_name          = "iam_changes_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "iam_changes_metric"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.trail-unauthorised.arn]
}

resource "aws_cloudwatch_log_metric_filter" "policychange" {
  name           = "iam_changes_metric"
  pattern        = <<PATTERN
   "($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||
    ($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||
    ($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||
    ($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||
    ($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||
    ($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||
    ($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||
    ($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  PATTERN
  log_group_name = resource.aws_cloudwatch_log_group.example.name
  metric_transformation {
    name      = "iam_changes_metric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}