resource "aws_cloudwatch_metric_alarm" "nacl" {
  alarm_name          = "nacl_changes_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "nacl_changes_metric"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.trail-unauthorised.arn]
}

resource "aws_cloudwatch_log_metric_filter" "nacl" {
  name           = "nacl_changes_metric"
  pattern        = <<PATTERN
{($.eventName = CreateNetworkAcl) ||
($.eventName = CreateNetworkAclEntry) ||
($.eventName = DeleteNetworkAcl) ||
($.eventName = DeleteNetworkAclEntry) ||
($.eventName = ReplaceNetworkAclEntry) ||
($.eventName = ReplaceNetworkAclAssociation) }
PATTERN
  log_group_name = resource.aws_cloudwatch_log_group.example.name
  metric_transformation {
    name      = "nacl_changes_metric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}