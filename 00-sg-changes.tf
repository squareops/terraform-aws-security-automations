resource "aws_cloudwatch_metric_alarm" "sg" {
  alarm_name          = "security_group_changes_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "security_group_changes_metric"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.trail-unauthorised.arn]
}

resource "aws_cloudwatch_log_metric_filter" "sg" {
  name           = "security_group_changes_metric"
  pattern        = <<PATTERN
{($.eventName = AuthorizeSecurityGroupIngress) ||
($.eventName = AuthorizeSecurityGroupEgress) ||
($.eventName = RevokeSecurityGroupIngress) ||
($.eventName = RevokeSecurityGroupEgress) ||
($.eventName = CreateSecurityGroup) ||
($.eventName = DeleteSecurityGroup) }
  PATTERN
  log_group_name = resource.aws_cloudwatch_log_group.example.name
  metric_transformation {
    name      = "security_group_changes_metric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}