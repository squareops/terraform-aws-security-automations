resource "aws_cloudwatch_log_metric_filter" "signfail" {
  name           = "console_signin_failure_metric"
  pattern        = "{($.eventName = \"ConsoleLogin\") && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = resource.aws_cloudwatch_log_group.example.name
  metric_transformation {
    name      = "console_signin_failure_metric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "signfail" {
  alarm_name          = "console_signin_failure_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "console_signin_failure_metric"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.trail-unauthorised.arn]
}