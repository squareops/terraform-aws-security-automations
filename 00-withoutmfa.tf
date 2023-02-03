resource "aws_cloudwatch_log_metric_filter" "nomfa" {
  name           = "no_mfa_console_signin_metric"
  pattern        = "{($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\")}"
  log_group_name = resource.aws_cloudwatch_log_group.example.name

  metric_transformation {
    name      = "no_mfa_console_signin_metric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "nomfa" {
  alarm_name          = "no_mfa_console_signin_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "no_mfa_console_signin_metric"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.trail-unauthorised.arn]
}
