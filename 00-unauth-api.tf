resource "aws_cloudwatch_log_metric_filter" "unauth" {
  name           = "unauthorized_api_calls_metric"
  pattern        = "{($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\")}"
  log_group_name = resource.aws_cloudwatch_log_group.example.name

  metric_transformation {
    name      = "unauthorized_api_calls_metric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}


resource "aws_cloudwatch_metric_alarm" "unauth" {
  alarm_name          = "unauthorized_api_calls_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "unauthorized_api_calls_metric"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.trail-unauthorised.arn]
}