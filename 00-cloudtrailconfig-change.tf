
resource "aws_cloudwatch_metric_alarm" "cloudtrail_cfg" {
  alarm_name          = "cloudtrail_cfg_changes_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "cloudtrail_cfg_changes_metric"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.trail-unauthorised.arn]
}

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_cfg" {
  name           = "cloudtrail_cfg_changes_metric"
  pattern        = "{($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging)}"
  log_group_name = resource.aws_cloudwatch_log_group.example.name

  metric_transformation {
    name      = "cloudtrail_cfg_changes_metric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}