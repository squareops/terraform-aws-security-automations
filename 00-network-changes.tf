resource "aws_cloudwatch_metric_alarm" "gateway" {
  alarm_name          = "gateway_changes_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "gateway_changes_metric"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.trail-unauthorised.arn]
}

resource "aws_cloudwatch_log_metric_filter" "gateway" {
  name           = "gateway_changes_metric"
  pattern        = <<PATTERN
{ ($.eventName = CreateCustomerGateway) ||
($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) ||
($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) ||
($.eventName = DetachInternetGateway) }
PATTERN
  log_group_name = resource.aws_cloudwatch_log_group.example.name
  metric_transformation {
    name      = "gateway_changes_metric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}