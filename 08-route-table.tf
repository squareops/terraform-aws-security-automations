resource "aws_cloudwatch_log_metric_filter" "routes" {
  name           = "route_table_changes_metric"
  pattern        = <<PATTERN
{($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) ||
($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation)||
($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) ||
($.eventName = DisassociateRouteTable) }
PATTERN
  log_group_name = resource.aws_cloudwatch_log_group.example.name
  metric_transformation {
    name      = "route_table_changes_metric"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "routes" {
  alarm_name          = "route_table_changes_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "route_table_changes_metric"
  namespace           = "CISBenchmark"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.trail-unauthorised.arn]
}