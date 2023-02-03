resource "aws_sns_topic" "trail-unauthorised" {
  name = "Unauthorised1"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "sms" {
  topic_arn = aws_sns_topic.trail-unauthorised.arn
  protocol  = "email"
  endpoint  = local.endpoint
}