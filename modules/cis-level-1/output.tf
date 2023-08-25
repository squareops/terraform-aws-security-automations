output "sns_topic_arn" {
  description = "SNS topic arn"
  value       = aws_sns_topic.trail-unauthorised.arn
}

output "cloudwatch_log_group_id" {
  description = "Cloud watch log group name"
  value       = aws_cloudwatch_log_group.cloudtrail_events.id
}

output "audit_bucket_arn" {
  description = "S3 bucket for storing audit logs of config."
  value       = aws_s3_bucket.audit[0].arn
}

output "audit_bucket_id" {
  description = "S3 bucket for storing audit logs of config."
  value       = aws_s3_bucket.audit[0].id
}

output "aws_s3_bucket_policy" {
  description = "S3 bucket for storing audit logs of config."
  value       = aws_s3_bucket_policy.audit_log[0].id
}

output "aws_s3_bucket_public_access_block" {
  description = "S3 bucket for storing audit logs of config."
  value       = aws_s3_bucket_public_access_block.access_log[0].id
}
