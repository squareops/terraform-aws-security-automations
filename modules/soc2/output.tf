output "guardduty_bucket_id" {
  description = "S3 bucket for storing guardduty findings."
  value       = aws_s3_bucket.gd_bucket[0].id
}

output "guardduty_bucket_arn" {
  description = "S3 bucket for storing guardduty findings."
  value       = aws_s3_bucket.gd_bucket[0].arn
}