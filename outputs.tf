output "access_log_bucket" {
  description = "S3 bucket for storing access logs of config."
  value       = aws_s3_bucket.access_log[0].id
}

output "audit_bucket" {
  description = "S3 bucket for storing audit logs of config."
  value       = aws_s3_bucket.audit[0].id
}
