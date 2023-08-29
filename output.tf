output "sns_topic_arn" {
  description = "SNS topic arn"
  value       = module.cis-level-1.sns_topic_arn
}

output "audit_bucket_arn" {
  description = "S3 bucket for storing audit logs of config."
  value       = module.cis-level-1.audit_bucket_arn
}

output "audit_bucket_id" {
  description = "S3 bucket for storing audit logs of config."
  value       = module.cis-level-1.audit_bucket_id
}

output "access_log_bucket_arn" {
  description = "S3 bucket for storing audit logs of config."
  value       = module.cis-level-1.access_log_bucket_arn
}

output "access_log_bucket_id" {
  description = "S3 bucket for storing audit logs of config."
  value       = module.cis-level-1.access_log_bucket_id
}
