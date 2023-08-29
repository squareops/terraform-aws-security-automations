output "sns_topic_arn" {
  description = "SNS topic arn"
  value       = module.cis.sns_topic_arn
}

output "audit_bucket_arn" {
  description = "audit bucket arn"
  value       = module.cis.audit_bucket_arn
}

output "audit_bucket_id" {
  description = "audit bucket id"
  value       = module.cis.audit_bucket_id
}

output "access_log_bucket_id" {
  description = "access log bucket id"
  value       = module.cis.access_log_bucket_id
}

output "access_log_bucket_arn" {
  description = "access log bucket arn"
  value       = module.cis.access_log_bucket_id
}
