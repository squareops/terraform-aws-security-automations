output "access_log_bucket" {
  description = "S3 bucket for storing access logs of config."
  value       = module.cis.access_log_bucket
}

output "audit_bucket" {
  description = "S3 bucket for storing audit logs of config."
  value       = module.cis.audit_bucket
}
