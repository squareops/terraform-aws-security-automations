variable "name" {
  type        = string
  default     = "skaf-cis"
  description = "Prefix for all the resources"
}

# SNS
# variable "sns_arn" {
#   description = "ARN of SNS for CIS Notifications"
#   type        = string
# }

variable "email" {
  type        = string
  default     = ""
  description = "Email address that can receive notifications from Amazon SNS"
}

variable "cron_expression" {
  type        = string
  default     = "cron(0 22 1,10,20,28 * ? 2023)"
  description = "Expession to trigger lambda function regularly on the schedule"
}
# S3
variable "s3_enabled" {
  type        = bool
  default     = true
  description = "Set it true to export logs of CloudTrail to S3 Bucket"
}

variable "audit_log_bucket_custom_policy_json" {
  type        = string
  default     = ""
  description = "Override cusom policy for S3 Logging bucket"
}

# AWS Config
variable "config_enabled" {
  type        = bool
  default     = true
  description = "Set it to true to enable AWS Config"
}

variable "include_global_resource_types" {
  type        = bool
  default     = true
  description = "Set it to true to enable recording of global resources in AWS Config"
}

# CloudTrail

variable "cw_log_enabled" {
  type        = bool
  default     = true
  description = "Set it to true to aggregate logs on CloudWatch"
}

variable "cloudwatch_logs_kms_id" {
  type        = string
  default     = ""
  description = "KMS key for CloudWatch Logs Encryption"
}

variable "cloudtrail_event_selector_type" {
  type        = string
  default     = "All"
  description = "Types of events that will be aggregated in CloudTrail"
}

variable "region" {
  type        = string
  default     = "us-east-2"
  description = "AWS Region"
}

variable "cloudtrail_kms_policy" {
  type        = string
  default     = ""
  description = "KMS policy for Cloudtrail Logs"
}

# Alerting
variable "alerting_enabled" {
  type        = bool
  default     = true
  description = "Enable alerting"
}

variable "alarm_namespace" {
  type        = string
  default     = "CISBenchmark"
  description = "Namespace for CloudWatch Alarm Metric"
}

variable "tags" {
  type = map(string)
  default = {
    "key"   = "AWS_CIS_Benchmark"
    "value" = "1.2.0"
  }
  description = "Tags to be used in all the resources"
}

# Password Policy
variable "iam_allow_users_to_change_password" {
  type        = bool
  default     = true
  description = "Set it to true to allow users to change their own password"
}

variable "iam_hard_expiry" {
  type        = bool
  default     = true
  description = "Everyone needs hard reset for expired passwords"
}

variable "iam_require_uppercase_characters" {
  type        = bool
  default     = true
  description = "Require at least one uppercase letter in passwords"
}

variable "iam_require_lowercase_characters" {
  type        = bool
  default     = true
  description = "Require at least one lowercase letter in passwords"
}

variable "iam_require_symbols" {
  type        = bool
  default     = true
  description = "Require at least one symbol in passwords"
}

variable "iam_require_numbers" {
  type        = bool
  default     = true
  description = "Require at least one number in passwords"
}

variable "iam_minimum_password_length" {
  type        = number
  default     = 14
  description = "Require minimum length of password"
}

variable "iam_password_reuse_prevention" {
  type        = number
  default     = 24
  description = "Prevent password reuse N times"
}

variable "iam_max_password_age" {
  type        = number
  default     = 90
  description = "Passwords expire in N days"
}

variable "multiple_access_key_notification" {
  type        = bool
  default     = true
  description = "It will send email notification of IAM user with multiple active access key "
}

variable "multiple_access_key_deactivate" {
  type        = bool
  default     = false
  description = "It will deactivate the newly created active access key"
}

variable "notify_unused_cred_90_days" {
  type        = bool
  default     = true
  description = "It will notify unused cred more than 90 days"
}

variable "disable_unused_cred_90_days" {
  type        = bool
  default     = false
  description = "It will deactivate the newly created active access key"
}

variable "notify_unused_cred_45_days" {
  type        = bool
  default     = true
  description = "It will notify about unused cred more than 45 days."
}

variable "disable_unused_cred_45_days" {
  type        = bool
  default     = false
  description = "It will disable cred for more than 45 days"
}

variable "remove_ssl_tls_iam" {
  type        = bool
  default     = false
  description = "Remove expire ssl tls cert from IAM"
}