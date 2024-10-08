variable "name" {
  type        = string
  default     = ""
  description = "Prefix for all the resources"
}

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

# CloudTrail
variable "cw_log_enabled" {
  type        = bool
  default     = true
  description = "Set it to true to aggregate logs on CloudWatch"
}

variable "cloudwatch_logs_kms_key_arn" {
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

variable "remove_ssl_tls_iam" {
  type        = bool
  default     = false
  description = "Remove expire ssl tls cert from IAM"
}

variable "mfa_iam_group_name" {
  type        = string
  default     = "test-user-group"
  description = "Enter the user group name in which you want to add mfa user policy"
}

variable "cloudwatch_log_group_retention_days" {
  type        = number
  default     = 30
  description = "Enter the number of days in which you want your cloud watch log group for cloudtrail will got expired"
}

variable "disable_unused_credentials_after_days" {
  type        = number
  default     = "90"
  description = "Enter no of days after which unused credentials will be disable"
}

variable "disable_unused_credentials" {
  type        = bool
  default     = false
  description = "It will disable unused credentials of IAM user"
}
