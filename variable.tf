variable "name" {
  type        = string
  default     = ""
  description = "Prefix for all resources (e.g., 'my-app') to identify them in the cloud environment."
}

variable "email" {
  type        = string
  default     = ""
  description = "Email address for receiving notifications from Amazon SNS."
}

variable "cron_expression" {
  type        = string
  default     = "cron(0 22 1,10,20,28 * ? 2023)"
  description = "Cron expression to trigger a Lambda function on a regular schedule."
}
# S3
variable "s3_enabled" {
  type        = bool
  default     = true
  description = "Set to true to enable exporting CloudTrail logs to an S3 bucket."
}

variable "audit_log_bucket_custom_policy_json" {
  type        = string
  default     = ""
  description = "Override the custom policy for the S3 logging bucket (JSON format)."
}

#AWS Config
variable "config_enabled" {
  type        = bool
  default     = true
  description = "Set to true to enable AWS Config."
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
  description = "AWS region where resources will be provisioned."
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
  description = "Namespace for the CloudWatch Alarm Metric"
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
  description = "Set it true to enforce hard password expiration for all users."
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
  description = "Minimum length requirement for user passwords."
}

variable "iam_password_reuse_prevention" {
  type        = number
  default     = 24
  description = "Prevent password reuse multiple times"
}

variable "iam_max_password_age" {
  type        = number
  default     = 90
  description = "Maximum password age in days before expiration."
}

variable "multiple_access_key_notification" {
  type        = bool
  default     = true
  description = "Send email notifications for IAM users with multiple active access keys. "
}

variable "multiple_access_key_deactivate" {
  type        = bool
  default     = false
  description = "Deactivate newly created active access keys for IAM users."
}

variable "disable_unused_credentials" {
  type        = bool
  default     = false
  description = "Disable unused IAM user credentials."
}

variable "remove_ssl_tls_iam" {
  type        = bool
  default     = false
  description = "Remove expired SSL/TLS certificates from IAM."
}

variable "enable_guard_duty" {
  type        = bool
  default     = true
  description = "Enable AWS GuardDuty for threat detection."
}

variable "enable_security_hub" {
  type        = bool
  default     = true
  description = "Enable AWS Security Hub for centralized security monitoring."
}

variable "mfa_iam_group_name" {
  type        = string
  default     = "test-user-group"
  description = "Name of the IAM user group to which MFA user policies will be added."
}

variable "check_level" {
  type        = list(any)
  default     = []
  description = "List of CIS checks to deploy."
}

variable "cloudwatch_log_group_retention_days" {
  type        = number
  default     = 30
  description = "Number of days to retain logs in CloudWatch log groups for CloudTrail."
}

variable "enable_aws_macie" {
  type        = bool
  default     = true
  description = "Enable AWS Macie for data discovery and protection."
}

variable "disable_unused_credentials_after_days" {
  type        = number
  default     = "90"
  description = "Number of days after which unused IAM credentials will be disabled."
}
