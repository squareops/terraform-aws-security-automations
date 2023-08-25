variable "name" {
  type        = string
  default     = ""
  description = "Prefix for all the resources"
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

variable "region" {
  type        = string
  default     = "us-east-2"
  description = "AWS Region"
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

variable "audit_bucket_arn" {
  type        = string
  default     = ""
  description = "s3 bucket arn for audit bucket"
}

variable "audit_bucket_id" {
  type        = string
  default     = ""
  description = "s3 bucket id for audit bucket"
}

variable "sns_topic_arn" {
  type        = string
  default     = ""
  description = "sns topic for sending notification"
}

variable "cloud_watch_log_group" {
  type        = string
  default     = ""
  description = "cloudwatch log group for metric filter"
}
