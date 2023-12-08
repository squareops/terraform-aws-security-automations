variable "name" {
  type        = string
  default     = ""
  description = "Prefix for all the resources"
}

variable "region" {
  type        = string
  default     = "us-east-2"
  description = "AWS Region"
}

variable "enable_guard_duty" {
  type        = bool
  default     = true
  description = "This will enable guard duty"
}

variable "enable_security_hub" {
  type        = bool
  default     = true
  description = "This will security hub"
}

variable "s3_object_expiration" {
  type        = string
  default     = "90"
  description = "This will set gaurd duty s3 expiration"
}
