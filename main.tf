data "aws_region" "current" {}

module "cis-level-1" {
  source                                = "./modules/cis-level-1"
  name                                  = var.name
  region                                = data.aws_region.current.name
  email                                 = var.email
  mfa_iam_group_name                    = var.mfa_iam_group_name
  s3_enabled                            = var.s3_enabled
  cw_log_enabled                        = var.cw_log_enabled
  multiple_access_key_deactivate        = var.multiple_access_key_deactivate
  disable_unused_credentials            = var.disable_unused_credentials
  disable_unused_credentials_after_days = var.disable_unused_credentials_after_days
  remove_ssl_tls_iam                    = var.remove_ssl_tls_iam
  cloudwatch_logs_kms_key_arn           = var.cloudwatch_logs_kms_key_arn
  cloudwatch_log_group_retention_days   = var.cloudwatch_log_group_retention_days
}

module "cis-level-2" {
  source                = "./modules/cis-level-2"
  depends_on            = [module.cis-level-1]
  count                 = contains(var.check_level, "level-2") || contains(var.check_level, "soc2") ? 1 : 0
  region                = data.aws_region.current.name
  audit_bucket_arn      = module.cis-level-1.audit_bucket_arn
  audit_bucket_id       = module.cis-level-1.audit_bucket_id
  sns_topic_arn         = module.cis-level-1.sns_topic_arn
  cloud_watch_log_group = module.cis-level-1.cloudwatch_log_group_id
  config_enabled        = var.config_enabled
  enable_aws_macie      = var.enable_aws_macie
}

module "soc2" {
  source                    = "./modules/soc2"
  depends_on                = [module.cis-level-2]
  count                     = contains(var.check_level, "soc2") ? 1 : 0
  region                    = data.aws_region.current.name
  name                      = var.name
  enable_guard_duty         = var.enable_guard_duty
  enable_security_hub       = var.enable_security_hub
  s3_object_expiration_days = var.s3_object_expiration_days
}
