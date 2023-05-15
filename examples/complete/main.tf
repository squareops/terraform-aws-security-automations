locals {
  region      = "us-east-2"
  environment = "prod"
  name        = "skaf"
  additional_tags = {
    Owner      = "SquareOps"
    Expires    = "Never"
    Department = "Engineering"
  }
}

module "cis" {

  source = "../../"

  name                          = local.name
  region                        = local.region
  email                         = "shibra@squareops.com"
  s3_enabled                    = true
  config_enabled                = true
  include_global_resource_types = true
  cw_log_enabled                = true
  aws_account_id                = "1234567890"
  alerting_enabled              = true
  alarm_namespace               = "CISBenchmark"

}
