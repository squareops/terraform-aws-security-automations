locals {
  region      = "us-east-2"
  environment = "prod"
  name        = "skaf"
  additional_tags = {
    Owner      = "organization_name"
    Expires    = "Never"
    Department = "Engineering"
  }
}

module "cis" {

  source = "../../"

  name                          = local.name
  region                        = local.region
  email                         = "shibra@squareops.com"
  cron_expression               = "cron(0 22 1,10,20,28 * ? 2023)"
  s3_enabled                    = true
  config_enabled                = true
  include_global_resource_types = true
  cw_log_enabled                = true
  alerting_enabled              = true

}
