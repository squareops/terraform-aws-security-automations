resource "aws_config_configuration_aggregator" "organization" {
  name = local.name
  account_aggregation_source {
    account_ids = [local.accountID]
    all_regions = true
  }
}