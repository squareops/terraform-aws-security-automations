module "cloudtrail" {
  source                        = "cloudposse/cloudtrail/aws"
  version                       = "0.22.0"
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true
  s3_bucket_name                = module.cloudtrail_s3_bucket.bucket_id
}

module "cloudtrail_s3_bucket" {
  source  = "cloudposse/cloudtrail-s3-bucket/aws"
  version = "0.23.1"
}
