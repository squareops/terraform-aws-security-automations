# CIS Base

AWS CIS Controls module for terraform

https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html

### Controls covered:
- 1.1 Avoid the use of the "root" account
- 1.3 Ensure credentials unused for 90 days or greater are disabled
- 1.4 Ensure access keys are rotated every 90 days or less
- 1.5 Ensure IAM password policy requires at least one uppercase letter
- 1.6 Ensure IAM password policy requires at least one lowercase letter
- 1.7 Ensure IAM password policy requires at least one symbol
- 1.8 Ensure IAM password policy requires at least one number
- 1.9 Ensure IAM password policy requires a minimum length of 14 or greater 1.9
- 1.10 Ensure IAM password policy prevents password reuse
- 1.12 Ensure no root account access key exists
- 1.11 Ensure IAM password policy expires passwords within 90 days or less
- 1.16 Ensure IAM policies are attached only to groups or roles
- 2.1 Ensure CloudTrail is enabled in all Regions
- 2.2 Ensure CloudTrail log file validation is enabled
- 2.3 Ensure the S3 bucket CloudTrail logs to is not publicly accessible
- 2.4 Ensure CloudTrail trails are integrated with Amazon CloudWatch Logs
- 2.5 Ensure AWS Config is enabled
- 2.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket
- 2.7 Ensure CloudTrail logs are encrypted at rest using AWS KMS CMKs
- 3.1 Ensure a log metric filter and alarm exist for unauthorized API calls
- 3.2 Ensure a log metric filter and alarm exist for AWS Management Console sign-in without MFA
- 3.3 Ensure a log metric filter and alarm exist for usage of "root" account
- 3.4 Ensure a log metric filter and alarm exist for IAM policy changes
- 3.5 Ensure a log metric filter and alarm exist for CloudTrail configuration changes
- 3.6 Ensure a log metric filter and alarm exist for AWS Management Console authentication failures
- 3.7 Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs
- 3.8 Ensure a log metric filter and alarm exist for S3 bucket policy changes
- 3.9 Ensure a log metric filter and alarm exist for AWS Config configuration changes
- 3.10 Ensure a log metric filter and alarm exist for security group changes
- 3.11 Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)
- 3.12 Ensure a log metric filter and alarm exist for changes to network gateways
- 3.13 Ensure a log metric filter and alarm exist for route table changes
- 3.14 Ensure a log metric filter and alarm exist for VPC changes
- 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to port 22
- 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to port 3389
<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.12 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_archive"></a> [archive](#provider\_archive) | n/a |
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |
| <a name="provider_local"></a> [local](#provider\_local) | n/a |
| <a name="provider_template"></a> [template](#provider\_template) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudtrail.cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_admin_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_direct_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_mfa_user](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_remove_port_22](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_remove_port_3389](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_user_cred](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.lambda_target_admin_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_direct_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_mfa_user](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_remove_port_22](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_remove_port_3389](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_user_cred](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_log_group.cloudtrail_events](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_metric_filter.aws_cis_1_1_avoid_the_use_of_root_account](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.aws_config_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.cloudtrail_cfg_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.console_signin_failures](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.disable_or_delete_cmk](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.iam_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.nacl_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.network_gw_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.no_mfa_console_signin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.root_usage](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.route_table_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.security_group_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.unauthorized_api_calls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.vpc_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_metric_alarm.aws_cis_1_1_avoid_the_use_of_root_account](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.aws_config_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.cloudtrail_cfg_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.console_signin_failures](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.disable_or_delete_cmk](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.iam_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.nacl_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.network_gw_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.no_mfa_console_signin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.root_usage](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.route_table_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.s3_bucket_policy_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.security_group_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.unauthorized_api_calls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.vpc_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_config_configuration_recorder.recorder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_recorder) | resource |
| [aws_config_configuration_recorder_status.recorder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_recorder_status) | resource |
| [aws_config_delivery_channel.bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_delivery_channel) | resource |
| [aws_iam_account_password_policy.cis](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy) | resource |
| [aws_iam_policy.lambda_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.mfa_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.cloudwatch_delivery](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.lambda_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.recorder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.cloudwatch_delivery_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy.recorder_publish_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.lambda_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_iam_role_policy_attachment.recorder_read_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_kms_alias.cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_lambda_function.lambda_function_admin_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_direct_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_mfa_user](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_remove_port_22](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_remove_port_3389](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_user_cred](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_permission.lambda_permission_admin_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_direct_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_mfa_user](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_remove_port_22](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_remove_port_3389](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_user_cred](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_s3_bucket.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_acl.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl) | resource |
| [aws_s3_bucket_acl.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl) | resource |
| [aws_s3_bucket_logging.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_logging) | resource |
| [aws_s3_bucket_ownership_controls.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_ownership_controls.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_policy.audit_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_public_access_block.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_sns_topic.trail-unauthorised](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_policy.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy) | resource |
| [aws_sns_topic_subscription.sms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [local_file.lambda_code_admin_policy](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_direct_policy](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_mfa_user](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_remove_port_22](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_remove_port_3389](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_user_cred](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [archive_file.lambda_zip_admin_policy](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_direct_policy](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_mfa_user](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_remove_port_22](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_remove_port_3389](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_user_cred](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.audit_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudtrail_key_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudwatch_delivery_assume_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudwatch_delivery_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.recorder_assume_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.recorder_publish_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.sns_topic_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [template_file.lambda_function_script_admin_policy](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_direct_policy](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_mfa_user](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_remove_port_22](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_remove_port_3389](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_user_cred](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alarm_namespace"></a> [alarm\_namespace](#input\_alarm\_namespace) | Namespace for CloudWatch Alarm Metric | `string` | `"CISBenchmark"` | no |
| <a name="input_alerting_enabled"></a> [alerting\_enabled](#input\_alerting\_enabled) | Enable alerting | `bool` | `true` | no |
| <a name="input_audit_log_bucket_custom_policy_json"></a> [audit\_log\_bucket\_custom\_policy\_json](#input\_audit\_log\_bucket\_custom\_policy\_json) | Override cusom policy for S3 Logging bucket | `string` | `""` | no |
| <a name="input_cloudtrail_event_selector_type"></a> [cloudtrail\_event\_selector\_type](#input\_cloudtrail\_event\_selector\_type) | Types of events that will be aggregated in CloudTrail | `string` | `"All"` | no |
| <a name="input_cloudtrail_kms_policy"></a> [cloudtrail\_kms\_policy](#input\_cloudtrail\_kms\_policy) | KMS policy for Cloudtrail Logs | `string` | `""` | no |
| <a name="input_cloudwatch_logs_kms_id"></a> [cloudwatch\_logs\_kms\_id](#input\_cloudwatch\_logs\_kms\_id) | KMS key for CloudWatch Logs Encryption | `string` | `""` | no |
| <a name="input_config_enabled"></a> [config\_enabled](#input\_config\_enabled) | Set it to true to enable AWS Config | `bool` | `true` | no |
| <a name="input_cron_expression"></a> [cron\_expression](#input\_cron\_expression) | Expession to trigger lambda function regularly on the schedule | `string` | `"cron(0 22 1,10,20,28 * ? 2023)"` | no |
| <a name="input_cw_log_enabled"></a> [cw\_log\_enabled](#input\_cw\_log\_enabled) | Set it to true to aggregate logs on CloudWatch | `bool` | `true` | no |
| <a name="input_email"></a> [email](#input\_email) | Email address that can receive notifications from Amazon SNS | `string` | `""` | no |
| <a name="input_iam_allow_users_to_change_password"></a> [iam\_allow\_users\_to\_change\_password](#input\_iam\_allow\_users\_to\_change\_password) | Set it to true to allow users to change their own password | `bool` | `true` | no |
| <a name="input_iam_hard_expiry"></a> [iam\_hard\_expiry](#input\_iam\_hard\_expiry) | Everyone needs hard reset for expired passwords | `bool` | `true` | no |
| <a name="input_iam_max_password_age"></a> [iam\_max\_password\_age](#input\_iam\_max\_password\_age) | Passwords expire in N days | `number` | `90` | no |
| <a name="input_iam_minimum_password_length"></a> [iam\_minimum\_password\_length](#input\_iam\_minimum\_password\_length) | Require minimum length of password | `number` | `14` | no |
| <a name="input_iam_password_reuse_prevention"></a> [iam\_password\_reuse\_prevention](#input\_iam\_password\_reuse\_prevention) | Prevent password reuse N times | `number` | `24` | no |
| <a name="input_iam_require_lowercase_characters"></a> [iam\_require\_lowercase\_characters](#input\_iam\_require\_lowercase\_characters) | Require at least one lowercase letter in passwords | `bool` | `true` | no |
| <a name="input_iam_require_numbers"></a> [iam\_require\_numbers](#input\_iam\_require\_numbers) | Require at least one number in passwords | `bool` | `true` | no |
| <a name="input_iam_require_symbols"></a> [iam\_require\_symbols](#input\_iam\_require\_symbols) | Require at least one symbol in passwords | `bool` | `true` | no |
| <a name="input_iam_require_uppercase_characters"></a> [iam\_require\_uppercase\_characters](#input\_iam\_require\_uppercase\_characters) | Require at least one uppercase letter in passwords | `bool` | `true` | no |
| <a name="input_include_global_resource_types"></a> [include\_global\_resource\_types](#input\_include\_global\_resource\_types) | Set it to true to enable recording of global resources in AWS Config | `bool` | `true` | no |
| <a name="input_name"></a> [name](#input\_name) | Prefix for all the resources | `string` | `"skaf-cis"` | no |
| <a name="input_region"></a> [region](#input\_region) | AWS Region | `string` | `"us-east-2"` | no |
| <a name="input_s3_enabled"></a> [s3\_enabled](#input\_s3\_enabled) | Set it true to export logs of CloudTrail to S3 Bucket | `bool` | `true` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags to be used in all the resources | `map(string)` | <pre>{<br>  "key": "AWS_CIS_Benchmark",<br>  "value": "1.2.0"<br>}</pre> | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_access_log_bucket"></a> [access\_log\_bucket](#output\_access\_log\_bucket) | S3 bucket for storing access logs of config. |
| <a name="output_audit_bucket"></a> [audit\_bucket](#output\_audit\_bucket) | S3 bucket for storing audit logs of config. |
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
