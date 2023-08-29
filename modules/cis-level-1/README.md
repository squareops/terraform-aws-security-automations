# AWS CIS Level 1 Security Compliance Checks

This repository contains automated and manual checks to assess the security compliance of your AWS environment based on the Center for Internet Security (CIS) AWS Foundations Benchmark Level 1.

## Introduction

The CIS AWS Foundations Benchmark provides best practice guidelines for securing your AWS resources. This repository includes a set of automated and manual checks that align with the CIS Level 1 recommendations. These checks help ensure that your AWS environment follows the recommended security configurations.

## Automated checks covered

We have developed a set of automated checks using infrastructure-as-code (IAC). These checks assess various AWS services and resources to ensure they are configured according to CIS Level 1 requirements.

- Ensure IAM password policy requires minimum length of 14 or
greater
- Ensure IAM password policy prevents password reuse .
- Ensure credentials unused for 45 days or greater are
disabled
- Ensure there is only one active access key available for any
single IAM user.
- Ensure access keys are rotated every 90 days or less.
- Ensure IAM Users Receive Permissions Only Through
Groups.
- Ensure IAM policies that allow full "*:*" administrative
privileges are not attached.
- Ensure a support role has been created to manage incidents
with AWS Support.
- Ensure that all the expired SSL/TLS certificates stored in
AWS IAM are removed.
- Ensure that IAM Access analyzer is enabled for all regions
- Ensure that S3 Buckets are configured with 'Block public
access.
- Ensure EBS Volume Encryption is Enabled.
- Ensure that encryption-at-rest is enabled for RDS Instances.
- Ensure Auto Minor Version Upgrade feature is Enabled for
RDS Instances.
- Ensure that public access is not given to RDS Instance.
- Ensure that encryption is enabled for EFS file systems.
- Ensure CloudTrail is enabled in all regions.
- Ensure the S3 bucket used to store CloudTrail logs is not
publicly accessible.
- Ensure CloudTrail trails are integrated with CloudWatch Logs.
- Ensure S3 bucket access logging is enabled on the CloudTrail
S3 bucket.
- Ensure a log metric filter and alarm exist for unauthorized API calls.
- Ensure a log metric filter and alarm exist for changes to network gateways.
- Ensure a log metric filter and alarm exist for route table changes.
- Ensure a log metric filter and alarm exist for VPC changes.
- Ensure a log metric filter and alarm exists for AWS Organizations changes.
- Ensure a log metric filter and alarm exist for Management Console sign-in without MFA.
- Ensure a log metric filter and alarm exist for usage of 'root' account
- Ensure a log metric filter and alarm exist for IAM policy changes.
- Ensure a log metric filter and alarm exist for CloudTrail configuration changes.
- Ensure a log metric filter and alarm exist for S3 bucket policy changes.
- Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports.
- Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports.

## Manual Checks

In addition to automated checks, this repository provides a list of manual checks that require human validation. These checks cover areas where automated validation might not be feasible or practical.

- Maintain current contact details.
- Ensure security contact information is registered.
- Ensure security questions are registered in the AWS account
- Ensure no 'root' user account access key exists.
- Ensure MFA is enabled for the 'root' user account.
- Eliminate use of the 'root' user for administrative and daily
tasks
- Ensure multi-factor authentication (MFA) is enabled for all
IAM users that have a console password.
- Do not setup access keys during initial user setup for all IAM
users that have a console password.
- Ensure access to AWSCloudShellFullAccess is restricted.
- Ensure management console sign-in without MFA is
monitored
- Ensure MFA Delete is enabled on S3 buckets.

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

No requirements.

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
| [aws_cloudwatch_event_rule.lambda_trigger_access_analyzer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_acm_cert_expire](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_active_access_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_active_access_key_enforcing](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_admin_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_direct_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_expire_ssl_tls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_mfa_user](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_remove_port_22](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_remove_port_3389](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_ssl_tls_iam](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_user_cred](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_user_cred_45_days](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_user_cred_45_days_disable](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_rule.lambda_trigger_user_cred_permissive](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule) | resource |
| [aws_cloudwatch_event_target.lambda_target_access_analyzer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_acm_cert_expire](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_active_acess_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_active_acess_key_enforcing](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_admin_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_direct_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_expire_ssl_tls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_mfa_user](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_remove_port_22](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_remove_port_3389](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_ssl_tls_iam](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_user_cred](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_user_cred_45_days](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_user_cred_45_days_disable](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_event_target.lambda_target_user_cred_permissive](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_target) | resource |
| [aws_cloudwatch_log_group.cloudtrail_events](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_cloudwatch_log_metric_filter.aws_cis_1_1_avoid_the_use_of_root_account](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.aws_organizations](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.cloudtrail_cfg_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.iam_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.network_gw_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.no_mfa_console_signin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.route_table_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.unauthorized_api_calls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.vpc_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_metric_alarm.aws_cis_1_1_avoid_the_use_of_root_account](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.aws_organizations](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.cloudtrail_cfg_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.iam_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.network_gw_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.no_mfa_console_signin](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.route_table_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.s3_bucket_policy_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.unauthorized_api_calls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.vpc_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_ebs_encryption_by_default.ebs-encryption](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ebs_encryption_by_default) | resource |
| [aws_iam_account_password_policy.cis](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_account_password_policy) | resource |
| [aws_iam_policy.lambda_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_policy.mfa_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_policy) | resource |
| [aws_iam_role.cloudwatch_delivery](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role.lambda_role](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.cloudwatch_delivery_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.lambda_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_kms_alias.cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_alias) | resource |
| [aws_kms_key.cloudtrail](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_lambda_function.lambda_function_access_analyzer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_acm_cert_expire](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_admin_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_direct_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_expire_ssl_tls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_mfa_user](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_one_active_access_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_one_active_access_key_enforcing](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_remove_port_22](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_remove_port_3389](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_ssl_tls_iam](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_user_cred](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_user_cred_45_days](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_user_cred_45_days_disable](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_function.lambda_function_user_cred_permissive](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function) | resource |
| [aws_lambda_permission.lambda_permission_access_analyzer](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_acm_cert_expire](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_active_access_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_active_access_key_enforcing](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_admin_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_direct_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_expire_ssl_tls](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_mfa_user](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_remove_port_22](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_remove_port_3389](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_ssl_tls_iam](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_user_cred](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_user_cred_45_days](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_user_cred_45_days_disable](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_lambda_permission.lambda_permission_user_cred_permissive](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_s3_bucket.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_acl.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl) | resource |
| [aws_s3_bucket_acl.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_acl) | resource |
| [aws_s3_bucket_logging.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_logging) | resource |
| [aws_s3_bucket_ownership_controls.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_ownership_controls.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_ownership_controls) | resource |
| [aws_s3_bucket_policy.access_log_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_policy.audit_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_s3_bucket_public_access_block.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_public_access_block.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_public_access_block) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.access_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_server_side_encryption_configuration.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_server_side_encryption_configuration) | resource |
| [aws_s3_bucket_versioning.audit](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_versioning) | resource |
| [aws_sns_topic.trail-unauthorised](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_policy.default](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_policy) | resource |
| [aws_sns_topic_subscription.sms](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |
| [local_file.lambda_code_access_analyzer](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_acm_cert_expire](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_active_access_key](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_active_access_key_enforcing](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_admin_policy](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_direct_policy](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_expire_ssl_tls](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_mfa_user](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_remove_port_22](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_remove_port_3389](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_ssl_tls_iam](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_user_cred](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_user_cred_45_days](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_user_cred_45_days_disable](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [local_file.lambda_code_user_cred_permissive](https://registry.terraform.io/providers/hashicorp/local/latest/docs/resources/file) | resource |
| [archive_file.lambda_zip_access_analyzer](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_acm_cert_expire](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_active-access-key](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_active_access_key_enforcing](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_admin_policy](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_direct_policy](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_expire_ssl_tls](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_mfa_user](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_remove_port_22](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_remove_port_3389](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_ssl_tls_iam](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_user_cred](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_user_cred_45_days](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_user_cred_45_days_disable](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [archive_file.lambda_zip_user_cred_permissive](https://registry.terraform.io/providers/hashicorp/archive/latest/docs/data-sources/file) | data source |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.access_log_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.audit_log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudtrail_key_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudwatch_delivery_assume_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.cloudwatch_delivery_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.sns_topic_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [template_file.lambda_function_active_access_key](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_active_access_key_enforcing](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_access_analyzer](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_acm_cert_expire](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_admin_policy](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_direct_policy](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_expire_ssl_tls](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_mfa_user](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_remove_port_22](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_remove_port_3389](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_ssl_tls_iam](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_user_cred](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_user_cred_45_days](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_user_cred_45_days_disable](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |
| [template_file.lambda_function_script_user_cred_permissive](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alarm_namespace"></a> [alarm\_namespace](#input\_alarm\_namespace) | Namespace for CloudWatch Alarm Metric | `string` | `"CISBenchmark"` | no |
| <a name="input_alerting_enabled"></a> [alerting\_enabled](#input\_alerting\_enabled) | Enable alerting | `bool` | `true` | no |
| <a name="input_audit_log_bucket_custom_policy_json"></a> [audit\_log\_bucket\_custom\_policy\_json](#input\_audit\_log\_bucket\_custom\_policy\_json) | Override cusom policy for S3 Logging bucket | `string` | `""` | no |
| <a name="input_cloudtrail_event_selector_type"></a> [cloudtrail\_event\_selector\_type](#input\_cloudtrail\_event\_selector\_type) | Types of events that will be aggregated in CloudTrail | `string` | `"All"` | no |
| <a name="input_cloudtrail_kms_policy"></a> [cloudtrail\_kms\_policy](#input\_cloudtrail\_kms\_policy) | KMS policy for Cloudtrail Logs | `string` | `""` | no |
| <a name="input_cloudwatch_logs_kms_id"></a> [cloudwatch\_logs\_kms\_id](#input\_cloudwatch\_logs\_kms\_id) | KMS key for CloudWatch Logs Encryption | `string` | `""` | no |
| <a name="input_cron_expression"></a> [cron\_expression](#input\_cron\_expression) | Expession to trigger lambda function regularly on the schedule | `string` | `"cron(0 22 1,10,20,28 * ? 2023)"` | no |
| <a name="input_cw_log_enabled"></a> [cw\_log\_enabled](#input\_cw\_log\_enabled) | Set it to true to aggregate logs on CloudWatch | `bool` | `true` | no |
| <a name="input_disable_unused_cred_45_days"></a> [disable\_unused\_cred\_45\_days](#input\_disable\_unused\_cred\_45\_days) | It will disable cred for more than 45 days | `bool` | `false` | no |
| <a name="input_disable_unused_cred_90_days"></a> [disable\_unused\_cred\_90\_days](#input\_disable\_unused\_cred\_90\_days) | It will deactivate the newly created active access key | `bool` | `false` | no |
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
| <a name="input_mfa_iam_group_name"></a> [mfa\_iam\_group\_name](#input\_mfa\_iam\_group\_name) | Enter the user group name in which you want to add mfa user policy | `string` | `"test-user-group"` | no |
| <a name="input_multiple_access_key_deactivate"></a> [multiple\_access\_key\_deactivate](#input\_multiple\_access\_key\_deactivate) | It will deactivate the newly created active access key | `bool` | `false` | no |
| <a name="input_multiple_access_key_notification"></a> [multiple\_access\_key\_notification](#input\_multiple\_access\_key\_notification) | It will send email notification of IAM user with multiple active access key | `bool` | `true` | no |
| <a name="input_name"></a> [name](#input\_name) | Prefix for all the resources | `string` | `""` | no |
| <a name="input_notify_unused_cred_45_days"></a> [notify\_unused\_cred\_45\_days](#input\_notify\_unused\_cred\_45\_days) | It will notify about unused cred more than 45 days. | `bool` | `true` | no |
| <a name="input_notify_unused_cred_90_days"></a> [notify\_unused\_cred\_90\_days](#input\_notify\_unused\_cred\_90\_days) | It will notify unused cred more than 90 days | `bool` | `true` | no |
| <a name="input_region"></a> [region](#input\_region) | AWS Region | `string` | `"us-east-2"` | no |
| <a name="input_remove_ssl_tls_iam"></a> [remove\_ssl\_tls\_iam](#input\_remove\_ssl\_tls\_iam) | Remove expire ssl tls cert from IAM | `bool` | `false` | no |
| <a name="input_s3_enabled"></a> [s3\_enabled](#input\_s3\_enabled) | Set it true to export logs of CloudTrail to S3 Bucket | `bool` | `true` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags to be used in all the resources | `map(string)` | <pre>{<br>  "key": "AWS_CIS_Benchmark",<br>  "value": "1.2.0"<br>}</pre> | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_access_log_bucket_arn"></a> [access\_log\_bucket\_arn](#output\_access\_log\_bucket\_arn) | S3 bucket for storing access logs of config. |
| <a name="output_access_log_bucket_id"></a> [access\_log\_bucket\_id](#output\_access\_log\_bucket\_id) | S3 bucket for storing access logs of config. |
| <a name="output_audit_bucket_arn"></a> [audit\_bucket\_arn](#output\_audit\_bucket\_arn) | S3 bucket for storing audit logs of config. |
| <a name="output_audit_bucket_id"></a> [audit\_bucket\_id](#output\_audit\_bucket\_id) | S3 bucket for storing audit logs of config. |
| <a name="output_aws_s3_bucket_policy"></a> [aws\_s3\_bucket\_policy](#output\_aws\_s3\_bucket\_policy) | S3 bucket for storing audit logs of config. |
| <a name="output_aws_s3_bucket_public_access_block"></a> [aws\_s3\_bucket\_public\_access\_block](#output\_aws\_s3\_bucket\_public\_access\_block) | S3 bucket for storing audit logs of config. |
| <a name="output_cloudwatch_log_group_id"></a> [cloudwatch\_log\_group\_id](#output\_cloudwatch\_log\_group\_id) | Cloud watch log group name |
| <a name="output_sns_topic_arn"></a> [sns\_topic\_arn](#output\_sns\_topic\_arn) | SNS topic arn |
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
