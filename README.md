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
- 1.13 Ensure there is only one active access key available for any single IAM user
- 1.19 Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed
- 1.20 Ensure that IAM Access analyzer is enabled for all regions
- 1.12 Ensure credentials unused for 45 days or greater are disabled
<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 0.12 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_cis-level-1"></a> [cis-level-1](#module\_cis-level-1) | ./modules/cis-level-1 | n/a |
| <a name="module_cis-level-2"></a> [cis-level-2](#module\_cis-level-2) | ./modules/cis-level-2 | n/a |
| <a name="module_soc2"></a> [soc2](#module\_soc2) | ./modules/soc2 | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alarm_namespace"></a> [alarm\_namespace](#input\_alarm\_namespace) | Namespace for CloudWatch Alarm Metric | `string` | `"CISBenchmark"` | no |
| <a name="input_alerting_enabled"></a> [alerting\_enabled](#input\_alerting\_enabled) | Enable alerting | `bool` | `true` | no |
| <a name="input_audit_log_bucket_custom_policy_json"></a> [audit\_log\_bucket\_custom\_policy\_json](#input\_audit\_log\_bucket\_custom\_policy\_json) | Override cusom policy for S3 Logging bucket | `string` | `""` | no |
| <a name="input_check_level"></a> [check\_level](#input\_check\_level) | CIS level-2 checks deployment | `string` | `""` | no |
| <a name="input_cloudtrail_event_selector_type"></a> [cloudtrail\_event\_selector\_type](#input\_cloudtrail\_event\_selector\_type) | Types of events that will be aggregated in CloudTrail | `string` | `"All"` | no |
| <a name="input_cloudtrail_kms_policy"></a> [cloudtrail\_kms\_policy](#input\_cloudtrail\_kms\_policy) | KMS policy for Cloudtrail Logs | `string` | `""` | no |
| <a name="input_cloudwatch_logs_kms_id"></a> [cloudwatch\_logs\_kms\_id](#input\_cloudwatch\_logs\_kms\_id) | KMS key for CloudWatch Logs Encryption | `string` | `""` | no |
| <a name="input_config_enabled"></a> [config\_enabled](#input\_config\_enabled) | Set it to true to enable AWS Config | `bool` | `true` | no |
| <a name="input_cron_expression"></a> [cron\_expression](#input\_cron\_expression) | Expession to trigger lambda function regularly on the schedule | `string` | `"cron(0 22 1,10,20,28 * ? 2023)"` | no |
| <a name="input_cw_log_enabled"></a> [cw\_log\_enabled](#input\_cw\_log\_enabled) | Set it to true to aggregate logs on CloudWatch | `bool` | `true` | no |
| <a name="input_disable_unused_cred_45_days"></a> [disable\_unused\_cred\_45\_days](#input\_disable\_unused\_cred\_45\_days) | It will disable cred for more than 45 days | `bool` | `false` | no |
| <a name="input_disable_unused_cred_90_days"></a> [disable\_unused\_cred\_90\_days](#input\_disable\_unused\_cred\_90\_days) | It will deactivate the newly created active access key | `bool` | `false` | no |
| <a name="input_email"></a> [email](#input\_email) | Email address that can receive notifications from Amazon SNS | `string` | `""` | no |
| <a name="input_enable_guard_duty"></a> [enable\_guard\_duty](#input\_enable\_guard\_duty) | This will enable guard duty | `bool` | `true` | no |
| <a name="input_enable_security_hub"></a> [enable\_security\_hub](#input\_enable\_security\_hub) | This will security hub | `bool` | `true` | no |
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

No outputs.
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
