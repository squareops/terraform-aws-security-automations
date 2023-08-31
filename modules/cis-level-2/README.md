# AWS CIS Level 2 Security Compliance Checks

This repository contains automated and manual checks to assess the security compliance of your AWS environment based on the Center for Internet Security (CIS) AWS Foundations Benchmark Level 2.

## Introduction

The CIS AWS Foundations Benchmark provides best practice guidelines for securing your AWS resources. This repository includes a set of automated and manual checks that align with the CIS Level 2 recommendations. These checks help ensure that your AWS environment follows the recommended security configurations.

## Automated checks covered

We have developed a set of automated checks using infrastructure-as-code (IAC). These checks assess various AWS services and resources to ensure they are configured according to CIS Level 2 requirements.

- Ensure AWS Config is enabled in all regions.
- Ensure all S3 buckets employ encryption-at-rest.
- Ensure IAM instance roles are used for AWS resource access from instances.
- Ensure CloudTrail log file validation is enabled.
- Ensure VPC flow logging is enabled in all VPCs.
- Ensure that Object-level logging for write events is enabled for S3 bucket.
- Ensure that Object-level logging for read events is enabled for S3 bucket.
- Ensure S3 Bucket Policy is set to deny HTTP requests.
- Ensure all data in Amazon S3 has been discovered, classified and secured when required.
- Ensure CloudTrail logs are encrypted at rest using KMS CMKs.
- Ensure rotation for customer created symmetric CMKs is enabled.
- Ensure VPC flow logging is enabled in all VPCs.
- Ensure a log metric filter and alarm exist for security group changes.
- Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL).
- Ensure a log metric filter and alarm exist for AWS Management Console authentication failures.
- Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs.
- Ensure a log metric filter and alarm exist for AWS Config configuration changes.

## Manual Checks

In addition to automated checks, this repository provides a list of manual checks that require human validation. These checks cover areas where automated validation might not be feasible or practical.

- Ensure hardware MFA is enabled for the 'root' user account
- Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments.
- Ensure MFA Delete is enabled on S3 buckets.
- Ensure the default security group of every VPC restricts all traffic.
- Ensure routing tables for VPC peering are \"least access\.

<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

No requirements.

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | n/a |

## Modules

No modules.

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_metric_filter.aws_config_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.console_signin_failures](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.disable_or_delete_cmk](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.nacl_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_log_metric_filter.security_group_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_metric_filter) | resource |
| [aws_cloudwatch_metric_alarm.aws_config_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.console_signin_failures](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.disable_or_delete_cmk](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.nacl_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_cloudwatch_metric_alarm.security_group_changes](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_metric_alarm) | resource |
| [aws_config_configuration_recorder.recorder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_recorder) | resource |
| [aws_config_configuration_recorder_status.recorder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_recorder_status) | resource |
| [aws_config_delivery_channel.bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_delivery_channel) | resource |
| [aws_iam_role.recorder](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.recorder_publish_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_iam_role_policy_attachment.recorder_read_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy_attachment) | resource |
| [aws_macie2_account.aws-macie](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/macie2_account) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.recorder_assume_role_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.recorder_publish_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_alarm_namespace"></a> [alarm\_namespace](#input\_alarm\_namespace) | Namespace for CloudWatch Alarm Metric | `string` | `"CISBenchmark"` | no |
| <a name="input_alerting_enabled"></a> [alerting\_enabled](#input\_alerting\_enabled) | Enable alerting | `bool` | `true` | no |
| <a name="input_audit_bucket_arn"></a> [audit\_bucket\_arn](#input\_audit\_bucket\_arn) | s3 bucket arn for audit bucket | `string` | `""` | no |
| <a name="input_audit_bucket_id"></a> [audit\_bucket\_id](#input\_audit\_bucket\_id) | s3 bucket id for audit bucket | `string` | `""` | no |
| <a name="input_cloud_watch_log_group"></a> [cloud\_watch\_log\_group](#input\_cloud\_watch\_log\_group) | cloudwatch log group for metric filter | `string` | `""` | no |
| <a name="input_config_enabled"></a> [config\_enabled](#input\_config\_enabled) | Set it to true to enable AWS Config | `bool` | `true` | no |
| <a name="input_enable_aws_macie"></a> [enable\_aws\_macie](#input\_enable\_aws\_macie) | Enable aws macie | `bool` | `true` | no |
| <a name="input_include_global_resource_types"></a> [include\_global\_resource\_types](#input\_include\_global\_resource\_types) | Set it to true to enable recording of global resources in AWS Config | `bool` | `true` | no |
| <a name="input_name"></a> [name](#input\_name) | Prefix for all the resources | `string` | `""` | no |
| <a name="input_region"></a> [region](#input\_region) | AWS Region | `string` | `"us-east-2"` | no |
| <a name="input_sns_topic_arn"></a> [sns\_topic\_arn](#input\_sns\_topic\_arn) | sns topic for sending notification | `string` | `""` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags to be used in all the resources | `map(string)` | <pre>{<br>  "key": "AWS_CIS_Benchmark",<br>  "value": "1.2.0"<br>}</pre> | no |

## Outputs

No outputs.
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
