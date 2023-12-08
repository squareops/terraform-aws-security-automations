# SOC 2 Compliance checks

This repository contains checks to assess the security compliance of your AWS environment based on the service organisation control 2 (soc2). It outlines the controls we have implemented to meet the requirements of SOC 2.

## Introduction

SOC 2 (Service Organization Control 2) is a widely recognized framework for assessing the security, availability, processing integrity, confidentiality, and privacy of systems and data. This repository serves as a central source of information regarding our SOC 2 compliance.

## Checks covered

We have developed a set of checks using infrastructure-as-code (IAC). These checks assess various AWS services and resources to ensure they are configured according to soc2 requirements.

- Guardduty is enabled.
- ACM certificates expiration check.
- Security hub is enabled.
- EC2 instance managed by ssm.
- Cloudwatch log group retention policy specific days enabled.
- Cloudwatch log group kms encryption enabled.
- Dynamodb tables point in time recovery enable.
- EFS have backup enabled.
- Elastic load balancer logging enabled.
- EC2 instance imdsv2 enabled.
- RDS instance deletion protection is enabled.

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
| [aws_guardduty_detector.gd](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_detector) | resource |
| [aws_guardduty_publishing_destination.gd_destination](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/guardduty_publishing_destination) | resource |
| [aws_kms_key.gd_key](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/kms_key) | resource |
| [aws_s3_bucket.gd_bucket](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket) | resource |
| [aws_s3_bucket_lifecycle_configuration.bucket-config](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_lifecycle_configuration) | resource |
| [aws_s3_bucket_policy.gd_bucket_policy](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/s3_bucket_policy) | resource |
| [aws_securityhub_account.security-hub](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_account) | resource |
| [aws_securityhub_standards_subscription.cis_v1](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_standards_subscription) | resource |
| [aws_securityhub_standards_subscription.cis_v1_2](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_standards_subscription) | resource |
| [aws_securityhub_standards_subscription.cis_v1_4](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_standards_subscription) | resource |
| [aws_securityhub_standards_subscription.nist_800_53](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_standards_subscription) | resource |
| [aws_securityhub_standards_subscription.pci_321](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_standards_subscription) | resource |
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.bucket_pol](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_iam_policy_document.kms_pol](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_enable_guard_duty"></a> [enable\_guard\_duty](#input\_enable\_guard\_duty) | This will enable guard duty | `bool` | `true` | no |
| <a name="input_enable_security_hub"></a> [enable\_security\_hub](#input\_enable\_security\_hub) | This will enable security hub | `bool` | `true` | no |
| <a name="input_name"></a> [name](#input\_name) | Prefix for all the resources | `string` | `""` | no |
| <a name="input_region"></a> [region](#input\_region) | AWS Region | `string` | `"us-east-2"` | no |
| <a name="input_s3_object_expiration_days"></a> [s3\_object\_expiration\_days](#input\_s3\_object\_expiration\_days) | Number of days after which object of s3 expires | `string` | `"90"` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_guardduty_bucket_arn"></a> [guardduty\_bucket\_arn](#output\_guardduty\_bucket\_arn) | S3 bucket for storing guardduty findings. |
| <a name="output_guardduty_bucket_id"></a> [guardduty\_bucket\_id](#output\_guardduty\_bucket\_id) | S3 bucket for storing guardduty findings. |
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
