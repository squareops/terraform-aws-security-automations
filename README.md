# AWS Security Check

Welcome to the AWS Security Checks Module! This module is designed to perform security compliance checks on AWS accounts according to the CIS Level 1, CIS Level 2, and SOC 2 frameworks. It helps ensure that your AWS infrastructure aligns with these security standards.

## Introduction

The AWS Security Checks Module is a powerful tool for automating the process of auditing and validating AWS accounts against common security benchmarks. It provides a structured framework for performing CIS Level 1, CIS Level 2, and SOC 2 compliance checks.

## Important note

For acheiving 100% compliant for AWS Infrastructure we need to perform some manual checks which are listed in the respective directory of cis-levels.

For encrypting cloudwatch log group of cloudtrail please use this KMS key policy. Please change the account id and region.

```
{
    "Version": "2012-10-17",
    "Id": "allow-cloudwatch-logs-encryption",
    "Statement": [
        {
            "Sid": "AllowRootFullPermissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::12345678:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "AllowCloudWatchLogsEncryption",
            "Effect": "Allow",
            "Principal": {
                "Service": "logs.us-east-2.amazonaws.com"
            },
            "Action": [
                "kms:Encrypt*",
                "kms:Decrypt*",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:Describe*"
            ],
            "Resource": "*"
        }
    ]
}
```
## Features

- Pre-configured checks for CIS Level 1, CIS Level 2, and SOC 2 security benchmarks.
- Organized folder structure for easy navigation and maintenance.
- Customizable configurations to adapt to different environments.
- Automated and repeatable security assessment process.

## Directory Structure

The module is organized into the following directory:

- `cis-level-1`: Contains code for CIS Level 1 compliance checks.
- `cis-level-2`: Contains code for CIS Level 2 compliance checks.
- `soc2`: Contains code for SOC 2 compliance checks.
- `examples`: Contains example scripts to call compliance checks based on the desired level.

Each folder contains configuration files specific to the corresponding security framework.

## Getting Started

To get started with the AWS Security Checks Module, follow these steps:

1. Clone the repository to your local machine: `git clone https://sq-ia//terraform-aws-cis-level1.git`
2. Navigate to the desired framework folder (`cis-level-1`, `cis-level-2`, or `soc2`).
3. Review the documentation for each check to understand its purpose and requirements.

## Usage

The `examples` folder contains terraform code to call compliance checks based on the desired level:

- To perform CIS Level 1, Level 2 and soc2 check input the value of variable `check_level`. Please refer the below example.

``` bash

module "cis" {

  source = "../../"

  name                                = "skaf"
  region                              = "us-east-1"
  email                               = "skaf-demo@squareops.com"
  cron_expression                     = "cron(0 22 1,10,20,28 * ? 2023)"
  check_level                         = ["level-1", "level-2", "soc2"] ##Enter check level (level-1 or level-2 or soc2)
  s3_enabled                          = true
  config_enabled                      = true
  include_global_resource_types       = true
  cw_log_enabled                      = true
  alerting_enabled                    = true
  multiple_access_key_notification    = true
  multiple_access_key_deactivate      = false
  disable_unused_credentials            = true
  disable_unused_credentials_after_days = 90
  remove_ssl_tls_iam                  = false
  enable_guard_duty                   = true
  enable_security_hub                 = true
  enable_aws_macie                    = true
  mfa_iam_group_name                  = "mfa-group" ## enter your IAM user group for mfa
  cloudwatch_logs_kms_key_arn         = "arn:aws:kms:us-east-2:222222222222:key/kms_key_arn" ## enter kms key arn for encrypting cloudwatch log group of cloud trail
  cloudwatch_log_group_retention_days = 60
}

```

## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | > 1.0.0 |

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

## Contribution & Issue Reporting

To report an issue with a project:

  1. Check the repository's [issue tracker](https://github.com/sq-ia/terraform-aws-cis-level1/issues) on GitHub
  2. Search to see if the issue has already been reported
  3. If you can't find an answer to your question in the documentation or issue tracker, you can ask a question by creating a new issue. Be sure to provide enough context and details so others can understand your problem.

## License

Apache License, Version 2.0, January 2004 (http://www.apache.org/licenses/).

## Support Us

To support a GitHub project by liking it, you can follow these steps:

  1. Visit the repository: Navigate to the [GitHub repository](https://github.com/sq-ia/terraform-aws-cis-level1).

  2. Click the "Star" button: On the repository page, you'll see a "Star" button in the upper right corner. Clicking on it will star the repository, indicating your support for the project.

  3. Optionally, you can also leave a comment on the repository or open an issue to give feedback or suggest changes.

Starring a repository on GitHub is a simple way to show your support and appreciation for the project. It also helps to increase the visibility of the project and make it more discoverable to others.

## Who we are

We believe that the key to success in the digital age is the ability to deliver value quickly and reliably. That’s why we offer a comprehensive range of DevOps & Cloud services designed to help your organization optimize its systems & Processes for speed and agility.

  1. We are an AWS Advanced consulting partner which reflects our deep expertise in AWS Cloud and helping 100+ clients over the last 5 years.
  2. Expertise in Kubernetes and overall container solution helps companies expedite their journey by 10X.
  3. Infrastructure Automation is a key component to the success of our Clients and our Expertise helps deliver the same in the shortest time.
  4. DevSecOps as a service to implement security within the overall DevOps process and helping companies deploy securely and at speed.
  5. Platform engineering which supports scalable,Cost efficient infrastructure that supports rapid development, testing, and deployment.
  6. 24*7 SRE service to help you Monitor the state of your infrastructure and eradicate any issue within the SLA.

We provide [support](https://squareops.com/contact-us/) on all of our projects, no matter how small or large they may be.

To find more information about our company, visit [squareops.com](https://squareops.com/), follow us on [Linkedin](https://www.linkedin.com/company/squareops-technologies-pvt-ltd/), or fill out a [job application](https://squareops.com/careers/). If you have any questions or would like assistance with your cloud strategy and implementation, please don't hesitate to [contact us](https://squareops.com/contact-us/).
<!-- BEGINNING OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | > 1.0.0 |

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
| <a name="input_check_level"></a> [check\_level](#input\_check\_level) | CIS level-2 checks deployment | `list(any)` | `[]` | no |
| <a name="input_cloudtrail_event_selector_type"></a> [cloudtrail\_event\_selector\_type](#input\_cloudtrail\_event\_selector\_type) | Types of events that will be aggregated in CloudTrail | `string` | `"All"` | no |
| <a name="input_cloudtrail_kms_policy"></a> [cloudtrail\_kms\_policy](#input\_cloudtrail\_kms\_policy) | KMS policy for Cloudtrail Logs | `string` | `""` | no |
| <a name="input_cloudwatch_log_group_retention_days"></a> [cloudwatch\_log\_group\_retention\_days](#input\_cloudwatch\_log\_group\_retention\_days) | Enter the number of days in which you want your cloud watch log group for cloudtrail will got expired | `number` | `30` | no |
| <a name="input_cloudwatch_logs_kms_key_arn"></a> [cloudwatch\_logs\_kms\_key\_arn](#input\_cloudwatch\_logs\_kms\_key\_arn) | KMS key for CloudWatch Logs Encryption | `string` | `""` | no |
| <a name="input_config_enabled"></a> [config\_enabled](#input\_config\_enabled) | Set it to true to enable AWS Config | `bool` | `true` | no |
| <a name="input_cron_expression"></a> [cron\_expression](#input\_cron\_expression) | Expession to trigger lambda function regularly on the schedule | `string` | `"cron(0 22 1,10,20,28 * ? 2023)"` | no |
| <a name="input_cw_log_enabled"></a> [cw\_log\_enabled](#input\_cw\_log\_enabled) | Set it to true to aggregate logs on CloudWatch | `bool` | `true` | no |
| <a name="input_disable_unused_credentials"></a> [disable\_unused\_credentials](#input\_disable\_unused\_credentials) | It will disable unused credentials of IAM user | `bool` | `false` | no |
| <a name="input_disable_unused_credentials_after_days"></a> [disable\_unused\_credentials\_after\_days](#input\_disable\_unused\_credentials\_after\_days) | Enter no of days after which unused credentials will be diable | `number` | `"90"` | no |
| <a name="input_email"></a> [email](#input\_email) | Email address that can receive notifications from Amazon SNS | `string` | `""` | no |
| <a name="input_enable_aws_macie"></a> [enable\_aws\_macie](#input\_enable\_aws\_macie) | Enable aws macie | `bool` | `true` | no |
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
| <a name="input_region"></a> [region](#input\_region) | AWS Region | `string` | `"us-east-2"` | no |
| <a name="input_remove_ssl_tls_iam"></a> [remove\_ssl\_tls\_iam](#input\_remove\_ssl\_tls\_iam) | Remove expire ssl tls cert from IAM | `bool` | `false` | no |
| <a name="input_s3_enabled"></a> [s3\_enabled](#input\_s3\_enabled) | Set it true to export logs of CloudTrail to S3 Bucket | `bool` | `true` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags to be used in all the resources | `map(string)` | <pre>{<br>  "key": "AWS_CIS_Benchmark",<br>  "value": "1.2.0"<br>}</pre> | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_access_log_bucket_arn"></a> [access\_log\_bucket\_arn](#output\_access\_log\_bucket\_arn) | S3 bucket for storing audit logs of config. |
| <a name="output_access_log_bucket_id"></a> [access\_log\_bucket\_id](#output\_access\_log\_bucket\_id) | S3 bucket for storing audit logs of config. |
| <a name="output_audit_bucket_arn"></a> [audit\_bucket\_arn](#output\_audit\_bucket\_arn) | S3 bucket for storing audit logs of config. |
| <a name="output_audit_bucket_id"></a> [audit\_bucket\_id](#output\_audit\_bucket\_id) | S3 bucket for storing audit logs of config. |
| <a name="output_sns_topic_arn"></a> [sns\_topic\_arn](#output\_sns\_topic\_arn) | SNS topic arn |
<!-- END OF PRE-COMMIT-TERRAFORM DOCS HOOK -->
