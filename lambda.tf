resource "aws_iam_role" "lambda_role" {
  name = "lambda_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_policy" {
  name        = "lambda_policy"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow",
        Action = [
            "iam:GetAccountSummary",
            "iam:ListPolicies",
            "iam:ListAttachedUserPolicies",
            "iam:ListUserPolicies",
            "iam:ListUsers",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:CreatePolicyVersion",
            "iam:DetachUserPolicy",
            "iam:DeleteUserPolicy",
            "iam:ListAccessKeys",
            "iam:GetAccountPasswordPolicy",
            "iam:UpdateAccessKey",
            "iam:UpdateLoginProfile",
            "iam:ListGroups",
            "iam:ListAttachedGroupPolicies",
            "iam:AttachGroupPolicy",
            "ec2:DescribeSecurityGroups",
            "ec2:DescribeSecurityGroupRules",
            "ec2:AuthorizeSecurityGroupIngress",
            "ec2:RevokeSecurityGroupIngress",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:RevokeSecurityGroupEgress",
            "ec2:ModifySecurityGroupRules",
            "SNS:Publish"
        ],
        Resource = "*"
        }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_role_policy" {
  policy_arn = aws_iam_policy.lambda_policy.arn
  role       = aws_iam_role.lambda_role.name
}

resource "aws_cloudwatch_event_rule" "lambda_trigger" {
  name        = "lambda_trigger"
  description = "Trigger for lambda function"
  schedule_expression = "cron(0 22 5,10,15,20,25 * ? 2023)"
}

# 1.2  Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password

resource "aws_iam_policy" "mfa_policy" {
  name        = "mfa_policy"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [
      {
        Sid     = "AllowAllUsersToListAccounts"
        Effect  = "Allow"
        Action  = [
          "iam:ListAccountAliases",
          "iam:ListUsers",
          "iam:GetAccountPasswordPolicy",
          "iam:GetAccountSummary",
        ]
        Resource = "*"
      },
      {
        Sid     = "AllowIndividualUserToSeeAndManageOnlyTheirOwnAccountInformation"
        Effect  = "Allow"
        Action  = [
          "iam:ChangePassword",
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile",
          "iam:DeleteAccessKey",
          "iam:DeleteLoginProfile",
          "iam:GetLoginProfile",
          "iam:ListAccessKeys",
          "iam:UpdateAccessKey",
          "iam:UpdateLoginProfile",
          "iam:ListSigningCertificates",
          "iam:DeleteSigningCertificate",
          "iam:UpdateSigningCertificate",
          "iam:UploadSigningCertificate",
          "iam:ListSSHPublicKeys",
          "iam:GetSSHPublicKey",
          "iam:DeleteSSHPublicKey",
          "iam:UpdateSSHPublicKey",
          "iam:UploadSSHPublicKey",
        ]
        Resource = "arn:aws:iam::*:user/$${aws:username}"
      },
      {
        Sid     = "AllowIndividualUserToListOnlyTheirOwnMFA"
        Effect  = "Allow"
        Action  = [
          "iam:ListVirtualMFADevices",
          "iam:ListMFADevices",
        ]
        Resource = [
          "arn:aws:iam::*:mfa/*",
          "arn:aws:iam::*:user/$${aws:username}",
        ]
      },
      {
        Sid     = "AllowIndividualUserToManageTheirOwnMFA"
        Effect  = "Allow"
        Action  = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
        ]
        Resource = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}",
        ]
      },
      {
        Sid       = "AllowIndividualUserToDeactivateOnlyTheirOwnMFAOnlyWhenUsingMFA"
        Effect    = "Allow"
        Action    = [
          "iam:DeactivateMFADevice",
        ]
        Resource  = [
          "arn:aws:iam::*:mfa/$${aws:username}",
          "arn:aws:iam::*:user/$${aws:username}",
        ]
        Condition = {
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      },
      {
        Sid        = "BlockMostAccessUnlessSignedInWithMFA"
        Effect     = "Deny"
        NotAction  = [
          "iam:CreateVirtualMFADevice",
          "iam:DeleteVirtualMFADevice",
          "iam:ListVirtualMFADevices",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:ListAccountAliases",
          "iam:ListUsers",
          "iam:ListSSHPublicKeys",
          "iam:ListAccessKeys",
          "iam:ListServiceSpecificCredentials",
          "iam:ListMFADevices",
          "iam:GetAccountSummary",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}
         

data "template_file" "lambda_function_script_mfa_user" {
  template = file("${path.module}/lambda_code/1.2_mfa_all_user.py")
  vars = {
    policy_arn = aws_iam_policy.mfa_policy.arn,
  }
}
resource "local_file" "lambda_code_mfa_user" {
  content  = data.template_file.lambda_function_script_mfa_user.rendered
  filename = "${path.module}/rendered/mfa-all-user.py"
}

data "archive_file" "lambda_zip_mfa_user" {
  depends_on  = [local_file.lambda_code_mfa_user]
  type        = "zip"
  source_dir  = "${path.module}/rendered/"
  output_path = "${path.module}/lambda_mfa_user.zip"
}

resource "aws_lambda_function" "lambda_function_mfa_user" {
  filename         = data.archive_file.lambda_zip_mfa_user.output_path
  function_name    = "mfa_user"
  role             = aws_iam_role.lambda_role.arn
  handler          = "mfa-all-user.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip_mfa_user.output_base64sha256
  runtime          = "python3.8"
  timeout          = 180
  memory_size      = 256
}

resource "aws_lambda_permission" "lambda_permission_mfa_user" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function_mfa_user.arn
  principal     = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.lambda_trigger_mfa_user.arn
}

resource "aws_cloudwatch_event_rule" "lambda_trigger_mfa_user" {
  name        = "lambda_trigger_mfa_user"
  description = "Trigger for lambda function"
  schedule_expression = "cron(0 22 5,10,15,20,25 * ? 2023)"
}

resource "aws_cloudwatch_event_target" "lambda_target_mfa_user" {
  rule      = aws_cloudwatch_event_rule.lambda_trigger_mfa_user.name
  arn       = aws_lambda_function.lambda_function_mfa_user.arn
  target_id = "lambda_target_mfa_user"
}

# 1.3 Ensure credentials unused for 90 days or greater are disabled
# 1.4 Ensure access keys are rotated every 90 days or less
data "template_file" "lambda_function_script_user_cred" {
  template = file("${path.module}/lambda_code/1.3_disable_user_cred.py")
}
resource "local_file" "lambda_code_user_cred" {
  content  = data.template_file.lambda_function_script_user_cred.rendered
  filename = "${path.module}/rendered/user-cred.py"
}

data "archive_file" "lambda_zip_user_cred" {
  depends_on  = [local_file.lambda_code_user_cred]
  type        = "zip"
  source_dir  = "${path.module}/rendered/"
  output_path = "${path.module}/lambda_user_cred.zip"
}

resource "aws_lambda_function" "lambda_function_user_cred" {
  filename         = data.archive_file.lambda_zip_user_cred.output_path
  function_name    = "user_cred"
  role             = aws_iam_role.lambda_role.arn
  handler          = "user-cred.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip_user_cred.output_base64sha256
  runtime          = "python3.8"
  timeout          = 180
  memory_size      = 256
}

resource "aws_lambda_permission" "lambda_permission_user_cred" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function_user_cred.arn
  principal     = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.lambda_trigger_user_cred.arn
}

resource "aws_cloudwatch_event_rule" "lambda_trigger_user_cred" {
  name        = "lambda_trigger_user_cred"
  description = "Trigger for lambda function"
  schedule_expression = "cron(0 22 5,10,15,20,25 * ? 2023)"
}

resource "aws_cloudwatch_event_target" "lambda_target_user_cred" {
  rule      = aws_cloudwatch_event_rule.lambda_trigger_user_cred.name
  arn       = aws_lambda_function.lambda_function_user_cred.arn
  target_id = "lambda_target_user_cred"
}

# 1.16 Ensure IAM policies are attached only to groups or roles
data "template_file" "lambda_function_script_direct_policy" {
  template = file("${path.module}/lambda_code/1.16-remove-direct-policy.py")
}
resource "local_file" "lambda_code_direct_policy" {
  content  = data.template_file.lambda_function_script_direct_policy.rendered
  filename = "${path.module}/rendered/remove-direct-policy.py"
}

data "archive_file" "lambda_zip_direct_policy" {
  depends_on  = [local_file.lambda_code_direct_policy]
  type        = "zip"
  source_dir  = "${path.module}/rendered/"
  output_path = "${path.module}/lambda_direct_policy.zip"
}

resource "aws_lambda_function" "lambda_function_direct_policy" {
  filename         = data.archive_file.lambda_zip_direct_policy.output_path
  function_name    = "direct_policy"
  role             = aws_iam_role.lambda_role.arn
  handler          = "remove-direct-policy.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip_direct_policy.output_base64sha256
  runtime          = "python3.8"
  timeout          = 180
  memory_size      = 256
}

resource "aws_lambda_permission" "lambda_permission_direct_policy" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function_direct_policy.arn
  principal     = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.lambda_trigger_direct_policy.arn
}

resource "aws_cloudwatch_event_rule" "lambda_trigger_direct_policy" {
  name        = "lambda_trigger_direct_policy"
  description = "Trigger for lambda function"
  schedule_expression = "cron(0 22 5,10,15,20,25 * ? 2023)"
}

resource "aws_cloudwatch_event_target" "lambda_target_direct_policy" {
  rule      = aws_cloudwatch_event_rule.lambda_trigger_direct_policy.name
  arn       = aws_lambda_function.lambda_function_direct_policy.arn
  target_id = "lambda_target_direct_policy"
}

# 1.22 Ensure IAM policies that allow full "*:*" administrative privileges are not created
data "template_file" "lambda_function_script_admin_policy" {
  template = file("${path.module}/lambda_code/1.22_admin_policy.py")
  vars = {
    sns_topic_arn = aws_sns_topic.trail-unauthorised.arn,
  }
}
resource "local_file" "lambda_code_admin_policy" {
  content  = data.template_file.lambda_function_script_admin_policy.rendered
  filename = "${path.module}/rendered/admin-policy.py"
}

data "archive_file" "lambda_zip_admin_policy" {
  depends_on  = [local_file.lambda_code_admin_policy]
  type        = "zip"
  source_dir  = "${path.module}/rendered/"
  output_path = "${path.module}/lambda_admin_policy.zip"
}

resource "aws_lambda_function" "lambda_function_admin_policy" {
  filename         = data.archive_file.lambda_zip_admin_policy.output_path
  function_name    = "admin_policy"
  role             = aws_iam_role.lambda_role.arn
  handler          = "admin-policy.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip_admin_policy.output_base64sha256
  runtime          = "python3.8"
  timeout          = 180
  memory_size      = 256
}

resource "aws_lambda_permission" "lambda_permission_admin_policy" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function_admin_policy.arn
  principal     = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.lambda_trigger_admin_policy.arn
}

resource "aws_cloudwatch_event_rule" "lambda_trigger_admin_policy" {
  name        = "lambda_trigger_admin_policy"
  description = "Trigger for lambda function"
  schedule_expression = "cron(0 22 5,10,15,20,25 * ? 2023)"
}

resource "aws_cloudwatch_event_target" "lambda_target_admin_policy" {
  rule      = aws_cloudwatch_event_rule.lambda_trigger_admin_policy.name
  arn       = aws_lambda_function.lambda_function_admin_policy.arn
  target_id = "lambda_target_admin_policy"
}

# 4.1 Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to port 22


data "template_file" "lambda_function_script_remove_port_22" {
  template = file("${path.module}/lambda_code/4.1_remove_port_22.py")
}
resource "local_file" "lambda_code_remove_port_22" {
  content  = data.template_file.lambda_function_script_remove_port_22.rendered
  filename = "${path.module}/rendered/remove-port-22.py"
}

data "archive_file" "lambda_zip_remove_port_22" {
  depends_on  = [local_file.lambda_code_remove_port_22]
  type        = "zip"
  source_dir  = "${path.module}/rendered/"
  output_path = "${path.module}/lambda_remove_port_22.zip"
}

resource "aws_lambda_function" "lambda_function_remove_port_22" {
  filename         = data.archive_file.lambda_zip_remove_port_22.output_path
  function_name    = "port_22"
  role             = aws_iam_role.lambda_role.arn
  handler          = "remove-port-22.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip_remove_port_22.output_base64sha256
  runtime          = "python3.8"
  timeout          = 180
  memory_size      = 256
}

resource "aws_lambda_permission" "lambda_permission_remove_port_22" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function_remove_port_22.arn
  principal     = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.lambda_trigger_remove_port_22.arn
}

resource "aws_cloudwatch_event_rule" "lambda_trigger_remove_port_22" {
  name        = "lambda_trigger_remove_port_22"
  description = "Trigger for lambda function"
  schedule_expression = "cron(0 22 5,10,15,20,25 * ? 2023)"
}

resource "aws_cloudwatch_event_target" "lambda_target_remove_port_22" {
  rule      = aws_cloudwatch_event_rule.lambda_trigger_remove_port_22.name
  arn       = aws_lambda_function.lambda_function_remove_port_22.arn
  target_id = "lambda_target_remove_port_22"
}


# 4.2 Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to port 3389


data "template_file" "lambda_function_script_remove_port_3389" {
  template = file("${path.module}/lambda_code/4.2_remove_port_3389.py")
}
resource "local_file" "lambda_code_remove_port_3389" {
  content  = data.template_file.lambda_function_script_remove_port_3389.rendered
  filename = "${path.module}/rendered/remove-port-3389.py"
}

data "archive_file" "lambda_zip_remove_port_3389" {
  depends_on  = [local_file.lambda_code_remove_port_3389]
  type        = "zip"
  source_dir  = "${path.module}/rendered/"
  output_path = "${path.module}/lambda_remove_port_3389.zip"
}

resource "aws_lambda_function" "lambda_function_remove_port_3389" {
  filename         = data.archive_file.lambda_zip_remove_port_3389.output_path
  function_name    = "port_3389"
  role             = aws_iam_role.lambda_role.arn
  handler          = "remove-port-3389.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip_remove_port_3389.output_base64sha256
  runtime          = "python3.8"
  timeout          = 180
  memory_size      = 256
}

resource "aws_lambda_permission" "lambda_permission_remove_port_3389" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lambda_function_remove_port_3389.arn
  principal     = "events.amazonaws.com"
  source_arn = aws_cloudwatch_event_rule.lambda_trigger_remove_port_3389.arn
}

resource "aws_cloudwatch_event_rule" "lambda_trigger_remove_port_3389" {
  name        = "lambda_trigger_remove_port_3389"
  description = "Trigger for lambda function"
  schedule_expression = "cron(0 22 5,10,15,20,25 * ? 2023)"
}

resource "aws_cloudwatch_event_target" "lambda_target_remove_port_3389" {
  rule      = aws_cloudwatch_event_rule.lambda_trigger_remove_port_3389.name
  arn       = aws_lambda_function.lambda_function_remove_port_3389.arn
  target_id = "lambda_target_remove_port_3389"
}
