data "aws_iam_policy_document" "enforce_mfa" {
  statement {
    sid    = "DenyAllExceptListedIfNoMFA"
    effect = "Deny"
    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:ResyncMFADevice",
      "sts:GetSessionToken"
    ]
    resources = ["*"]
    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false", ]
    }
  }
}

resource "aws_iam_policy" "enforce_mfa" {
  name        = "enforce-to-use-mfa"
  path        = "/"
  description = "Policy to allow MFA management"
  policy      = data.aws_iam_policy_document.enforce_mfa.json
}

