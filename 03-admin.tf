resource "aws_iam_group" "administrators" {
  name = local.admin_group_name
  path = "/"
}

data "aws_iam_policy" "administrator_access" {
  name = "AdministratorAccess"
}

resource "aws_iam_group_policy_attachment" "administrators" {
  group      = aws_iam_group.administrators.name
  policy_arn = data.aws_iam_policy.administrator_access.arn
}

resource "aws_iam_user" "administrator" {
  name = local.user
}

resource "aws_iam_user_group_membership" "dev" {
  user   = aws_iam_user.administrator.name
  groups = [aws_iam_group.administrators.name]
}

resource "aws_iam_user_login_profile" "administrator" {
  user                    = aws_iam_user.administrator.name
  password_reset_required = true
}

output "password" {
  value     = aws_iam_user_login_profile.administrator.password
  sensitive = true
}

resource "aws_iam_group_policy_attachment" "enforce_mfa" {
  group      = aws_iam_group.administrators.name
  policy_arn = aws_iam_policy.enforce_mfa.arn
}

