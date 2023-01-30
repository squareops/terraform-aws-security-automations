resource "aws_iam_account_password_policy" "pwd" {
  minimum_password_length        = local.password_length
  require_lowercase_characters   = local.lowercase_characters
  require_numbers                = local.require_numbers
  require_uppercase_characters   = local.uppercase_characters
  require_symbols                = local.require_symbols
  allow_users_to_change_password = local.change_password
  max_password_age               = local.password_age
  password_reuse_prevention      = local.reuse_prevention

}
