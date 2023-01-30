locals {

  password_length      = 16
  lowercase_characters = true
  require_numbers      = true
  uppercase_characters = true
  require_symbols      = true
  change_password      = true
  password_age         = 90
  reuse_prevention     = 24
  signing_certificates = true
  ssh_public_keys      = true
  git_credentials      = true
  env                  = "dev"
  admin_group_name     = "Administrators"
  user                 = "admin"
  s3policy             = "deny-http"
  s3role               = "s3-deny-http"
  window_in_days       = 10
  s3                   = "squareops-cis"
  acl                  = "private"
  sse_algorithm        = "aws:kms"
  arn                  = "arn:aws:iam::421320058418:user/rachit-squareops-dev"

}
