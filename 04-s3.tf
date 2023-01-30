resource "aws_kms_key" "mykey" {
  description             = "This key is used to encrypt bucket objects"
  deletion_window_in_days = local.window_in_days
}

resource "aws_s3_bucket" "bucket" {
  bucket = local.s3
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.mykey.arn
        sse_algorithm     = local.sse_algorithm
      }
    }
  }
}


resource "aws_s3_bucket_acl" "example" {
  bucket = aws_s3_bucket.bucket.id
  acl    = local.acl
}


resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}


resource "aws_iam_role" "deny-http" {
  name = local.s3role

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "s3.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_policy" "http-deny" {
  name = local.s3policy

  policy = <<POLICY
{
    "Id": "ExamplePolicy",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AllowSSLRequestsOnly",
            "Action": "s3:*",
            "Effect": "Deny",
            "Resource": [
                "arn:aws:s3:::${local.s3}",
                "arn:aws:s3:::${local.s3}/*"
            ],
            "Condition": {
                "Bool": {
                     "aws:SecureTransport": "false"
                }
            },
           "Principal": "*"
        }
    ]
}
POLICY
}


resource "aws_iam_policy" "blockpublic" {
  name = "BlockS3PublicAccess"

  policy = <<POLICY
{
  "Id": "Example",
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BlockPublicAccess",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Effect": "Allow",
      "Resource": "arn:aws:s3:::${local.s3}/*",
      "Principal": { "AWS": "${local.arn}" } 
    }
  ]
}
POLICY
}
resource "aws_iam_role_policy_attachment" "http-deny" {
  role       = aws_iam_role.deny-http.name
  policy_arn = aws_iam_policy.http-deny.arn
}

resource "aws_iam_role_policy_attachment" "blockpublic" {
  role       = aws_iam_role.deny-http.name
  policy_arn = aws_iam_policy.blockpublic.arn
}
