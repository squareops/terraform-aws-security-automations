data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

resource "aws_cloudtrail" "test" {
  name                          = "tf-trail-s3"
  s3_bucket_name                = aws_s3_bucket.test.id
  s3_key_prefix                 = "prefix"
  cloud_watch_logs_group_arn    = "${resource.aws_cloudwatch_log_group.example.arn}:*"
  cloud_watch_logs_role_arn     = resource.aws_iam_role.cloudwatch_role.arn
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }
}

resource "aws_s3_bucket" "test" {
  bucket        = "rachit-tf-labs-trail"
  force_destroy = true
}


resource "aws_iam_role" "cloudwatch_role" {
  name = "${local.name}-cloudwatch-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "cloudwatch" {
  name = "${local.name}-cloudwatch"
  role = resource.aws_iam_role.cloudwatch_role.id

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {

      "Sid": "AWSCloudTrailCreateLogStream2014110",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogStream"
      ],
      "Resource": [
        "arn:aws:logs:${local.region}:${local.accountID}:log-group:${resource.aws_cloudwatch_log_group.example.name}:log-stream:${resource.aws_cloudwatch_log_stream.test.name}"
      ]
    },
    {
      "Sid": "AWSCloudTrailPutLogEvents20141101",
      "Effect": "Allow",
      "Action": [
        "logs:PutLogEvents"
      ],
      "Resource": [
        "arn:aws:logs:${local.region}:${local.accountID}:log-group:${resource.aws_cloudwatch_log_group.example.name}:log-stream:${resource.aws_cloudwatch_log_stream.test.name}"
      ]
    }
  ]
}
POLICY
}




resource "aws_s3_bucket_policy" "test" {
  bucket = aws_s3_bucket.test.id
  policy = <<POLICY
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "AWSCloudTrailAclCheck",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:GetBucketAcl",
            "Resource": "${aws_s3_bucket.test.arn}"
        },
        {
            "Sid": "AWSCloudTrailWrite",
            "Effect": "Allow",
            "Principal": {
              "Service": "cloudtrail.amazonaws.com"
            },
            "Action": "s3:PutObject",
            "Resource": "${aws_s3_bucket.test.arn}/prefix/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        }
    ]
}
POLICY
}
resource "aws_cloudwatch_log_group" "example" {
  name              = "cloudtrail"
  retention_in_days = 90
}

resource "aws_cloudwatch_log_stream" "test" {
  name           = "${data.aws_caller_identity.current.account_id}_CloudTrail_${data.aws_region.current.name}"
  log_group_name = aws_cloudwatch_log_group.example.name
}