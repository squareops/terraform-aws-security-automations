module "vpc_example_vpc-flow-logs" {
  source  = "terraform-aws-modules/vpc/aws//examples/vpc-flow-logs"
  version = "3.19.0"
}
