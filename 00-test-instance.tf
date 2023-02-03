module "vpn" {
  source                 = "terraform-aws-modules/ec2-instance/aws"
  version                = "~> 3.0"
  name                   = local.name
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = local.instance_type
  vpc_security_group_ids = [aws_security_group.pritunl-sg.id]
  subnet_id              = element(module.vpc.public_subnets, 0)
  monitoring             = true 

  tags = {
    Environment = local.env
    Owner       = local.Owner
  }
}
############### Filter Amazon Images For Ubuntu20.04 ###############




data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  owners = ["amazon"]
}

################ security group for pritunl ######################



resource "aws_security_group" "pritunl-sg" {
  name   = "${local.name}-vpn-sg"
  vpc_id = module.vpc.vpc_id
  ingress {
    description = "TLS from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "TLS from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "TLS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "TLS from VPC"
    from_port   = 19103
    to_port     = 19103
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    name  = local.name
    Owner = local.Owner
  }
}