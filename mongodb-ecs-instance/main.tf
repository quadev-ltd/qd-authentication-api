provider "aws" {
  region = var.aws_region
}

locals {
  instance_name = "mongodb-auth-instance"
}

resource "aws_security_group" "mongodb" {
  name        = "mongodb-sg"
  description = "Allow MongoDB traffic"

  ingress {
    from_port   = 27017
    to_port     = 27017
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "image-type"
    values = ["machine"]
  }

  owners = ["amazon"]
}

resource "aws_instance" "mongodb_instance" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "t2.micro"

  vpc_security_group_ids = [aws_security_group.mongodb.id]

  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name

  tags = {
    Name = local.instance_name
  }

  user_data = <<-EOF
              #!/bin/bash
              sudo yum update -y
              sudo amazon-linux-extras install -y mongodb4.0
              sudo yum install -y mongodb-org-server
              sudo systemctl enable mongod
              sudo systemctl start mongod
              EOF
}

resource "aws_iam_role" "ec2_instance_role" {
  name = "ec2-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-instance-profile"
  role = aws_iam_role.ec2_instance_role.name
}

resource "aws_iam_role_policy" "ec2_instance_policy" {
  name = "ec2-instance-policy"
  role = aws_iam_role.ec2_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "ssm:*"
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}
