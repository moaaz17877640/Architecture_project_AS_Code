#VPC OF ARCHITECTURE
resource "aws_vpc" "architecture_vpc" {
  cidr_block = "10.1.0.0/16"
}
resource "aws_subnet" "public_subnet1" {
  vpc_id     = aws_vpc.architecture_vpc.id
  map_public_ip_on_launch = true
  availability_zone = "eu-north-1a"
  cidr_block = "10.1.1.0/24"

  tags = {
    Name = "public_subnet1"
  }
}

resource "aws_subnet" "public_subnet2" {
  vpc_id     = aws_vpc.architecture_vpc.id
  cidr_block = "10.1.2.0/24"
  availability_zone = "eu-north-1b"
  tags = {
    Name = "public_subnet2"
  }
}

resource "aws_subnet" "private_subnet1" {
  vpc_id     = aws_vpc.architecture_vpc.id
  cidr_block = "10.1.3.0/24"
  availability_zone = "eu-north-1b"
  tags = {
    Name = "private_subnet1"
  }
}

resource "aws_subnet" "private_subnet2" {
  vpc_id     = aws_vpc.architecture_vpc.id
  cidr_block = "10.1.4.0/24"
  availability_zone = "eu-north-1a"
  tags = {
    Name = "private_subnet2"
  }
}

resource "aws_internet_gateway" "lab_igw" {
  vpc_id = aws_vpc.architecture_vpc.id

  tags = {
    Name = "gateway_for_lab"
  }
}


resource "aws_nat_gateway" "gw_nat" {
  allocation_id = aws_eip.eip_nat.id
  subnet_id     = aws_subnet.public_subnet1.id

  tags = {
    Name = "gw NAT"
  }

  # To ensure proper ordering, it is recommended to add an explicit dependency
  # on the Internet Gateway for the VPC.
  # depends_on = [aws_internet_gateway.eip_nat]
  depends_on = [aws_internet_gateway.lab_igw]
}

resource "aws_eip" "eip_nat" {
  domain = "vpc" # Specify that the EIP is for use in a VPC

  tags = {
    Name = "project_eip" # Add a tag for better resource management
  }
}

output "eip_public_ip" {
  description = "The public IP address of the Elastic IP"
  value       = aws_eip.eip_nat.public_ip
}

resource "aws_route_table" "publicvpc_route_table" {
  vpc_id = aws_vpc.architecture_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab_igw.id
  }
  tags = {
    Name = "public route table"
  }
}

resource "aws_route_table" "privatevpc_route_table" {
  vpc_id = aws_vpc.architecture_vpc.id

  tags = {
    Name = "private route table"
  }
}

resource "aws_route_table_association" "ass_public_subnet1" {
  subnet_id      = aws_subnet.public_subnet1.id
  route_table_id = aws_route_table.publicvpc_route_table.id
}

resource "aws_route_table_association" "ass_public_subnet2" {
  subnet_id      = aws_subnet.public_subnet2.id
  route_table_id = aws_route_table.publicvpc_route_table.id
}

resource "aws_route_table_association" "ass_private_subnet1" {
  subnet_id      = aws_subnet.private_subnet1.id
  route_table_id = aws_route_table.privatevpc_route_table.id
}

resource "aws_route_table_association" "ass_private_subnet2" {
  subnet_id      = aws_subnet.private_subnet2.id
  route_table_id = aws_route_table.privatevpc_route_table.id
}

#security group for public subnets
resource "aws_security_group" "public_security_group_v2" {
  name        = "allow_tls"
  description = "Allow TLS inbound traffic and all outbound traffic"
  vpc_id      = aws_vpc.architecture_vpc.id

  tags = {
    Name = "public security group"
  }
}

#inbound rules for security group in same vpc
resource "aws_security_group_rule" "inbound_rule_1" {
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.architecture_vpc.cidr_block]
  #ipv6_cidr_blocks  = [aws_vpc.architecture_vpc.ipv6_cidr_block]
  security_group_id = aws_security_group.public_security_group_v2.id
}
#http rule from anywhere inbound
resource "aws_vpc_security_group_ingress_rule" "inbound_rule_2" {
  security_group_id = aws_security_group.public_security_group_v2.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
}
#https rule from anywhere inbound
resource "aws_vpc_security_group_ingress_rule" "inbound_rule_3" {
  security_group_id = aws_security_group.public_security_group_v2.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}
#`ssh rule from anywhere inbound
resource "aws_vpc_security_group_ingress_rule" "inbound_rule_4" {
  security_group_id = aws_security_group.public_security_group_v2.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
}


#outbound rules for security group for public subnets
resource "aws_vpc_security_group_egress_rule" "outbound_rule_1" {
  security_group_id = aws_security_group.public_security_group_v2.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 0
  ip_protocol       = "tcp"
  to_port           = 65535
}

#security group for pruvate subnets
resource "aws_security_group" "private_security_group" {
  name        = "allow_tls_private"
  description = "deny TLS inbound traffic and all outbound traffic expected in same vpc"
  vpc_id      = aws_vpc.architecture_vpc.id

  tags = {
    Name = "private security group"
  }
}

#inbound rules(sql/aurora) for security group in same vpc
resource "aws_security_group_rule" "inbound_rule_5" {
  type              = "ingress"
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  cidr_blocks       = [aws_vpc.architecture_vpc.cidr_block]
  #ipv6_cidr_blocks  = [aws_vpc.architecture_vpc.ipv6_cidr_block]
  security_group_id = aws_security_group.private_security_group.id
}


#sql rule from anywhere inbound
#need edit 
resource "aws_vpc_security_group_ingress_rule" "inbound_rule_6" {
  security_group_id = aws_security_group.private_security_group.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 3306
  ip_protocol       = "tcp"
  to_port           = 3306
  description       = "allow mysql traffic"
}

resource "aws_vpc_security_group_egress_rule" "outbound_rule_2" {
  security_group_id = aws_security_group.private_security_group.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 3306
  ip_protocol       = "tcp"
  to_port           = 3306
}
#outbound rules for security group for public subnets
#######################################################################################
#autoscaling group
# resource "aws_placement_group" "placement_group" {
#   name     = "test"
#   strategy = "cluster"
# }

# data "aws_ami" "ubuntu" {
#   most_recent = true
#   owners      = ["099720109477"]
#   filter {
#     name   = "name"
#     values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
#   }

#   filter {
#     name   = "virtualization-type"
#     values = ["hvm"]
#   }

#   # Canonical
# }

resource "aws_launch_template" "as_template" {
  name          = "web_template"
  image_id      = "ami-000b9845467bba0de"
  instance_type = "t3.micro"
  key_name      = aws_key_pair.my_key_pair.key_name
  iam_instance_profile {
    name = aws_iam_instance_profile.instance_role.name
  }
  user_data = base64encode(<<EOF
    #!/bin/bash
    sudo apt update -y
    sudo apt install -y nginx
    sudo systemctl start nginx
    sudo systemctl enable nginx
  EOF
  )

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.public_security_group_v2.id]
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "web-instance"
    }
  }
}

resource "aws_autoscaling_group" "bar" {
  name                      = "foobar3-terraform-test"
  max_size                  = 3
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 2
  force_delete              = true
  
  #wait_for_capacity_timeout = "20m"
  
  #placement_group           = aws_placement_group.placement_group.id
  launch_template {
    id      = aws_launch_template.as_template.id
    version = "$Latest"
  }
  vpc_zone_identifier       = [aws_subnet.public_subnet1.id, aws_subnet.public_subnet2.id]
  target_group_arns         = [aws_lb_target_group.project_target_group.arn]

#   instance_maintenance_policy {
#     min_healthy_percentage = 90
#     max_healthy_percentage = 120
#   }
# ##################editing v2
# initial_lifecycle_hook {
#   name                 = "foobar"
#   default_result       = "CONTINUE"
#   heartbeat_timeout    = 2000
#   lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"

#   notification_metadata = jsonencode({
#     foo = "bar"
#   })

#   notification_target_arn = aws_sqs_queue.project_queue.arn # Replace with your SQS ARN
#   role_arn                = aws_iam_role.asg_lifecycle_role.arn # Use the IAM role created above
# }
# ##################editing v2
  tag {
    key                 = "foo"
    value               = "bar"
    propagate_at_launch = true
  }
  lifecycle {
    ignore_changes = [ desired_capacity ]
  }

  # timeouts block removed as it is not valid for aws_autoscaling_group
  
  tag {
    key                 = "lorem"
    value               = "ipsum"
    propagate_at_launch = false
  }
}
######################################################################################
resource "aws_autoscaling_policy" "scale_up" {
  name                   = "scale-up"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.bar.name
}

resource "aws_autoscaling_policy" "scale_down" {
  name                   = "scale-down"
  scaling_adjustment     = -1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.bar.name
}

resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 70
  alarm_actions       = [aws_autoscaling_policy.scale_up.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.bar.name
  }
}

resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "low-cpu"
  comparison_operator = "LessThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 30
  alarm_actions       = [aws_autoscaling_policy.scale_down.arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.bar.name
  }
}
#######################################################################################
#RDS
#secret store password of aws rds
resource "aws_kms_key" "rds_key" {
  description = "Example KMS Key"
}

resource "aws_db_instance" "project_db" {
  allocated_storage             = 10
  db_name                       = "mydb"
  engine                        = "mysql"
  engine_version                = "8.0"
  instance_class                = "db.t3.micro"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = aws_kms_key.rds_key.key_id
  username                      = "moaz"
  parameter_group_name          = "default.mysql8.0"
}
#######################################################################################
#LOAD BALANCER
resource "aws_lb" "project_load_balancer" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.public_security_group_v2.id]
  subnets            = [aws_subnet.public_subnet1.id, aws_subnet.public_subnet2.id]
  
  

  enable_deletion_protection = true

  # access_logs {
  #   bucket  = aws_s3_bucket.lb_logs.bucket
  #   prefix  = "test-lb"
  #   enabled = true
  # }
  

  tags = {
    Environment = "production"
  }
}

resource "aws_s3_bucket" "project_date_bucket" {
  bucket = "project-date-bucket-moaz-elmahi" # Add a random suffix
  tags = {
    Name        = "Load Balancer Logs"
    Environment = "Dev"
  }
}

# resource "random_id" "bucket_suffix" {
#   byte_length = 4
#}
# data "aws_caller_identity" "current" {}

# resource "aws_s3_bucket_policy" "lb_logs_policy" {
#   bucket = aws_s3_bucket.lb_logs.id

#   policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Effect = "Allow"
#         Principal = {
#           Service = "delivery.logs.amazonaws.com"
#         }
#         Action = [
#           "s3:PutObject",
#           "s3:GetBucketAcl"
#         ]
#         Resource = "${aws_s3_bucket.lb_logs.arn}/*"
#         Condition = {
#           StringEquals = {
#             "s3:x-amz-acl" = "bucket-owner-full-control"
#           }
#         }
#       },
#       {
#         Effect = "Allow"
#         Principal = {
#           AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
#         }
#         Action = [
#           "s3:PutObject",
#           "s3:GetObject",
#           "s3:ListBucket"
#         ]
#         Resource = [
#           "${aws_s3_bucket.lb_logs.arn}",
#           "${aws_s3_bucket.lb_logs.arn}/*"
#         ]
#       }
#     ]
#   })
# }

resource "aws_lb_target_group" "project_target_group" {
  name     = "tf-example-lb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.architecture_vpc.id
  health_check {
    path ="/"
    protocol = "HTTP"
    port = "80"
  }
}

resource "aws_lb_listener" "front_end" {
  load_balancer_arn = aws_lb.project_load_balancer.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.project_target_group.arn
  }
}
resource "aws_eip" "network_interface_ip" {
  domain = "vpc"
}
###error of ips  need to edit
# resource "aws_network_interface" "nci" {
#   subnet_id   = aws_subnet.public_subnet1.id
#   tags = {
#     Name = "primary_network_interface"
#   }
# }

resource "aws_instance" "project_instance" {
  tags = {
    name = "web-instance"
  }
  ami                         = "ami-000b9845467bba0de" # us-west-2
  instance_type               = "t3.micro"
  #associate_public_ip_address = true
  key_name                    = aws_key_pair.my_key_pair.key_name
  subnet_id = aws_subnet.public_subnet1.id
  #security_groups = [aws_security_group.public_security_group_v2.id]
  vpc_security_group_ids = [aws_security_group.public_security_group_v2.id]
  user_data              = <<EOF
    #!/bin/bash
    sudo apt update -y
    sudo apt install -y nginx
    sudo systemctl start nginx
    sudo systemctl enable nginx
  EOF
  # network_interface {
  #   network_interface_id = aws_network_interface.nci.id
  #   device_index         = 0
  #}

  credit_specification {
    cpu_credits = "unlimited"
  }
  provisioner "local-exec" {
    command = "echo ${aws_instance.project_instance.public_ip} >> ip_address.txt"

  }
  # provisioner "remote-exec" {
  #   inline = [
  #     "sudo apt update -y",
  #     "sudo apt install -y nginx",
  #     "sudo systemctl start nginx",
  #     "sudo systemctl enable nginx",
  #   ]

  # }
  # connection {
  #   type = "ssh"
  #   user = "ubuntu"
  #   # private_key = file("${path.module}/my-key-pair.pem")
  #   host = aws_instance.foo.public_ip
  # }

}
output "instance_ip" {
  value = aws_instance.project_instance.public_ip

}
##########################
##########################
#########################
#########################
##solving error of roles
resource "aws_iam_role" "asg_lifecycle_role" {
  name = "asg-lifecycle-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "autoscaling.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "asg_lifecycle_policy" {
  name = "asg-lifecycle-policy"
  role = aws_iam_role.asg_lifecycle_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "autoscaling:PutLifecycleHook",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:CompleteLifecycleAction",
          "sqs:SendMessage", # Add this permission
          "sqs:GetQueueUrl"  # Add this permission
        ]
        Resource = "*"
      }
    ]
  })
}
###SQS queue
resource "aws_sqs_queue" "project_queue" {
  name = "example-queue"
}

resource "aws_lb_target_group_attachment" "test" {
  target_group_arn = aws_lb_target_group.project_target_group.arn
  target_id        = aws_instance.project_instance.id
  port             = 80
}
##not valid for new accounts-----..
# resource "aws_launch_configuration" "launcher" {
#   name = "example-launch-config"
#   image_id = "ami-000b9845467bba0de"
#   instance_type = "t2.micro"
#   key_name = aws_key_pair.my_key_pair.key_name
#   iam_instance_profile = aws_iam_instance_profile.instance_role.name
#   security_groups = [aws_security_group.public_security_group_v2.id]
#   user_data = <<EOF
#     #!/bin/bash
#     sudo apt update -y
#     sudo apt install -y nginx
#     sudo systemctl start nginx
#     sudo systemctl enable nginx
#   EOF
  
# }

resource "aws_iam_instance_profile" "instance_role" {
  name = "ec2-profile"
  role = aws_iam_role.ec2_role.name
  
}
resource "aws_iam_role" "ec2_role" {
  name = "example-role"
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

resource "aws_iam_policy" "s3_access_policy" {
  name = "s3-access-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::project-date-bucket-moaz-elmahi",
          "arn:aws:s3:::project-date-bucket-moaz-elmahi/*"
        ]
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "att_policy_role" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}
