#VPC OF ARCHITECTURE
resource "aws_vpc" "architecture_vpc" {
  cidr_block = "10.1.0.0/16"
}
resource "aws_subnet" "public_subnet1" {
  vpc_id     = aws_vpc.architecture_vpc.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "public_subnet1"
  }
}

resource "aws_subnet" "public_subnet2" {
  vpc_id     = aws_vpc.architecture_vpc.id
  cidr_block = "10.0.2.0/24"

  tags = {
    Name = "public_subnet2"
  }
}

resource "aws_subnet" "private_subnet1" {
  vpc_id     = aws_vpc.architecture_vpc.id
  cidr_block = "10.0.3.0/24"

  tags = {
    Name = "private_subnet1"
  }
}

resource "aws_subnet" "private_subnet2" {
  vpc_id     = aws_vpc.architecture_vpc.id
  cidr_block = "10.0.4.0/24"

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
}

resource "aws_eip" "eip_nat" {
  domain = "vpc"  # Specify that the EIP is for use in a VPC

  tags = {
    Name = "project_eip"  # Add a tag for better resource management
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

  route {
    
  }
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
 resource "aws_security_group" "public_security_group" {
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
  ipv6_cidr_blocks  = [aws_vpc.architecture_vpc.ipv6_cidr_block]
  security_group_id = aws_security_group.public_security_group.id
}
#http rule from anywhere inbound
resource "aws_vpc_security_group_ingress_rule" "inbound_rule_2" {
  security_group_id = aws_security_group.public_security_group.id
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 80
  ip_protocol = "tcp"
  to_port     = 80
}
#https rule from anywhere inbound
resource "aws_vpc_security_group_ingress_rule" "inbound_rule_3" {
  security_group_id = aws_security_group.public_security_group.id
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 443
  ip_protocol = "tcp"
  to_port     = 443
}
#`ssh rule from anywhere inbound
resource "aws_vpc_security_group_ingress_rule" "inbound_rule_4" {
  security_group_id = aws_security_group.public_security_group.id
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 22
  ip_protocol = "tcp"
  to_port     = 22
}


#outbound rules for security group for public subnets
resource "aws_vpc_security_group_egress_rule" "outbound_rule_1" {
  security_group_id = aws_security_group.public_security_group.id
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 0
  ip_protocol = "tcp"
  to_port     = 65535
}

#security group for pruvate subnets
 resource "aws_security_group" "private_security_group" {
  name        = "allow_tls"
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
  ipv6_cidr_blocks  = [aws_vpc.architecture_vpc.ipv6_cidr_block]
  security_group_id = aws_security_group.private_security_group.id
}


#sql rule from anywhere inbound
#need edit 
resource "aws_vpc_security_group_ingress_rule" "inbound_rule_6" {
  security_group_id = aws_security_group.private_security_group.id
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 3306
  ip_protocol = "tcp"
  to_port     = 3306
  description = "allow mysql traffic"
}

resource "aws_vpc_security_group_egress_rule" "outbound_rule_2" {
  security_group_id = aws_security_group.private_security_group.id
  cidr_ipv4   = "0.0.0.0/0"
  from_port   = 0
  ip_protocol = "-1"
  to_port     = 0
}
#outbound rules for security group for public subnets
#######################################################################################
#autoscaling group
resource "aws_placement_group" "placement_group" {
  name     = "test"
  strategy = "cluster"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-*-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

   # Canonical
}

resource "aws_launch_configuration" "as_conf" {
  name          = "web_config"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
}

resource "aws_autoscaling_group" "bar" {
  name                      = "foobar3-terraform-test"
  max_size                  = 6
  min_size                  = 2
  health_check_grace_period = 300
  health_check_type         = "ELB"
  desired_capacity          = 4
  force_delete              = true
  placement_group           = aws_placement_group.placement_group.id
  launch_configuration      = aws_launch_configuration.as_conf.name
  vpc_zone_identifier       = [aws_subnet.public_subnet1.id, aws_subnet.public_subnet2.id]

  instance_maintenance_policy {
    min_healthy_percentage = 90
    max_healthy_percentage = 120
  }

  initial_lifecycle_hook {
    name                 = "foobar"
    default_result       = "CONTINUE"
    heartbeat_timeout    = 2000
    lifecycle_transition = "autoscaling:EC2_INSTANCE_LAUNCHING"

    notification_metadata = jsonencode({
      foo = "bar"
    })
#####need for edit
    notification_target_arn = "arn:aws:sqs:us-east-1:444455556666:queue1*"
    role_arn                = "arn:aws:iam::123456789012:role/S3Access"
  }

  tag {
    key                 = "foo"
    value               = "bar"
    propagate_at_launch = true
  }

  timeouts {
    delete = "15m"
  }

  tag {
    key                 = "lorem"
    value               = "ipsum"
    propagate_at_launch = false
  }
}

#######################################################################################
#RDS
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
  username                      = "foo"
  parameter_group_name          = "default.mysql8.0"
}
#######################################################################################
#LOAD BALANCER
resource "aws_lb" "project_load_balancer" {
  name               = "test-lb-tf"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.public_security_group.id]
  subnets            = [aws_subnet.public_subnet1.id , aws_subnet.public_subnet2.id]

  enable_deletion_protection = true

  access_logs {
    bucket  = aws_s3_bucket.lb_logs.id
    prefix  = "test-lb"
    enabled = true
  }

  tags = {
    Environment = "production"
  }
}

resource "aws_s3_bucket" "lb_logs" {
  bucket = "my-LOGS-test-bucket"

  tags = {
    Name        = "My bucket"
    Environment = "Dev"
  }
}

resource "aws_lb_target_group" "project_target_group" {
  name     = "tf-example-lb-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.architecture_vpc.id
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
resource "aws_network_interface" "nci" {
  subnet_id   = aws_subnet.public_subnet1.id
  private_ips = ["100.0.0.1"]
  tags = {
    Name = "primary_network_interface"
  }
}

resource "aws_instance" "foo" {
  ami           = "ami-005e54dee72cc1d00" # us-west-2
  instance_type = "t2.micro"  
  key_name = aws_key_pair.my_key_pair.key_name
  network_interface {
    network_interface_id = aws_network_interface.nci.id
    device_index         = 0
  }

  credit_specification {
    cpu_credits = "unlimited"
  }
}