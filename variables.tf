### Provider 
variable "region" {
  description = "aws region to deploy to"
  default = "us-east-1"
  type        = string
}

variable "availability_zones" {
  type  = list(string)
  default = ["us-east-1a", "us-east-1b"]
  description = "List of availability zones for the selected region"
}

### Networking

variable "vpc_tag_name" {
  type        = string
  default = "vpc-test"
  description = "Name tag for the VPC"
}

variable "vpc_cidr_block" {
  type        = string
  default     = "10.0.0.0/16"
  description = "CIDR block range for vpc"
}

variable "internet_gateway_tag" {
  type        = string
  default = "igw-test"
  description = "Name tag for the VPC"  
}

variable "route_table_tag_name" {
  type        = string
  default     = "test-igw"
  description = "Route table description"
}

variable "private_subnet_tag_name" {
  type        = string
  default = "test Kubernetes cluster private subnet"
  description = "Name tag for the private subnet"
}

variable "public_subnet_tag_name" {
  type        = string
  default = "test Kubernetes cluster public subnet"
  description = "Name tag for the public subnet"
}

variable "private_subnet_cidr_blocks" {
  type        = list(string)
  default     = ["10.0.0.0/24", "10.0.1.0/24"]
  description = "CIDR block range for the private subnet"
}

variable "public_subnet_cidr_blocks" {
  type = list(string)
  default     = ["10.0.2.0/24", "10.0.3.0/24"]
  description = "CIDR block range for the public subnet"
}

### Security group
variable "public_security_group_name" {
  description = "security group public name"
  default = "public-sg"
  type        = string
}

variable "cluster_security_group_name" {
  description = "cluster security group name"
  default = "cluster-eks-sg"
  type        = string  
}

variable "nodes_security_group_name" {
  description = "node security group  name"
  default = "node-eks-sg"
  type        = string    
}

### EKS 
variable "eks_cluster_name" {
  description = "The name of the EKS cluster"
  default = "test-test"
  type = string
}

### Node 
variable "node_group_name" {
  description = "eks node group name"
  default = "test-eks-node"
  type        = string   
}

variable "ami_type" {
  description = "Type of Amazon Machine Image (AMI) associated with the EKS Node Group. Defaults to AL2_x86_64. Valid values: AL2_x86_64, AL2_x86_64_GPU."
  type = string 
  default = "AL2_x86_64"
}

variable "disk_size" {
  description = "Disk size in GiB for worker nodes. Defaults to 20."
  type = number
  default = 20
}

variable "instance_types" {
  type = list(string)
  default = ["t3.medium"]
  description = "Set of instance types associated with the EKS Node Group."
}

variable "private_node_desired_size" {
  description = "Desired number of worker nodes in private subnet"
  default = 1
  type = number
}

variable "private_node_max_size" {
  description = "Maximum number of worker nodes in private subnet."
  default = 5
  type = number
}

variable "private_node_min_size" {
  description = "Minimum number of worker nodes in private subnet."
  default = 1
  type = number
}