terraform {
  backend "remote" {
    hostname = "app.terraform.io"
    organization = "mel-ciscolabs-com"
    workspaces {
      name = "terraform-cloud-aci-demo"
    }
  }
  required_providers {
    # mso = {
    #   source = "CiscoDevNet/mso"
    #   version = "~> 0.1.5"
    # }
    aws = {
      source = "hashicorp/aws"
      version = "3.25.0"
    }
    vault = {
      source = "hashicorp/vault"
      version = "2.18.0"
    }
  }
}


### Vault Provider ###
## Username & Password provided by Workspace Variable
variable vault_username {}
variable vault_password {
  sensitive = true
}

provider "vault" {
  address = "https://Hashi-Vault-1F899TQ4290I3-1824033843.ap-southeast-2.elb.amazonaws.com"
  skip_tls_verify = true
  auth_login {
    path = "auth/userpass/login/${var.vault_username}"
    parameters = {
      password = var.vault_password
    }
  }
}

data "vault_generic_secret" "aws-prod" {
  path = "kv/aws-prod"
}

provider "aws" {
  region     = "ap-southeast-2"
  access_key = data.vault_generic_secret.aws-prod.data["access"]
  secret_key = data.vault_generic_secret.aws-prod.data["secret"]
}

provider "random" {
  # version = "~> 2.1"
}

provider "local" {
  # version = "~> 1.2"
}

provider "null" {
  # version = "~> 2.1"
}

provider "template" {
  # version = "~> 2.1"
}

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}

## Data - Existing Prod VPC
data "aws_vpc" "prod-vpc" {
  cidr_block = "10.111.0.0/16"
}

## Data - Existing Prod Subnets
data "aws_subnet" "eks-1" {
  vpc_id = data.aws_vpc.prod-vpc.id
  cidr_block = "10.111.3.0/24"
}

data "aws_subnet" "eks-2" {
  vpc_id = data.aws_vpc.prod-vpc.id
  cidr_block = "10.111.4.0/24"
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
  load_config_file       = false
  # version                = "~> 1.11"
}

data "aws_availability_zones" "available" {
}

locals {
  cluster_name = "test-eks-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
}

variable "map_accounts" {
  description = "Additional AWS account numbers to add to the aws-auth configmap."
  type        = list(string)

  default = [
    "616148879479",
    "243509099659",
    "466657174487"
  ]
}

variable "map_roles" {
  description = "Additional IAM roles to add to the aws-auth configmap."
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))

  default = [
    {
      rolearn  = "arn:aws:iam::616148879479:role/admin"
      username = "admin"
      groups   = ["system:masters"]
    },
  ]
}

variable "map_users" {
  description = "Additional IAM users to add to the aws-auth configmap."
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))

  default = [
    {
      userarn  = "arn:aws:iam::616148879479:user/terraform"
      username = "terraform"
      groups   = ["system:masters"]
    },
  ]
}

resource "aws_security_group" "worker_group_mgmt_one" {
  name_prefix = "worker_group_mgmt_one"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"

    cidr_blocks = [
      "0.0.0.0/0",
      # "10.0.0.0/8",
    ]
  }
}

# resource "aws_security_group" "worker_group_mgmt_two" {
#   name_prefix = "worker_group_mgmt_two"
#   vpc_id      = module.vpc.vpc_id
#
#   ingress {
#     from_port = 22
#     to_port   = 22
#     protocol  = "tcp"
#
#     cidr_blocks = [
#       "192.168.0.0/16",
#     ]
#   }
# }

resource "aws_security_group" "all_worker_mgmt" {
  name_prefix = "all_worker_management"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"

    cidr_blocks = [
      "0.0.0.0/0",
      # "10.0.0.0/8",
      # "172.16.0.0/12",
      # "192.168.0.0/16",
    ]
  }
}

# module "vpc" {
#   source  = "terraform-aws-modules/vpc/aws"
#   version = "2.47.0"
#
#   name                 = "test-vpc"
#   cidr                 = "10.0.0.0/16"
#   azs                  = data.aws_availability_zones.available.names
#   private_subnets      = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
#   public_subnets       = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]
#   enable_nat_gateway   = true
#   single_nat_gateway   = true
#   enable_dns_hostnames = true
#
#   public_subnet_tags = {
#     "kubernetes.io/cluster/${local.cluster_name}" = "shared"
#     "kubernetes.io/role/elb"                      = "1"
#   }
#
#   private_subnet_tags = {
#     "kubernetes.io/cluster/${local.cluster_name}" = "shared"
#     "kubernetes.io/role/internal-elb"             = "1"
#   }
# }

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  # version = "14.0.0"
  cluster_name    = local.cluster_name
  cluster_version = "1.18"
  # subnets         = module.vpc.private_subnets
  subnets         = [data.aws_subnet.eks-1.id, data.aws_subnet.eks-2.id]

  # tags = {
  #   Environment = "test"
  #   GithubRepo  = "terraform-aws-eks"
  #   GithubOrg   = "terraform-aws-modules"
  # }

  # vpc_id = module.vpc.vpc_id
  vpc_id = data.aws_vpc.prod-vpc.id

  worker_groups = [
    {
      name                          = "worker-group-1"
      instance_type                 = "t3.small"
      # additional_userdata           = "echo foo bar"
      asg_desired_capacity          = 2
      # additional_security_group_ids = [aws_security_group.worker_group_mgmt_one.id]
    },
    # {
    #   name                          = "worker-group-2"
    #   instance_type                 = "t3.medium"
    #   additional_userdata           = "echo foo bar"
    #   additional_security_group_ids = [aws_security_group.worker_group_mgmt_two.id]
    #   asg_desired_capacity          = 1
    # },
  ]

  worker_additional_security_group_ids = [aws_security_group.all_worker_mgmt.id]
  map_roles                            = var.map_roles
  map_users                            = var.map_users
  map_accounts                         = var.map_accounts
}



# # ### Cisco MSO Provider ###
# # data "vault_generic_secret" "aws-mso" {
# #   path = "kv/aws-mso"
# # }
# #
# # provider "mso" {
# #   username = data.vault_generic_secret.aws-mso.data["username"]
# #   password = data.vault_generic_secret.aws-mso.data["password"]
# #   url      = "https://aws-syd-ase-n1.mel.ciscolabs.com/mso/"
# #   insecure = true
# # }
#
# ### AWS Provider ###
# data "vault_generic_secret" "aws-prod" {
#   path = "kv/aws-prod"
# }
#
# provider "aws" {
#   region     = "ap-southeast-2"
#   access_key = data.vault_generic_secret.aws-prod.data["access"]
#   secret_key = data.vault_generic_secret.aws-prod.data["secret"]
# }
#
# ### Nested Modules ###
# # module "cloud-aci" {
# #   source = "./modules/mso"
# #
# # }
#
# # output "test1" {
# #   value = module.cloud-aci.aws-syd-prod-vrf
# # }
# #
# # output "test2" {
# #   value = module.cloud-aci.aws-syd-reg
# # }
#
#
# ## Data - Existing Prod VPC
# data "aws_vpc" "prod-vpc" {
#   cidr_block = "10.111.0.0/16"
#   # id = var.aws-vpc-id
#   # Tag? - Name?
# }
#
# ## Data - Existing Prod Subnets
# data "aws_subnet" "eks-1" {
#   vpc_id = data.aws_vpc.prod-vpc.id
#   cidr_block = "10.111.3.0/24"
# }
#
# data "aws_subnet" "eks-2" {
#   vpc_id = data.aws_vpc.prod-vpc.id
#   cidr_block = "10.111.4.0/24"
# }
#
# ## IAM Role for EKS
# resource "aws_iam_role" "tf-eks-role" {
#   name = "tf-eks-role"
#
#   assume_role_policy = <<POLICY
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Principal": {
#         "Service": "eks.amazonaws.com"
#       },
#       "Action": "sts:AssumeRole"
#     }
#   ]
# }
# POLICY
# }
#
# resource "aws_iam_role_policy_attachment" "tf-eks-AmazonEKSClusterPolicy" {
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
#   role       = aws_iam_role.tf-eks-role.name
# }
#
# # Optionally, enable Security Groups for Pods
# # Reference: https://docs.aws.amazon.com/eks/latest/userguide/security-groups-for-pods.html
# resource "aws_iam_role_policy_attachment" "tf-eks-AmazonEKSVPCResourceController" {
#   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
#   role       = aws_iam_role.tf-eks-role.name
# }
#
#
# variable "map_accounts" {
#   description = "Additional AWS account numbers to add to the aws-auth configmap."
#   type        = list(string)
#
#   default = [
#     "777777777777",
#     "888888888888",
#   ]
# }
#
# variable "map_roles" {
#   description = "Additional IAM roles to add to the aws-auth configmap."
#   type = list(object({
#     rolearn  = string
#     username = string
#     groups   = list(string)
#   }))
#
#   default = [
#     {
#       rolearn  = "arn:aws:iam::616148879479:role/admin"
#       username = "admin"
#       groups   = ["system:masters"]
#     },
#   ]
# }
#
# variable "map_users" {
#   description = "Additional IAM users to add to the aws-auth configmap."
#   type = list(object({
#     userarn  = string
#     username = string
#     groups   = list(string)
#   }))
#
#   default = [
#     {
#       userarn  = "arn:aws:iam::616148879479:user/terraform"
#       username = "terraform"
#       groups   = ["system:masters"]
#     },
#   ]
# }
#
# module "eks" {
#   source          = "terraform-aws-modules/eks/aws"
#   cluster_name    = "tf-eks1"
#   cluster_version = "1.18"
#   subnets         = [data.aws_subnet.eks-1.id, data.aws_subnet.eks-2.id]
#   write_kubeconfig = false
#
#   # tags = {
#   #   Environment = "training"
#   #   GithubRepo  = "terraform-aws-eks"
#   #   GithubOrg   = "terraform-aws-modules"
#   # }
#
#   vpc_id          = data.aws_vpc.prod-vpc.id
#
#   map_roles       = var.map_roles
#   map_users       = var.map_users
#
#   workers_group_defaults = {
#     root_volume_type = "gp2"
#   }
#
#   worker_groups = [
#     {
#       name                          = "tf-eks1-wg1"
#       instance_type                 = "t2.micro"
#       # additional_userdata           = "echo foo bar"
#       asg_desired_capacity          = 2
#       # additional_security_group_ids = [aws_security_group.worker_group_mgmt_one.id]
#       public_ip                     = true
#     },
#     # {
#     #   name                          = "worker-group-2"
#     #   instance_type                 = "t2.medium"
#     #   additional_userdata           = "echo foo bar"
#     #   additional_security_group_ids = [aws_security_group.worker_group_mgmt_two.id]
#     #   asg_desired_capacity          = 1
#     # },
#   ]
# }
#
# data "aws_eks_cluster" "cluster" {
#   name = module.eks.cluster_id
# }
#
# data "aws_eks_cluster_auth" "cluster" {
#   name = module.eks.cluster_id
# }
#
#
# # resource "aws_eks_cluster" "tf-eks-1" {
# #   name     = "tf-eks-1"
# #   # role_arn = aws_iam_role.tf-eks-role.arn
# #   role_arn = "arn:aws:iam::616148879479:user/terraform"
# #
# #
# #   vpc_config {
# #     subnet_ids = [data.aws_subnet.eks-1.id, data.aws_subnet.eks-2.id]
# #   }
# #
# #   # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
# #   # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
# #   # depends_on = [
# #   #   aws_iam_role_policy_attachment.tf-eks-AmazonEKSClusterPolicy,
# #   #   aws_iam_role_policy_attachment.tf-eks-AmazonEKSVPCResourceController,
# #   # ]
# # }
#
# output "endpoint" {
#   value = module.eks.cluster_endpoint
# }
#
# output "kubeconfig" {
#   value = module.eks.kubeconfig
# }
#
# output "kubeconfig-certificate-authority-data" {
#   value = module.eks.cluster_certificate_authority_data
# }
#
#
# ### Need to fix subnets ###
# ## - Not allocating public IPv4 IPs
#
#
# # resource "aws_cloudwatch_log_group" "aws_eks" {
# #   name              = "/aws/eks/eks_cluster/cluster"
# #   retention_in_days = 7
# # }
# #
# # resource "aws_iam_role" "eks_cluster" {
# #   name = "eks-cluster"
# #
# #   assume_role_policy = <<POLICY
# # {
# #   "Version": "2012-10-17",
# #   "Statement": [
# #     {
# #       "Effect": "Allow",
# #       "Principal": {
# #         "Service": "eks.amazonaws.com"
# #       },
# #       "Action": "sts:AssumeRole"
# #     }
# #   ]
# # }
# # POLICY
# # }
# #
# # resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
# #   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
# #   role       = aws_iam_role.eks_cluster.name
# # }
# #
# # resource "aws_iam_role_policy_attachment" "AmazonEKSServicePolicy" {
# #   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
# #   role       = aws_iam_role.eks_cluster.name
# # }
# #
# #
# # resource "aws_eks_cluster" "aws_eks" {
# #   name     = "eks_cluster"
# #   role_arn = aws_iam_role.eks_cluster.arn
# #
# #   vpc_config {
# #     subnet_ids = [data.aws_subnet.eks-1.id, data.aws_subnet.eks-2.id]
# #   }
# #
# #   tags = {
# #     Name = "TF_EKS"
# #   }
# #
# #   depends_on = [aws_cloudwatch_log_group.aws_eks]
# #   enabled_cluster_log_types = ["api", "audit"]
# # }
# #
# # resource "aws_iam_role" "eks_nodes" {
# #   name = "eks-node-group-1"
# #
# #   assume_role_policy = <<POLICY
# # {
# #   "Version": "2012-10-17",
# #   "Statement": [
# #     {
# #       "Effect": "Allow",
# #       "Principal": {
# #         "Service": "ec2.amazonaws.com"
# #       },
# #       "Action": "sts:AssumeRole"
# #     }
# #   ]
# # }
# # POLICY
# # }
# #
# # resource "aws_iam_role_policy_attachment" "AmazonEKSWorkerNodePolicy" {
# #   policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
# #   role       = aws_iam_role.eks_nodes.name
# # }
# #
# # resource "aws_iam_role_policy_attachment" "AmazonEKS_CNI_Policy" {
# #   policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
# #   role       = aws_iam_role.eks_nodes.name
# # }
# #
# # resource "aws_iam_role_policy_attachment" "AmazonEC2ContainerRegistryReadOnly" {
# #   policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
# #   role       = aws_iam_role.eks_nodes.name
# # }
# #
# # resource "aws_eks_node_group" "node" {
# #   cluster_name    = aws_eks_cluster.aws_eks.name
# #   node_group_name = "tf-eks-ng1"
# #   node_role_arn   = aws_iam_role.eks_nodes.arn
# #   subnet_ids      = [data.aws_subnet.eks-1.id, data.aws_subnet.eks-2.id]
# #
# #   scaling_config {
# #     desired_size = 1
# #     max_size     = 1
# #     min_size     = 1
# #   }
# #
# #   # Ensure that IAM Role permissions are created before and deleted after EKS Node Group handling.
# #   # Otherwise, EKS will not be able to properly delete EC2 Instances and Elastic Network Interfaces.
# #   depends_on = [
# #     aws_iam_role_policy_attachment.AmazonEKSWorkerNodePolicy,
# #     aws_iam_role_policy_attachment.AmazonEKS_CNI_Policy,
# #     aws_iam_role_policy_attachment.AmazonEC2ContainerRegistryReadOnly,
# #   ]
# # }
