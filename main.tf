terraform {
  backend "remote" {
    hostname = "app.terraform.io"
    organization = "mel-ciscolabs-com"
    workspaces {
      name = "terraform-cloud-k8s"
    }
  }
  required_providers {
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

## Data - Existing Prod VPC
data "aws_vpc" "prod-vpc" {
  cidr_block = "10.111.0.0/16"
}

## Existing EPG's SG ##
data "aws_security_group" "tf-k8s-worker" {
  name = "uni/tn-Production/cloudapp-tf-k8s-1/cloudepg-tf-k8s-worker"
  vpc_id = data.aws_vpc.prod-vpc.id
}

#### NEED TO MARK PUBLIC IPV4 AUTO ALLOCATION ###

# Data - Existing Prod Subnets
data "aws_subnet" "eks-1" {
  vpc_id = data.aws_vpc.prod-vpc.id
  cidr_block = "10.111.5.0/24"
}

# resource "aws_subnet" "eks-1" {
#   ## Exists but needs Auto IP Settings Changed
#   vpc_id     = data.aws_vpc.prod-vpc.id
#   cidr_block = "10.111.5.0/24"
#   map_public_ip_on_launch = true
# }

data "aws_subnet" "eks-2" {
  vpc_id = data.aws_vpc.prod-vpc.id
  cidr_block = "10.111.6.0/24"
}

# resource "aws_subnet" "eks-2" {
#   ## Exists but needs Auto IP Settings Changed
#   vpc_id     = data.aws_vpc.prod-vpc.id
#   cidr_block = "10.111.6.0/24"
#   map_public_ip_on_launch = true
# }


### Build Kubernets Provider

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  token                  = data.aws_eks_cluster_auth.cluster.token
  # load_config_file       = false
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

# resource "aws_security_group" "worker_group_mgmt_one" {
#   name_prefix = "worker_group_mgmt_one"
#   # vpc_id      = module.vpc.vpc_id
#   vpc_id = data.aws_vpc.prod-vpc.id
#
#   ingress {
#     from_port = 22
#     to_port   = 22
#     protocol  = "tcp"
#
#     cidr_blocks = [
#       "0.0.0.0/0",
#       # "10.0.0.0/8",
#     ]
#   }
# }

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

# resource "aws_security_group" "all_worker_mgmt" {
#   name_prefix = "all_worker_management"
#   # vpc_id      = module.vpc.vpc_id
#   vpc_id = data.aws_vpc.prod-vpc.id
#
#   ingress {
#     from_port = 22
#     to_port   = 22
#     protocol  = "tcp"
#
#     cidr_blocks = [
#       "0.0.0.0/0",
#       # "10.0.0.0/8",
#       # "172.16.0.0/12",
#       # "192.168.0.0/16",
#     ]
#   }
# }

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

# timeouts {
#   create = "20m"
#   delete = "15m"
# }

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  # version = "14.0.0"
  cluster_name    = local.cluster_name
  cluster_version = "1.18"
  cluster_service_ipv4_cidr = "192.168.101.0/24"
  # subnets         = module.vpc.private_subnets
  subnets         = [data.aws_subnet.eks-1.id, data.aws_subnet.eks-2.id]

  cluster_create_security_group = false
  cluster_security_group_id = data.aws_security_group.tf-k8s-worker.id

  manage_cluster_iam_resources = false
  cluster_iam_role_name = "ManualEKSClusterRole"

  # tags = {
  #   Environment = "test"
  #   GithubRepo  = "terraform-aws-eks"
  #   GithubOrg   = "terraform-aws-modules"
  # }

  # vpc_id = module.vpc.vpc_id
  vpc_id = data.aws_vpc.prod-vpc.id

  # tags = {
  #   EPG = "tf-k8s-worker"
  # }

  # ## Doesn't work??
  # cluster_create_security_group = false
  # cluster_security_group_id = data.aws_security_group.tf-k8s-cluster.id

  worker_create_security_group = false
  worker_create_cluster_primary_security_group_rules = false
  worker_security_group_id = data.aws_security_group.tf-k8s-worker.id
  # worker_additional_security_group_ids = [data.aws_security_group.tf-k8s-worker.id]

  node_groups_defaults = {
    ## Default to gp3 which doesn't work...
    root_volume_type = "gp2"
    iam_role_arn = "arn:aws:iam::616148879479:role/ManualEKSNodeRole"
  }

  node_groups = {
    tf-ng-1 = {
      desired_capacity = 3
      max_capacity     = 3
      min_capacity     = 3

      instance_types = ["t3.small"]
      capacity_type  = "SPOT"
      # k8s_labels = {
      #   Environment = "test"
      #   GithubRepo  = "terraform-aws-eks"
      #   GithubOrg   = "terraform-aws-modules"
      # }

      # ## Does not apply to EC2 instances
      # additional_tags = {
      #   EPG = "tf-k8s-worker"
      # }
    }
  }

  # workers_group_defaults = {
  #   ## Default to gp3 which doesn't work...
  #   root_volume_type = "gp2"
  #   public_ip = true
  # }
  #
  # worker_groups = [
  #   {
  #     name                          = "worker-group-1"
  #     instance_type                 = "t3.small"
  #     # additional_userdata           = "echo foo bar"
  #     asg_desired_capacity          = 3
  #     asg_min_size                  = 3
  #     # asg_recreate_on_change        = true
  #     # additional_security_group_ids = [data.aws_security_group.tf-k8s-worker.id]
  #   },
  # ]

  # worker_additional_security_group_ids = [aws_security_group.all_worker_mgmt.id]
  map_roles                            = var.map_roles
  map_users                            = var.map_users
  map_accounts                         = var.map_accounts

  cluster_enabled_log_types = ["audit","api"]

  # depends_on = [aws_subnet.eks-1,aws_subnet.eks-2]
}
