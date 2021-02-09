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

variable "namespace" {
  default = "test"
}

variable "name" {
  default = "test"
}

variable "stage" {
  default = "prod"
}

variable "delimiter" {
  default = "-"
}

variable "attributes" {
  type    = list(string)
  default = []
}

variable "tags" {
  type    = list(string)
  default = []
}

variable "kubernetes_version" {
  default = "1.18"
}

# variable "instance_type" {
#   default = "t3.small"
# }

variable "desired_size" {
  default = "3"
}

variable "min_size" {
  default = "3"
}

variable "max_size" {
  default = "3"
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

# module "label" {
#   source = "cloudposse/label/null"
#   # Cloud Posse recommends pinning every module to a specific version
#   # version     = "x.x.x"
#   namespace  = var.namespace
#   name       = var.name
#   stage      = var.stage
#   delimiter  = var.delimiter
#   attributes = compact(concat(var.attributes, list("cluster")))
#   # tags       = var.tags
# }

# locals {
#   # The usage of the specific kubernetes.io/cluster/* resource tags below are required
#   # for EKS and Kubernetes to discover and manage networking resources
#   # https://www.terraform.io/docs/providers/aws/guides/eks-getting-started.html#base-vpc-networking
#   tags = merge(var.tags, map("kubernetes.io/cluster/${module.label.id}", "shared"))
#
#   # Unfortunately, most_recent (https://github.com/cloudposse/terraform-aws-eks-workers/blob/34a43c25624a6efb3ba5d2770a601d7cb3c0d391/main.tf#L141)
#   # variable does not work as expected, if you are not going to use custom AMI you should
#   # enforce usage of eks_worker_ami_name_filter variable to set the right kubernetes version for EKS workers,
#   # otherwise the first version of Kubernetes supported by AWS (v1.11) for EKS workers will be used, but
#   # EKS control plane will use the version specified by kubernetes_version variable.
#   eks_worker_ami_name_filter = "amazon-eks-node-${var.kubernetes_version}*"
# }

module "eks_cluster" {
  source = "cloudposse/eks-cluster/aws"
  # Cloud Posse recommends pinning every module to a specific version
  # version     = "x.x.x"
  region     = "ap-southeast-2"
  namespace  = var.namespace
  stage      = var.stage
  name       = var.name
  attributes = var.attributes
  # tags       = var.tags
  # vpc_id     = module.vpc.vpc_id
  vpc_id     = data.aws_vpc.prod-vpc.id
  subnet_ids = [data.aws_subnet.eks-1.id, data.aws_subnet.eks-2.id]

  kubernetes_version    = var.kubernetes_version
  oidc_provider_enabled = false

  workers_security_group_ids   = [data.aws_security_group.tf-k8s-worker.id]
  # workers_role_arns            = ["arn:aws:iam::616148879479:role/ManualEKSNodeRole"]
  workers_role_arns          = [module.eks_node_group.eks_node_group_role_arn]
}

module "eks_node_group" {
  source = "cloudposse/eks-node-group/aws"
  # Cloud Posse recommends pinning every module to a specific version
  # version     = "x.x.x"
  namespace                 = var.namespace
  stage                     = var.stage
  name                      = var.name
  attributes                = var.attributes
  # tags                      = var.tags
  subnet_ids                = [data.aws_subnet.eks-1.id, data.aws_subnet.eks-2.id]
  instance_types            = ["t3.small"]
  desired_size              = 3
  min_size                  = 3
  max_size                  = 3
  cluster_name              = module.eks_cluster.eks_cluster_id
  kubernetes_version        = var.kubernetes_version
}
