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
    azurerm = {
      source = "hashicorp/azurerm"
      version = "2.48.0"
    }
    azuread = {
      source = "hashicorp/azuread"
      version = "1.4.0"
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

### HashiCorp EKS Module ###
# - Security Group manually assigned to prevent new SGs being created - CAPIC will override otherwise
# - IP-based (Subnet) from CAPIC - EPG mapping
# - Open ACL - Need restricting
# - Cluster SG always created by EKS - can't manually assign


module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  # version = "14.0.0"
  cluster_name    = local.cluster_name
  cluster_version = "1.19"
  cluster_service_ipv4_cidr = "192.168.101.0/24"
  # subnets         = module.vpc.private_subnets
  subnets         = [data.aws_subnet.eks-1.id, data.aws_subnet.eks-2.id]

  # # Doesn't work?  Still creates own SG?
  # cluster_create_security_group = false
  # cluster_security_group_id = data.aws_security_group.tf-k8s-worker.id

  manage_cluster_iam_resources = false
  cluster_iam_role_name = "ManualEKSClusterRole"
  manage_worker_iam_resources = false

  # tags = {
  #   Environment = "test"
  #   GithubRepo  = "terraform-aws-eks"
  #   GithubOrg   = "terraform-aws-modules"
  # }

  cluster_create_timeout = "20m"
  cluster_delete_timeout = "20m"

  # vpc_id = module.vpc.vpc_id
  vpc_id = data.aws_vpc.prod-vpc.id

  # tags = {
  #   EPG = "tf-k8s-worker"
  # }

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
      # Can't use SPOT and shutdown manually...
      # capacity_type  = "SPOT"

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

  map_roles                            = var.map_roles
  map_users                            = var.map_users
  map_accounts                         = var.map_accounts

  cluster_enabled_log_types = ["audit","api"]

  # depends_on = [aws_subnet.eks-1,aws_subnet.eks-2]
}



#### Azure Kubernetes Service ####

data "vault_generic_secret" "azure" {
  path = "kv/azure"
}

data "azurerm_resource_group" "tf-hc-prod" {
  name     = "CAPIC_Production_tf-hc-prod_australiasoutheast"
  # location = "eastus"
}

provider azurerm {
  # alias           = "production"
  client_id         = data.vault_generic_secret.azure.data["client_id"]
  client_secret     = data.vault_generic_secret.azure.data["secret"]
  subscription_id   = data.vault_generic_secret.azure.data["subscription_id"]
  tenant_id         = data.vault_generic_secret.azure.data["tenant"]
  # whilst the `version` attribute is optional, we recommend pinning to a given version of the Provider
  # version = "=2.0.0"
  features {}
}

provider azuread {
  # alias           = "production"
  client_id         = data.vault_generic_secret.azure.data["client_id"]
  client_secret     = data.vault_generic_secret.azure.data["secret"]
  # subscription_id   = data.vault_generic_secret.azure.data["subscription_id"]
  tenant_id         = data.vault_generic_secret.azure.data["tenant"]
  # whilst the `version` attribute is optional, we recommend pinning to a given version of the Provider
  # version = "=2.0.0"
  features {}
}

# data "azuread_group" "tf-hc-prod" {
#   name = "AKS-cluster-admins"
# }
#
data "azuread_group" "cluster-admins" {
  display_name     = "ManualAKSClusterAdmins"
  # security_enabled = true
}

data "azurerm_virtual_network" "tf-hc-prod" {
  name                = "tf-hc-prod"
  resource_group_name = data.azurerm_resource_group.tf-hc-prod.name
}

# module "aks" {
#   source                           = "Azure/aks/azurerm"
#   resource_group_name              = data.azurerm_resource_group.tf-hc-prod.name
#   client_id                        = data.vault_generic_secret.azure.data["client_id"]
#   client_secret                    = data.vault_generic_secret.azure.data["secret"]
#   kubernetes_version               = "1.19.3"
#   orchestrator_version             = "1.19.3"
#   prefix                           = "tf-aks"
#   network_plugin                   = "azure"
#   vnet_subnet_id                   = data.azurerm_virtual_network.tf-hc-prod.id
#   os_disk_size_gb                  = 50
#   sku_tier                         = "Paid" # defaults to Free
#   enable_role_based_access_control = true
#   rbac_aad_admin_group_object_ids  = [data.azuread_group.cluster-admins.id]
#   rbac_aad_managed                 = true
#   private_cluster_enabled          = true # default value
#   enable_http_application_routing  = true
#   enable_azure_policy              = true
#   enable_auto_scaling              = true
#   agents_min_count                 = 1
#   agents_max_count                 = 2
#   agents_count                     = null # Please set `agents_count` `null` while `enable_auto_scaling` is `true` to avoid possible `agents_count` changes.
#   agents_max_pods                  = 100
#   agents_pool_name                 = "exnodepool"
#   # agents_availability_zones        = ["1", "2"]
#   agents_type                      = "VirtualMachineScaleSets"
#   agents_size                      = "Standard DS1 v2"
#
#   agents_labels = {
#     "nodepool" : "defaultnodepool"
#   }
#
#   agents_tags = {
#     "Agent" : "defaultnodepoolagent"
#   }
#
#   network_policy                 = "azure"
#   # net_profile_dns_service_ip     = "10.0.0.10"
#   # net_profile_docker_bridge_cidr = "170.10.0.1/16"
#   net_profile_service_cidr       = "192.168.102.0/24"
#
#   # depends_on = [module.network]
# }
