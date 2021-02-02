terraform {
  required_providers {
    aws = {
          source = "hashicorp/aws"
          version = "3.25.0"
        }
    # vault = {
    #   source = "hashicorp/vault"
    #   version = "2.18.0"
    # }
  }
}
#
# provider "vault" {
#   address = "https://Hashi-Vault-1F899TQ4290I3-1824033843.ap-southeast-2.elb.amazonaws.com"
#   skip_tls_verify = true
# }
#
# data "vault_generic_secret" "aws-prod" {
#   path = "kv/aws-prod"
# }
#
# provider "aws" {
#   region     = "ap-southeast-2"
#   access_key = data.vault_generic_secret.aws-prod.data["access"]
#   secret_key = data.vault_generic_secret.aws-prod.data["secret"]
# }

data "aws_vpc" "selected" {
  # id = var.vpc_id
  filter = {
    name = ""
    values = []
  }
}

# ## Data - Existing Produ VPC
# data "aws_vpc" "target-vpc" {
#   id = var.aws-vpc-id
# }

# ## Data - Existing Prod Subnets
# data "aws_subnet" "eks-1" {
#   id = var.aws-subnet-1-id
# }
#
# data "aws_subnet" "eks-2" {
#   id = var.aws-subnet-2-id
# }


## Role Manually Configured ##

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

# resource "aws_eks_cluster" "tf-eks-1" {
#   name     = "tf-eks-1"
#   role_arn = aws_iam_role.tf-eks-role.arn
#
#   vpc_config {
#     subnet_ids = [aws_subnet.eks-1.id, aws_subnet.eks-2.id]
#   }
#
#   # Ensure that IAM Role permissions are created before and deleted after EKS Cluster handling.
#   # Otherwise, EKS will not be able to properly delete EKS managed EC2 infrastructure such as Security Groups.
#   depends_on = [
#     aws_iam_role_policy_attachment.tf-eks-AmazonEKSClusterPolicy,
#     aws_iam_role_policy_attachment.tf-eks-AmazonEKSVPCResourceController,
#   ]
# }
#
# output "endpoint" {
#   value = aws_eks_cluster.tf-eks-1.endpoint
# }
#
# output "kubeconfig-certificate-authority-data" {
#   value = aws_eks_cluster.tf-eks-1.certificate_authority[0].data
# }
