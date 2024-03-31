### Provider
provider "aws" {
  region = var.region
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

### Network 
## virtual private cloud network size 
resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr_block

  tags = {
    Name = var.vpc_tag_name
  }
}

## internet gateway for the VPC
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = var.internet_gateway_tag
  }
}

## Subnets 
# private subnet
resource "aws_subnet" "private_subnet" {
  count = length(var.availability_zones)
  vpc_id            = aws_vpc.main.id
  cidr_block = element(var.private_subnet_cidr_blocks, count.index)
  availability_zone = element(var.availability_zones, count.index)

  tags = {
    Name = var.private_subnet_tag_name
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "owned"
    "kubernetes.io/role/internal-elb" = 1
  }
}

# public subnet
resource "aws_subnet" "public_subnet" {
  count = length(var.availability_zones)
  vpc_id            = aws_vpc.main.id
  cidr_block = element(var.public_subnet_cidr_blocks, count.index)
  availability_zone = element(var.availability_zones, count.index)

  tags = {
    Name = "${var.public_subnet_tag_name}"
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "owned"
    "kubernetes.io/role/elb" = 1
  }
  ## Option to public Kubernetes instance groups
  # map_public_ip_on_launch = true
}

## Elastic IP
resource "aws_eip" "nat" {
  vpc = true

  tags = {
    Name = "nat"
  }
}
## NAT gateway 
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_subnet[0].id

  tags = {
    Name = "nat"
  }

  depends_on = [aws_internet_gateway.igw]
}

## routes 
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "private"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "public"
  }
}

resource "aws_route_table_association" "private-us-east-1a" {
  subnet_id      = "${aws_subnet.private_subnet[0].id}"
  route_table_id = aws_route_table.private.id
}

resource "aws_route_table_association" "private-us-east-1b" {
  subnet_id      = "${aws_subnet.private_subnet[1].id}"
  route_table_id = aws_route_table.private.id
}


resource "aws_route_table_association" "public-us-east-1a" {
  subnet_id      = "${aws_subnet.public_subnet[0].id}"
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public-us-east-1b" {
  subnet_id      = "${aws_subnet.public_subnet[1].id}"
  route_table_id = aws_route_table.public.id
}

### EKS
##IAM 
#Cluster IAM Role
resource "aws_iam_role" "eks_cluster" {
  name = "${var.eks_cluster_name}-cluster"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "eks.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "AmazonEKSClusterPolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
  role       = aws_iam_role.eks_cluster.name
}


## Security Groups
# Security group for public subnet resources
resource "aws_security_group" "public_sg" {
  name   = "public-sg"
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "public-sg"
  }
}

# Security group traffic rules
## Ingress rule
resource "aws_security_group_rule" "sg_ingress_public_443" {
  security_group_id = aws_security_group.public_sg.id
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "sg_ingress_public_80" {
  security_group_id = aws_security_group.public_sg.id
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

## Egress rule
resource "aws_security_group_rule" "sg_egress_public" {
  security_group_id = aws_security_group.public_sg.id
  type              = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

# Security group for data plane
resource "aws_security_group" "data_plane_sg" {
  name   = "k8s-data-plane-sg"
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "k8s-data-plane-sg"
  }
}

## Egress rule
resource "aws_security_group_rule" "node_outbound" {
  security_group_id = aws_security_group.data_plane_sg.id
  type              = "egress"
  from_port   = 0
  to_port     = 0
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

# Security group for control plane
resource "aws_security_group" "control_plane_sg" {
  name   = "k8s-control-plane-sg"
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "k8s-control-plane-sg"
  }
}

# Security group traffic rules
## Ingress rule
resource "aws_security_group_rule" "control_plane_inbound" {
  security_group_id = aws_security_group.control_plane_sg.id
  type              = "ingress"
  from_port   = 0
  to_port     = 65535
  protocol          = "tcp"
  cidr_blocks = flatten([var.private_subnet_cidr_blocks, var.public_subnet_cidr_blocks])
}

## Egress rule
resource "aws_security_group_rule" "control_plane_outbound" {
  security_group_id = aws_security_group.control_plane_sg.id
  type              = "egress"
  from_port   = 0
  to_port     = 65535
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group" "eks_cluster" {
  name        = var.cluster_security_group_name
  description = "Cluster communication with worker nodes"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = var.cluster_security_group_name
  }
}

resource "aws_security_group_rule" "cluster_inbound" {
  description              = "Allow worker nodes to communicate with the cluster API Server"
  from_port                = 443
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_cluster.id
  source_security_group_id = aws_security_group.eks_nodes.id
  to_port                  = 443
  type                     = "ingress"
}

resource "aws_security_group_rule" "cluster_outbound" {
  description              = "Allow cluster API Server to communicate with the worker nodes"
  from_port                = 1024
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_cluster.id
  source_security_group_id = aws_security_group.eks_nodes.id
  to_port                  = 65535
  type                     = "egress"
}

resource "aws_security_group" "eks_nodes" {
  name        = var.nodes_security_group_name
  description = "Security group for all nodes in the cluster"
  vpc_id      = aws_vpc.main.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name                                        = var.nodes_security_group_name
    "kubernetes.io/cluster/${var.eks_cluster_name}" = "owned"
  }
}

resource "aws_security_group_rule" "nodes" {
  description              = "Allow nodes to communicate with each other"
  from_port                = 0
  protocol                 = "-1"
  security_group_id        = aws_security_group.eks_nodes.id
  source_security_group_id = aws_security_group.eks_nodes.id
  to_port                  = 65535
  type                     = "ingress"
}

resource "aws_security_group_rule" "nodes_inbound" {
  description              = "Allow worker Kubelets and pods to receive communication from the cluster control plane"
  from_port                = 1025
  protocol                 = "tcp"
  security_group_id        = aws_security_group.eks_nodes.id
  source_security_group_id = aws_security_group.eks_cluster.id
  to_port                  = 65535
  type                     = "ingress"
}


# EKS cluster 
resource "aws_eks_cluster" "main" {
  name     = var.eks_cluster_name
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {
    security_group_ids = [aws_security_group.eks_cluster.id, aws_security_group.eks_nodes.id]
    subnet_ids = [
      aws_subnet.private_subnet[0].id,
      aws_subnet.private_subnet[1].id,
      aws_subnet.public_subnet[0].id,
      aws_subnet.public_subnet[1].id
    ]
  }

  depends_on = [aws_iam_role_policy_attachment.AmazonEKSClusterPolicy]
}

### NODE 
# OpenID connect
#grant permission based on the service account used by the cluster auto-scaler 
data "tls_certificate" "eks" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

# autoscaler IAM 
data "aws_iam_policy_document" "eks_cluster_autoscaler_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"

    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:cluster-autoscaler"]
    }

    principals {
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
      type        = "Federated"
    }
  }
}

resource "aws_iam_role" "eks_cluster_autoscaler" {
  assume_role_policy = data.aws_iam_policy_document.eks_cluster_autoscaler_assume_role_policy.json
  name               = "eks-cluster-autoscaler"
}

resource "aws_iam_policy" "eks_cluster_autoscaler" {
  name = "eks-cluster-autoscaler"

  policy = jsonencode({
    Statement = [{
      Action = [
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeAutoScalingInstances",
                "autoscaling:DescribeLaunchConfigurations",
                "autoscaling:DescribeTags",
                "autoscaling:SetDesiredCapacity",
                "autoscaling:TerminateInstanceInAutoScalingGroup",
                "ec2:DescribeLaunchTemplateVersions"
            ]
      Effect   = "Allow"
      Resource = "*"
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_autoscaler_attach" {
  role       = aws_iam_role.eks_cluster_autoscaler.name
  policy_arn = aws_iam_policy.eks_cluster_autoscaler.arn
}


resource "aws_iam_role" "nodes" {
  name = "eks-node-group-nodes"

  assume_role_policy = jsonencode({
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
    Version = "2012-10-17"
  })
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKSWorkerNodePolicy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEKS_CNI_Policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.nodes.name
}

resource "aws_iam_role_policy_attachment" "nodes-AmazonEC2ContainerRegistryReadOnly" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.nodes.name
}

resource "aws_eks_node_group" "nodes" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = var.node_group_name
  node_role_arn   = aws_iam_role.nodes.arn

  subnet_ids = [
    aws_subnet.private_subnet[0].id,
    aws_subnet.private_subnet[1].id
  ]

  ami_type       = var.ami_type
  disk_size      = var.disk_size
  instance_types = var.instance_types

  scaling_config {
    desired_size = var.private_node_desired_size
    max_size     = var.private_node_max_size
    min_size     = var.private_node_min_size
  }

  update_config {
    max_unavailable = 1
  }
  depends_on = [
    aws_iam_role_policy_attachment.nodes-AmazonEKSWorkerNodePolicy,
    aws_iam_role_policy_attachment.nodes-AmazonEKS_CNI_Policy,
    aws_iam_role_policy_attachment.nodes-AmazonEC2ContainerRegistryReadOnly,
  ]
}


### kubernetes Deployment 
provider "kubernetes" {
  host                   = aws_eks_cluster.main.endpoint
  cluster_ca_certificate = "${base64decode(aws_eks_cluster.main.certificate_authority.0.data)}"
  token                  = "${data.aws_eks_cluster_auth.cluster_auth.token}"
}

## cluster-autoscaler
# Create the ServiceAccount
resource "kubernetes_service_account" "cluster_autoscaler_service_account" {
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"
    labels = {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"   = "cluster-autoscaler"
    }
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.eks_cluster_autoscaler.arn
    }
  }
}

# Create the autoscaler cluster role
resource "kubernetes_cluster_role" "cluster_autoscaler" {
  metadata {
    name   = "cluster-autoscaler"
    labels = {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"   = "cluster-autoscaler"
    }
  }

  rule {
    api_groups = [""]
    resources  = ["events", "endpoints"]
    verbs      = ["create", "patch"]
  }

  rule {
    api_groups = [""]
    resources  = ["pods/eviction"]
    verbs      = ["create"]
  }

  rule {
    api_groups = [""]
    resources  = ["pods/status"]
    verbs      = ["update"]
  }

  rule {
    api_groups       = [""]
    resources        = ["endpoints"]
    resource_names   = ["cluster-autoscaler"]
    verbs            = ["get", "update"]
  }

  rule {
    api_groups = [""]
    resources  = ["nodes"]
    verbs      = ["watch", "list", "get", "update"]
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces", "pods", "services", "replicationcontrollers", "persistentvolumeclaims", "persistentvolumes"]
    verbs      = ["watch", "list", "get"]
  }

  rule {
    api_groups = ["extensions"]
    resources  = ["replicasets", "daemonsets"]
    verbs      = ["watch", "list", "get"]
  }

  rule {
    api_groups = ["policy"]
    resources  = ["poddisruptionbudgets"]
    verbs      = ["watch", "list"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["statefulsets", "replicasets", "daemonsets"]
    verbs      = ["watch", "list", "get"]
  }

  rule {
    api_groups = ["storage.k8s.io"]
    resources  = ["storageclasses", "csinodes", "csidrivers", "csistoragecapacities"]
    verbs      = ["watch", "list", "get"]
  }

  rule {
    api_groups = ["batch", "extensions"]
    resources  = ["jobs"]
    verbs      = ["get", "list", "watch", "patch"]
  }

  rule {
    api_groups = ["coordination.k8s.io"]
    resources  = ["leases"]
    verbs      = ["create"]
  }

  rule {
    api_groups       = ["coordination.k8s.io"]
    resources        = ["leases"]
    resource_names   = ["cluster-autoscaler"]
    verbs            = ["get", "update"]
  }
}

# Create the autoscaler cluster role binding 
resource "kubernetes_cluster_role_binding" "cluster_autoscaler_binding" {
  metadata {
    name   = "cluster-autoscaler"
    labels = {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"   = "cluster-autoscaler"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.cluster_autoscaler.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "cluster-autoscaler"
    namespace = "kube-system"
  }
}

# Create the autoscaler role in kube-system namespace 
resource "kubernetes_role" "cluster_autoscaler_role" {
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"
    labels = {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"   = "cluster-autoscaler"
    }
  }

  rule {
    api_groups = [""]
    resources  = ["configmaps"]
    verbs      = ["create", "list", "watch"]
  }

  rule {
    api_groups       = [""]
    resources        = ["configmaps"]
    resource_names   = ["cluster-autoscaler-status", "cluster-autoscaler-priority-expander"]
    verbs            = ["delete", "get", "update", "watch"]
  }
}

# Create the autoscaler role binding in kube-system namespace 
resource "kubernetes_role_binding" "cluster_autoscaler_role_binding" {
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"
    labels = {
      "k8s-addon" = "cluster-autoscaler.addons.k8s.io"
      "k8s-app"   = "cluster-autoscaler"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.cluster_autoscaler_role.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "cluster-autoscaler"
    namespace = "kube-system"
  }
}

# Create  the autoscaler Deployment
resource "kubernetes_deployment" "cluster_autoscaler_deployment" {
  metadata {
    name      = "cluster-autoscaler"
    namespace = "kube-system"
    labels = {
      "app" = "cluster-autoscaler"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        "app" = "cluster-autoscaler"
      }
    }

    template {
      metadata {
        labels = {
          "app" = "cluster-autoscaler"
        }
        annotations = {
          "prometheus.io/scrape" = "true"
          "prometheus.io/port"   = "8085"
        }
      }

      spec {
        priority_class_name = "system-cluster-critical"

        security_context {
          run_as_non_root = true
          run_as_user     = 65534
          fs_group        = 65534
          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        service_account_name = kubernetes_service_account.cluster_autoscaler_service_account.metadata[0].name

        container {
          name  = "cluster-autoscaler"
          image = "registry.k8s.io/autoscaling/cluster-autoscaler:v1.25.1"

          resources {
            limits = {
              cpu    = "100m"
              memory = "600Mi"
            }
            requests = {
              cpu    = "100m"
              memory = "600Mi"
            }
          }

          command = ["./cluster-autoscaler", "--v=4", "--stderrthreshold=info", "--cloud-provider=aws", "--skip-nodes-with-local-storage=false", "--expander=least-waste", "--scan-interval=25s", "--scale-down-unneeded-time=30s", "--scale-down-delay-after-add=10s", "--node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/${var.eks_cluster_name}"]

          volume_mount {
            name      = "ssl-certs"
            mount_path = "/etc/ssl/certs/ca-certificates.crt"
            read_only = true
          }

          image_pull_policy = "Always"

          security_context {
            allow_privilege_escalation = false
            capabilities {
              drop = ["ALL"]
            }
            read_only_root_filesystem = true
          }
        }

        volume {
          name = "ssl-certs"
          host_path {
            path = "/etc/ssl/certs/ca-bundle.crt"
          }
        }
      }
    }
  }
}

## metrics-server
# create metrics-server for HPA deployment\pod in EKS 
# Create the Service Account
resource "kubernetes_service_account" "metric_server_service_account" {
  metadata {
    name      = "metrics-server"
    namespace = "kube-system"
    labels = {
      k8s-app = "metrics-server"
    }
  }
}

# Create the Cluster Role
resource "kubernetes_cluster_role" "aggregated_metrics_reader" {
  metadata {
    name = "system:aggregated-metrics-reader"
    labels = {
      k8s-app                                      = "metrics-server"
      "rbac.authorization.k8s.io/aggregate-to-admin" = "true"
      "rbac.authorization.k8s.io/aggregate-to-edit"  = "true"
      "rbac.authorization.k8s.io/aggregate-to-view"  = "true"
    }
  }

  rule {
    api_groups = ["metrics.k8s.io"]
    resources  = ["pods", "nodes"]
    verbs      = ["get", "list", "watch"]
  }
}

# Create the Metric Server Cluster Role
resource "kubernetes_cluster_role" "metrics_server_cluster_role" {
  metadata {
    name = "system:metrics-server"
    labels = {
      k8s-app = "metrics-server"
    }
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "nodes", "nodes/metrics", "namespaces", "configmaps"]
    verbs      = ["get", "list", "watch"]
  }
}

# Create the Metric Server Role Binding
resource "kubernetes_role_binding" "metrics_server_auth_reader" {
  metadata {
    name      = "metrics-server-auth-reader"
    namespace = "kube-system"
    labels = {
      k8s-app = "metrics-server"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = "extension-apiserver-authentication-reader"
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.metric_server_service_account.metadata[0].name
    namespace = "kube-system"
  }
}

# Create the Metric Server Cluster Role Binding
resource "kubernetes_cluster_role_binding" "metrics_server_auth_delegator" {
  metadata {
    name      = "metrics-server:system:auth-delegator"
    labels = {
      k8s-app = "metrics-server"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "system:auth-delegator"
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.metric_server_service_account.metadata[0].name
    namespace = "kube-system"
  }
}

# Create the Metric Server Cluster Role Binding
resource "kubernetes_cluster_role_binding" "metrics_server_cluster_role_binding" {
  metadata {
    name      = "system:metrics-server"
    labels = {
      k8s-app = "metrics-server"
    }
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "system:metrics-server"
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.metric_server_service_account.metadata[0].name
    namespace = "kube-system"
  }
}

# Create the Metric Server Service
resource "kubernetes_service" "metrics_server_service" {
  metadata {
    name      = "metrics-server"
    namespace = "kube-system"
    labels = {
      k8s-app = "metrics-server"
    }
  }

  spec {
    selector = {
      k8s-app = "metrics-server"
    }

    port {
      name       = "https"
      port       = 443
      target_port = "https"
      protocol   = "TCP"
    }
  }
}

# Create the Metric Server Deployment
resource "kubernetes_deployment" "metrics_server_deployment" {
  metadata {
    name      = "metrics-server"
    namespace = "kube-system"
    labels = {
      k8s-app = "metrics-server"
    }
  }

  spec {
    selector {
      match_labels = {
        k8s-app = "metrics-server"
      }
    }

    strategy {
      rolling_update {
        max_unavailable = 0
      }
    }

    template {
      metadata {
        labels = {
          k8s-app = "metrics-server"
        }
      }

      spec {
        host_network       = true

        container {
          name  = "metrics-server"
          image = "k8s.gcr.io/metrics-server/metrics-server:v0.6.2"
          image_pull_policy = "IfNotPresent"

          args = [
            "--cert-dir=/tmp",
            "--secure-port=4443",
            "--kubelet-insecure-tls=true",
            "--kubelet-preferred-address-types=InternalIP",
            "--kubelet-use-node-status-port",
            "--metric-resolution=15s",
          ]

          port {
            container_port = 4443
            name           = "https"
            protocol       = "TCP"
          }

          liveness_probe {
            http_get {
              path      = "/livez"
              port      = "https"
              scheme    = "HTTPS"
            }
            initial_delay_seconds = 10
            period_seconds        = 10
            failure_threshold     = 3
          }

          readiness_probe {
            http_get {
              path      = "/readyz"
              port      = "https"
              scheme    = "HTTPS"
            }
            initial_delay_seconds = 20
            period_seconds        = 10
            failure_threshold     = 3
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true
            run_as_non_root            = true
            run_as_user                = 1000
          }

          volume_mount {
            mount_path = "/tmp"
            name       = "tmp-dir"
          }
        }

        node_selector = {
          "kubernetes.io/os" = "linux"
        }

        priority_class_name = "system-cluster-critical"

        service_account_name = kubernetes_service_account.metric_server_service_account.metadata[0].name

        volume {
          empty_dir {}
          name = "tmp-dir"
        }
      }
    }
  }
}

# Create the Metric Server APIService
resource "kubernetes_api_service" "metrics_server_api_service" {
  metadata {
    name      = "v1beta1.metrics.k8s.io"
    labels = {
      k8s-app = "metrics-server"
    }
  }

  spec {
    group                  = "metrics.k8s.io"
    group_priority_minimum = 100
    insecure_skip_tls_verify = true

    service {
      name      = "metrics-server"
      namespace = "kube-system"
    }

    version           = "v1beta1"
    version_priority = 100
  }
}

## Nginx Application with Public LB 
data "aws_eks_cluster_auth" "cluster_auth" {
  name = var.eks_cluster_name
}

# Create NS application 
resource "kubernetes_namespace" "app" {
  metadata {
    name = "application"
  }
}

# Create deployment for nginx 
resource "kubernetes_deployment" "nginx_deployment" {
  metadata {
    name = "nginx"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "nginx"
      }
    }

    template {
      metadata {
        labels = {
          app = "nginx"
        }
      }
      spec {
        container {
          name  = "nginx"
          image = "nginx:1.14.2"

          port {
            name          = "web"
            container_port = 80
          }
          resources {
            limits = {
                cpu    = "500m"
            } 
            requests = {
                cpu = "200m"
            }
        } 
        }
      }
    }
  }
}

# Create the Service publice LoadBalancer
resource "kubernetes_service" "public_lb_service" {
  metadata {
    name = "nginx-public-lb"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  spec {
    type = "LoadBalancer"

    selector = {
      app = "nginx"
    }

    port {
      protocol   = "TCP"
      port       = 443
      target_port = 80
    }
  }
}

# Create HPA for auto scaler nginx pod base on CPU 
resource "kubernetes_horizontal_pod_autoscaler" "hpa_deployment" {
  metadata {
    name = "nginx-deployment-hpa"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = "nginx"
    }
    min_replicas                          = 1
    max_replicas                          = 30
    target_cpu_utilization_percentage     = 30
  }
}

