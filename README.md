# AWS EKS terraform
Terraform resource code for EKS.

includ: 
  - 1. EKS 
  - 2. 2 privet subnet && 2 public subnet 
  - 3. Security Groups
  - 4. privet Node group with aws-autoscaler ( and option to public) 
  - 5. Kubernetes base - Nginx web page application With public loadbalncer and HPA ///CPU base 


component: 
  - AWS - cluster-autoscaler
  - metrics-server - for resource metrices
  - Nginx Application with Public LB and pod autoscaling

<pre>
.
├── main.tf
├── outputs.tf
├── README.md
└── variables.tf
</pre>

Please be sure that you have kubectl and awc-cli install.

***Get started***
Clone the repo 
>$ git clone XXX
>$ cd AWS-eks_terraform

**Run Terraform command**
>$ terraform init  
>$ terraform plan 

and apply 
>$ terraform apply
>
>
all setting can be change form the variables.tf file 

**Get the KUBECONFIG file**
>$ aws eks --region us-east-1 update-kubeconfig --name test-test 
>need to get locaion of the file, like: /home/USER/.kube/config
>
>$ export KUBECONFIG=/home/USER/.kube/config

**Check**
>$ kubectl get all -A


