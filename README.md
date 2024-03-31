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
  - metrics-server - for resource metrice
  - Nginx Application with Public LB and pod autoscaling

<pre>
.
├── main.tf
├── outputs.tf
├── README.md
└── variables.tf
</pre>

Please be sure that you have kubectl and aws-cli installed.

***Get started***
Clone the repo 
>$ git clone XXX
>$ cd AWS-eks_terraform

**Run Terraform command**
>$ terraform init  
>$ terraform plan 

**and apply**
>$ terraform apply
>

all setting can be change form the variables.tf file 

**Get the KUBECONFIG file**
>$ aws eks --region us-east-1 update-kubeconfig --name test-test 

need to get locaion of the file, like: /home/USER/.kube/config


>$ export KUBECONFIG=/home/USER/.kube/config

**Check**
>$ kubectl get all -A

**For test the autoscaling**
Open new terminal and run  
> $ export KUBECONFIG=/home/USER/.kube/config
> $ watch -n1 kubectl -n application get no,po,hpa
>

On the first terminal.
>$ kubectl -n application run -i --tty load-generator --rm --image=busybox --restart=Never -- /bin/sh -c "while sleep 0.01; do wget -q -O- http://nginx-public-lb:443; done"

The POD run wget function to generator CPU load on the Nginx deployment and force the HPA create new pod and new NODE 

**Clean up**
>$ kubectl delete ns application


>$ terraform destroy --auto-approve

