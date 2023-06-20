# <a name="KubernetesEKS"></a>Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)

* [Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)](#KubernetesEKS)
    - [Prerequisites](#Prerequisites)
    - [Procedure](#Procedure)
* [Attribution](#AWSAttribution)

This document outlines the process of setting up a cluster on [Amazon Elastic Kubernetes Service (EKS)](https://aws.amazon.com/eks/) using [Amazon Web Services](https://aws.amazon.com/) in preparation for [**Deploying Malcolm with Kubernetes**](kubernetes.md).

This is a work-in-progress document that is still a bit rough around the edges. Users will need to replace things such as `cluster-name` and `us-east-1` with the values that are appliable to the cluster. Any feedback is welcome in the [relevant issue](https://github.com/idaholab/Malcolm/issues/194) on GitHub.

This document assumes good working knowledge of Amazon Web Services (AWS) and Amazon Elastic Kubernetes Service (EKS). Good documentation resources can be found in the [AWS documentation](https://docs.aws.amazon.com/index.html), the [EKS documentation](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html
) and the [EKS Workshop](https://www.eksworkshop.com/).

## <a name="Prerequisites"></a> Prerequisites

* [aws cli](https://aws.amazon.com/cli/) - the AWS Command Line Interface with functioning access to the AWS infrastructure
* [eksctl](https://eksctl.io/) - the official CLI for Amazon EKS

## <a name="Procedure"></a> Procedure

1. Create a [Virtual Private Cloud (VPC)](https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html)
    * subnets in at least 2 availability zones
    * tag private subnets with `kubernetes.io/role/internal-elb`: `1`
    * tag public subnets with `kubernetes.io/role/elb`: `1`
    * enable "auto-assign public IP address" for public subnets
1. Create a [security group](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html) for the VPC
1. Create an [Elastic Kubernetes Service (EKS) cluster](https://docs.aws.amazon.com/eks/latest/userguide/clusters.html)
1. Generate a kubeconfig file to use with Malcolm's control scripts (`malcolmeks.yaml` is used in this example)
    ```bash
    aws eks update-kubeconfig --region us-east-1 --name cluster-name --kubeconfig malcolmeks.yaml
    ```
1. Create a [node group](https://docs.aws.amazon.com/eks/latest/userguide/managed-node-groups.html)
    * Both `c4.4xlarge` and `t3a.2xlarge` seem to be good instance types for Malcolm, but users' needs may vary (see [recommended system requirements](system-requirements.md#SystemRequirements) for Malcolm)
    * set the nodes to run on the VPC's public subnets
1. [Deploy `metrics-server`](https://docs.aws.amazon.com/eks/latest/userguide/metrics-server.html) 
    ```bash
    kubectl --kubeconfig=malcolmeks.yaml apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
    ```
1. Associate IAM OIDC provider with cluster
    ```bash
    eksctl utils associate-iam-oidc-provider --region=us-east-1 --cluster=cluster-name --approve
    ```
1. Deploy the AWS Load Ballancer Controller add-on
    * See [**Ingress Controllers**](kubernetes.md#Ingress) under [**Deploying Malcolm with Kubernetes**](kubernetes.md)
    * [`kubernetes/99-ingress-aws-alb.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-aws-alb.yml.example) is an example ingress manifest for Malcolm using the ALB controller for HTTP(S) requests and the NLB controller for TCP connections to Logstash and Filebeat
    * Users must set `type: LoadBalancer` for the `nginx-proxy` service in [`98-nginx-proxy.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/98-nginx-proxy.yml), the `filebeat` service in [`12-filebeat.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/12-filebeat.yml) and the the `logstash` service in [`13-logstash.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/13-logstash.yml)
    * [How do I set up the AWS Load Balancer Controller on an Amazon EKS cluster...?](https://repost.aws/knowledge-center/eks-alb-ingress-controller-fargate)
    * [Installing the AWS Load Balancer Controller add-on](https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html)
    * [Application load balancing on Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/alb-ingress.html)
    * [Network load balancing on Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/network-load-balancing.html)
1. [deploy Amazon EFS CSI driver](https://docs.aws.amazon.com/eks/latest/userguide/efs-csi.html)
    * review **Prerequisites**
    * follow steps for **Create an IAM policy and role**
    * follow steps for **Install the Amazon EFS driver**
    * follow steps for **Create an Amazon [EFS file system](https://docs.aws.amazon.com/efs/latest/ug/gs-step-two-create-efs-resources.html)**
1. Set up [access points](https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html), and note the **Access point ID**s to put in the YAML in the next step

    | name              | mountpoint                 | access point ID | 
    | ----------------- | -------------------------- | ----------------|
    | config            | /malcolm/config            | fsap-…          |
    | opensearch        | /malcolm/opensearch        | fsap-…          |
    | opensearch-backup | /malcolm/opensearch-backup | fsap-…          |
    | pcap              | /malcolm/pcap              | fsap-…          |
    | runtime-logs      | /malcolm/runtime-logs      | fsap-…          |
    | suricata-logs     | /malcolm/suricata-logs     | fsap-…          |
    | zeek-logs         | /malcolm/zeek-logs         | fsap-…          |

1. Create manifest for persistent volumes and volume claims from the EFS file system ID and access point IDs
    * See [**PersistentVolumeClaim Definitions**](kubernetes.md#PVC) under [**Deploying Malcolm with Kubernetes**](kubernetes.md)
    * [`kubernetes/01-volumes-aws-efs.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/01-volumes-aws-efs.yml.example) is an example manifest to use as a starting point. Copy `01-volumes-aws-efs.yml.example` to `01-volumes.yml` and replace `fs-FILESYSTEMID` with the EFS file system and each `fsap-…` value with the corresponding access point ID from the previous step.
1. Finish [the configuration](kubernetes.md#Config) then [start](kubernetes.md#Running) Malcolm as described in [**Deploying Malcolm with Kubernetes**](kubernetes.md)

## <a name="AWSAttribution"></a> Attribution

Amazon Web Services, AWS, the Powered by AWS logo, and Amazon Elastic Kubernetes Service (EKS) are trademarks of Amazon.com, Inc. or its affiliates. The information about providers and services contained in this document is for instructional purposes and does not constitute endorsement or recommendation. 
