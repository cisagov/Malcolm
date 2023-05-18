# <a name="KubernetesEKS"></a>Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)

* [Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)](#KubernetesEKS)
    - [Prerequisites](#Prerequisites)
    - [Procedure](#Procedure)
* [Attribution](#AWSAttribution)

This document outlines the process of setting up a cluster on [Amazon Elastic Kubernetes Service (EKS)](https://aws.amazon.com/eks/) using [Amazon Web Services](https://aws.amazon.com/) in preparation for [**Deploying Malcolm with Kubernetes**](kubernetes.md).

This is a work-in-progress document that is still a bit rough around the edges. You'll need to replace things like `cluster-name` and `us-east-1` with the values that are appliable to your cluster. Any feedback is welcome in the [relevant issue](https://github.com/idaholab/Malcolm/issues/194) on GitHub.

This document assumes you have good working knowledge of Amazon Web Services (AWS) and Amazon Elastic Kubernetes Service (EKS). Good documentation resources can be found in the [AWS documentation](https://docs.aws.amazon.com/index.html), the [EKS documentation](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html
) and the [EKS Workshop](https://www.eksworkshop.com/).

## <a name="Prerequisites"></a> Prerequisites

* [aws cli](https://aws.amazon.com/cli/) - the AWS Command Line Interface with functioning access to your AWS infrastructure
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
    * `c4.4xlarge` seems to be a good instance type for Malcolm, but your needs may vary (see [recommended system requirements](system-requirements.md#SystemRequirements) for Malcolm)
    * set the nodes to run on your VPC's public subnets
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
    * [`kubernetes/99-ingress-aws-alb.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/99-ingress-aws-alb.yml.example) is an example ingress manifest for Malcolm using the ALB controller
    * You **must** set `type: LoadBalancer` for the `nginx-proxy` service in [`98-nginx-proxy.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/98-nginx-proxy.yml)
    * [How do I set up the AWS Load Balancer Controller on an Amazon EKS cluster...?](https://repost.aws/knowledge-center/eks-alb-ingress-controller-fargate)
    * [Installing the AWS Load Balancer Controller add-on](https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html)
    * [Application load balancing on Amazon EKS](https://docs.aws.amazon.com/eks/latest/userguide/alb-ingress.html)
1. [deploy Amazon EFS CSI driver](https://docs.aws.amazon.com/eks/latest/userguide/efs-csi.html)
    * review **Prerequisites**
    * follow steps for **Create an IAM policy and role**
    * follow steps for **Install the Amazon EFS driver**
    * follow steps for **Create an Amazon [EFS file system](https://docs.aws.amazon.com/efs/latest/ug/gs-step-two-create-efs-resources.html)**
1. [Create and launch an EC2 instance](https://docs.aws.amazon.com/efs/latest/ug/gs-step-one-create-ec2-resources.html) for initializing the directory structure on the EFS filesystem (this can be a very small instance, e.g., `t2.micro`). Make sure when configuring this instance to give access to the EFS file system in the storage configuration.
1. SSH to the EC2 instance and initialize NFS subdirectories
    - set up malcolm subdirectory
      ```bash
      sudo touch /mnt/efs/fs1/test-file.txt
      sudo mkdir -p /mnt/efs/fs1/malcolm
      sudo chown 1000:1000 /mnt/efs/fs1/malcolm
      ```
    - `/mnt/efs/fs1/malcolm/init_storage.sh`
      ```bash
      #!/bin/bash

      if [ -z "$BASH_VERSION" ]; then
        echo "Wrong interpreter, please run \"$0\" with bash"
        exit 1
      fi

      ENCODING="utf-8"

      RUN_PATH="$(pwd)"
      [[ "$(uname -s)" = 'Darwin' ]] && REALPATH=grealpath || REALPATH=realpath
      [[ "$(uname -s)" = 'Darwin' ]] && DIRNAME=gdirname || DIRNAME=dirname
      if ! (type "$REALPATH" && type "$DIRNAME") > /dev/null; then
        echo "$(basename "${BASH_SOURCE[0]}") requires $REALPATH and $DIRNAME"
        exit 1
      fi
      SCRIPT_PATH="$($DIRNAME $($REALPATH -e "${BASH_SOURCE[0]}"))"
      pushd "$SCRIPT_PATH" >/dev/null 2>&1

      rm -rf ./opensearch/* ./opensearch-backup/* ./pcap/* ./suricata-logs/* ./zeek-logs/* ./config/netbox/* ./config/zeek/* ./runtime-logs/*
      mkdir -vp ./config/auth ./config/htadmin ./config/opensearch ./config/logstash ./config/netbox/media ./config/netbox/postgres ./config/netbox/redis ./config/zeek/intel/MISP ./config/zeek/intel/STIX ./opensearch ./opensearch-backup ./pcap/upload ./pcap/processed ./suricata-logs ./zeek-logs/current ./zeek-logs/upload ./zeek-logs/extract_files ./runtime-logs/arkime ./runtime-logs/nginx

      popd >/dev/null 2>&1
      ```
      ```bash
      /mnt/efs/fs1/malcolm/init_storage.sh
      mkdir: created directory './config/netbox/media'
      mkdir: created directory './config/netbox/postgres'
      mkdir: created directory './config/netbox/redis'
      mkdir: created directory './config/zeek/intel'
      mkdir: created directory './config/zeek/intel/MISP'
      mkdir: created directory './config/zeek/intel/STIX'
      mkdir: created directory './pcap/upload'
      mkdir: created directory './pcap/processed'
      mkdir: created directory './zeek-logs/current'
      mkdir: created directory './zeek-logs/upload'
      mkdir: created directory './zeek-logs/extract_files'
      mkdir: created directory './runtime-logs'
      ```
1. Set up [access points](https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html), and note the **Access point ID**s to put in your YAML in the next step

    | name              | mountpoint                 | access point ID        | 
    | ----------------- | -------------------------- | ---------------------- |
    | config            | /malcolm/config            | fsap-config            |
    | opensearch        | /malcolm/opensearch        | fsap-opensearch        |
    | opensearch-backup | /malcolm/opensearch-backup | fsap-opensearch-backup |
    | pcap              | /malcolm/pcap              | fsap-pcap              |
    | runtime-logs      | /malcolm/runtime-logs      | fsap-runtime-logs      |
    | suricata-logs     | /malcolm/suricata-logs     | fsap-suricata-logs     |
    | zeek-logs         | /malcolm/zeek-logs         | fsap-zeek-logs         |

1. Create manifest for persistent volumes and volume claims from the EFS file system ID and access point IDs
    * See [**PersistentVolumeClaim Definitions**](kubernetes.md#PVC) under [**Deploying Malcolm with Kubernetes**](kubernetes.md)
    * [`kubernetes/01-volumes-aws-efs.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/01-volumes-aws-efs.yml.example) is an example manifest you can use as a starting point. Copy `01-volumes-aws-efs.yml.example` to `01-volumes.yml` and replace `fs-FILESYSTEMID` with the EFS file system and each `fsap-…` value with the corresponding access point ID from the previous step.
1. Finish [configuring](kubernetes.md#Config) and [start](kubernetes.md#Running) Malcolm as described in [**Deploying Malcolm with Kubernetes**](kubernetes.md)

## <a name="AWSAttribution"></a> Attribution

Amazon Web Services, AWS, the Powered by AWS logo, and Amazon Elastic Kubernetes Service (EKS) are trademarks of Amazon.com, Inc. or its affiliates. The information about providers and services contained in this document is for instructional purposes and does not constitute endorsement or recommendation. 
