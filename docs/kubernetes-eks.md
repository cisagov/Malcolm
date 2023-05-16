# <a name="KubernetesEKS"></a>Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)

This document outlines the process of setting up a cluster on [Amazon Elastic Kubernetes Service (EKS)](https://aws.amazon.com/eks/) using [Amazon Web Services](https://aws.amazon.com/) in preparation for [**Deploying Malcolm with Kubernetes**](kubernetes.md).

This is a work-in-progress document that is still a bit rough around the edges. You'll need to replace things like `cluster-name` and `us-east-1` with the values that are appliable to your cluster. Any feedback is welcome in the [relevant issue](https://github.com/idaholab/Malcolm/issues/194) on GitHub.

## Prerequisites

* [aws cli](https://aws.amazon.com/cli/) with functioning access to your AWS infrastructure
* [eksctl](https://eksctl.io/)

## Procedure

1. Create a [VPC](https://us-east-1.console.aws.amazon.com/vpc/home?region=us-east-1#vpcs:) with subnets in 2 or more availability zones
1. Create a [security group](https://us-east-1.console.aws.amazon.com/vpc/home?region=us-east-1#SecurityGroups:) for VPC
1. Create an [EKS cluster](https://us-east-1.console.aws.amazon.com/eks/home?region=us-east-1#/clusters)
1. Generate a kubeconfig file to use with Malcolm's control scripts (`malcolmeks.yaml` is used in this example)
    ```bash
    aws eks update-kubeconfig --region us-east-1 --name cluster-name --kubeconfig malcolmeks.yaml
    ```
1. Create a [node group](https://us-east-1.console.aws.amazon.com/eks/home?region=us-east-1#/clusters/cluster-name/add-node-group)
1. [Deploy](https://docs.aws.amazon.com/eks/latest/userguide/metrics-server.html) `metrics-server`
    ```bash
    kubectl --kubeconfig=malcolmeks.yaml apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
    ```
1. Deploy ingress-nginx as described [here](kubernetes.md#Ingress). [This script (`deploy_ingress_nginx.sh`)]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/deploy_ingress_nginx.sh) may be helpful in doing so. To [provide external access](https://repost.aws/knowledge-center/eks-access-kubernetes-services) to services in the EKS cluster, pass `-a -e` to `deploy_ingress_nginx.sh`
1. Associate IAM OIDC provider with cluster
    ```bash
    eksctl utils associate-iam-oidc-provider --region=us-east-1 --cluster=cluster-name --approve
    ```
1. [deploy Amazon EFS CSI driver](https://docs.aws.amazon.com/eks/latest/userguide/efs-csi.html)
    * review **Prerequisites**
    * follow steps for **Create an IAM policy and role**
    * follow steps for **Install the Amazon EFS driver**
    * follow steps for **Create an Amazon [EFS file system](https://docs.aws.amazon.com/efs/latest/ug/gs-step-two-create-efs-resources.html)**
1. [Create and launch an EC2 instance](https://docs.aws.amazon.com/efs/latest/ug/gs-step-one-create-ec2-resources.html) for initializing the directory structure on the EFS filesystem (this can be a very small instance, e.g., t2.micro). Make sure when configuring this instance you give configure to the EFS file system in the storage configuration.
1. SSH to instance and initialize NFS subdirectories
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

1. Create YAML for persistent volumes and volume claims from the EBS Volume ID. In this example, replace `fs-FILESYSTEMID` with your EFS filesystem ID and `fsap-XXXXXXXX` with the appropriate access point ID
    ```yaml
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: pcap-volume
      namespace: malcolm
      labels:
        namespace: malcolm
    spec:
      capacity:
        storage: 500Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteMany
      persistentVolumeReclaimPolicy: Retain
      storageClassName: efs-sc
      csi:
        driver: efs.csi.aws.com
        volumeHandle: fs-FILESYSTEMID::fsap-pcap

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: pcap-claim
      namespace: malcolm
    spec:
      storageClassName: efs-sc
      accessModes:
        - ReadWriteMany
      volumeMode: Filesystem
      resources:
        requests:
          storage: 500Gi
      volumeName: pcap-volume

    ---
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: zeek-volume
      namespace: malcolm
      labels:
        namespace: malcolm
    spec:
      capacity:
        storage: 250Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteMany
      persistentVolumeReclaimPolicy: Retain
      storageClassName: efs-sc
      csi:
        driver: efs.csi.aws.com
        volumeHandle: fs-FILESYSTEMID::fsap-zeek-logs

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: zeek-claim
      namespace: malcolm
    spec:
      storageClassName: efs-sc
      accessModes:
        - ReadWriteMany
      volumeMode: Filesystem
      resources:
        requests:
          storage: 250Gi
      volumeName: zeek-volume

    ---
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: suricata-volume
      namespace: malcolm
      labels:
        namespace: malcolm
    spec:
      capacity:
        storage: 100Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteMany
      persistentVolumeReclaimPolicy: Retain
      storageClassName: efs-sc
      csi:
        driver: efs.csi.aws.com
        volumeHandle: fs-FILESYSTEMID::fsap-suricata-logs

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: suricata-claim
      namespace: malcolm
    spec:
      storageClassName: efs-sc
      accessModes:
        - ReadWriteMany
      volumeMode: Filesystem
      resources:
        requests:
          storage: 100Gi
      volumeName: suricata-volume

    ---
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: config-volume
      namespace: malcolm
      labels:
        namespace: malcolm
    spec:
      capacity:
        storage: 25Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteMany
      persistentVolumeReclaimPolicy: Retain
      storageClassName: efs-sc
      csi:
        driver: efs.csi.aws.com
        volumeHandle: fs-FILESYSTEMID::fsap-config

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: config-claim
      namespace: malcolm
    spec:
      storageClassName: efs-sc
      accessModes:
        - ReadWriteMany
      volumeMode: Filesystem
      resources:
        requests:
          storage: 25Gi
      volumeName: config-volume

    ---
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: runtime-logs-volume
      namespace: malcolm
      labels:
        namespace: malcolm
    spec:
      capacity:
        storage: 25Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteMany
      persistentVolumeReclaimPolicy: Retain
      storageClassName: efs-sc
      csi:
        driver: efs.csi.aws.com
        volumeHandle: fs-02997421cdc55b8e4::fsap-runtime-logs

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: runtime-logs-claim
      namespace: malcolm
    spec:
      storageClassName: efs-sc
      accessModes:
        - ReadWriteMany
      volumeMode: Filesystem
      resources:
        requests:
          storage: 25Gi
      volumeName: runtime-logs-volume

    ---
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: opensearch-volume
      namespace: malcolm
      labels:
        namespace: malcolm
    spec:
      capacity:
        storage: 500Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteOnce
      persistentVolumeReclaimPolicy: Retain
      storageClassName: efs-sc
      csi:
        driver: efs.csi.aws.com
        volumeHandle: fs-FILESYSTEMID::fsap-opensearch

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: opensearch-claim
      namespace: malcolm
    spec:
      storageClassName: efs-sc
      accessModes:
        - ReadWriteOnce
      volumeMode: Filesystem
      resources:
        requests:
          storage: 500Gi
      volumeName: opensearch-volume

    ---
    apiVersion: v1
    kind: PersistentVolume
    metadata:
      name: opensearch-backup-volume
      namespace: malcolm
      labels:
        namespace: malcolm
    spec:
      capacity:
        storage: 500Gi
      volumeMode: Filesystem
      accessModes:
        - ReadWriteOnce
      persistentVolumeReclaimPolicy: Retain
      storageClassName: efs-sc
      csi:
        driver: efs.csi.aws.com
        volumeHandle: fs-FILESYSTEMID::fsap-opensearch-backup

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: opensearch-backup-claim
      namespace: malcolm
    spec:
      storageClassName: efs-sc
      accessModes:
        - ReadWriteOnce
      volumeMode: Filesystem
      resources:
        requests:
          storage: 500Gi
      volumeName: opensearch-backup-volume
    ```
1. Finish [configuring](kubernetes.md#Config) and [configuring](kubernetes.md#Running) Malcolm as described in [**Deploying Malcolm with Kubernetes**](kubernetes.md)