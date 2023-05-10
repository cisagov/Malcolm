## Notes for deploying Malcolm on AWS EKS

This document is a rough work in progress and isn't necessarily correct (yet). -SG

Prerequisites:

* [aws cli](https://aws.amazon.com/cli/)
* [eksctl](https://eksctl.io/)

1. Create [VPC](https://us-east-1.console.aws.amazon.com/vpc/home?region=us-east-1#vpcs:) with subnets in 2 availability zones
1. Create [security group](https://us-east-1.console.aws.amazon.com/vpc/home?region=us-east-1#SecurityGroups:) for VPC
1. [Create and launch an EC2 instance](https://docs.aws.amazon.com/efs/latest/ug/gs-step-one-create-ec2-resources.html)
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

      rm -rf ./opensearch/* ./opensearch-backup/* ./pcap/* ./suricata-logs/* ./zeek-logs/* ./config/netbox/* ./config/zeek/*
      mkdir -vp ./config/auth ./config/htadmin ./config/opensearch ./config/logstash ./config/netbox/media ./config/netbox/postgres ./config/netbox/redis ./config/zeek/intel/MISP ./config/zeek/intel/STIX ./opensearch ./opensearch-backup ./pcap/upload ./pcap/processed ./suricata-logs ./zeek-logs/current ./zeek-logs/upload ./zeek-logs/extract_files

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
      ```
1. I set up [access points](https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html), but I don't know (yet) if that will be useful
    ```
    opensearch-backup /malcolm/opensearch-backup
    opensearch /malcolm/opensearch
    pcap /malcolm/pcap
    config /malcolm/config
    suricata-logs /malcolm/suricata-logs
    zeek-logs /malcolm/zeek-logs
    ```
1. Create [EKS cluster](https://us-east-1.console.aws.amazon.com/eks/home?region=us-east-1#/clusters)
1. Create [node group](https://us-east-1.console.aws.amazon.com/eks/home?region=us-east-1#/clusters/cluster-name/add-node-group)
1. Generate kubeconfig file if you need to
    ```bash
    aws eks update-kubeconfig --region us-east-1 --name cluster-name --kubeconfig malcolmeks.yaml
    ```
1. [Deploy](https://docs.aws.amazon.com/eks/latest/userguide/metrics-server.html) `metrics-server`
    ```bash
    kubectl --kubeconfig=malcolmeks.yaml apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
    ```
1. [Deploy]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/vagrant/deploy_ingress_nginx.sh) [ingress-nginx](kubernetes.md#Ingress)
1. Associate IAM OIDC provider with cluster
    ```bash
    eksctl utils associate-iam-oidc-provider --region=us-east-1 --cluster=cluster-name
    ```
1. [deploy Amazon EFS CSI driver](https://docs.aws.amazon.com/eks/latest/userguide/efs-csi.html)
    * look at **Prerequisites**
    * do **Create an IAM policy and role**
    * do **Install the Amazon EFS driver**
    * do **Create an Amazon [EFS file system](https://docs.aws.amazon.com/efs/latest/ug/gs-step-two-create-efs-resources.html)**
1. Create YAML for persistent volumes and volume claims from the EBS Volume ID
    ```yaml
    ---
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
      storageClassName: io1
      awsElasticBlockStore:
        fsType: xfs
        volumeID: aws://us-east-1a/vol-0123456789c82a042

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: pcap-claim
      namespace: malcolm
    spec:
      storageClassName: io1
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
      storageClassName: io1
      awsElasticBlockStore:
        fsType: xfs
        volumeID: aws://us-east-1a/vol-0123456789c67edd9

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: zeek-claim
      namespace: malcolm
    spec:
      storageClassName: io1
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
      storageClassName: io1
      awsElasticBlockStore:
        fsType: xfs
        volumeID: aws://us-east-1a/vol-0123456789dccd75e

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: suricata-claim
      namespace: malcolm
    spec:
      storageClassName: io1
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
      storageClassName: io1
      awsElasticBlockStore:
        fsType: xfs
        volumeID: aws://us-east-1a/vol-0123456789429a231

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: config-claim
      namespace: malcolm
    spec:
      storageClassName: io1
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
      storageClassName: io1
      awsElasticBlockStore:
        fsType: xfs
        volumeID: aws://us-east-1a/vol-0123456789dc2ea7a

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: runtime-logs-claim
      namespace: malcolm
    spec:
      storageClassName: io1
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
      storageClassName: gp2-retain
      awsElasticBlockStore:
        fsType: xfs
        volumeID: aws://us-east-1a/vol-01234567895ff99a1

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: opensearch-claim
      namespace: malcolm
    spec:
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
      awsElasticBlockStore:
        fsType: xfs
        volumeID: aws://us-east-1a/vol-01234567891150804

    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: opensearch-backup-claim
      namespace: malcolm
    spec:
      storageClassName: gp2-retain
      accessModes:
        - ReadWriteOnce
      volumeMode: Filesystem
      resources:
        requests:
          storage: 500Gi
      volumeName: opensearch-backup-volume
    ```
