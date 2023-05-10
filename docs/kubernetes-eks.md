## Notes for deploying Malcolm on AWS EKS

This document is a rough work in progress and isn't necessarily correct (yet). -SG

1. Create [VPC](https://us-east-1.console.aws.amazon.com/vpc/home?region=us-east-1#vpcs:) with subnets in 2 availability zones
1. Create [security group](https://us-east-1.console.aws.amazon.com/vpc/home?region=us-east-1#SecurityGroups:) for VPC
1. Create [EKS cluster](https://us-east-1.console.aws.amazon.com/eks/home?region=us-east-1#/clusters)
1. Create [node group](https://us-east-1.console.aws.amazon.com/eks/home?region=us-east-1#/clusters/cluster-name/add-node-group)
1. Create volumes (**p**cap, **z**eek, **s**uricata, **c**onfig, **r**untime-**l**ogs, **o**pensearch, **b**ackup), got volume IDs
        ```bash
        aws ec2 create-volume --region us-east-1 --availability-zone us-east-1a --size 500 --volume-type gp2
        aws ec2 create-volume --region us-east-1 --availability-zone us-east-1a --size 250 --volume-type gp2
        aws ec2 create-volume --region us-east-1 --availability-zone us-east-1a --size 100 --volume-type gp2
        aws ec2 create-volume --region us-east-1 --availability-zone us-east-1a --size 25 --volume-type gp2
        aws ec2 create-volume --region us-east-1 --availability-zone us-east-1a --size 25 --volume-type gp2
        aws ec2 create-volume --region us-east-1 --availability-zone us-east-1a --size 500 --volume-type gp2
        aws ec2 create-volume --region us-east-1 --availability-zone us-east-1a --size 500 --volume-type gp2
        ```
        ```
        p vol-0123456789c82a042
        z vol-0123456789c67edd9
        s vol-0123456789dccd75e
        c vol-0123456789429a231
        r vol-0123456789dc2ea7a
        o vol-01234567895ff99a1
        b vol-01234567891150804
        ```
1. Create EC2 instance, attach volumes
    ```bash
    aws ec2 attach-volume --volume-id vol-0123456789c82a042 --instance-id i-0123456789abcdef0 --device /dev/xvdp
    aws ec2 attach-volume --volume-id vol-0123456789c67edd9 --instance-id i-0123456789abcdef0 --device /dev/xvdz
    aws ec2 attach-volume --volume-id vol-0123456789dccd75e --instance-id i-0123456789abcdef0 --device /dev/xvds
    aws ec2 attach-volume --volume-id vol-0123456789429a231 --instance-id i-0123456789abcdef0 --device /dev/xvdc
    aws ec2 attach-volume --volume-id vol-0123456789dc2ea7a --instance-id i-0123456789abcdef0 --device /dev/xvdr
    aws ec2 attach-volume --volume-id vol-01234567895ff99a1 --instance-id i-0123456789abcdef0 --device /dev/xvdo
    aws ec2 attach-volume --volume-id vol-01234567891150804 --instance-id i-0123456789abcdef0 --device /dev/xvdb
    ```
1. Format attached volumes as XFS
    ```bash
    for DRV in p z s c r o b; do sudo mkfs.xfs -f /dev/xvd${DRV}; done
    ```
1. Mount drives and set permissions
    ```bash
    for DRV in p z s c r o b; do sudo umount -f /dev/xvd${DRV} 2>/dev/null; sudo mkdir -vp /media/xvd${DRV}; sudo mount /dev/xvd${DRV} /media/xvd${DRV}; sudo chown -R $(id -u):$(id -g) /media/xvd${DRV}; df -h /media/xvd${DRV}; done
    ```
1. Create necessary subdirectories inside of some directories (config, pcap, zeek)
    ```bash
    mkdir -vp /media/xvdc/{auth,htadmin,opensearch,logstash,netbox/media,netbox/postgres,netbox/redis,zeek/intel/MISP,zeek/intel/STIX}
    mkdir -vp /media/xvdp/{upload,proceessed}
    mkdir -vp /media/xvdz/{current,upload,extract_files}
    ```
1. Unmount drives
    ```bash
    for DRV in p z s c r o b; do sudo umount -f /dev/xvd${DRV}; done
    ```
1. Detach volumes
    ```bash
    aws ec2 detach-volume --volume-id vol-0123456789c82a042 --instance-id i-0123456789abcdef0
    aws ec2 detach-volume --volume-id vol-0123456789c67edd9 --instance-id i-0123456789abcdef0
    aws ec2 detach-volume --volume-id vol-0123456789dccd75e --instance-id i-0123456789abcdef0
    aws ec2 detach-volume --volume-id vol-0123456789429a231 --instance-id i-0123456789abcdef0
    aws ec2 detach-volume --volume-id vol-0123456789dc2ea7a --instance-id i-0123456789abcdef0
    aws ec2 detach-volume --volume-id vol-01234567895ff99a1 --instance-id i-0123456789abcdef0
    aws ec2 detach-volume --volume-id vol-01234567891150804 --instance-id i-0123456789abcdef0
    ```
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
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
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
      storageClassName: gp2-retain
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
        - ReadWriteMany
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
        - ReadWriteMany
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
        - ReadWriteMany
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
        - ReadWriteMany
      volumeMode: Filesystem
      resources:
        requests:
          storage: 500Gi
      volumeName: opensearch-backup-volume
    ```
