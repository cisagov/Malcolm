# <a name="ThirdPartyEnv"></a>Deploying Malcolm in Other Third-Party Environments

* [Deploying Malcolm in Other Third-Party Environments](#ThirdPartyEnv)
    - [Installing Malcolm in an EC2 instance on Amazon Web Services (AWS)](#AWSEC2)
        + [Prerequisites](#AWSEC2Prerequisites)
        + [Procedure](#AWSEC2Procedure)
            - [Instance creation](#AWSEC2Instance)
            - [Malcolm setup](#AWSEC2Install)
            - [Running Malcolm](#AWSEC2Run)
    - [Installing Malcolm on Amazon Web Services (AWS) Fargate](#AWSFargate)
    - [Generating a Malcolm Amazon Machine Image (AMI) for Use on Amazon Web Services (AWS)](#AWSAMI)
        + [Prerequisites](#AWSAMIPrerequisites)
        + [Procedure](#AWSAMIProcedure)
            * [Using MFA](#AWSAMIMFA)
    - [Attribution](#AWSAttribution)

## <a name="AWSEC2"></a>Installing Malcolm in an EC2 instance on Amazon Web Services (AWS)

This section outlines the process of using the [AWS Command Line Interface (CLI)](https://aws.amazon.com/cli/) to instantiate an [EC2](https://aws.amazon.com/ec2/) instance running Malcolm. This section assumes good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

### <a name="AWSEC2Prerequisites"></a> Prerequisites

* [aws cli](https://aws.amazon.com/cli/)
    - the AWS Command Line Interface with functioning access to AWS infrastructure

    ```bash
    $ curl -sSL \
        -o /tmp/awscli.zip \
        "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip"
    $ unzip -d /tmp /tmp/awscli.zip
    …
    $ sudo /tmp/aws/install
    You can now run: /usr/local/bin/aws --version
    $ aws --version
    aws-cli/2.26.2 Python/3.13.2 Linux/6.1.0-32-amd64 exe/x86_64.ubuntu.24
    ```

### <a name="AWSEC2Procedure"></a> Procedure

#### <a name="AWSEC2Instance"></a> Instance creation

These steps are to be run on a Linux, Windows, or macOS system in a command line environment with the [AWS Command Line Interface (AWS CLI)](https://aws.amazon.com/cli/) installed. Users should adjust these steps to their own use cases in terms of naming resources, setting security policies, etc.

* Create a [key pair for the EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html)

```bash
$ aws ec2 create-key-pair \
    --key-name malcolm-key \
    --query "KeyMaterial" \
    --output text > malcolm-key.pem
```

* Create a [security group for the EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html)

```bash
$ aws ec2 create-security-group \
    --group-name malcolm-sg \
    --description "Malcolm SG"
```

* Set inbound [security group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
    - These rules will allow SSH and HTTPS access from the address(es) specified
    - Replace `YOUR_PUBLIC_IP` with the public IP address(es) (i.e., addresses which will be allowed to connect to the Malcolm instance via SSH and HTTPS) in the following commands

```bash
$ aws ec2 authorize-security-group-ingress \
    --group-name malcolm-sg \
    --protocol tcp \
    --port 22 \
    --cidr YOUR_PUBLIC_IP/32
$ aws ec2 authorize-security-group-ingress \
    --group-name malcolm-sg \
    --protocol tcp \
    --port 443 \
    --cidr YOUR_PUBLIC_IP/32
```

* [Get a list](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/finding-an-ami.html) of Ubuntu Minimal [AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html)
    - This example uses Ubuntu as the base operating system for the EC2 instance
    - `099720109477` is the account number for Canonical, the producer of Ubuntu
    - Replace `ARCH` with the desired architecture (`amd64` or `arm64`) in the following command
    - Make note of the most recent AMI ID for the next step

```bash
$ aws ec2 describe-images \
    --owners 099720109477 \
    --filters "Name=name,Values=ubuntu-minimal/images/*/ubuntu-noble-24.04-ARCH*" \
    --query "Images[*].[Name,ImageId,CreationDate]" \
    --output text
```

* Launch selected AMI
    - Malcolm is a resource-intensive tool: instance types should meet Malcolm's [minimum system requirements](system-requirements.md#SystemRequirements). Some instance types meeting recommended minimum requirements:
        + amd64
            * [c4.4xlarge](https://aws.amazon.com/ec2/instance-types/#Compute_Optimized), [t2.2xlarge, or t3a.2xlarge](https://aws.amazon.com/ec2/instance-types/#General_Purpose)
        + arm64
            * [m6gd.2xlarge, m6g.2xlarge, m7g.2xlarge, and t4g.2xlarge](https://aws.amazon.com/ec2/instance-types/#General_Purpose)
    - Replace `INSTANCE_TYPE` with the desired instance type in the following command
    - Replace `AMI_ID` with the AMI ID from the previous step in the following command
    - The size of the storage volume will vary depending on the amount of data users plan to process and retain in Malcolm. The example here uses 100 GiB; users should adjust as needed for their specific use case.

```bash
$ aws ec2 run-instances \
    --image-id AMI_ID \
    --instance-type INSTANCE_TYPE \
    --key-name malcolm-key \
    --security-group-ids malcolm-sg \
    --block-device-mappings "[{\"DeviceName\":\"/dev/sda1\",\"Ebs\":{\"VolumeSize\":100,\"VolumeType\":\"gp3\"}}]" \
    --count 1 \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=Malcolm}]"
```

* Get [instance details](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instances.html) and check its status

```bash
$ aws ec2 describe-instances \
    --filters "Name=tag:Name,Values=Malcolm" \
    --query "Reservations[].Instances[].{ID:InstanceId,IP:PublicIpAddress,State:State.Name}"
```

#### <a name="AWSEC2Install"></a> Malcolm setup

The next steps are to be run as the `ubuntu` user inside the EC2 instance, either connected via [Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) or via SSH using the key pair created in the first step.

* Install `curl`, `unzip`, and `python3`

```bash
$ sudo apt-get -y update
…
$ sudo apt-get -y install --no-install-recommends \
    curl \
    unzip \
    python3 \
    python3-dialog \
    python3-pip \
    python3-ruamel.yaml
…
```

* [Download](download.md#DownloadDockerImages) the latest Malcolm release ZIP file
    - Navigate a web browser to the [Malcolm releases page]({{ site.github.repository_url }}/releases/latest) and identify the version number of the latest Malcolm release (`{{ site.malcolm.version }}` is used in this example).

```bash
$ curl -OJsSLf https://github.com/cisagov/Malcolm/releases/latest/download/malcolm-{{ site.malcolm.version }}-docker_install.zip

$ ls -l malcolm*.zip
-rw-rw-r-- 1 ubuntu ubuntu 191053 Apr 10 14:26 malcolm-{{ site.malcolm.version }}-docker_install.zip
```

* Extract the Malcolm release ZIP file

```bash
$ unzip malcolm-{{ site.malcolm.version }}-docker_install.zip
Archive:  malcolm-{{ site.malcolm.version }}-docker_install.zip
  inflating: install.py
  inflating: malcolm_20250401_225238_df27028c.README.txt
  inflating: malcolm_20250401_225238_df27028c.tar.gz
  inflating: malcolm_common.py
  inflating: malcolm_kubernetes.py
  inflating: malcolm_utils.py
```

* Run `install.py`.
    - Malcolm's installation and configuration scripts will guide users through the setup process.
    - Use the following resources to answer the installation and configuration questions:
        + [Installation example using Ubuntu 24.04 LTS](ubuntu-install-example.md#InstallationExample)
        + [In-depth description of configuration questions](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)

* `install.py`: Docker installation and system configuration
    - The [installer script](malcolm-config.md#ConfigAndTuning) will install and configure Docker and Docker Compose, and make necessary changes to system configuration.

```bash
"docker info" failed, attempt to install Docker? (Y / n): y

Attempt to install Docker using official repositories? (Y / n): y

Apply recommended system tweaks automatically without asking for confirmation? y
…
```

* `install.py`: Malcolm configuration
    - Users should answer the remaining [configuration questions](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig) as they apply to their use case.

* Pull Malcolm container images
    - Answer **Yes** when prompted to **Pull Malcolm images?**
    - Pulling the container images may take several minutes.

* Reboot the instance
    - This allows the changes to system configuration to take effect
    - After a few minutes, reconnect via Session Manager or SSH

```bash
$ sudo reboot
…
```

* Set up authentication
    - [Configure authentication](authsetup.md#AuthSetup) using `./scripts/auth_setup` in the Malcolm installation directory.
    - [This example](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) can guide users through the remaining prompts.

```bash
$ cd ~/malcolm

$ ./scripts/auth_setup

all        Configure all authentication-related settings
…
```

#### <a name="AWSEC2Run"></a> Running Malcolm

* Start Malcolm
    - Running `./scripts/start` in the Malcolm installation directory will [start Malcolm](running.md#Starting).
    - Malcolm takes a few minutes to start. During this time users may see text scroll past from the containers' logs that look like error messages. This is normal while Malcolm's services synchronize among themselves.
    - Once Malcolm is running, the start script will output **Started Malcolm** and return to the command prompt.

```bash
$ cd ~/malcolm

$ ./scripts/start
…
logstash-1 | [2025-04-10T15:03:28,294][INFO ][logstash.agent ] Pipelines running {:count=>6, :running_pipelines=>[:"malcolm-input", :"malcolm-output", :"malcolm-suricata", :"malcolm-enrichment", :"malcolm-beats", :"malcolm-zeek"], :non_running_pipelines=>[]}

Started Malcolm

Malcolm services can be accessed at https://<IP address>/
------------------------------------------------------------------------------
```

* Check Malcolm's status
    - Running `./scripts/status` in the Malcolm installation directory will display the status of Malcolm's services.

```bash
$ cd ~/malcolm

$ ./scripts/status
NAME                          IMAGE                                                      COMMAND                  SERVICE             CREATED         STATUS                   PORTS
malcolm-api-1                 ghcr.io/idaholab/malcolm/api:{{ site.malcolm.version }}-arm64                 "/usr/bin/tini -- /u…"   api                 7 minutes ago   Up 7 minutes (healthy)   5000/tcp
malcolm-arkime-1              ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}-arm64              "/usr/bin/tini -- /u…"   arkime              7 minutes ago   Up 7 minutes (healthy)   8000/tcp, 8005/tcp, 8081/tcp
malcolm-arkime-live-1         ghcr.io/idaholab/malcolm/arkime:{{ site.malcolm.version }}-arm64              "/usr/bin/tini -- /u…"   arkime-live         7 minutes ago   Up 7 minutes (healthy)
malcolm-dashboards-1          ghcr.io/idaholab/malcolm/dashboards:{{ site.malcolm.version }}-arm64          "/usr/bin/tini -- /u…"   dashboards          7 minutes ago   Up 7 minutes (healthy)   5601/tcp
malcolm-dashboards-helper-1   ghcr.io/idaholab/malcolm/dashboards-helper:{{ site.malcolm.version }}-arm64   "/usr/bin/tini -- /u…"   dashboards-helper   7 minutes ago   Up 7 minutes (healthy)   28991/tcp
malcolm-file-monitor-1        ghcr.io/idaholab/malcolm/file-monitor:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   file-monitor        7 minutes ago   Up 7 minutes (healthy)   3310/tcp, 8440/tcp
malcolm-filebeat-1            ghcr.io/idaholab/malcolm/filebeat-oss:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   filebeat            7 minutes ago   Up 7 minutes (healthy)
malcolm-freq-1                ghcr.io/idaholab/malcolm/freq:{{ site.malcolm.version }}-arm64                "/usr/bin/tini -- /u…"   freq                7 minutes ago   Up 7 minutes (healthy)   10004/tcp
malcolm-htadmin-1             ghcr.io/idaholab/malcolm/htadmin:{{ site.malcolm.version }}-arm64             "/usr/bin/tini -- /u…"   htadmin             7 minutes ago   Up 7 minutes (healthy)   80/tcp
malcolm-keycloak-1            ghcr.io/idaholab/malcolm/keycloak:{{ site.malcolm.version }}-arm64            "/usr/bin/tini -- /u…"   keycloak            7 minutes ago   Up 7 minutes (healthy)   8080/tcp, 8443/tcp, 9000/tcp
malcolm-logstash-1            ghcr.io/idaholab/malcolm/logstash-oss:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   logstash            7 minutes ago   Up 7 minutes (healthy)   5044/tcp, 9001/tcp, 9600/tcp
malcolm-netbox-1              ghcr.io/idaholab/malcolm/netbox:{{ site.malcolm.version }}-arm64              "/usr/bin/tini -- /u…"   netbox              7 minutes ago   Up 7 minutes (healthy)   9001/tcp
malcolm-nginx-proxy-1         ghcr.io/idaholab/malcolm/nginx-proxy:{{ site.malcolm.version }}-arm64         "/sbin/tini -- /usr/…"   nginx-proxy         7 minutes ago   Up 7 minutes (healthy)   0.0.0.0:443->443/tcp
malcolm-opensearch-1          ghcr.io/idaholab/malcolm/opensearch:{{ site.malcolm.version }}-arm64          "/usr/bin/tini -- /u…"   opensearch          7 minutes ago   Up 7 minutes (healthy)   9200/tcp, 9300/tcp, 9600/tcp, 9650/tcp
malcolm-pcap-capture-1        ghcr.io/idaholab/malcolm/pcap-capture:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   pcap-capture        7 minutes ago   Up 7 minutes (healthy)
malcolm-pcap-monitor-1        ghcr.io/idaholab/malcolm/pcap-monitor:{{ site.malcolm.version }}-arm64        "/usr/bin/tini -- /u…"   pcap-monitor        7 minutes ago   Up 7 minutes (healthy)   30441/tcp
malcolm-postgres-1            ghcr.io/idaholab/malcolm/postgresql:{{ site.malcolm.version }}-arm64          "/sbin/tini -- /usr/…"   postgres            7 minutes ago   Up 7 minutes (healthy)   5432/tcp
malcolm-redis-1               ghcr.io/idaholab/malcolm/redis:{{ site.malcolm.version }}-arm64               "/sbin/tini -- /usr/…"   redis               7 minutes ago   Up 7 minutes (healthy)   6379/tcp
malcolm-redis-cache-1         ghcr.io/idaholab/malcolm/redis:{{ site.malcolm.version }}-arm64               "/sbin/tini -- /usr/…"   redis-cache         7 minutes ago   Up 7 minutes (healthy)   6379/tcp
malcolm-suricata-1            ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}-arm64            "/usr/bin/tini -- /u…"   suricata            7 minutes ago   Up 7 minutes (healthy)
malcolm-suricata-live-1       ghcr.io/idaholab/malcolm/suricata:{{ site.malcolm.version }}-arm64            "/usr/bin/tini -- /u…"   suricata-live       7 minutes ago   Up 7 minutes (healthy)
malcolm-upload-1              ghcr.io/idaholab/malcolm/file-upload:{{ site.malcolm.version }}-arm64         "/usr/bin/tini -- /u…"   upload              7 minutes ago   Up 7 minutes (healthy)   22/tcp, 80/tcp
malcolm-zeek-1                ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}-arm64                "/usr/bin/tini -- /u…"   zeek                7 minutes ago   Up 7 minutes (healthy)
malcolm-zeek-live-1           ghcr.io/idaholab/malcolm/zeek:{{ site.malcolm.version }}-arm64                "/usr/bin/tini -- /u…"   zeek-live           7 minutes ago   Up 7 minutes (healthy)
```

* Connect to Malcolm's [web interface](quickstart.md#UserInterfaceURLs)
    - Navigate a web browser to the IP address of the instance using HTTPS
    - Log in with the credentials specified when setting up authentication
    - See the Malcolm [Learning Tree](https://github.com/cisagov/Malcolm/wiki/Learning) and [documentation](README.md) for next steps.

## <a name="AWSFargate"></a> Installing Malcolm on Amazon Web Services (AWS) Fargate

### 👷🏼‍♀️ Note: These instructions are a work in progress and are not yet functional. 👷🏻

* Install prerequisites (may vary by platform)
    * `curl`, `unzip`, and `python3`

    ```bash
    $ sudo apt-get -y update
    …
    $ sudo apt-get -y install --no-install-recommends \
        curl \
        unzip \
        python3 \
        python3-dialog \
        python3-pip \
        python3-ruamel.yaml \
        python3-kubernetes
    …
    ```

    * [`eksctl`](https://eksctl.io/)

    ```bash
    $ curl -sSL \
        -o /tmp/eksctl.tar.gz \
        "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_Linux_$(uname -m | sed 's/^x86_64$/amd64/').tar.gz"
    $ tar -xzf /tmp/eksctl.tar.gz -C /tmp && rm /tmp/eksctl.tar.gz
    $ sudo mv /tmp/eksctl /usr/local/bin/
    $ eksctl version
    0.207.0
    ```

    * [`aws` Command Line Interface](https://aws.amazon.com/cli/)

    ```bash
    $ curl -sSL \
        -o /tmp/awscli.zip \
        "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip"
    $ unzip -d /tmp /tmp/awscli.zip
    …
    $ sudo /tmp/aws/install
    You can now run: /usr/local/bin/aws --version
    $ aws --version
    aws-cli/2.26.2 Python/3.13.2 Linux/6.1.0-32-amd64 exe/x86_64.ubuntu.24
    ```

    * [`kubectl`](https://kubernetes.io/docs/reference/kubectl/)

    ```bash
    $ curl -sSL \
        -o /tmp/kubectl \
        "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/$(uname -m | sed 's/^x86_64$/amd64/' | sed 's/^aarch64$/arm64/')/kubectl"
    $ chmod 755 /tmp/kubectl
    $ sudo mv /tmp/kubectl /usr/local/bin/
    $ kubectl version
    Client Version: v1.32.3
    ```

* Get Malcolm (**TODO: NOT FINAL**)
    * These are **not** the final instructions for doing this, as in developing these instructions I've gone through and made some modifications to the Malcolm Kubernetes manifests that have not been released yet (e.g., adding `role` labels to the manifests). But for now those as-yet unreleased changes can be gotten from [here](https://github.com/mmguero-dev/malcolm/); however, the `image:` in the manifests needs to be changed from `idaholab` to `mmguero-dev` for the org and from `25.04.0` to `main` for the version, like this:

    ```bash
    $ git clone --single-branch --depth 1 https://github.com/mmguero-dev/Malcolm
    $ sed -i "s@ghcr.io/idaholab@ghcr.io/mmguero-dev@g" ./Malcolm/kubernetes/*.yml
    $ sed -i "s@25\.04\.0@main@g" ./Malcolm/kubernetes/*.yml
    ```

* Create cluster for Fargate

```bash
$ eksctl create cluster \
    --name malcolm-cluster \
    --region us-east-1 \
    --fargate \
    --version 1.28 \
    --vpc-nat-mode HighlyAvailable \
    --with-oidc \
    --vpc-cidr 10.0.0.0/16 \
    --node-private-networking
```

* Create IAM policy for EFS CSI Driver

```bash
$ aws iam create-policy \
    --policy-name AmazonEKS_EFS_CSI_Driver_Policy \
    --policy-document '{
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "elasticfilesystem:DescribeAccessPoints",
            "elasticfilesystem:DescribeFileSystems",
            "elasticfilesystem:DescribeMountTargets",
            "ec2:DescribeAvailabilityZones"
          ],
          "Resource": "*"
        },
        {
          "Effect": "Allow",
          "Action": [
            "elasticfilesystem:CreateAccessPoint"
          ],
          "Resource": "*",
          "Condition": {
            "StringLike": {
              "aws:RequestTag/efs.csi.aws.com/cluster": "true"
            }
          }
        },
        {
          "Effect": "Allow",
          "Action": "elasticfilesystem:DeleteAccessPoint",
          "Resource": "*",
          "Condition": {
            "StringEquals": {
              "aws:ResourceTag/efs.csi.aws.com/cluster": "true"
            }
          }
        }
      ]
    }'
```

* Create service account and attach the policy

```bash
$ eksctl create iamserviceaccount \
    --cluster malcolm-cluster \
    --namespace kube-system \
    --name efs-csi-controller-sa \
    --attach-policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/AmazonEKS_EFS_CSI_Driver_Policy \
    --approve \
    --override-existing-serviceaccounts \
    --region us-east-1
```

* Install EFS CSI driver

```bash
$ eksctl create addon \
  --name aws-efs-csi-driver \
  --cluster malcolm-cluster \
  --service-account-role-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):role/efs-csi-controller-sa \
  --force \
  --region us-east-1
```

* Create namespace

```bash
$ kubectl create namespace malcolm
```

* Create Fargate profiles for Malcolm components based on pods' "role" labels

```bash
$ for ROLE in $(grep -h role: ./Malcolm/kubernetes/*.yml | awk '{print $2}' | sort -u); do \
    eksctl create fargateprofile \
        --cluster malcolm-cluster \
        --region us-east-1 \
        --name malcolm-"$ROLE" \
        --namespace malcolm \
        --labels role="$ROLE"; \
done
```

* Create EFS file system and get file system ID

```bash
$ aws efs create-file-system \
    --creation-token malcolm-efs \
    --encrypted \
    --region us-east-1 \
    --tags Key=Name,Value=malcolm-efs \
    --performance-mode generalPurpose \
    --throughput-mode bursting

$ EFS_ID=$(aws efs describe-file-systems --creation-token malcolm-efs \
    --query 'FileSystems[0].FileSystemId' --output text)

$ echo $EFS_ID
```

* Create file system [access points](https://docs.aws.amazon.com/efs/latest/ug/efs-access-points.html)

```bash
$ for AP in config opensearch opensearch-backup pcap runtime-logs suricata-logs zeek-logs; do \
    aws efs create-access-point \
            --file-system-id $EFS_ID \
            --client-token $(head -c 1024 /dev/urandom 2>/dev/null | tr -cd 'a-f0-9' | head -c 32) \
            --root-directory "Path=/malcolm/$AP,CreationInfo={OwnerUid=1000,OwnerGid=1000,Permissions=0770}" \
            --tags "Key=Name,Value=$AP"; \
done
```

* Get VPC ID

```bash
$ VPC_ID=$(aws eks describe-cluster --name malcolm-cluster \
        --query "cluster.resourcesVpcConfig.vpcId" --output text)

$ echo $VPC_ID
```

* Create Security Group for EFS and get Security Group ID

```bash
$ aws ec2 create-security-group \
    --group-name malcolm-efs-sg \
    --description "Security group for Malcolm EFS" \
    --vpc-id $VPC_ID

$ SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=malcolm-efs-sg" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' --output text)

$ echo $SG_ID
```

* Add NFS inbound rule to Security Group

```bash
$ aws ec2 authorize-security-group-ingress \
    --group-id $SG_ID \
    --protocol tcp \
    --port 2049 \
    --cidr 10.0.0.0/16
```

* Get subnet IDs and create EFS mount targets

```bash
$ SUBNETS=$(aws ec2 describe-subnets \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:aws:cloudformation:logical-id,Values=SubnetPrivate*" \
    --query 'Subnets[*].SubnetId' --output text)

$ echo $SUBNETS
```

* Create mount targets

```bash
$ for subnet in $SUBNETS; do \
    aws efs create-mount-target \
        --file-system-id $EFS_ID \
        --subnet-id $subnet \
        --security-groups $SG_ID; \
done
```

* Create Persistent Volumes (PV) and Persistent Volume Claims (PVC) using static provisioning
    * Ensure file system ID is **exported** in `$EFS_ID`
    
    ```bash
    $ export EFS_ID=$(aws efs describe-file-systems --creation-token malcolm-efs \
        --query 'FileSystems[0].FileSystemId' --output text)

    $ echo $EFS_ID
    ```

    * Ensure the Access Point IDs are **exported** in `$EFS_ACCESS_POINT_CONFIG_ID`, etc.
    
    ```bash
    $ for AP in config opensearch opensearch-backup pcap runtime-logs suricata-logs zeek-logs; do \
        AP_UPPER=$(echo "$AP" | tr 'a-z-' 'A-Z_'); \
        ACCESS_POINT_ID=$(aws efs describe-access-points \
                            --file-system-id $EFS_ID \
                            --query "AccessPoints[?Tags[?Key=='Name' && Value=='$AP']].AccessPointId" \
                            --output text); \

        [[ -n "$ACCESS_POINT_ID" ]] && export EFS_ACCESS_POINT_${AP_UPPER}_ID=$ACCESS_POINT_ID; \
    done

    $ env | grep EFS_ACCESS_POINT_
    ```

    * Create and verify PVs and PVCs to be used by Malcolm services

    ```bash
    $ envsubst < ./Malcolm/kubernetes/01-volumes-aws-efs.yml.example | kubectl apply -f -
    ```

    * Verify PVs and PVCs have "Bound" status
    
    ```bash
    $ kubectl get pv -n malcolm
    NAME                       CAPACITY   ACCESS MODES   RECLAIM POLICY   STATUS   CLAIM                             STORAGECLASS   REASON   AGE
    config-volume              25Gi       RWX            Retain           Bound    malcolm/config-claim              efs-sc                  2m11s
    opensearch-backup-volume   500Gi      RWO            Retain           Bound    malcolm/opensearch-backup-claim   efs-sc                  2m11s
    opensearch-volume          500Gi      RWO            Retain           Bound    malcolm/opensearch-claim          efs-sc                  2m11s
    pcap-volume                500Gi      RWX            Retain           Bound    malcolm/pcap-claim                efs-sc                  2m12s
    runtime-logs-volume        25Gi       RWX            Retain           Bound    malcolm/runtime-logs-claim        efs-sc                  2m11s
    suricata-volume            100Gi      RWX            Retain           Bound    malcolm/suricata-claim            efs-sc                  2m12s
    zeek-volume                250Gi      RWX            Retain           Bound    malcolm/zeek-claim                efs-sc                  2m12s

    $ kubectl get pvc -n malcolm
    kubectl get pvc -n malcolm
    NAME                      STATUS   VOLUME                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
    config-claim              Bound    config-volume              25Gi       RWX            efs-sc         2m32s
    opensearch-backup-claim   Bound    opensearch-backup-volume   500Gi      RWO            efs-sc         2m31s
    opensearch-claim          Bound    opensearch-volume          500Gi      RWO            efs-sc         2m32s
    pcap-claim                Bound    pcap-volume                500Gi      RWX            efs-sc         2m33s
    runtime-logs-claim        Bound    runtime-logs-volume        25Gi       RWX            efs-sc         2m32s
    suricata-claim            Bound    suricata-volume            100Gi      RWX            efs-sc         2m32s
    zeek-claim                Bound    zeek-volume                250Gi      RWX            efs-sc         2m33s
    ```

* Configure Malcolm
    * `./Malcolm/scripts/install.py -f "${KUBECONFIG:-$HOME/.kube/config}"`
    * Malcolm's configuration scripts will guide users through the setup process.
    * Use the following resources to answer the installation and configuration questions:
        * [Installation example using Ubuntu 24.04 LTS](ubuntu-install-example.md#InstallationExample)
        * [In-depth description of configuration questions](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)

* Configure [authentication](authsetup.md#AuthSetup)
    * `./Malcolm/scripts/auth_setup -f "${KUBECONFIG:-$HOME/.kube/config}"`
    * [This example](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) can guide users through the prompts.

* If needed, copy `./Malcolm/config/kubernetes-container-resources.yml.example` to `./Malcolm/config/kubernetes-container-resources.yml` and [adjust container resources](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits) in the copy.

* Start Malcolm (**TODO: NOT FINAL**)

```bash
$ ./Malcolm/scripts/start -f "${KUBECONFIG:-$HOME/.kube/config}" \
    --inject-resources \
    --no-capture-pods \
    --no-capabilities \
    --skip-persistent-volume-checks
```

* Monitor deployment
    * Check pods

    ```bash
    $ kubectl get pods -n malcolm -w
    kubectl get pods -n malcolm -w
    NAME                                            READY   STATUS     RESTARTS   AGE
    api-deployment-5c8b9c7c5b-dtpkq                 1/1     Running    0          3m6s
    arkime-deployment-fcbb44c8f-plh8k               1/1     Running    0          3m6s
    dashboards-deployment-95467ff6f-h2zx5           1/1     Running    0          3m7s
    dashboards-helper-deployment-7686756dc4-vxw4r   1/1     Running    0          3m5s
    file-monitor-deployment-7fccbb7c98-8hxrv        1/1     Running    0          3m5s
    filebeat-deployment-57db54b549-zvfb4            1/1     Running    0          3m4s
    freq-deployment-6c7688b4c-zhdfw                 1/1     Running    0          3m2s
    htadmin-deployment-767c78b4bf-sjzmf             1/1     Running    0          3m2s
    keycloak-deployment-7ff7bb9c8c-trkc6            1/1     Running    0          3m2s
    logstash-deployment-54ffd8c85-spmh5             1/1     Running    0          3m4s
    netbox-deployment-7bdbfcbf6c-xc725              1/1     Running    0          3m3s
    nginx-proxy-deployment-864c896ff6-v8jrs         1/1     Running    0          3m1s
    opensearch-deployment-654b79f6f9-2tss2          1/1     Running    0          3m7s
    pcap-monitor-deployment-5f644fb9b-tzk8k         1/1     Running    0          3m6s
    postgres-deployment-76fb787976-pgwsr            1/1     Running    0          3m3s
    redis-cache-deployment-6f9b9d65bf-dssjt         1/1     Running    0          3m3s
    redis-deployment-7b985fb7d7-zz9jb               1/1     Running    0          3m4s
    suricata-offline-deployment-669c759f88-nt24v    1/1     Running    0          3m5s
    upload-deployment-76c6c49cb5-9zdtp              1/1     Running    0          3m7s
    zeek-offline-deployment-c56f7f46f-m62sd         1/1     Running    0          3m5s
    ```

    * Check all resources

    ```bash
    $ kubectl get all -n malcolm
    …
    ```

    * Watch logs

    ```bash
    $ kubectl logs --follow=true -n malcolm --all-containers <pod>
    ```

    * Get all events in the namespace for more detailed information and debugging
    ```bash
    $ kubectl get events -n malcolm --sort-by='.metadata.creationTimestamp'
    …
    ```

* Stop Malcolm (**TODO**)

# Current issues

* Figuring out EFS mounting issues
    * I'm gettting these warnings (using the `zeek-offline` container as an example, but it's not just that)
    
    ```
    k describe pod -n malcolm zeek-offline
    Name:                 zeek-offline-deployment-7ffc55d489-rtgfz
    Namespace:            malcolm
    Priority:             2000001000
    Priority Class Name:  system-node-critical
    Service Account:      default
    Node:                 fargate-ip-10-0-96-58.ec2.internal/10.0.96.58
    Start Time:           Thu, 17 Apr 2025 14:00:33 -0600
    Labels:               app=zeek-offline
                          eks.amazonaws.com/fargate-profile=malcolm-ingest
                          pod-template-hash=7ffc55d489
                          role=ingest
    Annotations:          CapacityProvisioned: 1vCPU 5GB
                          Logging: LoggingDisabled: LOGGING_CONFIGMAP_NOT_FOUND
    Status:               Running
    IP:                   10.0.96.58
    IPs:
      IP:           10.0.96.58
    Controlled By:  ReplicaSet/zeek-offline-deployment-7ffc55d489
    Init Containers:
      zeek-offline-dirinit-container:
        Container ID:   containerd://83ebab0f4b962479c2df6948b5c2cb1e2a133fa6ef1921e5864cb9746f645206
        Image:          ghcr.io/mmguero-dev/malcolm/dirinit:main
        Image ID:       ghcr.io/mmguero-dev/malcolm/dirinit@sha256:c044f40d8c50cd18680624c7c8cf550812fc0410de24577aa15a141399d07203
        Port:           <none>
        Host Port:      <none>
        State:          Terminated
          Reason:       Completed
          Exit Code:    0
          Started:      Thu, 17 Apr 2025 14:00:52 -0600
          Finished:     Thu, 17 Apr 2025 14:00:52 -0600
        Ready:          True
        Restart Count:  0
        Limits:
          cpu:     500m
          memory:  256Mi
        Requests:
          cpu:     250m
          memory:  128Mi
        Environment Variables from:
          process-env  ConfigMap  Optional: false
        Environment:
          PUSER_MKDIR:  /data/config:zeek/intel/Mandiant,zeek/intel/MISP,zeek/intel/STIX;/data/pcap:processed;/data/zeek-logs:current,extract_files/preserved,extract_files/quarantine,live,processed,upload
        Mounts:
          /data/config from zeek-offline-intel-volume (rw)
          /data/pcap from zeek-offline-pcap-volume (rw)
          /data/zeek-logs from zeek-offline-zeek-volume (rw)
          /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-97z9j (ro)
    Containers:
      zeek-offline-container:
        Container ID:   containerd://874233ff2317fd0f016e405108bc0f1875f095361779538c8344c198c5c108be
        Image:          ghcr.io/mmguero-dev/malcolm/zeek:main
        Image ID:       ghcr.io/mmguero-dev/malcolm/zeek@sha256:021208f0a15aefc684fa058745bc36a9fdde13c996071c5f9f7d5c6cbe1dd9b4
        Port:           <none>
        Host Port:      <none>
        State:          Running
          Started:      Thu, 17 Apr 2025 14:01:22 -0600
        Ready:          True
        Restart Count:  0
        Requests:
          cpu:     1
          memory:  4Gi
        Liveness:  exec [/usr/local/bin/container_health.sh] delay=60s timeout=15s period=30s #success=1 #failure=10
        Environment Variables from:
          process-env        ConfigMap  Optional: false
          ssl-env            ConfigMap  Optional: false
          upload-common-env  ConfigMap  Optional: false
          zeek-env           ConfigMap  Optional: false
          zeek-secret-env    Secret     Optional: false
          zeek-offline-env   ConfigMap  Optional: false
        Environment:         <none>
        Mounts:
          /opt/zeek/share/zeek/site/custom/configmap from zeek-offline-custom-volume (rw)
          /opt/zeek/share/zeek/site/intel from zeek-offline-intel-volume (rw,path="zeek/intel")
          /opt/zeek/share/zeek/site/intel-preseed/configmap from zeek-offline-intel-preseed-volume (rw)
          /pcap from zeek-offline-pcap-volume (rw)
          /var/local/ca-trust/configmap from zeek-offline-var-local-catrust-volume (rw)
          /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-97z9j (ro)
          /zeek/extract_files from zeek-offline-zeek-volume (rw,path="extract_files")
          /zeek/upload from zeek-offline-zeek-volume (rw,path="upload")
    Conditions:
      Type              Status
      Initialized       True 
      Ready             True 
      ContainersReady   True 
      PodScheduled      True 
    Volumes:
      zeek-offline-var-local-catrust-volume:
        Type:      ConfigMap (a volume populated by a ConfigMap)
        Name:      var-local-catrust
        Optional:  false
      zeek-offline-pcap-volume:
        Type:       PersistentVolumeClaim (a reference to a PersistentVolumeClaim in the same namespace)
        ClaimName:  pcap-claim
        ReadOnly:   false
      zeek-offline-zeek-volume:
        Type:       PersistentVolumeClaim (a reference to a PersistentVolumeClaim in the same namespace)
        ClaimName:  zeek-claim
        ReadOnly:   false
      zeek-offline-custom-volume:
        Type:      ConfigMap (a volume populated by a ConfigMap)
        Name:      zeek-custom
        Optional:  false
      zeek-offline-intel-preseed-volume:
        Type:      ConfigMap (a volume populated by a ConfigMap)
        Name:      zeek-intel-preseed
        Optional:  false
      zeek-offline-intel-volume:
        Type:       PersistentVolumeClaim (a reference to a PersistentVolumeClaim in the same namespace)
        ClaimName:  config-claim
        ReadOnly:   false
      kube-api-access-97z9j:
        Type:                    Projected (a volume that contains injected data from multiple sources)
        TokenExpirationSeconds:  3607
        ConfigMapName:           kube-root-ca.crt
        ConfigMapOptional:       <nil>
        DownwardAPI:             true
    QoS Class:                   Burstable
    Node-Selectors:              <none>
    Tolerations:                 node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                                 node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
    Events:
      Type     Reason           Age                From               Message
      ----     ------           ----               ----               -------
      Warning  LoggingDisabled  22m                fargate-scheduler  Disabled logging because aws-logging configmap was not found. configmap "aws-logging" not found
      Normal   Scheduled        22m                fargate-scheduler  Successfully assigned malcolm/zeek-offline-deployment-7ffc55d489-rtgfz to fargate-ip-10-0-96-58.ec2.internal
      Warning  FailedMount      22m                kubelet            MountVolume.MountDevice failed for volume "config-volume" : kubernetes.io/csi: attacher.MountDevice failed to create newCsiDriverClient: driver name efs.csi.aws.com not found in the list of registered CSI drivers
      Warning  FailedMount      22m                kubelet            MountVolume.MountDevice failed for volume "pcap-volume" : kubernetes.io/csi: attacher.MountDevice failed to create newCsiDriverClient: driver name efs.csi.aws.com not found in the list of registered CSI drivers
      Warning  FailedMount      22m                kubelet            MountVolume.MountDevice failed for volume "zeek-volume" : kubernetes.io/csi: attacher.MountDevice failed to create newCsiDriverClient: driver name efs.csi.aws.com not found in the list of registered CSI drivers
      Warning  FailedMount      22m (x4 over 22m)  kubelet            MountVolume.SetUp failed for volume "config-volume" : rpc error: code = Internal desc = Could not mount "fs-0d66110f5e994381a:/" at "/var/lib/kubelet/pods/341b9199-aa1b-4f8e-93c5-ca5f76fd5b9d/volumes/kubernetes.io~csi/config-volume/mount": mount failed: exit status 1
    Mounting command: mount
    Mounting arguments: -t efs -o accesspoint=fsap-0e37af706726f3234,tls fs-0d66110f5e994381a:/ /var/lib/kubelet/pods/341b9199-aa1b-4f8e-93c5-ca5f76fd5b9d/volumes/kubernetes.io~csi/config-volume/mount
    Output: Failed to resolve "fs-0d66110f5e994381a.efs.us-east-1.amazonaws.com" - check that your file system ID is correct, and ensure that the VPC has an EFS mount target for this file system ID.
    See https://docs.aws.amazon.com/console/efs/mount-dns-name for more detail.
    Attempting to lookup mount target ip address using botocore. Failed to import necessary dependency botocore, please install botocore first.
      Warning  FailedMount  22m (x4 over 22m)  kubelet  MountVolume.SetUp failed for volume "zeek-volume" : rpc error: code = Internal desc = Could not mount "fs-0d66110f5e994381a:/" at "/var/lib/kubelet/pods/341b9199-aa1b-4f8e-93c5-ca5f76fd5b9d/volumes/kubernetes.io~csi/zeek-volume/mount": mount failed: exit status 1
    Mounting command: mount
    Mounting arguments: -t efs -o accesspoint=fsap-0ceb805a5f513d3ad,tls fs-0d66110f5e994381a:/ /var/lib/kubelet/pods/341b9199-aa1b-4f8e-93c5-ca5f76fd5b9d/volumes/kubernetes.io~csi/zeek-volume/mount
    Output: Failed to resolve "fs-0d66110f5e994381a.efs.us-east-1.amazonaws.com" - check that your file system ID is correct, and ensure that the VPC has an EFS mount target for this file system ID.
    See https://docs.aws.amazon.com/console/efs/mount-dns-name for more detail.
    Attempting to lookup mount target ip address using botocore. Failed to import necessary dependency botocore, please install botocore first.
      Warning  FailedMount  22m (x4 over 22m)  kubelet  MountVolume.SetUp failed for volume "pcap-volume" : rpc error: code = Internal desc = Could not mount "fs-0d66110f5e994381a:/" at "/var/lib/kubelet/pods/341b9199-aa1b-4f8e-93c5-ca5f76fd5b9d/volumes/kubernetes.io~csi/pcap-volume/mount": mount failed: exit status 1
    Mounting command: mount
    Mounting arguments: -t efs -o accesspoint=fsap-05356388be7048aec,tls fs-0d66110f5e994381a:/ /var/lib/kubelet/pods/341b9199-aa1b-4f8e-93c5-ca5f76fd5b9d/volumes/kubernetes.io~csi/pcap-volume/mount
    Output: Failed to resolve "fs-0d66110f5e994381a.efs.us-east-1.amazonaws.com" - check that your file system ID is correct, and ensure that the VPC has an EFS mount target for this file system ID.
    See https://docs.aws.amazon.com/console/efs/mount-dns-name for more detail.
    Attempting to lookup mount target ip address using botocore. Failed to import necessary dependency botocore, please install botocore first.
      Normal  Pulling  21m  kubelet  Pulling image "ghcr.io/mmguero-dev/malcolm/dirinit:main"
      Normal  Pulled   21m  kubelet  Successfully pulled image "ghcr.io/mmguero-dev/malcolm/dirinit:main" in 649ms (649ms including waiting)
      Normal  Created  21m  kubelet  Created container zeek-offline-dirinit-container
      Normal  Started  21m  kubelet  Started container zeek-offline-dirinit-container
      Normal  Pulling  21m  kubelet  Pulling image "ghcr.io/mmguero-dev/malcolm/zeek:main"
      Normal  Pulled   21m  kubelet  Successfully pulled image "ghcr.io/mmguero-dev/malcolm/zeek:main" in 29.435s (29.435s including waiting)
      Normal  Created  21m  kubelet  Created container zeek-offline-container
      Normal  Started  21m  kubelet  Started container zeek-offline-container
    ```

    * However, things seem to be working?

    ```bash
    kshell zeek
    Defaulted container "zeek-offline-container" out of: zeek-offline-container, zeek-offline-dirinit-container (init)
    root@zeek-offline-deployment-7ffc55d489-rtgfz:/# df|grep 127
    127.0.0.1:/              9007199254739968        0 9007199254739968   0% /pcap
    127.0.0.1:/extract_files 9007199254739968        0 9007199254739968   0% /zeek/extract_files
    127.0.0.1:/upload        9007199254739968        0 9007199254739968   0% /zeek/upload
    127.0.0.1:/zeek/intel    9007199254739968        0 9007199254739968   0% /opt/zeek/share/zeek/site/intel
    ```

    * And for the "read-write many" containers, I can see that stuff is actually shared:
    
    ```bash
    $ kshell zeek
    root@zeek-offline-deployment-7ffc55d489-rtgfz:/# touch /pcap/heythere.txt
    root@zeek-offline-deployment-7ffc55d489-rtgfz:/# 

    $ kshell arkime
    root@arkime-deployment-c7f5d47b5-9brc8:/opt/arkime# ls -l /data/pcap/
    total 12
    -rw-r--r-- 1 root   root      0 Apr 17 20:24 heythere.txt
    drwxr-xr-x 2 arkime arkime 6144 Apr 17 20:00 processed
    drwxrwxr-x 4 arkime arkime 6144 Apr 17 20:00 upload
    ```

    * Describing the addon (`aws eks describe-addon --cluster-name malcolm-cluster --addon-name aws-efs-csi-driver`)

    ```json
    {
        "addon": {
            "addonName": "aws-efs-csi-driver",
            "clusterName": "malcolm-cluster",
            "status": "DEGRADED",
            "addonVersion": "v2.1.7-eksbuild.1",
            "health": {
                "issues": [
                    {
                        "code": "InsufficientNumberOfReplicas",
                        "message": "The add-on is unhealthy because all deployments have all pods unscheduled Pod not supported on Fargate: invalid SecurityContext fields: Privileged"
                    }
                ]
            },
            "addonArn": "arn:aws:eks:us-east-1:422382356529:addon/malcolm-cluster/aws-efs-csi-driver/7ccb22a7-98d7-bde2-4c76-404a1a4784e2",
            "createdAt": "2025-04-17T13:52:20.276000-06:00",
            "modifiedAt": "2025-04-17T13:52:34.383000-06:00",
            "serviceAccountRoleArn": "arn:aws:iam::422382356529:role/efs-csi-controller-sa",
            "tags": {}
        }
    }
    ```

    * My hypothesis
        * The EFS CSI Controller (the "control plane" part of the add-on) is deployed and working — it's a Deployment, and Fargate can run that part.
        * The EFS CSI Node (which is a DaemonSet) is supposed to run on every node to handle volume mounts the "traditional" CSI way — but with Fargate it's not supported
        * The reason it still works:
            * I have configured static EFS mounts via access points and the pod spec directly, so pods themselves are directly mounting the EFS volumes, so we don’t need the EFS CSI node DaemonSet
            * Fargate won't run it anyway (because it uses privileged: true)
            * So the add-on status is "degraded" (because it checks the DaemonSet)
            * But the actual workload is using EFS just fine

* What about ingress?
* Malcolm's `./scripts/stop` deletes the namespace, which we don't want to do, so I need to update that or make an option to leave things in place.


## <a name="AWSAMI"></a> Generating a Malcolm Amazon Machine Image (AMI) for Use on Amazon Web Services (AWS)

This section outlines the process of using [packer](https://www.packer.io/)'s [Amazon AMI Builder](https://developer.hashicorp.com/packer/plugins/builders/amazon) to create an [EBS-backed](https://developer.hashicorp.com/packer/plugins/builders/amazon/ebs) Malcolm AMI for either the x86-64 or arm64 CPU architecture. This section assumes good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

### <a name="AWSAMIPrerequisites"></a> Prerequisites

* [packer](https://www.packer.io/)
    - the packer command-line tool ([download](https://developer.hashicorp.com/packer/downloads))
* [aws cli](https://aws.amazon.com/cli/)
    - the AWS Command Line Interface with functioning access to AWS infrastructure
* AWS access key ID and secret access key
    - [AWS security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/security-creds.html)
* ensure the AWS account used for packer has minimal required permissions
    - [Amazon AMI builder](https://developer.hashicorp.com/packer/plugins/builders/amazon)

### <a name="AWSAMIProcedure"></a> Procedure

The files referenced in this section can be found in [scripts/third-party-environments/aws/ami]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/scripts/third-party-environments/aws/ami).

1. Copy `packer_vars.json.example` to `packer_vars.json`
    ```bash
    $ cp ./packer_vars.json.example ./packer_vars.json
    ```
1. Edit `packer_vars.json` 
    * set `vpc_region`, `instance_arch`, and other variables as needed
1. Validate the packer configuration
    ```bash
    $ packer validate packer_build.json
    The configuration is valid.
    ```
1. Launch packer to build the AMI, providing `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` as environment variables:
    ```bash
    $ AWS_ACCESS_KEY_ID=YOUR_AWS_ACCESS_KEY \
        AWS_SECRET_ACCESS_KEY=YOUR_AWS_SECRET_KEY \
        packer build -var-file=packer_vars.json packer_build.json

    amazon-ebs: output will be in this color.

    ==> amazon-ebs: Prevalidating any provided VPC information
    ==> amazon-ebs: Prevalidating AMI Name: malcolm-v{{ site.malcolm.version }}-x86_64-2024-10-10T15-41-32Z
        amazon-ebs: Found Image ID: ami-xxxxxxxxxxxxxxxxx

    ...

    ==> amazon-ebs: Waiting for AMI to become ready...
    ==> amazon-ebs: Skipping Enable AMI deprecation...
    ==> amazon-ebs: Adding tags to AMI (ami-xxxxxxxxxxxxxxxxx)...
    ==> amazon-ebs: Tagging snapshot: snap-xxxxxxxxxxxxxxxxx
    ==> amazon-ebs: Creating AMI tags
        amazon-ebs: Adding tag: "Malcolm": "idaholab/Malcolm/v{{ site.malcolm.version }}"
        amazon-ebs: Adding tag: "source_ami_name": "al2023-ami-ecs-hvm-2023.0.20241003-kernel-6.1-x86_64"
    ==> amazon-ebs: Creating snapshot tags
    ==> amazon-ebs: Terminating the source AWS instance...
    ==> amazon-ebs: Cleaning up any extra volumes...
    ==> amazon-ebs: No volumes to clean up, skipping
    ==> amazon-ebs: Deleting temporary keypair...
    Build 'amazon-ebs' finished after 19 minutes 57 seconds.

    ==> Wait completed after 19 minutes 57 seconds

    ==> Builds finished. The artifacts of successful builds are:
    --> amazon-ebs: AMIs were created:
    us-east-1: ami-xxxxxxxxxxxxxxxxx
    ```
1. Use `aws` (or the [Amazon EC2 console](https://us-east-1.console.aws.amazon.com/ec2/home)) to verify that the new AMI exists
    ```bash
    $ aws ec2 describe-images --owners self --filters "Name=root-device-type,Values=ebs" --filters "Name=name,Values=malcolm-*"
    ```
    ```json
    {
        "Images": [
            {
                "Architecture": "x86_64",
                "CreationDate": "2024-05-30T14:02:21.000Z",
                "ImageId": "ami-xxxxxxxxxxxxxxxxx",
                "ImageLocation": "xxxxxxxxxxxx/malcolm-v{{ site.malcolm.version }}-arm64-2024-05-30T13-57-31Z",
                "ImageType": "machine",
                "Public": false,
                "OwnerId": "xxxxxxxxxxxx",
                "PlatformDetails": "Linux/UNIX",
                "UsageOperation": "RunInstances",
                "State": "available",
                "BlockDeviceMappings": [
                    {
                        "DeviceName": "/dev/xvda",
                        "Ebs": {
                            "DeleteOnTermination": true,
                            "SnapshotId": "snap-xxxxxxxxxxxxxxxxx",
                            "VolumeSize": 30,
                            "VolumeType": "gp2",
                            "Encrypted": false
                        }
                    }
                ],
                "EnaSupport": true,
                "Hypervisor": "xen",
                "Name": "malcolm-v{{ site.malcolm.version }}-arm64-2024-05-30T13-57-31Z",
                "RootDeviceName": "/dev/xvda",
                "RootDeviceType": "ebs",
                "SriovNetSupport": "simple",
                "Tags": [
                    {
                        "Key": "Malcolm",
                        "Value": "idaholab/Malcolm/v{{ site.malcolm.version }}"
                    },
                    {
                        "Key": "source_ami_name",
                        "Value": "al2023-ami-ecs-hvm-2023.0.20241003-kernel-6.1-x86_64"
                    }
                ],
                "VirtualizationType": "hvm",
                "BootMode": "uefi",
                "SourceInstanceId": "i-xxxxxxxxxxxxxxxxx",
                "DeregistrationProtection": "disabled"
            }
        ]
    }
    ```
1. Launch an instance from the new AMI
    * for x86-64 instances `c4.4xlarge`, `t2.2xlarge`, and `t3a.2xlarge` seem to be good instance types for Malcolm
    * for arm64 instances, `m6gd.2xlarge`, `m6g.2xlarge`, `m7g.2xlarge`, and `t4g.2xlarge` seem to be good instance types for Malcolm
    * see [recommended system requirements](system-requirements.md#SystemRequirements) for Malcolm
1. SSH into the instance
1. Run `~/Malcolm/scripts/configure` to configure Malcolm
1. Run `~/Malcolm/scripts/auth_setup` to set up authentication for Malcolm
1. Run `~/Malcolm/scripts/start` to start Malcolm

### <a name="AWSAMIMFA"></a> Using MFA

Users with [AWS MFA requirements](https://docs.aws.amazon.com/console/iam/self-mfa) may receive an `UnauthorizedOperation` error when performing the steps outlined above. If this is the case, the following workaround may allow the build to execute (thanks to [this GitHub comment](https://github.com/hashicorp/packer-plugin-amazon/issues/441#issuecomment-1880073476)):

1. Remove the `access_key` and `secret_key` lines from the `builders` section of `packer_build.json` (right below `"type": "amazon-ebs"`)
1. Run `aws ec2 describe-instances --profile=xxxxxxxx` (replacing `xxxxxxxx` with the credential profile name) to cause `aws` to authenticate (prompting for the MFA code) and cache the credentials
1. At the bash command line, run: `eval "$(aws configure export-credentials --profile xxxxxxxx --format env)"` to load the current AWS credentials into environment variables in the current session
1. Run the `packer build` command as described in the previous section

## <a name="AWSAttribution"></a> Attribution

Amazon Web Services, AWS, the Powered by AWS logo, and Amazon Machine Image (AMI) are trademarks of Amazon.com, Inc. or its affiliates. The information about providers and services contained in this document is for instructional purposes and does not constitute endorsement or recommendation. 
