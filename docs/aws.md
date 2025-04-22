# <a name="AWS"></a>Deploying Malcolm on Amazon Web Services (AWS)

* [Deploying Malcolm on Amazon Web Services (AWS)](#AWS)
    - [Installing prerequisites](#AWSPrereqInstall)
    - [Installing Malcolm in an EC2 instance](#AWSEC2)
        + [Instance creation](#AWSEC2Instance)
        + [Malcolm setup](#AWSEC2Install)
        + [Running Malcolm](#AWSEC2Run)
    - [Installing Malcolm on Fargate](#AWSFargate)
    - [Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)](#KubernetesEKS)
    - [Generating a Malcolm Amazon Machine Image (AMI)](#AWSAMI)
        + [Using MFA](#AWSAMIMFA)
    - [Attribution and Disclaimer](#AWSAttribution)

## <a name="AWSPrereqInstall"></a>Installing prerequisites

The sections below make use of various command line tools. Installation may vary from platform to platform; however, this section gives some basic examples of how to install these tools in \*nix-based environments. Not every guide in this document requires each of the following commands.

* [`aws`, the AWS Command Line Interface](https://aws.amazon.com/cli/)

```bash
$ curl -fsSL \
    -o /tmp/awscli.zip \
    "https://awscli.amazonaws.com/awscli-exe-linux-$(uname -m).zip"
$ unzip -d /tmp /tmp/awscli.zip
…
$ sudo /tmp/aws/install
You can now run: /usr/local/bin/aws --version
$ aws --version
aws-cli/2.26.2 Python/3.13.2 Linux/6.1.0-32-amd64 exe/x86_64.ubuntu.24
```

* [`eksctl`, the official CLI for Amazon EKS](https://eksctl.io/)

```bash
$ curl -fsSL \
    -o /tmp/eksctl.tar.gz \
    "https://github.com/eksctl-io/eksctl/releases/latest/download/eksctl_Linux_$(uname -m | sed 's/^x86_64$/amd64/').tar.gz"
$ tar -xzf /tmp/eksctl.tar.gz -C /tmp && rm /tmp/eksctl.tar.gz
$ sudo mv /tmp/eksctl /usr/local/bin/
$ eksctl version
0.207.0
```

* [`kubectl`, the Kubernetes command line tool](https://kubernetes.io/docs/reference/kubectl/)

```bash
$ curl -fsSL \
    -o /tmp/kubectl \
    "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/$(uname -m | sed 's/^x86_64$/amd64/' | sed 's/^aarch64$/arm64/')/kubectl"
$ chmod 755 /tmp/kubectl
$ sudo mv /tmp/kubectl /usr/local/bin/
$ kubectl version
Client Version: v1.32.3
```

* [`helm`, the package manager for Kubernetes](https://helm.sh/)

```bash
$ curl -fsSL \
    -o /tmp/get_helm.sh \
    https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
$ chmod 700 /tmp/get_helm.sh
$ /tmp/get_helm.sh
$ helm version
version.BuildInfo{Version:"v3.17.3", GitCommit:"e4da49785aa6e6ee2b86efd5dd9e43400318262b", GitTreeState:"clean", GoVersion:"go1.23.7"}
```

* [`packer`, a tool to build automated machine images](https://developer.hashicorp.com/packer)

```bash
$ PACKER_VERSION="$(curl -fsSL 'https://releases.hashicorp.com/packer/' | grep -Po 'href="/packer/[^"]+"' | sort --version-sort | cut -d'/' -f3 | tail -n 1)"
$ curl -fsSL \
    -o /tmp/packer.zip \
    "https://releases.hashicorp.com/packer/${PACKER_VERSION}/packer_${PACKER_VERSION}_linux_$(uname -m | sed 's/^x86_64$/amd64/' | sed 's/^aarch64$/arm64/').zip"
$ unzip -d /tmp /tmp/packer.zip
$ chmod 755 /tmp/packer
$ sudo mv /tmp/packer /usr/local/bin/
$ packer --version
Packer v1.12.0
```

## <a name="AWSEC2"></a>Installing Malcolm in an EC2 instance

This section outlines the process of using the [AWS Command Line Interface (CLI)](https://aws.amazon.com/cli/) to instantiate an [EC2](https://aws.amazon.com/ec2/) instance running Malcolm. This section assumes good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

### <a name="AWSEC2Instance"></a> Instance creation

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

### <a name="AWSEC2Install"></a> Malcolm setup

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

### <a name="AWSEC2Run"></a> Running Malcolm

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

## <a name="AWSFargate"></a> Installing Malcolm on [Fargate](https://aws.amazon.com/fargate/)

### 👷🏼‍♀️ Note: These instructions are a work in progress and may not yet be fully functional. 👷🏻

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

* Create IAM policy for EFS CSI driver

```bash
$ aws iam create-policy \
  --policy-name AmazonEKS_EFS_CSI_Driver_Policy \
  --policy-document "$(curl -fsSL 'https://raw.githubusercontent.com/kubernetes-sigs/aws-efs-csi-driver/refs/heads/master/docs/iam-policy-example.json')"
```

* Create service account for EFS CSI driver

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

* Create IAM policy for AWS load balancer

```bash
$ aws iam create-policy \
  --policy-name AmazonAWS_Load_Balancer_Controller_Policy \
  --policy-document "$(curl -fsSL 'https://raw.githubusercontent.com/kubernetes-sigs/aws-load-balancer-controller/main/docs/install/iam_policy.json')"
```

* Create service account for AWS load balancer

```bash
$ eksctl create iamserviceaccount \
    --cluster malcolm-cluster \
    --namespace kube-system \
    --name aws-alb-controller-sa \
    --attach-policy-arn arn:aws:iam::$(aws sts get-caller-identity --query Account --output text):policy/AmazonAWS_Load_Balancer_Controller_Policy \
    --approve \
    --override-existing-serviceaccounts \
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

$ EFS_SG_ID=$(aws ec2 describe-security-groups \
    --filters "Name=group-name,Values=malcolm-efs-sg" "Name=vpc-id,Values=$VPC_ID" \
    --query 'SecurityGroups[0].GroupId' --output text)

$ echo $EFS_SG_ID
```

* Add NFS inbound rule to Security Group

```bash
$ aws ec2 authorize-security-group-ingress \
    --group-id $EFS_SG_ID \
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
        --security-groups $EFS_SG_ID; \
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
    NAME                      STATUS   VOLUME                     CAPACITY   ACCESS MODES   STORAGECLASS   AGE
    config-claim              Bound    config-volume              25Gi       RWX            efs-sc         2m32s
    opensearch-backup-claim   Bound    opensearch-backup-volume   500Gi      RWO            efs-sc         2m31s
    opensearch-claim          Bound    opensearch-volume          500Gi      RWO            efs-sc         2m32s
    pcap-claim                Bound    pcap-volume                500Gi      RWX            efs-sc         2m33s
    runtime-logs-claim        Bound    runtime-logs-volume        25Gi       RWX            efs-sc         2m32s
    suricata-claim            Bound    suricata-volume            100Gi      RWX            efs-sc         2m32s
    zeek-claim                Bound    zeek-volume                250Gi      RWX            efs-sc         2m33s
    ```

* Install AWS Load Balancer Controller via Helm

```bash
$ helm repo add eks https://aws.github.io/eks-charts
…
$ helm repo update
…
$ helm install aws-load-balancer-controller eks/aws-load-balancer-controller \
  -n kube-system \
  --set clusterName=malcolm-cluster \
  --set serviceAccount.create=false \
  --set serviceAccount.name=aws-alb-controller-sa \
  --set region=us-east-1 \
  --set vpcId=$VPC_ID
```

* Request a certificate and get its ARN (here `malcolm.example.org` is placeholder that should be replaced with the domain name which will point to the Malcolm instance)

```bash
$ aws acm request-certificate \
  --domain-name malcolm.example.org \
  --validation-method DNS \
  --region us-east-1

$ CERT_ARN=$(aws acm list-certificates \
    --region us-east-1 \
    --query "CertificateSummaryList[?DomainName=='malcolm.example.org'].CertificateArn" \
    --output text)
```

* Get the DNS validation record from ACM

```bash
$ VALIDATION_RECORD=$(aws acm describe-certificate \
  --certificate-arn "$CERT_ARN" \
  --region us-east-1 \
  --query "Certificate.DomainValidationOptions[0].ResourceRecord" \
  --output json)

$ echo $VALIDATION_RECORD
```

* Using the dashboard or other tools provided by your domain name provider (i.e., the issuer of `malcolm.example.org` in this example), create a DNS record of type `CNAME` with the host set to the subdomain part of `Name` (e.g., `_0954b44630d36d77d12d12ed6c03c1e4.aws` if `Name` was `_0954b44630d36d77d12d12ed6c03c1e4.aws.malcolm.example.org.`) and the value/target set to `Value` (normally including the trailing dot; however, if your domain name provider gives an error it may be attempted without the trailing dot) of `$VALIDATION_RECORD`. Wait five to ten minutes for DNS to propogate.

* Periodically check the status of the certificate until it has changed from `PENDING_VALIDATION` to `ISSUED`.

```bash
$ aws acm describe-certificate \
  --certificate-arn "$CERT_ARN" \
  --region us-east-1 \
  --query "Certificate.Status"
```

* Configure Malcolm
    * `./Malcolm/scripts/configure -f "${KUBECONFIG:-$HOME/.kube/config}"`
    * Malcolm's configuration scripts will guide users through the setup process.
    * Use the following resources to answer the installation and configuration questions:
        * [Installation example using Ubuntu 24.04 LTS](ubuntu-install-example.md#InstallationExample)
        * [In-depth description of configuration questions](malcolm-hedgehog-e2e-iso-install.md#MalcolmConfig)

* Configure [authentication](authsetup.md#AuthSetup)
    * `./Malcolm/scripts/auth_setup -f "${KUBECONFIG:-$HOME/.kube/config}"`
    * [This example](malcolm-hedgehog-e2e-iso-install.md#MalcolmAuthSetup) can guide users through the prompts.

* Copy `./Malcolm/config/kubernetes-container-resources.yml.example` to `./Malcolm/config/kubernetes-container-resources.yml` and [adjust container resources](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits) in the copy.

* Copy `./Malcolm/kubernetes/99-ingress-aws-alb.yml.example` to `./Malcolm/kubernetes/99-ingress-aws-alb.yml` and edit as needed. This file is an example ingress manifest for Malcolm using the ALB controller for HTTPS. The ingress configuration will vary depending on the situation, but the values likely to need changing include:
    * The `host: "malcolm.example.org"` references to be replaced with the domain name to be associated with the cluster's Malcolm instance.
    * The `alb.ingress.kubernetes.io/certificate-arn` value to be replaced with the certificate ARN for the domain name (`$CERT_ARN` from a previous step).

* Start Malcolm (**TODO: NOT FINAL**)

```bash
$ ./Malcolm/scripts/start -f "${KUBECONFIG:-$HOME/.kube/config}" \
    --inject-resources \
    --service-type LoadBalancer \
    --no-capture-pods \
    --no-capabilities \
    --skip-persistent-volume-checks
```

* Allow incoming TCP connections from remote sensors (**OPTIONAL**: only needed to allow forwarding from a remote [Hedgehog Linux](live-analysis.md#Hedgehog) network sensor)
    * Create and assign a security group for Logstash (5044/tcp) and Filebeat (5045/tcp) to accept logs. Replacing `0.0.0.0/0` with a more limited CIDR block in the following commands is recommended.
    
    ```bash
    $ aws ec2 create-security-group \
        --group-name malcolm-raw-tcp-sg \
        --description "Security group for raw TCP services" \
        --vpc-id $VPC_ID
    
    $ TCP_SG_ID=$(aws ec2 describe-security-groups \
                    --filters Name=group-name,Values=malcolm-raw-tcp-sg \
                    --query 'SecurityGroups[0].GroupId' \
                    --output text)
    
    $ for PORT in 5044 5045; do \
        aws ec2 authorize-security-group-ingress \
            --group-id $TCP_SG_ID \
            --protocol tcp \
            --port $PORT \
            --cidr 0.0.0.0/0; \
    done
    ```

    * Assign the new security group to the network interfaces 

    ```bash
    $ for POD in logstash filebeat; do \
        POD_NAME="$(kubectl get pods -n malcolm --no-headers -o custom-columns=':metadata.name' | grep "$POD" | head -n 1)"; \
        [[ -n "$POD_NAME" ]] || continue; \
        POD_IP="$(kubectl get pod -n malcolm "$POD_NAME" -o jsonpath='{.status.podIP}')"; \
        [[ -n "$POD_IP" ]] || continue; \
        NIC_ID="$(aws ec2 describe-network-interfaces --filters "Name=addresses.private-ip-address,Values=$POD_IP" --query "NetworkInterfaces[0].NetworkInterfaceId" --output text)"; \
        [[ -n "$NIC_ID" ]] || continue; \
        NIC_GROUPS="$(aws ec2 describe-network-interfaces --network-interface-ids "$NIC_ID" --query "NetworkInterfaces[0].Groups[].GroupId" --output text)"; \
        [[ -n "$NIC_GROUPS" ]] || continue; \
        aws ec2 modify-network-interface-attribute \
          --network-interface-id "$NIC_ID" \
          --groups $TCP_SG_ID $NIC_GROUPS; \
    done
    ```

* Get the ALB hostname for the ALB ingress created from `./Malcolm/kubernetes/99-ingress-aws-alb.yml`

```bash
$ ALB_HOSTNAME=$(kubectl get ingress malcolm-ingress-https -n malcolm -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

$ echo $ALB_HOSTNAME
```

* Using the dashboard or other tools provided by your domain name provider (i.e., the issuer of `malcolm.example.org` in this example), create a DNS record of type `CNAME` with the host set to your subdomain (e.g., `malcolm` if the domain is `malcolm.example.org`) and the value/target set to the value of `$ALB_HOSTNAME`. Wait five to ten minutes for DNS to propogate.

* Open a web browser to connect to the Malcolm Fargate cluster (e.g., `https://malcolm.example.org`)

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

## <a name="KubernetesEKS"></a>Deploying Malcolm on Amazon Elastic Kubernetes Service (EKS)

This section outlines the process of setting up a cluster on [Amazon Elastic Kubernetes Service (EKS)](https://aws.amazon.com/eks/) using [Amazon Web Services](https://aws.amazon.com/) in preparation for [**Deploying Malcolm with Kubernetes**](kubernetes.md).

This is a work-in-progress document that is still a bit rough around the edges. Users will need to replace things such as `cluster-name` and `us-east-1` with the values that are appliable to the cluster. Any feedback is welcome in the [relevant issue](https://github.com/idaholab/Malcolm/issues/194) on GitHub.

This section assumes good working knowledge of Amazon Web Services (AWS) and Amazon Elastic Kubernetes Service (EKS). Good documentation resources can be found in the [AWS documentation](https://docs.aws.amazon.com/index.html), the [EKS documentation](https://docs.aws.amazon.com/eks/latest/userguide/what-is-eks.html
) and the [EKS Workshop](https://www.eksworkshop.com/).

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
    * For x86-64 instances `c4.4xlarge`, `t2.2xlarge`, and `t3a.2xlarge` seem to be good instance types for Malcolm; or , for arm64 instances, `m6gd.2xlarge`, `m6g.2xlarge`, `m7g.2xlarge`, and `t4g.2xlarge`; but users' needs may vary (see [recommended system requirements](system-requirements.md#SystemRequirements) for Malcolm)
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
    * Users must specify `--service-type LoadBalancer` when [starting](kubernetes.md#Running) Malcolm; or, set `type: LoadBalancer` for the `nginx-proxy` service in [`98-nginx-proxy.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/98-nginx-proxy.yml), the `filebeat` service in [`12-filebeat.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/12-filebeat.yml) and the the `logstash` service in [`13-logstash.yml`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/13-logstash.yml)
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
    * [`kubernetes/01-volumes-aws-efs.yml.example`]({{ site.github.repository_url }}/blob/{{ site.github.build_revision }}/kubernetes/01-volumes-aws-efs.yml.example) is an example manifest to use as a starting point. Copy `01-volumes-aws-efs.yml.example` to `01-volumes.yml` and replace `${EFS_ID}` with the EFS file system and each `${EFS_ACCESS_POINT_…_ID}` value with the corresponding access point ID from the previous step.
1. Finish [the configuration](kubernetes.md#Config) then [start](kubernetes.md#Running) Malcolm as described in [**Deploying Malcolm with Kubernetes**](kubernetes.md)

## <a name="AWSAMI"></a> Generating a Malcolm Amazon Machine Image (AMI)

This section outlines the process of using [packer](https://www.packer.io/)'s [Amazon AMI Builder](https://developer.hashicorp.com/packer/plugins/builders/amazon) to create an [EBS-backed](https://developer.hashicorp.com/packer/plugins/builders/amazon/ebs) Malcolm AMI for either the x86-64 or arm64 CPU architecture. This section assumes good working knowledge of [Amazon Web Services (AWS)](https://docs.aws.amazon.com/index.html).

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

Amazon Web Services, AWS, the Powered by AWS logo, Amazon Elastic Kubernetes Service (EKS), and Amazon Machine Image (AMI) are trademarks of Amazon.com, Inc. or its affiliates. The information about providers and services contained in this document is for instructional purposes and does not constitute endorsement or recommendation.
